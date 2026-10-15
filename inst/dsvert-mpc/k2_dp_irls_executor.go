package main

// This adapter ends at the private durable COMMIT boundary. It exposes no
// command, publication, reconstruction, or noise-disable option. B3 must pass
// both lanes and the shared validity into the once-only protected DP handoff.
import (
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
)

func dpIRLSBuildStageGraph(p dpIRLSStagePlan, authorities [2]string) (crossGridStageGraph, error) {
	var graph crossGridStageGraph
	if p.validate() != nil {
		return graph, errCrossGridKernel
	}
	decode := func(s string) [32]byte {
		var out [32]byte
		b, _ := hex.DecodeString(s) // validate has checked the canonical digest.
		copy(out[:], b)
		return out
	}
	coords := make([]string, 0, 9)
	for i := 0; i < p.P; i++ {
		coords = append(coords, fmt.Sprintf("g:%d", i+1))
	}
	for i := 0; i < p.P; i++ {
		for j := i; j < p.P; j++ {
			coords = append(coords, fmt.Sprintf("H:%d:%d", i+1, j+1))
		}
	}
	graph = crossGridStageGraph{
		Version: "cross-grid-stage-graph-v1", Family: "dp-irls-" + p.Family,
		Session: "dp-irls/" + p.StageID, Authorities: authorities,
		SchemaDigest: crossGridStageHash("dp-irls-evaluation-point-v1", p),
		SemanticKey:  decode(p.StageID),
		Stages: []crossGridStagePlan{{
			ID: "fused-score-curvature", Kind: "dp-irls-public-point-v1",
			Ring: 128, FPScale: 12, CoordOrder: coords,
			PublicBounds: map[string]int{"capacity": p.Rows, "p": p.P, "row_cap": 1},
			SourceDigest: decode(p.Root), ProfileDigest: decode(p.CertificateDigest),
		}},
	}
	if graph.validate() != nil {
		return crossGridStageGraph{}, errCrossGridStage
	}
	return graph, nil
}

func dpIRLSStageCompute(k *crossGridKernelPrepared, role exactGCRole, source []*big.Int, timings *exactGCProtocolTimings) (crossGridStageCompute, error) {
	if k == nil || k.circuit == nil || k.plan.IRLS == nil || k.plan.validate() != nil ||
		(role != exactGCRoleGarbler && role != exactGCRoleEvaluator) {
		return nil, errCrossGridKernel
	}
	// Own the local source snapshot before a durable attempt starts. This checks
	// only the share representation; all semantic clamps remain in the circuit.
	owned, err := crossGridKernelPrivateInput(k.plan, source, role == exactGCRoleGarbler)
	if err != nil {
		return nil, err
	}
	return func(rw io.ReadWriter, attempt crossGridStageAttempt, previous []crossGridStageOutput) (crossGridStageOutput, error) {
		if len(previous) != 0 || attempt.Nonce == ([32]byte{}) || attempt.OutputMaskDomainTag == ([32]byte{}) {
			return crossGridStageOutput{}, errCrossGridStage
		}
		session := attempt.Session
		session.Purpose = k.plan.purpose()
		session.Spec = exactGCCircuitSpec{Operation: dpIRLSStageOperation, RingBits: 128, VectorLen: 9}
		// The seed is nil: masks are fresh private garbler randomness. The shared
		// attempt tag is NOT a private mask seed. Executor remasking is additional.
		words, err := k.runWithSeedMeasured(rw, session, owned, role, nil, timings)
		if err != nil {
			return crossGridStageOutput{}, err
		}
		defer exactGCZeroBigInts(words)
		if len(words) != 10 || words[9].BitLen() > 1 {
			return crossGridStageOutput{}, errCrossGridStage
		}
		out := crossGridStageOutput{Share: make([]byte, 9*16), Validity: make([]byte, 9)}
		for i := range out.Validity {
			b := words[i].Bytes()
			for j := range b {
				out.Share[16*i+j] = b[len(b)-1-j]
			}
			out.Validity[i] = byte(words[9].Uint64())
		}
		return out, nil
	}, nil
}

func dpIRLSExecuteStage(rw io.ReadWriter, executor *crossGridStageExecutor, k *crossGridKernelPrepared, source []*big.Int, timings *exactGCProtocolTimings) (crossGridStageOutput, error) {
	if executor == nil || executor.Store == nil || k == nil || k.plan.IRLS == nil {
		return crossGridStageOutput{}, errCrossGridStage
	}
	want, err := dpIRLSBuildStageGraph(*k.plan.IRLS, executor.Store.graph.Authorities)
	if err != nil || crossGridStageHash("plan", want) != crossGridStageHash("plan", executor.Store.graph) {
		return crossGridStageOutput{}, errCrossGridStage
	}
	compute, err := dpIRLSStageCompute(k, executor.Store.role, source, timings)
	if err != nil {
		return crossGridStageOutput{}, err
	}
	outputs, err := executor.Execute(rw, []crossGridStageCompute{compute})
	if err != nil {
		return crossGridStageOutput{}, err
	}
	return outputs[0], nil
}
