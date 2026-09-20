package main

// Exact decimal boundary for the owner-local R handoff. R carries the native
// worker configuration as one opaque string, never as floating-point numbers.
import (
	"encoding/hex"
	"encoding/json"
	"math/big"
)

type groupedGLMMSourceWirePlan struct {
	Version                     string `json:"version"`
	SpecSHA256                  string `json:"spec_sha256"`
	SourceContractSHA256        string `json:"source_contract_sha256"`
	ProfileSHA256               string `json:"profile_sha256"`
	SchemaSHA256                string `json:"schema_sha256"`
	Clusters, Slots, Predictors int
	Numeric                     struct {
		Family          string `json:"family,omitempty"`
		MaxOutcome      string `json:"max_outcome,omitempty"`
		Slots, GridBits int
		OutputCap       string
	}
	Beta         [][]string
	Caps         []string
	VarianceGrid []string
}

type groupedGLMMSourceWireOutput struct{ Share, Validity string }
type groupedGLMMSourceWireHandoff struct {
	Plan     groupedGLMMSourceWirePlan   `json:"plan"`
	Numeric  groupedGLMMSourceWireOutput `json:"numeric"`
	Outcome  groupedGLMMSourceWireOutput `json:"outcome"`
	Metadata groupedGLMMSourceWireOutput `json:"metadata"`
}
type groupedGLMMPrepareWireInput struct {
	Handoff        groupedGLMMSourceWireHandoff `json:"handoff"`
	Role           string                       `json:"role"`
	Session        string                       `json:"session"`
	Authorities    [2]string                    `json:"authorities"`
	SemanticKey    string                       `json:"semantic_key"`
	StoreDirectory string                       `json:"store_directory"`
	StoreKey       string                       `json:"store_key"`
	Routing        *struct {
		Labels  []int  `json:"labels"`
		Present []bool `json:"present"`
	} `json:"routing"`
}

func groupedGLMMPrepareWire(input groupedGLMMPrepareWireInput) (*groupedGLMMWorkerInput, error) {
	w := input.Handoff.Plan
	role := exactGCRoleGarbler
	if input.Role == "evaluator" {
		role = exactGCRoleEvaluator
	} else if input.Role != "garbler" {
		return nil, errCrossGridStage
	}
	if w.Version != "dsvert-glmm-staged-source-handoff-v1" || w.Numeric.Slots != w.Slots ||
		len(w.Beta) < 1 || len(w.Caps) < 1 || len(w.Caps) > 256 {
		return nil, errCrossGridStage
	}
	digests := [5][32]byte{}
	for i, text := range []string{w.SpecSHA256, w.SourceContractSHA256, w.ProfileSHA256, w.SchemaSHA256, input.SemanticKey} {
		var err error
		digests[i], err = groupedLMMWireDigest(text)
		if err != nil {
			return nil, err
		}
	}
	profile := crossGridStageHash("glmm-signed-numeric-profile", [2][32]byte{digests[0], digests[2]})
	spec := groupedGLMMSourceSpec{Session: input.Session, Authorities: input.Authorities, SchemaDigest: digests[3], SemanticKey: digests[4],
		Route: groupedRouteStagedSpec{Clusters: w.Clusters, Slots: w.Slots, Predictors: w.Predictors,
			NumericStage: "glmm.source.normalized", MetadataStage: "glmm.source.metadata", SourceDigest: digests[1], ProfileDigest: profile,
			NumericBound: new(big.Int).Lsh(big.NewInt(1), 50), Nonnegative: true},
		GLMM: groupedGLMMStagedSpec{Clusters: w.Clusters, Slots: w.Slots, Predictors: w.Predictors, GridBits: w.Numeric.GridBits,
			SourceDigest: digests[1], ProfileDigest: profile, RoutedStage: "glmm.source.ring192"}}
	if w.Numeric.Family != "" || w.Numeric.MaxOutcome != "" {
		maxOutcome, err := groupedLMMWireInteger(w.Numeric.MaxOutcome)
		if err != nil || !maxOutcome.IsInt64() || w.Numeric.Family != "poisson" || maxOutcome.Int64() < 1 || maxOutcome.Int64() > 4 {
			return nil, errCrossGridStage
		}
		spec.GLMM.Family, spec.GLMM.MaxOutcome = w.Numeric.Family, int(maxOutcome.Int64())
		spec.Route.OutcomeBound = new(big.Int).Lsh(maxOutcome, 50)
	}
	outputCap, err := groupedLMMWireInteger(w.Numeric.OutputCap)
	if err != nil || !outputCap.IsInt64() || outputCap.Sign() < 1 {
		return nil, errCrossGridStage
	}
	for _, text := range w.VarianceGrid {
		variance, e := groupedLMMWireInteger(text)
		if e != nil || !variance.IsInt64() {
			return nil, errCrossGridStage
		}
		spec.GLMM.VarianceGrid = append(spec.GLMM.VarianceGrid, variance.Int64())
	}
	for _, beta := range w.Beta {
		row := make([]*big.Int, len(beta))
		for j, text := range beta {
			var err error
			row[j], err = groupedLMMWireInteger(text)
			if err != nil {
				return nil, err
			}
		}
		spec.GLMM.Beta = append(spec.GLMM.Beta, row)
	}
	maxCap := int64(0)
	for _, text := range w.Caps {
		cap, err := groupedLMMWireInteger(text)
		if err != nil || !cap.IsInt64() {
			return nil, errCrossGridStage
		}
		spec.GLMM.Caps = append(spec.GLMM.Caps, cap.Int64())
		if cap.Int64() > maxCap {
			maxCap = cap.Int64()
		}
	}
	if outputCap.Int64() != maxCap {
		return nil, errCrossGridStage
	}
	plans, err := groupedGLMMSourcePlans(spec)
	if err != nil {
		return nil, err
	}
	outputs := [3]crossGridStageOutput{}
	for i, wire := range []groupedGLMMSourceWireOutput{input.Handoff.Numeric, input.Handoff.Outcome, input.Handoff.Metadata} {
		outputs[i].Share, err = exactGCStrictBase64(wire.Share, len(plans[i].CoordOrder)*16)
		if err != nil {
			return nil, err
		}
		outputs[i].Validity, err = exactGCStrictBase64(wire.Validity, len(plans[i].CoordOrder))
		if err != nil {
			return nil, err
		}
	}
	keyBytes, err := exactGCStrictBase64(input.StoreKey, 32)
	if err != nil {
		return nil, err
	}
	var key [32]byte
	copy(key[:], keyBytes)
	defer clear(key[:])
	defer clear(keyBytes)
	source, err := groupedGLMMSealSource(spec, role, outputs[0], outputs[1], outputs[2], key)
	if err != nil {
		return nil, err
	}
	var routing *groupedRouteSidecar
	if role == exactGCRoleGarbler {
		if input.Routing == nil {
			return nil, errCrossGridStage
		}
		routing, err = groupedRouteSeal(spec.Route, input.Routing.Labels, input.Routing.Present, key)
		if err != nil {
			return nil, err
		}
	} else if input.Routing != nil {
		return nil, errCrossGridStage
	}
	return &groupedGLMMWorkerInput{Spec: spec, Source: source, Routing: routing, StoreDirectory: input.StoreDirectory, StoreKey: input.StoreKey}, nil
}

// Strictly server-local: all inputs and the opaque result remain private
// worker material. No DataSHIELD aggregate endpoint invokes this command.
func handleGroupedGLMMPrepareWire() {
	var input groupedGLMMPrepareWireInput
	mpcReadInput(&input)
	worker, err := groupedGLMMPrepareWire(input)
	if err != nil {
		outputError("GLMM staged handoff rejected")
		return
	}
	raw, err := json.Marshal(worker)
	if err != nil {
		outputError("GLMM staged handoff rejected")
		return
	}
	var encoded string
	if json.Unmarshal(raw, &encoded) != nil {
		outputError("GLMM staged handoff rejected")
		return
	}
	keyBytes, err := exactGCStrictBase64(worker.StoreKey, 32)
	if err != nil {
		outputError("GLMM staged handoff rejected")
		return
	}
	var key [32]byte
	copy(key[:], keyBytes)
	defer clear(key[:])
	defer clear(keyBytes)
	graph, err := groupedGLMMBuildSourceGraph(worker.Spec, worker.Source.Role, worker.Source, worker.Routing, key)
	if err != nil {
		outputError("GLMM staged handoff rejected")
		return
	}
	digest := crossGridStageHash("public-plan", graph.Graph)
	mpcWriteOutput(struct {
		StagePlanDigest string `json:"stage_plan_digest"`
		WorkerInput     string `json:"worker_input"`
		Purpose         string `json:"purpose"`
		VectorLen       int    `json:"vector_len"`
	}{hex.EncodeToString(digest[:]), encoded, groupedGLMMWorkerPurpose(worker.Spec), len(worker.Spec.GLMM.Caps)})
}
