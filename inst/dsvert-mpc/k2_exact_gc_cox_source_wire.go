package main

// Owner-local exact handoff; source shares and the opaque worker config never
// traverse an aggregate endpoint. Public descriptors construct the only graph.
import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type coxLossSourceWirePlan struct {
	Version              string   `json:"version"`
	SpecSHA256           string   `json:"spec_sha256"`
	SourceContractSHA256 string   `json:"source_contract_sha256"`
	ProfileSHA256        string   `json:"profile_sha256"`
	SchemaSHA256         string   `json:"schema_sha256"`
	Capacity             int      `json:"capacity"`
	GridBits             int      `json:"grid_bits"`
	Caps                 []string `json:"caps"`
}
type coxLossSourceWireOutput struct{ Share, Validity string }
type coxLossSourceWireHandoff struct {
	Plan       coxLossSourceWirePlan   `json:"plan"`
	Predictors coxLossSourceWireOutput `json:"predictors"`
	LiveEvent  coxLossSourceWireOutput `json:"live_event"`
}
type coxLossPrepareWireInput struct {
	Handoff        coxLossSourceWireHandoff `json:"handoff"`
	Role           string                   `json:"role"`
	Session        string                   `json:"session"`
	Authorities    [2]string                `json:"authorities"`
	SemanticKey    string                   `json:"semantic_key"`
	StoreDirectory string                   `json:"store_directory"`
	StoreKey       string                   `json:"store_key"`
	RoutingDigest  string                   `json:"routing_digest"`
	Routing        *struct {
		Permutation []int  `json:"permutation"`
		Ends        []bool `json:"ends"`
	} `json:"routing"`
}

func coxLossPrepareWire(input coxLossPrepareWireInput) (*coxLossWorkerInput, error) {
	w := input.Handoff.Plan
	role := exactGCRoleGarbler
	if input.Role == "evaluator" {
		role = exactGCRoleEvaluator
	} else if input.Role != "garbler" {
		return nil, errCrossGridStage
	}
	if w.Version != "dsvert-cox-staged-source-handoff-v1" || len(w.Caps) < 1 || len(w.Caps) > 50 {
		return nil, errCrossGridStage
	}
	var digests [5][32]byte
	for i, text := range []string{w.SpecSHA256, w.SourceContractSHA256, w.ProfileSHA256, w.SchemaSHA256, input.SemanticKey} {
		var err error
		digests[i], err = groupedLMMWireDigest(text)
		if err != nil {
			return nil, err
		}
	}
	caps := make([]uint64, len(w.Caps))
	for i, text := range w.Caps {
		value, err := groupedLMMWireInteger(text)
		if err != nil || !value.IsUint64() {
			return nil, errCrossGridStage
		}
		caps[i] = value.Uint64()
	}
	plan, err := registerCoxGridCrossLoss().SharedPlan(coxLossSpec{w.Capacity, len(caps), w.GridBits, caps, CoxGridCrossProfileID})
	if err != nil {
		return nil, err
	}
	contract := crossGridStageHash("cox-signed-numeric-profile", [2][32]byte{digests[0], digests[2]})
	spec := coxLossSourceSpec{Session: input.Session, Authorities: input.Authorities, SchemaDigest: digests[3], SemanticKey: digests[4], Cox: coxLossStagedSpec{Plan: plan, Prefix: "cox.loss", SourceDigest: digests[1], Contract: contract}}
	for i, width := range []int{plan.PaddedRows * len(caps), 2 * plan.PaddedRows} {
		name := []string{"predictors", "live-event"}[i]
		coords := make([]string, width)
		for j := range coords {
			coords[j] = fmt.Sprintf("%s/%d", name, j)
		}
		spec.Cox.Sources[i] = crossGridStagePlan{ID: "cox.source." + name, Kind: "cox.authenticated-source", Ring: 128, FPScale: []int{100, 0}[i], CoordOrder: coords, PublicBounds: map[string]int{"capacity": w.Capacity, "padded_rows": plan.PaddedRows, "candidates": len(caps)}, SourceDigest: digests[1], ProfileDigest: contract}
	}
	keyBytes, err := exactGCStrictBase64(input.StoreKey, 32)
	if err != nil {
		return nil, err
	}
	var key [32]byte
	copy(key[:], keyBytes)
	defer clear(key[:])
	defer clear(keyBytes)
	var routing *coxLossStagedRouting
	if role == exactGCRoleGarbler {
		if input.Routing == nil || len(input.Routing.Permutation) != plan.PaddedRows {
			return nil, errCrossGridStage
		}
		controls, err := primitiveVPermutationControls(input.Routing.Permutation)
		if err != nil {
			return nil, err
		}
		routing, err = coxLossSealStagedRouting(spec.Cox, controls, input.Routing.Ends, key)
		if err != nil {
			return nil, err
		}
		spec.Cox.RoutingDigest = routing.MAC
		if input.RoutingDigest != "" && input.RoutingDigest != hex.EncodeToString(routing.MAC[:]) {
			return nil, errCrossGridStage
		}
	} else {
		if input.Routing != nil {
			return nil, errCrossGridStage
		}
		spec.Cox.RoutingDigest, err = groupedLMMWireDigest(input.RoutingDigest)
		if err != nil {
			return nil, err
		}
	}
	plans, err := coxLossSourcePlans(spec)
	if err != nil {
		return nil, err
	}
	var values [2]crossGridStageOutput
	for i, wire := range []coxLossSourceWireOutput{input.Handoff.Predictors, input.Handoff.LiveEvent} {
		values[i].Share, err = exactGCStrictBase64(wire.Share, 16*len(plans[i].CoordOrder))
		if err != nil {
			return nil, err
		}
		values[i].Validity, err = exactGCStrictBase64(wire.Validity, len(plans[i].CoordOrder))
		if err != nil {
			return nil, err
		}
	}
	source, err := coxLossSealSource(spec, role, values[0], values[1], key)
	if err != nil {
		return nil, err
	}
	return &coxLossWorkerInput{Spec: spec, Source: source, Routing: routing, StoreDirectory: input.StoreDirectory, StoreKey: input.StoreKey}, nil
}

func handleCoxLossPrepareWire() {
	var input coxLossPrepareWireInput
	mpcReadInput(&input)
	worker, err := coxLossPrepareWire(input)
	if err != nil {
		outputError("Cox staged handoff rejected")
		return
	}
	raw, err := json.Marshal(worker)
	if err != nil {
		outputError("Cox staged handoff rejected")
		return
	}
	var encoded string
	if json.Unmarshal(raw, &encoded) != nil {
		outputError("Cox staged handoff rejected")
		return
	}
	keyBytes, err := exactGCStrictBase64(worker.StoreKey, 32)
	if err != nil {
		outputError("Cox staged handoff rejected")
		return
	}
	var key [32]byte
	copy(key[:], keyBytes)
	defer clear(key[:])
	defer clear(keyBytes)
	graph, err := coxLossBuildSourceGraph(worker.Spec, worker.Source.Role, worker.Source, worker.Routing, key)
	if err != nil {
		outputError("Cox staged handoff rejected")
		return
	}
	digest := crossGridStageHash("public-plan", graph.Graph)
	mpcWriteOutput(struct {
		StagePlanDigest string `json:"stage_plan_digest"`
		WorkerInput     string `json:"worker_input"`
		Purpose         string `json:"purpose"`
		VectorLen       int    `json:"vector_len"`
		RoutingDigest   string `json:"routing_digest"`
	}{hex.EncodeToString(digest[:]), encoded, coxLossWorkerPurpose(worker.Spec), len(worker.Spec.Cox.Plan.Spec.Caps), hex.EncodeToString(worker.Spec.Cox.RoutingDigest[:])})
}
