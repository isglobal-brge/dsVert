package main

// Exact decimal boundary for the owner-local R handoff. R carries the native
// worker configuration as one opaque string, never as floating-point numbers.
import (
	"encoding/hex"
	"encoding/json"
	"math/big"
)

type groupedLMMSourceWirePlan struct {
	Version                     string `json:"version"`
	SpecSHA256                  string `json:"spec_sha256"`
	SourceContractSHA256        string `json:"source_contract_sha256"`
	ProfileSHA256               string `json:"profile_sha256"`
	SchemaSHA256                string `json:"schema_sha256"`
	Clusters, Slots, Predictors int
	Numeric                     struct {
		Slots, GridBits               int
		ResidualCap                   int64
		Sigma2Q64, Tau2Q64, OutputCap string
	}
	Beta         [][]string
	Caps         []string
	Objective    string                                `json:",omitempty"`
	VarianceGrid []struct{ Sigma2Q64, Tau2Q64 string } `json:",omitempty"`
}

type groupedLMMSourceWireOutput struct{ Share, Validity string }
type groupedLMMSourceWireHandoff struct {
	Plan     groupedLMMSourceWirePlan   `json:"plan"`
	Numeric  groupedLMMSourceWireOutput `json:"numeric"`
	Metadata groupedLMMSourceWireOutput `json:"metadata"`
}
type groupedLMMPrepareWireInput struct {
	Handoff        groupedLMMSourceWireHandoff `json:"handoff"`
	Role           string                      `json:"role"`
	Session        string                      `json:"session"`
	Authorities    [2]string                   `json:"authorities"`
	SemanticKey    string                      `json:"semantic_key"`
	StoreDirectory string                      `json:"store_directory"`
	StoreKey       string                      `json:"store_key"`
	Routing        *struct {
		Labels  []int  `json:"labels"`
		Present []bool `json:"present"`
	} `json:"routing"`
}

func groupedLMMWireDigest(value string) ([32]byte, error) {
	var result [32]byte
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != value {
		return result, errCrossGridStage
	}
	copy(result[:], raw)
	if result == ([32]byte{}) {
		return result, errCrossGridStage
	}
	return result, nil
}
func groupedLMMWireInteger(value string) (*big.Int, error) {
	v, ok := new(big.Int).SetString(value, 10)
	if !ok || v.String() != value || v.BitLen() > 127 {
		return nil, errCrossGridStage
	}
	return v, nil
}

func groupedLMMPrepareWire(input groupedLMMPrepareWireInput) (*groupedLMMWorkerInput, error) {
	w := input.Handoff.Plan
	role := exactGCRoleGarbler
	if input.Role == "evaluator" {
		role = exactGCRoleEvaluator
	} else if input.Role != "garbler" {
		return nil, errCrossGridStage
	}
	if w.Version != "dsvert-lmm-staged-source-handoff-v1" || w.Numeric.Slots != w.Slots ||
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
	integers := make([]*big.Int, 3)
	for i, text := range []string{w.Numeric.Sigma2Q64, w.Numeric.Tau2Q64, w.Numeric.OutputCap} {
		var err error
		integers[i], err = groupedLMMWireInteger(text)
		if err != nil {
			return nil, err
		}
	}
	if !integers[2].IsInt64() {
		return nil, errCrossGridStage
	}
	profile := crossGridStageHash("lmm-signed-numeric-profile", [2][32]byte{digests[0], digests[2]})
	spec := groupedLMMSourceSpec{Session: input.Session, Authorities: input.Authorities, SchemaDigest: digests[3], SemanticKey: digests[4],
		Route: groupedRouteStagedSpec{Clusters: w.Clusters, Slots: w.Slots, Predictors: w.Predictors,
			NumericStage: "lmm.source.numeric", MetadataStage: "lmm.source.metadata", SourceDigest: digests[1], ProfileDigest: profile,
			NumericBound: new(big.Int).Lsh(big.NewInt(1), 50), Nonnegative: true},
		LMM: groupedLMMStagedSpec{Moments: groupedLMMMomentPlan{w.Clusters, w.Slots, w.Predictors + 2},
			Numeric: groupedLMMSpec{Slots: w.Slots, GridBits: w.Numeric.GridBits, ResidualCap: w.Numeric.ResidualCap,
				Sigma2Q64: integers[0], Tau2Q64: integers[1], OutputCap: integers[2].Int64()},
			SourceDigest: digests[1], ProfileDigest: profile, RoutedStage: "lmm.source.ring192"}}
	spec.LMM.Objective = w.Objective
	for _, pair := range w.VarianceGrid {
		sigma, e := groupedLMMWireInteger(pair.Sigma2Q64)
		if e != nil {
			return nil, e
		}
		tau, e := groupedLMMWireInteger(pair.Tau2Q64)
		if e != nil {
			return nil, e
		}
		spec.LMM.VarianceGrid = append(spec.LMM.VarianceGrid, groupedLMMVariance{Sigma2Q64: sigma, Tau2Q64: tau})
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
		spec.LMM.Beta = append(spec.LMM.Beta, row)
	}
	for _, text := range w.Caps {
		cap, err := groupedLMMWireInteger(text)
		if err != nil || !cap.IsInt64() {
			return nil, errCrossGridStage
		}
		spec.LMM.Caps = append(spec.LMM.Caps, cap.Int64())
	}
	plans, err := groupedLMMSourcePlans(spec)
	if err != nil {
		return nil, err
	}
	outputs := [2]crossGridStageOutput{}
	for i, wire := range []groupedLMMSourceWireOutput{input.Handoff.Numeric, input.Handoff.Metadata} {
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
	source, err := groupedLMMSealSource(spec, role, outputs[0], outputs[1], key)
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
	return &groupedLMMWorkerInput{Spec: spec, Source: source, Routing: routing, StoreDirectory: input.StoreDirectory, StoreKey: input.StoreKey}, nil
}

// Strictly server-local: all inputs and the opaque result remain private
// worker material. No DataSHIELD aggregate endpoint invokes this command.
func handleGroupedLMMPrepareWire() {
	var input groupedLMMPrepareWireInput
	mpcReadInput(&input)
	worker, err := groupedLMMPrepareWire(input)
	if err != nil {
		outputError("LMM staged handoff rejected")
		return
	}
	raw, err := json.Marshal(worker)
	if err != nil {
		outputError("LMM staged handoff rejected")
		return
	}
	var encoded string
	if json.Unmarshal(raw, &encoded) != nil {
		outputError("LMM staged handoff rejected")
		return
	}
	keyBytes, err := exactGCStrictBase64(worker.StoreKey, 32)
	if err != nil {
		outputError("LMM staged handoff rejected")
		return
	}
	var key [32]byte
	copy(key[:], keyBytes)
	defer clear(key[:])
	defer clear(keyBytes)
	graph, err := groupedLMMBuildSourceGraph(worker.Spec, worker.Source.Role, worker.Source, worker.Routing, key)
	if err != nil {
		outputError("LMM staged handoff rejected")
		return
	}
	digest := crossGridStageHash("public-plan", graph.Graph)
	mpcWriteOutput(struct {
		StagePlanDigest string `json:"stage_plan_digest"`
		WorkerInput     string `json:"worker_input"`
		Purpose         string `json:"purpose"`
		VectorLen       int    `json:"vector_len"`
	}{hex.EncodeToString(digest[:]), encoded, groupedLMMWorkerPurpose(worker.Spec), len(worker.Spec.LMM.Caps)})
}
