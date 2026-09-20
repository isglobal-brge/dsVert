package main

// Exact decimal boundary for the owner-local R handoff. R carries the native
// worker configuration as one opaque string, never as floating-point numbers.
import (
	"encoding/hex"
	"encoding/json"
	"math/big"
)

type groupedGEESourceWirePlan struct {
	Version                     string `json:"version"`
	SpecSHA256                  string `json:"spec_sha256"`
	SourceContractSHA256        string `json:"source_contract_sha256"`
	ProfileSHA256               string `json:"profile_sha256"`
	SchemaSHA256                string `json:"schema_sha256"`
	Clusters, Slots, Predictors int
	CorrelationContract         string `json:"correlation_contract"`
	Numeric                     struct {
		Family, Correlation                                    string
		Slots, Predictors, GridBits                            int
		RhoQ16, ScoreClipQ16, RowLossCap, BreadCap, MaxOutcome string
	}
	Beta [][]string
	Caps []string
}

type groupedGEESourceWireOutput struct{ Share, Validity string }
type groupedGEESourceWireHandoff struct {
	Plan     groupedGEESourceWirePlan   `json:"plan"`
	Numeric  groupedGEESourceWireOutput `json:"numeric"`
	Outcome  groupedGEESourceWireOutput `json:"outcome"`
	Metadata groupedGEESourceWireOutput `json:"metadata"`
}
type groupedGEEPrepareWireInput struct {
	Handoff        groupedGEESourceWireHandoff `json:"handoff"`
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

func groupedGEEPrepareWire(input groupedGEEPrepareWireInput) (*groupedGEEWorkerInput, error) {
	w := input.Handoff.Plan
	role := exactGCRoleGarbler
	if input.Role == "evaluator" {
		role = exactGCRoleEvaluator
	} else if input.Role != "garbler" {
		return nil, errCrossGridStage
	}
	if w.Version != "dsvert-gee-fixed-rho-staged-source-handoff-v1" || w.Numeric.Slots != w.Slots || w.Numeric.Predictors != w.Predictors ||
		len(w.Beta) < 1 || len(w.Caps) < 1 || len(w.Caps) > 4 {
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
	profile := crossGridStageHash("gee-fixed-rho-signed-numeric-profile", [2][32]byte{digests[0], digests[2]})
	spec := groupedGEESourceSpec{Session: input.Session, Authorities: input.Authorities, SchemaDigest: digests[3], SemanticKey: digests[4], Contract: profile,
		CorrelationContract: w.CorrelationContract,
		Route: groupedRouteStagedSpec{Clusters: w.Clusters, Slots: w.Slots, Predictors: w.Predictors,
			NumericStage: "gee.source.normalized", MetadataStage: "gee.source.metadata", SourceDigest: digests[1], ProfileDigest: profile,
			NumericBound: new(big.Int).Lsh(big.NewInt(1), 50), Nonnegative: true},
		Numeric: groupedGEESpec{Slots: w.Slots, Predictors: w.Predictors, GridBits: w.Numeric.GridBits,
			Family: w.Numeric.Family, Correlation: w.Numeric.Correlation}}
	for _, field := range []struct {
		text   string
		target *int64
	}{
		{w.Numeric.RhoQ16, &spec.Numeric.RhoQ16}, {w.Numeric.ScoreClipQ16, &spec.Numeric.ScoreClipQ16},
		{w.Numeric.RowLossCap, &spec.Numeric.RowLossCap}, {w.Numeric.BreadCap, &spec.Numeric.BreadCap},
		{w.Numeric.MaxOutcome, &spec.Numeric.MaxOutcome},
	} {
		value, err := groupedLMMWireInteger(field.text)
		if err != nil || !value.IsInt64() {
			return nil, errCrossGridStage
		}
		*field.target = value.Int64()
	}
	spec.Route.OutcomeBound = new(big.Int).Lsh(big.NewInt(spec.Numeric.MaxOutcome), 50)
	for _, beta := range w.Beta {
		row := make([]*big.Int, len(beta))
		for j, text := range beta {
			var err error
			row[j], err = groupedLMMWireInteger(text)
			if err != nil {
				return nil, err
			}
		}
		spec.Beta = append(spec.Beta, row)
	}
	for _, text := range w.Caps {
		cap, err := groupedLMMWireInteger(text)
		if err != nil || !cap.IsInt64() {
			return nil, errCrossGridStage
		}
		spec.Caps = append(spec.Caps, cap.Int64())
	}
	plans, err := groupedGEESourcePlans(spec)
	if err != nil {
		return nil, err
	}
	outputs := [3]crossGridStageOutput{}
	for i, wire := range []groupedGEESourceWireOutput{input.Handoff.Numeric, input.Handoff.Outcome, input.Handoff.Metadata} {
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
	source, err := groupedGEESealSource(spec, role, outputs[0], outputs[1], outputs[2], key)
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
	return &groupedGEEWorkerInput{Spec: spec, Source: source, Routing: routing, StoreDirectory: input.StoreDirectory, StoreKey: input.StoreKey}, nil
}

// Strictly server-local: all inputs and the opaque result remain private
// worker material. No DataSHIELD aggregate endpoint invokes this command.
func handleGroupedGEEPrepareWire() {
	var input groupedGEEPrepareWireInput
	mpcReadInput(&input)
	worker, err := groupedGEEPrepareWire(input)
	if err != nil {
		outputError("GEE staged handoff rejected")
		return
	}
	raw, err := json.Marshal(worker)
	if err != nil {
		outputError("GEE staged handoff rejected")
		return
	}
	var encoded string
	if json.Unmarshal(raw, &encoded) != nil {
		outputError("GEE staged handoff rejected")
		return
	}
	keyBytes, err := exactGCStrictBase64(worker.StoreKey, 32)
	if err != nil {
		outputError("GEE staged handoff rejected")
		return
	}
	var key [32]byte
	copy(key[:], keyBytes)
	defer clear(key[:])
	defer clear(keyBytes)
	graph, err := groupedGEEBuildSourceGraph(worker.Spec, worker.Source.Role, worker.Source, worker.Routing, key)
	if err != nil {
		outputError("GEE staged handoff rejected")
		return
	}
	digest := crossGridStageHash("public-plan", graph.Graph)
	mpcWriteOutput(struct {
		StagePlanDigest string `json:"stage_plan_digest"`
		WorkerInput     string `json:"worker_input"`
		Purpose         string `json:"purpose"`
		VectorLen       int    `json:"vector_len"`
	}{hex.EncodeToString(digest[:]), encoded, groupedGEEWorkerPurpose(worker.Spec), len(worker.Spec.Caps) * (1 + (worker.Spec.Numeric.Predictors+1)*(worker.Spec.Numeric.Predictors+2))})
}
