package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
)

func TestGroupedLMMExactSourceWire(t *testing.T) {
	spec, sources, sidecar, _ := groupedLMMSourceFixture(t)
	plan := groupedLMMSourceWirePlan{Version: "dsvert-lmm-staged-source-handoff-v1",
		SpecSHA256: strings.Repeat("1", 64), SourceContractSHA256: strings.Repeat("2", 64),
		ProfileSHA256: strings.Repeat("3", 64), SchemaSHA256: strings.Repeat("4", 64),
		Clusters: spec.Route.Clusters, Slots: spec.Route.Slots, Predictors: spec.Route.Predictors}
	plan.Numeric.Slots, plan.Numeric.GridBits, plan.Numeric.ResidualCap = plan.Slots, spec.LMM.Numeric.GridBits, spec.LMM.Numeric.ResidualCap
	plan.Numeric.Sigma2Q64 = "18447025548686262272" // (1+2^-16)*2^64, exact from R
	plan.Numeric.Tau2Q64 = spec.LMM.Numeric.Tau2Q64.String()
	plan.Numeric.OutputCap = big.NewInt(spec.LMM.Numeric.OutputCap).String()
	for i, row := range spec.LMM.Beta {
		beta := []string{}
		for _, coefficient := range row {
			beta = append(beta, coefficient.String())
		}
		plan.Beta = append(plan.Beta, beta)
		plan.Caps = append(plan.Caps, big.NewInt(spec.LMM.Caps[i]).String())
	}
	key := crossGridStageTestKey(0)
	input := groupedLMMPrepareWireInput{Role: "garbler", Session: spec.Session, Authorities: spec.Authorities,
		SemanticKey: hex.EncodeToString(spec.SemanticKey[:]), StoreDirectory: filepath.Join(t.TempDir(), "durable"),
		StoreKey: base64.StdEncoding.EncodeToString(key[:]), Handoff: groupedLMMSourceWireHandoff{Plan: plan}}
	input.Routing = &struct {
		Labels  []int  `json:"labels"`
		Present []bool `json:"present"`
	}{sidecar.Labels, sidecar.Present}
	encode := func(out crossGridStageOutput) groupedLMMSourceWireOutput {
		return groupedLMMSourceWireOutput{base64.StdEncoding.EncodeToString(out.Share), base64.StdEncoding.EncodeToString(out.Validity)}
	}
	input.Handoff.Numeric, input.Handoff.Metadata = encode(sources[0].Numeric), encode(sources[0].Metadata)
	worker, err := groupedLMMPrepareWire(input)
	if err != nil {
		t.Fatal(err)
	}
	if worker.Spec.LMM.Numeric.Sigma2Q64.String() != plan.Numeric.Sigma2Q64 {
		t.Fatal("R q64 variance lost integer precision")
	}
	raw, err := json.Marshal(worker)
	if err != nil {
		t.Fatal(err)
	}
	var restored groupedLMMWorkerInput
	if json.Unmarshal(raw, &restored) != nil || restored.Spec.LMM.Numeric.Sigma2Q64.String() != plan.Numeric.Sigma2Q64 ||
		groupedLMMWorkerPurpose(restored.Spec) != groupedLMMWorkerPurpose(worker.Spec) {
		t.Fatal("opaque worker handoff changed numeric contract")
	}
	for _, bad := range []string{"18447025548686262272.0", "1.8447025548686262e19", "+18447025548686262272", "018447025548686262272"} {
		changed := input
		changed.Handoff.Plan.Numeric.Sigma2Q64 = bad
		if _, err := groupedLMMPrepareWire(changed); err == nil {
			t.Fatalf("accepted noncanonical integer %q", bad)
		}
	}
	changed := input
	changed.Handoff.Metadata.Share = input.Handoff.Numeric.Share
	if _, err := groupedLMMPrepareWire(changed); err == nil {
		t.Fatal("accepted wrong metadata shape")
	}
	changed = input
	changed.Role = "evaluator"
	if _, err := groupedLMMPrepareWire(changed); err == nil {
		t.Fatal("provided owner labels to evaluator")
	}
}
