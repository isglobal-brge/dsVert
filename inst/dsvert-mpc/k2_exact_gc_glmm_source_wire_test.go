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

func TestGroupedGLMMExactSourceWire(t *testing.T) { groupedGLMMExactSourceWireTest(t, "") }
func TestGroupedGLMMPoissonExactSourceWire(t *testing.T) {
	groupedGLMMExactSourceWireTest(t, "poisson")
}
func groupedGLMMExactSourceWireTest(t *testing.T, family string) {
	spec, sources, sidecar, _ := groupedGLMMSourceFixture(t, family)
	plan := groupedGLMMSourceWirePlan{Version: "dsvert-glmm-staged-source-handoff-v1",
		SpecSHA256: strings.Repeat("1", 64), SourceContractSHA256: strings.Repeat("2", 64),
		ProfileSHA256: strings.Repeat("3", 64), SchemaSHA256: strings.Repeat("4", 64),
		Clusters: spec.Route.Clusters, Slots: spec.Route.Slots, Predictors: spec.Route.Predictors}
	plan.Numeric.Slots, plan.Numeric.GridBits = plan.Slots, spec.GLMM.GridBits
	plan.Numeric.OutputCap = "2000"
	if family == "poisson" {
		plan.Numeric.Family, plan.Numeric.MaxOutcome = "poisson", "4"
	}
	plan.VarianceGrid = []string{"0", "16384"}
	for _, row := range spec.GLMM.Beta {
		beta := []string{}
		for _, coefficient := range row {
			beta = append(beta, coefficient.String())
		}
		plan.Beta = append(plan.Beta, beta)
	}
	for _, cap := range spec.GLMM.Caps {
		plan.Caps = append(plan.Caps, big.NewInt(cap).String())
	}
	key := crossGridStageTestKey(0)
	input := groupedGLMMPrepareWireInput{Role: "garbler", Session: spec.Session, Authorities: spec.Authorities,
		SemanticKey: hex.EncodeToString(spec.SemanticKey[:]), StoreDirectory: filepath.Join(t.TempDir(), "durable"),
		StoreKey: base64.StdEncoding.EncodeToString(key[:]), Handoff: groupedGLMMSourceWireHandoff{Plan: plan}}
	input.Routing = &struct {
		Labels  []int  `json:"labels"`
		Present []bool `json:"present"`
	}{sidecar.Labels, sidecar.Present}
	encode := func(out crossGridStageOutput) groupedGLMMSourceWireOutput {
		return groupedGLMMSourceWireOutput{base64.StdEncoding.EncodeToString(out.Share), base64.StdEncoding.EncodeToString(out.Validity)}
	}
	input.Handoff.Numeric, input.Handoff.Outcome, input.Handoff.Metadata = encode(sources[0].Numeric), encode(sources[0].Outcome), encode(sources[0].Metadata)
	worker, err := groupedGLMMPrepareWire(input)
	if err != nil {
		t.Fatal(err)
	}
	if worker.Spec.GLMM.family() != spec.GLMM.family() || worker.Spec.GLMM.maxOutcome() != spec.GLMM.maxOutcome() {
		t.Fatal("wire lost family/outcome contract")
	}
	raw, err := json.Marshal(worker)
	if err != nil {
		t.Fatal(err)
	}
	var restored groupedGLMMWorkerInput
	if json.Unmarshal(raw, &restored) != nil || restored.Spec.GLMM.VarianceGrid[1] != 16384 ||
		groupedGLMMWorkerPurpose(restored.Spec) != groupedGLMMWorkerPurpose(worker.Spec) {
		t.Fatal("opaque worker handoff changed numeric contract")
	}
	for _, bad := range []string{"18447025548686262272.0", "1.8447025548686262e19", "+18447025548686262272", "018447025548686262272"} {
		changed := input
		changed.Handoff.Plan.Numeric.OutputCap = bad
		if _, err := groupedGLMMPrepareWire(changed); err == nil {
			t.Fatalf("accepted noncanonical integer %q", bad)
		}
	}
	for _, bad := range []string{"", "0", "5", "4.0", "+4", "04"} {
		changed := input
		changed.Handoff.Plan.Numeric.Family = "poisson"
		changed.Handoff.Plan.Numeric.MaxOutcome = bad
		if _, err := groupedGLMMPrepareWire(changed); err == nil {
			t.Fatalf("accepted bad maximum %q", bad)
		}
	}
	changed := input
	changed.Handoff.Plan.Numeric.OutputCap = "2001"
	if _, err := groupedGLMMPrepareWire(changed); err == nil {
		t.Fatal("accepted inconsistent redundant output cap")
	}
	changed = input
	changed.Handoff.Metadata.Share = input.Handoff.Numeric.Share
	if _, err := groupedGLMMPrepareWire(changed); err == nil {
		t.Fatal("accepted wrong metadata shape")
	}
	changed = input
	changed.Role = "evaluator"
	if _, err := groupedGLMMPrepareWire(changed); err == nil {
		t.Fatal("provided owner labels to evaluator")
	}
}
