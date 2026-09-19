package main

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// Match the signed R smoke fixture: two four-slot clusters, one predictor,
// three beta candidates, and two variance pairs. Admission remains independent
// of the private live pattern; these opaque source records contain no live rows.
func TestGroupedLMMMLExactSourceWireGraph(t *testing.T) {
	plan := groupedLMMSourceWirePlan{Version: "dsvert-lmm-staged-source-handoff-v1",
		SpecSHA256: strings.Repeat("1", 64), SourceContractSHA256: strings.Repeat("2", 64),
		ProfileSHA256: strings.Repeat("3", 64), SchemaSHA256: strings.Repeat("4", 64),
		Clusters: 2, Slots: 4, Predictors: 1, Objective: "ml",
		Beta: [][]string{{"-281474976710656", "562949953421312"}, {"0", "0"}, {"281474976710656", "562949953421312"}},
		Caps: []string{"4784129", "4194305", "3735553", "3555329", "3407873", "3293185"}}
	plan.Numeric.Slots, plan.Numeric.GridBits, plan.Numeric.ResidualCap = 4, 16, 2
	plan.Numeric.Sigma2Q64, plan.Numeric.Tau2Q64, plan.Numeric.OutputCap = "4611686018427387904", "0", "4784129"
	plan.VarianceGrid = []struct{ Sigma2Q64, Tau2Q64 string }{
		{"4611686018427387904", "0"}, {"18446744073709551616", "4611686018427387904"},
	}
	key := crossGridStageTestKey(0)
	block := func(columns int) groupedLMMSourceWireOutput {
		validity := make([]byte, 8*columns)
		for i := range validity {
			validity[i] = 1
		}
		return groupedLMMSourceWireOutput{base64.StdEncoding.EncodeToString(make([]byte, 16*len(validity))),
			base64.StdEncoding.EncodeToString(validity)}
	}
	input := groupedLMMPrepareWireInput{Role: "garbler", Session: "lmm-ml-signed-wire-test",
		Authorities: [2]string{"authority-a", "authority-b"}, SemanticKey: strings.Repeat("5", 64),
		StoreDirectory: filepath.Join(t.TempDir(), "durable"), StoreKey: base64.StdEncoding.EncodeToString(key[:]),
		Handoff: groupedLMMSourceWireHandoff{Plan: plan, Numeric: block(2), Metadata: block(4)}}
	input.Routing = &struct {
		Labels  []int  `json:"labels"`
		Present []bool `json:"present"`
	}{make([]int, 8), make([]bool, 8)}
	worker, err := groupedLMMPrepareWire(input)
	if err != nil {
		t.Fatalf("signed ML wire admission: %v", err)
	}
	graph, err := groupedLMMBuildSourceGraph(worker.Spec, 0, worker.Source, worker.Routing, key)
	if err != nil {
		t.Fatalf("signed ML source graph: %v", err)
	}
	terminal := graph.Graph.Stages[len(graph.Graph.Stages)-1]
	want := []string{"variance:0:candidate:0", "variance:0:candidate:1", "variance:0:candidate:2",
		"variance:1:candidate:0", "variance:1:candidate:1", "variance:1:candidate:2"}
	if terminal.ID != "lmm.terminal" || len(terminal.CoordOrder) != len(want) {
		t.Fatal("ML handoff lost variance-major coordinates")
	}
	for i := range want {
		if terminal.CoordOrder[i] != want[i] {
			t.Fatalf("coordinate %d: got %q, want %q", i, terminal.CoordOrder[i], want[i])
		}
	}
	raw, err := json.Marshal(worker)
	var restored groupedLMMWorkerInput
	if err != nil || json.Unmarshal(raw, &restored) != nil {
		t.Fatal("opaque ML worker round trip failed")
	}
	replayed, err := groupedLMMBuildSourceGraph(restored.Spec, 0, restored.Source, restored.Routing, key)
	if err != nil || crossGridStageHash("public-plan", replayed.Graph) != crossGridStageHash("public-plan", graph.Graph) {
		t.Fatal("opaque ML wire round trip changed the exact stage plan")
	}
	// V*K is checked after exact native decoding; the old K-wide ABI cannot
	// silently select or truncate one variance branch.
	input.Handoff.Plan.Caps = input.Handoff.Plan.Caps[:3]
	if _, err := groupedLMMPrepareWire(input); err == nil {
		t.Fatal("accepted K caps for a V*K ML workload")
	}
}
