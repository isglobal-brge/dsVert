package main

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"
)

func TestCoxGridCrossSourceAuthentication(t *testing.T) {
	cap, err := coxLossCap(4, 12, []float64{4, 4})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := registerCoxGridCrossLoss().SharedPlan(coxLossSpec{4, 2, 12, []uint64{cap, cap}, CoxGridCrossProfileID})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("synthetic source contract"))
	s := coxLossSourceSpec{Session: "cox-source-auth-test", Authorities: [2]string{"a", "b"}, SchemaDigest: digest, SemanticKey: digest, Cox: coxLossStagedSpec{Plan: plan, Prefix: "cox.auth", SourceDigest: digest, Contract: digest}}
	var values [2]crossGridStageOutput
	for i := range values {
		coords := make([]string, 8)
		for j := range coords {
			coords[j] = fmt.Sprintf("source/%d/%d", i, j)
		}
		s.Cox.Sources[i] = crossGridStagePlan{ID: fmt.Sprintf("source.%d", i), Kind: "test.source", Ring: 128, FPScale: []int{100, 0}[i], CoordOrder: coords, PublicBounds: map[string]int{"rows": 4}, SourceDigest: digest, ProfileDigest: digest}
		values[i] = crossGridStageOutput{Share: make([]byte, 128), Validity: make([]byte, 8)}
	}
	key := sha256.Sum256([]byte("owner source key"))
	controls, err := primitiveVPermutationControls([]int{1, 0, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	side, err := coxLossSealStagedRouting(s.Cox, controls, []bool{true, true, true, true}, key)
	if err != nil {
		t.Fatal(err)
	}
	s.Cox.RoutingDigest = side.MAC
	source, err := coxLossSealSource(s, exactGCRoleGarbler, values[0], values[1], key)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := coxLossBuildSourceGraph(s, exactGCRoleGarbler, source, side, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Graph.Stages) != 3 || graph.Graph.Stages[2].Ring != 128 || graph.Graph.Stages[2].FPScale != 12 {
		t.Fatal("typed authenticated graph")
	}
	// Tampering either data or validity in either source record rejects before MPC.
	for _, field := range []string{"predictors", "live-event"} {
		for _, flag := range []bool{false, true} {
			t.Run(fmt.Sprintf("tamper/%s/validity-%v", field, flag), func(t *testing.T) {
				changed := *source
				changed.Predictors = crossGridStageClone(source.Predictors)
				changed.LiveEvent = crossGridStageClone(source.LiveEvent)
				value := &changed.Predictors
				if field == "live-event" {
					value = &changed.LiveEvent
				}
				if flag {
					value.Validity[0] ^= 1
				} else {
					value.Share[0] ^= 1
				}
				if _, err := coxLossBuildSourceGraph(s, exactGCRoleGarbler, &changed, side, key); err == nil {
					t.Fatal("tampered source accepted")
				}
			})
		}
	}
	if _, err := coxLossBuildSourceGraph(s, exactGCRoleEvaluator, source, nil, key); err == nil {
		t.Fatal("cross-role replacement")
	}
	if _, err := coxLossBuildSourceGraph(s, exactGCRoleGarbler, source, side, sha256.Sum256([]byte("wrong local key"))); err == nil {
		t.Fatal("wrong local key")
	}
	for _, mutate := range []func(*coxLossSourceSpec){
		func(v *coxLossSourceSpec) { v.Session += "-other" }, func(v *coxLossSourceSpec) { v.Authorities[1] = "other" }, func(v *coxLossSourceSpec) { v.SemanticKey[0] ^= 1 }, func(v *coxLossSourceSpec) { v.SchemaDigest[0] ^= 1 }, func(v *coxLossSourceSpec) { v.Cox.SourceDigest[0] ^= 1 }, func(v *coxLossSourceSpec) { v.Cox.Contract[0] ^= 1 }, func(v *coxLossSourceSpec) { v.Cox.RoutingDigest[0] ^= 1 }, func(v *coxLossSourceSpec) { v.Cox.Plan.Spec.GridBits = 13 },
	} {
		changed := s
		mutate(&changed)
		if _, err := coxLossBuildSourceGraph(changed, exactGCRoleGarbler, source, side, key); err == nil {
			t.Fatal("cross-contract source replacement")
		}
	}
	// Seal and graph compilation both freeze caller-owned buffers.
	source.Predictors.Share[0] = 99
	values[0].Share[0] = 77
	s.Cox.Sources[0].CoordOrder[0] = "caller-mutated"
	got, err := graph.Compute[0](nil, crossGridStageAttempt{}, nil)
	if err != nil || got.Share[0] != 0 || !reflect.DeepEqual(graph.Graph.Stages[0].CoordOrder[0], "source/0/0") {
		t.Fatal("caller mutation changed pinned source", err)
	}
	got.Share[0] = 88
	again, err := graph.Compute[0](nil, crossGridStageAttempt{}, nil)
	if err != nil || again.Share[0] != 0 {
		t.Fatal("replay source clone was mutable")
	}
}
