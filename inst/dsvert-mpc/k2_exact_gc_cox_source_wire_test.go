package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestCoxLossExactSourceWire(t *testing.T) {
	key := crossGridStageTestKey(0)
	cap, err := coxLossCap(4, 12, []float64{4, 4})
	if err != nil {
		t.Fatal(err)
	}
	input := coxLossPrepareWireInput{Role: "garbler", Session: "cox-wire-test", Authorities: [2]string{"a", "b"}, SemanticKey: strings.Repeat("5", 64), StoreDirectory: t.TempDir(), StoreKey: base64.StdEncoding.EncodeToString(key[:]), Handoff: coxLossSourceWireHandoff{Plan: coxLossSourceWirePlan{Version: "dsvert-cox-staged-source-handoff-v1", SpecSHA256: strings.Repeat("1", 64), SourceContractSHA256: strings.Repeat("2", 64), ProfileSHA256: strings.Repeat("3", 64), SchemaSHA256: strings.Repeat("4", 64), Capacity: 4, GridBits: 12, Caps: []string{fmt.Sprint(cap), fmt.Sprint(cap)}}}}
	input.Routing = &struct {
		Permutation []int  `json:"permutation"`
		Ends        []bool `json:"ends"`
	}{[]int{1, 0, 2, 3}, []bool{false, true, true, true}}
	wire := coxLossSourceWireOutput{base64.StdEncoding.EncodeToString(make([]byte, 128)), base64.StdEncoding.EncodeToString(make([]byte, 8))}
	input.Handoff.Predictors, input.Handoff.LiveEvent = wire, wire
	worker, err := coxLossPrepareWire(input)
	if err != nil {
		t.Fatal(err)
	}
	if worker.Spec.Cox.Sources[0].FPScale != 100 || worker.Spec.Cox.Sources[1].FPScale != 0 {
		t.Fatal("source scales lost")
	}
	raw, err := json.Marshal(worker)
	if err != nil {
		t.Fatal(err)
	}
	var restored coxLossWorkerInput
	if json.Unmarshal(raw, &restored) != nil || !reflect.DeepEqual(worker, &restored) {
		t.Fatal("opaque worker round trip")
	}
	evaluator := input
	evaluator.Role = "evaluator"
	evaluator.Routing = nil
	evaluator.RoutingDigest = hex.EncodeToString(worker.Spec.Cox.RoutingDigest[:])
	other, err := coxLossPrepareWire(evaluator)
	if err != nil || !reflect.DeepEqual(worker.Spec, other.Spec) || coxLossWorkerPurpose(worker.Spec) != coxLossWorkerPurpose(other.Spec) {
		t.Fatal("authorities disagree on public graph", err)
	}
	tests := map[string]func(*coxLossPrepareWireInput){
		"fractional cap":       func(v *coxLossPrepareWireInput) { v.Handoff.Plan.Caps = []string{"100.0", "100"} },
		"exponent cap":         func(v *coxLossPrepareWireInput) { v.Handoff.Plan.Caps = []string{"1e2", "100"} },
		"padded cap":           func(v *coxLossPrepareWireInput) { v.Handoff.Plan.Caps = []string{"0100", "100"} },
		"negative cap":         func(v *coxLossPrepareWireInput) { v.Handoff.Plan.Caps = []string{"-1", "100"} },
		"overflow cap":         func(v *coxLossPrepareWireInput) { v.Handoff.Plan.Caps = []string{"18446744073709551616", "100"} },
		"missing routing":      func(v *coxLossPrepareWireInput) { v.Routing = nil },
		"evaluator routing":    func(v *coxLossPrepareWireInput) { v.Role = "evaluator" },
		"wrong routing digest": func(v *coxLossPrepareWireInput) { v.RoutingDigest = strings.Repeat("a", 64) },
		"share width": func(v *coxLossPrepareWireInput) {
			v.Handoff.Predictors.Share = base64.StdEncoding.EncodeToString(make([]byte, 127))
		},
		"invalid validity": func(v *coxLossPrepareWireInput) {
			v.Handoff.LiveEvent.Validity = base64.StdEncoding.EncodeToString([]byte{2, 0, 0, 0, 0, 0, 0, 0})
		},
		"repeated authority": func(v *coxLossPrepareWireInput) { v.Authorities[1] = v.Authorities[0] },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := input
			mutate(&changed)
			if _, err := coxLossPrepareWire(changed); err == nil {
				t.Fatal("accepted malformed handoff")
			}
		})
	}
	t.Run("private-complete-case-v2", func(t *testing.T) {
		v2 := input
		v2.Handoff.Plan.Version = "dsvert-cox-staged-source-handoff-v2"
		v2.Handoff.Plan.PresenceColumns = 4
		v2.Handoff.LiveEvent = coxLossSourceWireOutput{base64.StdEncoding.EncodeToString(make([]byte, 16*4*5)), base64.StdEncoding.EncodeToString(make([]byte, 4*5))}
		owner, err := coxLossPrepareWire(v2)
		if err != nil {
			t.Fatal(err)
		}
		graph, err := coxLossBuildSourceGraph(owner.Spec, 0, owner.Source, owner.Routing, key)
		if err != nil || len(graph.Graph.Stages) != 4 {
			t.Fatal("complete-case graph missing", err)
		}
		if graph.Graph.Stages[2].Kind != "cox.private-complete-case" || graph.Graph.Stages[3].Predecessors[1] != graph.Graph.Stages[2].ID {
			t.Fatal("Cox arithmetic bypassed private composition")
		}
		v2.Role, v2.Routing, v2.RoutingDigest = "evaluator", nil, hex.EncodeToString(owner.Spec.Cox.RoutingDigest[:])
		peer, err := coxLossPrepareWire(v2)
		if err != nil || !reflect.DeepEqual(owner.Spec, peer.Spec) {
			t.Fatal("v2 public graph disagreement", err)
		}
		if coxLossWorkerPurpose(owner.Spec) == coxLossWorkerPurpose(worker.Spec) {
			t.Fatal("v2 reused v1 purpose")
		}
		bad := owner.Spec
		bad.PresenceColumns++
		if _, err := coxLossBuildSourceGraph(bad, 0, owner.Source, owner.Routing, key); err == nil {
			t.Fatal("presence shape substitution")
		}
		v2.Handoff.Plan.Version = "dsvert-cox-staged-source-handoff-v1"
		if _, err := coxLossPrepareWire(v2); err == nil {
			t.Fatal("v2 metadata accepted as v1 live/event")
		}
	})
}
