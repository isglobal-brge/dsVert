package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func groupedGEEWireFixture(t *testing.T, family string, role exactGCRole) groupedGEEPrepareWireInput {
	t.Helper()
	spec, sources, sidecar, _ := groupedGEESourceFixture(t, family)
	n := spec.Numeric
	plan := groupedGEESourceWirePlan{Version: "dsvert-gee-fixed-rho-staged-source-handoff-v1",
		SpecSHA256: strings.Repeat("1", 64), SourceContractSHA256: strings.Repeat("2", 64),
		ProfileSHA256: strings.Repeat("3", 64), SchemaSHA256: strings.Repeat("4", 64),
		Clusters: spec.Route.Clusters, Slots: spec.Route.Slots, Predictors: spec.Route.Predictors,
		CorrelationContract: spec.CorrelationContract}
	plan.Numeric.Family, plan.Numeric.Correlation = n.Family, n.Correlation
	plan.Numeric.Slots, plan.Numeric.Predictors, plan.Numeric.GridBits = n.Slots, n.Predictors, n.GridBits
	plan.Numeric.RhoQ16 = big.NewInt(n.RhoQ16).String()
	plan.Numeric.ScoreClipQ16 = big.NewInt(n.ScoreClipQ16).String()
	plan.Numeric.RowLossCap = big.NewInt(n.RowLossCap).String()
	plan.Numeric.BreadCap = big.NewInt(n.BreadCap).String()
	plan.Numeric.MaxOutcome = big.NewInt(n.MaxOutcome).String()
	for _, row := range spec.Beta {
		var beta []string
		for _, b := range row {
			beta = append(beta, b.String())
		}
		plan.Beta = append(plan.Beta, beta)
	}
	for _, cap := range spec.Caps {
		plan.Caps = append(plan.Caps, big.NewInt(cap).String())
	}
	key := crossGridStageTestKey(role)
	input := groupedGEEPrepareWireInput{Role: []string{"garbler", "evaluator"}[role], Session: spec.Session, Authorities: spec.Authorities,
		SemanticKey: hex.EncodeToString(spec.SemanticKey[:]), StoreDirectory: filepath.Join(t.TempDir(), "durable"), StoreKey: base64.StdEncoding.EncodeToString(key[:]),
		Handoff: groupedGEESourceWireHandoff{Plan: plan}}
	if role == exactGCRoleGarbler {
		input.Routing = &struct {
			Labels  []int  `json:"labels"`
			Present []bool `json:"present"`
		}{sidecar.Labels, sidecar.Present}
	}
	encode := func(out crossGridStageOutput) groupedGEESourceWireOutput {
		return groupedGEESourceWireOutput{base64.StdEncoding.EncodeToString(out.Share), base64.StdEncoding.EncodeToString(out.Validity)}
	}
	input.Handoff.Numeric, input.Handoff.Outcome, input.Handoff.Metadata = encode(sources[role].Numeric), encode(sources[role].Outcome), encode(sources[role].Metadata)
	return input
}

func TestGroupedGEEExactSourceWire(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		t.Run(family, func(t *testing.T) {
			var plans [2][32]byte
			for role := exactGCRoleGarbler; role <= exactGCRoleEvaluator; role++ {
				in := groupedGEEWireFixture(t, family, role)
				// Exercise an exactly represented f50 coefficient whose bits must survive JSON.
				in.Handoff.Plan.Beta[0][0] = "1125899906842623"
				worker, err := groupedGEEPrepareWire(in)
				if err != nil {
					t.Fatal(err)
				}
				if worker.Spec.Numeric.Family != family || worker.Spec.Beta[0][0].String() != in.Handoff.Plan.Beta[0][0] {
					t.Fatal("wire changed exact family/coefficients")
				}
				raw, err := json.Marshal(worker)
				if err != nil {
					t.Fatal(err)
				}
				var restored groupedGEEWorkerInput
				if json.Unmarshal(raw, &restored) != nil || !reflect.DeepEqual(worker, &restored) {
					t.Fatal("opaque handoff changed native inputs")
				}
				key := crossGridStageTestKey(role)
				graph, err := groupedGEEBuildSourceGraph(restored.Spec, role, restored.Source, restored.Routing, key)
				if err != nil {
					t.Fatal(err)
				}
				plans[role] = crossGridStageHash("public-plan", graph.Graph)
				last := graph.Graph.Stages[len(graph.Graph.Stages)-1]
				want := len(in.Handoff.Plan.Beta) * (1 + (in.Handoff.Plan.Predictors+1)*(in.Handoff.Plan.Predictors+2))
				if last.Ring != 128 || len(last.CoordOrder) != want {
					t.Fatal("dropped GEE bread/meat terminal coordinates")
				}
			}
			if plans[0] != plans[1] {
				t.Fatal("roles constructed different public plans")
			}
		})
	}
}

func TestGroupedGEEExactSourceWireRejects(t *testing.T) {
	for _, change := range []string{"decimal", "exponent", "plus", "leading-zero", "overflow", "alpha", "family", "max-outcome", "shape", "validity", "digest", "beta", "caps", "evaluator-routing"} {
		t.Run(change, func(t *testing.T) {
			in := groupedGEEWireFixture(t, "binomial", 0)
			switch change {
			case "decimal":
				in.Handoff.Plan.Numeric.RowLossCap = "65536.0"
			case "exponent":
				in.Handoff.Plan.Numeric.RowLossCap = "1e6"
			case "plus":
				in.Handoff.Plan.Numeric.RhoQ16 = "+0"
			case "leading-zero":
				in.Handoff.Plan.Numeric.RhoQ16 = "00"
			case "overflow":
				in.Handoff.Plan.Numeric.BreadCap = "9223372036854775808"
			case "alpha":
				in.Handoff.Plan.CorrelationContract = "moment-estimated-alpha"
			case "family":
				in.Handoff.Plan.Numeric.Family = "binomial_glmm"
			case "max-outcome":
				in.Handoff.Plan.Numeric.MaxOutcome = "4"
			case "shape":
				in.Handoff.Metadata.Share = in.Handoff.Numeric.Share
			case "validity":
				raw, _ := base64.StdEncoding.DecodeString(in.Handoff.Numeric.Validity)
				raw[0] = 2
				in.Handoff.Numeric.Validity = base64.StdEncoding.EncodeToString(raw)
			case "digest":
				in.Handoff.Plan.ProfileSHA256 = strings.Repeat("0", 64)
			case "beta":
				in.Handoff.Plan.Beta[0][0] = "-0"
			case "caps":
				in.Handoff.Plan.Caps = in.Handoff.Plan.Caps[:1]
			case "evaluator-routing":
				in.Role = "evaluator"
			}
			if _, err := groupedGEEPrepareWire(in); err == nil {
				t.Fatal("accepted invalid GEE handoff")
			}
		})
	}
}
