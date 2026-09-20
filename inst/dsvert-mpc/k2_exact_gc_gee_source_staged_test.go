package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func groupedGEESourceFixture(t *testing.T, family string) (groupedGEESourceSpec, [2]*groupedGEESourceRecord, *groupedRouteSidecar, [][]*big.Int) {
	old, raw, side, routed := groupedGLMMSourceFixture(t, family)
	numeric := groupedGEEStagedTestSpec(family).Numeric
	numeric.Slots = old.Route.Slots
	s := groupedGEESourceSpec{Session: "gee-fixed-rho-source-test", Authorities: old.Authorities, SchemaDigest: old.SchemaDigest, SemanticKey: old.SemanticKey, Contract: sha256.Sum256([]byte("signed GEE fixed-rho predecessor")), Route: old.Route, Numeric: numeric, Beta: old.GLMM.Beta, Caps: []int64{100000000, 100000000}, CorrelationContract: "signed-fixed-rho-v3-predecessor"}
	s.Route.NumericStage, s.Route.MetadataStage = "gee.source.normalized", "gee.source.metadata"
	s.Route.ProfileDigest = s.Contract
	s.Route.OutcomeBound = new(big.Int).Lsh(big.NewInt(s.Numeric.MaxOutcome), 50)
	var records [2]*groupedGEESourceRecord
	for role := range records {
		var err error
		records[role], err = groupedGEESealSource(s, exactGCRole(role), raw[role].Numeric, raw[role].Outcome, raw[role].Metadata, crossGridStageTestKey(exactGCRole(role)))
		if err != nil {
			t.Fatal(err)
		}
	}
	route, err := groupedRouteSeal(s.Route, side.Labels, side.Present, crossGridStageTestKey(0))
	if err != nil {
		t.Fatal(err)
	}
	return s, records, route, routed
}

func groupedGEESourceOracle(t *testing.T, s groupedGEESourceSpec, routed [][]*big.Int) []int64 {
	t.Helper()
	width := 1 + (s.Numeric.Predictors+1)*(s.Numeric.Predictors+2)
	want := make([]int64, width*len(s.Beta))
	for candidate, beta := range s.Beta {
		for cluster := 0; cluster < s.Route.Clusters; cluster++ {
			rows := make([]groupedGEERow, s.Numeric.Slots)
			for row := range rows {
				r := routed[cluster*s.Numeric.Slots+row]
				dot := new(big.Int)
				for j, b := range beta {
					dot.Add(dot, new(big.Int).Mul(r[j], b))
				}
				rows[row] = groupedGEERow{EtaQ64: primitiveVRoundDivReference(dot, new(big.Int).Lsh(big.NewInt(1), 36)), FeaturesF50: r[1 : len(r)-1], Outcome: new(big.Int).Rsh(new(big.Int).Set(r[len(r)-1]), 50).Int64(), Live: new(big.Int).Rsh(new(big.Int).Set(r[0]), 50).Int64()}
			}
			values, ok := groupedGEEWhiteningOracle(s.Numeric, rows, s.Caps[candidate])
			if !ok {
				t.Fatal("independent source oracle rejected fixture")
			}
			for j, v := range values {
				want[candidate*width+j] += v
			}
		}
	}
	return want
}

func TestGroupedGEESourceContract(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		s, records, side, _ := groupedGEESourceFixture(t, family)
		graph, err := groupedGEEBuildSourceGraph(s, 0, records[0], side, crossGridStageTestKey(0))
		if err != nil {
			t.Fatal(err)
		}
		routes, lifts := 0, 0
		for _, stage := range graph.Graph.Stages {
			if stage.ID == "grouped.route.output" {
				routes++
			}
			if stage.ID == "gee.source.ring192" {
				lifts++
			}
		}
		if routes != 1 || lifts != 1 || graph.Graph.Stages[len(graph.Graph.Stages)-1].Ring != 128 {
			t.Fatal("source routing/conversion repeated by candidate")
		}
		for _, change := range []string{"family", "alpha", "feature-bound", "outcome-bound", "beta", "source-tamper"} {
			raw, _ := json.Marshal(s)
			var bad groupedGEESourceSpec
			json.Unmarshal(raw, &bad)
			record := *records[0]
			switch change {
			case "family":
				bad.Numeric.Family = "poisson"
				if family == "poisson" {
					bad.Numeric.Family = "binomial"
				}
				bad.Numeric.MaxOutcome = 1
				bad.Route.OutcomeBound = new(big.Int).Lsh(big.NewInt(1), 50)
				if _, err := groupedGEESourcePlans(bad); err != nil {
					t.Fatal("cross-family replacement fixture must be valid", err)
				}
			case "alpha":
				bad.CorrelationContract = "moment-estimated-alpha"
			case "feature-bound":
				bad.Route.NumericBound.Lsh(big.NewInt(4), 50)
			case "outcome-bound":
				bad.Route.OutcomeBound.Add(bad.Route.OutcomeBound, big.NewInt(1))
			case "beta":
				bad.Beta[0][0].Lsh(big.NewInt(5), 50)
			case "source-tamper":
				record.Outcome = crossGridStageClone(record.Outcome)
				record.Outcome.Share[0] ^= 1
			}
			if _, err := groupedGEEBuildSourceGraph(bad, 0, &record, side, crossGridStageTestKey(0)); err == nil {
				t.Fatalf("accepted %s", change)
			}
		}
	}
}

func TestGroupedGEESourceTwoAuthority(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		t.Run(family, func(t *testing.T) { groupedGEESourceGraphRunTest(t, family) })
	}
}

func groupedGEESourceGraphRunTest(t *testing.T, family string) {
	// This is the complete internal source/router/conversion/arithmetic path;
	// it is intentionally not labelled a DSLite release or promotion proof.
	s, sources, sidecar, routed := groupedGEESourceFixture(t, family)
	graphs := [2]*groupedGEESourceGraph{}
	for role := range graphs {
		local := sidecar
		if role == 1 {
			local = nil
		}
		var err error
		graphs[role], err = groupedGEEBuildSourceGraph(s, exactGCRole(role), sources[role], local, crossGridStageTestKey(exactGCRole(role)))
		if err != nil {
			t.Fatal(err)
		}
	}
	if crossGridStageHash("test", graphs[0].Graph) != crossGridStageHash("test", graphs[1].Graph) {
		t.Fatal("private routing state changed public graph")
	}
	for _, scenario := range []string{"fresh", "conversion-abort", "routing-unilateral", "source-invalid", "outcome-invalid", "outcome-high-alias"} {
		t.Run(scenario, func(t *testing.T) {
			localGraphs := graphs
			if scenario == "source-invalid" || scenario == "outcome-invalid" || scenario == "outcome-high-alias" {
				bad := *sources[1]
				if scenario == "source-invalid" {
					bad.Metadata = crossGridStageClone(bad.Metadata)
					bad.Metadata.Validity[0] ^= 1
				} else {
					bad.Outcome = crossGridStageClone(bad.Outcome)
					value := getUint128LE(bad.Outcome.Share[16:32]).ToBig()
					delta := big.NewInt(1)
					if scenario == "outcome-high-alias" {
						delta.Lsh(delta, 64)
					}
					value.Add(value, delta)
					putUint128LE(bad.Outcome.Share[16:32], U128FromBig(value))
				}
				bad.MAC = groupedGEESourceMAC(crossGridStageTestKey(1), bad)
				var err error
				localGraphs[1], err = groupedGEEBuildSourceGraph(s, 1, &bad, nil, crossGridStageTestKey(1))
				if err != nil {
					t.Fatal(err)
				}
			}
			dirs := [2]string{filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")}
			type result struct {
				out []crossGridStageOutput
				err error
			}
			run := func(interrupt, cold bool) [2]result {
				stores := [2]*crossGridStageStore{}
				for role := range stores {
					var err error
					stores[role], err = crossGridStageOpenStore(dirs[role], crossGridStageTestKey(exactGCRole(role)), localGraphs[role].Graph, exactGCRole(role))
					if err != nil {
						t.Fatal(err)
					}
					defer stores[role].Close()
				}
				a, b := net.Pipe()
				defer a.Close()
				defer b.Close()
				a.SetDeadline(time.Now().Add(3 * time.Minute))
				b.SetDeadline(time.Now().Add(3 * time.Minute))
				base := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 192, VectorLen: 1})
				endpoints := [2]net.Conn{a, b}
				results := [2]chan result{make(chan result, 1), make(chan result, 1)}
				for role := range stores {
					go func(role int) {
						executor := crossGridStageExecutor{Store: stores[role], Base: base}
						if interrupt {
							executor.fault = func(event string, record crossGridStageRecord) error {
								if scenario == "conversion-abort" && role == 0 && record.StageID == "gee.source.ring192" && event == "after-compute" ||
									scenario == "routing-unilateral" && role == 1 && record.StageID == "grouped.route.output" && event == "after-prepare-exchange" {
									return errors.New("injected composed GEE interruption")
								}
								return nil
							}
						}
						kernels := localGraphs[role].Compute
						if cold {
							kernels = make([]crossGridStageCompute, len(kernels))
							for i := range kernels {
								kernels[i] = func(io.ReadWriter, crossGridStageAttempt, []crossGridStageOutput) (crossGridStageOutput, error) {
									return crossGridStageOutput{}, errors.New("cold replay recomputed source, route or arithmetic")
								}
							}
						}
						out, err := executor.Execute(endpoints[role], kernels)
						endpoints[role].Close()
						results[role] <- result{out, err}
					}(role)
				}
				return [2]result{<-results[0], <-results[1]}
			}
			if scenario == "conversion-abort" || scenario == "routing-unilateral" {
				stopped := run(true, false)
				if stopped[0].err == nil || stopped[1].err == nil {
					t.Fatal("interruption was not observed bilaterally")
				}
			}
			out := run(false, false)
			if out[0].err != nil || out[1].err != nil {
				t.Fatalf("composed GEE: %v / %v", out[0].err, out[1].err)
			}
			if scenario != "source-invalid" && scenario != "outcome-invalid" && scenario != "outcome-high-alias" {
				for stage, abi := range localGraphs[0].Graph.Stages {
					for coordinate := range out[0].out[stage].Validity {
						if out[0].out[stage].Validity[coordinate]^out[1].out[stage].Validity[coordinate] != 1 {
							t.Fatalf("first invalid stage %s coordinate %d", abi.ID, coordinate)
						}
					}
				}
			}
			cold := run(false, true)
			for role := range out {
				if cold[role].err != nil || len(cold[role].out) != len(out[role].out) {
					t.Fatalf("cold replay: %v", cold[role].err)
				}
				for i := range out[role].out {
					if !bytes.Equal(out[role].out[i].Share, cold[role].out[i].Share) || !bytes.Equal(out[role].out[i].Validity, cold[role].out[i].Validity) {
						t.Fatal("cold replay changed a private stage")
					}
				}
			}
			last := len(out[0].out) - 1
			expected := groupedGEESourceOracle(t, s, routed)
			for coordinate, value := range expected {
				a, b := out[0].out[last], out[1].out[last]
				got := getUint128LE(a.Share[16*coordinate : 16*(coordinate+1)]).Add(getUint128LE(b.Share[16*coordinate : 16*(coordinate+1)])).ToBig()
				valid := byte(1)
				if scenario == "source-invalid" || scenario == "outcome-invalid" || scenario == "outcome-high-alias" {
					value = 0
					valid = 0
				}
				if got.Cmp(big.NewInt(value)) != 0 || a.Validity[coordinate]^b.Validity[coordinate] != valid {
					t.Fatalf("coordinate %d got=%s want=%d valid=%d", coordinate, got, value, a.Validity[coordinate]^b.Validity[coordinate])
				}
			}
		})
	}
}
