package main

import (
	"bytes"
	"crypto/rand"
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

func groupedLMMSourceFixture(t *testing.T) (groupedLMMSourceSpec, [2]*groupedLMMSourceRecord, *groupedRouteSidecar, [][]*big.Int) {
	t.Helper()
	lmm := groupedLMMStagedTestSpec()
	lmm.RoutedStage = "lmm.source.ring192"
	s := groupedLMMSourceSpec{Session: "authenticated-lmm-source-test",
		Authorities: [2]string{"peer-a-pinned-key", "peer-b-pinned-key"}, SchemaDigest: sha256.Sum256([]byte("signed LMM schema")),
		SemanticKey: sha256.Sum256([]byte("sticky LMM release")), LMM: lmm,
		Route: groupedRouteStagedSpec{Clusters: 2, Slots: 2, Predictors: 1,
			Nonnegative:  true,
			NumericStage: "lmm.source.numeric", MetadataStage: "lmm.source.metadata",
			SourceDigest: lmm.SourceDigest, ProfileDigest: lmm.ProfileDigest,
			NumericBound: new(big.Int).Lsh(big.NewInt(1), 50)}}
	f := new(big.Int).Lsh(big.NewInt(1), 50)
	value := func(divisor int64) *big.Int { return new(big.Int).Quo(new(big.Int).Set(f), big.NewInt(divisor)) }
	// Labels are deliberately out of cluster order. Row zero is missing y,
	// and must retain cluster one's original slot zero after complete-casing.
	numbers := []*big.Int{value(3), new(big.Int), value(7), value(3), value(5), value(7), value(9), value(5)}
	metadata := []*big.Int{}
	labels := []int{1, 0, 1, 0}
	for row, label := range labels {
		yp := int64(1)
		if row == 0 {
			yp = 0
		}
		metadata = append(metadata, big.NewInt(1), big.NewInt(yp), big.NewInt(int64(label)), big.NewInt(1))
	}
	split := func(values []*big.Int) [2]crossGridStageOutput {
		out := [2]crossGridStageOutput{}
		for _, v := range values {
			mask := make([]byte, 16)
			if _, err := io.ReadFull(rand.Reader, mask); err != nil {
				t.Fatal(err)
			}
			out[0].Share = append(out[0].Share, mask...)
			out[1].Share = append(out[1].Share, crossGridStageTestBytes(new(big.Int).Sub(v, crossGridStageTestInteger(mask)))...)
			out[0].Validity = append(out[0].Validity, mask[0]&1)
			out[1].Validity = append(out[1].Validity, (mask[0]&1)^1)
		}
		return out
	}
	numeric, meta := split(numbers), split(metadata)
	sources := [2]*groupedLMMSourceRecord{}
	for role := range sources {
		var err error
		sources[role], err = groupedLMMSealSource(s, exactGCRole(role), numeric[role], meta[role], crossGridStageTestKey(exactGCRole(role)))
		if err != nil {
			t.Fatal(err)
		}
	}
	sidecar, err := groupedRouteSeal(s.Route, labels, []bool{true, true, true, true}, crossGridStageTestKey(0))
	if err != nil {
		t.Fatal(err)
	}
	routed := [][]*big.Int{{new(big.Int).Set(f), value(7), value(3)},
		{new(big.Int).Set(f), value(9), value(5)}, {new(big.Int), new(big.Int), new(big.Int)},
		{new(big.Int).Set(f), value(5), value(7)}}
	return s, sources, sidecar, routed
}

func TestGroupedLMMSourceGraphAuthentication(t *testing.T) {
	s, sources, sidecar, _ := groupedLMMSourceFixture(t)
	key := crossGridStageTestKey(0)
	if _, err := groupedLMMBuildSourceGraph(s, 0, sources[0], sidecar, key); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"share", "validity", "role", "source", "schema", "semantic", "profile", "shape", "scale", "overflow-bound", "negative-domain"} {
		t.Run(change, func(t *testing.T) {
			raw, _ := json.Marshal(sources[0])
			var record groupedLMMSourceRecord
			json.Unmarshal(raw, &record)
			raw, _ = json.Marshal(s)
			var spec groupedLMMSourceSpec
			json.Unmarshal(raw, &spec)
			switch change {
			case "share":
				record.Numeric.Share[0] ^= 1
			case "validity":
				record.Metadata.Validity[0] ^= 1
			case "role":
				record.Role = 1
			case "source":
				spec.Route.SourceDigest[0] ^= 1
			case "schema":
				spec.SchemaDigest[0] ^= 1
			case "semantic":
				spec.SemanticKey[0] ^= 1
			case "profile":
				spec.LMM.ProfileDigest[0] ^= 1
			case "shape":
				spec.Route.Slots++
			case "scale":
				spec.LMM.Numeric.GridBits++
			case "overflow-bound":
				spec.Route.NumericBound.Lsh(big.NewInt(1), 96)
			case "negative-domain":
				spec.Route.Nonnegative = false
			}
			if _, err := groupedLMMBuildSourceGraph(spec, 0, &record, sidecar, key); err == nil {
				t.Fatal("accepted changed authenticated source binding")
			}
		})
	}
	for _, bad := range []groupedRouteStagedSpec{
		func() groupedRouteStagedSpec {
			r := s.Route
			r.NumericBound = new(big.Int).Lsh(big.NewInt(1), 96)
			return r
		}(),
		func() groupedRouteStagedSpec { r := s.Route; r.Nonnegative = false; return r }(),
	} {
		badSpec := s
		badSpec.Route = bad
		if _, err := groupedLMMSealSource(badSpec, 0, sources[0].Numeric, sources[0].Metadata, key); err == nil {
			t.Fatal("sealed source outside the certified normalized LMM domain")
		}
	}
}

func TestGroupedLMMSourceEncodedEndpointSlack(t *testing.T) {
	s, _, _, _ := groupedLMMSourceFixture(t)
	s.Route.Predictors, s.LMM.Moments.Columns = 2, 4
	s.LMM.Caps = s.LMM.Caps[:1]
	f := new(big.Int).Lsh(big.NewInt(1), 50)
	coefficient := func(integer, ulps int64) *big.Int {
		return new(big.Int).Add(new(big.Int).Mul(big.NewInt(integer), f), big.NewInt(ulps))
	}
	for _, test := range []struct {
		name   string
		cap    int64
		beta   []*big.Int
		accept bool
	}{
		{"cap17-encoded-l1-slack", 17, []*big.Int{coefficient(-6, 0), coefficient(-5, 0), coefficient(-5, -1)}, true},
		{"upper-at-slack", 2, []*big.Int{coefficient(1, 0), coefficient(1, 2), big.NewInt(0)}, true},
		{"upper-beyond-slack", 2, []*big.Int{coefficient(1, 0), coefficient(1, 3), big.NewInt(0)}, false},
		{"lower-at-slack", 2, []*big.Int{coefficient(-1, 0), big.NewInt(-2), big.NewInt(0)}, true},
		{"lower-beyond-slack", 2, []*big.Int{coefficient(-1, 0), big.NewInt(-3), big.NewInt(0)}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := s
			spec.LMM.Numeric.ResidualCap = test.cap
			spec.LMM.Beta = [][]*big.Int{test.beta}
			if spec.LMM.validate() != nil {
				t.Fatal("fixture must satisfy the retained encoded arithmetic contract")
			}
			_, err := groupedLMMSourcePlans(spec)
			if (err == nil) != test.accept {
				t.Fatalf("encoded residual endpoint admission=%v want=%v", err == nil, test.accept)
			}
		})
	}
}

func TestGroupedLMMSourceGraphTwoAuthority(t *testing.T) {
	// This is the complete internal source/router/conversion/arithmetic path;
	// it is intentionally not labelled a DSLite release or promotion proof.
	s, sources, sidecar, routed := groupedLMMSourceFixture(t)
	graphs := [2]*groupedLMMSourceGraph{}
	for role := range graphs {
		local := sidecar
		if role == 1 {
			local = nil
		}
		var err error
		graphs[role], err = groupedLMMBuildSourceGraph(s, exactGCRole(role), sources[role], local, crossGridStageTestKey(exactGCRole(role)))
		if err != nil {
			t.Fatal(err)
		}
	}
	if crossGridStageHash("test", graphs[0].Graph) != crossGridStageHash("test", graphs[1].Graph) {
		t.Fatal("private routing state changed public graph")
	}
	for _, scenario := range []string{"fresh", "conversion-abort", "routing-unilateral", "source-invalid"} {
		t.Run(scenario, func(t *testing.T) {
			localGraphs := graphs
			if scenario == "source-invalid" {
				bad := *sources[1]
				bad.Metadata = crossGridStageClone(bad.Metadata)
				bad.Metadata.Validity[0] ^= 1
				bad.MAC = groupedLMMSourceMAC(crossGridStageTestKey(1), bad)
				var err error
				localGraphs[1], err = groupedLMMBuildSourceGraph(s, 1, &bad, nil, crossGridStageTestKey(1))
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
								if scenario == "conversion-abort" && role == 0 && record.StageID == "lmm.source.ring192" && event == "after-compute" ||
									scenario == "routing-unilateral" && role == 1 && record.StageID == "grouped.route.output" && event == "after-prepare-exchange" {
									return errors.New("injected composed LMM interruption")
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
				t.Fatalf("composed LMM: %v / %v", out[0].err, out[1].err)
			}
			if scenario != "source-invalid" {
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
			for candidate, beta := range s.LMM.Beta {
				a, b := out[0].out[last], out[1].out[last]
				got := new(big.Int).Add(crossGridStageTestInteger(a.Share[16*candidate:16*(candidate+1)]), crossGridStageTestInteger(b.Share[16*candidate:16*(candidate+1)]))
				got.Mod(got, exactGCModulus(128))
				want := new(big.Int)
				valid := byte(0)
				if scenario != "source-invalid" {
					valid = 1
					for cluster := 0; cluster < s.Route.Clusters; cluster++ {
						want.Add(want, groupedLMMStatsOracle(s.LMM.Numeric, routed[cluster*2:cluster*2+2], beta))
					}
				}
				if got.Cmp(want) != 0 || a.Validity[candidate]^b.Validity[candidate] != valid {
					t.Fatalf("candidate %d got %s want %s; validity %d", candidate, got, want, a.Validity[candidate]^b.Validity[candidate])
				}
			}
		})
	}
}
