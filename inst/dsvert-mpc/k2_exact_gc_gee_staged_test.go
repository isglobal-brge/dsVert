package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func groupedGEEStagedTestSpec(family string) groupedGEEStagedSpec {
	s := groupedGEEStagedSpec{Numeric: groupedGEESpec{Slots: 3, Predictors: 1, GridBits: 16, Family: family, Correlation: "ar1", RhoQ16: 32768, ScoreClipQ16: 65536, RowLossCap: 10000000, BreadCap: 100000000, MaxOutcome: 1}, ClusterCap: 100000000, Prefix: "gee.test", SourceDigest: sha256.Sum256([]byte("synthetic sources")), Contract: sha256.Sum256([]byte("synthetic fixed rho")), CorrelationContract: "signed-fixed-rho-v3-predecessor"}
	if family == "poisson" {
		s.Numeric.MaxOutcome = 4
	}
	for i, width := range []int{3, 3, 6} {
		s.Sources[i] = crossGridStagePlan{ID: fmt.Sprintf("source.%d", i), Kind: "test.source", Ring: 192, FPScale: []int{100, 50, 0}[i], CoordOrder: make([]string, width), PublicBounds: map[string]int{"slots": 3}, SourceDigest: s.SourceDigest, ProfileDigest: s.Contract}
		for j := range s.Sources[i].CoordOrder {
			s.Sources[i].CoordOrder[j] = fmt.Sprintf("source.%d/coordinate/%d", i, j)
		}
	}
	return s
}

func TestGroupedGEEStagedContract(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		s := groupedGEEStagedTestSpec(family)
		a, err := groupedGEEBuildStagedGraph(s, exactGCRoleGarbler)
		if err != nil {
			t.Fatal(err)
		}
		b, err := groupedGEEBuildStagedGraph(s, exactGCRoleEvaluator)
		if err != nil || !reflect.DeepEqual(a.Plans, b.Plans) {
			t.Fatal("authority plan mismatch", err)
		}
		if len(a.Plans) != 3 || a.Plans[0].FPScale != 64 || a.Plans[1].FPScale != 64 || len(a.Plans[2].CoordOrder) != 7 {
			t.Fatal("typed terminal shape")
		}
		changed := s
		changed.Numeric.RhoQ16 = 16384
		c, err := groupedGEEBuildStagedGraph(changed, exactGCRoleGarbler)
		if err != nil || c.Plans[0].ProfileDigest == a.Plans[0].ProfileDigest {
			t.Fatal("rho not bound")
		}
		for _, alter := range []func(*groupedGEEStagedSpec){
			func(v *groupedGEEStagedSpec) { v.ClusterCap++ },
			func(v *groupedGEEStagedSpec) { v.Numeric.BreadCap++ },
			func(v *groupedGEEStagedSpec) { v.Numeric.ScoreClipQ16 = 32768 },
			func(v *groupedGEEStagedSpec) {
				v.Sources[0].CoordOrder = append([]string(nil), v.Sources[0].CoordOrder...)
				v.Sources[0].CoordOrder[0], v.Sources[0].CoordOrder[1] = v.Sources[0].CoordOrder[1], v.Sources[0].CoordOrder[0]
			},
		} {
			changed = s
			alter(&changed)
			other, err := groupedGEEBuildStagedGraph(changed, exactGCRoleGarbler)
			if err != nil || other.Plans[0].ProfileDigest == a.Plans[0].ProfileDigest {
				t.Fatal("cap/clip/order not bound", err)
			}
		}
		changed = s
		changed.Sources[0].SourceDigest = sha256.Sum256([]byte("substituted source"))
		if _, err := groupedGEEBuildStagedGraph(changed, exactGCRoleGarbler); err == nil {
			t.Fatal("source substitution admitted")
		}
		changed = s
		changed.CorrelationContract = "moment-estimated-alpha"
		if _, err := groupedGEEBuildStagedGraph(changed, exactGCRoleGarbler); err == nil {
			t.Fatal("unresolved estimator admitted")
		}
		changed = s
		changed.Sources[0].FPScale = 64
		if _, err := groupedGEEBuildStagedGraph(changed, exactGCRoleGarbler); err == nil {
			t.Fatal("mixed raw scale admitted")
		}
	}
}

func TestGroupedGEEStagedExactLattice(t *testing.T) {
	p, err := groupedGEEStagedUnpackCompile([]int{48, 32, 0})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []bool{false, true} {
		x := new(big.Int).Lsh(big.NewInt(-3), 48)
		if bad {
			x.Add(x, big.NewInt(1))
		}
		got := groupedGEETestBoundary(t, p, []*big.Int{x, new(big.Int).Lsh(big.NewInt(9), 32), big.NewInt(7), big.NewInt(1)}, 4)
		if bad {
			for _, v := range got {
				if v.Sign() != 0 {
					t.Fatal("inexact common lattice escaped")
				}
			}
		} else if got[0].Cmp(big.NewInt(-3)) != 0 || got[1].Int64() != 9 || got[2].Int64() != 7 || got[3].Int64() != 1 {
			t.Fatal(got)
		}
	}
}

func TestGroupedGEEStagedTwoAuthority(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		for _, invalidSource := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/source-invalid-%v", family, invalidSource), func(t *testing.T) {
				s := groupedGEEStagedTestSpec(family)
				rows := []groupedGEERow{{new(big.Int).Lsh(big.NewInt(-1), 64), []*big.Int{new(big.Int).Lsh(big.NewInt(1), 49)}, s.Numeric.MaxOutcome, 1}, {new(big.Int), []*big.Int{big.NewInt(0)}, 0, 0}, {new(big.Int).Lsh(big.NewInt(1), 64), []*big.Int{new(big.Int).Lsh(big.NewInt(1), 50)}, 0, 1}}
				want, ok := groupedGEEWhiteningOracle(s.Numeric, rows, s.ClusterCap)
				if !ok {
					t.Fatal("oracle")
				}
				var raw [3][]groupedWord
				for _, row := range rows {
					raw[0] = append(raw[0], groupedWordFromBig(new(big.Int).Lsh(new(big.Int).Set(row.EtaQ64), 36)))
					raw[1] = append(raw[1], groupedWordFromBig(row.FeaturesF50[0]))
					raw[2] = append(raw[2], groupedWordFromBig(big.NewInt(row.Outcome)), groupedWordFromBig(big.NewInt(row.Live)))
				}
				var source [2][3]crossGridStageOutput
				for i := range raw {
					var a, b []groupedWord
					for _, w := range raw[i] {
						mask, err := groupedRandomWord()
						if err != nil {
							t.Fatal(err)
						}
						a = append(a, mask)
						b = append(b, w.sub(mask))
					}
					source[0][i] = groupedGEEStagedOutput(a, groupedWord{1})
					source[1][i] = groupedGEEStagedOutput(b, groupedWord{})
				}
				if invalidSource {
					source[1][2].Validity[0] ^= 1
					for i := range want {
						want[i] = 0
					}
				}
				base := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 192, VectorLen: 1})
				ga, err := groupedGEEBuildStagedGraph(s, exactGCRoleGarbler)
				if err != nil {
					t.Fatal(err)
				}
				gb, err := groupedGEEBuildStagedGraph(s, exactGCRoleEvaluator)
				if err != nil {
					t.Fatal(err)
				}
				plan := crossGridStageGraph{Version: "cross-grid-stage-graph-v1", Family: "gee-fixed-rho-test", Session: "gee-staged-test", Authorities: [2]string{base.GarblerID, base.EvaluatorID}, SchemaDigest: s.Contract, SemanticKey: s.Contract, Stages: append(append([]crossGridStagePlan(nil), s.Sources[:]...), ga.Plans...)}
				var kernels [2][]crossGridStageCompute
				for role := range kernels {
					for i := range raw {
						value := source[role][i]
						kernels[role] = append(kernels[role], func(io.ReadWriter, crossGridStageAttempt, []crossGridStageOutput) (crossGridStageOutput, error) {
							return value, nil
						})
					}
				}
				kernels[0] = append(kernels[0], ga.Compute...)
				kernels[1] = append(kernels[1], gb.Compute...)
				dirs := [2]string{filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")}
				var previous []byte
				for _, scenario := range []string{"bilateral-abort", "unilateral-commit", "fresh", "cold"} {
					cold := scenario == "cold"
					stores := [2]*crossGridStageStore{}
					for role := range stores {
						stores[role], err = crossGridStageOpenStore(dirs[role], crossGridStageTestKey(exactGCRole(role)), plan, exactGCRole(role))
						if err != nil {
							t.Fatal(err)
						}
					}
					left, right := net.Pipe()
					left.SetDeadline(time.Now().Add(3 * time.Minute))
					right.SetDeadline(time.Now().Add(3 * time.Minute))
					type result struct {
						out []crossGridStageOutput
						err error
					}
					ch := make(chan result, 1)
					run := func(role int, rw io.ReadWriter) result {
						k := kernels[role]
						if cold {
							k = make([]crossGridStageCompute, len(k))
							for i := range k {
								k[i] = func(io.ReadWriter, crossGridStageAttempt, []crossGridStageOutput) (crossGridStageOutput, error) {
									return crossGridStageOutput{}, errors.New("cold recomputation")
								}
							}
						}
						e := crossGridStageExecutor{Store: stores[role], Base: base}
						if role == 0 && (scenario == "bilateral-abort" || scenario == "unilateral-commit") {
							e.fault = func(event string, record crossGridStageRecord) error {
								if (scenario == "bilateral-abort" && record.StageID == s.Prefix+".factors" && event == "after-compute") || (scenario == "unilateral-commit" && record.StageID == s.Prefix+".terminal" && event == "after-commit") {
									return errors.New("synthetic stage death")
								}
								return nil
							}
						}
						out, err := e.Execute(rw, k)
						return result{out, err}
					}
					go func() {
						v := run(0, left)
						if v.err != nil {
							left.Close()
						}
						ch <- v
					}()
					b := run(1, right)
					if b.err != nil {
						right.Close()
					}
					a := <-ch
					left.Close()
					right.Close()
					for _, store := range stores {
						store.Close()
					}
					if scenario == "bilateral-abort" || scenario == "unilateral-commit" {
						if a.err == nil || b.err == nil {
							t.Fatal("injected stage death did not stop both peers")
						}
						continue
					}
					if a.err != nil || b.err != nil {
						t.Fatalf("durable composition %v / %v", a.err, b.err)
					}
					av, bv := a.out[len(a.out)-1], b.out[len(b.out)-1]
					got := make([]groupedWord, len(want))
					for i, w := range want {
						got[i] = groupedDecodeWord(av.Share[24*i : 24*(i+1)]).add(groupedDecodeWord(bv.Share[24*i : 24*(i+1)]))
						if groupedWordInteger(got[i]).Int64() != w || av.Validity[i]^bv.Validity[i] != map[bool]byte{false: 1, true: 0}[invalidSource] {
							t.Fatalf("coordinate %d got %v want %d", i, got[i], w)
						}
					}
					encoded := groupedEncodeWords(got)
					if cold && !bytes.Equal(previous, encoded) {
						t.Fatal("cold changed output")
					}
					previous = encoded
				}
			})
		}
	}
}

// A rejected likelihood, bread predecessor or meat boundary suppresses the
// complete workload, including otherwise-valid coordinates from other branches.
func TestGroupedGEEStagedBranchValidity(t *testing.T) {
	conjunction, err := groupedGEEValidityCompile(3)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := groupedGEEStagedUnpackCompile(make([]int, 7))
	if err != nil {
		t.Fatal(err)
	}
	for failed, name := range []string{"bread-predecessor", "meat", "likelihood"} {
		t.Run(name, func(t *testing.T) {
			flags := []*big.Int{big.NewInt(1), big.NewInt(1), big.NewInt(1)}
			flags[failed] = big.NewInt(0)
			valid := groupedGEETestBoundary(t, conjunction, flags, 1)
			args := make([]*big.Int, 8)
			for i := 0; i < 7; i++ {
				args[i] = big.NewInt(int64(100 + i))
			}
			args[7] = valid[0]
			out := groupedGEETestBoundary(t, gate, args, 8)
			for _, v := range out {
				if v.Sign() != 0 {
					t.Fatal("invalid branch escaped terminal gate")
				}
			}
		})
	}
}
