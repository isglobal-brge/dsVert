package main

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"github.com/markkurossi/mpc/circuit"
)

func crossGridCategoricalKernelOracle(t testing.TB, p crossGridKernelPlan, x []*big.Int) []*big.Int {
	t.Helper()
	if p.validate() != nil || len(x) != p.sourceCount() {
		t.Fatal("invalid synthetic categorical oracle input")
	}
	start := p.Rows * 2 * (p.Predictors + 1)
	aligned := x[start].Sign() != 0 || x[start+1].Sign() != 0
	for k := 1; k < p.Owners; k++ {
		aligned = aligned && x[start].Cmp(x[start+2*k]) == 0 && x[start+1].Cmp(x[start+2*k+1]) == 0
	}
	out := make([]*big.Int, len(p.Beta))
	for j := range out {
		out[j] = new(big.Int)
	}
	for r := 0; r < p.Rows; r++ {
		valid := aligned
		for k := 0; k <= p.Predictors; k++ {
			i := r*2*(p.Predictors+1) + 2*k
			upper := int64(1 << 50)
			if k == p.Predictors {
				upper = int64(p.MaxOutcome)
			}
			valid = valid && x[i].Sign() >= 0 && x[i].Cmp(big.NewInt(upper)) <= 0 && x[i+1].Cmp(big.NewInt(1)) == 0
		}
		if !valid {
			continue
		}
		y := int(x[r*2*(p.Predictors+1)+2*p.Predictors].Int64())
		for j, beta := range p.Beta {
			dots := make([]*big.Int, p.predictorGroups())
			for group := range dots {
				b := beta[group*(p.Predictors+1) : (group+1)*(p.Predictors+1)]
				dot, _ := new(big.Int).SetString(b[0], 10)
				dot.Lsh(dot, 50)
				for k := 0; k < p.Predictors; k++ {
					coefficient, _ := new(big.Int).SetString(b[k+1], 10)
					dot.Add(dot, new(big.Int).Mul(coefficient, x[r*2*(p.Predictors+1)+2*k]))
				}
				dots[group] = dot
			}
			spec := exactGCFamilyLossSpec{Classes: p.Classes, GridBits: p.GridBits, Cap: int64(p.Caps[j])}
			if p.Family == "ordinal" {
				spec.Thresholds = p.Thresholds[j]
			}
			out[j].Add(out[j], familyLossReference(p.Family, spec, dots, y, true))
		}
	}
	return out
}

func TestCrossGridCategoricalSharedBatchOracle(t *testing.T) {
	rng := rand.New(rand.NewSource(20260919))
	for _, family := range []string{"multinomial", "ordinal"} {
		for _, classes := range []int{2, 3, 8} {
			for _, owners := range []int{2, 3, 5} {
				t.Run(fmt.Sprintf("%s/classes%d/owners%d", family, classes, owners), func(t *testing.T) {
					p := crossGridKernelTestPlan(family)
					p.A = 16
					p.Classes = classes
					p.MaxOutcome = classes - 1
					p.Owners = owners
					p.Caps[1] = 17
					if family == "multinomial" {
						for j, b := range p.Beta {
							p.Beta[j] = nil
							for k := 0; k < classes-1; k++ {
								p.Beta[j] = append(p.Beta[j], b...)
							}
						}
					} else {
						p.A = 8
						for j := range p.Beta {
							p.Beta[j][0] = "0"
							thresholds := make([]string, classes-1)
							for k := range thresholds {
								thresholds[k] = fmt.Sprint(int64(k-(classes-2)/2) * (1 << 50))
							}
							p.Thresholds = append(p.Thresholds, thresholds)
						}
					}
					c := crossGridKernelTestCompile(t, p)
					t.Logf("AND=%d rows=%d candidates=%d", c.Stats[circuit.AND], p.Rows, len(p.Beta))
					for test := 0; test < 16; test++ {
						x := crossGridKernelTestSource(p, rng)
						switch test {
						case 0:
							x[0].SetInt64(0)
						case 1:
							x[0].SetInt64(1 << 50)
						case 2:
							x[0].SetInt64(1<<50 + 1)
						case 3:
							x[1].SetInt64(0)
						case 4:
							x[2*p.Predictors].SetInt64(int64(classes))
						case 5:
							x[len(x)-1].SetInt64(92)
						}
						want := crossGridCategoricalKernelOracle(t, p, x)
						g, e, masks := crossGridKernelTestInputs(t, p, x, rng)
						got, err := c.Compute([]*big.Int{exactGCPackChunks(g, 128), exactGCPackChunks(e, 128)})
						if err != nil {
							t.Fatal(err)
						}
						for j := range want {
							actual := new(big.Int).Rsh(new(big.Int).Set(got[0]), uint(128*j))
							actual.Add(actual, masks[j])
							actual.Mod(actual, exactGCModulus(128))
							if actual.Cmp(want[j]) != 0 {
								t.Fatalf("case=%d candidate=%d got=%s want=%s", test, j, actual, want[j])
							}
						}
						guard := new(big.Int).Rsh(new(big.Int).Set(got[0]), uint(128*len(want)))
						guard.Xor(guard, masks[len(want)])
						if (guard.Sign() != 0) != (test != 5) {
							t.Fatal("private terminal guard mismatch")
						}
					}
				})
			}
		}
	}
}
