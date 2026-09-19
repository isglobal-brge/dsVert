package main

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/markkurossi/mpc/circuit"
)

func TestCrossGridNBSharedBatchOracle(t *testing.T) {
	rng := rand.New(rand.NewSource(20260919))
	for _, owners := range []int{2, 3, 5} {
		for exponent := -3; exponent <= 7; exponent++ {
			p := crossGridKernelTestPlan("nb")
			p.Owners = owners
			p.A = 16
			p.MaxOutcome = 4
			p.ThetaExponents = []int{exponent, exponent}
			c := crossGridKernelTestCompile(t, p)
			t.Logf("owners=%d theta_exponent=%d AND=%d rows=%d candidates=%d", owners, exponent, c.Stats[circuit.AND], p.Rows, len(p.Beta))
			for test := 0; test < 12; test++ {
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
					x[2*p.Predictors].SetInt64(5)
				case 5:
					x[len(x)-1].SetInt64(92)
				}
				aligned := true
				start := p.Rows * 2 * (p.Predictors + 1)
				for k := 1; k < p.Owners; k++ {
					aligned = aligned && x[start].Cmp(x[start+2*k]) == 0 && x[start+1].Cmp(x[start+2*k+1]) == 0
				}
				want := crossGridNBKernelOracle(t, p, x)
				g, e, masks := crossGridKernelTestInputs(t, p, x, rng)
				got, err := c.Compute([]*big.Int{exactGCPackChunks(g, 128), exactGCPackChunks(e, 128)})
				if err != nil {
					t.Fatal(err)
				}
				for j := range want {
					actual := new(big.Int).Rsh(new(big.Int).Set(got[0]), uint(128*j))
					actual.Mod(actual, exactGCModulus(128))
					actual.Add(actual, masks[j])
					actual.Mod(actual, exactGCModulus(128))
					if actual.Cmp(want[j]) != 0 {
						t.Fatalf("owners=%d theta=%d case=%d candidate=%d got=%s want=%s", owners, exponent, test, j, actual, want[j])
					}
				}
				guard := new(big.Int).Rsh(new(big.Int).Set(got[0]), uint(128*len(want)))
				guard.Xor(guard, masks[len(want)])
				if (guard.Sign() != 0) != aligned {
					t.Fatal("private terminal guard mismatch")
				}
			}
		}
	}
}

func TestCrossGridNBSharedPlanRejectsTheta(t *testing.T) {
	p := crossGridKernelTestPlan("nb")
	p.A = 16
	if p.validate() == nil {
		t.Fatal("missing theta accepted")
	}
	p.ThetaExponents = []int{-4, 0}
	if p.validate() == nil {
		t.Fatal("theta outside profile accepted")
	}
	p.ThetaExponents = []int{0, 8}
	if p.validate() == nil {
		t.Fatal("theta outside profile accepted")
	}
	p.ThetaExponents = []int{0, 0}
	if p.validate() != nil {
		t.Fatal("valid theta rejected")
	}
	p.Family = "binomial"
	if p.validate() == nil {
		t.Fatal("foreign family theta accepted")
	}
}

// Independent central integer evaluation, linked only into test/oracle binaries.
func crossGridNBKernelOracle(t testing.TB, p crossGridKernelPlan, x []*big.Int) []*big.Int {
	t.Helper()
	profile, err := exactGCNBReadProfileV1(crossGridNBProfileJSON)
	if err != nil || p.validate() != nil || len(x) != p.sourceCount() {
		t.Fatal("invalid synthetic NB oracle input")
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
		y := x[r*2*(p.Predictors+1)+2*p.Predictors].Int64()
		for j, beta := range p.Beta {
			dot, _ := new(big.Int).SetString(beta[0], 10)
			dot.Lsh(dot, 50)
			for k := 0; k < p.Predictors; k++ {
				b, _ := new(big.Int).SetString(beta[k+1], 10)
				dot.Add(dot, new(big.Int).Mul(b, x[r*2*(p.Predictors+1)+2*k]))
			}
			eta := crossGridRoundDivV1(dot, crossGridPow2V1(36))
			out[j].Add(out[j], crossGridNBReferenceLossV1(profile, eta, y, true, p.ThetaExponents[j], p.GridBits, int64(p.Caps[j])))
		}
	}
	return out
}
