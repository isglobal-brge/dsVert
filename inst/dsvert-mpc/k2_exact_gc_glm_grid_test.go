package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"testing"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
)

func crossGridKernelTestPlan(family string) crossGridKernelPlan {
	m := 1
	if family == "poisson" {
		m = 4
	}
	return crossGridKernelPlan{Family: family, Rows: 2, Predictors: 2, Owners: 2, A: 4, GridBits: 16, MaxOutcome: m, Beta: [][]string{{"1125899906842624", "-1125899906842624", "562949953421312"}, {"-281474976710656", "1125899906842624", "-562949953421312"}}, Caps: []uint64{1 << 24, 1 << 24}}
}

func crossGridKernelTestSource(p crossGridKernelPlan, rng *rand.Rand) []*big.Int {
	x := make([]*big.Int, p.sourceCount())
	for i := range x {
		x[i] = new(big.Int)
	}
	for r := 0; r < p.Rows; r++ {
		for k := 0; k <= p.Predictors; k++ {
			i := r*2*(p.Predictors+1) + 2*k
			v := rng.Int63n(1<<50 + 1)
			if k == p.Predictors {
				v = int64(rng.Intn(p.MaxOutcome + 1))
			}
			x[i].SetInt64(v)
			x[i+1].SetInt64(1)
		}
	}
	offset := p.Rows * 2 * (p.Predictors + 1)
	for k := 0; k < p.Owners; k++ {
		x[offset+2*k].SetInt64(37)
		x[offset+2*k+1].SetInt64(91)
	}
	return x
}

func crossGridKernelTestInputs(t testing.TB, p crossGridKernelPlan, x []*big.Int, rng *rand.Rand) ([]*big.Int, []*big.Int, []*big.Int) {
	t.Helper()
	left, right := exactGCTestSplit(rng, x, 128)
	start := p.Rows * 2 * (p.Predictors + 1)
	for i := start; i < len(x); i++ {
		right[i].Xor(left[i], x[i])
	}
	g, err := crossGridKernelPrivateInput(p, left, true)
	if err != nil {
		t.Fatal(err)
	}
	e, err := crossGridKernelPrivateInput(p, right, false)
	if err != nil {
		t.Fatal(err)
	}
	masks := make([]*big.Int, len(p.Beta)+1)
	for i := range masks {
		masks[i] = exactGCTestRandomResidue(rng, 128)
	}
	masks[len(p.Beta)].And(masks[len(p.Beta)], big.NewInt(1))
	return append(g, masks...), e, masks
}

func crossGridKernelOracle(t testing.TB, p crossGridKernelPlan, x []*big.Int) []*big.Int {
	t.Helper()
	profiles, err := crossGridKernelProfilesLoad()
	if err != nil {
		t.Fatal(err)
	}
	q := 26
	if p.Family == "binomial" {
		q = 16
	}
	out := make([]*big.Int, len(p.Beta))
	for j := range out {
		out[j] = new(big.Int)
	}
	start := p.Rows * 2 * (p.Predictors + 1)
	aligned := x[start].Sign() != 0 || x[start+1].Sign() != 0
	for k := 1; k < p.Owners; k++ {
		aligned = aligned && x[start].Cmp(x[start+2*k]) == 0 && x[start+1].Cmp(x[start+2*k+1]) == 0
	}
	for r := 0; r < p.Rows; r++ {
		valid := aligned
		for k := 0; k <= p.Predictors; k++ {
			i := r*2*(p.Predictors+1) + 2*k
			bound := int64(1 << 50)
			if k == p.Predictors {
				bound = int64(p.MaxOutcome)
			}
			valid = valid && x[i].Sign() >= 0 && x[i].Cmp(big.NewInt(bound)) <= 0 && x[i+1].Cmp(big.NewInt(1)) == 0
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
			eta := crossGridRoundDivV1(dot, new(big.Int).Lsh(big.NewInt(1), uint(100-q))).Int64()
			lim := int64(p.A) << q
			if eta < -lim {
				eta = -lim
			}
			if eta > lim {
				eta = lim
			}
			var loss int64
			if p.Family == "binomial" {
				for _, v := range profiles.Binomial {
					if v.A == p.A {
						value, _ := crossGridPWOracle(v, uint32(eta+lim))
						loss = int64(value) - y*eta
					}
				}
			} else {
				v, _ := crossGridExpReducedOracle(profiles.Poisson, int32(eta))
				loss = int64(v<<10) - y*eta + int64(profiles.LogFactorial[y]<<10)
			}
			if loss < 0 {
				loss = 0
			}
			quant := big.NewInt(loss)
			if q > p.GridBits {
				quant = crossGridRoundDivV1(quant, new(big.Int).Lsh(big.NewInt(1), uint(q-p.GridBits)))
			} else {
				quant.Lsh(quant, uint(p.GridBits-q))
			}
			cap := new(big.Int).SetUint64(p.Caps[j])
			if quant.Cmp(cap) > 0 {
				quant.Set(cap)
			}
			out[j].Add(out[j], quant)
		}
	}
	return out
}

func crossGridKernelTestCompile(t testing.TB, p crossGridKernelPlan) *circuit.Circuit {
	t.Helper()
	source, err := crossGridKernelSource(p)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := compiler.New(crossGridPWCompilerParams()).Compile(source, nil)
	if err != nil {
		t.Fatal(err)
	}
	return crossGridPWOptimize(c)
}

func TestCrossGridKernelInteger(t *testing.T) {
	rng := rand.New(rand.NewSource(20260918))
	for _, family := range []string{"binomial", "poisson"} {
		t.Run(family, func(t *testing.T) {
			p := crossGridKernelTestPlan(family)
			p.Caps[1] = 17 // Deliberate saturation stress, never a signed admission cap.
			c := crossGridKernelTestCompile(t, p)
			t.Logf("AND/eval=%.3f", float64(c.Stats[circuit.AND])/float64(p.Rows*len(p.Beta)))
			for test := 0; test < 40; test++ {
				x := crossGridKernelTestSource(p, rng)
				if test < 12 {
					switch test {
					case 0:
						x[0].SetInt64(0)
					case 1:
						x[0].SetInt64(1 << 50)
					case 2:
						x[0].SetInt64(1<<50 + 1)
					case 3:
						x[0].Sub(exactGCModulus(128), big.NewInt(1))
					case 4:
						x[1].SetInt64(0)
					case 5:
						x[1].SetInt64(2)
					case 6:
						x[1].Lsh(big.NewInt(1), 127)
					case 7:
						x[2*p.Predictors].SetInt64(int64(p.MaxOutcome + 1))
					case 8:
						x[len(x)-1].SetInt64(92)
					case 9:
						for i := p.Rows * 2 * (p.Predictors + 1); i < len(x); i++ {
							x[i].SetInt64(0)
						}
					case 10:
						for i := 1; i < p.Rows*2*(p.Predictors+1); i += 2 {
							x[i].SetInt64(0)
						}
					}
				}
				g, e, masks := crossGridKernelTestInputs(t, p, x, rng)
				got, err := c.Compute([]*big.Int{exactGCPackChunks(g, 128), exactGCPackChunks(e, 128)})
				if err != nil {
					t.Fatal(err)
				}
				want := crossGridKernelOracle(t, p, x)
				for j := range want {
					actual := new(big.Int).Rsh(new(big.Int).Set(got[0]), uint(128*j))
					actual.Mod(actual, exactGCModulus(128))
					actual.Add(actual, masks[j])
					actual.Mod(actual, exactGCModulus(128))
					if actual.Cmp(want[j]) != 0 {
						t.Fatal("fused integer oracle mismatch", test, j)
					}
				}
			}
		})
	}
}

func TestCrossGridKernelRejectsPublicPlanAndShares(t *testing.T) {
	p := crossGridKernelTestPlan("binomial")
	cases := []crossGridKernelPlan{p, p, p, p, p, p}
	cases[0].Family = "gaussian"
	cases[1].Rows = 33
	cases[2].A = 3
	cases[3].Owners = 1
	cases[4].GridBits = 7
	cases[5].MaxOutcome = 2
	for _, bad := range cases {
		if err := bad.validate(); err != errCrossGridKernel {
			t.Fatal("unsafe public rejection")
		}
	}
	for _, s := range []string{"-0", "+1", "01", "9007199254740993", "protected-value"} {
		bad := p
		bad.Beta = [][]string{{s, "0", "0"}}
		bad.Caps = []uint64{1}
		if bad.validate() != errCrossGridKernel {
			t.Fatal("noncanonical public beta accepted")
		}
	}
	if _, err := crossGridKernelPrivateInput(p, nil, true); err != errCrossGridKernel {
		t.Fatal("source shape accepted")
	}
	t.Log(fmt.Sprint(errCrossGridKernel))
}

func TestCrossGridKernelRound(t *testing.T) {
	for _, q := range []int{16, 26} {
		s := "package main\n" + crossGridKernelRoundSource("rounddot", 100-q) + "func main(g uint128,e uint128) int64 {return rounddot(int128(g+e))}\n"
		c, _, err := compiler.New(crossGridPWCompilerParams()).Compile(s, nil)
		if err != nil {
			t.Fatal(err)
		}
		divisor := new(big.Int).Lsh(big.NewInt(1), uint(100-q))
		half := new(big.Int).Rsh(new(big.Int).Set(divisor), 1)
		for v := int64(-3); v <= 3; v++ {
			for _, offset := range []int64{-1, 0, 1} {
				for _, sign := range []int64{-1, 1} {
					raw := new(big.Int).Mul(big.NewInt(v), divisor)
					raw.Add(raw, new(big.Int).Mul(half, big.NewInt(sign)))
					raw.Add(raw, big.NewInt(offset))
					want := crossGridRoundDivV1(raw, divisor)
					residue := new(big.Int).Mod(new(big.Int).Set(raw), exactGCModulus(128))
					got, err := c.Compute([]*big.Int{residue, new(big.Int)})
					if err != nil || int64(got[0].Uint64()) != want.Int64() {
						t.Fatal("signed tie/slack rounding mismatch")
					}
				}
			}
		}
	}
}

func TestCrossGridKernelPredictor(t *testing.T) {
	p := crossGridKernelTestPlan("binomial")
	p.Rows = 1
	rng := rand.New(rand.NewSource(20260918))
	x := crossGridKernelTestSource(p, rng)
	g, e, _ := crossGridKernelTestInputs(t, p, x, rng)
	n := len(e)
	i := p.sourceCount()
	s := "package main\n" + crossGridKernelRoundSource("rounddot", 84) + fmt.Sprintf("func main(g [%d]uint128,e [%d]uint128) int64 { v:=int32(rounddot(int128(g[%d]+e[%d])))\n if v < -262144 {v= -262144}\n if v>262144 {v=262144}\n return int64(v)\n }\n", len(g), n, i, i)
	c, _, err := compiler.New(crossGridPWCompilerParams()).Compile(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Compute([]*big.Int{exactGCPackChunks(g, 128), exactGCPackChunks(e, 128)})
	if err != nil {
		t.Fatal(err)
	}
	dot := new(big.Int).Add(g[i], e[i])
	dot.Mod(dot, exactGCModulus(128))
	if dot.Bit(127) != 0 {
		dot.Sub(dot, exactGCModulus(128))
	}
	want := crossGridRoundDivV1(dot, new(big.Int).Lsh(big.NewInt(1), 84))
	if int64(got[0].Uint64()) != want.Int64() {
		t.Fatal("synthetic predictor", got[0], want)
	}
}

func TestCrossGridKernelFrozenShapeCost(t *testing.T) {
	if testing.Short() {
		t.Skip("frozen public cost shape")
	}
	for _, family := range []string{"binomial", "poisson"} {
		p := crossGridKernelCostPlan(t, family)
		c := crossGridKernelTestCompile(t, p)
		t.Logf("family=%s rows=32 p=10 candidates=8 AND/eval=%.3f table-B/eval=%.3f input-bits=%d", family, float64(c.Stats[circuit.AND])/256, float64(c.Stats[circuit.AND])*32/256, c.Inputs.Size())
	}
}

func TestCrossGridKernelSharedVectors(t *testing.T) {
	data, err := os.ReadFile("../cross-grid-v2/fused_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var groups []struct {
		Plan    crossGridKernelPlan `json:"plan"`
		Vectors []struct {
			Source   []string `json:"source"`
			Expected []string `json:"expected"`
		} `json:"vectors"`
	}
	if json.Unmarshal(data, &groups) != nil {
		t.Fatal("invalid public fixtures")
	}
	rng := rand.New(rand.NewSource(1234))
	for _, group := range groups {
		c := crossGridKernelTestCompile(t, group.Plan)
		for _, v := range group.Vectors {
			x := make([]*big.Int, len(v.Source))
			for i, s := range v.Source {
				x[i], _ = new(big.Int).SetString(s, 10)
			}
			g, e, masks := crossGridKernelTestInputs(t, group.Plan, x, rng)
			result, err := c.Compute([]*big.Int{exactGCPackChunks(g, 128), exactGCPackChunks(e, 128)})
			if err != nil {
				t.Fatal(err)
			}
			for j, s := range v.Expected {
				want, _ := new(big.Int).SetString(s, 10)
				got := new(big.Int).Rsh(new(big.Int).Set(result[0]), uint(j*128))
				got.Add(got, masks[j])
				got.Mod(got, exactGCModulus(128))
				if got.Cmp(want) != 0 {
					t.Fatal("shared R/Go fixture mismatch")
				}
			}
		}
	}
	t.Log("288 shared full-dot fixtures passed")
}

// Public A=4 envelope, exact L1=4 for every distinct candidate, certified caps.
// This is a source/loss batch benchmark, not signed release admission.
func crossGridKernelCostPlan(t testing.TB, family string) crossGridKernelPlan {
	t.Helper()
	var profiles struct {
		Binomial []struct {
			A    int `json:"a"`
			Caps []struct {
				U uint64 `json:"per_patient_cap"`
			} `json:"caps"`
		} `json:"binomial"`
		Poisson struct {
			Caps []struct {
				A int    `json:"a"`
				M int    `json:"max_outcome"`
				U uint64 `json:"per_patient_cap"`
			} `json:"caps"`
		} `json:"poisson"`
	}
	if json.Unmarshal(crossGridProfilesV2JSON, &profiles) != nil {
		t.Fatal("public profile fixture invalid")
	}
	var cap uint64
	if family == "binomial" {
		for _, p := range profiles.Binomial {
			if p.A == 4 {
				cap = p.Caps[0].U
			}
		}
	} else {
		for _, p := range profiles.Poisson.Caps {
			if p.A == 4 && p.M == 4 {
				cap = p.U
			}
		}
	}
	if cap == 0 {
		t.Fatal("missing certified cap")
	}
	p := crossGridKernelTestPlan(family)
	p.Rows = 32
	p.Predictors = 10
	p.Beta = nil
	p.Caps = nil
	for j := 0; j < 8; j++ {
		beta := make([]string, 11)
		beta[0] = fmt.Sprint(int64(1<<48) + int64(j)*(1<<40))
		for k := 1; k < 11; k++ {
			v := int64(3 << 47)
			if k == 1 {
				v -= int64(j) * (1 << 40)
			}
			beta[k] = fmt.Sprint(v)
		}
		p.Beta = append(p.Beta, beta)
		p.Caps = append(p.Caps, cap)
	}
	return p
}

func TestCrossGridKernelBoundarySlack(t *testing.T) {
	rng := rand.New(rand.NewSource(811))
	for _, family := range []string{"binomial", "poisson"} {
		for _, a := range []int{4, 16} {
			p := crossGridKernelTestPlan(family)
			p.Rows = 1
			p.A = a
			p.Caps = []uint64{1 << 50, 1 << 50}
			if a == 16 {
				p.Beta = [][]string{{"9007199254740992", "9007199254740992", "0"}, {"-9007199254740992", "-9007199254740992", "0"}}
			} else {
				// Encoded aggregate slack is projected onto the real signed envelope.
				// This internal numeric stress plan is not a signed raw-beta fixture.
				p.Beta = [][]string{{"4503599627370497", "0", "0"}, {"-4503599627370497", "0", "0"}}
			}
			c := crossGridKernelTestCompile(t, p)
			for _, value := range []int64{0, 1, 1<<50 - 1, 1 << 50, 1<<50 + 1} {
				for _, y := range []int64{0, int64(p.MaxOutcome)} {
					x := crossGridKernelTestSource(p, rng)
					x[0].SetInt64(value)
					x[4].SetInt64(y)
					g, e, masks := crossGridKernelTestInputs(t, p, x, rng)
					result, err := c.Compute([]*big.Int{exactGCPackChunks(g, 128), exactGCPackChunks(e, 128)})
					if err != nil {
						t.Fatal(err)
					}
					want := crossGridKernelOracle(t, p, x)
					for j := range want {
						got := new(big.Int).Rsh(new(big.Int).Set(result[0]), uint(128*j))
						got.Add(got, masks[j])
						got.Mod(got, exactGCModulus(128))
						if got.Cmp(want[j]) != 0 {
							t.Fatal("certified endpoint/slack mismatch")
						}
					}
				}
			}
		}
	}
}
