package main

// Candidate arithmetic only; never accepted as an existing signed V1 profile.
import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"os"
	"testing"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
)

func crossGridExpReducedProfiles(t testing.TB) []crossGridExpReducedProfile {
	t.Helper()
	data, err := os.ReadFile("../cross-grid-v2/exp_reduced_candidate.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Profiles []crossGridExpReducedProfile `json:"profiles"`
	}
	if err = json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Profiles) != 3 {
		t.Fatal("public profile inventory mismatch")
	}
	return f.Profiles
}

// Independent big-integer implementation, including signed ties-to-even.
func crossGridExpReducedOracle(p crossGridExpReducedProfile, eta int32) (uint64, bool) {
	x := int64(eta)
	if x < -(16<<26) || x > 16<<26 {
		return 0, false
	}
	k := crossGridRoundDivV1(new(big.Int).Mul(big.NewInt(x), big.NewInt(p.InvLn2)), new(big.Int).Lsh(big.NewInt(1), 56)).Int64()
	r := crossGridRoundDivV1(big.NewInt(x*16-k*p.Ln2), big.NewInt(64)).Int64()
	offset := r + (1 << 23)
	j := int(offset) / p.Width
	c := p.Coefficients[j]
	rem := big.NewInt(offset - int64(j*p.Width))
	v := crossGridRoundDivV1(new(big.Int).Mul(big.NewInt(c[2]), rem), big.NewInt(int64(p.Width)))
	v.Add(v, big.NewInt(c[1]))
	v = crossGridRoundDivV1(new(big.Int).Mul(v, rem), big.NewInt(int64(p.Width)))
	v.Add(v, big.NewInt(c[0]))
	shift := 11 - k
	if shift > 0 {
		v = crossGridRoundDivV1(v, new(big.Int).Lsh(big.NewInt(1), uint(shift)))
	} else {
		v.Lsh(v, uint(-shift))
	}
	return v.Uint64(), true
}

func crossGridExpReducedCompile(t testing.TB, p crossGridExpReducedProfile) *circuit.Circuit {
	t.Helper()
	c, _, err := compiler.New(crossGridPWCompilerParams()).Compile(crossGridExpReducedSource(p), nil)
	if err != nil {
		t.Fatal(err)
	}
	return crossGridPWOptimize(c)
}

func TestCrossGridExpReducedV2Certificate(t *testing.T) {
	for _, p := range crossGridExpReducedProfiles(t) {
		t.Run(p.Identity, func(t *testing.T) {
			for _, v := range p.TestVectors {
				got, ok := crossGridExpReducedOracle(p, int32(v[0]))
				if !ok || got != uint64(v[1]) {
					t.Fatal("shared integer fixture mismatch")
				}
			}
			for _, a := range []int{1, 2, 4, 8, 16} {
				var bound float64
				if _, err := fmt.Sscan(p.LossErrors[fmt.Sprint(a)], &bound); err != nil {
					t.Fatal(err)
				}
				maximum := 0.0
				for i := 0; i <= 65536; i++ {
					x := -float64(a) + float64(2*a*i)/65536 + 0.37/(1<<26)
					if x > float64(a) {
						x = float64(a)
					}
					eta := int32(math.RoundToEven(x * (1 << 26)))
					v, ok := crossGridExpReducedOracle(p, eta)
					e := math.Abs(float64(v)/65536 - math.Exp(x))
					if !ok || e > bound {
						t.Fatal("dense error exceeds public certificate")
					}
					maximum = math.Max(maximum, e)
				}
				for i := 0; i <= 64; i++ {
					x := -float64(a) + float64(2*a*i)/64
					v, _ := crossGridExpReducedOracle(p, int32(math.RoundToEven(x*(1<<26))))
					want := crossGridHighExpV1(crossGridHighV1().SetFloat64(x))
					error := crossGridHighV1().Sub(crossGridHighV1().SetFloat64(float64(v)/65536), want)
					if error.Abs(error).Cmp(crossGridHighV1().SetFloat64(bound)) > 0 {
						t.Fatal("independent high precision certificate mismatch")
					}
				}
				t.Logf("A=%d dense_max=%.9g loss_bound=%.9g", a, maximum, bound)
			}
		})
	}
}

func TestCrossGridExpReducedV2Circuit(t *testing.T) {
	rng := rand.New(rand.NewSource(20260918))
	for _, p := range crossGridExpReducedProfiles(t) {
		t.Run(p.Identity, func(t *testing.T) {
			c := crossGridExpReducedCompile(t, p)
			t.Logf("AND/eval=%d gates=%d table_bytes=%d", c.Stats[circuit.AND], c.NumGates, 32*c.Stats[circuit.AND])
			values := []int32{math.MinInt32, math.MaxInt32, -(16 << 26) - 1, 16<<26 + 1}
			for _, v := range p.TestVectors {
				values = append(values, int32(v[0]))
			}
			for _, x := range values {
				share, mask := rng.Uint32(), rng.Uint64()
				g := new(big.Int).Lsh(new(big.Int).SetUint64(mask), 64)
				g.Or(g, new(big.Int).SetUint64(uint64(share)))
				result, err := c.Compute([]*big.Int{g, new(big.Int).SetUint64(uint64(uint32(x) - share))})
				if err != nil {
					t.Fatal(err)
				}
				want, valid := crossGridExpReducedOracle(p, x)
				if result[0].Uint64()+mask != want || (result[1].Sign() != 0) != valid {
					t.Fatal("circuit/oracle mismatch")
				}
			}
		})
	}
}

func TestCrossGridExpReducedV2NotAdmittedAsV1(t *testing.T) {
	for _, p := range crossGridExpReducedProfiles(t) {
		contract, err := crossGridNumericContractV1("poisson")
		if err != nil {
			t.Fatal(err)
		}
		contract.ProfileIdentity = p.Identity
		err = crossGridValidateNumericContractV1("poisson", contract)
		if err == nil || err.Error() != "cross-grid contract rejected" {
			t.Fatal("candidate crossed frozen admission boundary")
		}
	}
}
