package main

// Candidate arithmetic only; never accepted as an existing signed V1 profile.
import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"os"
	"strings"
	"testing"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
)

type crossGridExpReducedProfile struct {
	Identity      string            `json:"identity"`
	Pieces        int               `json:"pieces"`
	Width         int               `json:"width"`
	Ln2           int64             `json:"ln2"`
	InvLn2        int64             `json:"inv_ln2"`
	Coefficients  [][3]int64        `json:"coefficients"`
	TestVectors   [][2]int64        `json:"test_vectors"`
	LossErrors    map[string]string `json:"loss_errors"`
	RelativeError string            `json:"relative_exp_error"`
}

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

func crossGridExpReducedSource(p crossGridExpReducedProfile) string {
	var s strings.Builder
	s.WriteString("package main\n")
	s.WriteString("func scale(v uint32,n uint8) uint64 {\n out:=uint64(v)<<12\n guard:=false\n sticky:=false\n")
	for b := 0; b < 6; b++ {
		d := 1 << b
		fmt.Fprintf(&s, "if (n & %d)!=0 {\n sticky=sticky || guard || (out & %d)!=0\n guard=(out & %d)!=0\n out=out >> %d\n}\n", d, (uint64(1)<<(d-1))-1, uint64(1)<<(d-1), d)
	}
	s.WriteString("if guard && (sticky || (out & 1)!=0) {out=out+1}\n return out\n}\n")
	table := crossGridPWProfile{Pieces: p.Pieces, Coefficients: p.Coefficients}
	for col := 0; col < 3; col++ {
		s.WriteString(crossGridPWLookup(table, col))
	}
	shift := 0
	for 1<<shift < p.Width {
		shift++
	}
	fmt.Fprintf(&s, `func roundpoly(x uint64) uint32 {
 q:=uint32(x >> %d)
 r:=uint32(x & %d)
 if r > %d || (r == %d && (q & 1) != 0) {q=q+1}
 return q
}
func main(g [2]uint64,e uint32) (uint64,bool) {
 eta:=int32(uint32(g[0])+e)
 valid:=eta >= -1073741824 && eta <= 1073741824
 if !valid {eta=0}
 neg:=eta<0
 magnitude:=uint32(eta)
 if neg {magnitude=uint32(-eta)}
 raw:=uint64(magnitude)*%d
 k:=int32(raw >> 56)
 tail:=raw & 72057594037927935
 if tail > 36028797018963968 || (tail == 36028797018963968 && (k & 1)!=0) {k=k+1}
 residual:=int32(uint64(magnitude)*16-uint64(uint32(k))*%d)
 if neg {
 k=-k
 residual=-residual
 }
 rneg:=residual<0
 ar:=uint32(residual)
 if rneg {ar=uint32(-residual)}
 rq:=int32(ar >> 6)
 rt:=uint32(ar & 63)
 if rt > 32 || (rt == 32 && (rq & 1)!=0) {rq=rq+1}
 if rneg {rq=-rq}
 offset:=uint32(rq+8388608)
 i:=uint8(offset >> %d)
 r:=offset & %d
 v:=table1(i)+roundpoly(uint64(table2(i))*uint64(r))
 v=table0(i)+roundpoly(uint64(v)*uint64(r))
 out:=scale(v,uint8(23-k))
 if !valid {out=0}
 return out-g[1],valid
}
`, shift, p.Width-1, p.Width/2, p.Width/2, p.InvLn2, p.Ln2, shift, p.Width-1)
	return s.String()
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
