package main

// Arithmetic/cost experiment only. These profiles are deliberately absent from
// the production dispatcher and signed-contract allowlist until all gates pass.
import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"math/rand"
	"os"
	"strings"
	"testing"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/compiler/utils"
)

type crossGridPWProfile struct {
	TestVectors  [][2]uint32 `json:"test_vectors"`
	Identity     string      `json:"identity"`
	Family       string      `json:"family"`
	A            int         `json:"a"`
	Pieces       int         `json:"pieces"`
	FractionBits int         `json:"fraction_bits"`
	Width        int         `json:"interval_integer_width"`
	Coefficients [][3]int64  `json:"coefficients"`
	LossError    string      `json:"loss_error"`
}

func crossGridPWProfiles(t testing.TB) []crossGridPWProfile {
	t.Helper()
	data, err := os.ReadFile("../cross-grid-v2/profile_candidate.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Profiles []crossGridPWProfile `json:"profiles"`
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Profiles) != 30 {
		t.Fatal("invalid public profile inventory")
	}
	return fixture.Profiles
}

// Independent big.Int oracle; no floating-point products or truncations.
func crossGridPWOracle(p crossGridPWProfile, offset uint32) (uint32, bool) {
	if offset > uint32(2*p.A*65536) {
		return 0, false
	}
	j := int(offset) / p.Width
	if j == p.Pieces {
		j--
	}
	r := int64(offset) - int64(j*p.Width)
	c := p.Coefficients[j]
	div := big.NewInt(int64(p.Width))
	first := crossGridRoundDivV1(new(big.Int).Mul(big.NewInt(c[2]), big.NewInt(r)), div)
	first.Add(first, big.NewInt(c[1]))
	result := crossGridRoundDivV1(new(big.Int).Mul(first, big.NewInt(r)), div)
	result.Add(result, big.NewInt(c[0]))
	if !result.IsUint64() || result.BitLen() > 31 {
		panic("public profile width proof failed")
	}
	return uint32(result.Uint64()), true
}

// A balanced public-table mux uses index bits, avoiding K full-width compares.
func crossGridPWLookup(p crossGridPWProfile, column int) string {
	var out strings.Builder
	fmt.Fprintf(&out, "func table%d(i uint8) uint32 {\n", column)
	for j, c := range p.Coefficients {
		fmt.Fprintf(&out, "v0_%d := uint32(%d)\n", j, c[column])
	}
	for level, n := 1, p.Pieces/2; n > 0; level, n = level+1, n/2 {
		for j := 0; j < n; j++ {
			fmt.Fprintf(&out, "v%d_%d := v%d_%d\nif (i & %d) != 0 { v%d_%d = v%d_%d }\n", level, j, level-1, 2*j, 1<<(level-1), level, j, level-1, 2*j+1)
		}
	}
	fmt.Fprintf(&out, "return v%d_0\n}\n", bits.Len(uint(p.Pieces))-1)
	return out.String()
}

func crossGridPWSource(p crossGridPWProfile) string {
	var out strings.Builder
	out.WriteString("package main\n")
	for c := 0; c < 3; c++ {
		out.WriteString(crossGridPWLookup(p, c))
	}
	shift := bits.TrailingZeros(uint(p.Width))
	fmt.Fprintf(&out, `func rounded(x uint64) uint32 {
 q := uint32(x >> %d)
 r := uint32(x & %d)
 if r > %d || (r == %d && (q & 1) != 0) { q = q + 1 }
 return q
}
func main(g [2]uint32, e uint32) (uint32, bool) {
 x := g[0] + e
 valid := x <= %d
 if !valid { x = 0 }
 i := uint8(x >> %d)
 if i == %d { i = %d }
 r := x - uint32(i)*%d
 v := table1(i) + rounded(uint64(table2(i))*uint64(r))
 v = table0(i) + rounded(uint64(v)*uint64(r))
 if !valid { v = 0 }
 return v - g[1], valid
}
`, shift, p.Width-1, p.Width/2, p.Width/2, 2*p.A*65536, shift, p.Pieces, p.Pieces-1, p.Width)
	return out.String()
}

func crossGridPWCompilerParams() *utils.Params {
	p := utils.NewParams()
	p.OptPruneGates = true
	p.CircMultArrayTreshold = 128
	return p
}

func crossGridPWCompile(t testing.TB, p crossGridPWProfile) *circuit.Circuit {
	t.Helper()
	c, _, err := compiler.New(crossGridPWCompilerParams()).Compile(crossGridPWSource(p), nil)
	if err != nil {
		t.Fatal(err)
	}
	return crossGridPWOptimize(c)
}

func TestCrossGridPWV2CertificateDense(t *testing.T) {
	for _, p := range crossGridPWProfiles(t) {
		t.Run(p.Identity, func(t *testing.T) {
			var bound float64
			if _, err := fmt.Sscan(p.LossError, &bound); err != nil {
				t.Fatal(err)
			}
			maximum := 0.0
			// Real eta values intentionally lie off the eta16 lattice.
			for i := 0; i <= 16384; i++ {
				x := -float64(p.A) + float64(2*p.A)*float64(i)/16384 + 0.37/65536
				if x > float64(p.A) {
					x = float64(p.A)
				}
				offset := uint32(math.RoundToEven((x + float64(p.A)) * 65536))
				encoded, valid := crossGridPWOracle(p, offset)
				if !valid {
					t.Fatal("valid public point rejected")
				}
				want := math.Log1p(math.Exp(x))
				if p.Family == "poisson" {
					want = math.Exp(x)
				}
				error := math.Abs(float64(encoded)/math.Ldexp(1, p.FractionBits) - want)
				maximum = math.Max(maximum, error)
				if error > bound {
					t.Fatalf("public profile error exceeds certificate")
				}
			}
			t.Logf("dense_max=%.9g certified_loss_error=%.9g", maximum, bound)
		})
	}
}

func TestCrossGridPWV2CircuitOracleAndCost(t *testing.T) {
	rng := rand.New(rand.NewSource(20260918))
	for _, p := range crossGridPWProfiles(t) {
		// Compare alternative K at the intended utility-test domain and full domain.
		if p.A != 4 && p.A != 16 {
			continue
		}
		t.Run(p.Identity, func(t *testing.T) {
			c := crossGridPWCompile(t, p)
			var gateBytes uint64
			for _, g := range c.Gates {
				gateBytes += 16 * uint64(exactGCGarbledRowSize(g.Op))
			}
			t.Logf("gates=%d non_xor=%d garbled_table_bytes=%d input_bits=%d", c.NumGates, c.Stats.NumNonXOR(), gateBytes, c.Inputs.Size())
			values := []uint32{0, uint32(2 * p.A * 65536), uint32(2*p.A*65536 + 1), math.MaxUint32}
			for j := 1; j < p.Pieces; j++ {
				for d := -1; d <= 1; d++ {
					values = append(values, uint32(j*p.Width+d))
				}
			}
			for i := 0; i < 64; i++ {
				values = append(values, uint32(rng.Intn(2*p.A*65536+1)))
			}
			for _, x := range values {
				share, mask := rng.Uint32(), rng.Uint32()
				g := new(big.Int).SetUint64(uint64(mask)<<32 | uint64(share))
				result, err := c.Compute([]*big.Int{g, new(big.Int).SetUint64(uint64(x - share))})
				if err != nil {
					t.Fatal(err)
				}
				want, valid := crossGridPWOracle(p, x)
				if uint32(result[0].Uint64())+mask != want || (result[1].Sign() != 0) != valid {
					t.Fatal("integer circuit/oracle mismatch")
				}
			}
		})
	}
}

func TestCrossGridPWV2PublicVectorsAndHighPrecision(t *testing.T) {
	for _, p := range crossGridPWProfiles(t) {
		for _, v := range p.TestVectors {
			got, valid := crossGridPWOracle(p, v[0])
			if !valid || got != v[1] {
				t.Fatal("public integer fixture mismatch")
			}
		}
		var bound float64
		if _, err := fmt.Sscan(p.LossError, &bound); err != nil {
			t.Fatal(err)
		}
		for i := 0; i <= 32; i++ {
			x := -float64(p.A) + float64(2*p.A*i)/32
			arg := crossGridHighV1().SetFloat64(x)
			var expected *big.Float
			if p.Family == "binomial" {
				expected = crossGridHighSoftplusV1(arg)
			} else {
				expected = crossGridHighExpV1(arg)
			}
			encoded, _ := crossGridPWOracle(p, uint32(math.RoundToEven((x+float64(p.A))*65536)))
			got := crossGridHighV1().SetFloat64(float64(encoded) / math.Ldexp(1, p.FractionBits))
			error := crossGridHighV1().Sub(got, expected)
			error.Abs(error)
			if error.Cmp(crossGridHighV1().SetFloat64(bound)) > 0 {
				t.Fatal("independent high precision error exceeds certificate")
			}
		}
	}
}

func TestCrossGridPWV2NotAdmittedAsV1(t *testing.T) {
	for _, p := range crossGridPWProfiles(t) {
		contract, err := crossGridNumericContractV1(p.Family)
		if err != nil {
			t.Fatal(err)
		}
		contract.ProfileIdentity = p.Identity
		err = crossGridValidateNumericContractV1(p.Family, contract)
		if err == nil || err.Error() != "cross-grid contract rejected" {
			t.Fatal("candidate profile crossed the frozen admission boundary")
		}
	}
}
