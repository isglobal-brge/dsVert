package main

import (
	"encoding/json"
	"fmt"
	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/compiler/utils"
	"math"
	"math/big"
	"math/rand"
	"os"
	"strings"
	"testing"
)

func familyLossCompile(t *testing.T, source string) *circuit.Circuit {
	t.Helper()
	c, _, err := compiler.New(utils.NewParams()).Compile(source, nil)
	if err != nil {
		t.Fatal(err)
	}
	and, or, inv := 0, 0, 0
	for _, g := range c.Gates {
		switch g.Op {
		case circuit.AND:
			and++
		case circuit.OR:
			or++
		case circuit.INV:
			inv++
		}
	}
	bytes := 32*and + 48*or + 16*inv
	t.Logf("circuit gates=%d AND=%d OR=%d INV=%d garbled_table_bytes=%d n10000_grid50_bytes=%d target_met=%v", len(c.Gates), and, or, inv, bytes, int64(bytes)*500000, and <= 2000)
	return c
}
func familyLossCompute(t *testing.T, c *circuit.Circuit, values []*big.Int) (*big.Int, bool) {
	t.Helper()
	rng := rand.New(rand.NewSource(733))
	g, e := make([]*big.Int, len(values)), make([]*big.Int, len(values))
	for i, v := range values {
		g[i] = new(big.Int).Rand(rng, familyPow2(192))
		e[i] = new(big.Int).Mod(new(big.Int).Sub(v, g[i]), familyPow2(192))
	}
	mask := new(big.Int).Rand(rng, familyPow2(192))
	g = append(g, mask, big.NewInt(1))
	out, err := c.Compute([]*big.Int{familyPack(g), familyPack(e)})
	if err != nil {
		t.Fatal(err)
	}
	// main returns one packed two-element array.
	loss := new(big.Int).And(out[0], new(big.Int).Sub(familyPow2(192), big.NewInt(1)))
	loss.Add(loss, mask).Mod(loss, familyPow2(192))
	guard := new(big.Int).Rsh(out[0], 192).Bit(0) == 0
	return loss, guard
}
func familyPow2(n uint) *big.Int { return new(big.Int).Lsh(big.NewInt(1), n) }
func familyPack(v []*big.Int) *big.Int {
	out := big.NewInt(0)
	for i := len(v) - 1; i >= 0; i-- {
		out.Lsh(out, 192).Add(out, v[i])
	}
	return out
}
func familyRound(x int64, bits uint) int64 {
	negative := x < 0
	if negative {
		x = -x
	}
	q, r := x>>bits, x&((1<<bits)-1)
	if bits > 0 && (r > 1<<(bits-1) || (r == 1<<(bits-1) && q&1 != 0)) {
		q++
	}
	if negative {
		q = -q
	}
	return q
}
func familyPolynomial(x int64, table [64][3]int64, bits uint) int64 {
	i, t := x>>bits, x&((1<<bits)-1)
	if i >= 64 {
		i, t = 63, 1<<bits
	}
	v := table[i]
	return v[0] + familyRound(t*(v[1]+familyRound(v[2]*t, 16)), 16)
}
func familyExp16(x int64) int64 {
	if x == 0 {
		return 65536
	}
	if x < -16*65536 {
		return 0
	}
	return familyPolynomial(x+16*65536, exactGCFamilyExpProfile, 14)
}
func familyLog16(x int64) int64 {
	m, r := x, 0
	for k := 1; k <= 3; k++ {
		if x >= 65536<<k {
			m, r = familyRound(x, uint(k)), k
		}
	}
	return familyPolynomial(m-65536, exactGCFamilyLogProfile, 10) + int64(r)*45426
}
func familySoft16(x int64) int64 {
	a := x
	if a < 0 {
		a = -a
	}
	v := familyPolynomial(a, exactGCFamilySoftProfile, 14)
	if x > 0 {
		v += x
	}
	return v
}
func familyLossReference(family string, s exactGCFamilyLossSpec, dots []*big.Int, y int, valid bool) *big.Int {
	if !valid {
		return big.NewInt(0)
	}
	etas := make([]int64, len(dots))
	for i, d := range dots {
		etas[i] = exactGCOrdinalPublicRound(d, familyPow2(84)).Int64()
	}
	var loss int64
	if family == "multinomial" {
		maximum := int64(0)
		for _, eta := range etas {
			if eta > maximum {
				maximum = eta
			}
		}
		sum := familyExp16(-maximum)
		for _, eta := range etas {
			sum += familyExp16(eta - maximum)
		}
		loss = familyLog16(sum) + maximum
		if y > 0 {
			loss -= etas[y-1]
		}
	} else {
		cs := make([]int64, len(s.Thresholds))
		for i, v := range s.Thresholds {
			cs[i] = exactGCOrdinalPublicRound(exactGCFamilyInteger(v), familyPow2(34)).Int64()
		}
		if y == 0 {
			x := cs[0] - etas[0]
			loss = familySoft16(x) - x
		} else if y == s.Classes-1 {
			loss = familySoft16(cs[len(cs)-1] - etas[0])
		} else {
			hi, lo := cs[y]-etas[0], cs[y-1]-etas[0]
			gap := new(big.Int).Lsh(new(big.Int).Sub(exactGCFamilyInteger(s.Thresholds[y]), exactGCFamilyInteger(s.Thresholds[y-1])), 14)
			gaplog := exactGCOrdinalPublicRound(exactGCOrdinalPublicGapLog(gap), familyPow2(48)).Int64()
			loss = familySoft16(hi) + familySoft16(lo) - hi - gaplog
		}
	}
	if loss < 0 {
		loss = 0
	}
	if s.GridBits < 16 {
		loss = familyRound(loss, uint(16-s.GridBits))
	} else {
		loss <<= uint(s.GridBits - 16)
	}
	if loss > s.Cap {
		loss = s.Cap
	}
	return big.NewInt(loss)
}
func familyDot(v int64) *big.Int { return new(big.Int).Lsh(big.NewInt(v), 100) }

func TestExactGCMultinomialLossCircuit(t *testing.T) {
	s := exactGCFamilyLossSpec{Classes: 2, GridBits: 18, Cap: 9000000}
	source, err := exactGCMultinomialLossSource(s)
	if err != nil {
		t.Fatal(err)
	}
	c := familyLossCompile(t, source)
	slack := new(big.Int).Lsh(big.NewInt(9), 50)
	dots := []*big.Int{familyDot(-16), big.NewInt(0), familyDot(16), new(big.Int).Add(familyDot(16), slack), new(big.Int).Neg(new(big.Int).Add(familyDot(16), slack)), new(big.Int).Lsh(big.NewInt(1), 83), new(big.Int).Lsh(big.NewInt(3), 83), new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(3), 83))}
	for _, odd := range []int64{-3, -1, 1, 3} {
		tie := new(big.Int).Lsh(big.NewInt(odd), 83)
		for _, delta := range []int64{-1, 0, 1} {
			dots = append(dots, new(big.Int).Add(tie, big.NewInt(delta)))
		}
	}
	for _, dot := range dots {
		for y := 0; y < 2; y++ {
			for _, valid := range []bool{false, true} {
				v := int64(0)
				if valid {
					v = 1
				}
				got, guard := familyLossCompute(t, c, []*big.Int{dot, big.NewInt(int64(y)), big.NewInt(v)})
				want := familyLossReference("multinomial", s, []*big.Int{dot}, y, valid)
				if !guard || got.Cmp(want) != 0 {
					t.Fatalf("dot=%s y=%d valid=%v got=%s guard=%v want=%s", dot, y, valid, got, guard, want)
				}
			}
		}
	}
	for _, values := range [][]*big.Int{{new(big.Int).Add(dots[3], big.NewInt(1)), big.NewInt(0), big.NewInt(1)}, {big.NewInt(0), big.NewInt(2), big.NewInt(1)}, {big.NewInt(0), big.NewInt(0), big.NewInt(2)}} {
		got, guard := familyLossCompute(t, c, values)
		if guard || got.Sign() != 0 {
			t.Fatal("invalid private input did not fail closed")
		}
	}
}
func TestExactGCFamilyPublicRegistrationAndValidation(t *testing.T) {
	for _, r := range []exactGCFamilyLossRegistration{exactGCRegisterMultinomialLossV1(), exactGCRegisterOrdinalLossV1()} {
		if r.Version != r.Family+"_grid_cross_v1" {
			t.Fatal(r)
		}
		for _, s := range []exactGCFamilyLossSpec{{Classes: 1, GridBits: 18, Cap: 1}, {Classes: 9, GridBits: 18, Cap: 1}, {Classes: 2, GridBits: 7, Cap: 1}, {Classes: 2, GridBits: 19, Cap: 1}, {Classes: 2, GridBits: 18, Cap: 0}, {Classes: 2, GridBits: 18, Cap: 9007199254740992}} {
			if _, err := r.Source(s); err == nil || err.Error() != "cross-grid family contract rejected" {
				t.Fatal("invalid public spec accepted")
			}
		}
	}
	if _, err := exactGCMultinomialLossSource(exactGCFamilyLossSpec{Classes: 2, GridBits: 18, Cap: 1, Thresholds: []string{"0"}}); err == nil {
		t.Fatal("unexpected threshold accepted")
	}
}
func TestExactGCFamilyMathCircuit(t *testing.T) {
	for _, test := range []struct {
		name      string
		values    []int64
		reference func(int64) int64
	}{
		{"exp16", []int64{-32 * 65536, -16 * 65536, -16*65536 + 1, -65536, -1, 0}, familyExp16},
		{"log16", []int64{65536, 65537, 2*65536 - 1, 2 * 65536, 8 * 65536}, familyLog16},
		{"soft16", []int64{-16 * 65536, -65536, -1, 0, 1, 65536, 16 * 65536}, familySoft16},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := exactGCFamilyMathSource() + "func main(g uint32,e uint32) uint32 { return " + test.name + "(g+e) }\n"
			c := familyLossCompile(t, source)
			for k := 0; k <= 64; k++ {
				for _, delta := range []int64{-1, 0, 1} {
					var v int64
					if test.name == "exp16" {
						v = int64(k-64)*16384 + delta
						if v > 0 {
							continue
						}
					} else if test.name == "log16" {
						v = 65536 + int64(k)*1024 + delta
						if v < 65536 || v > 131072 {
							continue
						}
					} else {
						v = int64(k)*16384 + delta
						if v < 0 || v > 16*65536 {
							continue
						}
					}
					test.values = append(test.values, v)
				}
			}
			for _, v := range test.values {
				out, err := c.Compute([]*big.Int{new(big.Int).SetUint64(uint64(uint32(v))), big.NewInt(0)})
				if err != nil {
					t.Fatal(err)
				}
				if out[0].Uint64() != uint64(uint32(test.reference(v))) {
					t.Fatalf("%d got=%s want=%d", v, out[0], test.reference(v))
				}
			}
		})
	}
}
func TestExactGCFamilyReferenceAccuracy(t *testing.T) {
	for classes := 2; classes <= 8; classes++ {
		s := exactGCFamilyLossSpec{Classes: classes, GridBits: 18, Cap: 12000000}
		for _, eta := range []int64{-16, -8, 0, 8, 16} {
			dots := make([]*big.Int, classes-1)
			for i := range dots {
				dots[i] = familyDot(eta)
			}
			for y := 0; y < classes; y++ {
				got := float64(familyLossReference("multinomial", s, dots, y, true).Int64()) / (1 << 18)
				want := math.Log1p(float64(classes-1) * math.Exp(float64(eta)))
				if y > 0 {
					want -= float64(eta)
				}
				if math.Abs(got-want) > 0.0011 {
					t.Fatalf("multinomial error %g", got-want)
				}
			}
		}
	}
	// Production source contains no float evaluation or reference loss callback.
	src, _ := exactGCMultinomialLossSource(exactGCFamilyLossSpec{Classes: 8, GridBits: 18, Cap: 12000000})
	if strings.Contains(src, "float") || strings.Contains(src, "Reference") {
		t.Fatal("unexpected cleartext source")
	}
}

func TestExactGCFamilyProfileDenseCertificate(t *testing.T) {
	const points = 200000
	maxExp, maxLog, maxSoft := 0.0, 0.0, 0.0
	for i := 0; i <= points; i++ {
		e := -32*65536 + int64(i)*(32*65536)/points
		x := float64(e) / 65536
		maxExp = math.Max(maxExp, math.Abs(float64(familyExp16(e))/65536-math.Exp(x)))
		l := int64(65536) + int64(i)*(7*65536)/points
		maxLog = math.Max(maxLog, math.Abs(float64(familyLog16(l))/65536-math.Log(float64(l)/65536)))
		a := -16*65536 + int64(i)*(32*65536)/points
		maxSoft = math.Max(maxSoft, math.Abs(float64(familySoft16(a))/65536-math.Log1p(math.Exp(float64(a)/65536))))
	}
	t.Logf("dense profile points=%d exp_error=%g log_error=%g softplus_error=%g", points+1, maxExp, maxLog, maxSoft)
	if maxExp > 0.000147206 || maxLog > 0.00004608 || maxSoft > 0.000031607 {
		t.Fatal("profile exceeded analytic component certificate")
	}
	if familyExp16(0) != 65536 {
		t.Fatal("normalization identity not exact")
	}
}

func TestExactGCFamilyProfileWordBounds(t *testing.T) {
	for _, p := range []struct {
		table [64][3]int64
		shift uint
	}{
		{exactGCFamilyExpProfile, 14}, {exactGCFamilyLogProfile, 10}, {exactGCFamilySoftProfile, 14},
	} {
		for _, c := range p.table {
			for x := int64(0); x <= 1<<p.shift; x++ {
				first := c[2] * x
				second := (c[1] + familyRound(first, 16)) * x
				if first < -1<<31 || first > 1<<31-1 || second < -1<<31 || second > 1<<31-1 {
					t.Fatal("profile multiplication exceeds signed32")
				}
			}
		}
	}
}

func TestExactGCFamilyClassCostMatrix(t *testing.T) {
	for _, family := range []string{"multinomial", "ordinal"} {
		for _, classes := range []int{2, 3, 8} {
			t.Run(fmt.Sprintf("%s_K%d", family, classes), func(t *testing.T) {
				s := exactGCFamilyLossSpec{Classes: classes, GridBits: 18, Cap: 12000000}
				var source string
				var err error
				if family == "ordinal" {
					for k := 0; k < classes-1; k++ {
						s.Thresholds = append(s.Thresholds, new(big.Int).Lsh(big.NewInt(int64(-128+k)), 46).String())
					}
					source, err = exactGCOrdinalLossSource(s)
				} else {
					source, err = exactGCMultinomialLossSource(s)
				}
				if err != nil {
					t.Fatal(err)
				}
				c := familyLossCompile(t, source)
				n := classes - 1
				if family == "ordinal" {
					n = 1
				}
				for y := 0; y < classes; y++ {
					dots := make([]*big.Int, n)
					for k := range dots {
						dots[k] = familyDot(int64((k%2)*16 - 8))
					}
					values := append(append([]*big.Int{}, dots...), big.NewInt(int64(y)), big.NewInt(1))
					got, guard := familyLossCompute(t, c, values)
					want := familyLossReference(family, s, dots, y, true)
					if !guard || got.Cmp(want) != 0 {
						t.Fatalf("profile equality failed got=%s want=%s guard=%v", got, want, guard)
					}
				}
			})
		}
	}
}

func TestExactGCFamilyPinnedBoundaryFixtures(t *testing.T) {
	var fixture struct {
		Hash  string `json:"profile_sha256"`
		Cases map[string][]struct {
			Input  int64 `json:"input_q16"`
			Output int64 `json:"output_q16"`
		} `json:"cases"`
	}
	data, err := os.ReadFile("../cross-grid-family-b/piecewise_boundary_fixtures_v1.json")
	if err != nil || json.Unmarshal(data, &fixture) != nil {
		t.Fatal("public fixture unavailable")
	}
	if fixture.Hash != exactGCRegisterMultinomialLossV1().ProfileSHA256 {
		t.Fatal("profile fixture hash mismatch")
	}
	functions := map[string]func(int64) int64{
		"exp":        func(x int64) int64 { return familyPolynomial(x+16*65536, exactGCFamilyExpProfile, 14) },
		"log":        func(x int64) int64 { return familyPolynomial(x-65536, exactGCFamilyLogProfile, 10) },
		"softminus":  func(x int64) int64 { return familyPolynomial(x, exactGCFamilySoftProfile, 14) },
		"exp_kernel": familyExp16, "log_kernel": familyLog16,
	}
	for key, rows := range fixture.Cases {
		fn, ok := functions[key]
		if !ok {
			t.Fatal("unknown fixture kernel")
		}
		for _, row := range rows {
			if fn(row.Input) != row.Output {
				t.Fatalf("%s fixture input=%d got=%d want=%d", key, row.Input, fn(row.Input), row.Output)
			}
		}
	}
}

func TestExactGCFamilyInputRounding(t *testing.T) {
	source := exactGCFamilyMathSource() + "func main(g uint192,e uint192) uint32 { return eta16(g+e) }\n"
	c := familyLossCompile(t, source)
	for _, odd := range []int64{-5, -3, -1, 1, 3, 5} {
		for _, delta := range []int64{-1, 0, 1} {
			raw := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(odd), 83), big.NewInt(delta))
			encoded := new(big.Int).Mod(new(big.Int).Set(raw), familyPow2(192))
			out, err := c.Compute([]*big.Int{encoded, big.NewInt(0)})
			if err != nil {
				t.Fatal(err)
			}
			want := uint32(exactGCOrdinalPublicRound(raw, familyPow2(84)).Int64())
			if out[0].Uint64() != uint64(want) {
				t.Fatal("direct f100 rounding differs at half tie")
			}
		}
	}
}

func TestExactGCFamilyOutputQuantizationAndClamp(t *testing.T) {
	for _, g := range []int{8, 16, 18} {
		s := exactGCFamilyLossSpec{Classes: 2, GridBits: g, Cap: 100}
		var source strings.Builder
		source.WriteString(exactGCFamilyMathSource())
		source.WriteString("func main(g [5]uint192,e [3]uint192) [2]uint192 {\nloss:=uint32(g[0]+e[0])\nvalid:=g[2]+e[2]\nguard:=valid<=uint192(1)\n")
		exactGCFamilyFinishSource(&source, s, 3)
		c := familyLossCompile(t, source.String())
		for _, raw := range []int64{-1, 0, 1, 127, 128, 129, 383, 384, 385, 25599, 25600, 25601, 65536} {
			got, guard := familyLossCompute(t, c, []*big.Int{big.NewInt(raw), big.NewInt(0), big.NewInt(1)})
			want := raw
			if want < 0 {
				want = 0
			}
			if g < 16 {
				want = familyRound(want, uint(16-g))
			} else {
				want <<= uint(g - 16)
			}
			if want > s.Cap {
				want = s.Cap
			}
			if !guard || got.Int64() != want {
				t.Fatal("final nearest-even quantization or clamp differs")
			}
		}
	}
}
