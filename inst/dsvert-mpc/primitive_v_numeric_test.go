package main

import (
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"testing"

	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/compiler/utils"
)

func primitiveVTestNumericProgram(t *testing.T, expression string) *primitiveVProgram {
	t.Helper()
	source := "package main\n" + primitiveVNumericSource() + fmt.Sprintf("func main(g [2]int192,e [1]int192) [1]int192 {\nvar out [1]int192\nx := g[0]+e[0]\nout[0]=%s-g[1]\nreturn out\n}\n", expression)
	p, err := primitiveVCompile(source, 192, 2, 1, 1)
	if err != nil {
		_, _, detail := compiler.New(utils.NewParams()).Compile(source, nil)
		t.Fatalf("numeric compile: %v: %v", err, detail)
	}
	return p
}

func primitiveVTestCompute(t *testing.T, p *primitiveVProgram, g, e []*big.Int) []*big.Int {
	t.Helper()
	pack := func(words []*big.Int) *big.Int {
		out := new(big.Int)
		for i, w := range words {
			out.Or(out, new(big.Int).Lsh(exactGCEncodeSigned(w, 192), uint(192*i)))
		}
		return out
	}
	out, err := p.Circuit.Compute([]*big.Int{pack(g), pack(e)})
	if err != nil {
		t.Fatal(err)
	}
	// MPCL array return is one packed circuit output.
	result := make([]*big.Int, p.OutputWords)
	for i := range result {
		v := new(big.Int).Rsh(new(big.Int).Set(out[0]), uint(192*i))
		v.And(v, exactGCMask(192))
		result[i] = exactGCReferenceSigned(v, 192)
	}
	return result
}

func TestPrimitiveVNumericCircuitEquality(t *testing.T) {
	rng := rand.New(rand.NewSource(1974))
	cases := []struct {
		name, expr string
		ref        func(*big.Int) *big.Int
		values     []*big.Int
	}{
		{"exp", "primitiveVExpQ64(x)", primitiveVExpQ64Reference, nil},
		{"log", "primitiveVLogQ64(x)", func(x *big.Int) *big.Int {
			v, err := primitiveVLogQ64Reference(x)
			if err != nil {
				t.Fatal(err)
			}
			return v
		}, nil},
		{"negative_exp", "primitiveVExpNegativeQ64(x)", primitiveVExpNegativeQ64Reference, nil},
	}
	for j := range cases {
		if j == 1 {
			for _, bits := range []uint{0, 1, 31, 63, 64, 65, 80, 102, 126} {
				cases[j].values = append(cases[j].values, new(big.Int).Lsh(big.NewInt(1), bits))
			}
			cases[j].values = append(cases[j].values, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1)))
		} else {
			for _, k := range []int64{-17, -16, -1, 0, 1, 16, 17} {
				if j == 2 && k > 0 {
					continue
				}
				cases[j].values = append(cases[j].values, new(big.Int).Mul(big.NewInt(k), primitiveVScale))
			}
			if j == 2 {
				for _, k := range []int64{-32, -33, -1000000} {
					cases[j].values = append(cases[j].values, new(big.Int).Mul(big.NewInt(k), primitiveVScale))
				}
			}
		}
		for k := 0; k < 8; k++ {
			v := new(big.Int).SetUint64(rng.Uint64())
			if j != 1 && k%2 == 0 {
				v.Neg(v)
			}
			if j == 2 {
				v.Neg(new(big.Int).Abs(v))
			}
			cases[j].values = append(cases[j].values, v)
		}
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := primitiveVTestNumericProgram(t, c.expr)
			t.Logf("gates=%d table_bytes=%d", len(p.Circuit.Gates), primitiveVTableBytes(p.Circuit))
			for _, v := range c.values {
				got := primitiveVTestCompute(t, p, []*big.Int{v, big.NewInt(0)}, []*big.Int{big.NewInt(0)})[0]
				if got.Cmp(c.ref(v)) != 0 {
					t.Fatal("numeric circuit and independent integer reference differ")
				}
			}
		})
	}
}

func TestPrimitiveVNumericIndependentAccuracy(t *testing.T) {
	for k := -1700; k <= 1700; k++ {
		eta := primitiveVRoundDivReference(new(big.Int).Mul(big.NewInt(int64(k)), primitiveVScale), big.NewInt(100))
		x := crossGridHighV1().Quo(crossGridHighV1().SetInt(eta), crossGridHighV1().SetInt(primitiveVScale))
		want := crossGridHighExpV1(x)
		got := crossGridHighV1().Quo(crossGridHighV1().SetInt(primitiveVExpQ64Reference(eta)), crossGridHighV1().SetInt(primitiveVScale))
		relative := crossGridHighV1().Quo(crossGridHighV1().Abs(crossGridHighV1().Sub(got, want)), want)
		err, _ := relative.Float64()
		if err >= 7e-13 {
			t.Fatalf("exp relative certificate failed at public grid %d", k)
		}
		lse, err2 := primitiveVLogQ64Reference(primitiveVExpQ64Reference(eta))
		if err2 != nil {
			t.Fatal(err2)
		}
		delta := new(big.Int).Abs(new(big.Int).Sub(lse, eta))
		d, _ := new(big.Float).Quo(new(big.Float).SetInt(delta), new(big.Float).SetInt(primitiveVScale)).Float64()
		if d >= 7.1e-13 {
			t.Fatalf("log(exp) certificate failed at public grid %d", k)
		}
	}
	// Log independent real check uses 256-bit atanh, not binary64 math.Log.
	for k := 0; k < 128; k++ {
		v := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), uint(k)), big.NewInt(1))
		if v.BitLen() > 127 {
			continue
		}
		got, err := primitiveVLogQ64Reference(v)
		if err != nil {
			t.Fatal(err)
		}
		want := primitiveVHighLog(v)
		real := crossGridHighV1().Quo(crossGridHighV1().SetInt(got), crossGridHighV1().SetInt(primitiveVScale))
		difference, _ := crossGridHighV1().Abs(crossGridHighV1().Sub(real, want)).Float64()
		if difference >= 3e-17 {
			t.Fatal("log certificate failed")
		}
	}
	for _, bad := range []*big.Int{nil, big.NewInt(0), big.NewInt(-1), new(big.Int).Lsh(big.NewInt(1), 127)} {
		if _, err := primitiveVLogQ64Reference(bad); err == nil {
			t.Fatal("invalid log admitted")
		}
	}
}

func primitiveVHighLog(v *big.Int) *big.Float {
	k := v.BitLen() - 65
	m := crossGridHighV1().SetInt(v)
	m.SetMantExp(m, -64-k)
	one := crossGridHighV1().SetInt64(1)
	z := crossGridHighV1().Quo(crossGridHighV1().Sub(m, one), crossGridHighV1().Add(m, one))
	z2 := crossGridHighV1().Mul(z, z)
	term := crossGridHighV1().Set(z)
	sum := crossGridHighV1().SetInt64(0)
	for j := 0; j < 180; j++ {
		sum.Add(sum, crossGridHighV1().Quo(term, crossGridHighV1().SetInt64(int64(2*j+1))))
		term.Mul(term, z2)
	}
	sum.Mul(sum, crossGridHighV1().SetInt64(2))
	ln2 := crossGridHighLogRatioV1(2, 1)
	return sum.Add(sum, crossGridHighV1().Mul(crossGridHighV1().SetInt64(int64(k)), ln2))
}

func BenchmarkPrimitiveVExpReference(b *testing.B) {
	x := new(big.Int).Mul(big.NewInt(16), primitiveVScale)
	for i := 0; i < b.N; i++ {
		primitiveVExpQ64Reference(x)
	}
}

func TestPrimitiveVNumericRoundTies(t *testing.T) {
	for _, v := range []int64{-7, -5, -3, -1, 1, 3, 5, 7} {
		got := primitiveVRoundDivReference(big.NewInt(v), big.NewInt(2)).Int64()
		if got != int64(math.RoundToEven(float64(v)/2)) {
			t.Fatal("nearest even differs")
		}
	}
}

// This proves the outward numeric constants with exact rational arithmetic;
// pointwise high-precision tests above are supplementary, not the certificate.
func TestPrimitiveVNumericAnalyticCertificate(t *testing.T) {
	rat := func(n, d int64) *big.Rat { return big.NewRat(n, d) }
	add := func(a, b *big.Rat) *big.Rat { return new(big.Rat).Add(a, b) }
	mul := func(a, b *big.Rat) *big.Rat { return new(big.Rat).Mul(a, b) }
	quo := func(a, b *big.Rat) *big.Rat { return new(big.Rat).Quo(a, b) }
	pow := func(a *big.Rat, n int) *big.Rat {
		out := rat(1, 1)
		for i := 0; i < n; i++ {
			out.Mul(out, a)
		}
		return out
	}
	expUpper := func(x *big.Rat) *big.Rat {
		sum, term := rat(1, 1), rat(1, 1)
		for k := 1; k <= 128; k++ {
			term = quo(mul(term, x), rat(int64(k), 1))
			sum.Add(sum, term)
		}
		next := quo(mul(term, x), rat(129, 1))
		tail := quo(next, new(big.Rat).Sub(rat(1, 1), quo(x, rat(130, 1))))
		return add(sum, tail)
	}
	u := new(big.Rat).SetFrac(big.NewInt(1), primitiveVScale)
	radius := rat(133, 500)
	if expUpper(radius).Cmp(rat(4, 3)) >= 0 {
		t.Fatal("exp core modulus bound failed")
	}
	factorial := big.NewInt(1)
	for k := 2; k <= 13; k++ {
		factorial.Mul(factorial, big.NewInt(int64(k)))
	}
	e0 := add(add(quo(mul(rat(4, 3), pow(radius, 13)), new(big.Rat).SetInt(factorial)), quo(u, new(big.Rat).Sub(rat(1, 1), radius))), mul(rat(2, 3), u))
	relative := mul(rat(4, 3), e0)
	for i, bound := range []int64{2, 3, 9, 71, 4915, 24154953} {
		if expUpper(rat(17, 32>>uint(i))).Cmp(rat(bound, 1)) >= 0 {
			t.Fatal("inverse exponential bound failed")
		}
		relative = add(add(mul(rat(2, 1), relative), mul(relative, relative)), mul(u, rat(bound, 2)))
	}
	if relative.Cmp(rat(7, 10000000000000)) >= 0 {
		t.Fatal("relative exp error certificate failed")
	}
	absolute := e0
	for i := 0; i < 6; i++ {
		absolute = add(add(mul(rat(2, 1), absolute), mul(absolute, absolute)), mul(u, rat(1, 2)))
	}
	negativeErr := add(add(mul(rat(2, 1), absolute), mul(absolute, absolute)), u)
	if negativeErr.Cmp(rat(1, 1000000000000000)) >= 0 {
		t.Fatal("negative exp evaluation error certificate failed")
	}
	// exp(32) exceeds the finite positive Taylor sum; inversion gives tail bound.
	sum, term := rat(1, 1), rat(1, 1)
	for k := 1; k <= 128; k++ {
		term = quo(mul(term, rat(32, 1)), rat(int64(k), 1))
		sum.Add(sum, term)
	}
	if quo(rat(1, 1), sum).Cmp(rat(13, 1000000000000000)) >= 0 {
		t.Fatal("negative exp cutoff certificate failed")
	}
	tail := quo(rat(2, 1), mul(mul(rat(41, 1), pow(rat(3, 1), 41)), rat(8, 9)))
	logErr := add(mul(rat(80, 1), u), tail)
	if logErr.Cmp(rat(3, 100000000000000000)) >= 0 {
		t.Fatal("log roundoff certificate failed")
	}
	// ln2=2 atanh(1/3); enclose it with rational truncation and geometric tail.
	log2 := rat(0, 1)
	for j := 0; j < 80; j++ {
		log2.Add(log2, quo(rat(2, 1), mul(rat(int64(2*j+1), 1), pow(rat(3, 1), 2*j+1))))
	}
	log2Tail := quo(rat(2, 1), mul(mul(rat(161, 1), pow(rat(3, 1), 161)), rat(8, 9)))
	encodedLn2 := new(big.Rat).SetFrac(primitiveVLn2, primitiveVScale)
	halfU := mul(u, rat(1, 2))
	lo := new(big.Rat).Sub(encodedLn2, halfU)
	hi := add(encodedLn2, halfU)
	if log2.Cmp(lo) <= 0 || add(log2, log2Tail).Cmp(hi) >= 0 {
		t.Fatal("ln2 q64 nearest rounding certificate failed")
	}
}

func TestPrimitiveVNumericCompiledShiftTies(t *testing.T) {
	limit := new(big.Int).Mul(big.NewInt(17), primitiveVScale)
	for _, c := range []struct {
		name    string
		divisor int64
	}{{"primitiveVDiv64", 64}, {"primitiveVDiv2", 2}} {
		t.Run(c.name, func(t *testing.T) {
			p := primitiveVTestNumericProgram(t, c.name+"(x)")
			divisor := big.NewInt(c.divisor)
			largeQuotient := new(big.Int).Sub(new(big.Int).Quo(limit, divisor), big.NewInt(1))
			values := []*big.Int{new(big.Int), new(big.Int).Set(limit), new(big.Int).Neg(limit)}
			for _, quotient := range []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2), largeQuotient} {
				halfway := new(big.Int).Add(new(big.Int).Mul(quotient, divisor), big.NewInt(c.divisor/2))
				for _, offset := range []int64{-1, 0, 1} {
					v := new(big.Int).Add(halfway, big.NewInt(offset))
					values = append(values, v, new(big.Int).Neg(v))
				}
			}
			for _, v := range values {
				got := primitiveVTestCompute(t, p, []*big.Int{v, new(big.Int)}, []*big.Int{new(big.Int)})[0]
				want := primitiveVRoundDivReference(v, divisor)
				if got.Cmp(want) != 0 {
					t.Fatal("compiled signed shift differs at a public tie or neighboring fixture")
				}
			}
		})
	}
}
