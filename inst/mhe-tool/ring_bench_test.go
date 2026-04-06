package main

import (
	"math/big"
	"math/rand"
	"testing"
)

// benchRNG returns a *math/rand.Rand seeded from crypto/rand, suitable for
// generating random big.Int values in benchmarks (NOT for crypto).
func benchRNG() *rand.Rand {
	seed := int64(cryptoRandUint64K2() >> 1)
	return rand.New(rand.NewSource(seed))
}

// randBig128 returns a random big.Int in [0, mod128).
func randBig128(rng *rand.Rand) *big.Int {
	return new(big.Int).Rand(rng, mod128)
}

// ============================================================================
// 1. Ring63 Add — current: (a+b) % modulus with uint64
// ============================================================================

func BenchmarkRing63Add(b *testing.B) {
	r := NewRing63(20)
	a := cryptoRandUint64K2() % r.Modulus
	x := cryptoRandUint64K2() % r.Modulus
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a = r.Add(a, x)
	}
	_ = a
}

// ============================================================================
// 2. Ring128 Add — math/big with 128-bit values in Z_{2^127}
// ============================================================================

var mod128 = new(big.Int).Lsh(big.NewInt(1), 127) // 2^127

func ring128Add(a, x, m *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Add(a, x), m)
}

func BenchmarkRing128Add(b *testing.B) {
	rng := benchRNG()
	a := randBig128(rng)
	x := randBig128(rng)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a = ring128Add(a, x, mod128)
	}
	_ = a
}

// ============================================================================
// 3. Ring63 modMulBig63 — current: big.Int multiply mod 2^63
// ============================================================================

func BenchmarkRing63ModMulBig63(b *testing.B) {
	r := NewRing63(20)
	a := cryptoRandUint64K2() % r.Modulus
	x := cryptoRandUint64K2() % r.Modulus
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a = modMulBig63(a, x, r.Modulus)
	}
	_ = a
}

// ============================================================================
// 4. Ring128 modMulBig128 — big.Int multiply mod 2^127
// ============================================================================

func ring128ModMul(a, x, m *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Mul(a, x), m)
}

func BenchmarkRing128ModMulBig128(b *testing.B) {
	rng := benchRNG()
	a := randBig128(rng)
	x := randBig128(rng)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a = ring128ModMul(a, x, mod128)
	}
	_ = a
}

// ============================================================================
// 5. Ring63 TruncMul
// ============================================================================

func BenchmarkRing63TruncMul(b *testing.B) {
	r := NewRing63(20)
	a := cryptoRandUint64K2() % r.Modulus
	x := cryptoRandUint64K2() % r.Modulus
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a = r.TruncMul(a, x)
	}
	_ = a
}

// ============================================================================
// 6. Ring128 TruncMul — (a*b) >> 40 mod 2^127, with 40 fractional bits
// ============================================================================

func ring128TruncMul(a, x, m *big.Int, fracBits uint) *big.Int {
	product := new(big.Int).Mul(a, x)
	product.Rsh(product, fracBits)
	product.Mod(product, m)
	return product
}

func BenchmarkRing128TruncMul(b *testing.B) {
	rng := benchRNG()
	a := randBig128(rng)
	x := randBig128(rng)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a = ring128TruncMul(a, x, mod128, 40)
	}
	_ = a
}

// ============================================================================
// 7. Full HadamardProductLocal at Ring63 (n=155)
// ============================================================================

func BenchmarkRing63HadamardProductLocal_n155(b *testing.B) {
	const n = 155
	r := NewRing63(20)

	x0 := make([]uint64, n)
	x1 := make([]uint64, n)
	y0 := make([]uint64, n)
	y1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		val := r.FromDouble(float64(int(cryptoRandUint64K2()%2000)-1000) / 100.0)
		x0[i], x1[i] = r.SplitShare(val)
		val = r.FromDouble(float64(int(cryptoRandUint64K2()%2000)-1000) / 100.0)
		y0[i], y1[i] = r.SplitShare(val)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = HadamardProductLocal(x0, y0, x1, y1, 20, r)
	}
}

// ============================================================================
// 8. Simulated Ring128 HadamardProductLocal (n=155, using big.Int)
//
//    Mirrors the Ring63 protocol structure: Beaver triple generation,
//    gate message exchange, Party0/Party1 output, and truncation --
//    all lifted to Z_{2^127} with 40 fractional bits.
// ============================================================================

// ring128Ctx holds parameters for the 2^127 ring.
type ring128Ctx struct {
	Modulus  *big.Int
	FracBits uint
}

func newRing128Ctx(fracBits uint) ring128Ctx {
	return ring128Ctx{
		Modulus:  new(big.Int).Set(mod128),
		FracBits: fracBits,
	}
}

func (r ring128Ctx) add(a, b *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Add(a, b), r.Modulus)
}

func (r ring128Ctx) sub(a, b *big.Int) *big.Int {
	result := new(big.Int).Add(new(big.Int).Sub(a, b), r.Modulus)
	return result.Mod(result, r.Modulus)
}

func (r ring128Ctx) mul(a, b *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Mul(a, b), r.Modulus)
}

func (r ring128Ctx) splitShare(rng *rand.Rand, value *big.Int) (s0, s1 *big.Int) {
	s0 = new(big.Int).Rand(rng, r.Modulus)
	s1 = r.sub(value, s0)
	return
}

func (r ring128Ctx) fromDouble(x float64) *big.Int {
	fracMul := new(big.Int).Lsh(big.NewInt(1), r.FracBits)
	fracMulF := float64(uint64(1) << r.FracBits)
	if x >= 0 {
		scaled := new(big.Int).SetUint64(uint64(x*fracMulF + 0.5))
		return scaled.Mod(scaled, r.Modulus)
	}
	abs := new(big.Int).SetUint64(uint64(-x*fracMulF + 0.5))
	abs.Mod(abs, r.Modulus)
	_ = fracMul
	return r.sub(big.NewInt(0), abs)
}

// beaver128 holds element-wise Beaver triple shares for one party.
type beaver128 struct {
	A, B, C []*big.Int
}

func sampleBeaverTripleVec128(rng *rand.Rand, length int, r ring128Ctx) (party0, party1 beaver128) {
	party0 = beaver128{
		A: make([]*big.Int, length),
		B: make([]*big.Int, length),
		C: make([]*big.Int, length),
	}
	party1 = beaver128{
		A: make([]*big.Int, length),
		B: make([]*big.Int, length),
		C: make([]*big.Int, length),
	}
	for i := 0; i < length; i++ {
		a := new(big.Int).Rand(rng, r.Modulus)
		b := new(big.Int).Rand(rng, r.Modulus)
		c := r.mul(a, b)
		party0.A[i], party1.A[i] = r.splitShare(rng, a)
		party0.B[i], party1.B[i] = r.splitShare(rng, b)
		party0.C[i], party1.C[i] = r.splitShare(rng, c)
	}
	return
}

type multState128 struct {
	ShareXMinusA []*big.Int
	ShareYMinusB []*big.Int
}

type multMsg128 struct {
	XMinusAShares []*big.Int
	YMinusBShares []*big.Int
}

func genMultGateMsg128(
	shareX, shareY []*big.Int,
	bvr beaver128,
	r ring128Ctx,
) (state multState128, msg multMsg128) {
	n := len(shareX)
	state.ShareXMinusA = make([]*big.Int, n)
	state.ShareYMinusB = make([]*big.Int, n)
	msg.XMinusAShares = make([]*big.Int, n)
	msg.YMinusBShares = make([]*big.Int, n)
	for i := 0; i < n; i++ {
		state.ShareXMinusA[i] = r.sub(shareX[i], bvr.A[i])
		state.ShareYMinusB[i] = r.sub(shareY[i], bvr.B[i])
		msg.XMinusAShares[i] = new(big.Int).Set(state.ShareXMinusA[i])
		msg.YMinusBShares[i] = new(big.Int).Set(state.ShareYMinusB[i])
	}
	return
}

func hadamardP0_128(
	state multState128,
	bvr beaver128,
	otherMsg multMsg128,
	r ring128Ctx,
) []*big.Int {
	n := len(state.ShareXMinusA)
	result := make([]*big.Int, n)
	divisor := new(big.Int).Lsh(big.NewInt(1), r.FracBits)
	for i := 0; i < n; i++ {
		xMinusA := r.add(state.ShareXMinusA[i], otherMsg.XMinusAShares[i])
		yMinusB := r.add(state.ShareYMinusB[i], otherMsg.YMinusBShares[i])
		bTimesXA := r.mul(bvr.B[i], xMinusA)
		aTimesYB := r.mul(bvr.A[i], yMinusB)
		xaTimesYB := r.mul(xMinusA, yMinusB)
		raw := r.add(r.add(r.add(bvr.C[i], bTimesXA), aTimesYB), xaTimesYB)
		truncated := new(big.Int).Div(raw, divisor)
		truncated.Mod(truncated, r.Modulus)
		result[i] = truncated
	}
	return result
}

func hadamardP1_128(
	state multState128,
	bvr beaver128,
	otherMsg multMsg128,
	r ring128Ctx,
) []*big.Int {
	n := len(state.ShareXMinusA)
	result := make([]*big.Int, n)
	divisor := new(big.Int).Lsh(big.NewInt(1), r.FracBits)
	for i := 0; i < n; i++ {
		xMinusA := r.add(state.ShareXMinusA[i], otherMsg.XMinusAShares[i])
		yMinusB := r.add(state.ShareYMinusB[i], otherMsg.YMinusBShares[i])
		bTimesXA := r.mul(bvr.B[i], xMinusA)
		aTimesYB := r.mul(bvr.A[i], yMinusB)
		raw := r.add(r.add(bvr.C[i], bTimesXA), aTimesYB)
		negS := new(big.Int).Sub(r.Modulus, raw)
		negS.Mod(negS, r.Modulus)
		truncated := new(big.Int).Div(negS, divisor)
		truncated.Sub(r.Modulus, truncated)
		truncated.Mod(truncated, r.Modulus)
		result[i] = truncated
	}
	return result
}

func hadamardLocal128(
	rng *rand.Rand,
	x0, y0, x1, y1 []*big.Int,
	r ring128Ctx,
) ([]*big.Int, []*big.Int) {
	n := len(x0)
	bvr0, bvr1 := sampleBeaverTripleVec128(rng, n, r)
	state0, msg0 := genMultGateMsg128(x0, y0, bvr0, r)
	state1, msg1 := genMultGateMsg128(x1, y1, bvr1, r)
	res0 := hadamardP0_128(state0, bvr0, msg1, r)
	res1 := hadamardP1_128(state1, bvr1, msg0, r)
	return res0, res1
}

func BenchmarkRing128HadamardProductLocal_n155(b *testing.B) {
	const n = 155
	rng := benchRNG()
	r := newRing128Ctx(40)

	x0 := make([]*big.Int, n)
	x1 := make([]*big.Int, n)
	y0 := make([]*big.Int, n)
	y1 := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		val := r.fromDouble(float64(int(cryptoRandUint64K2()%2000)-1000) / 100.0)
		x0[i], x1[i] = r.splitShare(rng, val)
		val = r.fromDouble(float64(int(cryptoRandUint64K2()%2000)-1000) / 100.0)
		y0[i], y1[i] = r.splitShare(rng, val)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = hadamardLocal128(rng, x0, y0, x1, y1, r)
	}
}
