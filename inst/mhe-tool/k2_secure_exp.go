// k2_secure_exp.go: Secure exponentiation protocol (Kelkar et al.)
//
// 1:1 port of Google fss_machine_learning: poisson_regression/secure_exponentiation.cc
//
// Uses uint64 with EXPLICIT modulus (2^63) to match the C++ exactly.
// The C++ uses num_ring_bits=63, so modulus = 2^63 = 9223372036854775808.
// All arithmetic is done with explicit % modulus, not int64 wrapping.

package main

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"math/big"
)

const (
	log2e_const     = 1.4426950408889634073599
	kDefaultFracBits = 20
	kDefaultRingBits = 63
)

// Ring63 holds parameters for the 2^63 ring used by the C++ code.
type Ring63 struct {
	Modulus      uint64 // 2^63
	FracMul      uint64 // 2^fracBits
	IntRingMod   uint64 // 2^(63-fracBits)
	FracBits     int
	SignThreshold uint64 // modulus / 2
}

func NewRing63(fracBits int) Ring63 {
	mod := uint64(1) << 63
	return Ring63{
		Modulus:      mod,
		FracMul:      uint64(1) << fracBits,
		IntRingMod:   uint64(1) << (63 - fracBits),
		FracBits:     fracBits,
		SignThreshold: mod >> 1,
	}
}

// Ring63 arithmetic — ALL explicit % modulus, matching C++ exactly.
func (r Ring63) Add(a, b uint64) uint64  { return (a + b) % r.Modulus }
func (r Ring63) Sub(a, b uint64) uint64  { return (r.Modulus + a - b) % r.Modulus }
func (r Ring63) Neg(a uint64) uint64     { return (r.Modulus - a) % r.Modulus }
func (r Ring63) IsNeg(a uint64) bool     { return a >= r.SignThreshold }

func (r Ring63) FromDouble(x float64) uint64 {
	if x >= 0 {
		return uint64(x*float64(r.FracMul)+0.5) % r.Modulus
	}
	abs := uint64(-x*float64(r.FracMul) + 0.5)
	return r.Neg(abs % r.Modulus)
}

func (r Ring63) ToDouble(a uint64) float64 {
	a = a % r.Modulus
	if r.IsNeg(a) {
		return -float64(r.Neg(a)) / float64(r.FracMul)
	}
	return float64(a) / float64(r.FracMul)
}

// TruncMul: (a * b) >> fracBits, mod modulus.
// Matches C++ FixedPointElement::TruncMul.
func (r Ring63) TruncMul(a, b uint64) uint64 {
	// 128-bit multiply
	aBig := new(big.Int).SetUint64(a)
	bBig := new(big.Int).SetUint64(b)
	product := new(big.Int).Mul(aBig, bBig)
	// Right shift by fracBits
	product.Rsh(product, uint(r.FracBits))
	// Mod modulus
	product.Mod(product, new(big.Int).SetUint64(r.Modulus))
	return product.Uint64()
}

// TruncMulSigned: sign-aware truncated multiply (C++ TruncMulFP).
func (r Ring63) TruncMulSigned(a, b uint64) uint64 {
	aNeg := r.IsNeg(a)
	bNeg := r.IsNeg(b)
	aa, bb := a, b
	if aNeg { aa = r.Neg(a) }
	if bNeg { bb = r.Neg(b) }
	result := r.TruncMul(aa, bb)
	if aNeg != bNeg { result = r.Neg(result) }
	return result
}

func (r Ring63) SplitShare(value uint64) (s0, s1 uint64) {
	s0 = cryptoRandUint64K2() % r.Modulus
	s1 = r.Sub(value, s0)
	return
}

// --- Multiplicative-to-additive conversion ---

type MultToAddTuple struct {
	Alpha0, Beta0 uint64
	Alpha1, Beta1 uint64
}

func GenerateMultToAddTuple(q uint64) MultToAddTuple {
	qBig := new(big.Int).SetUint64(q)
	alpha0 := randModQ63(q)
	alpha1 := randModQ63(q)
	beta0 := randModQ63(q)

	aa := modMulBig63(alpha0, alpha1, q)
	target := (q + 1 - aa) % q
	beta0Inv := new(big.Int).ModInverse(new(big.Int).SetUint64(beta0), qBig)
	beta1 := new(big.Int).Mul(new(big.Int).SetUint64(target), beta0Inv)
	beta1.Mod(beta1, qBig)

	return MultToAddTuple{
		Alpha0: alpha0, Beta0: beta0,
		Alpha1: alpha1, Beta1: beta1.Uint64(),
	}
}

func cryptoRandUint64K2() uint64 {
	var buf [8]byte
	rand.Read(buf[:])
	return binary.LittleEndian.Uint64(buf[:])
}

func randModQ63(q uint64) uint64 {
	for {
		v := cryptoRandUint64K2() % q
		if v != 0 { return v }
	}
}

func modMulBig63(a, b, m uint64) uint64 {
	return new(big.Int).Mod(
		new(big.Int).Mul(new(big.Int).SetUint64(a), new(big.Int).SetUint64(b)),
		new(big.Int).SetUint64(m),
	).Uint64()
}

func modExpBig63(base, exp, mod uint64) uint64 {
	return new(big.Int).Exp(
		new(big.Int).SetUint64(base),
		new(big.Int).SetUint64(exp),
		new(big.Int).SetUint64(mod),
	).Uint64()
}

// --- Secure Exponentiation Protocol ---

type ExpConfig struct {
	Ring          Ring63
	ExponentBound int
	PrimeQ        uint64
}

func DefaultExpConfig() ExpConfig {
	return ExpConfig{
		Ring:          NewRing63(kDefaultFracBits),
		ExponentBound: 10,
		PrimeQ:        2305843009213693951, // 2^61 - 1 (Mersenne prime)
	}
}

// ExpParty0Round1 computes P0's message for secure exponentiation.
// Matches C++ SecureExponentiationPartyZero::GenerateMultToAddMessage.
func ExpParty0Round1(cfg ExpConfig, share0 []uint64, mta MultToAddTuple) (betaMultShares []uint64, ownMultShares []uint64) {
	r := cfg.Ring
	q := cfg.PrimeQ
	n := len(share0)
	base2Bound := int(math.Ceil(log2e_const*float64(cfg.ExponentBound))) + 1

	log2eFP := r.FromDouble(log2e_const)
	adderFP := uint64(base2Bound) * r.FracMul // base2Bound in integer = base2Bound * 2^fracBits

	betaMultShares = make([]uint64, n)
	ownMultShares = make([]uint64, n)

	for i := 0; i < n; i++ {
		// Step 1: Convert to base-2 exponent (truncated FP multiply)
		base2 := r.TruncMul(share0[i], log2eFP)

		// Step 2: Add offset to ensure positive
		posBase2 := r.Add(base2, adderFP)

		// Step 3: Split into integer and fractional
		intPart := posBase2 / r.FracMul
		fracPart := float64(posBase2%r.FracMul) / float64(r.FracMul) // in [0, 1)

		// Step 4: Convert integer to Z_{q-1}
		// P0: int_in_q_minus_1 = intPart + (q-1) - intRingMod  mod (q-1)
		intInQMinus1 := (intPart + (q - 1) - r.IntRingMod) % (q - 1)

		// Step 5: 2^{integer} mod q
		intExp := modExpBig63(2, intInQMinus1, q)

		// Step 6: 2^{fractional} as real, then scale to FP
		fracExp := math.Pow(2.0, fracPart)
		fracExpFP := uint64(fracExp*float64(r.FracMul) + 0.5)

		// Step 7: mult_share = intExp * fracExpFP mod q
		multShare := modMulBig63(intExp, fracExpFP, q)
		ownMultShares[i] = multShare

		// Step 8: Send beta0 * mult_share mod q
		betaMultShares[i] = modMulBig63(mta.Beta0, multShare, q)
	}
	return
}

// ExpParty1Round1 computes P1's message.
// Matches C++ SecureExponentiationPartyOne::GenerateMultToAddMessage.
func ExpParty1Round1(cfg ExpConfig, share1 []uint64, mta MultToAddTuple) (alphaMultShares []uint64, ownMultShares []uint64) {
	r := cfg.Ring
	q := cfg.PrimeQ
	n := len(share1)

	log2eFP := r.FromDouble(log2e_const)

	// P1's correction: log2(e) * modulus / fracMul  (mod modulus)
	// This is the C++ second_term computation
	correctionBig := new(big.Int).Mul(
		new(big.Int).SetUint64(log2eFP),
		new(big.Int).SetUint64(r.Modulus),
	)
	correctionBig.Div(correctionBig, new(big.Int).SetUint64(r.FracMul))
	correctionBig.Mod(correctionBig, new(big.Int).SetUint64(r.Modulus))
	correction := correctionBig.Uint64()

	alphaMultShares = make([]uint64, n)
	ownMultShares = make([]uint64, n)

	for i := 0; i < n; i++ {
		// Step 1: base2 = share1 * log2(e) - correction
		// Matches C++ exactly: both TruncMul and Sub are unsigned ring operations
		firstTerm := r.TruncMul(share1[i], log2eFP)
		base2 := r.Sub(firstTerm, correction)

		// Step 3: Split into integer and fractional (UNSIGNED, same as C++)
		// C++ SplitIntoIntegerAndFractionalParts: value / fracMul, value % fracMul / fracMul
		intPart := base2 / r.FracMul
		fracPart := float64(base2%r.FracMul) / float64(r.FracMul)

		// Step 4: P1's integer is already a share in Z_{q-1}
		// C++ comment: "For P_1, split_pair.first is already a share in Z_{prime_q - 1}"
		intInQMinus1 := intPart % (q - 1)

		// Step 5: 2^{integer} mod q
		intExp := modExpBig63(2, intInQMinus1, q)

		// Step 6: 2^{fractional}
		fracExp := math.Pow(2.0, fracPart)
		fracExpFP := uint64(fracExp*float64(r.FracMul) + 0.5)

		// Step 7: mult_share
		multShare := modMulBig63(intExp, fracExpFP, q)
		ownMultShares[i] = multShare

		// Step 8: Send alpha1 * mult_share mod q
		alphaMultShares[i] = modMulBig63(mta.Alpha1, multShare, q)
	}
	return
}

// ExpParty0Output computes P0's additive share of e^x.
// Matches C++ SecureExponentiationPartyZero::OutputResult.
func ExpParty0Output(cfg ExpConfig, ownMultShares, peerAlphaMultShares []uint64, mta MultToAddTuple) []uint64 {
	r := cfg.Ring
	q := cfg.PrimeQ
	n := len(ownMultShares)
	base2Bound := int(math.Ceil(log2e_const*float64(cfg.ExponentBound))) + 1
	twoPowBase2Bound := modExpBig63(2, uint64(base2Bound), q)
	scaleDivisor := modMulBig63(r.FracMul, twoPowBase2Bound, q) // Not for ring division! For integer division.

	result := make([]uint64, n)
	for i := 0; i < n; i++ {
		// P0: result = (alpha0 * own_mult) * (alpha1 * peer_mult) mod q
		// = alpha0*alpha1 * mult0*mult1 mod q
		r0 := modMulBig63(modMulBig63(ownMultShares[i], mta.Alpha0, q), peerAlphaMultShares[i], q)

		// additive_share_q = q - (q - r0) / scaleDivisor
		negR0 := (q - r0) % q
		// Integer division in Z_q
		divided := negR0 / (r.FracMul * twoPowBase2Bound)
		additiveShareQ := (q - divided) % q

		// Convert from Z_q to Z_{modulus}: final = share + modulus - q  mod modulus
		result[i] = (additiveShareQ + r.Modulus - q) % r.Modulus
	}
	_ = scaleDivisor
	return result
}

// ExpParty1Output computes P1's additive share of e^x.
func ExpParty1Output(cfg ExpConfig, ownMultShares, peerBetaMultShares []uint64, mta MultToAddTuple) []uint64 {
	r := cfg.Ring
	q := cfg.PrimeQ
	n := len(ownMultShares)
	base2Bound := int(math.Ceil(log2e_const*float64(cfg.ExponentBound))) + 1
	twoPowBase2Bound := modExpBig63(2, uint64(base2Bound), q)

	result := make([]uint64, n)
	for i := 0; i < n; i++ {
		// P1: result = (beta1 * own_mult) * (beta0 * peer_mult) mod q
		r1 := modMulBig63(modMulBig63(ownMultShares[i], mta.Beta1, q), peerBetaMultShares[i], q)

		// final = r1 / (fracMul * twoPowBase2Bound)
		result[i] = r1 / (r.FracMul * twoPowBase2Bound)
	}
	return result
}

// SecureExpKelkar simulates the full protocol locally for testing.
func SecureExpKelkar(cfg ExpConfig, x0, x1 []uint64) (exp0, exp1 []uint64) {
	mta := GenerateMultToAddTuple(cfg.PrimeQ)

	// Verify tuple
	check := (modMulBig63(mta.Alpha0, mta.Alpha1, cfg.PrimeQ) +
		modMulBig63(mta.Beta0, mta.Beta1, cfg.PrimeQ)) % cfg.PrimeQ
	if check != 1 {
		panic("MultToAdd tuple verification failed")
	}

	beta0Mult0, mult0 := ExpParty0Round1(cfg, x0, mta)
	alpha1Mult1, mult1 := ExpParty1Round1(cfg, x1, mta)

	exp0 = ExpParty0Output(cfg, mult0, alpha1Mult1, mta)
	exp1 = ExpParty1Output(cfg, mult1, beta0Mult0, mta)
	return
}
