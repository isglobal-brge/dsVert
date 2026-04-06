// kelkar_exp.go: Kelkar secure exponentiation — 1:1 port of Google C++.
//
// Computes additive shares of exp(x) from additive shares of x.
// Protocol: 1 communication round (each party sends one message).
//
// Reference: secure_exponentiation.cc in fss_machine_learning
// (Kelkar et al., USENIX Security 2022)
//
// Algorithm:
//   1. Convert x to base-2: x_b2 = x * log2(e)
//   2. Add offset to ensure positive: x_b2 += bound
//   3. Split: integer k, fractional f
//   4. 2^k via ModExp in Z_q (Fermat), 2^f via pow() in doubles
//   5. Combine: mult_share = 2^k * 2^f * FracMul mod q
//   6. Mult-to-Add: exchange one message → additive shares
//   7. Divide out FracMul * 2^bound, convert Z_q → Ring63

package main

import (
	"math"
	"math/big"
)

const kelkarLog2E = 1.4426950408889634073599

// KelkarExpConfig holds parameters for the secure exponentiation.
type KelkarExpConfig struct {
	RP            RingParams
	ExponentBound int    // max |x| supported
	PrimeQ        uint64 // Mersenne prime for intermediate computation
}

// DefaultKelkarExpConfig returns params matching Google C++.
func DefaultKelkarExpConfig() KelkarExpConfig {
	return KelkarExpConfig{
		RP:            DefaultRingParams(),
		ExponentBound: 10,
		PrimeQ:        2305843009213693951, // 2^61 - 1
	}
}

// KelkarMTA holds one mult-to-add preprocessing tuple.
// alpha0*alpha1 + beta0*beta1 = 1 mod q.
type KelkarMTA struct {
	Alpha0, Beta0, Alpha1, Beta1 uint64
}

// KelkarGenMTA generates a mult-to-add tuple.
func KelkarGenMTA(q uint64) KelkarMTA {
	qBig := new(big.Int).SetUint64(q)
	a0 := randMod(q)
	a1 := randMod(q)
	b0 := randMod(q)

	aa := mulMod(a0, a1, q)
	target := (q + 1 - aa) % q
	b0Inv := new(big.Int).ModInverse(new(big.Int).SetUint64(b0), qBig)
	b1 := new(big.Int).Mul(new(big.Int).SetUint64(target), b0Inv)
	b1.Mod(b1, qBig)

	return KelkarMTA{Alpha0: a0, Beta0: b0, Alpha1: a1, Beta1: b1.Uint64()}
}

// --- Per-party round functions ---

// KelkarExpR1P0 computes P0's message: beta0 * mult_share0 mod q.
// Returns (message_to_P1, own_mult_share).
func KelkarExpR1P0(cfg KelkarExpConfig, share0 []uint64, mta KelkarMTA) (msg []uint64, ownMult []uint64) {
	rp := cfg.RP
	q := cfg.PrimeQ
	n := len(share0)
	b2Bound := int(math.Ceil(kelkarLog2E*float64(cfg.ExponentBound))) + 1

	log2eFP := rp.FromDouble(kelkarLog2E)
	adderFP := uint64(b2Bound) * rp.FracMultiplier

	msg = make([]uint64, n)
	ownMult = make([]uint64, n)

	for i := 0; i < n; i++ {
		// Base-2 exponent + offset
		base2 := truncMul128(share0[i], log2eFP, rp)
		posBase2 := (base2 + adderFP) % rp.Modulus

		intPart := posBase2 / rp.FracMultiplier
		fracPart := float64(posBase2%rp.FracMultiplier) / float64(rp.FracMultiplier)

		// P0: convert integer to Z_{q-1}
		intInQ := (intPart + (q - 1) - rp.IntModulus) % (q - 1)

		// 2^int mod q, 2^frac as real
		intExp := expMod(2, intInQ, q)
		fracExp := uint64(math.Pow(2.0, fracPart)*float64(rp.FracMultiplier) + 0.5)

		// mult = intExp * fracExp mod q
		mult := mulMod(intExp, fracExp, q)
		ownMult[i] = mult
		msg[i] = mulMod(mta.Beta0, mult, q)
	}
	return
}

// KelkarExpR1P1 computes P1's message: alpha1 * mult_share1 mod q.
func KelkarExpR1P1(cfg KelkarExpConfig, share1 []uint64, mta KelkarMTA) (msg []uint64, ownMult []uint64) {
	rp := cfg.RP
	q := cfg.PrimeQ
	n := len(share1)

	log2eFP := rp.FromDouble(kelkarLog2E)

	// P1 correction: log2(e) * modulus / fracMul mod modulus
	corrBig := new(big.Int).Mul(
		new(big.Int).SetUint64(log2eFP),
		new(big.Int).SetUint64(rp.Modulus),
	)
	corrBig.Div(corrBig, new(big.Int).SetUint64(rp.FracMultiplier))
	corrBig.Mod(corrBig, new(big.Int).SetUint64(rp.Modulus))
	corr := corrBig.Uint64()

	msg = make([]uint64, n)
	ownMult = make([]uint64, n)

	for i := 0; i < n; i++ {
		firstTerm := truncMul128(share1[i], log2eFP, rp)
		base2 := rp.ModSub(firstTerm, corr)

		intPart := base2 / rp.FracMultiplier
		fracPart := float64(base2%rp.FracMultiplier) / float64(rp.FracMultiplier)

		// P1: integer already in Z_{q-1}
		intInQ := intPart % (q - 1)

		intExp := expMod(2, intInQ, q)
		fracExp := uint64(math.Pow(2.0, fracPart)*float64(rp.FracMultiplier) + 0.5)

		mult := mulMod(intExp, fracExp, q)
		ownMult[i] = mult
		msg[i] = mulMod(mta.Alpha1, mult, q)
	}
	return
}

// KelkarExpOutputP0 computes P0's additive share from P1's message.
func KelkarExpOutputP0(cfg KelkarExpConfig, ownMult, peerMsg []uint64, mta KelkarMTA) []uint64 {
	rp := cfg.RP
	q := cfg.PrimeQ
	n := len(ownMult)
	b2Bound := int(math.Ceil(kelkarLog2E*float64(cfg.ExponentBound))) + 1
	twoPowB2 := expMod(2, uint64(b2Bound), q)

	result := make([]uint64, n)
	for i := 0; i < n; i++ {
		// (alpha0 * own_mult) * (alpha1 * peer_mult)
		r0 := mulMod(mulMod(ownMult[i], mta.Alpha0, q), peerMsg[i], q)

		// Divide out scale: q - (q - r0) / (FracMul * 2^b2bound)
		negR0 := (q - r0) % q
		divided := negR0 / (rp.FracMultiplier * twoPowB2)
		shareQ := (q - divided) % q

		// Z_q → Ring63
		result[i] = (shareQ + rp.Modulus - q) % rp.Modulus
	}
	return result
}

// KelkarExpOutputP1 computes P1's additive share from P0's message.
func KelkarExpOutputP1(cfg KelkarExpConfig, ownMult, peerMsg []uint64, mta KelkarMTA) []uint64 {
	rp := cfg.RP
	q := cfg.PrimeQ
	n := len(ownMult)
	b2Bound := int(math.Ceil(kelkarLog2E*float64(cfg.ExponentBound))) + 1
	twoPowB2 := expMod(2, uint64(b2Bound), q)

	result := make([]uint64, n)
	for i := 0; i < n; i++ {
		r1 := mulMod(mulMod(ownMult[i], mta.Beta1, q), peerMsg[i], q)
		result[i] = r1 / (rp.FracMultiplier * twoPowB2)
	}
	return result
}

// KelkarExpLocal simulates the full protocol locally (for testing).
func KelkarExpLocal(rp RingParams, x0, x1 []uint64) (exp0, exp1 []uint64) {
	cfg := DefaultKelkarExpConfig()
	cfg.RP = rp
	mta := KelkarGenMTA(cfg.PrimeQ)

	p0Msg, p0Mult := KelkarExpR1P0(cfg, x0, mta)
	p1Msg, p1Mult := KelkarExpR1P1(cfg, x1, mta)

	exp0 = KelkarExpOutputP0(cfg, p0Mult, p1Msg, mta)
	exp1 = KelkarExpOutputP1(cfg, p1Mult, p0Msg, mta)
	return
}

// --- Helpers (big.Int wrappers) ---

func mulMod(a, b, m uint64) uint64 {
	return new(big.Int).Mod(
		new(big.Int).Mul(new(big.Int).SetUint64(a), new(big.Int).SetUint64(b)),
		new(big.Int).SetUint64(m),
	).Uint64()
}

func expMod(base, exp, mod uint64) uint64 {
	return new(big.Int).Exp(
		new(big.Int).SetUint64(base),
		new(big.Int).SetUint64(exp),
		new(big.Int).SetUint64(mod),
	).Uint64()
}

func randMod(m uint64) uint64 {
	for {
		v := cryptoRandUint64() % m
		if v != 0 {
			return v
		}
	}
}

// truncMul128 computes (a * b) >> fracBits mod modulus using 128-bit arithmetic.
func truncMul128(a, b uint64, rp RingParams) uint64 {
	aBig := new(big.Int).SetUint64(a)
	bBig := new(big.Int).SetUint64(b)
	prod := new(big.Int).Mul(aBig, bBig)
	prod.Rsh(prod, uint(rp.NumFractionalBits))
	prod.Mod(prod, new(big.Int).SetUint64(rp.Modulus))
	return prod.Uint64()
}
