// secure_exp_kelkar.go: Secure exponentiation protocol (Kelkar et al.)
//
// Port of Google fss_machine_learning: poisson_regression/secure_exponentiation.cc
//
// Computes e^x on secret shares via base-2 decomposition:
//   1. Convert to base-2: x_base2 = x * log2(e) (truncated FP multiply)
//   2. P0 adds constant to ensure non-negative
//   3. Split into integer + fractional parts
//   4. Integer part: 2^k via modular exponentiation in Z_q (multiplicative share)
//   5. Fractional part: 2^f via plaintext pow() (each party on its own share)
//   6. Combine int * frac = multiplicative share of 2^x
//   7. Multiplicative-to-additive conversion via (alpha, beta) tuple
//   8. Convert from Z_q to Z_{2^l} and divide by scaling factors
//
// Security: neither party sees x, x_base2, the integer part, or the final exp.
// Only the mult-to-add message (a single scalar per element) is exchanged.

package main

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"math/big"
)

const log2e = 1.4426950408889634073599 // log_2(e)

// cryptoRandUint64K2 returns a cryptographically secure random uint64.
func cryptoRandUint64K2() uint64 {
	var buf [8]byte
	rand.Read(buf[:])
	return binary.LittleEndian.Uint64(buf[:])
}

// ExpConfig holds parameters for the secure exponentiation protocol.
type ExpConfig struct {
	FracBits       int    // Number of fractional bits (e.g., 20)
	RingBits       int    // Ring size in bits (e.g., 63)
	ExponentBound  int    // Max absolute exponent (e.g., 10)
	PrimeQ         uint64 // Prime for multiplicative arithmetic
}

// DefaultExpConfig returns sensible defaults for the exponentiation protocol.
func DefaultExpConfig() ExpConfig {
	return ExpConfig{
		FracBits:      20,
		RingBits:      63,
		ExponentBound: 10,
		PrimeQ:        2305843009213693951, // 2^61 - 1 (Mersenne prime)
	}
}

// MultToAddTuple holds the correlated randomness for mult-to-add conversion.
// Satisfies: alpha0 * alpha1 + beta0 * beta1 = 1 mod q
type MultToAddTuple struct {
	Alpha0, Beta0 uint64 // Party 0's values
	Alpha1, Beta1 uint64 // Party 1's values
}

// GenerateMultToAddTuple generates a correlated tuple for the given prime q.
func GenerateMultToAddTuple(q uint64) MultToAddTuple {
	qBig := new(big.Int).SetUint64(q)

	// Sample random non-zero alpha0, alpha1, beta0
	alpha0 := randModQ(q)
	alpha1 := randModQ(q)
	beta0 := randModQ(q)

	// Compute beta1 = (1 - alpha0*alpha1) * beta0^{-1} mod q
	aa := modMulBig(alpha0, alpha1, q)
	target := (q + 1 - aa) % q // (1 - aa) mod q
	beta0Inv := new(big.Int).ModInverse(new(big.Int).SetUint64(beta0), qBig)
	beta1 := new(big.Int).Mul(new(big.Int).SetUint64(target), beta0Inv)
	beta1.Mod(beta1, qBig)

	return MultToAddTuple{
		Alpha0: alpha0,
		Beta0:  beta0,
		Alpha1: alpha1,
		Beta1:  beta1.Uint64(),
	}
}

// randModQ returns a random non-zero value in [1, q-1].
func randModQ(q uint64) uint64 {
	for {
		v := cryptoRandUint64K2() % q
		if v != 0 {
			return v
		}
	}
}

// modMulBig computes (a * b) mod m using big.Int.
func modMulBig(a, b, m uint64) uint64 {
	result := new(big.Int).Mul(
		new(big.Int).SetUint64(a),
		new(big.Int).SetUint64(b),
	)
	result.Mod(result, new(big.Int).SetUint64(m))
	return result.Uint64()
}

// modExpBigLocal computes base^exp mod modulus using big.Int.
func modExpBigLocal(base, exp, modulus uint64) uint64 {
	return new(big.Int).Exp(
		new(big.Int).SetUint64(base),
		new(big.Int).SetUint64(exp),
		new(big.Int).SetUint64(modulus),
	).Uint64()
}

// --- Protocol messages ---

// ExpRound1MessageP0 is what party 0 sends in round 1.
type ExpRound1MessageP0 struct {
	BetaMultShare []uint64 // beta0 * mult_share_0 mod q, per element
}

// ExpRound1MessageP1 is what party 1 sends in round 1.
type ExpRound1MessageP1 struct {
	AlphaMultShare []uint64 // alpha1 * mult_share_1 mod q, per element
}

// --- Party 0 protocol ---

// ExpParty0Round1 computes party 0's round-1 message for secure exponentiation.
// share0 is P0's additive share of x (in FixedPoint).
func ExpParty0Round1(cfg ExpConfig, share0 []FixedPoint, mta MultToAddTuple) (
	msg ExpRound1MessageP0, multShares []uint64) {

	n := len(share0)
	fracMul := int64(1) << cfg.FracBits
	q := cfg.PrimeQ
	intRingMod := int64(1) << (cfg.RingBits - cfg.FracBits)

	// exp_bound_adder = ceil(log2(e) * exponent_bound) + 1
	base2Bound := int(math.Ceil(log2e*float64(cfg.ExponentBound))) + 1

	msg.BetaMultShare = make([]uint64, n)
	multShares = make([]uint64, n)

	for i := 0; i < n; i++ {
		// Step 1: Convert to base-2 exponent
		// base2_fpe = share0 * log2(e) (truncated FP multiply)
		log2eFP := FromFloat64(log2e, cfg.FracBits)
		base2FPE := FPMulLocal(FixedPoint(share0[i]), log2eFP, cfg.FracBits)

		// Step 2: P0 adds exp_bound_adder to ensure positive
		// The adder is base2Bound in integer part = base2Bound * fracMul in FP
		adder := FixedPoint(int64(base2Bound) * fracMul)
		posBase2 := base2FPE + adder

		// Step 3: Split into integer and fractional
		value := int64(posBase2)
		if value < 0 {
			value += int64(1) << cfg.RingBits // ensure positive
		}
		intPart := value / fracMul
		fracPart := float64(value%fracMul) / float64(fracMul)

		// Step 4: Convert integer to Z_{q-1}
		intInQMinus1 := uint64((intPart + int64(q-1) - intRingMod) % int64(q-1))
		if intInQMinus1 == 0 {
			intInQMinus1 = uint64(q - 1) // 0 maps to q-1 (since 2^0 = 1 = 2^{q-1} mod q by FLT)
		}

		// Step 5: 2^{integer} mod q (via Fermat's little theorem)
		intExp := modExpBigLocal(2, intInQMinus1, q)

		// Step 6: 2^{fractional} (plaintext, since each party sees only its own share's fraction)
		fracExp := math.Pow(2, fracPart)
		fracExpFP := uint64(fracExp * float64(fracMul))

		// Step 7: Combine: mult_share = intExp * fracExpFP mod q
		multShare := modMulBig(intExp, fracExpFP, q)
		multShares[i] = multShare

		// Step 8: Send beta0 * mult_share mod q
		msg.BetaMultShare[i] = modMulBig(mta.Beta0, multShare, q)
	}
	return
}

// ExpParty1Round1 computes party 1's round-1 message for secure exponentiation.
func ExpParty1Round1(cfg ExpConfig, share1 []FixedPoint, mta MultToAddTuple) (
	msg ExpRound1MessageP1, multShares []uint64) {

	n := len(share1)
	fracMul := int64(1) << cfg.FracBits
	q := cfg.PrimeQ
	primaryRingMod := int64(1) << cfg.RingBits

	msg.AlphaMultShare = make([]uint64, n)
	multShares = make([]uint64, n)

	// P1's correction: log2(e) * primaryRingModulus / fracMul
	// This accounts for the ring wrap-around in the shared value
	log2eFP := FromFloat64(log2e, cfg.FracBits)
	correctionTerm := FPMulLocal(FixedPoint(primaryRingMod), log2eFP, cfg.FracBits)

	for i := 0; i < n; i++ {
		// Step 1: base2 = share1 * log2(e) - correction
		base2FPE := FPMulLocal(share1[i], log2eFP, cfg.FracBits)
		base2FPE -= correctionTerm

		// Step 3: Split into integer and fractional
		value := int64(base2FPE)
		intPart := value / fracMul
		fracPart := float64(value%fracMul) / float64(fracMul)
		if fracPart < 0 {
			fracPart += 1.0
			intPart--
		}

		// Step 4: Integer is already in Z_{q-1} range for P1
		// (P1's integer part is naturally in the right range after correction)
		intInQMinus1 := uint64(intPart % int64(q-1))
		if intPart < 0 {
			intInQMinus1 = uint64(int64(q-1) + (intPart % int64(q-1)))
		}

		// Step 5: 2^{integer} mod q
		intExp := modExpBigLocal(2, intInQMinus1, q)

		// Step 6: 2^{fractional}
		fracExp := math.Pow(2, fracPart)
		fracExpFP := uint64(fracExp * float64(fracMul))

		// Step 7: mult_share = intExp * fracExpFP mod q
		multShare := modMulBig(intExp, fracExpFP, q)
		multShares[i] = multShare

		// Step 8: Send alpha1 * mult_share mod q
		msg.AlphaMultShare[i] = modMulBig(mta.Alpha1, multShare, q)
	}
	return
}

// ExpParty0Output computes party 0's final additive share of e^x.
func ExpParty0Output(cfg ExpConfig, ownMultShares []uint64, peerMsg ExpRound1MessageP1, mta MultToAddTuple) []FixedPoint {
	n := len(ownMultShares)
	q := cfg.PrimeQ
	fracMul := uint64(1) << cfg.FracBits
	base2Bound := int(math.Ceil(log2e*float64(cfg.ExponentBound))) + 1
	twoPowerBase2Bound := modExpBigLocal(2, uint64(base2Bound), q) // Not needed for division? Actually it's frac_mult * 2^base2Bound
	scaleDivisor := fracMul * modExpBigLocal(2, uint64(base2Bound), q)
	_ = twoPowerBase2Bound

	primaryRingMod := uint64(1) << cfg.RingBits

	result := make([]FixedPoint, n)
	for i := 0; i < n; i++ {
		// result = mult_share_0 * alpha_0 * (alpha_1 * mult_share_1) mod q
		// = alpha_0 * alpha_1 * mult_share_0 * mult_share_1 mod q
		r := modMulBig(modMulBig(ownMultShares[i], mta.Alpha0, q), peerMsg.AlphaMultShare[i], q)

		// Convert from Z_q to Z_{primaryRingMod}
		// additive_share_q = q - (q - r) / scaleDivisor
		negR := (q - r) % q
		divided := negR / scaleDivisor
		additiveShareQ := (q - divided) % q

		// final = additiveShareQ + primaryRingMod - q mod primaryRingMod
		final := (additiveShareQ + primaryRingMod - q) % primaryRingMod
		result[i] = FixedPoint(int64(final))
	}
	return result
}

// ExpParty1Output computes party 1's final additive share of e^x.
func ExpParty1Output(cfg ExpConfig, ownMultShares []uint64, peerMsg ExpRound1MessageP0, mta MultToAddTuple) []FixedPoint {
	n := len(ownMultShares)
	q := cfg.PrimeQ
	fracMul := uint64(1) << cfg.FracBits
	base2Bound := int(math.Ceil(log2e*float64(cfg.ExponentBound))) + 1
	scaleDivisor := fracMul * modExpBigLocal(2, uint64(base2Bound), q)

	result := make([]FixedPoint, n)
	for i := 0; i < n; i++ {
		// result = mult_share_1 * beta_1 * (beta_0 * mult_share_0) mod q
		r := modMulBig(modMulBig(ownMultShares[i], mta.Beta1, q), peerMsg.BetaMultShare[i], q)

		// final = r / scaleDivisor
		final := r / scaleDivisor
		result[i] = FixedPoint(int64(final))
	}
	return result
}

// SecureExpKelkar computes e^x on secret shares using the full Kelkar protocol.
// This simulates both parties locally for testing.
func SecureExpKelkar(cfg ExpConfig, x0, x1 []FixedPoint) (exp0, exp1 []FixedPoint) {
	n := len(x0)

	// Generate MultToAdd tuple
	mta := GenerateMultToAddTuple(cfg.PrimeQ)

	// Verify tuple: alpha0*alpha1 + beta0*beta1 = 1 mod q
	check := (modMulBig(mta.Alpha0, mta.Alpha1, cfg.PrimeQ) +
		modMulBig(mta.Beta0, mta.Beta1, cfg.PrimeQ)) % cfg.PrimeQ
	if check != 1 {
		panic("MultToAdd tuple verification failed")
	}

	// Round 1
	msg0, mult0 := ExpParty0Round1(cfg, x0, mta)
	msg1, mult1 := ExpParty1Round1(cfg, x1, mta)

	// Round 2 (output)
	exp0 = ExpParty0Output(cfg, mult0, msg1, mta)
	exp1 = ExpParty1Output(cfg, mult1, msg0, mta)

	_ = n
	return
}
