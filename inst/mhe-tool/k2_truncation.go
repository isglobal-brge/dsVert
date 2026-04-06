// k2_truncation.go: Truncation strategies for K=2 MPC fixed-point arithmetic.
//
// Implements the SecureML/ABY3-style stochastic truncation that converts
// deterministic floor-division bias into zero-mean random noise.
//
// Reference:
//   - Catrina & de Hoogh, "Improved Primitives for Secure Multiparty Integer
//     Computation", SCN 2010 (TruncPR protocol)
//   - Mohassel & Zhang, "SecureML", IEEE S&P 2017 (local truncation)
//   - Harth-Kitzerow et al., "Truncation Untangled", PoPETS 2025 (SoK)

package main

// CorrelatedStochasticTruncate truncates BOTH parties' shares using
// a SHARED random carry bit (SecureML-style).
//
// The key insight: P0 and P1 must use the SAME carry decision.
// With independent random bits, the error is ±2 ULP (worse than deterministic).
// With shared random bit, the error is ±1 ULP but ZERO MEAN.
//
// In local simulation, we generate one random bit and use it for both.
// In production, both parties derive it from a shared PRG seed.
func CorrelatedStochasticTruncate(share0, share1, divisor, modulus uint64) (trunc0, trunc1 uint64) {
	// Deterministic truncation first
	trunc0 = share0 / divisor
	negS := (modulus - share1) % modulus
	trunc1 = (modulus - negS/divisor) % modulus

	// Compute the TRUE remainder of the PRODUCT (share0 + share1)
	// to decide the carry with the right probability.
	// product_remainder = (share0 + share1) % divisor
	// But we can't reconstruct share0 + share1!
	//
	// SecureML approach: use a RANDOM carry bit, shared between parties.
	// P(carry=1) = 0.5. This makes E[error] = 0 (unbiased).
	// The variance is 0.25 ULP^2 per truncation.
	carry := cryptoRandUint64K2() & 1 // 0 or 1, shared between P0 and P1

	if carry == 1 {
		trunc0 = (trunc0 + 1) % modulus
		trunc1 = (modulus + trunc1 - 1) % modulus
	}
	return
}

// StochasticHadamardProduct computes Hadamard product with CORRELATED
// stochastic truncation. Returns BOTH parties' shares (must be called together
// in local simulation; in production, uses shared PRG).
func StochasticHadamardProduct(
	state0 BatchedMultState, beaver0 BeaverTripleVec, msg1 MultGateMessage,
	state1 BatchedMultState, beaver1 BeaverTripleVec, msg0 MultGateMessage,
	fracBits int, r Ring63) (res0, res1 []uint64) {

	raw0 := GenerateBatchedMultiplicationOutputPartyZero(state0, beaver0, msg1, r)
	raw1 := GenerateBatchedMultiplicationOutputPartyOne(state1, beaver1, msg0, r)

	divisor := uint64(1) << fracBits
	res0 = make([]uint64, len(raw0))
	res1 = make([]uint64, len(raw1))
	for i := range raw0 {
		res0[i], res1[i] = CorrelatedStochasticTruncate(raw0[i], raw1[i], divisor, r.Modulus)
	}
	return
}

// Legacy wrappers for backward compat (delegate to correlated version is not possible
// without both parties, so keep deterministic for single-party calls)
func StochasticHadamardProductPartyZero(
	state BatchedMultState, beaver BeaverTripleVec, otherMsg MultGateMessage,
	fracBits int, r Ring63) []uint64 {
	return HadamardProductPartyZero(state, beaver, otherMsg, fracBits, r)
}

func StochasticHadamardProductPartyOne(
	state BatchedMultState, beaver BeaverTripleVec, otherMsg MultGateMessage,
	fracBits int, r Ring63) []uint64 {
	return HadamardProductPartyOne(state, beaver, otherMsg, fracBits, r)
}
