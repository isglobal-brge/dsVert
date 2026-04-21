// k2_beaver_google_ring127.go — Ring127 parallel of Beaver protocol helpers.
//
// Structurally identical to k2_beaver_google.go but operating on Uint128
// under Ring127 (2^127 modulus, implicit). This enables selective routing
// of Cox Path B + LMM cross-server Gram assembly through Ring127 without
// touching Ring63 paths used by GLM/NB/Desc/etc.
//
// Invariants (per user directive 2026-04-20):
//   - No big.Int in the hot loops (Beaver per-element products use
//     Ring127.TruncMul which currently uses big.Int internally for the
//     256-bit product — will hot-path-inline in a follow-up if needed).
//   - Uses k2_ring127.go Uint128 type + Ring127 arithmetic.
//   - Parallel name convention: foo → fooRing127.

package main

// BeaverTripleVec127 holds Uint128 Beaver triple shares for one party.
type BeaverTripleVec127 struct {
	A []Uint128
	B []Uint128
	C []Uint128
}

// SampleBeaverTripleVector127 generates correlated Ring127 Beaver triples.
// c_i = a_i × b_i (mod 2^127), split as additive shares per party.
func SampleBeaverTripleVector127(length int, r Ring127) (party0, party1 BeaverTripleVec127) {
	party0 = BeaverTripleVec127{
		A: make([]Uint128, length),
		B: make([]Uint128, length),
		C: make([]Uint128, length),
	}
	party1 = BeaverTripleVec127{
		A: make([]Uint128, length),
		B: make([]Uint128, length),
		C: make([]Uint128, length),
	}
	for i := 0; i < length; i++ {
		a := cryptoRandUint128()
		b := cryptoRandUint128()
		// c = a × b mod 2^127, UNTRUNCATED (FP semantics: output is at
		// 2*fracBits worth of fraction; caller applies TruncateShare to
		// return to fracBits). Matches Ring63 modMulBig63 behaviour.
		c := a.Mul(b).ModPow127()
		party0.A[i], party1.A[i] = r.SplitShare(a)
		party0.B[i], party1.B[i] = r.SplitShare(b)
		party0.C[i], party1.C[i] = r.SplitShare(c)
	}
	return
}

// BatchedMultState127 holds a party's state after Beaver round 1.
type BatchedMultState127 struct {
	ShareXMinusA []Uint128
	ShareYMinusB []Uint128
}

// MultGateMessage127 holds the (x-a, y-b) round-1 message between parties.
type MultGateMessage127 struct {
	XMinusAShares []Uint128
	YMinusBShares []Uint128
}

// GenerateBatchedMultiplicationGateMessage127: round 1.
// Ring127 parallel of GenerateBatchedMultiplicationGateMessage.
func GenerateBatchedMultiplicationGateMessage127(
	shareX, shareY []Uint128,
	beaver BeaverTripleVec127,
	r Ring127,
) (state BatchedMultState127, msg MultGateMessage127) {
	n := len(shareX)
	state.ShareXMinusA = make([]Uint128, n)
	state.ShareYMinusB = make([]Uint128, n)
	msg.XMinusAShares = make([]Uint128, n)
	msg.YMinusBShares = make([]Uint128, n)
	for i := 0; i < n; i++ {
		state.ShareXMinusA[i] = r.Sub(shareX[i], beaver.A[i])
		state.ShareYMinusB[i] = r.Sub(shareY[i], beaver.B[i])
	}
	copy(msg.XMinusAShares, state.ShareXMinusA)
	copy(msg.YMinusBShares, state.ShareYMinusB)
	return
}

// GenerateBatchedMultiplicationOutputPartyZero127 — Ring127 parallel.
// [XY]_0 = [C]_0 + [B]_0·(X-A) + [A]_0·(Y-B) + (X-A)·(Y-B)
func GenerateBatchedMultiplicationOutputPartyZero127(
	state BatchedMultState127,
	beaver BeaverTripleVec127,
	otherMsg MultGateMessage127,
	r Ring127,
) []Uint128 {
	n := len(state.ShareXMinusA)
	result := make([]Uint128, n)
	for i := 0; i < n; i++ {
		xMinusA := r.Add(state.ShareXMinusA[i], otherMsg.XMinusAShares[i])
		yMinusB := r.Add(state.ShareYMinusB[i], otherMsg.YMinusBShares[i])
		// UNtruncated products (Beaver at 2*fracBits output convention).
		bTimesXA := beaver.B[i].Mul(xMinusA).ModPow127()
		aTimesYB := beaver.A[i].Mul(yMinusB).ModPow127()
		xaTimesYB := xMinusA.Mul(yMinusB).ModPow127()
		result[i] = r.Add(r.Add(r.Add(beaver.C[i], bTimesXA), aTimesYB), xaTimesYB)
	}
	return result
}

// GenerateBatchedMultiplicationOutputPartyOne127 — Ring127 parallel.
// [XY]_1 = [C]_1 + [B]_1·(X-A) + [A]_1·(Y-B)
func GenerateBatchedMultiplicationOutputPartyOne127(
	state BatchedMultState127,
	beaver BeaverTripleVec127,
	otherMsg MultGateMessage127,
	r Ring127,
) []Uint128 {
	n := len(state.ShareXMinusA)
	result := make([]Uint128, n)
	for i := 0; i < n; i++ {
		xMinusA := r.Add(state.ShareXMinusA[i], otherMsg.XMinusAShares[i])
		yMinusB := r.Add(state.ShareYMinusB[i], otherMsg.YMinusBShares[i])
		// UNtruncated products (Beaver at 2*fracBits output convention).
		bTimesXA := beaver.B[i].Mul(xMinusA).ModPow127()
		aTimesYB := beaver.A[i].Mul(yMinusB).ModPow127()
		result[i] = r.Add(r.Add(beaver.C[i], bTimesXA), aTimesYB)
	}
	return result
}
