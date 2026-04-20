// k2_recip127_handler.go — dispatch handler `k2-recip127-get-coeffs`.
//
// Exposes the public Ring127 Chebyshev-reciprocal coefficients plus the
// affine mapping constants needed to transform x into the Chebyshev
// domain t ∈ [-1, 1]. All values are public (deterministic constants
// computed at init from the domain [Ring127RecipChebXMin,
// Ring127RecipChebXMax]), so distributing them leaks nothing.
//
// R client orchestration (dsVertClient:::.recip127_round):
//   1. Fetch (once per session) via .callMpcTool("k2-recip127-get-coeffs", ...).
//   2. Apply LocalScale + Affine to map x → t.
//   3. Run 30-step Clenshaw Horner via Beaver vecmul + AffineCombine.
//   4. Run 6 NR iterations via Beaver vecmul + AffineCombine(const=2).
//
// Step 5c(I-c-6b): minimal Go deliverable paralleling k2-exp127-get-coeffs.
// No new cryptographic primitives; pure data dump.

package main

// K2Recip127GetCoeffsInput carries the FP precision for coefficient encoding.
// Optional ring127 fracBits override (default 50).
type K2Recip127GetCoeffsInput struct {
	FracBits int `json:"frac_bits"`
}

// K2Recip127GetCoeffsOutput carries the base64-encoded constants.
//
//	OneOverHalfRange     : single Uint128, the affine slope 1/halfRange
//	                        applied to x via LocalScale.
//	NegMidOverHalfRange  : single Uint128, the affine offset -mid/halfRange
//	                        added as party-0 public constant.
//	TwoFp                : single Uint128, FP encoding of the constant 2.0.
//	                        Used as the `const` of the NR AffineCombine step
//	                        `twoMinusXy = 2 − x·y` (sign_a=0, sign_b=-1).
//	Coeffs               : (degree+1) Uint128 values, c_0..c_N in degree order.
//	Degree               : polynomial degree (30).
//	NRSteps              : number of Newton-Raphson refinement iters (6).
//	FracBits             : Ring127 fracBits used for FP encoding (50).
type K2Recip127GetCoeffsOutput struct {
	OneOverHalfRange    string `json:"one_over_half_range"`
	NegMidOverHalfRange string `json:"neg_mid_over_half_range"`
	TwoFp               string `json:"two_fp"`
	Coeffs              string `json:"coeffs"`
	Degree              int    `json:"degree"`
	NRSteps             int    `json:"nr_steps"`
	FracBits            int    `json:"frac_bits"`
}

// handleK2Recip127GetCoeffs serializes the Chebyshev recip constants.
// The Coeffs blob layout is the standard Uint128VecToB64 packing:
// [c_0_Lo | c_0_Hi | c_1_Lo | c_1_Hi | ... | c_N_Lo | c_N_Hi] little-endian.
func handleK2Recip127GetCoeffs() {
	var input K2Recip127GetCoeffsInput
	mpcReadInput(&input)
	fb := input.FracBits
	if fb <= 0 {
		fb = K2DefaultFracBits127
	}
	r := NewRing127(fb)
	coeffs, oneOverHalfRange, negMidOverHalfRange, degree :=
		Ring127RecipChebCoeffsFP(r)
	twoFp := r.FromDouble(2.0)

	mpcWriteOutput(K2Recip127GetCoeffsOutput{
		OneOverHalfRange:    Uint128VecToB64([]Uint128{oneOverHalfRange}),
		NegMidOverHalfRange: Uint128VecToB64([]Uint128{negMidOverHalfRange}),
		TwoFp:               Uint128VecToB64([]Uint128{twoFp}),
		Coeffs:              Uint128VecToB64(coeffs),
		Degree:              degree,
		NRSteps:             Ring127RecipChebNRSteps,
		FracBits:            fb,
	})
}
