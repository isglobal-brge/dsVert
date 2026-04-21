// k2_exp127_handler.go — dispatch handler `k2-exp127-get-coeffs`.
//
// Exposes the public Ring127 Chebyshev-exp coefficients for the R client's
// Horner orchestration. The coefficients themselves are public (they are
// computed deterministically from exp on Chebyshev nodes at init()), so
// distributing them does not leak any secret. The R client fetches these
// once per dsVert session and uses them to drive 30 Beaver vecmul rounds
// per exp call at ring=127 — replacing the spline noise path (1e-4 floor)
// with structural Chebyshev evaluation (~3e-14 rel).
//
// Step 5c(I-c-1): minimal Go deliverable to unblock the R-side
// orchestration. No new cryptographic primitives; pure data dump.

package main

// K2Exp127GetCoeffsInput carries the FP precision for coefficient encoding.
// Optional ring127 fracBits override (default 50).
type K2Exp127GetCoeffsInput struct {
	FracBits int `json:"frac_bits"`
}

// K2Exp127GetCoeffsOutput carries the base64-encoded coefficients.
//   OneOverA  : single Uint128, the rescale factor 1/a (a=5)
//   Coeffs    : 31 Uint128 values, c_0..c_30 in degree order
//   Degree    : polynomial degree (30)
//   FracBits  : Ring127 fracBits used for FP encoding (50)
type K2Exp127GetCoeffsOutput struct {
	OneOverA string `json:"one_over_a"`
	Coeffs   string `json:"coeffs"`
	Degree   int    `json:"degree"`
	FracBits int    `json:"frac_bits"`
}

// handleK2Exp127GetCoeffs serializes 1/a + 31 Chebyshev coefficients as
// little-endian 16-byte-per-Uint128 base64 blobs. The Coeffs blob layout is
// [c_0_Lo(8) | c_0_Hi(8) | c_1_Lo(8) | c_1_Hi(8) | ... | c_30_Lo | c_30_Hi]
// matching uint128VecToBytes / bytesToUint128Vec used everywhere in the
// Ring127 code path.
func handleK2Exp127GetCoeffs() {
	var input K2Exp127GetCoeffsInput
	mpcReadInput(&input)
	fb := input.FracBits
	if fb <= 0 {
		fb = K2DefaultFracBits127
	}
	r := NewRing127(fb)
	oneOverA, coeffs, degree := Ring127ExpCoeffsFP(r)

	mpcWriteOutput(K2Exp127GetCoeffsOutput{
		OneOverA: Uint128VecToB64([]Uint128{oneOverA}),
		Coeffs:   Uint128VecToB64(coeffs[:]),
		Degree:   degree,
		FracBits: fb,
	})
}
