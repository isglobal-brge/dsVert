// k2_sigmoid127_handler.go — dispatch handler `k2-sigmoid127-get-coeffs`.
//
// Exposes the public Ring127 Chebyshev-sigmoid coefficients for the R
// client's Clenshaw orchestration. The coefficients are public (computed
// deterministically from sigmoid on Chebyshev nodes at init()), so
// distributing them leaks nothing. The R client fetches these once per
// dsVert session and drives 29 Beaver vecmul rounds per sigmoid call at
// ring=127 — replacing the exp127+recip127 composition (~85 rounds) for the
// GLM logistic link. Pure public data dump; no new cryptographic primitive.

package main

// K2Sigmoid127GetCoeffsInput carries the FP precision (ring127 fracBits,
// default 50).
type K2Sigmoid127GetCoeffsInput struct {
	FracBits int `json:"frac_bits"`
}

// K2Sigmoid127GetCoeffsOutput carries the base64-encoded coefficients:
//   OneOverA : single Uint128, rescale factor 1/a (a = 8)
//   Coeffs   : 30 Uint128 values, c_0..c_29 in degree order
//   Degree   : polynomial degree (29)
//   FracBits : Ring127 fracBits used (50)
type K2Sigmoid127GetCoeffsOutput struct {
	OneOverA string `json:"one_over_a"`
	Coeffs   string `json:"coeffs"`
	Degree   int    `json:"degree"`
	FracBits int    `json:"frac_bits"`
}

// handleK2Sigmoid127GetCoeffs serializes 1/a + the Chebyshev coefficients as
// little-endian 16-byte-per-Uint128 base64 blobs (identical stride to
// handleK2Exp127GetCoeffs, so the R decoder is reused verbatim).
func handleK2Sigmoid127GetCoeffs() {
	var input K2Sigmoid127GetCoeffsInput
	mpcReadInput(&input)
	fb := input.FracBits
	if fb <= 0 {
		fb = K2DefaultFracBits127
	}
	r := NewRing127(fb)
	oneOverA, coeffs, degree := Ring127SigmoidCoeffsFP(r)

	mpcWriteOutput(K2Sigmoid127GetCoeffsOutput{
		OneOverA: Uint128VecToB64([]Uint128{oneOverA}),
		Coeffs:   Uint128VecToB64(coeffs[:]),
		Degree:   degree,
		FracBits: fb,
	})
}
