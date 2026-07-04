// k2_softplus127_handler.go — dispatch handler `k2-softplus127-get-coeffs`.
//
// Public Ring127 Chebyshev-softplus coefficients for the R client's Clenshaw
// orchestration (binomial-deviance link). Coefficients are public/deterministic,
// so distributing them leaks nothing. Pure data dump; no new crypto primitive.

package main

type K2Softplus127GetCoeffsInput struct {
	FracBits int `json:"frac_bits"`
}

type K2Softplus127GetCoeffsOutput struct {
	OneOverA string `json:"one_over_a"`
	Coeffs   string `json:"coeffs"`
	Degree   int    `json:"degree"`
	FracBits int    `json:"frac_bits"`
}

func handleK2Softplus127GetCoeffs() {
	var input K2Softplus127GetCoeffsInput
	mpcReadInput(&input)
	fb := input.FracBits
	if fb <= 0 {
		fb = K2DefaultFracBits127
	}
	r := NewRing127(fb)
	oneOverA, coeffs, degree := Ring127SoftplusCoeffsFP(r)

	mpcWriteOutput(K2Softplus127GetCoeffsOutput{
		OneOverA: Uint128VecToB64([]Uint128{oneOverA}),
		Coeffs:   Uint128VecToB64(coeffs[:]),
		Degree:   degree,
		FracBits: fb,
	})
}
