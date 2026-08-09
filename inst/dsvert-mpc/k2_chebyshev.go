// k2_chebyshev.go: Float-to-FP conversion command for K=2.

package main

// ============================================================================
// Command: k2-float-to-fp
// Converts float64 array to base64 FixedPoint vector (no splitting).
// ============================================================================

type K2FloatToFPInput struct {
	Values   []float64 `json:"values"`
	FracBits int       `json:"frac_bits"`
	// Ring selector. "" or "ring63" (default, 8-byte per element) / "ring127"
	// (16-byte per element Uint128). Ring127 selected by task #116 Cox/LMM
	// plumbing at step 5+.
	Ring string `json:"ring"`
}

type K2FloatToFPOutput struct {
	FPData string `json:"fp_data"` // base64 FixedPoint
}

func handleK2FloatToFP() {
	var input K2FloatToFPInput
	mpcReadInput(&input)
	out, err := encodeK2FloatToFP(input)
	if err != nil {
		outputError("k2-float-to-fp: " + err.Error())
		return
	}
	mpcWriteOutput(out)
}
