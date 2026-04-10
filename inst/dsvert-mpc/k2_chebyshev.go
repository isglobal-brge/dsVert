// k2_chebyshev.go: Float-to-FP conversion command for K=2.

package main

// ============================================================================
// Command: k2-float-to-fp
// Converts float64 array to base64 FixedPoint vector (no splitting).
// ============================================================================

type K2FloatToFPInput struct {
	Values   []float64 `json:"values"`
	FracBits int       `json:"frac_bits"`
}

type K2FloatToFPOutput struct {
	FPData string `json:"fp_data"` // base64 FixedPoint
}

func handleK2FloatToFP() {
	var input K2FloatToFPInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = 20
	}
	// Encode in Ring63 for the K=2 Beaver pipeline
	ring := NewRing63(input.FracBits)
	r63 := make([]uint64, len(input.Values))
	for i, v := range input.Values {
		r63[i] = ring.FromDouble(v)
	}
	mpcWriteOutput(K2FloatToFPOutput{
		FPData: bytesToBase64(fpVecToBytes(ring63ToFP(r63))),
	})
}
