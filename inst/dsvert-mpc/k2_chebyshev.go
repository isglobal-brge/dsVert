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
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}
	// Ring selector (forward-compat from step 3 pattern). Ring63 (default)
	// emits 8-byte records via fpVecToBytes. Ring127 emits 16-byte Uint128
	// records via uint128VecToBytes — same base64 envelope, wider payload.
	if input.Ring == "ring127" {
		ring127 := NewRing127(input.FracBits)
		r127 := make([]Uint128, len(input.Values))
		for i, v := range input.Values {
			r127[i] = ring127.FromDouble(v)
		}
		mpcWriteOutput(K2FloatToFPOutput{
			FPData: bytesToBase64(uint128VecToBytes(r127)),
		})
		return
	}
	if input.Ring != "" && input.Ring != "ring63" {
		panic("k2-float-to-fp: unknown ring='" + input.Ring + "'")
	}

	// Encode in Ring63 for the K=2 Beaver pipeline (default path).
	ring := NewRing63(input.FracBits)
	r63 := make([]uint64, len(input.Values))
	for i, v := range input.Values {
		r63[i] = ring.FromDouble(v)
	}
	mpcWriteOutput(K2FloatToFPOutput{
		FPData: bytesToBase64(fpVecToBytes(ring63ToFP(r63))),
	})
}
