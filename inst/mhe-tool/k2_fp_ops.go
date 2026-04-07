// k2_fp_ops.go: Fixed-point arithmetic helper commands.
package main

import "math"

// ============================================================================
// Command: k2-fp-add
// Element-wise Ring63 addition of two FP vectors. LOCAL, no communication.
// Used to add intercept shares to slope*x shares: spline = slope*x + intercept.
// ============================================================================

type K2FPAddInput struct {
	A        string `json:"a"`         // base64 FP
	B        string `json:"b"`         // base64 FP
	FracBits int    `json:"frac_bits"`
}

type K2FPAddOutput struct {
	Result string `json:"result"` // base64 FP
}

func handleK2FPAdd() {
	var input K2FPAddInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}
	r := NewRing63(input.FracBits)
	a := fpToRing63(bytesToFPVec(base64ToBytes(input.A)))
	b := fpToRing63(bytesToFPVec(base64ToBytes(input.B)))
	result := make([]uint64, len(a))
	for i := range a {
		result[i] = r.Add(a[i], b[i])
	}
	mpcWriteOutput(K2FPAddOutput{
		Result: bytesToBase64(fpVecToBytes(ring63ToFP(result))),
	})
}

// ============================================================================
// Command: k2-fp-scale-indicator
// Multiplies each element by FracMul (integer → FP scaling).
// Used to convert integer AND result to FP for subsequent Hadamard.
// ============================================================================

type K2FPScaleIndicatorInput struct {
	DataFP   string `json:"data_fp"`   // base64 FP (integer values as int64)
	FracBits int    `json:"frac_bits"`
}

type K2FPScaleIndicatorOutput struct {
	Result string `json:"result"` // base64 FP (FP-scaled)
}

func handleK2FPScaleIndicator() {
	var input K2FPScaleIndicatorInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}
	r := NewRing63(input.FracBits)
	data := fpToRing63(bytesToFPVec(base64ToBytes(input.DataFP)))
	result := make([]uint64, len(data))
	for i := range data {
		result[i] = modMulBig63(data[i], r.FracMul, r.Modulus)
	}
	mpcWriteOutput(K2FPScaleIndicatorOutput{
		Result: bytesToBase64(fpVecToBytes(ring63ToFP(result))),
	})
}

// ============================================================================
// Helpers
// ============================================================================

func computeSigmoidSplineCoeffs(numIntervals int) (slopes, intercepts []float64, lower, upper float64) {
	lower, upper = -5.0, 5.0
	sigma := func(x float64) float64 { return 1.0 / (1.0 + math.Exp(-x)) }
	slopes, intercepts = computeWideSpline(sigma, numIntervals, lower, upper)
	return
}

func computeExpSplineCoeffs(numIntervals int) (slopes, intercepts []float64, lower, upper float64) {
	lower, upper = -3.0, 8.0
	slopes, intercepts = computeWideSpline(math.Exp, numIntervals, lower, upper)
	return
}
