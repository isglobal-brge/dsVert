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
// Command: k2-fp-permute
// Permute elements of an FP vector by given indices.
// Used to align gradient column orders between DCF parties in K>=3.
// ============================================================================

type K2FPPermuteInput struct {
	FPData string `json:"fp_data"` // base64 FP
	Perm   []int  `json:"perm"`    // permutation: result[i] = input[perm[i]]
}

func handleK2FPPermute() {
	var input K2FPPermuteInput
	mpcReadInput(&input)
	data := bytesToFPVec(base64ToBytes(input.FPData))
	result := make([]FixedPoint, len(input.Perm))
	for i, p := range input.Perm {
		result[i] = data[p]
	}
	mpcWriteOutput(map[string]string{
		"fp_data": bytesToBase64(fpVecToBytes(result)),
	})
}

// ============================================================================
// Command: k2-fp-column-concat
// Concatenate column blocks of row-major FP matrices.
// Used for K>=3 input sharing: append extra servers' features to the peer share.
// ============================================================================

type K2FPColumnConcatInput struct {
	A    string `json:"a"`     // base64 FP (n × p_a, row-major)
	B    string `json:"b"`     // base64 FP (n × p_b, row-major)
	N    int    `json:"n"`     // number of rows
	PA   int    `json:"p_a"`   // columns in A
	PB   int    `json:"p_b"`   // columns in B
}

type K2FPColumnConcatOutput struct {
	Result string `json:"result"` // base64 FP (n × (p_a + p_b), row-major)
}

func handleK2FPColumnConcat() {
	var input K2FPColumnConcatInput
	mpcReadInput(&input)
	a := bytesToFPVec(base64ToBytes(input.A))
	b := bytesToFPVec(base64ToBytes(input.B))
	n, pa, pb := input.N, input.PA, input.PB
	ptotal := pa + pb
	result := make([]FixedPoint, n*ptotal)
	for i := 0; i < n; i++ {
		for j := 0; j < pa; j++ {
			result[i*ptotal+j] = a[i*pa+j]
		}
		for j := 0; j < pb; j++ {
			result[i*ptotal+pa+j] = b[i*pb+j]
		}
	}
	mpcWriteOutput(K2FPColumnConcatOutput{
		Result: bytesToBase64(fpVecToBytes(result)),
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
