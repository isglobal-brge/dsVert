// k2_fp_ops.go: Fixed-point arithmetic helper commands.
package main

import "fmt"

// ============================================================================
// Command: k2-fp-add
// Element-wise Ring63 addition of two FP vectors. LOCAL, no communication.
// Used to add intercept shares to slope*x shares: spline = slope*x + intercept.
// ============================================================================

type K2FPAddInput struct {
	A        string `json:"a"` // base64 FP
	B        string `json:"b"` // base64 FP
	FracBits int    `json:"frac_bits"`
	Ring     string `json:"ring"` // "" or "ring63" or "ring127"
}

type K2FPAddOutput struct {
	Result string `json:"result"` // base64 FP
}

func handleK2FPAdd() {
	var input K2FPAddInput
	mpcReadInput(&input)
	ringName, fracBits, err := normalizeRingAndFracBits(input.Ring, input.FracBits)
	if err != nil {
		outputError("k2-fp-add: " + err.Error())
		return
	}
	input.Ring, input.FracBits = ringName, fracBits
	if ringName == "ring127" {
		handleK2FPAdd127(input)
		return
	}
	r := NewRing63(fracBits)
	a, err := decodeRing63FPVector(input.A, -1)
	if err != nil {
		outputError("k2-fp-add: invalid a: " + err.Error())
		return
	}
	b, err := decodeRing63FPVector(input.B, len(a))
	if err != nil {
		outputError("k2-fp-add: invalid b: " + err.Error())
		return
	}
	result := make([]uint64, len(a))
	for i := range a {
		result[i] = r.Add(a[i], b[i])
	}
	mpcWriteOutput(K2FPAddOutput{
		Result: bytesToBase64(fpVecToBytes(ring63ToFP(result))),
	})
}

// ============================================================================
// Command: k2-fp-vec-mul
// Apply a public binary mask to a Ring63 FP share.
//
// This is LOCAL (no communication): it is intended for the case where
// A is a secret share held by this party and B is an encoded public 0/1
// vector. The historical command name is retained for compatibility.
//
// Copying a share for bit 1 and returning zero for bit 0 is exact and avoids
// local fixed-point truncation. Arbitrary public weights are deliberately
// rejected: independently truncating two random shares is not a linear share
// operation and has the catastrophic wrap event documented in
// k2_truncation.go.
// ============================================================================

type K2FPVecMulInput struct {
	A        string `json:"a"` // base64 FP
	B        string `json:"b"` // base64 FP
	FracBits int    `json:"frac_bits"`
	Ring     string `json:"ring"` // "" or "ring63" or "ring127"
}

type K2FPVecMulOutput struct {
	Result string `json:"result"` // base64 FP
}

func handleK2FPVecMul() {
	var input K2FPVecMulInput
	mpcReadInput(&input)
	ringName, fracBits, err := normalizeRingAndFracBits(input.Ring, input.FracBits)
	if err != nil {
		outputError("k2-fp-vec-mul: " + err.Error())
		return
	}
	input.Ring, input.FracBits = ringName, fracBits
	if ringName == "ring127" {
		handleK2FPVecMul127(input)
		return
	}
	r := NewRing63(fracBits)
	a, err := decodeRing63FPVector(input.A, -1)
	if err != nil {
		outputError("k2-fp-vec-mul: invalid a: " + err.Error())
		return
	}
	b, err := decodeRing63FPVector(input.B, len(a))
	if err != nil {
		outputError("k2-fp-vec-mul: invalid b: " + err.Error())
		return
	}
	result, err := applyPublicBitMask63(a, b, r)
	if err != nil {
		outputError("k2-fp-vec-mul: " + err.Error())
		return
	}
	mpcWriteOutput(K2FPVecMulOutput{
		Result: bytesToBase64(fpVecToBytes(ring63ToFP(result))),
	})
}

// ============================================================================
// Command: k2-fp-cumsum
// Cumulative sum of a Ring63 FP vector (forward or reverse). LOCAL on
// shares, no communication. Correctness under additive sharing:
//   Given shares a_A + a_B = a (element-wise), both parties compute
//   their local cumsum. Summed: cumsum(a_A) + cumsum(a_B) = cumsum(a),
//   because cumsum distributes over addition.
//
// Used as the kernel for Cox partial-likelihood gradient reverse-cumsum:
//     S(t_i) = sum_{k: t_k >= t_i} exp(eta_k)
// With patients pre-sorted in ascending time order, S(t_i) is the
// REVERSE cumulative sum of exp(eta) at position i. The forward
// cumulative sum is used for the G_j accumulator in the reformulated
// Cox gradient.
//
// Optional mask input: if provided, each element is multiplied by its
// mask bit before accumulation, so the caller can restrict the sum to
// events (delta_i == 1) in-place without a separate Beaver step.
// The mask must be an encoded public 0/1 vector. The element-wise operation
// is exact share selection, so it introduces neither truncation nor wrap.
// ============================================================================

type K2FPCumsumInput struct {
	A       string `json:"a"`       // base64 FP input vector (share)
	Mask    string `json:"mask"`    // optional base64 FP mask (plaintext)
	Reverse bool   `json:"reverse"` // true = right-to-left cumulative sum
	N       int    `json:"n"`
	// Strata: optional 1-based stratum id per element (same length as A).
	// If provided, the running accumulator RESETS to 0 at every stratum
	// boundary, so the cumsum is computed WITHIN each stratum. Used by
	// stratified Cox (one risk-set per stratum).
	Strata   []int  `json:"strata"`
	FracBits int    `json:"frac_bits"`
	Ring     string `json:"ring"` // "" or "ring63" or "ring127"
}

type K2FPCumsumOutput struct {
	Result string `json:"result"` // base64 FP cumulative-sum vector (share)
}

func handleK2FPCumsum() {
	var input K2FPCumsumInput
	mpcReadInput(&input)
	ringName, fracBits, err := normalizeRingAndFracBits(input.Ring, input.FracBits)
	if err != nil {
		outputError("k2-fp-cumsum: " + err.Error())
		return
	}
	input.Ring, input.FracBits = ringName, fracBits
	if ringName == "ring127" {
		handleK2FPCumsum127(input)
		return
	}
	r := NewRing63(fracBits)
	expected := -1
	if input.N > 0 {
		expected = input.N
	}
	a, err := decodeRing63FPVector(input.A, expected)
	if err != nil {
		outputError("k2-fp-cumsum: invalid a: " + err.Error())
		return
	}
	n := len(a)
	if len(input.Strata) != 0 && len(input.Strata) != n {
		outputError("k2-fp-cumsum: strata length mismatch")
		return
	}

	// Apply the optional public bit mask exactly, without truncation.
	if input.Mask != "" {
		mask, err := decodeRing63FPVector(input.Mask, n)
		if err != nil {
			outputError("k2-fp-cumsum: invalid mask: " + err.Error())
			return
		}
		a, err = applyPublicBitMask63(a, mask, r)
		if err != nil {
			outputError("k2-fp-cumsum: " + err.Error())
			return
		}
	}

	useStrata := len(input.Strata) == n
	out := make([]uint64, n)
	if input.Reverse {
		acc := uint64(0)
		for i := n - 1; i >= 0; i-- {
			// Reset accumulator at the END of each stratum segment (i.e.
			// when strata[i+1] differs from strata[i]): since we iterate
			// right-to-left, detect when we're about to step into a new
			// stratum.
			if useStrata && i+1 < n && input.Strata[i+1] != input.Strata[i] {
				acc = 0
			}
			acc = r.Add(acc, a[i])
			out[i] = acc
		}
	} else {
		acc := uint64(0)
		for i := 0; i < n; i++ {
			if useStrata && i > 0 && input.Strata[i] != input.Strata[i-1] {
				acc = 0
			}
			acc = r.Add(acc, a[i])
			out[i] = acc
		}
	}

	mpcWriteOutput(K2FPCumsumOutput{
		Result: bytesToBase64(fpVecToBytes(ring63ToFP(out))),
	})
}

// ============================================================================
// Command: k2-fp-permute
// Apply a public permutation to an FP vector share. LOCAL op: each
// party independently reorders its share, and the sum of shares after
// reordering equals the reordered sum.
// ============================================================================

type K2FPPermuteShareInput struct {
	A    string `json:"a"`    // base64 FP input vector (flat or row-major matrix)
	Perm []int  `json:"perm"` // 1-indexed permutation (R convention) or 0-indexed
	N    int    `json:"n"`
	// Cols: if >1, treat the share as a row-major n-by-cols matrix and
	// permute whole rows (output[i*cols+j] = input[perm[i]*cols+j]).
	// Zero or 1 means flat-vector permutation (legacy behaviour).
	Cols     int    `json:"cols"`
	FracBits int    `json:"frac_bits"`
	Ring     string `json:"ring"` // "" or "ring63" or "ring127"
}

type K2FPPermuteShareOutput struct {
	Result string `json:"result"`
}

func handleK2FPPermuteShare() {
	var input K2FPPermuteShareInput
	mpcReadInput(&input)
	if input.N < 0 || input.Cols < 0 {
		outputError("k2-fp-permute-share: n and cols must not be negative")
		return
	}
	ringName, fracBits, err := normalizeRingAndFracBits(input.Ring, input.FracBits)
	if err != nil {
		outputError("k2-fp-permute-share: " + err.Error())
		return
	}
	input.Ring, input.FracBits = ringName, fracBits
	if ringName == "ring127" {
		handleK2FPPermuteShare127(input)
		return
	}
	a, err := decodeRing63FPVector(input.A, -1)
	if err != nil {
		outputError("k2-fp-permute-share: invalid a: " + err.Error())
		return
	}
	cols := input.Cols
	if cols <= 0 {
		cols = 1
	}
	total := len(a)
	if total%cols != 0 {
		outputError("k2-fp-permute-share: vector length not divisible by cols")
		return
	}
	n := total / cols
	if input.N > 0 && input.N != n {
		outputError("k2-fp-permute-share: n does not match the payload")
		return
	}
	if len(input.Perm) != n {
		outputError("k2-fp-permute-share: permutation length mismatch")
		return
	}
	// Detect 1-indexed (R) vs 0-indexed and normalise to 0.
	maxIdx := 0
	for _, p := range input.Perm {
		if p > maxIdx {
			maxIdx = p
		}
	}
	base := 0
	if maxIdx == n {
		base = 1
	}
	out := make([]uint64, total)
	for i := 0; i < n; i++ {
		src := input.Perm[i] - base
		if src < 0 || src >= n {
			outputError("k2-fp-permute-share: index out of range")
			return
		}
		// Copy the whole row (cols = 1 for flat vectors).
		copy(out[i*cols:(i+1)*cols], a[src*cols:(src+1)*cols])
	}
	mpcWriteOutput(K2FPPermuteShareOutput{
		Result: bytesToBase64(fpVecToBytes(ring63ToFP(out))),
	})
}

// ============================================================================
// Command: k2-fp-sub
// Element-wise Ring63 subtraction: result = a - b.
// Used for computing residual = mu_share - y_share for deviance.
// ============================================================================

func handleK2FPSub() {
	var input K2FPAddInput
	mpcReadInput(&input)
	ringName, fracBits, err := normalizeRingAndFracBits(input.Ring, input.FracBits)
	if err != nil {
		outputError("k2-fp-sub: " + err.Error())
		return
	}
	input.Ring, input.FracBits = ringName, fracBits
	if ringName == "ring127" {
		handleK2FPSub127(input)
		return
	}
	r := NewRing63(fracBits)
	a, err := decodeRing63FPVector(input.A, -1)
	if err != nil {
		outputError("k2-fp-sub: invalid a: " + err.Error())
		return
	}
	b, err := decodeRing63FPVector(input.B, len(a))
	if err != nil {
		outputError("k2-fp-sub: invalid b: " + err.Error())
		return
	}
	result := make([]uint64, len(a))
	for i := range a {
		result[i] = r.Sub(a[i], b[i])
	}
	mpcWriteOutput(K2FPAddOutput{
		Result: bytesToBase64(fpVecToBytes(ring63ToFP(result))),
	})
}

// ============================================================================
// Command: k2-fp-sum
// Sum all elements of a Ring63 FP vector, returning a single scalar.
// Used for deviance computation: Σμ or Σsoftplus(η).
// ============================================================================

type K2FPSumInput struct {
	FPData string `json:"fp_data"` // base64 FP vector
	Ring   string `json:"ring"`    // "" or "ring63" or "ring127"
}

type K2FPSumOutput struct {
	SumFP string `json:"sum_fp"` // base64 FP single scalar (8 bytes)
}

func handleK2FPSum() {
	var input K2FPSumInput
	mpcReadInput(&input)
	ringName, _, err := normalizeRingAndFracBits(input.Ring, 0)
	if err != nil {
		outputError("k2-fp-sum: " + err.Error())
		return
	}
	input.Ring = ringName
	if ringName == "ring127" {
		handleK2FPSum127(input)
		return
	}
	data, err := decodeRing63FPVector(input.FPData, -1)
	if err != nil {
		outputError("k2-fp-sum: invalid fp_data: " + err.Error())
		return
	}
	ring := NewRing63(K2DefaultFracBits) // frac_bits doesn't matter for addition; use default for consistency
	var total uint64
	for _, v := range data {
		total = ring.Add(total, v)
	}
	result := make([]FixedPoint, 1)
	result[0] = ring63ToFP([]uint64{total})[0]
	mpcWriteOutput(K2FPSumOutput{
		SumFP: bytesToBase64(fpVecToBytes(result)),
	})
}

// ============================================================================
// Command: k2-fp-strided-sum
// Sum a row-major n-by-J FP share matrix down the rows, returning a
// length-J FP share vector. This is a linear operation on additive shares.
// Used by non-disclosive event-time Cox to aggregate n*J risk-set shares
// by hidden event-time index without reconstructing per-event quantities.
// ============================================================================

type K2FPStridedSumInput struct {
	FPData string `json:"fp_data"` // base64 FP vector, row-major n x J
	N      int    `json:"n"`
	J      int    `json:"j"`
	Ring   string `json:"ring"` // "" or "ring63" or "ring127"
}

type K2FPStridedSumOutput struct {
	Result string `json:"result"` // base64 FP length J
}

func handleK2FPStridedSum() {
	var input K2FPStridedSumInput
	mpcReadInput(&input)
	ringName, _, err := normalizeRingAndFracBits(input.Ring, 0)
	if err != nil {
		outputError("k2-fp-strided-sum: " + err.Error())
		return
	}
	input.Ring = ringName
	if ringName == "ring127" {
		handleK2FPStridedSum127(input)
		return
	}
	if input.N <= 0 || input.J <= 0 {
		outputError("k2-fp-strided-sum: bad n/j")
		return
	}
	expected, err := checkedProduct("k2-fp-strided-sum matrix", input.N, input.J)
	if err != nil {
		outputError("k2-fp-strided-sum: " + err.Error())
		return
	}
	data, err := decodeRing63FPVector(input.FPData, expected)
	if err != nil {
		outputError(fmt.Sprintf(
			"k2-fp-strided-sum: invalid fp_data: %s", err))
		return
	}
	ring := NewRing63(K2DefaultFracBits)
	out := make([]uint64, input.J)
	for i := 0; i < input.N; i++ {
		base := i * input.J
		for j := 0; j < input.J; j++ {
			out[j] = ring.Add(out[j], data[base+j])
		}
	}
	mpcWriteOutput(K2FPStridedSumOutput{
		Result: bytesToBase64(fpVecToBytes(ring63ToFP(out))),
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
	Ring   string `json:"ring"`    // "" or "ring63" or "ring127"
}

func handleK2FPPermute() {
	var input K2FPPermuteInput
	mpcReadInput(&input)
	ringName, _, err := normalizeRingAndFracBits(input.Ring, 0)
	if err != nil {
		outputError("k2-fp-permute: " + err.Error())
		return
	}
	if ringName == "ring127" {
		data, err := decodeRing127Vector(input.FPData, -1)
		if err != nil {
			outputError("k2-fp-permute (ring127): invalid fp_data: " + err.Error())
			return
		}
		result := make([]Uint128, len(input.Perm))
		for i, p := range input.Perm {
			if p < 0 || p >= len(data) {
				outputError("k2-fp-permute (ring127): index out of range")
				return
			}
			result[i] = data[p]
		}
		mpcWriteOutput(map[string]string{
			"fp_data": bytesToBase64(uint128VecToBytes(result)),
		})
		return
	}
	data, err := decodeRing63FPVector(input.FPData, -1)
	if err != nil {
		outputError("k2-fp-permute: invalid fp_data: " + err.Error())
		return
	}
	result := make([]uint64, len(input.Perm))
	for i, p := range input.Perm {
		if p < 0 || p >= len(data) {
			outputError("k2-fp-permute: index out of range")
			return
		}
		result[i] = data[p]
	}
	mpcWriteOutput(map[string]string{
		"fp_data": bytesToBase64(fpVecToBytes(ring63ToFP(result))),
	})
}

// ============================================================================
// Command: k2-fp-column-concat
// Concatenate column blocks of row-major FP matrices.
// Used for K>=3 input sharing: append extra servers' features to the peer share.
// ============================================================================

type K2FPColumnConcatInput struct {
	A    string `json:"a"`    // base64 FP (n × p_a, row-major)
	B    string `json:"b"`    // base64 FP (n × p_b, row-major)
	N    int    `json:"n"`    // number of rows
	PA   int    `json:"p_a"`  // columns in A
	PB   int    `json:"p_b"`  // columns in B
	Ring string `json:"ring"` // "" or "ring63" or "ring127"
}

type K2FPColumnConcatOutput struct {
	Result string `json:"result"` // base64 FP (n × (p_a + p_b), row-major)
}

// ============================================================================
// Command: k2-fp-extract-column
// Extract a single column from a row-major n*K FP vector (works on
// additively shared input because extraction is a linear operation).
// Used by the cross-server chi-square Beaver bilinear to extract
// individual one-hot indicator columns from the n*K one-hot matrix
// share.
// ============================================================================

type K2FPExtractColumnInput struct {
	FPData   string `json:"fp_data"`
	N        int    `json:"n"`
	K        int    `json:"k"`
	Col      int    `json:"col"` // 0-based
	FracBits int    `json:"frac_bits"`
	Ring     string `json:"ring"` // "" or "ring63" or "ring127"
}

type K2FPExtractColumnOutput struct {
	Result string `json:"result"`
}

func handleK2FPExtractColumn() {
	var input K2FPExtractColumnInput
	mpcReadInput(&input)
	ringName, fracBits, err := normalizeRingAndFracBits(input.Ring, input.FracBits)
	if err != nil {
		outputError("k2-fp-extract-column: " + err.Error())
		return
	}
	input.Ring, input.FracBits = ringName, fracBits
	if ringName == "ring127" {
		handleK2FPExtractColumn127(input)
		return
	}
	if input.N <= 0 || input.K <= 0 || input.Col < 0 || input.Col >= input.K {
		outputError("k2-fp-extract-column: bad n/k/col")
		return
	}
	expected, err := checkedProduct("k2-fp-extract-column matrix", input.N, input.K)
	if err != nil {
		outputError("k2-fp-extract-column: " + err.Error())
		return
	}
	a, err := decodeRing63FPVector(input.FPData, expected)
	if err != nil {
		outputError("k2-fp-extract-column: invalid fp_data: " + err.Error())
		return
	}
	out := make([]uint64, input.N)
	for i := 0; i < input.N; i++ {
		out[i] = a[i*input.K+input.Col]
	}
	mpcWriteOutput(K2FPExtractColumnOutput{
		Result: bytesToBase64(fpVecToBytes(ring63ToFP(out))),
	})
}

func handleK2FPColumnConcat() {
	var input K2FPColumnConcatInput
	mpcReadInput(&input)
	ringName, _, err := normalizeRingAndFracBits(input.Ring, 0)
	if err != nil {
		outputError("k2-fp-column-concat: " + err.Error())
		return
	}
	n, pa, pb := input.N, input.PA, input.PB
	if n <= 0 || pa < 0 || pb < 0 {
		outputError("k2-fp-column-concat: bad dimensions")
		return
	}
	lenA, err := checkedProduct("k2-fp-column-concat a", n, pa)
	if err != nil {
		outputError("k2-fp-column-concat: " + err.Error())
		return
	}
	lenB, err := checkedProduct("k2-fp-column-concat b", n, pb)
	if err != nil {
		outputError("k2-fp-column-concat: " + err.Error())
		return
	}
	if pa > int(^uint(0)>>1)-pb {
		outputError("k2-fp-column-concat: dimensions overflow")
		return
	}
	colsTotal := pa + pb
	outputLen, err := checkedProduct("k2-fp-column-concat output", n, colsTotal)
	if err != nil {
		outputError("k2-fp-column-concat: " + err.Error())
		return
	}
	if ringName == "ring127" {
		a, err := decodeRing127Vector(input.A, lenA)
		if err != nil {
			outputError("k2-fp-column-concat (ring127): invalid a: " + err.Error())
			return
		}
		b, err := decodeRing127Vector(input.B, lenB)
		if err != nil {
			outputError("k2-fp-column-concat (ring127): invalid b: " + err.Error())
			return
		}
		result := make([]Uint128, outputLen)
		for i := 0; i < n; i++ {
			for j := 0; j < pa; j++ {
				result[i*colsTotal+j] = a[i*pa+j]
			}
			for j := 0; j < pb; j++ {
				result[i*colsTotal+pa+j] = b[i*pb+j]
			}
		}
		mpcWriteOutput(K2FPColumnConcatOutput{
			Result: bytesToBase64(uint128VecToBytes(result)),
		})
		return
	}
	a, err := decodeRing63FPVector(input.A, lenA)
	if err != nil {
		outputError("k2-fp-column-concat: invalid a: " + err.Error())
		return
	}
	b, err := decodeRing63FPVector(input.B, lenB)
	if err != nil {
		outputError("k2-fp-column-concat: invalid b: " + err.Error())
		return
	}
	result := make([]uint64, outputLen)
	for i := 0; i < n; i++ {
		for j := 0; j < pa; j++ {
			result[i*colsTotal+j] = a[i*pa+j]
		}
		for j := 0; j < pb; j++ {
			result[i*colsTotal+pa+j] = b[i*pb+j]
		}
	}
	mpcWriteOutput(K2FPColumnConcatOutput{
		Result: bytesToBase64(fpVecToBytes(ring63ToFP(result))),
	})
}
