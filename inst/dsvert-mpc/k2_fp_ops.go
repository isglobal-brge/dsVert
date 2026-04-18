// k2_fp_ops.go: Fixed-point arithmetic helper commands.
package main

import "fmt"

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
// Command: k2-fp-vec-mul
// Element-wise Ring63 FP multiplication with truncation:
//   result[i] = (a[i] * b[i]) >> fracBits   (signed, mod 2^63).
//
// This is LOCAL (no communication): it is intended for the case where
// one operand is a secret share held by this party and the other is a
// public or server-to-server-broadcast plaintext vector known to this
// party -- e.g., element-wise scaling of a residual share by a
// per-patient weights vector in weighted GLM / IPW.
//
// Correctness of additive sharing under per-element scaling:
//   Given shares r_A + r_B = r, both parties locally compute
//   r'_A[i] = r_A[i] * w[i] and r'_B[i] = r_B[i] * w[i].
//   Then r'_A + r'_B = w * r element-wise. No Beaver round required.
// ============================================================================

type K2FPVecMulInput struct {
	A        string `json:"a"`         // base64 FP
	B        string `json:"b"`         // base64 FP
	FracBits int    `json:"frac_bits"`
}

type K2FPVecMulOutput struct {
	Result string `json:"result"` // base64 FP
}

func handleK2FPVecMul() {
	var input K2FPVecMulInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}
	r := NewRing63(input.FracBits)
	a := fpToRing63(bytesToFPVec(base64ToBytes(input.A)))
	b := fpToRing63(bytesToFPVec(base64ToBytes(input.B)))
	if len(a) != len(b) {
		outputError("k2-fp-vec-mul: length mismatch")
		return
	}
	result := make([]uint64, len(a))
	for i := range a {
		result[i] = r.TruncMulSigned(a[i], b[i])
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
// Because the mask is a plaintext vector known on each party (usually
// derived from event indicators held by the outcome server and shared
// to peer via the usual transport), the element-wise pre-multiply is a
// TruncMulSigned LOCAL operation per party.
// ============================================================================

type K2FPCumsumInput struct {
	A        string `json:"a"`        // base64 FP input vector (share)
	Mask     string `json:"mask"`     // optional base64 FP mask (plaintext)
	Reverse  bool   `json:"reverse"`  // true = right-to-left cumulative sum
	N        int    `json:"n"`
	// Strata: optional 1-based stratum id per element (same length as A).
	// If provided, the running accumulator RESETS to 0 at every stratum
	// boundary, so the cumsum is computed WITHIN each stratum. Used by
	// stratified Cox (one risk-set per stratum).
	Strata   []int  `json:"strata"`
	FracBits int    `json:"frac_bits"`
}

type K2FPCumsumOutput struct {
	Result string `json:"result"` // base64 FP cumulative-sum vector (share)
}

func handleK2FPCumsum() {
	var input K2FPCumsumInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}
	r := NewRing63(input.FracBits)
	a := fpToRing63(bytesToFPVec(base64ToBytes(input.A)))
	n := len(a)
	if input.N > 0 && input.N != n {
		outputError("k2-fp-cumsum: length mismatch")
		return
	}

	// Apply optional mask (element-wise TruncMulSigned)
	if input.Mask != "" {
		mask := fpToRing63(bytesToFPVec(base64ToBytes(input.Mask)))
		if len(mask) != n {
			outputError("k2-fp-cumsum: mask length mismatch")
			return
		}
		for i := 0; i < n; i++ {
			a[i] = r.TruncMulSigned(a[i], mask[i])
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
	Cols     int `json:"cols"`
	FracBits int `json:"frac_bits"`
}

type K2FPPermuteShareOutput struct {
	Result string `json:"result"`
}

func handleK2FPPermuteShare() {
	var input K2FPPermuteShareInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}
	a := fpToRing63(bytesToFPVec(base64ToBytes(input.A)))
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
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}
	r := NewRing63(input.FracBits)
	a := fpToRing63(bytesToFPVec(base64ToBytes(input.A)))
	b := fpToRing63(bytesToFPVec(base64ToBytes(input.B)))
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
}

type K2FPSumOutput struct {
	SumFP string `json:"sum_fp"` // base64 FP single scalar (8 bytes)
}

func handleK2FPSum() {
	var input K2FPSumInput
	mpcReadInput(&input)
	data := bytesToFPVec(base64ToBytes(input.FPData))
	ring := NewRing63(20) // frac_bits doesn't matter for addition
	var total uint64
	for _, v := range data {
		total = ring.Add(total, uint64(v))
	}
	result := make([]FixedPoint, 1)
	result[0] = FixedPoint(total)
	mpcWriteOutput(K2FPSumOutput{
		SumFP: bytesToBase64(fpVecToBytes(result)),
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
}

type K2FPExtractColumnOutput struct {
	Result string `json:"result"`
}

func handleK2FPExtractColumn() {
	var input K2FPExtractColumnInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}
	if input.N <= 0 || input.K <= 0 || input.Col < 0 || input.Col >= input.K {
		outputError("k2-fp-extract-column: bad n/k/col")
		return
	}
	a := fpToRing63(bytesToFPVec(base64ToBytes(input.FPData)))
	if len(a) != input.N*input.K {
		outputError(fmt.Sprintf(
			"k2-fp-extract-column: length mismatch (got %d, expected n*k=%d*%d=%d)",
			len(a), input.N, input.K, input.N*input.K))
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

