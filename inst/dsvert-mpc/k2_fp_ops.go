// k2_fp_ops.go: Fixed-point arithmetic helper commands.
package main

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

	out := make([]uint64, n)
	if input.Reverse {
		acc := uint64(0)
		for i := n - 1; i >= 0; i-- {
			acc = r.Add(acc, a[i])
			out[i] = acc
		}
	} else {
		acc := uint64(0)
		for i := 0; i < n; i++ {
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
	A    string `json:"a"`    // base64 FP input vector
	Perm []int  `json:"perm"` // 1-indexed permutation (R convention) or 0-indexed
	N    int    `json:"n"`
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
	n := len(a)
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
	out := make([]uint64, n)
	for i := 0; i < n; i++ {
		src := input.Perm[i] - base
		if src < 0 || src >= n {
			outputError("k2-fp-permute-share: index out of range")
			return
		}
		out[i] = a[src]
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

