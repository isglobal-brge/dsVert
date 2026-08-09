// k2_fp_ops_ring127.go — Ring127 variants of the local fixed-point ops.
//
// Structurally identical to k2_fp_ops.go but operating on Uint128 under
// Ring127 (2^127 modulus). Invoked by the existing handlers in k2_fp_ops.go
// when input.Ring == "ring127". 16-byte little-endian per element, layout
// [Lo(8) | Hi(8)] — identical to uint128VecToBytes / bytesToUint128Vec.
//
// Default fracBits for Ring127 = 50 (matches the Beaver sign-safety zone
// established in step 1: 2*fracBits = 100 << 2^126 sign threshold).
//
// Dispatch pattern: each helper takes a pre-parsed input struct. stdin
// must NOT be read here — that has already been done by the caller (the
// Ring63 handler's mpcReadInput). This avoids double-reading stdin.

package main

const K2DefaultFracBits127 = 50

// --- helpers ----------------------------------------------------------------

func ring127DefaultFracBits(v int) int {
	normalized, err := normalizeRing127FracBits(v)
	if err != nil {
		panic("Ring127: " + err.Error())
	}
	return normalized
}

// b64Uint128Vec decodes a base64 blob into a []Uint128 (16 bytes per element).
func b64Uint128Vec(s string) []Uint128 {
	return bytesToUint128Vec(base64ToBytes(s))
}

// Uint128VecToB64 encodes a []Uint128 as base64 (16 bytes per element).
func Uint128VecToB64(v []Uint128) string {
	return bytesToBase64(uint128VecToBytes(v))
}

// --- k2-fp-add / k2-fp-sub --------------------------------------------------

func handleK2FPAdd127(input K2FPAddInput) {
	fb := ring127DefaultFracBits(input.FracBits)
	r := NewRing127(fb)
	a, err := decodeRing127Vector(input.A, -1)
	if err != nil {
		outputError("k2-fp-add (ring127): invalid a: " + err.Error())
		return
	}
	b, err := decodeRing127Vector(input.B, len(a))
	if err != nil {
		outputError("k2-fp-add (ring127): invalid b: " + err.Error())
		return
	}
	out := make([]Uint128, len(a))
	for i := range a {
		out[i] = r.Add(a[i], b[i])
	}
	mpcWriteOutput(K2FPAddOutput{Result: Uint128VecToB64(out)})
}

func handleK2FPSub127(input K2FPAddInput) {
	fb := ring127DefaultFracBits(input.FracBits)
	r := NewRing127(fb)
	a, err := decodeRing127Vector(input.A, -1)
	if err != nil {
		outputError("k2-fp-sub (ring127): invalid a: " + err.Error())
		return
	}
	b, err := decodeRing127Vector(input.B, len(a))
	if err != nil {
		outputError("k2-fp-sub (ring127): invalid b: " + err.Error())
		return
	}
	out := make([]Uint128, len(a))
	for i := range a {
		out[i] = r.Sub(a[i], b[i])
	}
	mpcWriteOutput(K2FPAddOutput{Result: Uint128VecToB64(out)})
}

// --- k2-fp-vec-mul (LOCAL exact public bit-mask selection) ------------------

func handleK2FPVecMul127(input K2FPVecMulInput) {
	fb := ring127DefaultFracBits(input.FracBits)
	r := NewRing127(fb)
	a, err := decodeRing127Vector(input.A, -1)
	if err != nil {
		outputError("k2-fp-vec-mul (ring127): invalid a: " + err.Error())
		return
	}
	b, err := decodeRing127Vector(input.B, len(a))
	if err != nil {
		outputError("k2-fp-vec-mul (ring127): invalid b: " + err.Error())
		return
	}
	out, err := applyPublicBitMask127(a, b, r)
	if err != nil {
		outputError("k2-fp-vec-mul (ring127): " + err.Error())
		return
	}
	mpcWriteOutput(K2FPVecMulOutput{Result: Uint128VecToB64(out)})
}

// --- k2-fp-sum --------------------------------------------------------------

func handleK2FPSum127(input K2FPSumInput) {
	r := NewRing127(K2DefaultFracBits127) // fracBits doesn't affect Add
	data, err := decodeRing127Vector(input.FPData, -1)
	if err != nil {
		outputError("k2-fp-sum (ring127): invalid fp_data: " + err.Error())
		return
	}
	total := Uint128{}
	for _, v := range data {
		total = r.Add(total, v)
	}
	mpcWriteOutput(K2FPSumOutput{
		SumFP: Uint128VecToB64([]Uint128{total}),
	})
}

// --- k2-fp-strided-sum ------------------------------------------------------

func handleK2FPStridedSum127(input K2FPStridedSumInput) {
	if input.N <= 0 || input.J <= 0 {
		outputError("k2-fp-strided-sum (ring127): bad n/j")
		return
	}
	expected, err := checkedProduct("k2-fp-strided-sum matrix", input.N, input.J)
	if err != nil {
		outputError("k2-fp-strided-sum (ring127): " + err.Error())
		return
	}
	data, err := decodeRing127Vector(input.FPData, expected)
	if err != nil {
		outputError("k2-fp-strided-sum (ring127): invalid fp_data: " + err.Error())
		return
	}
	r := NewRing127(K2DefaultFracBits127)
	out := make([]Uint128, input.J)
	for i := 0; i < input.N; i++ {
		base := i * input.J
		for j := 0; j < input.J; j++ {
			out[j] = r.Add(out[j], data[base+j])
		}
	}
	mpcWriteOutput(K2FPStridedSumOutput{
		Result: Uint128VecToB64(out),
	})
}

// --- k2-fp-cumsum (strata-aware reverse/forward, optional mask) -------------

func handleK2FPCumsum127(input K2FPCumsumInput) {
	fb := ring127DefaultFracBits(input.FracBits)
	r := NewRing127(fb)
	expected := -1
	if input.N > 0 {
		expected = input.N
	}
	a, err := decodeRing127Vector(input.A, expected)
	if err != nil {
		outputError("k2-fp-cumsum (ring127): invalid a: " + err.Error())
		return
	}
	n := len(a)
	if len(input.Strata) != 0 && len(input.Strata) != n {
		outputError("k2-fp-cumsum (ring127): strata length mismatch")
		return
	}
	if input.Mask != "" {
		mask, err := decodeRing127Vector(input.Mask, n)
		if err != nil {
			outputError("k2-fp-cumsum (ring127): invalid mask: " + err.Error())
			return
		}
		a, err = applyPublicBitMask127(a, mask, r)
		if err != nil {
			outputError("k2-fp-cumsum (ring127): " + err.Error())
			return
		}
	}
	useStrata := len(input.Strata) == n
	out := make([]Uint128, n)
	if input.Reverse {
		acc := Uint128{}
		for i := n - 1; i >= 0; i-- {
			if useStrata && i+1 < n && input.Strata[i+1] != input.Strata[i] {
				acc = Uint128{}
			}
			acc = r.Add(acc, a[i])
			out[i] = acc
		}
	} else {
		acc := Uint128{}
		for i := 0; i < n; i++ {
			if useStrata && i > 0 && input.Strata[i] != input.Strata[i-1] {
				acc = Uint128{}
			}
			acc = r.Add(acc, a[i])
			out[i] = acc
		}
	}
	mpcWriteOutput(K2FPCumsumOutput{Result: Uint128VecToB64(out)})
}

// --- k2-fp-extract-column ---------------------------------------------------

func handleK2FPExtractColumn127(input K2FPExtractColumnInput) {
	if input.N <= 0 || input.K <= 0 || input.Col < 0 || input.Col >= input.K {
		outputError("k2-fp-extract-column (ring127): bad n/k/col")
		return
	}
	expected, err := checkedProduct("k2-fp-extract-column matrix", input.N, input.K)
	if err != nil {
		outputError("k2-fp-extract-column (ring127): " + err.Error())
		return
	}
	a, err := decodeRing127Vector(input.FPData, expected)
	if err != nil {
		outputError("k2-fp-extract-column (ring127): invalid fp_data: " + err.Error())
		return
	}
	out := make([]Uint128, input.N)
	for i := 0; i < input.N; i++ {
		out[i] = a[i*input.K+input.Col]
	}
	mpcWriteOutput(K2FPExtractColumnOutput{Result: Uint128VecToB64(out)})
}

// --- k2-fp-permute-share ----------------------------------------------------

func handleK2FPPermuteShare127(input K2FPPermuteShareInput) {
	a, err := decodeRing127Vector(input.A, -1)
	if err != nil {
		outputError("k2-fp-permute-share (ring127): invalid a: " + err.Error())
		return
	}
	cols := input.Cols
	if cols <= 0 {
		cols = 1
	}
	total := len(a)
	if total%cols != 0 {
		outputError("k2-fp-permute-share (ring127): vector length not divisible by cols")
		return
	}
	n := total / cols
	if input.N > 0 && input.N != n {
		outputError("k2-fp-permute-share (ring127): n does not match the payload")
		return
	}
	if len(input.Perm) != n {
		outputError("k2-fp-permute-share (ring127): permutation length mismatch")
		return
	}
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
	out := make([]Uint128, total)
	for i := 0; i < n; i++ {
		src := input.Perm[i] - base
		if src < 0 || src >= n {
			outputError("k2-fp-permute-share (ring127): index out of range")
			return
		}
		copy(out[i*cols:(i+1)*cols], a[src*cols:(src+1)*cols])
	}
	mpcWriteOutput(K2FPPermuteShareOutput{Result: Uint128VecToB64(out)})
}
