// k2_recip127.go — Ring127 plaintext reciprocal 1/x via Goldschmidt /
// Newton-Raphson iteration.
//
// Purpose (task #116 step 5c(I-b)): provide a Ring127 `1/x` primitive
// with rel error < 1e-12 over the Cox S(t) domain [~0.01, ~1e4], as
// the structural replacement for the wide-spline reciprocal path at
// ring=127. Combined with the Chebyshev exp primitive from 5c(I-a),
// this removes the spline noise floor from the Cox Path B pipeline
// and unblocks STRICT closure at large |β|.
//
// Algorithm:
//   1. Sign handling: if x < 0, negate, compute 1/|x|, negate result.
//   2. Range reduction: find integer shift s such that x_norm = x · 2^s
//      ∈ [1, 2). Achieved by locating the MSB of the Ring127 FP value.
//   3. Initial guess (linear interpolation through endpoints):
//        y_0 = 1.5 - 0.5 · x_norm          (i.e., line through (1,1), (2,0.5))
//      Maximum error ≈ 0.083 at x_norm = 1.5 → Newton-Raphson doubles
//      correct bits per iter, reaching >40 correct bits after 5 iters.
//      Always yields y_0 > 0 on [1, 2] (unlike non-endpoint minimax fits
//      that can cross zero and diverge NR).
//   4. Newton-Raphson iteration for 1/x_norm:
//        y_{k+1} = y_k · (2 - x_norm · y_k)
//      Quadratic convergence: err_{k+1} = x_norm · err_k^2. Starting at
//      0.0588, 5 iters: (0.0588)^32 ≈ 1e-40 — way below Ring127 ULP.
//   5. Denormalize: 1/x = y · 2^s (positive shift = left shift).
//
// The MPC variant (step 5c(I-c)): steps 1-2 (sign + range reduction)
// require DCF on shares to determine s. Step 3-4 is a sequence of
// Beaver vecmul rounds on shares (5 NR iters × 2 Beaver mults each =
// 10 Beaver rounds per recip call). Step 5 is local scalar mult by 2^s.

package main

// Ring127RecipPlaintext computes 1/x where x is a non-zero Ring127 FP
// value (plaintext). Used as ground truth for the MPC Goldschmidt/NR
// protocol and to validate the algorithm converges to Ring127 ULP
// precision.
//
// Accuracy: rel error <1e-12 over x ∈ [0.01, 1e4]; this is the Cox
// S(t) domain. Intrinsic error floor is Ring127 ULP at fracBits=50
// (~9e-16 abs), amplified by normalization shift and NR iterations.
//
// Panics if x is zero (reciprocal of 0 is undefined).
func Ring127RecipPlaintext(r Ring127, xRing Uint128) Uint128 {
	if (xRing == Uint128{}) {
		panic("Ring127RecipPlaintext: division by zero")
	}

	// ---- Step 1: sign extraction.
	neg := r.IsNeg(xRing)
	x := xRing
	if neg {
		x = r.Neg(xRing)
	}

	// ---- Step 2: range reduction to x_norm ∈ [1, 2).
	// Ring127 FP value v is stored as x = v · 2^fracBits. The MSB
	// position of x (as unsigned Uint128) is ⌊log₂(x)⌋. For x_norm ∈
	// [1, 2), we want ring_rep(x_norm) ∈ [2^fracBits, 2^(fracBits+1)),
	// i.e., MSB at position fracBits. Shift by s = fracBits - msb.
	msb := ring127HighestBit(x)
	s := int(r.FracBits) - msb
	var xNorm Uint128
	if s >= 0 {
		xNorm = x.Shl(uint(s)).ModPow127()
	} else {
		xNorm = x.Shr(uint(-s))
	}

	// ---- Step 3: initial guess y_0 = 1.5 - 0.5 · x_norm.
	// Linear interpolation through (1, 1) and (2, 0.5); max err ~0.083 at
	// x_norm = 1.5. Always positive on [1, 2] so NR never diverges.
	c1_5 := r.FromDouble(1.5)
	c0_5 := r.FromDouble(0.5)
	y := r.Sub(c1_5, r.TruncMulSigned(c0_5, xNorm))

	// ---- Step 4: Newton-Raphson iterations  y_{k+1} = y_k · (2 - x_norm·y_k).
	// Quadratic convergence: 5 iters bring error from 0.0588 to ~1e-40.
	// In Ring127 we are capped by ULP at fracBits=50 (~2^-50 ≈ 9e-16).
	two := r.FromDouble(2.0)
	for i := 0; i < 5; i++ {
		xy := r.TruncMulSigned(xNorm, y)
		twoMinusXy := r.Sub(two, xy)
		y = r.TruncMulSigned(y, twoMinusXy)
	}

	// ---- Step 5: denormalize  1/x = y · 2^s.
	// (1/x_norm) · 2^s = 1/(x_norm/2^s) = 1/x. The shift s applied to
	// x was to push x into [1, 2); the inverse shift applied to y
	// gives back 1/x.
	var result Uint128
	if s >= 0 {
		result = y.Shl(uint(s)).ModPow127()
	} else {
		result = y.Shr(uint(-s))
	}

	if neg {
		result = r.Neg(result)
	}
	return result
}

// ring127HighestBit returns the position of the highest set bit of the
// UNSIGNED Uint128 magnitude (0..126 for Ring127). For zero, returns -1.
// Uses bits.Len64 for speed — hot path during MPC recip.
func ring127HighestBit(a Uint128) int {
	if a.Hi != 0 {
		return 64 + bitsLen64(a.Hi) - 1
	}
	if a.Lo != 0 {
		return bitsLen64(a.Lo) - 1
	}
	return -1
}

// bitsLen64: number of bits needed to represent x (0..64). Match
// math/bits.Len64 without importing to avoid touching the hot-path
// dependency graph (keeps k2_ring127.go's bits import local).
func bitsLen64(x uint64) int {
	n := 0
	for x != 0 {
		x >>= 1
		n++
	}
	return n
}

// Ring127RecipNRSteps returns the number of NR iterations used by
// Ring127RecipPlaintext. Exposed for the MPC orchestration to size
// the Beaver round count.
const Ring127RecipNRSteps = 5
