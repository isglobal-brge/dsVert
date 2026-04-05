// ring.go: Fixed-point ring arithmetic for 2-party MPC.
//
// Ported from Google fss_machine_learning (Agarwal et al. / Kelkar et al.).
// All values are uint64 in Z_{2^numRingBits} with numFractionalBits
// fractional bits. Multiplication uses 128-bit intermediary.
//
// Reference: poisson_regression/fixed_point_element.h, ring_arithmetic_utils.h

package main

import (
	"math/bits"
)

// RingParams defines the fixed-point ring parameters.
type RingParams struct {
	NumRingBits       int    // Total ring bits (max 63 for signed interpretation)
	NumFractionalBits int    // Fractional bits
	Modulus           uint64 // 2^NumRingBits
	FracMultiplier    uint64 // 2^NumFractionalBits
	IntModulus        uint64 // 2^(NumRingBits - NumFractionalBits)
	SignThreshold     uint64 // Modulus / 2 — values >= this are negative
}

// NewRingParams creates ring parameters for the given bit widths.
func NewRingParams(ringBits, fracBits int) RingParams {
	if ringBits > 63 {
		ringBits = 63
	}
	mod := uint64(1) << ringBits
	return RingParams{
		NumRingBits:       ringBits,
		NumFractionalBits: fracBits,
		Modulus:           mod,
		FracMultiplier:    uint64(1) << fracBits,
		IntModulus:        uint64(1) << (ringBits - fracBits),
		SignThreshold:     mod >> 1,
	}
}

// DefaultRingParams returns the standard 63-bit ring with 20 fractional bits.
func DefaultRingParams() RingParams {
	return NewRingParams(63, 20)
}

// --- Ring element operations ---

// ModAdd computes (a + b) mod modulus.
func (rp RingParams) ModAdd(a, b uint64) uint64 {
	return (a + b) % rp.Modulus
}

// ModSub computes (a - b) mod modulus.
func (rp RingParams) ModSub(a, b uint64) uint64 {
	if a >= b {
		return (a - b) % rp.Modulus
	}
	return rp.Modulus - ((b - a) % rp.Modulus)
}

// ModNeg computes (-a) mod modulus.
func (rp RingParams) ModNeg(a uint64) uint64 {
	if a == 0 {
		return 0
	}
	return rp.Modulus - (a % rp.Modulus)
}

// IsNegative returns true if the ring element represents a negative number
// (i.e., value >= modulus/2).
func (rp RingParams) IsNegative(a uint64) bool {
	return a >= rp.SignThreshold
}

// mul128 multiplies two uint64 values and returns (hi, lo).
func mul128(a, b uint64) (uint64, uint64) {
	return bits.Mul64(a, b)
}

// ModMul computes (a * b) mod modulus using 128-bit intermediate.
func (rp RingParams) ModMul(a, b uint64) uint64 {
	hi, lo := mul128(a, b)
	// (hi*2^64 + lo) mod modulus
	// Since modulus = 2^k, this is just lo & (modulus - 1) when k <= 64
	// But we need (hi << 64 | lo) % modulus with proper 128-bit mod
	if rp.NumRingBits <= 64 {
		// modulus is a power of 2 <= 2^63
		// (hi * 2^64 + lo) mod 2^k = lo mod 2^k (if k <= 64 and hi*2^64 is 0 mod 2^k when k <= 64)
		// Actually: 2^64 mod 2^k = 0 when k <= 64, so hi*2^64 mod 2^k = 0
		_ = hi
		return lo % rp.Modulus
	}
	// Should not reach here since NumRingBits <= 63
	return lo % rp.Modulus
}

// TruncMul computes the truncated fixed-point multiplication:
// (a * b) >> NumFractionalBits, mod Modulus.
// This is the core operation for fixed-point arithmetic on raw ring values.
func (rp RingParams) TruncMul(a, b uint64) uint64 {
	hi, lo := mul128(a, b)
	// Right-shift the 128-bit result by NumFractionalBits
	shift := uint(rp.NumFractionalBits)
	result := (lo >> shift) | (hi << (64 - shift))
	return result % rp.Modulus
}

// TruncMulFP computes sign-aware fixed-point multiplication.
// Handles negative values by converting to absolute value, multiplying,
// then re-negating if needed.
func (rp RingParams) TruncMulFP(a, b uint64) uint64 {
	aNeg := rp.IsNegative(a)
	bNeg := rp.IsNegative(b)

	aa := a
	bb := b
	if aNeg {
		aa = rp.ModNeg(a)
	}
	if bNeg {
		bb = rp.ModNeg(b)
	}

	result := rp.TruncMul(aa, bb)

	if aNeg != bNeg {
		result = rp.ModNeg(result)
	}
	return result
}

// FromDouble converts a float64 to a fixed-point ring element.
func (rp RingParams) FromDouble(x float64) uint64 {
	if x >= 0 {
		return uint64(x*float64(rp.FracMultiplier)+0.5) % rp.Modulus
	}
	abs := uint64(-x*float64(rp.FracMultiplier) + 0.5)
	return rp.ModNeg(abs % rp.Modulus)
}

// ToDouble converts a fixed-point ring element back to float64.
func (rp RingParams) ToDouble(a uint64) float64 {
	a = a % rp.Modulus
	if rp.IsNegative(a) {
		neg := rp.ModNeg(a)
		return -float64(neg) / float64(rp.FracMultiplier)
	}
	return float64(a) / float64(rp.FracMultiplier)
}

// --- Vector operations ---

// VecAdd computes element-wise (a + b) mod modulus.
func (rp RingParams) VecAdd(a, b []uint64) []uint64 {
	n := len(a)
	out := make([]uint64, n)
	for i := 0; i < n; i++ {
		out[i] = rp.ModAdd(a[i], b[i])
	}
	return out
}

// VecSub computes element-wise (a - b) mod modulus.
func (rp RingParams) VecSub(a, b []uint64) []uint64 {
	n := len(a)
	out := make([]uint64, n)
	for i := 0; i < n; i++ {
		out[i] = rp.ModSub(a[i], b[i])
	}
	return out
}

// VecScale computes element-wise (scalar * a[i]) mod modulus.
func (rp RingParams) VecScale(scalar uint64, a []uint64) []uint64 {
	n := len(a)
	out := make([]uint64, n)
	for i := 0; i < n; i++ {
		out[i] = rp.ModMul(scalar, a[i])
	}
	return out
}

// VecHadamard computes element-wise truncated fixed-point multiplication.
func (rp RingParams) VecHadamard(a, b []uint64) []uint64 {
	n := len(a)
	out := make([]uint64, n)
	for i := 0; i < n; i++ {
		out[i] = rp.TruncMulFP(a[i], b[i])
	}
	return out
}

// VecDot computes the fixed-point dot product: sum(a[i] * b[i]) / 2^fracBits.
func (rp RingParams) VecDot(a, b []uint64) uint64 {
	var sum uint64
	for i := 0; i < len(a); i++ {
		sum = rp.ModAdd(sum, rp.TruncMulFP(a[i], b[i]))
	}
	return sum
}

// VecFromDoubles converts a float64 slice to fixed-point ring elements.
func (rp RingParams) VecFromDoubles(xs []float64) []uint64 {
	out := make([]uint64, len(xs))
	for i, x := range xs {
		out[i] = rp.FromDouble(x)
	}
	return out
}

// VecToDoubles converts fixed-point ring elements back to float64.
func (rp RingParams) VecToDoubles(vs []uint64) []float64 {
	out := make([]float64, len(vs))
	for i, v := range vs {
		out[i] = rp.ToDouble(v)
	}
	return out
}

// MatVecMul computes matrix-vector product: result[i] = sum_j(M[i][j] * v[j]).
// M is row-major: M[i*cols + j].
func (rp RingParams) MatVecMul(M []uint64, rows, cols int, v []uint64) []uint64 {
	out := make([]uint64, rows)
	for i := 0; i < rows; i++ {
		var sum uint64
		for j := 0; j < cols; j++ {
			sum = rp.ModAdd(sum, rp.TruncMulFP(M[i*cols+j], v[j]))
		}
		out[i] = sum
	}
	return out
}

// ScalarShareMulP0 multiplies a public signed fixed-point scalar by party 0's share.
// Returns party 0's share of the TRUNCATED product.
// Uses asymmetric truncation to ensure correctness when shares are reconstructed.
//
// Matches C++ ScalarVectorProductPartyZero:
//   result = floor(a * share / 2^lf) mod modulus
// For negative a: result = modulus - floor(|a| * share / 2^lf) mod modulus
func (rp RingParams) ScalarShareMulP0(scalar, share uint64) uint64 {
	product := rp.ModMul(scalar, share) // ring multiply (no truncation)
	return rp.TruncateShareP0(product)
}

// ScalarShareMulP1 multiplies a public signed fixed-point scalar by party 1's share.
// Uses asymmetric truncation matching C++ ScalarVectorProductPartyOne.
func (rp RingParams) ScalarShareMulP1(scalar, share uint64) uint64 {
	product := rp.ModMul(scalar, share) // ring multiply (no truncation)
	return rp.TruncateShareP1(product)
}

// MatTransVecMul computes M^T * v: result[j] = sum_i(M[i][j] * v[i]).
func (rp RingParams) MatTransVecMul(M []uint64, rows, cols int, v []uint64) []uint64 {
	out := make([]uint64, cols)
	for j := 0; j < cols; j++ {
		var sum uint64
		for i := 0; i < rows; i++ {
			sum = rp.ModAdd(sum, rp.TruncMulFP(M[i*cols+j], v[i]))
		}
		out[j] = sum
	}
	return out
}

// --- Share splitting ---

// SplitShare splits a value into two additive shares: share0 + share1 = value mod modulus.
// Uses crypto/rand for the random share.
func (rp RingParams) SplitShare(value uint64) (share0, share1 uint64) {
	share0 = cryptoRandUint64() % rp.Modulus
	share1 = rp.ModSub(value, share0)
	return
}

// SplitVecShare splits a vector into two additive share vectors.
func (rp RingParams) SplitVecShare(values []uint64) (shares0, shares1 []uint64) {
	n := len(values)
	shares0 = make([]uint64, n)
	shares1 = make([]uint64, n)
	for i, v := range values {
		shares0[i], shares1[i] = rp.SplitShare(v)
	}
	return
}

// ReconstructShare reconstructs a value from two additive shares.
func (rp RingParams) ReconstructShare(share0, share1 uint64) uint64 {
	return rp.ModAdd(share0, share1)
}

// ReconstructVecShare reconstructs a vector from two additive share vectors.
func (rp RingParams) ReconstructVecShare(shares0, shares1 []uint64) []uint64 {
	n := len(shares0)
	out := make([]uint64, n)
	for i := 0; i < n; i++ {
		out[i] = rp.ModAdd(shares0[i], shares1[i])
	}
	return out
}
