package main

import "math"

// FixedPoint represents a fixed-point number on Z_{2^64} with configurable
// fractional bits. Arithmetic wraps naturally via int64 overflow, which is
// correct for additive secret sharing (shares reconstruct mod 2^64).
type FixedPoint int64

// FromFloat64 converts a float64 to fixed-point with the given fractional bits.
func FromFloat64(v float64, fracBits int) FixedPoint {
	return FixedPoint(math.Round(v * float64(int64(1)<<fracBits)))
}

// ToFloat64 converts a fixed-point value back to float64.
func (f FixedPoint) ToFloat64(fracBits int) float64 {
	return float64(f) / float64(int64(1)<<fracBits)
}

// FPAdd returns a + b (wrapping mod 2^64).
func FPAdd(a, b FixedPoint) FixedPoint {
	return a + b
}

// FPSub returns a - b (wrapping mod 2^64).
func FPSub(a, b FixedPoint) FixedPoint {
	return a - b
}

// FPNeg returns -a (wrapping mod 2^64).
func FPNeg(a FixedPoint) FixedPoint {
	return -a
}

// FPMulLocal multiplies two fixed-point values locally and truncates.
// This is for LOCAL multiplication only (both values known to one party).
// For multiplication of secret-shared values, use Beaver triples.
//
// The result is (a * b) >> fracBits, which corrects the doubled scale factor.
func FPMulLocal(a, b FixedPoint, fracBits int) FixedPoint {
	// Use 128-bit multiplication to avoid overflow
	hi, lo := mul64(int64(a), int64(b))
	return FixedPoint(rshift128(hi, lo, fracBits))
}

// FPFromInt converts an integer to fixed-point.
func FPFromInt(n int64, fracBits int) FixedPoint {
	return FixedPoint(n << fracBits)
}

// mul64 performs 64x64 -> 128-bit signed multiplication.
// Returns (hi, lo) where result = hi * 2^64 + lo.
func mul64(a, b int64) (int64, uint64) {
	// Compute unsigned multiplication
	ua, ub := uint64(a), uint64(b)
	hi, lo := mulUnsigned64(ua, ub)

	// Adjust for signed: if a < 0, subtract b from hi; if b < 0, subtract a
	if a < 0 {
		hi -= ub
	}
	if b < 0 {
		hi -= ua
	}

	return int64(hi), lo
}

// mulUnsigned64 performs 64x64 -> 128-bit unsigned multiplication.
func mulUnsigned64(a, b uint64) (uint64, uint64) {
	aHi := a >> 32
	aLo := a & 0xFFFFFFFF
	bHi := b >> 32
	bLo := b & 0xFFFFFFFF

	mid1 := aHi * bLo
	mid2 := aLo * bHi

	lo := aLo * bLo
	hi := aHi * bHi

	mid := mid1 + mid2
	if mid < mid1 {
		hi += 1 << 32 // carry
	}

	loNew := lo + (mid << 32)
	if loNew < lo {
		hi++
	}

	hi += mid >> 32

	return hi, loNew
}

// rshift128 performs arithmetic right shift on a 128-bit signed value (hi:lo).
func rshift128(hi int64, lo uint64, shift int) int64 {
	if shift == 0 {
		return int64(lo)
	}
	if shift >= 64 {
		return hi >> (shift - 64)
	}
	return (hi << (64 - shift)) | int64(lo>>shift)
}

// FloatVecToFP converts a slice of float64 to fixed-point.
func FloatVecToFP(v []float64, fracBits int) []FixedPoint {
	fp := make([]FixedPoint, len(v))
	for i, x := range v {
		fp[i] = FromFloat64(x, fracBits)
	}
	return fp
}

// FPVecToFloat converts a slice of fixed-point to float64.
func FPVecToFloat(v []FixedPoint, fracBits int) []float64 {
	f := make([]float64, len(v))
	for i, x := range v {
		f[i] = x.ToFloat64(fracBits)
	}
	return f
}

// FPVecAdd adds two fixed-point vectors element-wise.
func FPVecAdd(a, b []FixedPoint) []FixedPoint {
	n := len(a)
	result := make([]FixedPoint, n)
	for i := 0; i < n; i++ {
		result[i] = FPAdd(a[i], b[i])
	}
	return result
}

// FPVecSub subtracts two fixed-point vectors element-wise.
func FPVecSub(a, b []FixedPoint) []FixedPoint {
	n := len(a)
	result := make([]FixedPoint, n)
	for i := 0; i < n; i++ {
		result[i] = FPSub(a[i], b[i])
	}
	return result
}

// FPDotProduct computes the dot product of two fixed-point vectors.
// Each element multiplication is truncated by fracBits.
func FPDotProduct(a, b []FixedPoint, fracBits int) FixedPoint {
	var sum FixedPoint
	for i := range a {
		sum = FPAdd(sum, FPMulLocal(a[i], b[i], fracBits))
	}
	return sum
}

// ============================================================================
// FP <-> Ring63 conversions
//
// FixedPoint is int64 (wrapping at 2^64).
// Ring63 is uint64 with explicit modulus 2^63.
// Conversion: interpret the int64 bit pattern as uint64, then reduce mod 2^63.
// ============================================================================

// fpToRing63 converts a FixedPoint (int64) vector to Ring63 (uint64 mod 2^63).
func fpToRing63(fp []FixedPoint) []uint64 {
	mod := uint64(1) << 63
	result := make([]uint64, len(fp))
	for i, v := range fp {
		result[i] = uint64(v) % mod
	}
	return result
}

// ring63ToFP converts Ring63 (uint64 mod 2^63) values back to FixedPoint (int64).
// Values >= modulus/2 are interpreted as negative.
func ring63ToFP(r63 []uint64) []FixedPoint {
	mod := uint64(1) << 63
	half := mod >> 1 // 2^62
	result := make([]FixedPoint, len(r63))
	for i, v := range r63 {
		v = v % mod
		if v >= half {
			result[i] = FixedPoint(int64(v) - int64(mod))
		} else {
			result[i] = FixedPoint(int64(v))
		}
	}
	return result
}
