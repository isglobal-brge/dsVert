// k2_secure_exp.go: Ring63 fixed-point arithmetic for 2-party MPC.
//
// Uses uint64 with EXPLICIT modulus (2^63) to match the Google C++ exactly.
// The C++ uses num_ring_bits=63, so modulus = 2^63 = 9223372036854775808.
// All arithmetic is done with explicit % modulus, not int64 wrapping.

package main

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
)

// Ring63 holds parameters for the 2^63 ring used by the C++ code.
type Ring63 struct {
	Modulus      uint64 // 2^63
	FracMul      uint64 // 2^fracBits
	IntRingMod   uint64 // 2^(63-fracBits)
	FracBits     int
	SignThreshold uint64 // modulus / 2
}

func NewRing63(fracBits int) Ring63 {
	mod := uint64(1) << 63
	return Ring63{
		Modulus:      mod,
		FracMul:      uint64(1) << fracBits,
		IntRingMod:   uint64(1) << (63 - fracBits),
		FracBits:     fracBits,
		SignThreshold: mod >> 1,
	}
}

// Ring63 arithmetic — ALL explicit % modulus, matching C++ exactly.
func (r Ring63) Add(a, b uint64) uint64  { return (a + b) % r.Modulus }
func (r Ring63) Sub(a, b uint64) uint64  { return (r.Modulus + a - b) % r.Modulus }
func (r Ring63) Neg(a uint64) uint64     { return (r.Modulus - a) % r.Modulus }
func (r Ring63) IsNeg(a uint64) bool     { return a >= r.SignThreshold }

func (r Ring63) FromDouble(x float64) uint64 {
	if x >= 0 {
		return uint64(x*float64(r.FracMul)+0.5) % r.Modulus
	}
	abs := uint64(-x*float64(r.FracMul) + 0.5)
	return r.Neg(abs % r.Modulus)
}

func (r Ring63) ToDouble(a uint64) float64 {
	a = a % r.Modulus
	if r.IsNeg(a) {
		return -float64(r.Neg(a)) / float64(r.FracMul)
	}
	return float64(a) / float64(r.FracMul)
}

// TruncMul: (a * b) >> fracBits, mod modulus.
// Matches C++ FixedPointElement::TruncMul.
func (r Ring63) TruncMul(a, b uint64) uint64 {
	// 128-bit multiply
	aBig := new(big.Int).SetUint64(a)
	bBig := new(big.Int).SetUint64(b)
	product := new(big.Int).Mul(aBig, bBig)
	// Right shift by fracBits
	product.Rsh(product, uint(r.FracBits))
	// Mod modulus
	product.Mod(product, new(big.Int).SetUint64(r.Modulus))
	return product.Uint64()
}

// TruncMulSigned: sign-aware truncated multiply (C++ TruncMulFP).
func (r Ring63) TruncMulSigned(a, b uint64) uint64 {
	aNeg := r.IsNeg(a)
	bNeg := r.IsNeg(b)
	aa, bb := a, b
	if aNeg { aa = r.Neg(a) }
	if bNeg { bb = r.Neg(b) }
	result := r.TruncMul(aa, bb)
	if aNeg != bNeg { result = r.Neg(result) }
	return result
}

func (r Ring63) SplitShare(value uint64) (s0, s1 uint64) {
	s0 = cryptoRandUint64K2() % r.Modulus
	s1 = r.Sub(value, s0)
	return
}

// cryptoRandUint64K2 generates a cryptographically random uint64.
func cryptoRandUint64K2() uint64 {
	var buf [8]byte
	rand.Read(buf[:])
	return binary.LittleEndian.Uint64(buf[:])
}

// modMulBig63 computes (a * b) mod m using big.Int to avoid overflow.
func modMulBig63(a, b, m uint64) uint64 {
	return new(big.Int).Mod(
		new(big.Int).Mul(new(big.Int).SetUint64(a), new(big.Int).SetUint64(b)),
		new(big.Int).SetUint64(m),
	).Uint64()
}
