package main

import (
	"crypto/rand"
	"encoding/binary"
)

// Split splits a fixed-point value into two additive shares.
// v = s0 + s1 (mod 2^64). s0 is uniformly random.
func Split(v FixedPoint) (s0, s1 FixedPoint) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	s0 = FixedPoint(binary.LittleEndian.Uint64(buf[:]))
	s1 = v - s0 // wrapping subtraction mod 2^64
	return
}

// Reconstruct reconstructs a value from two additive shares.
func Reconstruct(s0, s1 FixedPoint) FixedPoint {
	return s0 + s1 // wrapping addition mod 2^64
}

// SplitVec splits a vector of fixed-point values into two share vectors.
func SplitVec(v []FixedPoint) (s0, s1 []FixedPoint) {
	n := len(v)
	s0 = make([]FixedPoint, n)
	s1 = make([]FixedPoint, n)
	// Generate all random bytes at once for efficiency
	buf := make([]byte, n*8)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	for i := 0; i < n; i++ {
		s0[i] = FixedPoint(binary.LittleEndian.Uint64(buf[i*8 : (i+1)*8]))
		s1[i] = v[i] - s0[i]
	}
	return
}

// ReconstructVec reconstructs a vector from two share vectors.
func ReconstructVec(s0, s1 []FixedPoint) []FixedPoint {
	n := len(s0)
	v := make([]FixedPoint, n)
	for i := 0; i < n; i++ {
		v[i] = s0[i] + s1[i]
	}
	return v
}

// ShareVecAdd adds two share vectors element-wise (local operation).
func ShareVecAdd(a, b []FixedPoint) []FixedPoint {
	return FPVecAdd(a, b)
}

// ShareVecSub subtracts two share vectors element-wise (local operation).
func ShareVecSub(a, b []FixedPoint) []FixedPoint {
	return FPVecSub(a, b)
}

// PlaintextTimesShareVec multiplies a plaintext vector by a shared vector.
// result_share[i] = plaintext[i] * share[i], with fixed-point truncation.
// This is a LOCAL operation — no Beaver triples needed because one operand
// is plaintext (known to this party).
func PlaintextTimesShareVec(plaintext, share []FixedPoint, fracBits int) []FixedPoint {
	n := len(plaintext)
	result := make([]FixedPoint, n)
	for i := 0; i < n; i++ {
		result[i] = FPMulLocal(plaintext[i], share[i], fracBits)
	}
	return result
}

// PlaintextMatTVecMul computes X^T * v where X is plaintext (n x p) and v is
// a share vector (length n). Returns a share vector of length p.
// This is the gradient computation: g_k = X_k^T * residual.
// No Beaver triples needed because X is plaintext.
func PlaintextMatTVecMul(X [][]FixedPoint, v []FixedPoint, fracBits int) []FixedPoint {
	n := len(X)
	if n == 0 {
		return nil
	}
	p := len(X[0])
	result := make([]FixedPoint, p)
	for j := 0; j < p; j++ {
		var sum FixedPoint
		for i := 0; i < n; i++ {
			sum = FPAdd(sum, FPMulLocal(X[i][j], v[i], fracBits))
		}
		result[j] = sum
	}
	return result
}

// PlaintextMatVecMul computes X * beta where X is plaintext (n x p) and beta
// is a plaintext vector (length p). Returns a vector of length n.
// Used for computing eta_k = X_k * beta_k locally.
func PlaintextMatVecMul(X [][]FixedPoint, beta []FixedPoint, fracBits int) []FixedPoint {
	n := len(X)
	if n == 0 {
		return nil
	}
	p := len(X[0])
	result := make([]FixedPoint, n)
	for i := 0; i < n; i++ {
		var sum FixedPoint
		for j := 0; j < p; j++ {
			sum = FPAdd(sum, FPMulLocal(X[i][j], beta[j], fracBits))
		}
		result[i] = sum
	}
	return result
}
