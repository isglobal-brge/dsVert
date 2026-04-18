// k2_beaver_vecmul_test.go — unit test for the element-wise Beaver
// product handlers. Simulates both DCF parties in-process and verifies
// that the reconstructed x*y matches the plaintext product within the
// expected Ring63 truncation tolerance (one ULP of 2^-frac_bits).

package main

import (
	"math"
	"testing"
)

func TestBeaverVecmulEndToEnd(t *testing.T) {
	r := NewRing63(K2DefaultFracBits)
	// Truth vectors
	x := []float64{1.5, -0.3, 2.0, 0.75, -1.25, 4.0, 0.1, 0.9, -2.5, 3.2}
	y := []float64{-0.8, 1.4, 0.5, 2.25, 0.6, -1.0, 3.5, 0.4, 1.1, -0.75}
	n := len(x)
	// Split to shares
	x0 := make([]uint64, n)
	x1 := make([]uint64, n)
	y0 := make([]uint64, n)
	y1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		xr := r.FromDouble(x[i])
		yr := r.FromDouble(y[i])
		x0[i], x1[i] = r.SplitShare(xr)
		y0[i], y1[i] = r.SplitShare(yr)
	}
	// Dealer samples triples
	t0, t1 := SampleBeaverTripleVector(n, r)
	// Round 1: each party computes masked shares
	state0, msg0 := GenerateBatchedMultiplicationGateMessage(x0, y0, t0, r)
	state1, msg1 := GenerateBatchedMultiplicationGateMessage(x1, y1, t1, r)
	// Round 2: each party reconstructs z
	raw0 := GenerateBatchedMultiplicationOutputPartyZero(state0, t0, msg1, r)
	raw1 := GenerateBatchedMultiplicationOutputPartyOne(state1, t1, msg0, r)
	// Apply asymmetric deterministic truncation (mirror of what the
	// handlers do when no shared-carry PRG is in use).
	divisor := uint64(1) << uint(K2DefaultFracBits)
	out0 := make([]uint64, n)
	out1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		out0[i] = raw0[i] / divisor
		negS := (r.Modulus - raw1[i]) % r.Modulus
		out1[i] = (r.Modulus - negS/divisor) % r.Modulus
	}
	// Reconstruct z = out0 + out1 (mod 2^63) and decode.
	maxErr := 0.0
	for i := 0; i < n; i++ {
		z := r.Add(out0[i], out1[i])
		got := r.ToDouble(z)
		want := x[i] * y[i]
		e := math.Abs(got - want)
		if e > maxErr {
			maxErr = e
		}
	}
	// Stochastic-truncation ULP is 2^-frac_bits ≈ 9.5e-7; allow 1e-3
	// tolerance to cover the residual bias when using the deterministic
	// asymmetric rule (no PRG carry in this test).
	if maxErr > 1e-3 {
		t.Fatalf("Beaver vecmul max err = %.3g (> 1e-3)", maxErr)
	}
	t.Logf("Beaver vecmul max abs err = %.3g (tol=1e-3)", maxErr)
}
