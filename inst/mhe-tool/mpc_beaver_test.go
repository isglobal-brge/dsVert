package main

import (
	"math"
	"testing"
)

func TestBeaverMultiplication(t *testing.T) {
	fracBits := 20

	// Two secret values
	a_val := 3.5
	b_val := 2.0
	expected := a_val * b_val // 7.0

	// Split into additive shares
	a_fp := FromFloat64(a_val, fracBits)
	b_fp := FromFloat64(b_val, fracBits)
	a0, a1 := Split(a_fp)
	b0, b1 := Split(b_fp)

	// Generate Beaver triple (u, v, w = u*v)
	// In the real protocol, the CLIENT generates these
	u_val := 1.7
	v_val := -0.9
	_ = u_val * v_val

	u_fp := FromFloat64(u_val, fracBits)
	v_fp := FromFloat64(v_val, fracBits)
	w_fp := FPMulLocal(u_fp, v_fp, fracBits) // exact FP multiplication

	// Split triple into shares
	u0, u1 := Split(u_fp)
	v0, v1 := Split(v_fp)
	w0, w1 := Split(w_fp)

	// OPEN phase: both parties compute d, e
	d0 := FPSub(a0, u0)
	e0 := FPSub(b0, v0)
	d1 := FPSub(a1, u1)
	e1 := FPSub(b1, v1)

	// Exchange: both learn d = d0+d1, e = e0+e1
	d := FPAdd(d0, d1)
	e := FPAdd(e0, e1)

	// CLOSE phase: each party computes result share
	// c_i = w_i + e*u_i + d*v_i + [i==0]*d*e
	c0 := w0
	c0 = FPAdd(c0, FPMulLocal(e, u0, fracBits))
	c0 = FPAdd(c0, FPMulLocal(d, v0, fracBits))
	c0 = FPAdd(c0, FPMulLocal(d, e, fracBits)) // party 0 only

	c1 := w1
	c1 = FPAdd(c1, FPMulLocal(e, u1, fracBits))
	c1 = FPAdd(c1, FPMulLocal(d, v1, fracBits))
	// party 1: no d*e term

	// Reconstruct
	result := FPAdd(c0, c1)
	got := result.ToFloat64(fracBits)

	if math.Abs(got-expected) > 0.001 {
		t.Errorf("Beaver mult: got %.6f, want %.6f (error %.2e)", got, expected, math.Abs(got-expected))
	}
	t.Logf("Beaver mult: %.6f * %.6f = %.6f (error %.2e)", a_val, b_val, got, math.Abs(got-expected))
}

func TestBeaverPolynomialSigmoid(t *testing.T) {
	fracBits := 20
	degree := 21
	coeffs := SigmoidGlobalPoly(degree)

	// Test value
	eta := 1.5
	expected := sigmoid(eta) // 0.8175...

	eta_fp := FromFloat64(eta, fracBits)
	eta0, eta1 := Split(eta_fp)

	// Compute powers via Beaver multiplication
	// Power tree: x^2, then x^3=x^2*x, x^4=x^2*x^2, etc.
	powers0 := make([]FixedPoint, degree) // party 0's shares of x, x^2, ..., x^d
	powers1 := make([]FixedPoint, degree) // party 1's shares

	powers0[0] = eta0 // [x]_0
	powers1[0] = eta1 // [x]_1

	// Helper: Beaver multiply shares a0,a1 * b0,b1 → c0,c1
	beaverMul := func(a0, a1, b0, b1 FixedPoint) (FixedPoint, FixedPoint) {
		u_fp := FromFloat64(0.123, fracBits) // dummy triple
		v_fp := FromFloat64(-0.456, fracBits)
		w_fp := FPMulLocal(u_fp, v_fp, fracBits)
		u0, u1 := Split(u_fp)
		v0, v1 := Split(v_fp)
		w0, w1 := Split(w_fp)

		d0 := FPSub(a0, u0)
		e0 := FPSub(b0, v0)
		d1 := FPSub(a1, u1)
		e1 := FPSub(b1, v1)
		d := FPAdd(d0, d1)
		e := FPAdd(e0, e1)

		c0 := FPAdd(FPAdd(w0, FPMulLocal(e, u0, fracBits)),
			FPAdd(FPMulLocal(d, v0, fracBits), FPMulLocal(d, e, fracBits)))
		c1 := FPAdd(FPAdd(w1, FPMulLocal(e, u1, fracBits)),
			FPMulLocal(d, v1, fracBits))
		return c0, c1
	}

	// Build power tree
	for k := 1; k < degree; k++ {
		target := k + 1 // want x^(k+1)
		// Find a, b such that a+b = target and both < target
		var ai, bi int
		if target%2 == 0 {
			ai = target/2 - 1
			bi = target/2 - 1
		} else {
			ai = target - 2
			bi = 0
		}
		powers0[k], powers1[k] = beaverMul(powers0[ai], powers1[ai], powers0[bi], powers1[bi])
	}

	// Evaluate polynomial: p(x) = c0 + c1*[x] + c2*[x^2] + ...
	var result0, result1 FixedPoint
	c0FP := FromFloat64(coeffs[0], fracBits)
	result0 = c0FP // party 0 gets the constant
	for k := 1; k <= degree; k++ {
		ckFP := FromFloat64(coeffs[k], fracBits)
		result0 = FPAdd(result0, FPMulLocal(ckFP, powers0[k-1], fracBits))
		result1 = FPAdd(result1, FPMulLocal(ckFP, powers1[k-1], fracBits))
	}

	got := FPAdd(result0, result1).ToFloat64(fracBits)
	err := math.Abs(got - expected)

	// Allow for polynomial approx error + FP truncation
	polyErr := measurePolyError(sigmoid, coeffs, -8, 8, 0, 1, 100000)
	t.Logf("sigmoid(%.1f): got %.6f, exact %.6f, error %.2e (poly max err %.2e)",
		eta, got, expected, err, polyErr)

	if err > polyErr+0.01 {
		t.Errorf("Error %.2e exceeds polynomial error %.2e + tolerance", err, polyErr)
	}
}
