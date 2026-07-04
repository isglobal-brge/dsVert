package main

import (
	"math"
	"testing"
)

// TestSigmoid127Accuracy verifies the plaintext Ring127 Chebyshev sigmoid
// matches math sigmoid to < 1e-5 abs over eta in [-8, 8] — the accuracy the
// GLM logistic link needs (the shipped exp+recip overkill is 3.45e-14).
func TestSigmoid127Accuracy(t *testing.T) {
	r := NewRing127(50)
	maxAbs := 0.0
	var worst float64
	for x := -8.0; x <= 8.0+1e-9; x += 0.01 {
		want := 1.0 / (1.0 + math.Exp(-x))
		got := r.ToDouble(Ring127SigmoidPlaintext(r, r.FromDouble(x)))
		d := math.Abs(got - want)
		if d > maxAbs {
			maxAbs = d
			worst = x
		}
	}
	t.Logf("sigmoid127 max abs = %.3e at eta = %.3f (degree %d)", maxAbs, worst, Ring127SigmoidDegree)
	if maxAbs > 1e-5 {
		t.Fatalf("sigmoid127 max abs %.3e exceeds 1e-5 target", maxAbs)
	}
}

// TestSigmoid127OddSymmetry: sigmoid(x)-0.5 is odd, so even-index Chebyshev
// coeffs must be ~0 (catches an accidental extra +0.5 affine / wrong parity).
func TestSigmoid127OddSymmetry(t *testing.T) {
	// c_0 carries the +0.5 baseline.
	if math.Abs(ring127SigmoidCoeffs[0]-0.5) > 1e-6 {
		t.Fatalf("c_0 = %.9f, expected ~0.5 (sigmoid baseline)", ring127SigmoidCoeffs[0])
	}
	for k := 2; k <= Ring127SigmoidDegree; k += 2 {
		if math.Abs(ring127SigmoidCoeffs[k]) > 1e-9 {
			t.Fatalf("even coeff c_%d = %.3e, expected ~0 (sigmoid-0.5 is odd)", k, ring127SigmoidCoeffs[k])
		}
	}
}
