package main

import (
	"math"
	"testing"
)

func TestKelkarExpLocal(t *testing.T) {
	rp := DefaultRingParams()

	testX := []float64{-5, -3, -2, -1, -0.5, 0, 0.5, 1, 2, 3, 5}

	xFP := rp.VecFromDoubles(testX)
	x0, x1 := rp.SplitVecShare(xFP)

	exp0, exp1 := KelkarExpLocal(rp, x0, x1)

	maxErr := 0.0
	for i, x := range testX {
		got := rp.ToDouble(rp.ModAdd(exp0[i], exp1[i]))
		want := math.Exp(x)
		err := math.Abs(got - want)
		relErr := err / math.Max(1e-10, math.Abs(want))
		if err > maxErr {
			maxErr = err
		}
		t.Logf("exp(%.1f): got=%.6f want=%.6f err=%.2e relErr=%.2e", x, got, want, err, relErr)
	}
	t.Logf("Max absolute error: %.2e", maxErr)

	if maxErr > 0.1 {
		t.Errorf("Max error %.2e exceeds 0.1", maxErr)
	}
}

// TestKelkarNegExpForSigmoid tests exp(-x) for positive x (needed for sigmoid I1/I4).
func TestKelkarNegExpForSigmoid(t *testing.T) {
	rp := DefaultRingParams()

	// For sigmoid I1 (x in [1, L)), we need exp(-x)
	testX := []float64{1, 1.5, 2, 3, 5, 10}
	n := len(testX)

	// Negate: compute exp(-x) by providing shares of -x
	negX := make([]float64, n)
	for i, x := range testX {
		negX[i] = -x
	}

	xFP := rp.VecFromDoubles(negX)
	x0, x1 := rp.SplitVecShare(xFP)

	exp0, exp1 := KelkarExpLocal(rp, x0, x1)

	maxErr := 0.0
	for i, x := range testX {
		got := rp.ToDouble(rp.ModAdd(exp0[i], exp1[i]))
		want := math.Exp(-x) // should be small positive
		err := math.Abs(got - want)
		if err > maxErr {
			maxErr = err
		}
		t.Logf("exp(-%.1f): got=%.8f want=%.8f err=%.2e", x, got, want, err)
	}
	t.Logf("Max error exp(-x): %.2e", maxErr)
}
