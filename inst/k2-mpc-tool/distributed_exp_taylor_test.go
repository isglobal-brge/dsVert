package main

import (
	"math"
	"testing"
)

func TestExpTaylorSigmoidLocal(t *testing.T) {
	rp := DefaultRingParams()

	// Test sigmoid for x in [1, 13] (the I1 interval)
	testX := []float64{1.0, 1.5, 2.0, 3.0, 5.0, 10.0}

	xFP := rp.VecFromDoubles(testX)
	x0, x1 := rp.SplitVecShare(xFP)

	sig0, sig1 := ExpTaylorSigmoidLocal(rp, x0, x1)

	maxErr := 0.0
	for i, x := range testX {
		got := rp.ToDouble(rp.ModAdd(sig0[i], sig1[i]))
		want := 1.0 / (1.0 + math.Exp(-x))
		err := math.Abs(got - want)
		if err > maxErr {
			maxErr = err
		}
		t.Logf("sigmoid(%.1f): got=%.8f want=%.8f err=%.2e", x, got, want, err)
	}
	t.Logf("Max error: %.2e", maxErr)

	if maxErr > 1e-3 {
		t.Errorf("Max error %.2e exceeds 1e-3", maxErr)
	}
}

func TestExpTaylorSigmoidNegLocal(t *testing.T) {
	rp := DefaultRingParams()

	// Test sigmoid for x in [-13, -1] (the I4 interval)
	testX := []float64{-1.0, -1.5, -2.0, -3.0, -5.0, -10.0}

	xFP := rp.VecFromDoubles(testX)
	x0, x1 := rp.SplitVecShare(xFP)

	sig0, sig1 := ExpTaylorSigmoidNegLocal(rp, x0, x1)

	maxErr := 0.0
	for i, x := range testX {
		got := rp.ToDouble(rp.ModAdd(sig0[i], sig1[i]))
		want := 1.0 / (1.0 + math.Exp(-x))
		err := math.Abs(got - want)
		if err > maxErr {
			maxErr = err
		}
		t.Logf("sigmoid(%.1f): got=%.8f want=%.8f err=%.2e", x, got, want, err)
	}
	t.Logf("Max error: %.2e", maxErr)

	if maxErr > 1e-3 {
		t.Errorf("Max error %.2e exceeds 1e-3", maxErr)
	}
}
