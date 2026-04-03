package main

import (
	"math"
	"testing"
)

func TestSigmoidPiecewiseAccuracy(t *testing.T) {
	intervals := SigmoidIntervals()
	maxErr := 0.0

	for i := 0; i < 10000; i++ {
		x := -8.0 + 16.0*float64(i)/9999.0
		approx := EvalPiecewise(x, intervals, 0.0, 1.0)
		exact := sigmoid(x)
		err := math.Abs(approx - exact)
		if err > maxErr {
			maxErr = err
		}
	}

	t.Logf("Sigmoid piecewise max error: %.6e", maxErr)
	if maxErr > 1e-3 {
		t.Errorf("Sigmoid max error too high: %.6e (want < 1e-3)", maxErr)
	}
}

func TestExpPiecewiseAccuracy(t *testing.T) {
	intervals := ExpIntervals()
	maxErr := 0.0

	for i := 0; i < 10000; i++ {
		x := -3.0 + 6.0*float64(i)/9999.0
		approx := EvalPiecewise(x, intervals, math.Exp(-3.0), math.Exp(3.0))
		exact := math.Exp(x)
		err := math.Abs(approx - exact)
		if err > maxErr {
			maxErr = err
		}
	}

	t.Logf("Exp piecewise max error: %.6e", maxErr)
	if maxErr > 1e-3 {
		t.Errorf("Exp max error too high: %.6e (want < 1e-3)", maxErr)
	}
}

func TestSigmoidPiecewiseBoundary(t *testing.T) {
	// Test clamping outside range
	if got := EvalSigmoidPiecewise(-100.0); got != 0.0 {
		t.Errorf("sigmoid(-100) = %f, want 0", got)
	}
	if got := EvalSigmoidPiecewise(100.0); got != 1.0 {
		t.Errorf("sigmoid(100) = %f, want 1", got)
	}

	// Test at boundaries
	got0 := EvalSigmoidPiecewise(0.0)
	if math.Abs(got0-0.5) > 0.001 {
		t.Errorf("sigmoid(0) = %f, want ~0.5", got0)
	}
}

func TestExpPiecewiseBoundary(t *testing.T) {
	got0 := EvalExpPiecewise(0.0)
	if math.Abs(got0-1.0) > 0.001 {
		t.Errorf("exp(0) = %f, want 1.0", got0)
	}

	got1 := EvalExpPiecewise(1.0)
	if math.Abs(got1-math.E) > 0.01 {
		t.Errorf("exp(1) = %f, want %f", got1, math.E)
	}
}
