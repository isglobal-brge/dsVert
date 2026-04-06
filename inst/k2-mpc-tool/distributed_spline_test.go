package main

import (
	"math"
	"testing"
)

// TestDistributedSpline validates the distributed spline on [0, 1).
func TestDistributedSpline(t *testing.T) {
	rp := DefaultRingParams()
	sp := DefaultPiecewiseSigmoidParams()

	// Test points in [0, 1)
	testX := []float64{0.0, 0.05, 0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95}

	n := len(testX)
	xFP := rp.VecFromDoubles(testX)
	x0, x1 := rp.SplitVecShare(xFP)

	preproc := SplineDistPreprocessGen(rp, n)

	// Round 1
	p0R1 := SplineRound1(rp, 0, x0, preproc)
	p1R1 := SplineRound1(rp, 1, x1, preproc)

	// Round 2
	p0R2Msg, p0R2State := SplineRound2(rp, 0, x0, preproc, p0R1, p1R1)
	p1R2Msg, p1R2State := SplineRound2(rp, 1, x1, preproc, p1R1, p0R1)

	// Round 3
	res0 := SplineRound3(rp, 0, preproc, p0R2State, p0R2Msg, p1R2Msg)
	res1 := SplineRound3(rp, 1, preproc, p1R2State, p1R2Msg, p0R2Msg)

	maxErr := 0.0
	for i, x := range testX {
		got := rp.ToDouble(rp.ModAdd(res0[i], res1[i]))
		want := EvalPiecewiseSigmoid(x, sp) // reference piecewise sigmoid
		err := math.Abs(got - want)
		if err > maxErr {
			maxErr = err
		}
		t.Logf("x=%.2f: got=%.8f want=%.8f err=%.2e", x, got, want, err)
	}
	t.Logf("Max spline error: %.2e", maxErr)

	if maxErr > 1e-3 {
		t.Errorf("Max spline error %.2e exceeds 1e-3", maxErr)
	}
}
