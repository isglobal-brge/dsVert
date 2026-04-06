package main

import (
	"testing"
)

func TestBranchValuesForMixedVector(t *testing.T) {
	rp := DefaultRingParams()
	testX := []float64{0.5, -0.5, 2.0, -2.0, 15.0}

	xFP := rp.VecFromDoubles(testX)
	x0, x1 := rp.SplitVecShare(xFP)

	// I1 branch: exp(-x) + Taylor
	i1_0, i1_1 := ExpTaylorSigmoidLocal(rp, x0, x1)
	t.Log("I1 branch (exp+Taylor for positive x):")
	for i, x := range testX {
		val := rp.ToDouble(rp.ModAdd(i1_0[i], i1_1[i]))
		t.Logf("  x=%5.1f: %.6f", x, val)
	}

	// I4 branch: 1 - exp(x) + Taylor (for negative x)
	i4_0, i4_1 := ExpTaylorSigmoidNegLocal(rp, x0, x1)
	t.Log("I4 branch (1 - exp+Taylor for negative x):")
	for i, x := range testX {
		val := rp.ToDouble(rp.ModAdd(i4_0[i], i4_1[i]))
		t.Logf("  x=%5.1f: %.6f (this is garbage for positive x!)", x, val)
	}

	// Spline I0
	spI0_0, spI0_1 := func() ([]uint64, []uint64) {
		preproc := SplineDistPreprocessGen(rp, len(testX))
		p0R1 := SplineRound1(rp, 0, x0, preproc)
		p1R1 := SplineRound1(rp, 1, x1, preproc)
		p0R2M, p0R2S := SplineRound2(rp, 0, x0, preproc, p0R1, p1R1)
		p1R2M, p1R2S := SplineRound2(rp, 1, x1, preproc, p1R1, p0R1)
		r0 := SplineRound3(rp, 0, preproc, p0R2S, p0R2M, p1R2M)
		r1 := SplineRound3(rp, 1, preproc, p1R2S, p1R2M, p0R2M)
		return r0, r1
	}()
	t.Log("I0 branch (spline for [0,1)):")
	for i, x := range testX {
		val := rp.ToDouble(rp.ModAdd(spI0_0[i], spI0_1[i]))
		t.Logf("  x=%5.1f: %.6f (spline on shares, garbage for x>=1)", x, val)
	}
}
