package main

import (
	"math"
	"testing"
)

func TestSigmoidNearBoundary(t *testing.T) {
	rp := DefaultRingParams()

	// Test values near interval boundaries: 0, 1, -1, lfLn2
	nearVals := []float64{
		0.999, 1.0, 1.001,     // near I0/I1 boundary
		-0.001, 0.0, 0.001,    // near I5/I0 boundary
		-1.001, -1.0, -0.999,  // near I4/I5 boundary
	}

	for _, x := range nearVals {
		xFP := rp.VecFromDoubles([]float64{x})
		x0, x1 := rp.SplitVecShare(xFP)
		mu0, mu1 := DistributedSigmoidLocal(rp, x0, x1)
		got := rp.ToDouble(rp.ModAdd(mu0[0], mu1[0]))
		want := 1.0 / (1.0 + math.Exp(-x))
		err := math.Abs(got - want)
		status := "✓"
		if err > 0.01 { status = "✗" }
		t.Logf("sigmoid(%7.3f): got=%10.6f want=%10.6f err=%.2e %s", x, got, want, err, status)
	}
}
