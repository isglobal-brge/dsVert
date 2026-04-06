package main

import (
	"math"
	"testing"
)

func TestSigmoidSingleElement(t *testing.T) {
	rp := DefaultRingParams()

	for _, x := range []float64{0.5, -0.5, 2.0, -2.0, 15.0} {
		xFP := rp.VecFromDoubles([]float64{x})
		x0, x1 := rp.SplitVecShare(xFP)
		mu0, mu1 := DistributedSigmoidLocal(rp, x0, x1)
		got := rp.ToDouble(rp.ModAdd(mu0[0], mu1[0]))
		want := 1.0 / (1.0 + math.Exp(-x))
		err := math.Abs(got - want)
		status := "✓"
		if err > 0.01 { status = "✗ FAIL" }
		t.Logf("sigmoid(%.1f): got=%.8f want=%.8f err=%.2e %s", x, got, want, err, status)
	}
}
