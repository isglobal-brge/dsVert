package main

import (
	"math"
	"testing"
)

func TestKelkarExpNegativeInput(t *testing.T) {
	rp := DefaultRingParams()

	// Test exp(x) for negative x directly
	for _, x := range []float64{-0.5, -1.0, -2.0, -5.0, -10.0} {
		xFP := rp.VecFromDoubles([]float64{x})
		x0, x1 := rp.SplitVecShare(xFP)
		e0, e1 := KelkarExpLocal(rp, x0, x1)
		got := rp.ToDouble(rp.ModAdd(e0[0], e1[0]))
		want := math.Exp(x)
		err := math.Abs(got - want)
		t.Logf("exp(%.1f): got=%.8f want=%.8f err=%.2e", x, got, want, err)
	}
}
