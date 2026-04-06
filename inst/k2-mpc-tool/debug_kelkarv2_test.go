package main

import (
    "math"
    "testing"
)

func TestKelkarV2FailureRate(t *testing.T) {
    rp := DefaultRingParams()
    
    for _, x := range []float64{-1.54, -2.0, -0.5} {
        xFP := rp.VecFromDoubles([]float64{x})
        fails := 0
        N := 200
        for trial := 0; trial < N; trial++ {
            x0, x1 := rp.SplitVecShare(xFP)
            e0, e1 := KelkarExpLocalV2(rp, x0, x1)
            got := rp.ToDouble(rp.ModAdd(e0[0], e1[0]))
            want := math.Exp(x)
            if math.Abs(got - want) > 0.01 { fails++ }
        }
        t.Logf("V2 failure rate for exp(%.2f): %d/%d = %.1f%%", x, fails, N, 100*float64(fails)/float64(N))
    }
}
