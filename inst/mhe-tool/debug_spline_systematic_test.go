package main

import (
    "testing"
)

func TestSplineSystematicError(t *testing.T) {
    ring := NewRing63(20)
    params := DefaultSigmoidParams()
    
    // Compare evalSpline (float64) vs evalSplineOnShares (Ring63)
    // for the SAME x values, averaging over many share splits
    for _, x := range []float64{0.05, 0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95} {
        xFP := ring.FromDouble(x)
        plainVal := evalSpline(x, params)
        
        // Ring63 spline via FromDouble (what SecureSigmoidLocal effectively does)
        plainFP := ring.FromDouble(plainVal)
        plainFromRing := ring.ToDouble(plainFP)
        
        // Ring63 spline via evalSplineOnShares
        sumDiff := 0.0
        N := 50
        for trial := 0; trial < N; trial++ {
            x0, x1 := ring.SplitShare(xFP)
            r0, r1 := evalSplineOnShares(ring, params, []uint64{x0}, []uint64{x1})
            distVal := ring.ToDouble(ring.Add(r0[0], r1[0]))
            sumDiff += distVal - plainFromRing
        }
        meanDiff := sumDiff / float64(N)
        
        t.Logf("x=%.2f: float64=%.10f fromRing=%.10f meanDist-fromRing=%+.2e",
            x, plainVal, plainFromRing, meanDiff)
    }
}
