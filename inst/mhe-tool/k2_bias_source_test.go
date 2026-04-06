package main

import (
    "testing"
)

func TestBiasSource(t *testing.T) {
    ring := NewRing63(20)
    params := DefaultSigmoidParams()

    // Multiple x values — measure the MEAN bias of the Hadamard in the spline
    for _, x := range []float64{0.15, 0.35, 0.55, 0.75, 0.95} {
        xFP := ring.FromDouble(x)
        localVal := ring.FromDouble(evalSpline(x, params))
        
        sumBias := 0.0
        N := 1000
        for trial := 0; trial < N; trial++ {
            x0, x1 := ring.SplitShare(xFP)
            r0, r1 := evalSplineOnShares(ring, params, []uint64{x0}, []uint64{x1})
            distVal := ring.Add(r0[0], r1[0])
            sumBias += float64(int64(distVal) - int64(localVal))
        }
        t.Logf("x=%.2f: mean spline bias = %+.3f ULP", x, sumBias/float64(N))
    }
}
