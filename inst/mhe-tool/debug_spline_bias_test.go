package main

import (
    "testing"
)

func TestSplineBias(t *testing.T) {
    ring := NewRing63(20)
    params := DefaultSigmoidParams()
    
    // Compare evalSplineOnShares vs plaintext evalSpline
    testX := []float64{0.05, 0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95}
    
    for _, x := range testX {
        xFP := ring.FromDouble(x)
        
        // Plaintext spline
        wantSpline := evalSpline(x, params)
        
        // Distributed spline (average over 20 runs)
        sumErr := 0.0
        N := 20
        for trial := 0; trial < N; trial++ {
            x0, x1 := ring.SplitShare(xFP)
            res0, res1 := evalSplineOnShares(ring, params, []uint64{x0}, []uint64{x1})
            got := ring.ToDouble(ring.Add(res0[0], res1[0]))
            sumErr += got - wantSpline
        }
        meanBias := sumErr / float64(N)
        t.Logf("spline(%.2f): plaintext=%.8f bias=%+.2e", x, wantSpline, meanBias)
    }
}
