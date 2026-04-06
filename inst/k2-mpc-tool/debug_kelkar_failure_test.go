package main

import (
    "math"
    "testing"
)

func TestKelkarFailureRate(t *testing.T) {
    rp := DefaultRingParams()
    
    // Test exp(-x) for x=1.54 many times
    x := -1.54 // exp(-1.54) ≈ 0.2144
    xFP := rp.VecFromDoubles([]float64{x})
    
    fails := 0
    N := 100
    for trial := 0; trial < N; trial++ {
        x0, x1 := rp.SplitVecShare(xFP)
        e0, e1 := KelkarExpLocal(rp, x0, x1)
        got := rp.ToDouble(rp.ModAdd(e0[0], e1[0]))
        want := math.Exp(x)
        err := math.Abs(got - want)
        if err > 0.01 {
            fails++
            if fails <= 3 {
                t.Logf("FAIL trial %d: exp(%.2f)=%.6f (want %.6f, err=%.2e)", trial, x, got, want, err)
            }
        }
    }
    t.Logf("Failure rate for exp(%.2f): %d/%d = %.1f%%", x, fails, N, 100*float64(fails)/float64(N))
    
    // Also test exp(-2.0) 
    x2 := -2.0
    x2FP := rp.VecFromDoubles([]float64{x2})
    fails2 := 0
    for trial := 0; trial < N; trial++ {
        x0, x1 := rp.SplitVecShare(x2FP)
        e0, e1 := KelkarExpLocal(rp, x0, x1)
        got := rp.ToDouble(rp.ModAdd(e0[0], e1[0]))
        err := math.Abs(got - math.Exp(x2))
        if err > 0.01 { fails2++ }
    }
    t.Logf("Failure rate for exp(%.2f): %d/%d = %.1f%%", x2, fails2, N, 100*float64(fails2)/float64(N))
    
    // Test exp(-5.0)
    x3 := -5.0
    x3FP := rp.VecFromDoubles([]float64{x3})
    fails3 := 0
    for trial := 0; trial < N; trial++ {
        x0, x1 := rp.SplitVecShare(x3FP)
        e0, e1 := KelkarExpLocal(rp, x0, x1)
        got := rp.ToDouble(rp.ModAdd(e0[0], e1[0]))
        err := math.Abs(got - math.Exp(x3))
        if err > 0.01 { fails3++ }
    }
    t.Logf("Failure rate for exp(%.2f): %d/%d = %.1f%%", x3, fails3, N, 100*float64(fails3)/float64(N))
}
