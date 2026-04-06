package main

import (
    "testing"
)

func TestSplineAt1052(t *testing.T) {
    ring := NewRing63(20)
    params := DefaultSigmoidParams()

    x := 1.052364
    xFP := ring.FromDouble(x)

    fails := 0; N := 200
    for trial := 0; trial < N; trial++ {
        x0, x1 := ring.SplitShare(xFP)
        res0, res1 := evalSplineOnShares(ring, params, []uint64{x0}, []uint64{x1})
        val := ring.ToDouble(ring.Add(res0[0], res1[0]))
        // For x=1.052 outside [0,1), the spline gives garbage
        // but it should be bounded (not 4.5M)
        if val > 100 || val < -100 {
            fails++
            if fails <= 3 {
                t.Logf("FAIL trial %d: spline(1.052) = %.6f (should be bounded)", trial, val)
            }
        }
    }
    t.Logf("Spline(1.052) large value rate: %d/%d = %.1f%%", fails, N, 100*float64(fails)/float64(N))
}

func TestKelkarExpAt1052(t *testing.T) {
    ring := NewRing63(20)
    cfg := DefaultExpConfig()

    // Test exp(-1.052) = 0.349
    x := -1.052364
    xFP := ring.FromDouble(x)

    fails := 0; N := 200
    for trial := 0; trial < N; trial++ {
        x0, x1 := ring.SplitShare(xFP)
        e0, e1 := SecureExpKelkar(cfg, []uint64{x0}, []uint64{x1})
        val := ring.ToDouble(ring.Add(e0[0], e1[0]))
        if val < 0 || val > 1 {
            fails++
            if fails <= 3 {
                t.Logf("FAIL trial %d: exp(-1.052) = %.6f", trial, val)
            }
        }
    }
    t.Logf("Kelkar exp(-1.052) failure rate: %d/%d = %.1f%%", fails, N, 100*float64(fails)/float64(N))
}
