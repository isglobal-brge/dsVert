package main

import (
    "math"
    "testing"
)

func TestKelkarWithRetry(t *testing.T) {
    cfg := DefaultExpConfig()
    r := cfg.Ring

    for _, x := range []float64{-1.052, -0.5, -2.0, -5.0} {
        xFP := r.FromDouble(x)
        want := math.Exp(x)
        fails := 0; N := 2000
        for trial := 0; trial < N; trial++ {
            x0, x1 := r.SplitShare(xFP)
            e0, e1 := SecureExpKelkar(cfg, []uint64{x0}, []uint64{x1})
            got := r.ToDouble(r.Add(e0[0], e1[0]))
            if math.Abs(got-want) > 0.01 { fails++ }
        }
        t.Logf("Kelkar+retry exp(%.3f): %d/%d = %.2f%%", x, fails, N, 100*float64(fails)/float64(N))
    }
}
