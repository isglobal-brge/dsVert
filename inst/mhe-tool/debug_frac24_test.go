package main

import (
    "math"
    "testing"
)

func TestKelkarFrac24(t *testing.T) {
    ring := NewRing63(24)
    cfg := ExpConfig{Ring: ring, ExponentBound: 10, PrimeQ: 2305843009213693951}
    
    for _, x := range []float64{-1.052, -0.5, -2.0, -5.0} {
        xFP := ring.FromDouble(x)
        want := math.Exp(x)
        fails := 0; N := 500
        for trial := 0; trial < N; trial++ {
            x0, x1 := ring.SplitShare(xFP)
            e0, e1 := SecureExpKelkar(cfg, []uint64{x0}, []uint64{x1})
            got := ring.ToDouble(ring.Add(e0[0], e1[0]))
            if math.Abs(got-want) > 0.001 { fails++ }
        }
        t.Logf("frac24+retry exp(%.3f): %d/%d = %.1f%%", x, fails, N, 100*float64(fails)/float64(N))
    }
}
