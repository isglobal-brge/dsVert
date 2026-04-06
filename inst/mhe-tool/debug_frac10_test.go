package main

import (
    "math"
    "testing"
)

func TestKelkarFrac10(t *testing.T) {
    ring := NewRing63(10) // matching C++ test
    cfg := ExpConfig{Ring: ring, ExponentBound: 3, PrimeQ: 2305843009213693951}

    for _, x := range []float64{-1.052, -0.5, -2.0, -3.0} {
        xFP := ring.FromDouble(x)
        want := math.Exp(x)
        fails := 0; N := 500
        for trial := 0; trial < N; trial++ {
            x0, x1 := ring.SplitShare(xFP)
            e0, e1 := SecureExpKelkar(cfg, []uint64{x0}, []uint64{x1})
            got := ring.ToDouble(ring.Add(e0[0], e1[0]))
            if math.Abs(got-want) > 0.01 { fails++ }
        }
        t.Logf("fracBits=10 exp(%.3f): %d/%d failures = %.1f%%", x, fails, N, 100*float64(fails)/float64(N))
    }
}
