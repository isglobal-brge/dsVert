package main

import (
    "math"
    "testing"
)

func TestSigmoidAt1052FailRate(t *testing.T) {
    ring := NewRing63(20)

    x := 1.052364
    xFP := ring.FromDouble(x)
    want := 1.0 / (1.0 + math.Exp(-x))

    fails := 0; N := 200
    for trial := 0; trial < N; trial++ {
        x0, x1 := ring.SplitShare(xFP)
        mu0, mu1 := DistributedSigmoidLocalMhe(ring, []uint64{x0}, []uint64{x1})
        got := ring.ToDouble(ring.Add(mu0[0], mu1[0]))
        if math.Abs(got - want) > 0.01 {
            fails++
            if fails <= 3 {
                t.Logf("FAIL trial %d: sigmoid(%.4f) = %.6f (want %.6f)", trial, x, got, want)
            }
        }
    }
    t.Logf("Failure rate for sigmoid(%.4f): %d/%d = %.1f%%", x, fails, N, 100*float64(fails)/float64(N))
}
