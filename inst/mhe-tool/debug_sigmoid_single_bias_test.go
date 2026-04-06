package main

import (
    "math"
    "testing"
)

func TestSigmoidSingleValueBias(t *testing.T) {
    ring := NewRing63(20)

    x := -0.46
    xFP := ring.FromDouble(x)
    want := 1.0 / (1.0 + math.Exp(-x))

    // 50 evaluations with different shares
    for trial := 0; trial < 10; trial++ {
        x0, x1 := ring.SplitShare(xFP)
        dmu0, dmu1 := DistributedSigmoidLocalMhe(ring, []uint64{x0}, []uint64{x1})
        got := ring.ToDouble(ring.Add(dmu0[0], dmu1[0]))
        t.Logf("trial %d: sigmoid(-0.46) = %.10f (want %.10f, err=%+.2e)", trial, got, want, got-want)
    }
}
