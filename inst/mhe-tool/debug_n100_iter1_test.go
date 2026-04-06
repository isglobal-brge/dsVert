package main

import (
    "math"
    "testing"
)

func TestN100Iter1SigmoidCompare(t *testing.T) {
    ring := NewRing63(20)
    params := DefaultSigmoidParams()

    n := 100; p := 3
    X := make([]float64, n*p)
    y := make([]float64, n)
    for i := 0; i < n; i++ {
        for j := 0; j < p; j++ { X[i*p+j] = math.Sin(float64(i*p+j)*0.73) * 1.5 }
        eta := 0.5 - 0.8*X[i*p+0] + 0.3*X[i*p+1] - 0.6*X[i*p+2]
        if 1.0/(1.0+math.Exp(-eta)) > 0.5 { y[i] = 1 }
    }

    xFP := make([]uint64, n*p); yFP := make([]uint64, n)
    for i, v := range X { xFP[i] = ring.FromDouble(v) }
    for i, v := range y { yFP[i] = ring.FromDouble(v) }
    x0 := make([]uint64, n*p); x1 := make([]uint64, n*p)
    y0 := make([]uint64, n); y1 := make([]uint64, n)
    for i := range xFP { x0[i], x1[i] = ring.SplitShare(xFP[i]) }
    for i := range yFP { y0[i], y1[i] = ring.SplitShare(yFP[i]) }
    _, _ = y0, y1

    // Iter 1: beta=0, eta=0
    eta0 := make([]uint64, n)
    eta1 := make([]uint64, n)

    // Compare distributed vs local sigmoid
    dmu0, dmu1 := DistributedSigmoidLocalMhe(ring, eta0, eta1)
    pmu0, pmu1 := SecureSigmoidLocal(params, eta0, eta1)

    maxDiff := 0.0
    worstI := -1
    for i := 0; i < n; i++ {
        dv := ring.ToDouble(ring.Add(dmu0[i], dmu1[i]))
        pv := ring.ToDouble(ring.Add(pmu0[i], pmu1[i]))
        d := math.Abs(dv - pv)
        if d > maxDiff { maxDiff = d; worstI = i }
    }
    t.Logf("Iter 1 (beta=0, eta=0): maxSigDiff=%.2e worstI=%d", maxDiff, worstI)
    if worstI >= 0 {
        dv := ring.ToDouble(ring.Add(dmu0[worstI], dmu1[worstI]))
        pv := ring.ToDouble(ring.Add(pmu0[worstI], pmu1[worstI]))
        t.Logf("  worst: dist=%.8f local=%.8f", dv, pv)
    }

    // Now iter 2: beta from iter 1 gradient
    // Actually just check: does sigmoid(0) work for ALL 100 elements?
    for i := 0; i < n; i++ {
        dv := ring.ToDouble(ring.Add(dmu0[i], dmu1[i]))
        if math.Abs(dv - 0.5) > 0.01 {
            t.Errorf("Element %d: sigmoid(0) = %.6f (should be 0.5)", i, dv)
        }
    }
}
