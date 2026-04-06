package main

import (
    "math"
    "testing"
)

func TestFindBug(t *testing.T) {
    ring := NewRing63(20)
    params := DefaultSigmoidParams()
    
    // Simulate eta values from mid-training on Pima (iteration ~50)
    // These are typical standardized eta values
    etas := []float64{-0.5, -0.3, -0.1, 0.0, 0.1, 0.3, 0.5, 0.8, -0.8, 1.2, -1.2, 2.0, -2.0}
    n := len(etas)
    
    etaFP := make([]uint64, n)
    for i, v := range etas { etaFP[i] = ring.FromDouble(v) }
    e0 := make([]uint64, n); e1 := make([]uint64, n)
    for i := range etaFP { e0[i], e1[i] = ring.SplitShare(etaFP[i]) }
    
    dmu0, dmu1 := DistributedSigmoidLocalMhe(ring, e0, e1)
    lmu0, lmu1 := SecureSigmoidLocal(params, e0, e1)
    
    maxDiff := 0.0
    for i, eta := range etas {
        dv := ring.ToDouble(ring.Add(dmu0[i], dmu1[i]))
        lv := ring.ToDouble(ring.Add(lmu0[i], lmu1[i]))
        exact := 1.0 / (1.0 + math.Exp(-eta))
        diff := dv - lv
        if math.Abs(diff) > maxDiff { maxDiff = math.Abs(diff) }
        
        status := ""
        if math.Abs(diff) > 1e-4 { status = " *** LARGE DIFF ***" }
        t.Logf("eta=%+5.1f: dist=%.8f local=%.8f exact=%.8f diff=%+.2e%s",
            eta, dv, lv, exact, diff, status)
    }
    t.Logf("Max diff distributed-local: %.2e", maxDiff)
}
