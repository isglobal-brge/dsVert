package main

import (
    "testing"
)

func TestDeterministicBias(t *testing.T) {
    ring := NewRing63(20)
    params := DefaultSigmoidParams()
    
    x := 0.46
    xFP := ring.FromDouble(x)
    
    // Use SAME shares every time (fixed seed)
    x0 := uint64(3456789012345678901)
    x1 := ring.Sub(xFP, x0)
    
    // Evaluate 10 times with SAME shares
    for trial := 0; trial < 10; trial++ {
        dmu0, dmu1 := DistributedSigmoidLocalMhe(ring, []uint64{x0}, []uint64{x1})
        lmu0, lmu1 := SecureSigmoidLocal(params, []uint64{x0}, []uint64{x1})
        dv := ring.ToDouble(ring.Add(dmu0[0], dmu1[0]))
        lv := ring.ToDouble(ring.Add(lmu0[0], lmu1[0]))
        t.Logf("trial %d: dist=%.10f local=%.10f diff=%+.2e", trial, dv, lv, dv-lv)
    }
}
