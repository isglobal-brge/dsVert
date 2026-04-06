package main

import (
    "testing"
)

func TestBitLevelDiff(t *testing.T) {
    ring := NewRing63(20)
    params := DefaultSigmoidParams()
    
    // Fixed shares — EXACTLY the same input for both methods
    x := 0.46
    xFP := ring.FromDouble(x)
    x0 := uint64(3456789012345678901)
    x1 := ring.Sub(xFP, x0)
    
    // SecureSigmoidLocal
    lmu0, lmu1 := SecureSigmoidLocal(params, []uint64{x0}, []uint64{x1})
    lval := ring.Add(lmu0[0], lmu1[0])
    
    // DistributedSigmoidLocalMhe (run once — Beaver triples are random)
    dmu0, dmu1 := DistributedSigmoidLocalMhe(ring, []uint64{x0}, []uint64{x1})
    dval := ring.Add(dmu0[0], dmu1[0])
    
    t.Logf("Local FP value:       %d (%.10f)", lval, ring.ToDouble(lval))
    t.Logf("Distributed FP value: %d (%.10f)", dval, ring.ToDouble(dval))
    t.Logf("Diff in Ring63 units: %d", int64(dval) - int64(lval))
    t.Logf("Diff in float:        %+.2e", ring.ToDouble(dval) - ring.ToDouble(lval))
    
    // What does SecureSigmoidLocal ACTUALLY compute?
    // It reconstructs x, evaluates evalSpline in float64, then FromDouble + SplitShare
    xRecon := ring.ToDouble(ring.Add(x0, x1))
    splineFloat := evalSpline(xRecon, params) // float64
    splineFP := ring.FromDouble(splineFloat)
    t.Logf("")
    t.Logf("x reconstructed: %.15f", xRecon)
    t.Logf("evalSpline(float64): %.15f", splineFloat)
    t.Logf("FromDouble(spline): %d (%.10f)", splineFP, ring.ToDouble(splineFP))
    t.Logf("Local output:       %d (%.10f)", lval, ring.ToDouble(lval))
    t.Logf("Match FromDouble?   %v", lval == splineFP)
}
