package main

import (
    "math"
    "testing"
)

func TestSigmoidVectorVsSingletons(t *testing.T) {
    rp := DefaultRingParams()
    
    // Eta values from iter 5 of the training loop
    etas := []float64{-0.18, 1.28, -0.93, 0.74, -1.62, 1.54, -0.61, 1.11, -1.39, 0.47}
    _ = len(etas)
    
    // Vector evaluation
    etaFP := rp.VecFromDoubles(etas)
    e0, e1 := rp.SplitVecShare(etaFP)
    vmu0, vmu1 := DistributedSigmoidLocal(rp, e0, e1)
    
    maxErr := 0.0
    for i, eta := range etas {
        // Vector result
        vval := rp.ToDouble(rp.ModAdd(vmu0[i], vmu1[i]))
        
        // Singleton result
        sFP := rp.VecFromDoubles([]float64{eta})
        s0, s1 := rp.SplitVecShare(sFP)
        smu0, smu1 := DistributedSigmoidLocal(rp, s0, s1)
        sval := rp.ToDouble(rp.ModAdd(smu0[0], smu1[0]))
        
        want := 1.0 / (1.0 + math.Exp(-eta))
        verr := math.Abs(vval - want)
        serr := math.Abs(sval - want)
        
        if verr > maxErr { maxErr = verr }
        
        status := "✓"
        if verr > 0.01 { status = "✗ VECTOR FAIL" }
        
        t.Logf("eta=%6.2f: vector=%.6f single=%.6f exact=%.6f v_err=%.2e s_err=%.2e %s",
            eta, vval, sval, want, verr, serr, status)
    }
    t.Logf("Max vector error: %.2e", maxErr)
}
