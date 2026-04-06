package main

import (
    "math"
    "testing"
)

func TestElementDiff(t *testing.T) {
    ring := NewRing63(20)
    params := DefaultSigmoidParams()
    
    x := 0.46 // midpoint of spline interval [0.4, 0.5)
    xFP := ring.FromDouble(x)
    
    exactSigmoid := 1.0 / (1.0 + math.Exp(-x))
    
    // Plaintext spline evaluation
    splineVal := evalSpline(x, params)
    t.Logf("exact sigmoid: %.10f", exactSigmoid)
    t.Logf("plaintext spline: %.10f (err=%+.2e)", splineVal, splineVal-exactSigmoid)
    
    // SecureSigmoidLocal: float64 spline + SplitShare
    localResults := make([]float64, 20)
    for trial := 0; trial < 20; trial++ {
        x0, x1 := ring.SplitShare(xFP)
        mu0, mu1 := SecureSigmoidLocal(params, []uint64{x0}, []uint64{x1})
        localResults[trial] = ring.ToDouble(ring.Add(mu0[0], mu1[0]))
    }
    t.Logf("SecureSigmoidLocal (20 trials): all = %.10f", localResults[0])
    
    // DistributedSigmoidLocalMhe: Ring63 spline
    distResults := make([]float64, 20)
    for trial := 0; trial < 20; trial++ {
        x0, x1 := ring.SplitShare(xFP)
        mu0, mu1 := DistributedSigmoidLocalMhe(ring, []uint64{x0}, []uint64{x1})
        distResults[trial] = ring.ToDouble(ring.Add(mu0[0], mu1[0]))
    }
    
    // Count distinct values
    distinct := make(map[float64]int)
    for _, v := range distResults { distinct[v]++ }
    t.Logf("DistributedSigmoidLocalMhe: %d distinct values in 20 trials", len(distinct))
    for v, c := range distinct {
        t.Logf("  %.10f (%d times, err=%+.2e vs exact, %+.2e vs local)",
            v, c, v-exactSigmoid, v-localResults[0])
    }
}
