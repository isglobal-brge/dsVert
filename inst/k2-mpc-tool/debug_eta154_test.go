package main

import (
    "math"
    "testing"
)

func TestEta154(t *testing.T) {
    rp := DefaultRingParams()
    x := 1.54

    xFP := rp.VecFromDoubles([]float64{x})
    x0, x1 := rp.SplitVecShare(xFP)

    // Direct distributed sigmoid
    mu0, mu1 := DistributedSigmoidLocal(rp, x0, x1)
    t.Logf("sigmoid(%.2f) distributed = %.6f (want %.6f)", x,
        rp.ToDouble(rp.ModAdd(mu0[0], mu1[0])), 1.0/(1+math.Exp(-x)))

    // Kelkar exp(-1.54) 
    negOne := rp.ModSub(0, 1)
    negX0 := rp.VecScale(negOne, x0)
    negX1 := rp.VecScale(negOne, x1)
    z0, z1 := KelkarExpLocal(rp, negX0, negX1)
    t.Logf("exp(-%.2f) = %.6f (want %.6f)", x,
        rp.ToDouble(rp.ModAdd(z0[0], z1[0])), math.Exp(-x))

    // Taylor on z
    taylorCoeffs := make([]float64, 11)
    for k := 0; k <= 10; k++ {
        if k%2 == 0 { taylorCoeffs[k] = 1 } else { taylorCoeffs[k] = -1 }
    }
    t0, t1 := SecurePolyEval(rp, taylorCoeffs, z0, z1)
    t.Logf("Taylor(exp(-%.2f)) = %.6f (want %.6f)", x,
        rp.ToDouble(rp.ModAdd(t0[0], t1[0])), 1.0/(1+math.Exp(-x)))

    // Now test exp(+1.54) directly — this is what I4 branch computes for this x
    e0, e1 := KelkarExpLocal(rp, x0, x1)
    t.Logf("exp(+%.2f) = %.6f (want %.6f)", x,
        rp.ToDouble(rp.ModAdd(e0[0], e1[0])), math.Exp(x))
}
