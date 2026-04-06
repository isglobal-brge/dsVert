package main

import (
    "math"
    "testing"
)

func TestSigmoidAtEtaMinus1616(t *testing.T) {
    rp := DefaultRingParams()
    x := -1.616109

    xFP := rp.VecFromDoubles([]float64{x})
    x0, x1 := rp.SplitVecShare(xFP)

    // Distributed
    dmu0, dmu1 := DistributedSigmoidLocal(rp, x0, x1)
    dval := rp.ToDouble(rp.ModAdd(dmu0[0], dmu1[0]))

    // Reference
    pmu0, pmu1 := SecurePiecewiseSigmoidLocal(rp, x0, x1)
    pval := rp.ToDouble(rp.ModAdd(pmu0[0], pmu1[0]))

    want := 1.0 / (1.0 + math.Exp(-x))

    t.Logf("x=%.6f: dist=%.6f piecewise=%.6f exact=%.6f", x, dval, pval, want)

    // Also check what the branches produce
    negOne := rp.ModSub(0, 1)
    negX0 := rp.VecScale(negOne, x0)
    negX1 := rp.VecScale(negOne, x1)

    // I1 branch: exp(-x) = exp(1.616) = 5.03 → Taylor diverges
    z0, z1 := KelkarExpLocal(rp, negX0, negX1)
    zval := rp.ToDouble(rp.ModAdd(z0[0], z1[0]))
    t.Logf("Kelkar exp(+%.6f) = %.6f (for I1 branch, should be exp(1.616)=%.6f)", -x, zval, math.Exp(-x))

    // I4 branch: exp(x) = exp(-1.616) = 0.199
    e0, e1 := KelkarExpLocal(rp, x0, x1)
    eval2 := rp.ToDouble(rp.ModAdd(e0[0], e1[0]))
    t.Logf("Kelkar exp(%.6f) = %.6f (for I4 branch, should be exp(-1.616)=%.6f)", x, eval2, math.Exp(x))
}
