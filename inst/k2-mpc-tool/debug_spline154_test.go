package main

import (
    "testing"
)

func TestSplineAt154(t *testing.T) {
    rp := DefaultRingParams()
    x := 1.54

    xFP := rp.VecFromDoubles([]float64{x})
    x0, x1 := rp.SplitVecShare(xFP)

    preproc := SplineDistPreprocessGen(rp, 1)

    p0R1 := SplineRound1(rp, 0, x0, preproc)
    p1R1 := SplineRound1(rp, 1, x1, preproc)
    p0R2M, p0R2S := SplineRound2(rp, 0, x0, preproc, p0R1, p1R1)
    p1R2M, p1R2S := SplineRound2(rp, 1, x1, preproc, p1R1, p0R1)
    r0 := SplineRound3(rp, 0, preproc, p0R2S, p0R2M, p1R2M)
    r1 := SplineRound3(rp, 1, preproc, p1R2S, p1R2M, p0R2M)

    splineVal := rp.ToDouble(rp.ModAdd(r0[0], r1[0]))
    t.Logf("spline(1.54) = %.6f (garbage — x outside [0,1))", splineVal)

    // Also check spline for negated x
    negOne := rp.ModSub(0, 1)
    negX0 := rp.VecScale(negOne, x0)
    negX1 := rp.VecScale(negOne, x1)

    preproc2 := SplineDistPreprocessGen(rp, 1)
    q0R1 := SplineRound1(rp, 0, negX0, preproc2)
    q1R1 := SplineRound1(rp, 1, negX1, preproc2)
    q0R2M, q0R2S := SplineRound2(rp, 0, negX0, preproc2, q0R1, q1R1)
    q1R2M, q1R2S := SplineRound2(rp, 1, negX1, preproc2, q1R1, q0R1)
    s0 := SplineRound3(rp, 0, preproc2, q0R2S, q0R2M, q1R2M)
    s1 := SplineRound3(rp, 1, preproc2, q1R2S, q1R2M, q0R2M)

    splineNegVal := rp.ToDouble(rp.ModAdd(s0[0], s1[0]))
    t.Logf("spline(-1.54) = %.6f (garbage — |x| outside [0,1))", splineNegVal)
    
    // Check: 1 - spline(-x) for I5
    oneFP := rp.FromDouble(1.0)
    i5_0 := rp.ModSub(oneFP, s0[0])
    i5_1 := rp.ModSub(0, s1[0])
    t.Logf("1 - spline(-1.54) = %.6f (I5 branch for x=1.54)", rp.ToDouble(rp.ModAdd(i5_0, i5_1)))
}
