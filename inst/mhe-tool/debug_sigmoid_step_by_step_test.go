package main

import (
    "math"
    "testing"
)

func TestSigmoidStepByStepBias(t *testing.T) {
    ring := NewRing63(20)
    params := DefaultSigmoidParams()
    
    x := -0.46
    xFP := ring.FromDouble(x)
    
    // Plaintext reference
    wantSigmoid := 1.0 / (1.0 + math.Exp(-x))
    wantSpline := evalSpline(-x, params) // spline(-(-0.46)) = spline(0.46)
    want1MinusSpline := 1.0 - wantSpline
    
    t.Logf("x=%.2f: sigmoid=%.10f, spline(|x|)=%.10f, 1-spline=%.10f", x, wantSigmoid, wantSpline, want1MinusSpline)
    
    // Step by step distributed
    x0, x1 := ring.SplitShare(xFP)
    
    // 1. Negate x for I5 spline
    negX0 := ring.Neg(x0)
    negX1 := ring.Neg(x1)
    negXVal := ring.ToDouble(ring.Add(negX0, negX1))
    t.Logf("negated x: %.10f (should be %.10f)", negXVal, -x)
    
    // 2. Spline on negated x
    spl0, spl1 := evalSplineOnShares(ring, params, []uint64{negX0}, []uint64{negX1})
    splVal := ring.ToDouble(ring.Add(spl0[0], spl1[0]))
    t.Logf("spline(|x|) on shares: %.10f (want %.10f, err=%+.2e)", splVal, wantSpline, splVal-wantSpline)
    
    // 3. 1 - spline
    oneFP := ring.FromDouble(1.0)
    res0 := ring.Sub(oneFP, spl0[0])
    res1 := ring.Sub(0, spl1[0])
    resVal := ring.ToDouble(ring.Add(res0, res1))
    t.Logf("1-spline on shares: %.10f (want %.10f, err=%+.2e)", resVal, want1MinusSpline, resVal-want1MinusSpline)
    
    // 4. Full sigmoid
    mu0, mu1 := DistributedSigmoidLocalMhe(ring, []uint64{x0}, []uint64{x1})
    sigVal := ring.ToDouble(ring.Add(mu0[0], mu1[0]))
    t.Logf("full sigmoid: %.10f (want %.10f, err=%+.2e)", sigVal, wantSigmoid, sigVal-wantSigmoid)
    
    // The difference between step 3 (1-spline directly) and step 4 (full sigmoid)
    // reveals how much error the branch selection (Hadamard) adds
    t.Logf("Error from branch selection: %+.2e", sigVal - resVal)
}
