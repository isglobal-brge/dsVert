package main

import (
    "math"
    "testing"
)

func TestGradientDiff(t *testing.T) {
    ring := NewRing63(20)
    params := DefaultSigmoidParams()

    // Simple data: 5 elements, 1 feature
    X := []float64{0.5, -0.3, 0.7, -0.4, 1.1}
    y := []float64{1, 0, 1, 0, 1}
    n := 5; p := 1
    beta := []float64{0, 0.33}  // iter 2 beta
    
    xFP := make([]uint64, n*p); yFP := make([]uint64, n)
    for i, v := range X { xFP[i] = ring.FromDouble(v) }
    for i, v := range y { yFP[i] = ring.FromDouble(v) }
    x0 := make([]uint64, n*p); x1 := make([]uint64, n*p)
    y0 := make([]uint64, n); y1 := make([]uint64, n)
    for i := range xFP { x0[i], x1[i] = ring.SplitShare(xFP[i]) }
    for i := range yFP { y0[i], y1[i] = ring.SplitShare(yFP[i]) }

    // Compute eta
    betaFP := make([]uint64, p+1)
    for j := range beta { betaFP[j] = ring.FromDouble(beta[j]) }
    eta0 := make([]uint64, n); eta1 := make([]uint64, n)
    for i := 0; i < n; i++ {
        eta0[i] = betaFP[0]; eta1[i] = 0
        for j := 0; j < p; j++ {
            sv0 := ScalarVectorProductPartyZero(beta[j+1], []uint64{x0[i*p+j]}, ring)
            sv1 := ScalarVectorProductPartyOne(beta[j+1], []uint64{x1[i*p+j]}, ring)
            eta0[i] = ring.Add(eta0[i], sv0[0])
            eta1[i] = ring.Add(eta1[i], sv1[0])
        }
    }

    // Two sigmoids
    dmu0, dmu1 := DistributedSigmoidLocalMhe(ring, eta0, eta1)
    lmu0, lmu1 := SecureSigmoidLocal(params, eta0, eta1)

    // Compare per-element
    for i := 0; i < n; i++ {
        eta := ring.ToDouble(ring.Add(eta0[i], eta1[i]))
        dmu := ring.ToDouble(ring.Add(dmu0[i], dmu1[i]))
        lmu := ring.ToDouble(ring.Add(lmu0[i], lmu1[i]))
        exact := 1.0 / (1.0 + math.Exp(-eta))
        t.Logf("i=%d eta=%+.4f: dist=%.8f local=%.8f exact=%.8f diff_dl=%+.2e",
            i, eta, dmu, lmu, exact, dmu-lmu)
    }

    // Gradients
    dr0 := make([]uint64, n); dr1 := make([]uint64, n)
    lr0 := make([]uint64, n); lr1 := make([]uint64, n)
    for i := range dr0 {
        dr0[i] = ring.Sub(dmu0[i], y0[i]); dr1[i] = ring.Sub(dmu1[i], y1[i])
        lr0[i] = ring.Sub(lmu0[i], y0[i]); lr1[i] = ring.Sub(lmu1[i], y1[i])
    }

    var dSumR, lSumR float64
    for i := 0; i < n; i++ {
        dr := ring.ToDouble(ring.Add(dr0[i], dr1[i]))
        lr := ring.ToDouble(ring.Add(lr0[i], lr1[i]))
        dSumR += dr; lSumR += lr
    }
    t.Logf("Sum residual: dist=%.8f local=%.8f diff=%+.2e", dSumR, lSumR, dSumR-lSumR)
}
