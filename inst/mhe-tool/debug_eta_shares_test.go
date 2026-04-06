package main

import (
    "math"
    "testing"
)

func TestEtaShareStructure(t *testing.T) {
    ring := NewRing63(20)

    // Simulate what the training loop does at iter 2
    // beta = [0, 0.33, -0.165]
    beta := []float64{0, 0.33, -0.165}
    X := []float64{0.5, -0.3, -1.2, 0.8}  // 2 observations, 2 features
    n := 2; p := 2

    xFP := make([]uint64, n*p)
    for i, v := range X { xFP[i] = ring.FromDouble(v) }
    x0 := make([]uint64, n*p); x1 := make([]uint64, n*p)
    for i := range xFP { x0[i], x1[i] = ring.SplitShare(xFP[i]) }

    // Compute eta via ScalarVectorProduct (like training loop)
    eta0_svp := make([]uint64, n); eta1_svp := make([]uint64, n)
    for i := 0; i < n; i++ {
        for j := 0; j < p; j++ {
            sv0 := ScalarVectorProductPartyZero(beta[j+1], []uint64{x0[i*p+j]}, ring)
            sv1 := ScalarVectorProductPartyOne(beta[j+1], []uint64{x1[i*p+j]}, ring)
            eta0_svp[i] = ring.Add(eta0_svp[i], sv0[0])
            eta1_svp[i] = ring.Add(eta1_svp[i], sv1[0])
        }
    }

    // Compute eta in plaintext and re-share (like SecureSigmoidLocal does)
    for i := 0; i < n; i++ {
        etaPlain := 0.0
        for j := 0; j < p; j++ { etaPlain += X[i*p+j] * beta[j+1] }
        etaSVP := ring.ToDouble(ring.Add(eta0_svp[i], eta1_svp[i]))

        t.Logf("Obs %d: eta_plain=%.8f eta_svp=%.8f diff=%.2e", i, etaPlain, etaSVP, math.Abs(etaPlain-etaSVP))

        // Test sigmoid on SVP shares vs fresh shares
        etaFP := ring.FromDouble(etaPlain)
        fresh0, fresh1 := ring.SplitShare(etaFP)

        mu_svp0, mu_svp1 := DistributedSigmoidLocalMhe(ring, []uint64{eta0_svp[i]}, []uint64{eta1_svp[i]})
        mu_fresh0, mu_fresh1 := DistributedSigmoidLocalMhe(ring, []uint64{fresh0}, []uint64{fresh1})

        svpVal := ring.ToDouble(ring.Add(mu_svp0[0], mu_svp1[0]))
        freshVal := ring.ToDouble(ring.Add(mu_fresh0[0], mu_fresh1[0]))
        exactVal := 1.0 / (1.0 + math.Exp(-etaPlain))

        t.Logf("  sigmoid: svp_shares=%.8f fresh_shares=%.8f exact=%.8f", svpVal, freshVal, exactVal)
        t.Logf("  err_svp=%.2e err_fresh=%.2e", math.Abs(svpVal-exactVal), math.Abs(freshVal-exactVal))
    }
}
