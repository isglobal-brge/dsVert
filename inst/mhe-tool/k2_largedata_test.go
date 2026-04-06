package main

import (
    "math"
    "testing"
)

func TestDistributedSigmoidTrainingLargeN(t *testing.T) {
    ring := NewRing63(20)
    params := DefaultSigmoidParams()

    // Generate synthetic data: n=100, p=3
    n := 100; p := 3
    X := make([]float64, n*p)
    y := make([]float64, n)
    // Standardized features
    for i := 0; i < n; i++ {
        for j := 0; j < p; j++ {
            X[i*p+j] = math.Sin(float64(i*p+j)*0.73) * 1.5
        }
        // Label: logistic model
        eta := 0.5 - 0.8*X[i*p+0] + 0.3*X[i*p+1] - 0.6*X[i*p+2]
        prob := 1.0 / (1.0 + math.Exp(-eta))
        if prob > 0.5 { y[i] = 1 } else { y[i] = 0 }
    }

    xFP := make([]uint64, n*p); yFP := make([]uint64, n)
    for i, v := range X { xFP[i] = ring.FromDouble(v) }
    for i, v := range y { yFP[i] = ring.FromDouble(v) }
    x0 := make([]uint64, n*p); x1 := make([]uint64, n*p)
    y0 := make([]uint64, n); y1 := make([]uint64, n)
    for i := range xFP { x0[i], x1[i] = ring.SplitShare(xFP[i]) }
    for i := range yFP { y0[i], y1[i] = ring.SplitShare(yFP[i]) }

    // Distributed training
    betaD := make([]float64, p+1)
    // Plaintext training
    betaP := make([]float64, p+1)

    alpha := 0.3; lambda := 1e-4

    for iter := 1; iter <= 100; iter++ {
        // DISTRIBUTED
        betaFP := make([]uint64, p+1)
        for j := range betaD { betaFP[j] = ring.FromDouble(betaD[j]) }
        eta0 := make([]uint64, n); eta1 := make([]uint64, n)
        for i := 0; i < n; i++ {
            eta0[i] = betaFP[0]; eta1[i] = 0
            for j := 0; j < p; j++ {
                sv0 := ScalarVectorProductPartyZero(betaD[j+1], []uint64{x0[i*p+j]}, ring)
                sv1 := ScalarVectorProductPartyOne(betaD[j+1], []uint64{x1[i*p+j]}, ring)
                eta0[i] = ring.Add(eta0[i], sv0[0])
                eta1[i] = ring.Add(eta1[i], sv1[0])
            }
        }
        mu0, mu1 := SecureSigmoidLocal(params, eta0, eta1) // TEMPORARILY use local to confirm it's the sigmoid
        r0 := make([]uint64, n); r1 := make([]uint64, n)
        for i := range r0 { r0[i] = ring.Sub(mu0[i], y0[i]); r1[i] = ring.Sub(mu1[i], y1[i]) }
        var sR0, sR1 uint64
        for i := 0; i < n; i++ { sR0 = ring.Add(sR0, r0[i]); sR1 = ring.Add(sR1, r1[i]) }
        gD := make([]float64, p+1)
        gD[0] = ring.ToDouble(ring.Add(sR0, sR1))/float64(n) + lambda*betaD[0]
        for j := 0; j < p; j++ {
            xc0 := make([]uint64, n); xc1 := make([]uint64, n)
            for i := 0; i < n; i++ { xc0[i] = x0[i*p+j]; xc1[i] = x1[i*p+j] }
            t0, t1 := SampleBeaverTripleVector(n, ring)
            st0, m0 := GenerateBatchedMultiplicationGateMessage(xc0, r0, t0, ring)
            st1, m1 := GenerateBatchedMultiplicationGateMessage(xc1, r1, t1, ring)
            pr0 := HadamardProductPartyZero(st0, t0, m1, ring.FracBits, ring)
            pr1 := HadamardProductPartyOne(st1, t1, m0, ring.FracBits, ring)
            var s0, s1 uint64
            for i := 0; i < n; i++ { s0 = ring.Add(s0, pr0[i]); s1 = ring.Add(s1, pr1[i]) }
            gD[j+1] = ring.ToDouble(ring.Add(s0, s1))/float64(n) + lambda*betaD[j+1]
        }
        // Gradient clipping
        gnD := 0.0; for j := range gD { gnD += gD[j]*gD[j] }; gnD = math.Sqrt(gnD)
        scD := 1.0; if gnD > 5.0 { scD = 5.0/gnD }
        for j := range betaD { betaD[j] -= alpha * gD[j] * scD }

        // PLAINTEXT
        gP := make([]float64, p+1)
        for i := 0; i < n; i++ {
            eta := betaP[0]
            for j := 0; j < p; j++ { eta += X[i*p+j] * betaP[j+1] }
            mu := EvalPiecewiseSigmoid(eta, params)
            mu = math.Max(1e-10, math.Min(1-1e-10, mu))
            r := mu - y[i]; gP[0] += r
            for j := 0; j < p; j++ { gP[j+1] += X[i*p+j] * r }
        }
        for j := range gP { gP[j] = gP[j]/float64(n) + lambda*betaP[j] }
        gnP := 0.0; for j := range gP { gnP += gP[j]*gP[j] }; gnP = math.Sqrt(gnP)
        scP := 1.0; if gnP > 5.0 { scP = 5.0/gnP }
        for j := range betaP { betaP[j] -= alpha * gP[j] * scP }

        if iter%25 == 0 {
            maxDiff := 0.0
            for j := range betaD {
                d := math.Abs(betaD[j] - betaP[j]); if d > maxDiff { maxDiff = d }
            }
            t.Logf("Iter %d: dist-plain diff = %.2e", iter, maxDiff)
        }
    }

    maxErr := 0.0
    for j := range betaD {
        err := math.Abs(betaD[j] - betaP[j]); if err > maxErr { maxErr = err }
    }
    t.Logf("Distributed: %v", betaD)
    t.Logf("Plaintext:   %v", betaP)
    t.Logf("Max coef error (distributed vs plaintext): %.2e", maxErr)
}
