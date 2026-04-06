package main

import (
    "math"
    "testing"
)

func TestDistributedTrainingFrac10(t *testing.T) {
    ring := NewRing63(10)
    params := SigmoidParams{
        Ring: ring, FracBits: 10,
        SplineSlopes: DefaultSigmoidParams().SplineSlopes,
        SplineIntercepts: DefaultSigmoidParams().SplineIntercepts,
        SplineNumIntervals: 10,
        TaylorDegree: 10,
        ExpConfig: ExpConfig{Ring: ring, ExponentBound: 10, PrimeQ: 2305843009213693951},
    }

    n := 50; p := 2
    X := make([]float64, n*p)
    y := make([]float64, n)
    for i := 0; i < n; i++ {
        for j := 0; j < p; j++ { X[i*p+j] = math.Sin(float64(i*p+j+1)*0.73) * 1.5 }
        eta := 0.5 - 0.8*X[i*p+0] + 0.3*X[i*p+1]
        if 1.0/(1.0+math.Exp(-eta)) > 0.5 { y[i] = 1 }
    }

    xFP := make([]uint64, n*p); yFP := make([]uint64, n)
    for i, v := range X { xFP[i] = ring.FromDouble(v) }
    for i, v := range y { yFP[i] = ring.FromDouble(v) }
    x0 := make([]uint64, n*p); x1 := make([]uint64, n*p)
    y0 := make([]uint64, n); y1 := make([]uint64, n)
    for i := range xFP { x0[i], x1[i] = ring.SplitShare(xFP[i]) }
    for i := range yFP { y0[i], y1[i] = ring.SplitShare(yFP[i]) }

    beta := make([]float64, p+1)
    alpha := 0.3; lambda := 1e-4

    for iter := 1; iter <= 100; iter++ {
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

        mu0, mu1 := DistributedSigmoidLocalMhe(ring, eta0, eta1)

        r0 := make([]uint64, n); r1 := make([]uint64, n)
        for i := range r0 { r0[i] = ring.Sub(mu0[i], y0[i]); r1[i] = ring.Sub(mu1[i], y1[i]) }
        var sR0, sR1 uint64
        for i := 0; i < n; i++ { sR0 = ring.Add(sR0, r0[i]); sR1 = ring.Add(sR1, r1[i]) }
        grad := []float64{ring.ToDouble(ring.Add(sR0, sR1))/float64(n) + lambda*beta[0]}
        for j := 0; j < p; j++ {
            xc0 := make([]uint64, n); xc1 := make([]uint64, n)
            for i := 0; i < n; i++ { xc0[i] = x0[i*p+j]; xc1[i] = x1[i*p+j] }
            bt0, bt1 := SampleBeaverTripleVector(n, ring)
            st0, m0 := GenerateBatchedMultiplicationGateMessage(xc0, r0, bt0, ring)
            st1, m1 := GenerateBatchedMultiplicationGateMessage(xc1, r1, bt1, ring)
            pr0 := HadamardProductPartyZero(st0, bt0, m1, ring.FracBits, ring)
            pr1 := HadamardProductPartyOne(st1, bt1, m0, ring.FracBits, ring)
            var s0, s1 uint64
            for i := 0; i < n; i++ { s0 = ring.Add(s0, pr0[i]); s1 = ring.Add(s1, pr1[i]) }
            grad = append(grad, ring.ToDouble(ring.Add(s0, s1))/float64(n)+lambda*beta[j+1])
        }
        gn := 0.0; for j := range grad { gn += grad[j]*grad[j] }; gn = math.Sqrt(gn)
        sc := 1.0; if gn > 5.0 { sc = 5.0/gn }
        for j := range beta { beta[j] -= alpha * grad[j] * sc }
        if iter%25 == 0 { t.Logf("Iter %d: beta=%v", iter, beta) }
    }

    // Plaintext reference
    plainBeta := make([]float64, p+1)
    for iter := 0; iter < 100; iter++ {
        g := make([]float64, p+1)
        for i := 0; i < n; i++ {
            eta := plainBeta[0]
            for j := 0; j < p; j++ { eta += X[i*p+j] * plainBeta[j+1] }
            mu := EvalPiecewiseSigmoid(eta, params)
            mu = math.Max(1e-10, math.Min(1-1e-10, mu))
            r := mu - y[i]; g[0] += r
            for j := 0; j < p; j++ { g[j+1] += X[i*p+j] * r }
        }
        gn := 0.0
        for j := range g { g[j] = g[j]/float64(n)+lambda*plainBeta[j]; gn += g[j]*g[j] }
        gn = math.Sqrt(gn); sc := 1.0; if gn > 5.0 { sc = 5.0/gn }
        for j := range plainBeta { plainBeta[j] -= alpha * g[j] * sc }
    }

    maxErr := 0.0
    for j := range beta {
        err := math.Abs(beta[j] - plainBeta[j]); if err > maxErr { maxErr = err }
    }
    t.Logf("Distributed (fracBits=10): %v", beta)
    t.Logf("Plaintext:                 %v", plainBeta)
    t.Logf("Max coef error: %.2e", maxErr)
}
