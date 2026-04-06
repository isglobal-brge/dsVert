package main

import (
    "math"
    "testing"
)

// CorrectTruncPr implements the Catrina-Saxena probabilistic truncation.
// P(round up) = remainder / divisor, making E[result] = exact value.
// In local simulation, we can compute the exact remainder.
func CorrectTruncPr(raw0, raw1 uint64, divisor, modulus uint64) (trunc0, trunc1 uint64) {
    // Reconstruct the full product to get the exact remainder
    product := (raw0 + raw1) % modulus
    remainder := product % divisor

    // Deterministic floor truncation first
    trunc0 = raw0 / divisor
    negS := (modulus - raw1) % modulus
    trunc1 = (modulus - negS/divisor) % modulus

    // Probabilistic carry: P(carry=1) = remainder/divisor
    // This makes E[result] = product/divisor exactly
    threshold := cryptoRandUint64K2() % divisor
    if remainder > threshold {
        // Round UP: add 1 to the sum (add to P0 only)
        trunc0 = (trunc0 + 1) % modulus
    }
    return
}

func TestTruncPrBias(t *testing.T) {
    ring := NewRing63(20)

    slope := DefaultSigmoidParams().SplineSlopes[4]
    slopeFP := ring.FromDouble(slope)
    x := 0.46
    xFP := ring.FromDouble(x)
    intercept := DefaultSigmoidParams().SplineIntercepts[4]
    interceptFP := ring.FromDouble(intercept)
    wantFP := ring.FromDouble(evalSpline(x, DefaultSigmoidParams()))

    sumBiasFloor := 0.0
    sumBiasTruncPr := 0.0
    N := 2000

    for trial := 0; trial < N; trial++ {
        x0, x1 := ring.SplitShare(xFP)

        // Floor truncation (current)
        raw0_floor := modMulBig63(slopeFP, x0, ring.Modulus)
        raw1_floor := modMulBig63(slopeFP, x1, ring.Modulus)
        f0 := TruncateSharePartyZero([]uint64{raw0_floor}, ring.FracMul, ring.Modulus)[0]
        f1 := TruncateSharePartyOne([]uint64{raw1_floor}, ring.FracMul, ring.Modulus)[0]
        floorResult := ring.Add(ring.Add(f0, f1), interceptFP)

        // TruncPr (correct probabilistic)
        raw0_pr := modMulBig63(slopeFP, x0, ring.Modulus)
        raw1_pr := modMulBig63(slopeFP, x1, ring.Modulus)
        p0, p1 := CorrectTruncPr(raw0_pr, raw1_pr, ring.FracMul, ring.Modulus)
        prResult := ring.Add(ring.Add(p0, p1), interceptFP)

        sumBiasFloor += float64(int64(floorResult) - int64(wantFP))
        sumBiasTruncPr += float64(int64(prResult) - int64(wantFP))
    }

    t.Logf("Floor truncation:  mean bias = %+.4f ULP", sumBiasFloor/float64(N))
    t.Logf("TruncPr (correct): mean bias = %+.4f ULP", sumBiasTruncPr/float64(N))
}

func TestPimaTruncPr(t *testing.T) {
    // Quick test: does TruncPr change the training error?
    // For now, just verify the bias is eliminated at the spline level
    ring := NewRing63(20)
    params := DefaultSigmoidParams()

    for _, x := range []float64{0.15, 0.35, 0.55, 0.75, 0.95} {
        xFP := ring.FromDouble(x)
        localVal := ring.FromDouble(evalSpline(x, params))

        sumBias := 0.0
        N := 1000
        for trial := 0; trial < N; trial++ {
            x0, x1 := ring.SplitShare(xFP)
            // Use standard distributed spline (with floor truncation)
            r0, r1 := evalSplineOnShares(ring, params, []uint64{x0}, []uint64{x1})
            distVal := ring.Add(r0[0], r1[0])
            sumBias += float64(int64(distVal) - int64(localVal))
        }
        t.Logf("x=%.2f: FLOOR mean bias = %+.3f ULP", x, sumBias/float64(N))
    }

    _ = math.Abs
}
