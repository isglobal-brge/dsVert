package main

import (
    "math"
    "testing"
)

// SecureML-style symmetric truncation: both parties just right-shift
func secureMLTruncP0(share uint64, fracBits int) uint64 {
    return share >> uint(fracBits)
}

func secureMLTruncP1(share uint64, fracBits int) uint64 {
    return share >> uint(fracBits)
}

// Hadamard product with SecureML truncation
func HadamardSecureML(
    state0 BatchedMultState, beaver0 BeaverTripleVec, msg1 MultGateMessage,
    state1 BatchedMultState, beaver1 BeaverTripleVec, msg0 MultGateMessage,
    fracBits int, r Ring63) (res0, res1 []uint64) {

    raw0 := GenerateBatchedMultiplicationOutputPartyZero(state0, beaver0, msg1, r)
    raw1 := GenerateBatchedMultiplicationOutputPartyOne(state1, beaver1, msg0, r)

    res0 = make([]uint64, len(raw0))
    res1 = make([]uint64, len(raw1))
    for i := range raw0 {
        res0[i] = secureMLTruncP0(raw0[i], fracBits)
        res1[i] = secureMLTruncP1(raw1[i], fracBits)
    }
    return
}

func TestSecureMLTruncation(t *testing.T) {
    ring := NewRing63(20)

    // Test: does symmetric truncation produce zero-mean error?
    x := 0.46
    xFP := ring.FromDouble(x)
    wantSpline := evalSpline(x, DefaultSigmoidParams())
    wantFP := ring.FromDouble(wantSpline)

    slope := DefaultSigmoidParams().SplineSlopes[4] // interval [0.4, 0.5)
    intercept := DefaultSigmoidParams().SplineIntercepts[4]
    slopeFP := ring.FromDouble(slope)
    interceptFP := ring.FromDouble(intercept)

    sumErrAsym := 0.0
    sumErrSym := 0.0
    N := 1000

    for trial := 0; trial < N; trial++ {
        x0, x1 := ring.SplitShare(xFP)

        // Asymmetric (current Ring63)
        asym0 := TruncateSharePartyZero(
            []uint64{modMulBig63(slopeFP, x0, ring.Modulus)},
            ring.FracMul, ring.Modulus)[0]
        asym1 := TruncateSharePartyOne(
            []uint64{modMulBig63(slopeFP, x1, ring.Modulus)},
            ring.FracMul, ring.Modulus)[0]
        asymResult := ring.Add(ring.Add(asym0, asym1), interceptFP)

        // Symmetric (SecureML-style)
        sym0 := secureMLTruncP0(modMulBig63(slopeFP, x0, ring.Modulus), 20)
        sym1 := secureMLTruncP1(modMulBig63(slopeFP, x1, ring.Modulus), 20)
        symResult := ring.Add(ring.Add(sym0, sym1), interceptFP)

        errAsym := float64(int64(asymResult) - int64(wantFP))
        errSym := float64(int64(symResult) - int64(wantFP))

        sumErrAsym += errAsym
        sumErrSym += errSym
    }

    t.Logf("Asymmetric (Ring63):  mean error = %+.2f ULP", sumErrAsym/float64(N))
    t.Logf("Symmetric (SecureML): mean error = %+.2f ULP", sumErrSym/float64(N))
    t.Logf("")
    t.Logf("If asymmetric has nonzero mean → source of deterministic shift")
    t.Logf("If symmetric has zero mean → Ring64/SecureML would fix it")

    // Also test with actual distributed sigmoid but using SecureML truncation
    // in the Hadamard
    _ = math.Abs
}
