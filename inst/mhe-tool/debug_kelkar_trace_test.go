package main

import (
    "math"
    "math/big"
    "testing"
)

func TestKelkarExpTraceFailure(t *testing.T) {
    cfg := DefaultExpConfig()
    r := cfg.Ring
    q := cfg.PrimeQ

    x := -1.052364
    xFP := r.FromDouble(x)

    log2eFP := r.FromDouble(log2e_const)
    base2Bound := int(math.Ceil(log2e_const*float64(cfg.ExponentBound))) + 1
    adderFP := uint64(base2Bound) * r.FracMul

    corrBig := new(big.Int).Mul(new(big.Int).SetUint64(log2eFP), new(big.Int).SetUint64(r.Modulus))
    corrBig.Div(corrBig, new(big.Int).SetUint64(r.FracMul))
    corrBig.Mod(corrBig, new(big.Int).SetUint64(r.Modulus))
    corr := corrBig.Uint64()

    for trial := 0; trial < 500; trial++ {
        s0, s1 := r.SplitShare(xFP)

        // P0
        base2_p0 := r.TruncMul(s0, log2eFP)
        posBase2_p0 := r.Add(base2_p0, adderFP)
        intP0 := posBase2_p0 / r.FracMul
        fracP0 := float64(posBase2_p0 % r.FracMul) / float64(r.FracMul)

        // P1
        firstTerm_p1 := r.TruncMul(s1, log2eFP)
        base2_p1 := r.Sub(firstTerm_p1, corr)
        intP1 := base2_p1 / r.FracMul
        fracP1 := float64(base2_p1 % r.FracMul) / float64(r.FracMul)

        intSum := intP0 + intP1
        fracSum := fracP0 + fracP1

        // Expected: base2 = x*log2e = -1.052*1.4427 = -1.518
        // + bound = -1.518 + 16 = 14.482
        // int = 14, frac = 0.482
        expectedInt := uint64(14)

        wrapped := intSum >= r.IntRingMod
        actualInt := intSum
        if wrapped { actualInt = intSum - r.IntRingMod }

        if actualInt != expectedInt || !wrapped {
            // Run full exp to see if it fails
            mta := GenerateMultToAddTuple(q)
            _, mult0 := ExpParty0Round1(cfg, []uint64{s0}, mta)
            _, mult1 := ExpParty1Round1(cfg, []uint64{s1}, mta)
            exp0 := ExpParty0Output(cfg, mult0, []uint64{modMulBig63(mta.Alpha1, mult1[0], q)}, mta)
            exp1 := ExpParty1Output(cfg, mult1, []uint64{modMulBig63(mta.Beta0, mult0[0], q)}, mta)
            got := r.ToDouble(r.Add(exp0[0], exp1[0]))
            want := math.Exp(x)

            t.Logf("Trial %d: intP0=%d intP1=%d sum=%d wrapped=%v actualInt=%d expectedInt=%d fracSum=%.4f exp=%.6f want=%.6f err=%.2e",
                trial, intP0, intP1, intSum, wrapped, actualInt, expectedInt, fracSum, got, want, math.Abs(got-want))
            return
        }
    }
    t.Log("No anomalies in 500 trials")
}
