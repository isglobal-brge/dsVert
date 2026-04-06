package main

import (
    "math"
    "math/big"
    "testing"
)

func TestKelkarExpRealFailure(t *testing.T) {
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

    for trial := 0; trial < 10000; trial++ {
        s0, s1 := r.SplitShare(xFP)

        mta := GenerateMultToAddTuple(q)
        beta0Mult0, mult0 := ExpParty0Round1(cfg, []uint64{s0}, mta)
        alpha1Mult1, mult1 := ExpParty1Round1(cfg, []uint64{s1}, mta)
        exp0 := ExpParty0Output(cfg, mult0, alpha1Mult1, mta)
        exp1 := ExpParty1Output(cfg, mult1, beta0Mult0, mta)
        got := r.ToDouble(r.Add(exp0[0], exp1[0]))
        want := math.Exp(x)

        if math.Abs(got - want) > 0.01 {
            // Found a failure! Now trace it
            base2_p0 := r.TruncMul(s0, log2eFP)
            posBase2_p0 := r.Add(base2_p0, adderFP)
            intP0 := posBase2_p0 / r.FracMul
            fracP0 := float64(posBase2_p0 % r.FracMul) / float64(r.FracMul)

            firstTerm_p1 := r.TruncMul(s1, log2eFP)
            base2_p1 := r.Sub(firstTerm_p1, corr)
            intP1 := base2_p1 / r.FracMul
            fracP1 := float64(base2_p1 % r.FracMul) / float64(r.FracMul)

            t.Logf("FAIL at trial %d: got=%.6f want=%.6f err=%.2e", trial, got, want, math.Abs(got-want))
            t.Logf("  s0=%d s1=%d sumFP=%d xFP=%d", s0, s1, r.Add(s0, s1), xFP)
            t.Logf("  intP0=%d intP1=%d sum=%d IntRingMod=%d", intP0, intP1, intP0+intP1, r.IntRingMod)
            t.Logf("  fracP0=%.6f fracP1=%.6f sum=%.6f", fracP0, fracP1, fracP0+fracP1)
            t.Logf("  wrapped=%v", intP0+intP1 >= r.IntRingMod)
            _ = corr
            return
        }
    }
    t.Log("No failures in 10000 trials")
}
