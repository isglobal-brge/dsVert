package main

import (
    "fmt"
    "math"
    "testing"
)

func TestCaptureFailingShares(t *testing.T) {
    rp := DefaultRingParams()
    x := -0.5
    xFP := rp.VecFromDoubles([]float64{x})
    
    for trial := 0; trial < 1000; trial++ {
        x0, x1 := rp.SplitVecShare(xFP)
        e0, e1 := KelkarExpLocalV2(rp, x0, x1)
        got := rp.ToDouble(rp.ModAdd(e0[0], e1[0]))
        want := math.Exp(x)
        if math.Abs(got - want) > 0.01 {
            fmt.Printf("FAIL trial %d: x0=%d x1=%d got=%.6f want=%.6f\n", trial, x0[0], x1[0], got, want)
            t.Logf("Captured: x0=%d x1=%d", x0[0], x1[0])
            
            // Now trace through the computation
            q := kelkarPrimeQ
            log2eFP := kelkarFromDouble(kelkarLog2Ev2)
            b2Bound := int(math.Ceil(kelkarLog2Ev2*float64(kelkarExpBound))) + 1
            adderFP := uint64(b2Bound) * kelkarFracMul
            
            // P0
            base2_p0 := kelkarTruncMul(x0[0], log2eFP)
            posBase2_p0 := kelkarAdd(base2_p0, adderFP)
            intP0 := posBase2_p0 / kelkarFracMul
            fracP0 := float64(posBase2_p0%kelkarFracMul) / float64(kelkarFracMul)
            intInQ_p0 := (intP0 + (q - 1) - kelkarIntRingMod) % (q - 1)
            
            // P1 
            corrBig := new(big.Int).Mul(new(big.Int).SetUint64(log2eFP), new(big.Int).SetUint64(kelkarModulus))
            corrBig.Div(corrBig, new(big.Int).SetUint64(kelkarFracMul))
            corrBig.Mod(corrBig, new(big.Int).SetUint64(kelkarModulus))
            corr := corrBig.Uint64()
            
            firstTerm_p1 := kelkarTruncMul(x1[0], log2eFP)
            base2_p1 := kelkarSub(firstTerm_p1, corr)
            intP1 := base2_p1 / kelkarFracMul
            fracP1 := float64(base2_p1%kelkarFracMul) / float64(kelkarFracMul)
            intInQ_p1 := intP1 % (q - 1)
            
            t.Logf("P0: base2=%d posBase2=%d int=%d frac=%.6f intInQ=%d", base2_p0, posBase2_p0, intP0, fracP0, intInQ_p0)
            t.Logf("P1: firstTerm=%d base2=%d int=%d frac=%.6f intInQ=%d corr=%d", firstTerm_p1, base2_p1, intP1, fracP1, intInQ_p1, corr)
            t.Logf("IntSum: %d + %d = %d (IntRingMod=%d)", intP0, intP1, intP0+intP1, kelkarIntRingMod)
            t.Logf("FracSum: %.6f + %.6f = %.6f (should be actual_frac or 1+actual_frac)", fracP0, fracP1, fracP0+fracP1)
            
            // Expected: x=-0.5, base2 = -0.5 * log2(e) = -0.7213
            // After adder: -0.7213 + 16 = 15.2787
            // int = 15, frac = 0.2787
            t.Logf("Expected: base2=%.4f, after_adder=%.4f, int=15, frac=0.2787", -0.5*kelkarLog2Ev2, -0.5*kelkarLog2Ev2+float64(b2Bound))
            
            return
        }
    }
    t.Log("No failures in 1000 trials")
}
