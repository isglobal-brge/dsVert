package main

import (
    "testing"
)

func TestScalarVPOneIndicator(t *testing.T) {
    ring := NewRing63(20)
    
    // Indicator = 1: integer shares sum to 1, FP shares sum to FracMul
    slope := 0.24979187478940013
    slopeFP := ring.FromDouble(slope)
    wantFP := slopeFP // ScalarVP(slope, 1_FP) should give exactly slope_FP
    
    sumBias := 0.0
    N := 100
    for trial := 0; trial < N; trial++ {
        // Integer shares that sum to 1
        intS0 := cryptoRandUint64K2() % ring.Modulus
        intS1 := ring.Sub(1, intS0)
        
        // Scale to FP
        s0_fp := modMulBig63(intS0, ring.FracMul, ring.Modulus)
        s1_fp := modMulBig63(intS1, ring.FracMul, ring.Modulus)
        
        sv0 := ScalarVectorProductPartyZero(slope, []uint64{s0_fp}, ring)
        sv1 := ScalarVectorProductPartyOne(slope, []uint64{s1_fp}, ring)
        got := ring.Add(sv0[0], sv1[0])
        
        // Compare with expected
        diff := int64(got) - int64(wantFP)
        sumBias += float64(diff)
        
        if trial < 5 {
            t.Logf("trial %d: got=%d want=%d diff=%d", trial, got, wantFP, diff)
        }
    }
    t.Logf("Mean bias in SVP(slope, 1_FP): %.2f ULP (should be 0)", sumBias/float64(N))
}
