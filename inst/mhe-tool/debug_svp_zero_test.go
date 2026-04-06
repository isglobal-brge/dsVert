package main

import (
    "testing"
)

func TestScalarVPZeroIndicator(t *testing.T) {
    ring := NewRing63(20)
    
    // Indicator = 0: shares sum to 0
    // Test with different slopes and random shares
    slopes := []float64{0.2498, 0.2485, 0.2461, 0.2425, 0.2377, 0.2320, 0.2253, 0.2179, 0.2098, 0.2011}
    
    totalBias := 0.0
    N := 100
    for trial := 0; trial < N; trial++ {
        // Random shares that sum to 0
        s0 := cryptoRandUint64K2() % ring.Modulus
        s1 := ring.Sub(0, s0)

        // Scale to FP (indicator = 0 * FracMul = 0 in FP, but shares are random)
        s0_fp := modMulBig63(s0, ring.FracMul, ring.Modulus)
        s1_fp := modMulBig63(s1, ring.FracMul, ring.Modulus)

        sumProduct := uint64(0)
        for _, slope := range slopes {
            sv0 := ScalarVectorProductPartyZero(slope, []uint64{s0_fp}, ring)
            sv1 := ScalarVectorProductPartyOne(slope, []uint64{s1_fp}, ring)
            sumProduct = ring.Add(sumProduct, ring.Add(sv0[0], sv1[0]))
        }
        val := ring.ToDouble(sumProduct)
        totalBias += val
    }
    t.Logf("Mean sum of 10 ScalarVP(slopes, zero_indicator): %.2e (should be ~0)", totalBias/float64(N))
}
