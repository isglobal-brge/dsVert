package main

import (
    "testing"
)

func TestDCFFailRate(t *testing.T) {
    numBits := 63
    
    // Test DCF for a specific comparison: [m < alpha]
    // where alpha and m are close together
    fails := 0; N := 10000
    for trial := 0; trial < N; trial++ {
        // Random alpha and m where m < alpha (should return 1)
        alpha := cryptoRandUint64K2() % (uint64(1) << 63)
        // m = alpha - small_delta
        delta := cryptoRandUint64K2() % 1000 + 1
        if alpha < delta { continue }
        m := alpha - delta
        
        key0, key1 := DCFGen(alpha, 1, numBits)
        v0 := DCFEval(0, key0, m)
        v1 := DCFEval(1, key1, m)
        sum := v0 + v1
        if sum != 1 {
            fails++
            if fails <= 3 {
                t.Logf("FAIL: alpha=%d m=%d delta=%d sum=%d", alpha, m, delta, sum)
            }
        }
    }
    t.Logf("DCF [m < alpha] (TRUE case): %d/%d failures = %.2f%%", fails, N, 100*float64(fails)/float64(N))

    // Test DCF for m >= alpha (should return 0)
    fails2 := 0
    for trial := 0; trial < N; trial++ {
        alpha := cryptoRandUint64K2() % (uint64(1) << 63)
        delta := cryptoRandUint64K2() % 1000 + 1
        m := (alpha + delta) % (uint64(1) << 63)
        
        key0, key1 := DCFGen(alpha, 1, numBits)
        v0 := DCFEval(0, key0, m)
        v1 := DCFEval(1, key1, m)
        sum := v0 + v1
        if sum != 0 {
            fails2++
            if fails2 <= 3 {
                t.Logf("FAIL: alpha=%d m=%d delta=%d sum=%d", alpha, m, delta, sum)
            }
        }
    }
    t.Logf("DCF [m >= alpha] (FALSE case): %d/%d failures = %.2f%%", fails2, N, 100*float64(fails2)/float64(N))
}
