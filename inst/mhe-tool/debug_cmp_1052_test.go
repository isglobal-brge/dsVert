package main

import (
    "testing"
)

func TestCmpAt1052(t *testing.T) {
    ring := NewRing63(20)
    
    x := 1.052364
    xFP := ring.FromDouble(x)
    
    // Spline threshold 0.9
    threshold := ring.FromDouble(0.9)
    
    fails := 0; N := 1000
    for trial := 0; trial < N; trial++ {
        x0, x1 := ring.SplitShare(xFP)
        
        p0Pre, p1Pre := cmpGeneratePreprocess(ring, 1, threshold)
        p0R1 := cmpRound1(ring, 0, []uint64{x0}, p0Pre)
        p1R1 := cmpRound1(ring, 1, []uint64{x1}, p1Pre)
        p0Res := cmpRound2(ring, 0, p0Pre, p0R1, p1R1)
        p1Res := cmpRound2(ring, 1, p1Pre, p1R1, p0R1)
        
        sum := ring.Add(p0Res.Shares[0], p1Res.Shares[0])
        // x=1.052 > 0.9, so [x < 0.9] should be 0
        if sum != 0 {
            fails++
            if fails <= 3 {
                t.Logf("FAIL trial %d: [1.052 < 0.9] = %d (should be 0)", trial, sum)
                t.Logf("  x0=%d x1=%d sum=%d", x0, x1, ring.Add(x0, x1))
                t.Logf("  p0R1=%d p1R1=%d m=%d", p0R1.Values[0], p1R1.Values[0],
                    ring.Add(p0R1.Values[0], p1R1.Values[0]))
                t.Logf("  p0Res=%d p1Res=%d", p0Res.Shares[0], p1Res.Shares[0])
            }
        }
    }
    t.Logf("[1.052 < 0.9] failure rate: %d/%d = %.1f%%", fails, N, 100*float64(fails)/float64(N))
}
