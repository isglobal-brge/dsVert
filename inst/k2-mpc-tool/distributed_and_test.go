package main

import (
	"math"
	"testing"
)

// TestIntervalIndicators validates the full distributed comparison + AND pipeline.
// For each test value, checks that exactly ONE interval indicator is 1.
func TestIntervalIndicators(t *testing.T) {
	rp := DefaultRingParams()
	lfLn2 := float64(rp.NumFractionalBits) * math.Ln2

	// Test values covering all 6 intervals
	testCases := []struct {
		x        float64
		wantInterval int // 0-5
	}{
		{0.5, 0},    // I0: 0 <= x < 1 (spline)
		{0.0, 0},    // I0: boundary (0 is in [0,1))
		{0.99, 0},   // I0: near boundary
		{1.0, 1},    // I1: 1 <= x < L (exp+Taylor)
		{5.0, 1},    // I1: medium positive
		{13.0, 1},   // I1: near L boundary
		{14.0, 2},   // I2: x >= L (saturate 1) — L≈13.86
		{20.0, 2},   // I2: large positive
		{-20.0, 3},  // I3: x < -L (saturate 0)
		{-14.0, 3},  // I3: large negative
		{-5.0, 4},   // I4: -L <= x < -1 (1 - exp+Taylor)
		{-1.5, 4},   // I4: medium negative
		{-1.0, 5},   // I5: -1 <= x < 0 (1 - spline) — boundary
		{-0.5, 5},   // I5: small negative
		{-0.01, 5},  // I5: near zero negative
	}

	n := len(testCases)
	testX := make([]float64, n)
	for i, tc := range testCases {
		testX[i] = tc.x
	}

	// Secret-share
	xFP := rp.VecFromDoubles(testX)
	x0, x1 := rp.SplitVecShare(xFP)

	// 5 comparison thresholds (sorted by their signed value: -L, -1, 0, 1, L)
	thresholds := []uint64{
		rp.FromDouble(-lfLn2), // -L (in Ring63: large value near Modulus)
		rp.FromDouble(-1.0),   // -1
		rp.FromDouble(0.0),    // 0
		rp.FromDouble(1.0),    // 1
		rp.FromDouble(lfLn2),  // L
	}

	// --- Comparison phase (2 rounds) ---
	p0CmpPrep, p1CmpPrep := CmpPreprocessBatch(rp, n, thresholds)
	p0R1 := CmpRound1(rp, 0, x0, p0CmpPrep)
	p1R1 := CmpRound1(rp, 1, x1, p1CmpPrep)
	p0Cmp := CmpRound2(0, p0CmpPrep, p0R1, p1R1)
	p1Cmp := CmpRound2(1, p1CmpPrep, p1R1, p0R1)

	// --- AND phase (1 round) ---
	andPrep := IntervalPreprocessBatch(n)
	p0ANDMsg := IntervalIndicatorR1(0, n, p0Cmp.BitShares, andPrep.P0Triples)
	p1ANDMsg := IntervalIndicatorR1(1, n, p1Cmp.BitShares, andPrep.P1Triples)
	p0Ind := IntervalIndicatorR2(0, n, p0Cmp.BitShares, andPrep.P0Triples, p0ANDMsg, p1ANDMsg)
	p1Ind := IntervalIndicatorR2(1, n, p1Cmp.BitShares, andPrep.P1Triples, p1ANDMsg, p0ANDMsg)

	// --- Verify ---
	errors := 0
	for i, tc := range testCases {
		// Reconstruct indicators
		indicators := make([]int, 6)
		activeCount := 0
		activeInterval := -1
		for k := 0; k < 6; k++ {
			bit := (int(p0Ind[k][i]) + int(p1Ind[k][i])) % 2
			if bit < 0 {
				bit += 2
			}
			indicators[k] = bit
			if bit == 1 {
				activeCount++
				activeInterval = k
			}
		}

		if activeCount != 1 {
			t.Errorf("x=%.2f: %d active indicators (want exactly 1): %v", tc.x, activeCount, indicators)
			errors++
		} else if activeInterval != tc.wantInterval {
			t.Errorf("x=%.2f: active interval %d, want %d. indicators=%v", tc.x, activeInterval, tc.wantInterval, indicators)
			errors++
		} else {
			t.Logf("x=%6.2f → I%d ✓", tc.x, activeInterval)
		}
	}

	if errors > 0 {
		t.Errorf("Total interval errors: %d/%d", errors, n)
	}
}
