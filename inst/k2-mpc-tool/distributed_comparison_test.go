package main

import (
	"math"
	"testing"
)

// TestDistributedComparison validates that the distributed comparison protocol
// produces correct results for [x < threshold] on secret-shared x.
func TestDistributedComparison(t *testing.T) {
	rp := DefaultRingParams()

	// Test values: mix of positive, negative, near-boundary
	testX := []float64{-5.0, -1.5, -0.5, 0.0, 0.3, 0.99, 1.0, 2.5, 10.0}
	n := len(testX)

	// Secret-share the values
	xFP := rp.VecFromDoubles(testX)
	x0, x1 := rp.SplitVecShare(xFP)

	// Thresholds: the 6 sigmoid interval boundaries
	lfLn2 := float64(rp.NumFractionalBits) * math.Ln2
	thresholdsFloat := []float64{0.0, 1.0, lfLn2}
	thresholds := make([]uint64, len(thresholdsFloat))
	for i, tf := range thresholdsFloat {
		thresholds[i] = rp.FromDouble(tf)
	}

	// Generate preprocessing
	p0Preproc, p1Preproc := CmpPreprocessBatch(rp, n, thresholds)

	// Round 1: each party computes masked values
	p0R1 := CmpRound1(rp, 0, x0, p0Preproc)
	p1R1 := CmpRound1(rp, 1, x1, p1Preproc)

	// Round 2: each party evaluates DCF using own + peer's masked values
	p0Result := CmpRound2(0, p0Preproc, p0R1, p1R1)
	p1Result := CmpRound2(1, p1Preproc, p1R1, p0R1)

	// Verify: sum of shares should equal the comparison result
	for j, tf := range thresholdsFloat {
		for i, xv := range testX {
			bit0 := int(p0Result.BitShares[j][i])
			bit1 := int(p1Result.BitShares[j][i])
			got := (bit0 + bit1) % 2
			// Handle negative mod
			if got < 0 {
				got += 2
			}

			want := 0
			if xv < tf {
				want = 1
			}

			if got != want {
				t.Errorf("[x=%.1f < %.1f]: got %d (shares %d+%d), want %d",
					xv, tf, got, bit0, bit1, want)
			} else {
				t.Logf("[x=%.1f < %.1f] = %d ✓", xv, tf, got)
			}
		}
	}
}

// TestDistributedComparisonLargeN tests with realistic n=155 elements.
func TestDistributedComparisonLargeN(t *testing.T) {
	rp := DefaultRingParams()
	n := 155

	// Generate random eta values in [-3, 3] (standardized data range)
	testX := make([]float64, n)
	for i := range testX {
		// Deterministic pseudo-random for reproducibility
		testX[i] = math.Sin(float64(i)*1.37) * 3.0
	}

	xFP := rp.VecFromDoubles(testX)
	x0, x1 := rp.SplitVecShare(xFP)

	// All 6 sigmoid boundaries
	lfLn2 := float64(rp.NumFractionalBits) * math.Ln2
	thresholdsFloat := []float64{0.0, 1.0, lfLn2}
	thresholds := make([]uint64, len(thresholdsFloat))
	for i, tf := range thresholdsFloat {
		thresholds[i] = rp.FromDouble(tf)
	}

	p0Preproc, p1Preproc := CmpPreprocessBatch(rp, n, thresholds)
	p0R1 := CmpRound1(rp, 0, x0, p0Preproc)
	p1R1 := CmpRound1(rp, 1, x1, p1Preproc)
	p0Result := CmpRound2(0, p0Preproc, p0R1, p1R1)
	p1Result := CmpRound2(1, p1Preproc, p1R1, p0R1)

	errors := 0
	for j, tf := range thresholdsFloat {
		for i, xv := range testX {
			bit0 := int(p0Result.BitShares[j][i])
			bit1 := int(p1Result.BitShares[j][i])
			got := (bit0 + bit1) % 2
			if got < 0 {
				got += 2
			}

			want := 0
			if xv < tf {
				want = 1
			}

			if got != want {
				errors++
				if errors <= 5 {
					t.Errorf("[x=%.4f < %.1f]: got %d, want %d", xv, tf, got, want)
				}
			}
		}
	}

	total := n * len(thresholds)
	t.Logf("Distributed comparison: %d/%d correct (%.1f%%)", total-errors, total, 100*float64(total-errors)/float64(total))
	if errors > 0 {
		t.Errorf("Total errors: %d/%d", errors, total)
	}
}
