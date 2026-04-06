package main

import (
	"math"
	"testing"
)

// TestBranchSelectionAccuracy checks if indicator × branch_result
// produces correct results via Beaver Hadamard.
func TestBranchSelectionAccuracy(t *testing.T) {
	rp := DefaultRingParams()

	// Create indicator shares: indicator = 1 for element 0, 0 for element 1
	ind0 := []uint64{rp.FracMultiplier, 0} // Party 0 shares (FP 1.0 and 0.0)
	ind1 := []uint64{0, 0}                  // Party 1 shares

	// Branch result: both elements have value 0.7 in FP
	brFP := rp.FromDouble(0.7)
	br0 := []uint64{brFP, brFP} // Party 0
	br1 := []uint64{0, 0}       // Party 1

	// Beaver Hadamard: indicator * branch
	t0, t1 := GenerateBeaverTriples(rp, 2)
	msg0 := BeaverMulRound1(rp, ind0, br0, t0)
	msg1 := BeaverMulRound1(rp, ind1, br1, t1)
	raw0 := BeaverMulRound2(rp, msg0, msg1, t0, 0)
	raw1 := BeaverMulRound2(rp, msg1, msg0, t1, 1)
	trunc0 := rp.TruncateVecShare(raw0, 0)
	trunc1 := rp.TruncateVecShare(raw1, 1)

	for i := 0; i < 2; i++ {
		val := rp.ToDouble(rp.ModAdd(trunc0[i], trunc1[i]))
		t.Logf("Element %d: indicator=%.0f, branch=0.7, product=%.6f",
			i, rp.ToDouble(rp.ModAdd(ind0[i], ind1[i])), val)
	}
}

// TestSigmoidBranchIsolation checks mixed-interval vectors.
func TestSigmoidBranchIsolation(t *testing.T) {
	rp := DefaultRingParams()

	testX := []float64{0.5, -0.5, 2.0, -2.0, 15.0}
	xFP := rp.VecFromDoubles(testX)
	x0, x1 := rp.SplitVecShare(xFP)

	mu0, mu1 := DistributedSigmoidLocal(rp, x0, x1)

	for i, x := range testX {
		got := rp.ToDouble(rp.ModAdd(mu0[i], mu1[i]))
		want := 1.0 / (1.0 + math.Exp(-x))
		err := math.Abs(got - want)
		t.Logf("x=%5.1f: got=%.8f want=%.8f err=%.2e", x, got, want, err)
		if err > 0.01 {
			t.Errorf("x=%.1f: error %.2e too large", x, err)
		}
	}
}
