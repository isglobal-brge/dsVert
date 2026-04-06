package main

import (
	"fmt"
	"math"
	"testing"
)

// TestDebugIndicatorsForX2 traces the indicator computation for the failing case.
func TestDebugIndicatorsForX2(t *testing.T) {
	rp := DefaultRingParams()

	testX := []float64{0.5, -0.5, 2.0, -2.0, 15.0}
	n := len(testX)

	xFP := rp.VecFromDoubles(testX)
	x0, x1 := rp.SplitVecShare(xFP)

	lfLn2 := float64(rp.NumFractionalBits) * math.Ln2
	thresholds := []uint64{
		rp.FromDouble(-lfLn2),
		rp.FromDouble(-1.0),
		rp.FromDouble(0.0),
		rp.FromDouble(1.0),
		rp.FromDouble(lfLn2),
	}

	// Step 1: Comparisons
	broadCmpP0, broadCmpP1 := CmpPreprocessBatch(rp, n, thresholds)
	p0R1 := CmpRound1(rp, 0, x0, broadCmpP0)
	p1R1 := CmpRound1(rp, 1, x1, broadCmpP1)
	p0Cmp := CmpRound2(0, broadCmpP0, p0R1, p1R1)
	p1Cmp := CmpRound2(1, broadCmpP1, p1R1, p0R1)

	// Check comparison results
	threshNames := []string{"-L", "-1", "0", "1", "L"}
	for j := 0; j < 5; j++ {
		for i, x := range testX {
			cmpVal := rp.ToDouble(rp.ModAdd(
				p0Cmp.ArithShares[j][i] % rp.Modulus,
				p1Cmp.ArithShares[j][i] % rp.Modulus))
			bitVal := (int(p0Cmp.BitShares[j][i]) + int(p1Cmp.BitShares[j][i])) % 2
			fmt.Printf("  [x=%.1f < %s]: arith=%.6f, bit=%d\n", x, threshNames[j], cmpVal, bitVal)
		}
	}

	// Step 2: Beaver AND for indicators
	var indHadP0, indHadP1 [4]BeaverTriple
	for k := 0; k < 4; k++ {
		indHadP0[k], indHadP1[k] = GenerateBeaverTriples(rp, n)
	}

	// NOT shares
	notC := func(p0shares, p1shares []uint64, partyID int) []uint64 {
		result := make([]uint64, n)
		shares := p0shares
		if partyID == 1 { shares = p1shares }
		for i := 0; i < n; i++ {
			if partyID == 0 {
				result[i] = rp.ModSub(1, shares[i])
			} else {
				result[i] = rp.ModSub(0, shares[i])
			}
		}
		return result
	}

	// Build AND inputs
	// AND0: NOT(c2) * c3 → I0
	a0_p0 := notC(p0Cmp.ArithShares[2], p1Cmp.ArithShares[2], 0)
	b0_p0 := p0Cmp.ArithShares[3]
	a0_p1 := notC(p0Cmp.ArithShares[2], p1Cmp.ArithShares[2], 1)
	b0_p1 := p1Cmp.ArithShares[3]

	msg0_0 := BeaverMulRound1(rp, a0_p0, b0_p0, indHadP0[0])
	msg0_1 := BeaverMulRound1(rp, a0_p1, b0_p1, indHadP1[0])
	raw0_0 := BeaverMulRound2(rp, msg0_0, msg0_1, indHadP0[0], 0)
	raw0_1 := BeaverMulRound2(rp, msg0_1, msg0_0, indHadP1[0], 1)

	fmt.Println("\nI0 = NOT(c2) * c3:")
	for i, x := range testX {
		val := rp.ToDouble(rp.ModAdd(raw0_0[i], raw0_1[i]))
		fmt.Printf("  x=%.1f: I0=%.6f\n", x, val)
	}

	// AND1: NOT(c3) * c4 → I1
	a1_p0 := notC(p0Cmp.ArithShares[3], p1Cmp.ArithShares[3], 0)
	b1_p0 := p0Cmp.ArithShares[4]
	a1_p1 := notC(p0Cmp.ArithShares[3], p1Cmp.ArithShares[3], 1)
	b1_p1 := p1Cmp.ArithShares[4]

	msg1_0 := BeaverMulRound1(rp, a1_p0, b1_p0, indHadP0[1])
	msg1_1 := BeaverMulRound1(rp, a1_p1, b1_p1, indHadP1[1])
	raw1_0 := BeaverMulRound2(rp, msg1_0, msg1_1, indHadP0[1], 0)
	raw1_1 := BeaverMulRound2(rp, msg1_1, msg1_0, indHadP1[1], 1)

	fmt.Println("\nI1 = NOT(c3) * c4:")
	for i, x := range testX {
		val := rp.ToDouble(rp.ModAdd(raw1_0[i], raw1_1[i]))
		fmt.Printf("  x=%.1f: I1=%.6f\n", x, val)
	}

	// Check: for x=2.0 (index 2), I1 should be 1.0
	t.Logf("I1 for x=2.0: raw0=%d, raw1=%d, sum=%d",
		raw1_0[2], raw1_1[2], rp.ModAdd(raw1_0[2], raw1_1[2]))
}
