package main

import (
	"math"
	"testing"
)

// TestSigmoidStepByStep traces through the full sigmoid for x=-2.0.
func TestSigmoidStepByStep(t *testing.T) {
	rp := DefaultRingParams()
	x := -2.0

	xFP := rp.VecFromDoubles([]float64{x})
	x0, x1 := rp.SplitVecShare(xFP)

	// Verify shares
	t.Logf("x shares: x0=%d, x1=%d, sum=%.6f", x0[0], x1[0], rp.ToDouble(rp.ModAdd(x0[0], x1[0])))

	// 1. Broad comparisons
	lfLn2 := float64(rp.NumFractionalBits) * math.Ln2
	thresholds := []uint64{
		rp.FromDouble(-lfLn2), rp.FromDouble(-1.0), rp.FromDouble(0.0),
		rp.FromDouble(1.0), rp.FromDouble(lfLn2),
	}
	cmpP0, cmpP1 := CmpPreprocessBatch(rp, 1, thresholds)
	r1_0 := CmpRound1(rp, 0, x0, cmpP0)
	r1_1 := CmpRound1(rp, 1, x1, cmpP1)
	cmp0 := CmpRound2(0, cmpP0, r1_0, r1_1)
	cmp1 := CmpRound2(1, cmpP1, r1_1, r1_0)

	thNames := []string{"-L", "-1", "0", "1", "L"}
	for j := 0; j < 5; j++ {
		sum := rp.ModAdd(cmp0.ArithShares[j][0], cmp1.ArithShares[j][0])
		t.Logf("c[%s] = %d (%.6f)", thNames[j], sum, rp.ToDouble(sum))
	}

	// 2. Indicators via Beaver
	var indP0, indP1 [4]BeaverTriple
	for k := 0; k < 4; k++ {
		indP0[k], indP1[k] = GenerateBeaverTriples(rp, 1)
	}

	// NOT + Beaver for 4 AND gates
	notC := func(shares []uint64, pid int) []uint64 {
		r := make([]uint64, 1)
		if pid == 0 { r[0] = rp.ModSub(1, shares[0]) } else { r[0] = rp.ModSub(0, shares[0]) }
		return r
	}

	type andPair struct{ a0, b0, a1, b1 []uint64; name string }
	pairs := []andPair{
		{notC(cmp0.ArithShares[2], 0), cmp0.ArithShares[3], notC(cmp1.ArithShares[2], 1), cmp1.ArithShares[3], "I0=NOT(c2)*c3"},
		{notC(cmp0.ArithShares[3], 0), cmp0.ArithShares[4], notC(cmp1.ArithShares[3], 1), cmp1.ArithShares[4], "I1=NOT(c3)*c4"},
		{notC(cmp0.ArithShares[0], 0), cmp0.ArithShares[1], notC(cmp1.ArithShares[0], 1), cmp1.ArithShares[1], "I4=NOT(c0)*c1"},
		{notC(cmp0.ArithShares[1], 0), cmp0.ArithShares[2], notC(cmp1.ArithShares[1], 1), cmp1.ArithShares[2], "I5=NOT(c1)*c2"},
	}

	andVals := make([]uint64, 4)
	for k, p := range pairs {
		m0 := BeaverMulRound1(rp, p.a0, p.b0, indP0[k])
		m1 := BeaverMulRound1(rp, p.a1, p.b1, indP1[k])
		r0 := BeaverMulRound2(rp, m0, m1, indP0[k], 0)
		r1 := BeaverMulRound2(rp, m1, m0, indP1[k], 1)
		andVals[k] = rp.ModAdd(r0[0], r1[0])
		t.Logf("%s = %d (%.6f)", p.name, andVals[k], rp.ToDouble(andVals[k]))
	}

	// NOT(c4) for I2, c0 for I3
	notC4 := rp.ModAdd(
		rp.ModSub(1, cmp0.ArithShares[4][0]),
		rp.ModSub(0, cmp1.ArithShares[4][0]))
	t.Logf("I2=NOT(c4) = %d (%.6f)", notC4, rp.ToDouble(notC4))
	i3 := rp.ModAdd(cmp0.ArithShares[0][0], cmp1.ArithShares[0][0])
	t.Logf("I3=c0 = %d (%.6f)", i3, rp.ToDouble(i3))

	// The indicators should be: I4=1, all others=0 for x=-2.0
	t.Logf("Sum of all indicators: %d",
		rp.ModAdd(rp.ModAdd(rp.ModAdd(andVals[0], andVals[1]), rp.ModAdd(notC4, i3)),
			rp.ModAdd(andVals[2], andVals[3])))
}
