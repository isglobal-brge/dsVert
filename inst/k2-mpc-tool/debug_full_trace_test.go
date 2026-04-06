package main

import (
	"math"
	"testing"
)

func TestFullSigmoidTrace(t *testing.T) {
	rp := DefaultRingParams()
	x := -2.0
	n := 1

	xFP := rp.VecFromDoubles([]float64{x})
	x0, x1 := rp.SplitVecShare(xFP)

	preproc := SigmoidDistPreprocessGen(rp, n)

	// Manually replicate DistributedSigmoidLocal with prints

	// R1: Broad comparison masking
	broadP0R1 := CmpRound1(rp, 0, x0, preproc.BroadCmpP0)
	broadP1R1 := CmpRound1(rp, 1, x1, preproc.BroadCmpP1)

	// R2: DCF eval
	broadP0Cmp := CmpRound2(0, preproc.BroadCmpP0, broadP0R1, broadP1R1)
	broadP1Cmp := CmpRound2(1, preproc.BroadCmpP1, broadP1R1, broadP0R1)

	// Verify comparisons
	for j := 0; j < 5; j++ {
		s := rp.ModAdd(broadP0Cmp.ArithShares[j][0], broadP1Cmp.ArithShares[j][0])
		t.Logf("c[%d] sum = %d", j, s)
	}

	// AND indicators
	broadAND0R1 := broadIndicatorANDR1(rp, 0, n, broadP0Cmp, preproc.IndHadP0[:])
	broadAND1R1 := broadIndicatorANDR1(rp, 1, n, broadP1Cmp, preproc.IndHadP1[:])
	broadInd0 := broadIndicatorANDR2(rp, 0, n, broadP0Cmp, preproc.IndHadP0[:], broadAND0R1, broadAND1R1)
	broadInd1 := broadIndicatorANDR2(rp, 1, n, broadP1Cmp, preproc.IndHadP1[:], broadAND1R1, broadAND0R1)

	for k := 0; k < 6; k++ {
		s := rp.ModAdd(broadInd0[k][0], broadInd1[k][0])
		t.Logf("Indicator[%d] sum = %d (should be 0 or 1)", k, s)
	}

	// Scale to FP
	for k := 0; k < 6; k++ {
		broadInd0[k][0] = rp.ModMul(broadInd0[k][0], rp.FracMultiplier)
		broadInd1[k][0] = rp.ModMul(broadInd1[k][0], rp.FracMultiplier)
	}

	for k := 0; k < 6; k++ {
		s := rp.ModAdd(broadInd0[k][0], broadInd1[k][0])
		t.Logf("IndicatorFP[%d] sum = %d (should be 0 or FracMul=%d)", k, s, rp.FracMultiplier)
	}

	// Build branches (simplified - just use constant values for diagnosis)
	branches := [6]float64{
		0.932, // I0: spline garbage for x=-2
		0.881, // I1: expTaylor for x=-2 (negated → exp(+2) → diverge)
		1.0,   // I2
		0.0,   // I3
		0.119, // I4: correct value
		0.5,   // I5: spline garbage for x=-2
	}

	br0 := [6][]uint64{}
	br1 := [6][]uint64{}
	for k := 0; k < 6; k++ {
		brFP := rp.FromDouble(branches[k])
		br0[k] = []uint64{0}
		br1[k] = []uint64{0}
		br0[k][0], br1[k][0] = rp.SplitShare(brFP)
	}

	// Hadamard for each branch
	mu0Sum := uint64(0)
	mu1Sum := uint64(0)
	for k := 0; k < 6; k++ {
		t0, t1 := GenerateBeaverTriples(rp, 1)
		m0 := BeaverMulRound1(rp, broadInd0[k][:1], br0[k], t0)
		m1 := BeaverMulRound1(rp, broadInd1[k][:1], br1[k], t1)
		r0 := BeaverMulRound2(rp, m0, m1, t0, 0)
		r1 := BeaverMulRound2(rp, m1, m0, t1, 1)
		tr0 := rp.TruncateShareP0(r0[0])
		tr1 := rp.TruncateShareP1(r1[0])
		prod := rp.ToDouble(rp.ModAdd(tr0, tr1))
		mu0Sum = rp.ModAdd(mu0Sum, tr0)
		mu1Sum = rp.ModAdd(mu1Sum, tr1)
		t.Logf("Branch %d: ind_fp=%d × branch=%.3f → product=%.8f", k,
			rp.ModAdd(broadInd0[k][0], broadInd1[k][0]),
			branches[k], prod)
	}

	final := rp.ToDouble(rp.ModAdd(mu0Sum, mu1Sum))
	want := 1.0 / (1.0 + math.Exp(-x))
	t.Logf("Final sigmoid(%.1f) = %.8f (want %.8f, err=%.2e)", x, final, want, math.Abs(final-want))
}
