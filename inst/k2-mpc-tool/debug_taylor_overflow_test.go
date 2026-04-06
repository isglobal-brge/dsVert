package main

import (
	"testing"
)

func TestTaylorOverflow(t *testing.T) {
	rp := DefaultRingParams()

	// Simulate what happens when ExpTaylorSigmoidLocal is called with x=-2.0
	// It negates to +2.0, then Kelkar exp(+2.0) = 7.389
	// Then Taylor polynomial on shares of 7.389

	// Create shares of 7.389 (what exp(2.0) gives)
	zFP := rp.VecFromDoubles([]float64{7.389056099})
	z0, z1 := rp.SplitVecShare(zFP)

	t.Logf("z shares: z0=%d, z1=%d, sum=%.6f", z0[0], z1[0], rp.ToDouble(rp.ModAdd(z0[0], z1[0])))

	// Taylor coefficients: [1, -1, 1, -1, ..., -1, 1] degree 10
	taylorCoeffs := make([]float64, 11)
	for k := 0; k <= 10; k++ {
		if k%2 == 0 { taylorCoeffs[k] = 1 } else { taylorCoeffs[k] = -1 }
	}

	p0, p1 := SecurePolyEval(rp, taylorCoeffs, z0, z1)
	taylorVal := rp.ToDouble(rp.ModAdd(p0[0], p1[0]))
	t.Logf("Taylor(7.389) on shares = %.6f (should diverge to some large value)", taylorVal)
	t.Logf("p0=%d, p1=%d", p0[0], p1[0])

	// Now test Hadamard: 0 × taylorVal
	indFP := rp.FromDouble(0.0)
	ind0 := []uint64{0}
	ind1 := []uint64{0}
	ind0[0], ind1[0] = rp.SplitShare(indFP)

	t0, t1 := GenerateBeaverTriples(rp, 1)
	m0 := BeaverMulRound1(rp, ind0, p0, t0)
	m1 := BeaverMulRound1(rp, ind1, p1, t1)
	r0 := BeaverMulRound2(rp, m0, m1, t0, 0)
	r1 := BeaverMulRound2(rp, m1, m0, t1, 1)
	tr0 := rp.TruncateShareP0(r0[0])
	tr1 := rp.TruncateShareP1(r1[0])
	product := rp.ToDouble(rp.ModAdd(tr0, tr1))
	t.Logf("0 × Taylor(7.389) via Hadamard = %.10f (should be 0)", product)

	// Test with REAL indicator shares (from distributed comparison, not simple split)
	// The indicator for I1 when x=-2.0 should be exactly 0, but its shares are random Ring63 values
	t.Log("Now with 'real' zero indicator (random shares summing to 0):")
	r := cryptoRandUint64() % rp.Modulus
	realInd0 := []uint64{r}
	realInd1 := []uint64{rp.ModSub(0, r)} // sum = 0
	// Scale to FP
	realInd0[0] = rp.ModMul(realInd0[0], rp.FracMultiplier)
	realInd1[0] = rp.ModMul(realInd1[0], rp.FracMultiplier)
	t.Logf("Real ind0=%d, ind1=%d, sum=%d", realInd0[0], realInd1[0], rp.ModAdd(realInd0[0], realInd1[0]))

	t0b, t1b := GenerateBeaverTriples(rp, 1)
	m0b := BeaverMulRound1(rp, realInd0, p0, t0b)
	m1b := BeaverMulRound1(rp, realInd1, p1, t1b)
	r0b := BeaverMulRound2(rp, m0b, m1b, t0b, 0)
	r1b := BeaverMulRound2(rp, m1b, m0b, t1b, 1)
	tr0b := rp.TruncateShareP0(r0b[0])
	tr1b := rp.TruncateShareP1(r1b[0])
	product2 := rp.ToDouble(rp.ModAdd(tr0b, tr1b))
	t.Logf("realZero × Taylor(7.389) via Hadamard = %.10f (should be 0)", product2)
}
