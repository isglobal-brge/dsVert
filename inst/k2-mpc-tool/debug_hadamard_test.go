package main

import (
	"testing"
)

// TestHadamardZeroTimesLarge checks if Beaver Hadamard gives exactly 0
// when one factor (indicator) is 0 and the other (branch) is very large.
func TestHadamardZeroTimesLarge(t *testing.T) {
	rp := DefaultRingParams()
	n := 5

	// Indicator: exactly 0 (as Ring63 shares)
	zeroFP := rp.FromDouble(0.0)
	ind0 := make([]uint64, n)
	ind1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		ind0[i], ind1[i] = rp.SplitShare(zeroFP) // shares of 0
	}

	// Branch: various large values
	largeVals := []float64{100, 1000, 1e6, 1e9, 1e12}
	br0 := make([]uint64, n)
	br1 := make([]uint64, n)
	for i, v := range largeVals {
		fp := rp.FromDouble(v)
		br0[i], br1[i] = rp.SplitShare(fp)
	}

	// Beaver Hadamard
	t0, t1 := GenerateBeaverTriples(rp, n)
	msg0 := BeaverMulRound1(rp, ind0, br0, t0)
	msg1 := BeaverMulRound1(rp, ind1, br1, t1)
	raw0 := BeaverMulRound2(rp, msg0, msg1, t0, 0)
	raw1 := BeaverMulRound2(rp, msg1, msg0, t1, 1)
	trunc0 := rp.TruncateVecShare(raw0, 0)
	trunc1 := rp.TruncateVecShare(raw1, 1)

	for i, v := range largeVals {
		product := rp.ToDouble(rp.ModAdd(trunc0[i], trunc1[i]))
		t.Logf("0 × %.0e = %.10f (should be 0)", v, product)
		if product != 0 {
			t.Errorf("0 × %.0e = %f, not 0!", v, product)
		}
	}
}

// TestHadamardOneTimesValue checks 1 × value = value.
func TestHadamardOneTimesValue(t *testing.T) {
	rp := DefaultRingParams()
	vals := []float64{0.5, 0.88, 0.001, 0.95, 1094.5}
	n := len(vals)

	// Indicator: FracMultiplier (= 1.0 in FP)
	ind0 := make([]uint64, n)
	ind1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		ind0[i], ind1[i] = rp.SplitShare(rp.FracMultiplier)
	}

	br0 := make([]uint64, n)
	br1 := make([]uint64, n)
	for i, v := range vals {
		fp := rp.FromDouble(v)
		br0[i], br1[i] = rp.SplitShare(fp)
	}

	t0, t1 := GenerateBeaverTriples(rp, n)
	msg0 := BeaverMulRound1(rp, ind0, br0, t0)
	msg1 := BeaverMulRound1(rp, ind1, br1, t1)
	raw0 := BeaverMulRound2(rp, msg0, msg1, t0, 0)
	raw1 := BeaverMulRound2(rp, msg1, msg0, t1, 1)
	trunc0 := rp.TruncateVecShare(raw0, 0)
	trunc1 := rp.TruncateVecShare(raw1, 1)

	for i, v := range vals {
		product := rp.ToDouble(rp.ModAdd(trunc0[i], trunc1[i]))
		t.Logf("1 × %.4f = %.10f (err=%.2e)", v, product, product-v)
	}
}
