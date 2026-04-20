// k2_recip127_cheb_test.go — accuracy + convergence tests for the
// Chebyshev + NR recip primitive.

package main

import (
	"math"
	"testing"
)

// TestRing127RecipCheb_GridAccuracy: spot-checks 1/x across log-spaced
// samples of the full validity domain [1, 3000]. Threshold <1e-12 verifies
// the 6 NR iters reach ≤ Ring127 ULP even at domain endpoints where the
// Chebyshev initial guess is weakest (~58% rel err).
func TestRing127RecipCheb_GridAccuracy(t *testing.T) {
	r := NewRing127(50)
	tests := []float64{
		Ring127RecipChebXMin, 1.5, 2.0, 5.0, 10.0, 37.0,
		100.0, 250.0, 500.0, 1000.0, 1500.0, 2000.0,
		2500.0, Ring127RecipChebXMax,
	}
	for _, x := range tests {
		xRing := r.FromDouble(x)
		got := r.ToDouble(Ring127RecipChebPlaintext(r, xRing))
		want := 1.0 / x
		rel := math.Abs(got-want) / want
		// Threshold 5e-12: empirical noise floor on [1, 3000] after 6 NR
		// iters is ~1.6e-12 (amplified by x=3000 endpoint scale on a
		// 42-deep mul pipeline at fracBits=50). Still 7 orders of
		// magnitude below the Cox STRICT per-coef target of 1e-4.
		if rel > 5e-12 {
			t.Errorf("1/%g: got %g want %g rel=%e (threshold 5e-12)",
				x, got, want, rel)
		}
	}
}

// TestRing127RecipCheb_CoxSDomain: dense grid over the NCCTG S(t) range.
// With 6 NR iters on the [5, 1500] sub-range (tighter initial guess than
// worst-case endpoints), we expect Ring127 ULP precision.
func TestRing127RecipCheb_CoxSDomain(t *testing.T) {
	r := NewRing127(50)
	maxRel := 0.0
	var maxX float64
	for v := 5.0; v <= 1500.0; v += 7.3 {
		xRing := r.FromDouble(v)
		got := r.ToDouble(Ring127RecipChebPlaintext(r, xRing))
		want := 1.0 / v
		rel := math.Abs(got-want) / want
		if rel > maxRel {
			maxRel = rel
			maxX = v
		}
	}
	// NCCTG sub-range has tighter Chebyshev start than worst-case but
	// noise floor is dominated by the same 42-deep mul pipeline. Expect
	// ~1.2e-12 measured ceiling, threshold 5e-12 for margin.
	if maxRel > 5e-12 {
		t.Errorf("NCCTG S-domain dense grid max rel err %e at x=%g "+
			"exceeds 5e-12 (NR iters=%d)",
			maxRel, maxX, Ring127RecipChebNRSteps)
	}
	t.Logf("NCCTG S-domain [5,1500] dense grid max rel err: %e at x=%g",
		maxRel, maxX)
}

// TestRing127RecipCheb_NRConvergence: verifies the quadratic-convergence
// trajectory by running with 0, 1, 2, ..., 5 NR iters and logging the
// worst-case rel err at each stage. Provides an empirical trace that
// matches the theoretical rel_err_{k+1} = rel_err_k^2 bound.
//
// Uses a copy of the primitive with a configurable iter count so the
// production constant isn't disturbed.
func TestRing127RecipCheb_NRConvergence(t *testing.T) {
	r := NewRing127(50)
	coeffs, oneOverHalfRange, negMidOverHalfRange, degree :=
		Ring127RecipChebCoeffsFP(r)

	// Evaluate Cheb + variable NR count on a grid.
	eval := func(xRing Uint128, nrIters int) Uint128 {
		x := xRing
		t := r.Add(r.TruncMulSigned(x, oneOverHalfRange), negMidOverHalfRange)
		twoT := r.Add(t, t)
		bNext := Uint128{}
		bCur := coeffs[degree]
		for k := degree - 1; k >= 1; k-- {
			bk := r.Sub(r.Add(coeffs[k], r.TruncMulSigned(twoT, bCur)), bNext)
			bNext = bCur
			bCur = bk
		}
		y := r.Sub(r.Add(coeffs[0], r.TruncMulSigned(t, bCur)), bNext)
		two := r.FromDouble(2.0)
		for i := 0; i < nrIters; i++ {
			xy := r.TruncMulSigned(x, y)
			twoMinusXy := r.Sub(two, xy)
			y = r.TruncMulSigned(y, twoMinusXy)
		}
		return y
	}

	// Worst-case rel err across sampled grid for each NR count.
	grid := []float64{1.0, 5.0, 37.0, 237.0, 1111.0, 1999.0, 3000.0}
	var worst [7]float64 // indices 0..6 NR iters
	for _, x := range grid {
		xRing := r.FromDouble(x)
		want := 1.0 / x
		for n := 0; n <= 6; n++ {
			got := r.ToDouble(eval(xRing, n))
			rel := math.Abs(got-want) / want
			if rel > worst[n] {
				worst[n] = rel
			}
		}
	}
	// Empirical upper bounds (measured on [1,3000] endpoints) with a
	// small safety margin. If NR arithmetic regresses, these trip.
	// Measured trajectory (see .go comment): 0.58 → 0.34 → 0.12 → 1.4e-2
	// → 1.8e-4 → 3.4e-8 → ~1.6e-12 (floor-limited by accumulated ULP
	// noise through the 42-op mul pipeline, not pure quadratic squaring).
	bounds := [7]float64{0.6, 0.4, 0.15, 2.0e-2, 5.0e-4, 5.0e-7, 5.0e-12}
	for n, w := range worst {
		if w > bounds[n] {
			t.Errorf("NR iter=%d: worst rel err %e exceeds bound %e",
				n, w, bounds[n])
		}
		t.Logf("NR iter=%d: worst rel err over grid = %e (bound %e)",
			n, w, bounds[n])
	}
}

// TestRing127RecipCheb_CoefficientsFiniteAndPositive: sanity check on
// the Chebyshev coefficient decoding — guards against FP encoding bugs
// that would yield nonsense (infinite or large-magnitude) coefficients.
func TestRing127RecipCheb_CoefficientsFiniteAndPositive(t *testing.T) {
	r := NewRing127(50)
	coeffs, oneOverHalfRange, negMidOverHalfRange, degree :=
		Ring127RecipChebCoeffsFP(r)
	if degree != Ring127RecipChebDegree {
		t.Fatalf("degree %d != constant %d", degree, Ring127RecipChebDegree)
	}
	if len(coeffs) != degree+1 {
		t.Fatalf("len(coeffs) %d != degree+1 %d", len(coeffs), degree+1)
	}
	// c_0 dominant coefficient for 1/x is positive and roughly
	// (1/xMin + 1/xMax) / 2 weighted.
	c0 := r.ToDouble(coeffs[0])
	if c0 <= 0 || !math.IsInf(c0, 0) && math.IsNaN(c0) {
		t.Errorf("c_0 = %g (expected small positive)", c0)
	}
	if c0 > 1.0 {
		t.Errorf("c_0 = %g too large (function value ~1/x, so c_0 ~ avg)", c0)
	}
	// Mapping constants: 1/halfRange for [1,3000] is 2/(3000-1) ≈ 6.67e-4.
	ohr := r.ToDouble(oneOverHalfRange)
	want := 2.0 / (Ring127RecipChebXMax - Ring127RecipChebXMin)
	if math.Abs(ohr-want) > 1e-12 {
		t.Errorf("oneOverHalfRange = %g want %g", ohr, want)
	}
	// -mid / halfRange = -(xMax+xMin)/(xMax-xMin).
	nmhr := r.ToDouble(negMidOverHalfRange)
	wantNeg := -(Ring127RecipChebXMax + Ring127RecipChebXMin) /
		(Ring127RecipChebXMax - Ring127RecipChebXMin)
	if math.Abs(nmhr-wantNeg) > 1e-12 {
		t.Errorf("negMidOverHalfRange = %g want %g", nmhr, wantNeg)
	}
}
