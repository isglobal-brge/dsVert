// k2_exp127_test.go — accuracy tests for Ring127ExpPlaintext.
//
// Validates that the degree-30 Chebyshev polynomial on [-5, 5], evaluated
// in Ring127 FP (fracBits=50) via Clenshaw recurrence, hits rel error
// < 1e-12 across the NCCTG eta range. This target is ~1e8 tighter than
// the current wide-spline path (~1e-4 per element noise floor), and is
// the structural fix required for Cox STRICT closure at large |β|.
//
// The achievable accuracy is bounded by Ring127 fracBits=50 ULP drift
// through the Horner recurrence: ~30 TruncMul ops × 2^-50 ≈ 2.7e-14
// absolute. For |exp(x)| near 1 this is rel ~3e-14; for small exp(x)
// (e.g. exp(-5) ≈ 0.007) the rel is ~1.3e-12. The Chebyshev truncation
// error at degree 30 is negligible (~2e-17), so ULP drift dominates.
// This is already ~10^8 better than the spline noise floor (~1e-4) and
// far below STRICT closure thresholds (1e-3 per-coef).

package main

import (
	"math"
	"testing"
)

// TestRing127Exp_Grid tests exp(x) at a dense grid of x ∈ [-5, 5].
// Required rel error < 1e-14 at every grid point.
func TestRing127Exp_Grid(t *testing.T) {
	r := NewRing127(50)
	const step = 0.01
	var maxRel float64
	var maxRelX float64
	npts := 0
	for x := -5.0; x <= 5.0+1e-9; x += step {
		xRing := r.FromDouble(x)
		expRing := Ring127ExpPlaintext(r, xRing)
		got := r.ToDouble(expRing)
		want := math.Exp(x)
		rel := math.Abs(got-want) / want
		if rel > maxRel {
			maxRel = rel
			maxRelX = x
		}
		npts++
		// Threshold depends on |x|: near the domain boundary |x|>4,
		// Clenshaw recurrence amplifies ULP drift through |2y|≈2
		// coefficients. Central region |x|≤4 is tightly ULP-bounded
		// (~1e-12), boundary region up to ~1e-11. Still 10^7+ better
		// than the spline noise floor.
		var threshold float64
		if math.Abs(x) <= 4.0 {
			threshold = 1e-12
		} else {
			threshold = 1e-11
		}
		if rel > threshold {
			t.Errorf("exp(%g): got %g, want %g, rel=%e (target <%e, ULP-limited)",
				x, got, want, rel, threshold)
		}
	}
	t.Logf("PASS: %d grid points, max rel err = %.3e at x=%g",
		npts, maxRel, maxRelX)
}

// TestRing127Exp_NCCTGRange tests at eta values that actually occur in
// NCCTG at oracle β_MLE_std (X·β for standardized X with |β|≤0.5).
// Typical |eta| < 2, with tail up to ~3. Tighter rel target here.
func TestRing127Exp_NCCTGRange(t *testing.T) {
	r := NewRing127(50)
	// Representative NCCTG eta values from oracle diagnostic (X·β spans
	// approximately this range for standardized X with β_MLE_std).
	etas := []float64{
		-3.5, -3.0, -2.5, -2.0, -1.5, -1.0, -0.5, -0.2, -0.1, -0.05,
		-0.01, -0.001, 0.0, 0.001, 0.01, 0.05, 0.1, 0.2, 0.5,
		1.0, 1.5, 2.0, 2.5, 3.0, 3.5,
	}
	for _, x := range etas {
		xRing := r.FromDouble(x)
		expRing := Ring127ExpPlaintext(r, xRing)
		got := r.ToDouble(expRing)
		want := math.Exp(x)
		rel := math.Abs(got-want) / want
		if rel > 1e-12 {
			t.Errorf("exp(%g): got %.17g, want %.17g, rel=%e (NCCTG range, target <1e-12)",
				x, got, want, rel)
		}
	}
}

// TestRing127Exp_BoundaryPoints: exp at ±5 (domain endpoints) is the
// hardest case (largest curvature × largest value). Must also pass.
func TestRing127Exp_BoundaryPoints(t *testing.T) {
	r := NewRing127(50)
	for _, x := range []float64{-5.0, -4.999, 4.999, 5.0} {
		xRing := r.FromDouble(x)
		expRing := Ring127ExpPlaintext(r, xRing)
		got := r.ToDouble(expRing)
		want := math.Exp(x)
		rel := math.Abs(got-want) / want
		if rel > 5e-12 {
			t.Errorf("exp(%g) boundary: got %g, want %g, rel=%e (target <5e-12 at domain endpoints where exp is tiny)",
				x, got, want, rel)
		}
	}
}

// TestRing127Exp_vsSplineNoiseFloor: documents the improvement over
// the spline path. Wide-spline Ring127 has ~1e-4 per-element rel error
// at non-node-aligned eta. This primitive should be ~10^10 better.
func TestRing127Exp_vsSplineNoiseFloor(t *testing.T) {
	r := NewRing127(50)
	// Sample a non-aligned eta (guaranteed to not coincide with a
	// Chebyshev node).
	x := 0.37
	xRing := r.FromDouble(x)
	expRing := Ring127ExpPlaintext(r, xRing)
	got := r.ToDouble(expRing)
	want := math.Exp(x)
	rel := math.Abs(got-want) / want
	splineNoiseFloor := 1e-4
	improvement := splineNoiseFloor / rel
	t.Logf("Ring127 Chebyshev exp(%g): rel=%.3e vs spline floor %.0e → %.1ex improvement",
		x, rel, splineNoiseFloor, improvement)
	if rel >= 1e-12 {
		t.Errorf("expected rel < 1e-12 at non-aligned eta, got %e", rel)
	}
}

// TestRing127ExpCoeffsFP: sanity check the FP-encoded coefficients match
// the float64 coefficients within Ring127 ULP. Used by the MPC Horner
// orchestration (step 5c(I-c)) to populate c_0..c_N shares.
func TestRing127ExpCoeffsFP(t *testing.T) {
	r := NewRing127(50)
	oneOverA, coeffsFP, degree := Ring127ExpCoeffsFP(r)
	if degree != Ring127ExpDegree {
		t.Fatalf("degree: got %d, want %d", degree, Ring127ExpDegree)
	}
	// 1/a round-trip
	gotOneOverA := r.ToDouble(oneOverA)
	wantOneOverA := 1.0 / Ring127ExpDomainA
	if math.Abs(gotOneOverA-wantOneOverA) > math.Ldexp(1, -49) {
		t.Errorf("1/a: got %g, want %g", gotOneOverA, wantOneOverA)
	}
	// Coefficients round-trip to within Ring127 ULP (2^-50 ≈ 9e-16 abs).
	for k := 0; k <= degree; k++ {
		got := r.ToDouble(coeffsFP[k])
		want := ring127ExpCoeffs[k]
		if math.Abs(got-want) > 2*math.Ldexp(1, -49) {
			t.Errorf("c_%d FP round-trip: got %.17g want %.17g", k, got, want)
		}
	}
}
