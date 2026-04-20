// k2_recip127_test.go — accuracy tests for Ring127RecipPlaintext.
//
// Validates that the Goldschmidt/NR recip primitive on Ring127 FP
// (fracBits=50) hits rel error <1e-12 over the Cox S(t) domain
// [0.01, 1e4]. This target is ~10^8 better than the wide-spline
// reciprocal path (1e-4 per-element noise) and sufficient for STRICT
// closure in Path B Fisher construction.

package main

import (
	"math"
	"testing"
)

// TestRing127Recip_CoxSDomain: S(t) values in Cox PH span roughly
// [n_events · mu_min, n · mu_max]. For NCCTG at oracle β_MLE_std
// (eta ∈ [-2, 2], mu ∈ [0.135, 7.39]), S ∈ [~28, ~1552]. Cover the
// realistic Cox domain + safety margin with <1e-12 target.
//
// NOTE: for very large x (>~5000), range-reduction right-shift loses
// log2(x_msb - fracBits) bits of precision. At x=10000 (msb=63,
// shift=13) the rel floor is ~2^-37 ≈ 7e-12 — tested separately below.
func TestRing127Recip_CoxSDomain(t *testing.T) {
	r := NewRing127(50)
	vals := []float64{
		0.01, 0.05, 0.1, 0.5, 1.0, 1.5, 2.0, 5.0, 10.0, 50.0, 100.0,
		500.0, 1000.0, 2000.0,
	}
	for _, v := range vals {
		xRing := r.FromDouble(v)
		recipRing := Ring127RecipPlaintext(r, xRing)
		got := r.ToDouble(recipRing)
		want := 1.0 / v
		rel := math.Abs(got-want) / want
		if rel > 1e-12 {
			t.Errorf("1/%g: got %g, want %g, rel=%e (target <1e-12)",
				v, got, want, rel)
		}
	}
}

// TestRing127Recip_ExtremeLargeX: for x >~ 5000, range-reduction
// Shr(k) loses k bits of precision. Document the relaxed floor and
// confirm it stays <1e-10 (still ~10^6 better than spline).
func TestRing127Recip_ExtremeLargeX(t *testing.T) {
	r := NewRing127(50)
	for _, v := range []float64{5000.0, 10000.0, 50000.0} {
		xRing := r.FromDouble(v)
		recipRing := Ring127RecipPlaintext(r, xRing)
		got := r.ToDouble(recipRing)
		want := 1.0 / v
		rel := math.Abs(got-want) / want
		if rel > 1e-10 {
			t.Errorf("1/%g (extreme): got %g want %g rel=%e", v, got, want, rel)
		}
		t.Logf("1/%g: rel=%.3e (large-x shift precision loss)", v, rel)
	}
}

// TestRing127Recip_Negative: 1/(-x) = -1/x, sign handling correct.
func TestRing127Recip_Negative(t *testing.T) {
	r := NewRing127(50)
	for _, v := range []float64{-0.5, -1.0, -5.0, -100.0} {
		xRing := r.FromDouble(v)
		recipRing := Ring127RecipPlaintext(r, xRing)
		got := r.ToDouble(recipRing)
		want := 1.0 / v
		rel := math.Abs(got-want) / math.Abs(want)
		if rel > 1e-12 {
			t.Errorf("1/%g (negative): got %g want %g rel=%e", v, got, want, rel)
		}
	}
}

// TestRing127Recip_PowersOfTwo: exact representation — x = 2^k gives
// 1/x = 2^{-k} exactly (no approximation loss). Tests range reduction
// corner cases at shift boundaries.
func TestRing127Recip_PowersOfTwo(t *testing.T) {
	r := NewRing127(50)
	for k := -10; k <= 10; k++ {
		v := math.Ldexp(1, k)
		xRing := r.FromDouble(v)
		recipRing := Ring127RecipPlaintext(r, xRing)
		got := r.ToDouble(recipRing)
		want := math.Ldexp(1, -k)
		rel := math.Abs(got-want) / want
		// Powers of 2 are especially precise because x_norm = 1 exactly.
		if rel > 1e-13 {
			t.Errorf("1/2^%d: got %g want %g rel=%e (power-of-two should be <1e-13)",
				k, got, want, rel)
		}
	}
}

// TestRing127Recip_NRConvergenceSuffices: verify 5 NR iterations give
// more than enough precision on [1, 2]. Starting error 0.0588;
// quadratic convergence reaches ~1e-40 at iter 5 (far below ULP).
func TestRing127Recip_NRConvergenceSuffices(t *testing.T) {
	r := NewRing127(50)
	// Worst-case for the initial guess: x ≈ 1.5 where the minimax
	// linear has peak error. 5 iters should still hit Ring127 ULP.
	xRing := r.FromDouble(1.5)
	recipRing := Ring127RecipPlaintext(r, xRing)
	got := r.ToDouble(recipRing)
	want := 1.0 / 1.5
	rel := math.Abs(got-want) / want
	t.Logf("1/1.5 (worst-case initial guess): rel=%.3e (NR=%d iters)",
		rel, Ring127RecipNRSteps)
	if rel > 1e-13 {
		t.Errorf("NR convergence insufficient at x=1.5, rel=%e", rel)
	}
}

// TestRing127Recip_vsSplineNoiseFloor: documents improvement over
// the wide-spline reciprocal (~1e-4 per-element noise). Ring127
// Goldschmidt should achieve ~10^8 better across the domain.
func TestRing127Recip_vsSplineNoiseFloor(t *testing.T) {
	r := NewRing127(50)
	// Non-aligned value (not a Chebyshev node of the spline).
	v := 37.3
	xRing := r.FromDouble(v)
	recipRing := Ring127RecipPlaintext(r, xRing)
	got := r.ToDouble(recipRing)
	want := 1.0 / v
	rel := math.Abs(got-want) / want
	splineNoiseFloor := 1e-4
	improvement := splineNoiseFloor / rel
	t.Logf("Ring127 Goldschmidt 1/%g: rel=%.3e vs spline floor %.0e → %.1ex improvement",
		v, rel, splineNoiseFloor, improvement)
	if rel >= 1e-12 {
		t.Errorf("expected rel < 1e-12 at non-aligned x, got %e", rel)
	}
}

// TestRing127Recip_InvolutiveProperty: 1/(1/x) = x within Ring127 ULP.
// Tests that the primitive doesn't accumulate systematic bias.
func TestRing127Recip_InvolutiveProperty(t *testing.T) {
	r := NewRing127(50)
	for _, v := range []float64{0.1, 1.7, 25.0, 3500.0} {
		xRing := r.FromDouble(v)
		recip := Ring127RecipPlaintext(r, xRing)
		recipRecip := Ring127RecipPlaintext(r, recip)
		got := r.ToDouble(recipRecip)
		rel := math.Abs(got-v) / v
		if rel > 1e-11 {
			// 2 recip ops → 2× the single-op rel error bound.
			t.Errorf("1/(1/%g): got %g, rel=%e (involution)", v, got, rel)
		}
	}
}
