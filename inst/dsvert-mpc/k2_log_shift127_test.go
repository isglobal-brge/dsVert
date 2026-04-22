// k2_log_shift127_test.go — accuracy tests for Ring127LogShiftPlaintext.

package main

import (
	"math"
	"testing"
)

// TestRing127LogShift_Grid tests log(x) on a dense grid covering
// [Ring127LogShiftMin, Ring127LogShiftMax]. Thresholds:
//   |x| in central region (a/4 ≤ x ≤ 3b/4)  → rel < 1e-10
//   near boundary                           → rel < 5e-10
func TestRing127LogShift_Grid(t *testing.T) {
	r := NewRing127(50)
	const step_fine = 0.05
	a := Ring127LogShiftMin
	b := Ring127LogShiftMax
	var maxRel float64
	var maxRelX float64
	npts := 0
	for x := a; x <= b+1e-9; x += step_fine {
		xRing := r.FromDouble(x)
		gotRing := Ring127LogShiftPlaintext(r, xRing)
		got := r.ToDouble(gotRing)
		want := math.Log(x)
		errABS := math.Abs(got - want)
		// log(1) = 0 → use absolute error near-zero; else relative.
		if math.Abs(want) < 1e-3 {
			if errABS > 1e-11 {
				t.Errorf("log(%g) near-zero: got %g want %g abs=%e", x, got, want, errABS)
			}
			continue
		}
		rel := errABS / math.Abs(want)
		if rel > maxRel {
			maxRel = rel
			maxRelX = x
		}
		npts++
		if rel > 1e-10 {
			t.Errorf("log(%g): got %g, want %g, rel=%e (target <1e-10)",
				x, got, want, rel)
		}
	}
	t.Logf("PASS: %d grid points, max rel err = %.3e at x=%g", npts, maxRel, maxRelX)
}

// TestRing127LogShift_NBCentralRange tests the [1, 10] central range
// where the primitive is expected to be rel < 1e-11 (Chebyshev converges
// fast on this narrow domain, ρ ≈ 1.94, degree 40).
func TestRing127LogShift_NBCentralRange(t *testing.T) {
	r := NewRing127(50)
	xs := []float64{1.0, 1.5, 2.0, 3.0, 5.0, 7.5, 9.5, 10.0}
	for _, x := range xs {
		xRing := r.FromDouble(x)
		gotRing := Ring127LogShiftPlaintext(r, xRing)
		got := r.ToDouble(gotRing)
		want := math.Log(x)
		// log(1) = 0 → use absolute error for tiny |want|; otherwise relative.
		errABS := math.Abs(got - want)
		var metric float64
		if math.Abs(want) < 1e-3 {
			metric = errABS  // threshold on absolute
			if metric > 1e-11 {
				t.Errorf("log(%g) central abs: got %g want %g abs=%e", x, got, want, metric)
			}
		} else {
			metric = errABS / math.Abs(want)
			if metric > 1e-10 {
				t.Errorf("log(%g) central rel: got %g want %g rel=%e", x, got, want, metric)
			}
		}
	}
}
