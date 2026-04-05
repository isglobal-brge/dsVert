package main

import (
	"math"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	rp := DefaultRingParams() // 63 bits, 20 frac
	tests := []float64{0.0, 1.0, -1.0, 3.14159, -2.71828, 0.001, -0.001, 100.5, -100.5}
	for _, x := range tests {
		fp := rp.FromDouble(x)
		got := rp.ToDouble(fp)
		if math.Abs(got-x) > 1e-5 {
			t.Errorf("RoundTrip(%f): got %f, diff %e", x, got, got-x)
		}
	}
}

func TestModAdd(t *testing.T) {
	rp := DefaultRingParams()
	a := rp.FromDouble(1.5)
	b := rp.FromDouble(2.3)
	got := rp.ToDouble(rp.ModAdd(a, b))
	if math.Abs(got-3.8) > 1e-5 {
		t.Errorf("ModAdd(1.5, 2.3) = %f, want 3.8", got)
	}
}

func TestModSub(t *testing.T) {
	rp := DefaultRingParams()
	a := rp.FromDouble(3.0)
	b := rp.FromDouble(1.5)
	got := rp.ToDouble(rp.ModSub(a, b))
	if math.Abs(got-1.5) > 1e-5 {
		t.Errorf("ModSub(3.0, 1.5) = %f, want 1.5", got)
	}
	// Negative result
	got2 := rp.ToDouble(rp.ModSub(b, a))
	if math.Abs(got2-(-1.5)) > 1e-5 {
		t.Errorf("ModSub(1.5, 3.0) = %f, want -1.5", got2)
	}
}

func TestModNeg(t *testing.T) {
	rp := DefaultRingParams()
	a := rp.FromDouble(5.0)
	neg := rp.ModNeg(a)
	got := rp.ToDouble(neg)
	if math.Abs(got-(-5.0)) > 1e-5 {
		t.Errorf("ModNeg(5.0) = %f, want -5.0", got)
	}
	// Double negation
	got2 := rp.ToDouble(rp.ModNeg(neg))
	if math.Abs(got2-5.0) > 1e-5 {
		t.Errorf("ModNeg(ModNeg(5.0)) = %f, want 5.0", got2)
	}
}

func TestTruncMulFP(t *testing.T) {
	rp := DefaultRingParams()
	tests := [][3]float64{
		{2.0, 3.0, 6.0},
		{-2.0, 3.0, -6.0},
		{-2.0, -3.0, 6.0},
		{0.5, 0.5, 0.25},
		{1.5, 2.5, 3.75},
		{-1.5, 2.5, -3.75},
		{0.001, 1000.0, 1.0},
	}
	for _, tc := range tests {
		a := rp.FromDouble(tc[0])
		b := rp.FromDouble(tc[1])
		got := rp.ToDouble(rp.TruncMulFP(a, b))
		if math.Abs(got-tc[2]) > 1e-3 {
			t.Errorf("TruncMulFP(%f, %f) = %f, want %f (diff %e)",
				tc[0], tc[1], got, tc[2], got-tc[2])
		}
	}
}

func TestShareSplitReconstruct(t *testing.T) {
	rp := DefaultRingParams()
	values := []float64{1.5, -3.7, 0.0, 100.0, -0.001}
	for _, x := range values {
		fp := rp.FromDouble(x)
		s0, s1 := rp.SplitShare(fp)
		reconstructed := rp.ReconstructShare(s0, s1)
		got := rp.ToDouble(reconstructed)
		if math.Abs(got-x) > 1e-5 {
			t.Errorf("Share split/reconstruct(%f): got %f", x, got)
		}
	}
}

func TestVecShareSplitReconstruct(t *testing.T) {
	rp := DefaultRingParams()
	xs := []float64{1.0, -2.0, 3.5, -0.5, 0.0}
	fps := rp.VecFromDoubles(xs)
	s0, s1 := rp.SplitVecShare(fps)
	rec := rp.ReconstructVecShare(s0, s1)
	got := rp.VecToDoubles(rec)
	for i, x := range xs {
		if math.Abs(got[i]-x) > 1e-5 {
			t.Errorf("VecShare[%d]: got %f, want %f", i, got[i], x)
		}
	}
}

func TestVecDot(t *testing.T) {
	rp := DefaultRingParams()
	a := rp.VecFromDoubles([]float64{1.0, 2.0, 3.0})
	b := rp.VecFromDoubles([]float64{4.0, 5.0, 6.0})
	got := rp.ToDouble(rp.VecDot(a, b))
	want := 1.0*4.0 + 2.0*5.0 + 3.0*6.0 // 32.0
	if math.Abs(got-want) > 0.01 {
		t.Errorf("VecDot = %f, want %f", got, want)
	}
}

func TestMatVecMul(t *testing.T) {
	rp := DefaultRingParams()
	// 2x3 matrix [[1,2,3],[4,5,6]]
	M := rp.VecFromDoubles([]float64{1, 2, 3, 4, 5, 6})
	v := rp.VecFromDoubles([]float64{1, 1, 1})
	result := rp.MatVecMul(M, 2, 3, v)
	got := rp.VecToDoubles(result)
	if math.Abs(got[0]-6.0) > 0.01 || math.Abs(got[1]-15.0) > 0.01 {
		t.Errorf("MatVecMul = [%f, %f], want [6, 15]", got[0], got[1])
	}
}

func TestIsNegative(t *testing.T) {
	rp := DefaultRingParams()
	if rp.IsNegative(rp.FromDouble(5.0)) {
		t.Error("5.0 should not be negative")
	}
	if !rp.IsNegative(rp.FromDouble(-5.0)) {
		t.Error("-5.0 should be negative")
	}
	if rp.IsNegative(rp.FromDouble(0.0)) {
		t.Error("0.0 should not be negative")
	}
}
