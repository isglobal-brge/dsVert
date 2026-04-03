package main

import (
	"math"
	"testing"
)

func TestFromFloat64RoundTrip(t *testing.T) {
	fracBits := 20
	values := []float64{0.0, 1.0, -1.0, 3.14159, -2.71828, 100.5, -0.001}
	for _, v := range values {
		fp := FromFloat64(v, fracBits)
		got := fp.ToFloat64(fracBits)
		eps := 1.0 / float64(int64(1)<<fracBits) // ~1e-6
		if math.Abs(got-v) > eps {
			t.Errorf("FromFloat64(%f).ToFloat64() = %f, want %f (eps=%e)", v, got, v, eps)
		}
	}
}

func TestFPAdd(t *testing.T) {
	fracBits := 20
	a := FromFloat64(1.5, fracBits)
	b := FromFloat64(2.3, fracBits)
	got := FPAdd(a, b).ToFloat64(fracBits)
	want := 3.8
	if math.Abs(got-want) > 1e-5 {
		t.Errorf("FPAdd(1.5, 2.3) = %f, want %f", got, want)
	}
}

func TestFPSub(t *testing.T) {
	fracBits := 20
	a := FromFloat64(5.0, fracBits)
	b := FromFloat64(3.2, fracBits)
	got := FPSub(a, b).ToFloat64(fracBits)
	want := 1.8
	if math.Abs(got-want) > 1e-5 {
		t.Errorf("FPSub(5.0, 3.2) = %f, want %f", got, want)
	}
}

func TestFPMulLocal(t *testing.T) {
	fracBits := 20
	tests := []struct {
		a, b, want float64
	}{
		{2.0, 3.0, 6.0},
		{-1.5, 4.0, -6.0},
		{0.5, 0.5, 0.25},
		{100.0, 0.01, 1.0},
		{-3.0, -2.0, 6.0},
	}
	for _, tc := range tests {
		fa := FromFloat64(tc.a, fracBits)
		fb := FromFloat64(tc.b, fracBits)
		got := FPMulLocal(fa, fb, fracBits).ToFloat64(fracBits)
		eps := 1e-4 // multiplication has slightly larger error
		if math.Abs(got-tc.want) > eps {
			t.Errorf("FPMulLocal(%f, %f) = %f, want %f", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestFPNeg(t *testing.T) {
	fracBits := 20
	a := FromFloat64(3.14, fracBits)
	got := FPNeg(a).ToFloat64(fracBits)
	want := -3.14
	if math.Abs(got-want) > 1e-5 {
		t.Errorf("FPNeg(3.14) = %f, want %f", got, want)
	}
}

func TestFPDotProduct(t *testing.T) {
	fracBits := 20
	a := FloatVecToFP([]float64{1.0, 2.0, 3.0}, fracBits)
	b := FloatVecToFP([]float64{4.0, 5.0, 6.0}, fracBits)
	got := FPDotProduct(a, b, fracBits).ToFloat64(fracBits)
	want := 32.0 // 1*4 + 2*5 + 3*6
	if math.Abs(got-want) > 1e-3 {
		t.Errorf("FPDotProduct = %f, want %f", got, want)
	}
}

func TestFPVecOps(t *testing.T) {
	fracBits := 20
	a := FloatVecToFP([]float64{1.0, 2.0, 3.0}, fracBits)
	b := FloatVecToFP([]float64{0.5, 1.5, 2.5}, fracBits)

	sum := FPVecToFloat(FPVecAdd(a, b), fracBits)
	for i, want := range []float64{1.5, 3.5, 5.5} {
		if math.Abs(sum[i]-want) > 1e-5 {
			t.Errorf("FPVecAdd[%d] = %f, want %f", i, sum[i], want)
		}
	}

	diff := FPVecToFloat(FPVecSub(a, b), fracBits)
	for i, want := range []float64{0.5, 0.5, 0.5} {
		if math.Abs(diff[i]-want) > 1e-5 {
			t.Errorf("FPVecSub[%d] = %f, want %f", i, diff[i], want)
		}
	}
}

func TestFPFromInt(t *testing.T) {
	fracBits := 20
	fp := FPFromInt(42, fracBits)
	got := fp.ToFloat64(fracBits)
	if got != 42.0 {
		t.Errorf("FPFromInt(42) = %f, want 42.0", got)
	}
}
