package main

import (
	"math"
	"testing"
)

func TestBeaverElementwiseMul(t *testing.T) {
	rp := DefaultRingParams()

	X := rp.VecFromDoubles([]float64{2.0, -3.0, 0.5})
	Y := rp.VecFromDoubles([]float64{4.0, 2.0, -1.0})
	expected := []float64{8.0, -6.0, -0.5}

	x0, x1 := rp.SplitVecShare(X)
	y0, y1 := rp.SplitVecShare(Y)
	t0, t1 := GenerateBeaverTriples(rp, 3)

	z0, z1 := BeaverFixedPointMul(rp, x0, y0, x1, y1, t0, t1)

	Z := rp.ReconstructVecShare(z0, z1)
	got := rp.VecToDoubles(Z)

	for i, want := range expected {
		if math.Abs(got[i]-want) > 0.01 {
			t.Errorf("BeaverMul[%d] = %f, want %f (diff %e)", i, got[i], want, got[i]-want)
		}
	}
	t.Logf("Results: %v (want %v)", got, expected)
}

func TestBeaverMulAccuracy(t *testing.T) {
	rp := DefaultRingParams()

	n := 200
	xDoubles := make([]float64, n)
	yDoubles := make([]float64, n)
	for i := 0; i < n; i++ {
		xDoubles[i] = float64(int(cryptoRandUint64()%2000)-1000) / 100.0
		yDoubles[i] = float64(int(cryptoRandUint64()%2000)-1000) / 100.0
	}

	X := rp.VecFromDoubles(xDoubles)
	Y := rp.VecFromDoubles(yDoubles)
	x0, x1 := rp.SplitVecShare(X)
	y0, y1 := rp.SplitVecShare(Y)
	t0, t1 := GenerateBeaverTriples(rp, n)

	z0, z1 := BeaverFixedPointMul(rp, x0, y0, x1, y1, t0, t1)

	Z := rp.ReconstructVecShare(z0, z1)
	got := rp.VecToDoubles(Z)

	maxErr := 0.0
	for i := 0; i < n; i++ {
		want := xDoubles[i] * yDoubles[i]
		err := math.Abs(got[i] - want)
		if err > maxErr {
			maxErr = err
		}
		if err > 0.01 {
			t.Errorf("BeaverMul[%d]: %f * %f = %f, want %f (err %e)",
				i, xDoubles[i], yDoubles[i], got[i], want, err)
		}
	}
	t.Logf("Beaver elementwise mul: max error = %.2e over %d tests", maxErr, n)
}

func TestBeaverMulZero(t *testing.T) {
	rp := DefaultRingParams()

	X := rp.VecFromDoubles([]float64{5.0, -3.0, 0.0})
	Y := rp.VecFromDoubles([]float64{0.0, 0.0, 0.0})

	x0, x1 := rp.SplitVecShare(X)
	y0, y1 := rp.SplitVecShare(Y)
	t0, t1 := GenerateBeaverTriples(rp, 3)

	z0, z1 := BeaverFixedPointMul(rp, x0, y0, x1, y1, t0, t1)

	Z := rp.ReconstructVecShare(z0, z1)
	got := rp.VecToDoubles(Z)
	for i, v := range got {
		if math.Abs(v) > 0.01 {
			t.Errorf("BeaverMul[%d] * 0 = %f, want 0", i, v)
		}
	}
}

func TestBeaverMulNegatives(t *testing.T) {
	rp := DefaultRingParams()

	tests := [][3]float64{
		{-2.0, 3.0, -6.0},
		{-2.0, -3.0, 6.0},
		{1.5, -2.5, -3.75},
		{0.001, 1000.0, 1.0},
		{-0.5, -0.5, 0.25},
	}

	for _, tc := range tests {
		X := rp.VecFromDoubles([]float64{tc[0]})
		Y := rp.VecFromDoubles([]float64{tc[1]})
		x0, x1 := rp.SplitVecShare(X)
		y0, y1 := rp.SplitVecShare(Y)
		t0, t1 := GenerateBeaverTriples(rp, 1)

		z0, z1 := BeaverFixedPointMul(rp, x0, y0, x1, y1, t0, t1)
		Z := rp.ReconstructVecShare(z0, z1)
		got := rp.ToDouble(Z[0])

		if math.Abs(got-tc[2]) > 0.01 {
			t.Errorf("BeaverMul(%f, %f) = %f, want %f (diff %e)",
				tc[0], tc[1], got, tc[2], got-tc[2])
		}
	}
}
