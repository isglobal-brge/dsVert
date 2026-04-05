package main

import (
	"math"
	"testing"
)

func TestHadamardProductGooglePort(t *testing.T) {
	r := NewRing63(20)

	// Test from C++ beaver_protocol_test.cc:
	// X = {0, 0, 0, 1.5, -1.5, 1.5, 1.5, -1.5, -1.5}
	// Y = {0, 1.5, -1.5, 0, 0, 1.5, -1.5, 1.5, -1.5}
	xDoubles := []float64{0, 0, 0, 1.5, -1.5, 1.5, 1.5, -1.5, -1.5}
	yDoubles := []float64{0, 1.5, -1.5, 0, 0, 1.5, -1.5, 1.5, -1.5}

	n := len(xDoubles)
	x := make([]uint64, n)
	y := make([]uint64, n)
	for i := range xDoubles {
		x[i] = r.FromDouble(xDoubles[i])
		y[i] = r.FromDouble(yDoubles[i])
	}

	// Split into shares
	x0 := make([]uint64, n)
	x1 := make([]uint64, n)
	y0 := make([]uint64, n)
	y1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		x0[i], x1[i] = r.SplitShare(x[i])
		y0[i], y1[i] = r.SplitShare(y[i])
	}

	// Hadamard product
	res0, res1 := HadamardProductLocal(x0, y0, x1, y1, 20, r)

	// Verify
	expected := []float64{0, 0, 0, 0, 0, 2.25, -2.25, -2.25, 2.25}
	for i := 0; i < n; i++ {
		result := r.ToDouble(r.Add(res0[i], res1[i]))
		err := math.Abs(result - expected[i])
		if err > 0.01 {
			t.Errorf("Hadamard[%d]: %.4f * %.4f = %.4f, want %.4f (err %.2e)",
				i, xDoubles[i], yDoubles[i], result, expected[i], err)
		}
	}
	t.Log("Hadamard product (Google C++ test values): PASS")
}

func TestHadamardProductRandomLarge(t *testing.T) {
	r := NewRing63(20)

	n := 100
	xDoubles := make([]float64, n)
	yDoubles := make([]float64, n)
	for i := 0; i < n; i++ {
		xDoubles[i] = float64(int(cryptoRandUint64K2()%2000)-1000) / 100.0
		yDoubles[i] = float64(int(cryptoRandUint64K2()%2000)-1000) / 100.0
	}

	x := make([]uint64, n)
	y := make([]uint64, n)
	x0 := make([]uint64, n)
	x1 := make([]uint64, n)
	y0 := make([]uint64, n)
	y1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		x[i] = r.FromDouble(xDoubles[i])
		y[i] = r.FromDouble(yDoubles[i])
		x0[i], x1[i] = r.SplitShare(x[i])
		y0[i], y1[i] = r.SplitShare(y[i])
	}

	res0, res1 := HadamardProductLocal(x0, y0, x1, y1, 20, r)

	maxErr := 0.0
	for i := 0; i < n; i++ {
		result := r.ToDouble(r.Add(res0[i], res1[i]))
		expected := xDoubles[i] * yDoubles[i]
		err := math.Abs(result - expected)
		if err > maxErr {
			maxErr = err
		}
	}
	t.Logf("Hadamard product: max error %.2e over %d random tests", maxErr, n)
	if maxErr > 0.01 {
		t.Errorf("Max error %.2e exceeds 0.01", maxErr)
	}
}
