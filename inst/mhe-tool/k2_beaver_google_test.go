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

func TestScalarVectorProductGoogle(t *testing.T) {
	r := NewRing63(20)

	// Test: multiply scalar 2.5 by shared vector [1.0, -1.0, 0.5, -0.3]
	scalar := 2.5
	vals := []float64{1.0, -1.0, 0.5, -0.3}
	expected := []float64{2.5, -2.5, 1.25, -0.75}

	n := len(vals)
	x := make([]uint64, n)
	x0 := make([]uint64, n)
	x1 := make([]uint64, n)
	for i, v := range vals {
		x[i] = r.FromDouble(v)
		x0[i], x1[i] = r.SplitShare(x[i])
	}

	res0 := ScalarVectorProductPartyZero(scalar, x0, r)
	res1 := ScalarVectorProductPartyOne(scalar, x1, r)

	for i := range expected {
		result := r.ToDouble(r.Add(res0[i], res1[i]))
		err := math.Abs(result - expected[i])
		if err > 0.001 {
			t.Errorf("SVP[%d]: %.1f * %.1f = %.4f, want %.4f (err %.2e)",
				i, scalar, vals[i], result, expected[i], err)
		}
	}
	t.Log("ScalarVectorProduct: PASS")
}

func TestScalarVectorProductNegativeScalar(t *testing.T) {
	r := NewRing63(20)

	scalar := -0.5
	vals := []float64{2.0, -3.0, 0.0, 1.5}
	expected := []float64{-1.0, 1.5, 0.0, -0.75}

	n := len(vals)
	x := make([]uint64, n)
	x0 := make([]uint64, n)
	x1 := make([]uint64, n)
	for i, v := range vals {
		x[i] = r.FromDouble(v)
		x0[i], x1[i] = r.SplitShare(x[i])
	}

	res0 := ScalarVectorProductPartyZero(scalar, x0, r)
	res1 := ScalarVectorProductPartyOne(scalar, x1, r)

	for i := range expected {
		result := r.ToDouble(r.Add(res0[i], res1[i]))
		err := math.Abs(result - expected[i])
		if err > 0.001 {
			t.Errorf("SVP[%d]: %.1f * %.1f = %.4f, want %.4f",
				i, scalar, vals[i], result, expected[i])
		}
	}
	t.Log("ScalarVectorProduct (negative scalar): PASS")
}

func TestBeaverMatvecLocal(t *testing.T) {
	// Test: Z = X^T * r where X is 5x3, r is 5x1
	// X = [[1,2,3],[4,5,6],[7,8,9],[10,11,12],[13,14,15]]
	// r = [1, -1, 0.5, -0.5, 2]
	// Z = X^T * r = [1*1+4*(-1)+7*0.5+10*(-0.5)+13*2, ...] = [1-4+3.5-5+26, 2-5+4-5.5+28, 3-6+4.5-6+30]
	//   = [21.5, 23.5, 25.5]

	n := 5
	p := 3
	X := []float64{1,2,3, 4,5,6, 7,8,9, 10,11,12, 13,14,15}
	r := []float64{1, -1, 0.5, -0.5, 2}
	expected := []float64{21.5, 23.5, 25.5}

	// Split into shares
	x0 := make([]float64, n*p)
	x1 := make([]float64, n*p)
	r0 := make([]float64, n)
	r1 := make([]float64, n)
	for i := range X {
		x0[i] = float64(int(cryptoRandUint64K2()%2000)-1000) / 100.0
		x1[i] = X[i] - x0[i]
	}
	for i := range r {
		r0[i] = float64(int(cryptoRandUint64K2()%2000)-1000) / 100.0
		r1[i] = r[i] - r0[i]
	}

	// Generate Beaver triple: A (n*p), B (n), C (p) where C[j] = sum_i A[i,j]*B[i]
	A := make([]float64, n*p)
	B := make([]float64, n)
	for i := range A { A[i] = float64(int(cryptoRandUint64K2()%2000)-1000) / 100.0 }
	for i := range B { B[i] = float64(int(cryptoRandUint64K2()%2000)-1000) / 100.0 }
	C := make([]float64, p)
	for j := 0; j < p; j++ {
		for i := 0; i < n; i++ {
			C[j] += A[i*p+j] * B[i]
		}
	}

	// Split triples
	a0 := make([]float64, n*p); a1 := make([]float64, n*p)
	b0 := make([]float64, n); b1 := make([]float64, n)
	c0 := make([]float64, p); c1 := make([]float64, p)
	for i := range A { a0[i] = float64(int(cryptoRandUint64K2()%2000)-1000)/100; a1[i] = A[i]-a0[i] }
	for i := range B { b0[i] = float64(int(cryptoRandUint64K2()%2000)-1000)/100; b1[i] = B[i]-b0[i] }
	for i := range C { c0[i] = float64(int(cryptoRandUint64K2()%2000)-1000)/100; c1[i] = C[i]-c0[i] }

	// Round 1
	xma0 := make([]float64, n*p); rmb0 := make([]float64, n)
	xma1 := make([]float64, n*p); rmb1 := make([]float64, n)
	for i := range x0 { xma0[i] = x0[i] - a0[i] }
	for i := range r0 { rmb0[i] = r0[i] - b0[i] }
	for i := range x1 { xma1[i] = x1[i] - a1[i] }
	for i := range r1 { rmb1[i] = r1[i] - b1[i] }

	// Round 2
	// Reconstruct full (X-A) and (r-B)
	fullXMA := make([]float64, n*p)
	fullRMB := make([]float64, n)
	for i := range fullXMA { fullXMA[i] = xma0[i] + xma1[i] }
	for i := range fullRMB { fullRMB[i] = rmb0[i] + rmb1[i] }

	// Party 0
	g0 := make([]float64, p)
	copy(g0, c0)
	for j := 0; j < p; j++ {
		for i := 0; i < n; i++ { g0[j] += a0[i*p+j]*fullRMB[i] + fullXMA[i*p+j]*b0[i] + fullXMA[i*p+j]*fullRMB[i] }
	}

	// Party 1
	g1 := make([]float64, p)
	copy(g1, c1)
	for j := 0; j < p; j++ {
		for i := 0; i < n; i++ { g1[j] += a1[i*p+j]*fullRMB[i] + fullXMA[i*p+j]*b1[i] }
	}

	// Reconstruct
	gradient := make([]float64, p)
	for j := 0; j < p; j++ { gradient[j] = g0[j] + g1[j] }

	t.Logf("Expected: %v", expected)
	t.Logf("Got:      %v", gradient)

	maxErr := 0.0
	for j := 0; j < p; j++ {
		err := math.Abs(gradient[j] - expected[j])
		if err > maxErr { maxErr = err }
	}
	t.Logf("Max error: %.2e", maxErr)

	if maxErr > 0.01 {
		t.Errorf("Beaver matvec error %.2e exceeds 0.01", maxErr)
	}
}
