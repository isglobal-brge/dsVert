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

func TestGradientInRing(t *testing.T) {
	// Test: gradient = X^T * (mu - y) where X is 3x2, mu and y are 3x1
	// X = [[1, 2], [3, 4], [5, 6]], mu = [0.5, 0.3, 0.7], y = [1, 0, 1]
	// residual = mu - y = [-0.5, 0.3, -0.3]
	// gradient = X^T * r = [1*(-0.5)+3*0.3+5*(-0.3), 2*(-0.5)+4*0.3+6*(-0.3)]
	//          = [-0.5+0.9-1.5, -1+1.2-1.8] = [-1.1, -1.6]

	n := 3
	p := 2
	fracBits := 20

	X := []float64{1, 2, 3, 4, 5, 6}
	mu := []float64{0.5, 0.3, 0.7}
	y := []float64{1, 0, 1}
	expected := []float64{-1.1, -1.6}

	// Convert to FP and split into shares
	xFP := FloatVecToFP(X, fracBits)
	muFP := FloatVecToFP(mu, fracBits)
	yFP := FloatVecToFP(y, fracBits)

	x0 := make([]FixedPoint, len(xFP))
	x1 := make([]FixedPoint, len(xFP))
	mu0 := make([]FixedPoint, len(muFP))
	mu1 := make([]FixedPoint, len(muFP))
	y0 := make([]FixedPoint, len(yFP))
	y1 := make([]FixedPoint, len(yFP))

	for i := range xFP {
		r := FixedPoint(int64(cryptoRandUint64K2()))
		x0[i] = r; x1[i] = xFP[i] - r
	}
	for i := range muFP {
		r := FixedPoint(int64(cryptoRandUint64K2()))
		mu0[i] = r; mu1[i] = muFP[i] - r
	}
	for i := range yFP {
		r := FixedPoint(int64(cryptoRandUint64K2()))
		y0[i] = r; y1[i] = yFP[i] - r
	}

	// Compute residual shares in ring
	r0 := make([]FixedPoint, n)
	r1 := make([]FixedPoint, n)
	for i := 0; i < n; i++ {
		r0[i] = FPSub(mu0[i], y0[i])
		r1[i] = FPSub(mu1[i], y1[i])
	}

	// Generate Beaver triple: A (n*p), B (n), C (p) where C[j] = sum_i A[i,j]*B[i] / fracMul
	A := make([]FixedPoint, n*p)
	B := make([]FixedPoint, n)
	for i := range A { A[i] = FixedPoint(int64(cryptoRandUint64K2())) }
	for i := range B { B[i] = FixedPoint(int64(cryptoRandUint64K2())) }
	// C = A^T * B using RING multiply (matching C++ ModMul, no truncation)
	r63tmp := NewRing63(fracBits)
	C := make([]FixedPoint, p)
	for j := 0; j < p; j++ {
		var cj uint64
		for i := 0; i < n; i++ {
			cj = r63tmp.Add(cj, modMulBig63(uint64(A[i*p+j])%r63tmp.Modulus, uint64(B[i])%r63tmp.Modulus, r63tmp.Modulus))
		}
		C[j] = FixedPoint(int64(cj))
	}

	// Split triples
	a0 := make([]FixedPoint, n*p); a1 := make([]FixedPoint, n*p)
	b0 := make([]FixedPoint, n); b1 := make([]FixedPoint, n)
	c0 := make([]FixedPoint, p); c1 := make([]FixedPoint, p)
	for i := range A { s := FixedPoint(int64(cryptoRandUint64K2())); a0[i] = s; a1[i] = A[i]-s }
	for i := range B { s := FixedPoint(int64(cryptoRandUint64K2())); b0[i] = s; b1[i] = B[i]-s }
	for i := range C { s := FixedPoint(int64(cryptoRandUint64K2())); c0[i] = s; c1[i] = C[i]-s }

	// Round 1: (X-A, r-B) for each party
	xma0 := make([]FixedPoint, n*p); rmb0 := make([]FixedPoint, n)
	xma1 := make([]FixedPoint, n*p); rmb1 := make([]FixedPoint, n)
	for i := range x0 { xma0[i] = FPSub(x0[i], a0[i]) }
	for i := range r0 { rmb0[i] = FPSub(r0[i], b0[i]) }
	for i := range x1 { xma1[i] = FPSub(x1[i], a1[i]) }
	for i := range r1 { rmb1[i] = FPSub(r1[i], b1[i]) }

	// Round 2: each party computes gradient share
	fullXMA := make([]FixedPoint, n*p)
	fullRMB := make([]FixedPoint, n)
	for i := range fullXMA { fullXMA[i] = FPAdd(xma0[i], xma1[i]) }
	for i := range fullRMB { fullRMB[i] = FPAdd(rmb0[i], rmb1[i]) }

	// Use Ring63 with RING multiply (no per-term truncation) + final truncation.
	// This matches the C++ GenerateBatchedMultiplicationOutputPartyZero/One + TruncateShare.
	r63 := NewRing63(fracBits)

	// Convert all FP values to Ring63 uint64
	toU := func(fp []FixedPoint) []uint64 {
		u := make([]uint64, len(fp))
		for i, v := range fp { u[i] = uint64(v) % r63.Modulus }
		return u
	}

	ua0 := toU(a0); ua1 := toU(a1)
	ub0 := toU(b0); ub1 := toU(b1)
	uc0 := toU(c0); uc1 := toU(c1)
	uXMA := toU(fullXMA); uRMB := toU(fullRMB)

	// Party 0: ring multiply, no truncation
	g0_raw := make([]uint64, p)
	for j := 0; j < p; j++ { g0_raw[j] = uc0[j] }
	for j := 0; j < p; j++ {
		for i := 0; i < n; i++ {
			g0_raw[j] = r63.Add(g0_raw[j], modMulBig63(ua0[i*p+j], uRMB[i], r63.Modulus))
			g0_raw[j] = r63.Add(g0_raw[j], modMulBig63(uXMA[i*p+j], ub0[i], r63.Modulus))
			g0_raw[j] = r63.Add(g0_raw[j], modMulBig63(uXMA[i*p+j], uRMB[i], r63.Modulus)) // P0 only
		}
	}
	g0_trunc := TruncateSharePartyZero(g0_raw, uint64(1)<<fracBits, r63.Modulus)

	// Party 1: ring multiply, no truncation, NO (X-A)*(r-B)
	g1_raw := make([]uint64, p)
	for j := 0; j < p; j++ { g1_raw[j] = uc1[j] }
	for j := 0; j < p; j++ {
		for i := 0; i < n; i++ {
			g1_raw[j] = r63.Add(g1_raw[j], modMulBig63(ua1[i*p+j], uRMB[i], r63.Modulus))
			g1_raw[j] = r63.Add(g1_raw[j], modMulBig63(uXMA[i*p+j], ub1[i], r63.Modulus))
		}
	}
	g1_trunc := TruncateSharePartyOne(g1_raw, uint64(1)<<fracBits, r63.Modulus)

	// Reconstruct
	gradient := make([]float64, p)
	for j := 0; j < p; j++ {
		gradient[j] = r63.ToDouble(r63.Add(g0_trunc[j], g1_trunc[j]))
	}

	t.Logf("Expected: %v", expected)
	t.Logf("Got:      %v", gradient)

	maxErr := 0.0
	for j := 0; j < p; j++ {
		err := math.Abs(gradient[j] - expected[j])
		if err > maxErr { maxErr = err }
	}
	t.Logf("Max error: %.2e", maxErr)

	if maxErr > 0.01 {
		t.Errorf("Ring63 gradient error %.2e exceeds 0.01", maxErr)
	}
}

func TestGradientInt64Ring(t *testing.T) {
	// Same test as TestGradientInRing but using ONLY int64 FixedPoint
	fracBits := 20

	n := 3
	p := 2
	X := []float64{1, 2, 3, 4, 5, 6}
	mu := []float64{0.5, 0.3, 0.7}
	y := []float64{1, 0, 1}
	expected := []float64{-1.1, -1.6}

	xFP := FloatVecToFP(X, fracBits)
	muFP := FloatVecToFP(mu, fracBits)
	yFP := FloatVecToFP(y, fracBits)

	// Split into shares (int64 wrapping)
	x0 := make([]FixedPoint, len(xFP)); x1 := make([]FixedPoint, len(xFP))
	mu0 := make([]FixedPoint, len(muFP)); mu1 := make([]FixedPoint, len(muFP))
	y0 := make([]FixedPoint, len(yFP)); y1 := make([]FixedPoint, len(yFP))
	for i := range xFP { r := FixedPoint(int64(cryptoRandUint64K2())); x0[i]=r; x1[i]=xFP[i]-r }
	for i := range muFP { r := FixedPoint(int64(cryptoRandUint64K2())); mu0[i]=r; mu1[i]=muFP[i]-r }
	for i := range yFP { r := FixedPoint(int64(cryptoRandUint64K2())); y0[i]=r; y1[i]=yFP[i]-r }

	// Residual shares
	r0 := make([]FixedPoint, n); r1 := make([]FixedPoint, n)
	for i := 0; i < n; i++ { r0[i] = FPSub(mu0[i], y0[i]); r1[i] = FPSub(mu1[i], y1[i]) }

	// Beaver triples (int64 ring multiply)
	A := make([]FixedPoint, n*p); B := make([]FixedPoint, n)
	for i := range A { A[i] = FixedPoint(int64(cryptoRandUint64K2())) }
	for i := range B { B[i] = FixedPoint(int64(cryptoRandUint64K2())) }
	C := make([]FixedPoint, p)
	for j := 0; j < p; j++ {
		for i := 0; i < n; i++ {
			_, lo := mul64(int64(A[i*p+j]), int64(B[i]))
			C[j] += FixedPoint(lo) // low 64 bits = int64 ring product
		}
	}

	a0 := make([]FixedPoint, n*p); a1 := make([]FixedPoint, n*p)
	b0 := make([]FixedPoint, n); b1 := make([]FixedPoint, n)
	c0 := make([]FixedPoint, p); c1 := make([]FixedPoint, p)
	for i := range A { s := FixedPoint(int64(cryptoRandUint64K2())); a0[i]=s; a1[i]=A[i]-s }
	for i := range B { s := FixedPoint(int64(cryptoRandUint64K2())); b0[i]=s; b1[i]=B[i]-s }
	for i := range C { s := FixedPoint(int64(cryptoRandUint64K2())); c0[i]=s; c1[i]=C[i]-s }

	// Round 1
	xma0 := make([]FixedPoint, n*p); rmb0 := make([]FixedPoint, n)
	xma1 := make([]FixedPoint, n*p); rmb1 := make([]FixedPoint, n)
	for i := range x0 { xma0[i]=FPSub(x0[i],a0[i]) }
	for i := range r0 { rmb0[i]=FPSub(r0[i],b0[i]) }
	for i := range x1 { xma1[i]=FPSub(x1[i],a1[i]) }
	for i := range r1 { rmb1[i]=FPSub(r1[i],b1[i]) }

	fullXMA := make([]FixedPoint, n*p); fullRMB := make([]FixedPoint, n)
	for i := range fullXMA { fullXMA[i]=FPAdd(xma0[i],xma1[i]) }
	for i := range fullRMB { fullRMB[i]=FPAdd(rmb0[i],rmb1[i]) }

	// Round 2: int64 ring multiply
	g0 := make([]FixedPoint, p); copy(g0, c0)
	g1 := make([]FixedPoint, p); copy(g1, c1)

	for j := 0; j < p; j++ {
		for i := 0; i < n; i++ {
			_, lo1 := mul64(int64(a0[i*p+j]), int64(fullRMB[i])); g0[j] += FixedPoint(lo1)
			_, lo2 := mul64(int64(fullXMA[i*p+j]), int64(b0[i])); g0[j] += FixedPoint(lo2)
			_, lo3 := mul64(int64(fullXMA[i*p+j]), int64(fullRMB[i])); g0[j] += FixedPoint(lo3) // P0 only
			_, lo4 := mul64(int64(a1[i*p+j]), int64(fullRMB[i])); g1[j] += FixedPoint(lo4)
			_, lo5 := mul64(int64(fullXMA[i*p+j]), int64(b1[i])); g1[j] += FixedPoint(lo5)
		}
	}

	// Truncate and reconstruct
	gradient := make([]float64, p)
	for j := 0; j < p; j++ {
		// P0: arithmetic right-shift
		t0 := FixedPoint(int64(g0[j]) >> fracBits)
		// P1: -((-g1) >> fracBits)
		t1 := -FixedPoint(int64(-g1[j]) >> fracBits)
		gradient[j] = (t0 + t1).ToFloat64(fracBits)
	}

	t.Logf("Expected: %v", expected)
	t.Logf("Got:      %v", gradient)

	maxErr := 0.0
	for j := 0; j < p; j++ {
		err := math.Abs(gradient[j] - expected[j])
		if err > maxErr { maxErr = err }
	}
	t.Logf("Max error: %.2e", maxErr)

	if maxErr > 0.01 {
		t.Errorf("Int64 ring gradient error %.2e exceeds 0.01", maxErr)
	}
}
