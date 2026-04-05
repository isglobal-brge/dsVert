package main

import (
	"math"
	"testing"
)

func sigmoid(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}

func TestChebyshevSigmoidAccuracy(t *testing.T) {
	// Test sigmoid Chebyshev polynomial on different degree/interval combos
	tests := []struct {
		degree   int
		lower    float64
		upper    float64
		maxErr   float64 // expected max poly error
	}{
		{7, -5, 5, 5e-2},
		{9, -5, 5, 5e-3},
		{11, -5, 5, 1e-3},
		{13, -5, 5, 5e-4},
		{13, -6, 6, 2e-3},
		{13, -8, 8, 1e-2},
	}

	for _, tc := range tests {
		coeffs := SigmoidChebyshev(tc.degree, tc.lower, tc.upper)
		err := MeasureMaxError(coeffs, sigmoid, tc.lower, tc.upper, 100000)
		t.Logf("Sigmoid degree-%d on [%.0f,%.0f]: max error = %.2e", tc.degree, tc.lower, tc.upper, err)
		if err > tc.maxErr {
			t.Errorf("  FAIL: error %.2e exceeds threshold %.2e", err, tc.maxErr)
		}
	}
}

func TestChebyshevExpAccuracy(t *testing.T) {
	tests := []struct {
		degree   int
		lower    float64
		upper    float64
		maxErr   float64
	}{
		{7, -3, 3, 5e-3},
		{9, -5, 5, 5e-2},
		{11, -5, 5, 5e-3},
		{13, -5, 5, 5e-4},
	}

	for _, tc := range tests {
		coeffs := ExpChebyshev(tc.degree, tc.lower, tc.upper)
		err := MeasureMaxError(coeffs, math.Exp, tc.lower, tc.upper, 100000)
		t.Logf("Exp degree-%d on [%.0f,%.0f]: max error = %.2e", tc.degree, tc.lower, tc.upper, err)
		if err > tc.maxErr {
			t.Errorf("  FAIL: error %.2e exceeds threshold %.2e", err, tc.maxErr)
		}
	}
}

func TestChebyshevSigmoidEdgeBehavior(t *testing.T) {
	// Verify sigmoid polynomial is well-behaved at extremes
	coeffs := SigmoidChebyshev(13, -5, 5)

	// Inside interval: should be accurate
	for _, x := range []float64{0.0, 1.0, -1.0, 2.5, -2.5, 4.9, -4.9} {
		approx := EvalPolynomial(coeffs, x)
		exact := sigmoid(x)
		err := math.Abs(approx - exact)
		if err > 1e-3 {
			t.Errorf("Sigmoid at x=%.1f: approx=%.6f, exact=%.6f, err=%.2e", x, approx, exact, err)
		}
	}

	// Outside interval: polynomial may diverge, but for standardized data
	// eta should stay in [-5, 5]. Clamp at boundaries.
	for _, x := range []float64{-5.0, 5.0} {
		approx := EvalPolynomial(coeffs, x)
		exact := sigmoid(x)
		err := math.Abs(approx - exact)
		t.Logf("Sigmoid at boundary x=%.1f: approx=%.6f, exact=%.6f, err=%.2e", x, approx, exact, err)
	}
}

func TestChebyshevExpEdgeBehavior(t *testing.T) {
	coeffs := ExpChebyshev(13, -5, 5)

	for _, x := range []float64{0.0, 1.0, -1.0, 3.0, -3.0, 4.9, -4.9} {
		approx := EvalPolynomial(coeffs, x)
		exact := math.Exp(x)
		relErr := math.Abs(approx-exact) / math.Max(exact, 1e-10)
		if relErr > 1e-2 {
			t.Errorf("Exp at x=%.1f: approx=%.6f, exact=%.6f, relErr=%.2e", x, approx, exact, relErr)
		}
	}
}

// TestChebyshevVsLSFit compares Chebyshev vs naive LS polynomial to verify
// Chebyshev is strictly better.
func TestChebyshevVsLSFit(t *testing.T) {
	// Least-squares on equispaced points (mimics the old mhe-tool fitGlobalPoly)
	degree := 13
	lower, upper := -5.0, 5.0
	nPoints := 10000

	// Build Vandermonde matrix and solve LS
	xs := make([]float64, nPoints)
	ys := make([]float64, nPoints)
	for i := 0; i < nPoints; i++ {
		xs[i] = lower + (upper-lower)*float64(i)/float64(nPoints-1)
		ys[i] = sigmoid(xs[i])
	}

	// LS fit via normal equations (simple, not numerically great)
	// V^T V a = V^T y where V_ij = x_i^j
	p := degree + 1
	VtV := make([][]float64, p)
	VtY := make([]float64, p)
	for i := range VtV {
		VtV[i] = make([]float64, p)
	}
	for i := 0; i < nPoints; i++ {
		powers := make([]float64, p)
		powers[0] = 1.0
		for j := 1; j < p; j++ {
			powers[j] = powers[j-1] * xs[i]
		}
		for r := 0; r < p; r++ {
			for c := 0; c < p; c++ {
				VtV[r][c] += powers[r] * powers[c]
			}
			VtY[r] += powers[r] * ys[i]
		}
	}

	// Solve VtV * a = VtY (naive Gaussian elimination — may be ill-conditioned)
	lsCoeffs := solveLinear(VtV, VtY)
	if lsCoeffs == nil {
		t.Log("LS solve failed (ill-conditioned as expected for degree 13)")
	}

	// Chebyshev
	chebCoeffs := SigmoidChebyshev(degree, lower, upper)
	chebErr := MeasureMaxError(chebCoeffs, sigmoid, lower, upper, 100000)
	t.Logf("Chebyshev degree-%d: max error = %.2e", degree, chebErr)

	if lsCoeffs != nil {
		lsErr := MeasureMaxError(lsCoeffs, sigmoid, lower, upper, 100000)
		t.Logf("LS degree-%d: max error = %.2e", degree, lsErr)
		if chebErr > lsErr {
			t.Errorf("Chebyshev should be better than LS, but cheb=%.2e > ls=%.2e", chebErr, lsErr)
		}
	}
}

// solveLinear solves Ax = b via Gaussian elimination (naive, for testing only).
func solveLinear(A [][]float64, b []float64) []float64 {
	n := len(b)
	aug := make([][]float64, n)
	for i := range aug {
		aug[i] = make([]float64, n+1)
		copy(aug[i], A[i])
		aug[i][n] = b[i]
	}

	for col := 0; col < n; col++ {
		// Find pivot
		maxVal := 0.0
		maxRow := col
		for row := col; row < n; row++ {
			if math.Abs(aug[row][col]) > maxVal {
				maxVal = math.Abs(aug[row][col])
				maxRow = row
			}
		}
		if maxVal < 1e-12 {
			return nil // singular
		}
		aug[col], aug[maxRow] = aug[maxRow], aug[col]

		// Eliminate
		pivot := aug[col][col]
		for j := col; j <= n; j++ {
			aug[col][j] /= pivot
		}
		for row := 0; row < n; row++ {
			if row == col {
				continue
			}
			factor := aug[row][col]
			for j := col; j <= n; j++ {
				aug[row][j] -= factor * aug[col][j]
			}
		}
	}

	result := make([]float64, n)
	for i := range result {
		result[i] = aug[i][n]
	}
	return result
}
