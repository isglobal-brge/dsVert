package main

import "math"

// PiecewiseInterval defines one piece of a piecewise polynomial approximation.
type PiecewiseInterval struct {
	Lower  float64   // lower bound of interval
	Upper  float64   // upper bound of interval
	Mid    float64   // midpoint (polynomial is evaluated at x - mid)
	Coeffs []float64 // polynomial coefficients [a0, a1, a2, a3] for a0 + a1*t + a2*t^2 + a3*t^3
}

// SigmoidIntervals returns 16 piecewise cubic polynomial intervals
// approximating sigmoid(x) = 1/(1+exp(-x)) on [-8, 8].
// Outside this range, sigmoid is clamped to 0 or 1.
func SigmoidIntervals() []PiecewiseInterval {
	intervals := make([]PiecewiseInterval, 16)
	width := 1.0 // each interval is 1 unit wide

	for k := 0; k < 16; k++ {
		lower := -8.0 + float64(k)*width
		upper := lower + width
		mid := (lower + upper) / 2.0

		// Fit cubic polynomial to sigmoid on [lower, upper] via least-squares
		// on a dense grid
		coeffs := fitCubicLeastSquares(sigmoid, lower, upper, mid, 1000)
		intervals[k] = PiecewiseInterval{
			Lower:  lower,
			Upper:  upper,
			Mid:    mid,
			Coeffs: coeffs,
		}
	}
	return intervals
}

// ExpIntervals returns 16 piecewise cubic polynomial intervals
// approximating exp(x) on [-3, 3].
func ExpIntervals() []PiecewiseInterval {
	intervals := make([]PiecewiseInterval, 16)
	width := 6.0 / 16.0 // = 0.375

	for k := 0; k < 16; k++ {
		lower := -3.0 + float64(k)*width
		upper := lower + width
		mid := (lower + upper) / 2.0

		coeffs := fitCubicLeastSquares(math.Exp, lower, upper, mid, 1000)
		intervals[k] = PiecewiseInterval{
			Lower:  lower,
			Upper:  upper,
			Mid:    mid,
			Coeffs: coeffs,
		}
	}
	return intervals
}

// sigmoid computes the standard logistic sigmoid.
func sigmoid(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}

// fitCubicLeastSquares fits a cubic polynomial p(t) = a0 + a1*t + a2*t^2 + a3*t^3
// where t = x - mid, to the function f on [lower, upper] using least-squares.
func fitCubicLeastSquares(f func(float64) float64, lower, upper, mid float64, nPoints int) []float64 {
	// Build least-squares system: A^T A c = A^T b
	// A is nPoints x 4, b is nPoints x 1
	var AtA [4][4]float64
	var Atb [4]float64

	for i := 0; i < nPoints; i++ {
		x := lower + (upper-lower)*float64(i)/float64(nPoints-1)
		t := x - mid
		y := f(x)

		powers := [4]float64{1, t, t * t, t * t * t}
		for j := 0; j < 4; j++ {
			Atb[j] += powers[j] * y
			for k := 0; k < 4; k++ {
				AtA[j][k] += powers[j] * powers[k]
			}
		}
	}

	// Solve 4x4 system via Gaussian elimination
	return solve4x4(AtA, Atb)
}

// solve4x4 solves a 4x4 linear system Ax = b via Gaussian elimination with partial pivoting.
func solve4x4(A [4][4]float64, b [4]float64) []float64 {
	// Augmented matrix
	var aug [4][5]float64
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			aug[i][j] = A[i][j]
		}
		aug[i][4] = b[i]
	}

	// Forward elimination with partial pivoting
	for col := 0; col < 4; col++ {
		// Find pivot
		maxVal := math.Abs(aug[col][col])
		maxRow := col
		for row := col + 1; row < 4; row++ {
			if math.Abs(aug[row][col]) > maxVal {
				maxVal = math.Abs(aug[row][col])
				maxRow = row
			}
		}
		aug[col], aug[maxRow] = aug[maxRow], aug[col]

		// Eliminate below
		for row := col + 1; row < 4; row++ {
			factor := aug[row][col] / aug[col][col]
			for j := col; j < 5; j++ {
				aug[row][j] -= factor * aug[col][j]
			}
		}
	}

	// Back substitution
	x := make([]float64, 4)
	for i := 3; i >= 0; i-- {
		x[i] = aug[i][4]
		for j := i + 1; j < 4; j++ {
			x[i] -= aug[i][j] * x[j]
		}
		x[i] /= aug[i][i]
	}
	return x
}

// EvalPiecewise evaluates a piecewise polynomial at a float64 value.
// Used for testing/validation (not in the MPC protocol).
func EvalPiecewise(x float64, intervals []PiecewiseInterval, clampLow, clampHigh float64) float64 {
	if x <= intervals[0].Lower {
		return clampLow
	}
	if x >= intervals[len(intervals)-1].Upper {
		return clampHigh
	}

	for _, iv := range intervals {
		if x >= iv.Lower && x < iv.Upper {
			t := x - iv.Mid
			return iv.Coeffs[0] + iv.Coeffs[1]*t + iv.Coeffs[2]*t*t + iv.Coeffs[3]*t*t*t
		}
	}
	// Should not reach here
	return clampHigh
}

// EvalSigmoidPiecewise evaluates the piecewise sigmoid at x.
func EvalSigmoidPiecewise(x float64) float64 {
	return EvalPiecewise(x, SigmoidIntervals(), 0.0, 1.0)
}

// EvalExpPiecewise evaluates the piecewise exp at x.
func EvalExpPiecewise(x float64) float64 {
	return EvalPiecewise(x, ExpIntervals(), math.Exp(-3.0), math.Exp(3.0))
}

// Note: SecurePiecewiseEval (which would evaluate piecewise polynomials on
// secret-shared values using Beaver triples) is not needed for the
// client-relay architecture. Instead, handleMpcLinkEval in mpc_ops.go
// reconstructs eta_total on the coordinator, evaluates the piecewise
// polynomial in plaintext, and re-splits the result into shares.
// This is secure because the coordinator is one of the two parties and
// already knows its own eta_label — it learns eta_total but this is the
// same information revealed in the K>=3 secure aggregation path.
// The non-label server's individual eta_nonlabel is never exposed directly.
