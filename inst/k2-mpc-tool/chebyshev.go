// chebyshev.go: Chebyshev polynomial interpolation for secure nonlinear evaluation.
//
// Generates minimax-quality polynomial approximations of sigmoid and exp
// using Chebyshev interpolation at Chebyshev nodes (near-optimal L∞ error).
// The resulting monomial coefficients are used with the existing Beaver
// power-chain protocol for secure evaluation on secret shares.
//
// This replaces the least-squares global polynomial fit (SigmoidGlobalPoly /
// ExpGlobalPoly in mhe-tool/mpc_piecewise.go) which suffered from Runge
// phenomenon at high degrees.

package main

import (
	"math"
)

// ChebyshevNodes returns n+1 Chebyshev nodes of the second kind on [lower, upper].
// x_k = (upper+lower)/2 + (upper-lower)/2 * cos(k*pi/n), for k = 0, 1, ..., n.
func ChebyshevNodes(degree int, lower, upper float64) []float64 {
	n := degree
	nodes := make([]float64, n+1)
	mid := (upper + lower) / 2.0
	half := (upper - lower) / 2.0
	for k := 0; k <= n; k++ {
		nodes[k] = mid + half*math.Cos(float64(k)*math.Pi/float64(n))
	}
	return nodes
}

// ChebyshevInterpolate computes a degree-d polynomial that interpolates f
// at Chebyshev nodes on [lower, upper]. Returns monomial coefficients
// [a0, a1, ..., ad] such that p(x) = a0 + a1*x + a2*x^2 + ... + ad*x^d.
func ChebyshevInterpolate(f func(float64) float64, degree int, lower, upper float64) []float64 {
	n := degree
	nodes := ChebyshevNodes(n, lower, upper)

	// Evaluate f at nodes
	fvals := make([]float64, n+1)
	for i, x := range nodes {
		fvals[i] = f(x)
	}

	// Compute Chebyshev coefficients via DCT-like formula:
	// c_k = (2/n) * sum_{j=0}^{n} '' f(x_j) * cos(k*j*pi/n)
	// where '' means the first and last terms are halved.
	chebCoeffs := make([]float64, n+1)
	for k := 0; k <= n; k++ {
		sum := 0.0
		for j := 0; j <= n; j++ {
			term := fvals[j] * math.Cos(float64(k)*float64(j)*math.Pi/float64(n))
			if j == 0 || j == n {
				term *= 0.5
			}
			sum += term
		}
		chebCoeffs[k] = 2.0 / float64(n) * sum
		if k == 0 || k == n {
			chebCoeffs[k] *= 0.5
		}
	}

	// Convert from Chebyshev basis on [-1,1] to monomial basis on [lower, upper].
	// First: build monomial coefficients in the variable t in [-1,1],
	// where t = (2*x - (upper+lower)) / (upper-lower).
	// T_0(t) = 1, T_1(t) = t, T_k(t) = 2*t*T_{k-1}(t) - T_{k-2}(t)
	//
	// We build the monomial representation of each T_k and accumulate.
	mono_t := make([]float64, n+1) // monomial coeffs in t
	// T_0 = [1, 0, 0, ...]
	// T_1 = [0, 1, 0, ...]
	prev := make([]float64, n+1) // T_{k-2}
	curr := make([]float64, n+1) // T_{k-1}
	prev[0] = 1.0

	// Accumulate c_0 * T_0
	mono_t[0] += chebCoeffs[0]

	if n >= 1 {
		curr[1] = 1.0
		// Accumulate c_1 * T_1
		for i := 0; i <= n; i++ {
			mono_t[i] += chebCoeffs[1] * curr[i]
		}
	}

	for k := 2; k <= n; k++ {
		next := make([]float64, n+1)
		// T_k = 2*t*T_{k-1} - T_{k-2}
		// 2*t*T_{k-1}: shift curr up by 1 and multiply by 2
		for i := 0; i < n; i++ {
			next[i+1] += 2.0 * curr[i]
		}
		// Subtract T_{k-2}
		for i := 0; i <= n; i++ {
			next[i] -= prev[i]
		}

		// Accumulate c_k * T_k
		for i := 0; i <= n; i++ {
			mono_t[i] += chebCoeffs[k] * next[i]
		}

		prev = curr
		curr = next
	}

	// Now convert from monomial in t to monomial in x.
	// t = (2*x - (upper+lower)) / (upper-lower) = (2/(upper-lower))*x - (upper+lower)/(upper-lower)
	// Let a = 2/(upper-lower), b = -(upper+lower)/(upper-lower)
	// t = a*x + b
	// t^k = (a*x + b)^k = sum_{j=0}^{k} C(k,j) * a^j * b^{k-j} * x^j
	a := 2.0 / (upper - lower)
	b := -(upper + lower) / (upper - lower)

	mono_x := make([]float64, n+1)
	for k := 0; k <= n; k++ {
		if math.Abs(mono_t[k]) < 1e-20 {
			continue
		}
		// Expand t^k = (a*x + b)^k using binomial theorem
		binomCoeffs := binomialExpansion(k, a, b)
		for j := 0; j <= k; j++ {
			mono_x[j] += mono_t[k] * binomCoeffs[j]
		}
	}

	return mono_x
}

// binomialExpansion computes the coefficients of (a*x + b)^k in terms of x.
// Returns [c_0, c_1, ..., c_k] where (a*x + b)^k = c_0 + c_1*x + ... + c_k*x^k.
func binomialExpansion(k int, a, b float64) []float64 {
	coeffs := make([]float64, k+1)
	// (a*x + b)^k = sum_{j=0}^{k} C(k,j) * (a*x)^j * b^{k-j}
	//             = sum_{j=0}^{k} C(k,j) * a^j * b^{k-j} * x^j
	binom := 1.0 // C(k, 0)
	for j := 0; j <= k; j++ {
		coeffs[j] = binom * math.Pow(a, float64(j)) * math.Pow(b, float64(k-j))
		if j < k {
			binom = binom * float64(k-j) / float64(j+1)
		}
	}
	return coeffs
}

// SigmoidChebyshev returns Chebyshev polynomial coefficients for sigmoid on [lower, upper].
func SigmoidChebyshev(degree int, lower, upper float64) []float64 {
	sigmoid := func(x float64) float64 {
		return 1.0 / (1.0 + math.Exp(-x))
	}
	return ChebyshevInterpolate(sigmoid, degree, lower, upper)
}

// ExpChebyshev returns Chebyshev polynomial coefficients for exp on [lower, upper].
func ExpChebyshev(degree int, lower, upper float64) []float64 {
	return ChebyshevInterpolate(math.Exp, degree, lower, upper)
}

// EvalPolynomial evaluates a monomial polynomial at x: a0 + a1*x + a2*x^2 + ...
func EvalPolynomial(coeffs []float64, x float64) float64 {
	// Horner's method
	n := len(coeffs)
	if n == 0 {
		return 0
	}
	result := coeffs[n-1]
	for i := n - 2; i >= 0; i-- {
		result = result*x + coeffs[i]
	}
	return result
}

// MeasureMaxError measures the maximum absolute error of a polynomial
// approximation vs the true function on nPoints evenly-spaced points in [lower, upper].
func MeasureMaxError(coeffs []float64, f func(float64) float64,
	lower, upper float64, nPoints int) float64 {

	maxErr := 0.0
	for i := 0; i < nPoints; i++ {
		x := lower + (upper-lower)*float64(i)/float64(nPoints-1)
		approx := EvalPolynomial(coeffs, x)
		exact := f(x)
		err := math.Abs(approx - exact)
		if err > maxErr {
			maxErr = err
		}
	}
	return maxErr
}
