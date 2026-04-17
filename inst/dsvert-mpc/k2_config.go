// k2_config.go: Optimal configuration for K=2 MPC GLM.
//
// These defaults were determined by systematic experimentation:
// - Binomial (sigmoid): 50 intervals on [-5,5) gives 1.40e-3 coef error vs GLM
// - Poisson (exp): 100 intervals on [-3,8] gives 3.55e-3 MPC error vs centralized
// - Ring63 with fracBits=20 is sufficient for both families
// - Wide piecewise-linear spline (no Kelkar exp) eliminates the 4.57e-2 shift

package main

const (
	// K2DefaultFracBits is the number of fractional bits for fixed-point arithmetic.
	// Ring63 with 20 fractional bits gives 2^{-20} ≈ 1e-6 per-element precision.
	// Higher values (e.g., 25) would give more precision but risk Ring63 overflow
	// in Hadamard products (2*fracBits must be << 63).
	K2DefaultFracBits = 20

	// K2SigmoidIntervals is the number of piecewise-linear spline intervals
	// for the sigmoid function on [-5, 5).
	// 50 intervals (width=0.2) gives max point error 4.73e-4 and training error 1.40e-3.
	// Fewer intervals reduce communication rounds but increase approximation error.
	K2SigmoidIntervals = 50

	// K2ExpIntervals is the number of piecewise-linear spline intervals
	// for the exp function on [-3, 8].
	// 100 intervals (width=0.11) gives max relative error 0.15% and MPC error 3.55e-3.
	K2ExpIntervals = 100

	// K2ReciprocalIntervals is the number of piecewise-linear spline intervals
	// for the 1/x reciprocal function. Used as a primitive for Cox 1/S(t_i),
	// mixed-effects variance ratios, and IPW weights 1/p_hat.
	// On the default domain [K2ReciprocalLower, K2ReciprocalUpper] uniform
	// intervals are used; for extreme lower/upper ratios callers should override
	// via WideReciprocalParamsWithRange.
	K2ReciprocalIntervals = 100

	// K2ReciprocalLower is the default lower bound of the 1/x spline domain.
	// Must be strictly positive (> 0) to avoid the pole at x = 0.
	K2ReciprocalLower = 0.01

	// K2ReciprocalUpper is the default upper bound of the 1/x spline domain.
	K2ReciprocalUpper = 10.0
)
