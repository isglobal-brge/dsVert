// k2_wide_spline_test.go: unit tests for piecewise-linear spline approximations.
//
// These tests verify the *approximation* layer (slopes/intercepts vs the
// target function) in isolation from the MPC evaluation stack. The MPC layer
// is exercised end-to-end through the R integration tests; here we check
// only that the piecewise-linear parameters reproduce the underlying
// function within the tolerances the paper claims.
package main

import (
	"math"
	"testing"
)

// evalSpline evaluates the piecewise-linear spline at x using the locally
// computed interval index (uniform width).
func evalSpline(slopes, intercepts []float64, x, lower, upper float64) float64 {
	numIntervals := len(slopes)
	width := (upper - lower) / float64(numIntervals)
	if x < lower {
		return slopes[0]*lower + intercepts[0]
	}
	if x >= upper {
		return slopes[numIntervals-1]*upper + intercepts[numIntervals-1]
	}
	j := int((x - lower) / width)
	if j >= numIntervals {
		j = numIntervals - 1
	}
	return slopes[j]*x + intercepts[j]
}

// TestWideSigmoidParams documents the approximation tolerance of the
// existing sigmoid spline on [-5, 5] with K2SigmoidIntervals=50. Serves as
// a regression baseline when we later tune intervals or domain.
func TestWideSigmoidParams(t *testing.T) {
	slopes, intercepts, halfRange := WideSigmoidParams(K2SigmoidIntervals)
	lower, upper := -halfRange, halfRange

	nSamples := 1000
	maxAbsErr := 0.0
	sigma := func(x float64) float64 { return 1.0 / (1.0 + math.Exp(-x)) }
	for k := 0; k < nSamples; k++ {
		x := lower + (upper-lower)*float64(k)/float64(nSamples-1)
		approx := evalSpline(slopes, intercepts, x, lower, upper)
		absErr := math.Abs(approx - sigma(x))
		if absErr > maxAbsErr {
			maxAbsErr = absErr
		}
	}
	t.Logf("sigmoid: %d intervals on [%.1f, %.1f], max abs err=%.6e",
		K2SigmoidIntervals, lower, upper, maxAbsErr)
	if maxAbsErr > 5e-4 {
		t.Errorf("sigmoid spline max abs err %.6e exceeds documented 4.73e-4", maxAbsErr)
	}
}

// TestWideReciprocalParamsNarrow tests 1/x on [0.5, 5.0], a typical range
// for IPW propensity weights (1/p for p in ~[0.2, 2]) or for LMM variance
// ratios. Uniform spacing is sufficient at this ratio (10x).
func TestWideReciprocalParamsNarrow(t *testing.T) {
	numIntervals := 50
	lower := 0.5
	upper := 5.0
	slopes, intercepts := WideReciprocalParamsWithRange(numIntervals, lower, upper)

	nSamples := 500
	maxRelErr := 0.0
	worstX := 0.0
	for k := 0; k < nSamples; k++ {
		x := lower + (upper-lower)*float64(k)/float64(nSamples-1)
		approx := evalSpline(slopes, intercepts, x, lower, upper)
		exact := 1.0 / x
		relErr := math.Abs(approx-exact) / math.Abs(exact)
		if relErr > maxRelErr {
			maxRelErr = relErr
			worstX = x
		}
	}
	t.Logf("reciprocal narrow: %d intervals on [%.2f, %.2f], max rel err=%.4f%% at x=%.3f",
		numIntervals, lower, upper, maxRelErr*100, worstX)
	// Uniform 50-interval spline over 10x domain typically under 2% relative
	if maxRelErr > 0.02 {
		t.Errorf("reciprocal narrow domain max rel err %.4f%% exceeds 2%%", maxRelErr*100)
	}
}

// TestWideReciprocalParamsWideDocumentsLimitation characterises the
// documented limitation of uniform spacing for 1/x on wide domains
// (lower/upper ratio >> 100). This test does NOT assert a tolerance; it
// exists to produce a log record so that future log-spaced implementations
// have a quantified baseline to beat.
//
// TODO(cox): implement WideReciprocalParamsLogSpaced that returns both the
// slopes/intercepts and an explicit threshold breakpoint vector, and
// extend the MPC evaluator to accept explicit thresholds instead of
// assuming uniform width. This is needed when Cox S(t_i) spans many
// orders of magnitude; for IPW (weights 1/p with trimmed p ∈ [0.05, 1])
// and LMM variance ratios (σ_b² / σ² in a predictable narrow band), the
// uniform spline is sufficient and simpler.
func TestWideReciprocalParamsWideDocumentsLimitation(t *testing.T) {
	numIntervals := 200
	lower := 0.01
	upper := 10.0
	slopes, intercepts := WideReciprocalParamsWithRange(numIntervals, lower, upper)

	nSamples := 1000
	maxRelErr := 0.0
	worstX := 0.0
	for k := 0; k < nSamples; k++ {
		logL := math.Log(lower)
		logU := math.Log(upper)
		x := math.Exp(logL + (logU-logL)*float64(k)/float64(nSamples-1))
		approx := evalSpline(slopes, intercepts, x, lower, upper)
		exact := 1.0 / x
		relErr := math.Abs(approx-exact) / math.Abs(exact)
		if relErr > maxRelErr {
			maxRelErr = relErr
			worstX = x
		}
	}
	t.Logf("reciprocal wide (uniform) %d intervals on [%.3f, %.1f] with log-sampled grid: max rel err=%.2f%% at x=%.4f -- uniform spacing expected to fail near x->0; log-spaced variant is planned (see TODO(cox))",
		numIntervals, lower, upper, maxRelErr*100, worstX)
}

// TestWideReciprocalParamsDefault sanity-checks the default-domain params
// match the documented K2Reciprocal* constants.
func TestWideReciprocalParamsDefault(t *testing.T) {
	slopes, intercepts, lower, upper := WideReciprocalParams(K2ReciprocalIntervals)
	if lower != K2ReciprocalLower {
		t.Errorf("lower = %v, want %v", lower, K2ReciprocalLower)
	}
	if upper != K2ReciprocalUpper {
		t.Errorf("upper = %v, want %v", upper, K2ReciprocalUpper)
	}
	if len(slopes) != K2ReciprocalIntervals {
		t.Errorf("len(slopes) = %d, want %d", len(slopes), K2ReciprocalIntervals)
	}
	if len(intercepts) != K2ReciprocalIntervals {
		t.Errorf("len(intercepts) = %d, want %d", len(intercepts), K2ReciprocalIntervals)
	}
}

// TestWideLogParamsNarrow tests log(x) on [0.5, 5.0] — one order of
// magnitude, the regime where uniform intervals give tight accuracy
// (derivative 1/x ≤ 2 across the domain). Representative of multinomial
// log-sum-exp input ranges when η is already standardised or bounded by
// design. Expected max abs error < 0.01 with 50 intervals.
func TestWideLogParamsNarrow(t *testing.T) {
	numIntervals := 50
	lower := 0.5
	upper := 5.0
	slopes, intercepts := WideLogParamsWithRange(numIntervals, lower, upper)

	nSamples := 500
	maxAbsErr := 0.0
	worstX := 0.0
	for k := 0; k < nSamples; k++ {
		// Log-sample the input so small-x region is represented (this is
		// where linear approximation of log degrades).
		logL := math.Log(lower)
		logU := math.Log(upper)
		x := math.Exp(logL + (logU-logL)*float64(k)/float64(nSamples-1))
		approx := evalSpline(slopes, intercepts, x, lower, upper)
		exact := math.Log(x)
		absErr := math.Abs(approx - exact)
		if absErr > maxAbsErr {
			maxAbsErr = absErr
			worstX = x
		}
	}
	t.Logf("log narrow: %d intervals on [%.2f, %.1f], max abs err=%.6f at x=%.4f (log range ~%.2f units)",
		numIntervals, lower, upper, maxAbsErr, worstX, math.Log(upper)-math.Log(lower))
	if maxAbsErr > 0.01 {
		t.Errorf("log narrow max abs err %.6f exceeds 0.01 tolerance", maxAbsErr)
	}
}

// TestWideLogParamsMediumDocumentsLimitation exercises the 4-decade default
// domain [0.01, 100] with 200 uniform intervals. log(x) degrades near the
// small-x end where the derivative 1/x is large; uniform spacing amplifies
// the error there. This test records the measured ceiling without
// asserting, analogous to TestWideReciprocalParamsWideDocumentsLimitation.
// Future log-spaced variant (shared implementation with 1/x) will improve
// this.
func TestWideLogParamsMediumDocumentsLimitation(t *testing.T) {
	numIntervals := 200
	lower := 0.01
	upper := 100.0
	slopes, intercepts := WideLogParamsWithRange(numIntervals, lower, upper)

	nSamples := 1000
	maxAbsErr := 0.0
	worstX := 0.0
	for k := 0; k < nSamples; k++ {
		logL := math.Log(lower)
		logU := math.Log(upper)
		x := math.Exp(logL + (logU-logL)*float64(k)/float64(nSamples-1))
		approx := evalSpline(slopes, intercepts, x, lower, upper)
		exact := math.Log(x)
		absErr := math.Abs(approx - exact)
		if absErr > maxAbsErr {
			maxAbsErr = absErr
			worstX = x
		}
	}
	t.Logf("log medium (uniform) %d intervals on [%.3f, %.1f]: max abs err=%.4f at x=%.4f over ~%.1f unit log range -- uniform spacing degrades near x->0; log-spaced variant is planned",
		numIntervals, lower, upper, maxAbsErr, worstX, math.Log(upper)-math.Log(lower))
}

// TestWideLogParamsDefault sanity-checks the default-domain log params.
func TestWideLogParamsDefault(t *testing.T) {
	slopes, intercepts, lower, upper := WideLogParams(K2LogIntervals)
	if lower != K2LogLower {
		t.Errorf("lower = %v, want %v", lower, K2LogLower)
	}
	if upper != K2LogUpper {
		t.Errorf("upper = %v, want %v", upper, K2LogUpper)
	}
	if len(slopes) != K2LogIntervals {
		t.Errorf("len(slopes) = %d, want %d", len(slopes), K2LogIntervals)
	}
	if len(intercepts) != K2LogIntervals {
		t.Errorf("len(intercepts) = %d, want %d", len(intercepts), K2LogIntervals)
	}
}
