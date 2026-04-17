// k2_wide_spline_test.go: unit tests for piecewise-linear spline approximations.
//
// These tests verify the *approximation* layer (slopes/intercepts vs the
// target function) in isolation from the MPC evaluation stack, plus a
// smaller set of end-to-end MPC integration tests that split values into
// Ring63 shares, run the full WideSplineXxx pipeline, and reconstruct the
// output to confirm the crypto stack matches the pure-function reference
// within the documented tolerance.
//
// The reciprocal and log primitives switched to log-spaced intervals in
// commit TBD; tests below use explicit thresholds because uniform spacing
// is no longer the implicit bucket layout for those two functions. The
// sigmoid baseline still uses uniform spacing (its derivative is bounded
// so uniform is near-optimal there).
package main

import (
	"math"
	"testing"
)

// evalSplineUniform evaluates a piecewise-linear spline at x assuming
// uniform-width buckets over [lower, upper]. Used for the sigmoid
// baseline regression test.
func evalSplineUniform(slopes, intercepts []float64, x, lower, upper float64) float64 {
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

// evalSplineAt evaluates a piecewise-linear spline at x using explicit
// threshold breakpoints (length numIntervals+1). Handles log-spaced or
// any other non-uniform layout.
func evalSplineAt(slopes, intercepts, thresholds []float64, x float64) float64 {
	n := len(slopes)
	if x < thresholds[0] {
		return slopes[0]*thresholds[0] + intercepts[0]
	}
	if x >= thresholds[n] {
		return slopes[n-1]*thresholds[n] + intercepts[n-1]
	}
	// Binary search for the right bucket (thresholds are strictly
	// increasing).
	lo, hi := 0, n
	for lo+1 < hi {
		mid := (lo + hi) / 2
		if thresholds[mid] <= x {
			lo = mid
		} else {
			hi = mid
		}
	}
	return slopes[lo]*x + intercepts[lo]
}

// TestWideSigmoidParams documents the approximation tolerance of the
// existing sigmoid spline on [-5, 5] with K2SigmoidIntervals=50.
// Unchanged: sigmoid uses uniform spacing.
func TestWideSigmoidParams(t *testing.T) {
	slopes, intercepts, halfRange := WideSigmoidParams(K2SigmoidIntervals)
	lower, upper := -halfRange, halfRange

	nSamples := 1000
	maxAbsErr := 0.0
	sigma := func(x float64) float64 { return 1.0 / (1.0 + math.Exp(-x)) }
	for k := 0; k < nSamples; k++ {
		x := lower + (upper-lower)*float64(k)/float64(nSamples-1)
		approx := evalSplineUniform(slopes, intercepts, x, lower, upper)
		absErr := math.Abs(approx - sigma(x))
		if absErr > maxAbsErr {
			maxAbsErr = absErr
		}
	}
	t.Logf("sigmoid (uniform): %d intervals on [%.1f, %.1f], max abs err=%.6e",
		K2SigmoidIntervals, lower, upper, maxAbsErr)
	if maxAbsErr > 5e-4 {
		t.Errorf("sigmoid spline max abs err %.6e exceeds documented 4.73e-4", maxAbsErr)
	}
}

// TestWideReciprocalParamsNarrow tests 1/x on [0.5, 5.0] with log-spaced
// intervals. With the switch to log spacing, 50 intervals over a 10x
// domain give uniform relative error (r-1)^2/4 ~= 0.13% across the whole
// range, in line with the sigmoid baseline.
func TestWideReciprocalParamsNarrow(t *testing.T) {
	numIntervals := 50
	lower := 0.5
	upper := 5.0
	slopes, intercepts, thresholds := WideReciprocalParamsWithRange(numIntervals, lower, upper)

	nSamples := 500
	maxRelErr := 0.0
	worstX := 0.0
	for k := 0; k < nSamples; k++ {
		// Log-sample so every decade is represented with equal density.
		logL := math.Log(lower)
		logU := math.Log(upper)
		x := math.Exp(logL + (logU-logL)*float64(k)/float64(nSamples-1))
		approx := evalSplineAt(slopes, intercepts, thresholds, x)
		exact := 1.0 / x
		relErr := math.Abs(approx-exact) / math.Abs(exact)
		if relErr > maxRelErr {
			maxRelErr = relErr
			worstX = x
		}
	}
	t.Logf("reciprocal narrow (log-spaced): %d intervals on [%.2f, %.2f], max rel err=%.4f%% at x=%.3f",
		numIntervals, lower, upper, maxRelErr*100, worstX)
	// Theoretical ceiling with log-spacing: (r-1)^2/4 where r = 10^(1/50) = 1.0471
	// -> err <= (0.0471)^2/4 = 0.055%. Tolerance set at 0.15% to cover Ring63
	// FP rounding and test sampling noise.
	if maxRelErr > 0.0015 {
		t.Errorf("reciprocal narrow (log-spaced) max rel err %.4f%% exceeds 0.15%% target", maxRelErr*100)
	}
}

// TestWideReciprocalParamsWide tests 1/x on a 1000x domain with log-spaced
// intervals. This is the case where uniform spacing failed at 104% rel
// err; log-spaced reaches sub-percent with 200 intervals.
func TestWideReciprocalParamsWide(t *testing.T) {
	numIntervals := 200
	lower := 0.01
	upper := 10.0
	slopes, intercepts, thresholds := WideReciprocalParamsWithRange(numIntervals, lower, upper)

	nSamples := 1000
	maxRelErr := 0.0
	worstX := 0.0
	for k := 0; k < nSamples; k++ {
		logL := math.Log(lower)
		logU := math.Log(upper)
		x := math.Exp(logL + (logU-logL)*float64(k)/float64(nSamples-1))
		approx := evalSplineAt(slopes, intercepts, thresholds, x)
		exact := 1.0 / x
		relErr := math.Abs(approx-exact) / math.Abs(exact)
		if relErr > maxRelErr {
			maxRelErr = relErr
			worstX = x
		}
	}
	t.Logf("reciprocal wide (log-spaced): %d intervals on [%.3f, %.1f], max rel err=%.4f%% at x=%.4f (was 104%% with uniform spacing)",
		numIntervals, lower, upper, maxRelErr*100, worstX)
	// Theoretical ceiling: r = 1000^(1/200) = 1.0347 -> (r-1)^2/4 = 0.030%.
	// Tolerance at 0.1% to absorb FP + sampling.
	if maxRelErr > 0.001 {
		t.Errorf("reciprocal wide (log-spaced) max rel err %.4f%% exceeds 0.1%% target", maxRelErr*100)
	}
}

// TestWideReciprocalParamsDefault sanity-checks the default-domain params.
func TestWideReciprocalParamsDefault(t *testing.T) {
	slopes, intercepts, thresholds, lower, upper := WideReciprocalParams(K2ReciprocalIntervals)
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
	if len(thresholds) != K2ReciprocalIntervals+1 {
		t.Errorf("len(thresholds) = %d, want %d", len(thresholds), K2ReciprocalIntervals+1)
	}
	// thresholds should be log-spaced
	r := math.Pow(upper/lower, 1.0/float64(K2ReciprocalIntervals))
	expectedT1 := lower * r
	if math.Abs(thresholds[1]-expectedT1)/expectedT1 > 1e-10 {
		t.Errorf("thresholds[1] = %v, want log-spaced %v", thresholds[1], expectedT1)
	}
}

// TestWideLogParamsNarrow tests log(x) on [0.5, 5.0] with log-spaced
// intervals. Expected (r-1)^2/8 -> ~0.3e-3 max abs error.
func TestWideLogParamsNarrow(t *testing.T) {
	numIntervals := 50
	lower := 0.5
	upper := 5.0
	slopes, intercepts, thresholds := WideLogParamsWithRange(numIntervals, lower, upper)

	nSamples := 500
	maxAbsErr := 0.0
	worstX := 0.0
	for k := 0; k < nSamples; k++ {
		logL := math.Log(lower)
		logU := math.Log(upper)
		x := math.Exp(logL + (logU-logL)*float64(k)/float64(nSamples-1))
		approx := evalSplineAt(slopes, intercepts, thresholds, x)
		exact := math.Log(x)
		absErr := math.Abs(approx - exact)
		if absErr > maxAbsErr {
			maxAbsErr = absErr
			worstX = x
		}
	}
	t.Logf("log narrow (log-spaced): %d intervals on [%.2f, %.1f], max abs err=%.6f at x=%.4f (log range ~%.2f units)",
		numIntervals, lower, upper, maxAbsErr, worstX, math.Log(upper)-math.Log(lower))
	if maxAbsErr > 1e-3 {
		t.Errorf("log narrow (log-spaced) max abs err %.6f exceeds 1e-3 tolerance", maxAbsErr)
	}
}

// TestWideLogParamsWide tests log(x) on a 4-decade domain. Previously
// uniform spacing gave 1.62 abs err; log-spacing should bring this below
// 1e-2 with 200 intervals.
func TestWideLogParamsWide(t *testing.T) {
	numIntervals := 200
	lower := 0.01
	upper := 100.0
	slopes, intercepts, thresholds := WideLogParamsWithRange(numIntervals, lower, upper)

	nSamples := 1000
	maxAbsErr := 0.0
	worstX := 0.0
	for k := 0; k < nSamples; k++ {
		logL := math.Log(lower)
		logU := math.Log(upper)
		x := math.Exp(logL + (logU-logL)*float64(k)/float64(nSamples-1))
		approx := evalSplineAt(slopes, intercepts, thresholds, x)
		exact := math.Log(x)
		absErr := math.Abs(approx - exact)
		if absErr > maxAbsErr {
			maxAbsErr = absErr
			worstX = x
		}
	}
	t.Logf("log wide (log-spaced): %d intervals on [%.3f, %.1f], max abs err=%.6f at x=%.4f over ~%.1f unit log range (was 1.62 with uniform)",
		numIntervals, lower, upper, maxAbsErr, worstX, math.Log(upper)-math.Log(lower))
	// r = 10000^(1/200) = 1.0471 -> (r-1)^2/8 = 2.8e-4. Tolerance 1e-2.
	if maxAbsErr > 1e-2 {
		t.Errorf("log wide (log-spaced) max abs err %.6f exceeds 1e-2 tolerance", maxAbsErr)
	}
}

// TestWideLogParamsDefault sanity-checks the default-domain log params.
func TestWideLogParamsDefault(t *testing.T) {
	slopes, intercepts, thresholds, lower, upper := WideLogParams(K2LogIntervals)
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
	if len(thresholds) != K2LogIntervals+1 {
		t.Errorf("len(thresholds) = %d, want %d", len(thresholds), K2LogIntervals+1)
	}
}

// splitFPShares converts a vector of real values to Ring63 FP and returns
// an additive split between two parties.
func splitFPShares(ring Ring63, values []float64) (x0, x1 []uint64) {
	n := len(values)
	x0 = make([]uint64, n)
	x1 = make([]uint64, n)
	for i, v := range values {
		fp := ring.FromDouble(v)
		s0, s1 := ring.SplitShare(fp)
		x0[i] = s0
		x1[i] = s1
	}
	return
}

// reconstructFromShares sums per-party shares into float64 outputs.
func reconstructFromShares(ring Ring63, y0, y1 []uint64) []float64 {
	n := len(y0)
	out := make([]float64, n)
	for i := 0; i < n; i++ {
		out[i] = ring.ToDouble(ring.Add(y0[i], y1[i]))
	}
	return out
}

// TestWideSplineReciprocal_EndToEnd exercises the full MPC evaluation of
// 1/x on secret shares using the log-spaced thresholds path. Tolerance is
// now set to match the sigmoid baseline rather than 2% legacy.
func TestWideSplineReciprocal_EndToEnd(t *testing.T) {
	ring := NewRing63(K2DefaultFracBits)
	numIntervals := 100
	lower := 0.5
	upper := 5.0

	n := 20
	truth := make([]float64, n)
	for i := 0; i < n; i++ {
		logL := math.Log(lower)
		logU := math.Log(upper)
		truth[i] = math.Exp(logL + (logU-logL)*float64(i)/float64(n-1))
	}

	x0, x1 := splitFPShares(ring, truth)
	mu0, mu1 := WideSplineReciprocal(ring, x0, x1, numIntervals, lower, upper)
	got := reconstructFromShares(ring, mu0, mu1)

	maxRelErr := 0.0
	worstX := 0.0
	for i, tv := range truth {
		exact := 1.0 / tv
		relErr := math.Abs(got[i]-exact) / math.Abs(exact)
		if relErr > maxRelErr {
			maxRelErr = relErr
			worstX = tv
		}
	}
	t.Logf("WideSplineReciprocal end-to-end (log-spaced) on [%.2f, %.2f] with %d intervals, n=%d: max rel err=%.4f%% at x=%.3f",
		lower, upper, numIntervals, n, maxRelErr*100, worstX)
	if maxRelErr > 0.003 {
		t.Errorf("end-to-end reciprocal max rel err %.4f%% exceeds 0.3%% tolerance",
			maxRelErr*100)
	}
}

// TestWideSplineLog_EndToEnd exercises the full MPC evaluation of log(x)
// on secret shares, with log-spaced intervals.
func TestWideSplineLog_EndToEnd(t *testing.T) {
	ring := NewRing63(K2DefaultFracBits)
	numIntervals := 100
	lower := 0.5
	upper := 5.0

	n := 20
	truth := make([]float64, n)
	for i := 0; i < n; i++ {
		logL := math.Log(lower)
		logU := math.Log(upper)
		truth[i] = math.Exp(logL + (logU-logL)*float64(i)/float64(n-1))
	}

	x0, x1 := splitFPShares(ring, truth)
	y0, y1 := WideSplineLog(ring, x0, x1, numIntervals, lower, upper)
	got := reconstructFromShares(ring, y0, y1)

	maxAbsErr := 0.0
	worstX := 0.0
	for i, tv := range truth {
		exact := math.Log(tv)
		absErr := math.Abs(got[i] - exact)
		if absErr > maxAbsErr {
			maxAbsErr = absErr
			worstX = tv
		}
	}
	t.Logf("WideSplineLog end-to-end (log-spaced) on [%.2f, %.2f] with %d intervals, n=%d: max abs err=%.6f at x=%.3f",
		lower, upper, numIntervals, n, maxAbsErr, worstX)
	if maxAbsErr > 1e-3 {
		t.Errorf("end-to-end log max abs err %.6f exceeds 1e-3 tolerance",
			maxAbsErr)
	}
}

// TestGoldschmidtReciprocalStep verifies that one Newton--Raphson step on
// top of the piecewise-linear reciprocal delivers the expected quadratic
// convergence: initial ~0.05% rel err drops to ~1e-6 (Ring63 floor).
func TestGoldschmidtReciprocalStep(t *testing.T) {
	ring := NewRing63(K2DefaultFracBits)
	numIntervals := 50
	lower := 0.5
	upper := 5.0

	n := 30
	truth := make([]float64, n)
	for i := 0; i < n; i++ {
		logL := math.Log(lower)
		logU := math.Log(upper)
		truth[i] = math.Exp(logL + (logU-logL)*float64(i)/float64(n-1))
	}

	x0, x1 := splitFPShares(ring, truth)

	// Baseline: no refinement
	mu0, mu1 := WideSplineReciprocal(ring, x0, x1, numIntervals, lower, upper)
	baseline := reconstructFromShares(ring, mu0, mu1)

	// Refined: one Goldschmidt step
	muR0, muR1 := WideSplineReciprocalRefined(ring, x0, x1, numIntervals, lower, upper, 1)
	refined := reconstructFromShares(ring, muR0, muR1)

	maxRelBaseline, maxRelRefined := 0.0, 0.0
	for i, tv := range truth {
		exact := 1.0 / tv
		errBase := math.Abs(baseline[i]-exact) / math.Abs(exact)
		errRef := math.Abs(refined[i]-exact) / math.Abs(exact)
		if errBase > maxRelBaseline {
			maxRelBaseline = errBase
		}
		if errRef > maxRelRefined {
			maxRelRefined = errRef
		}
	}
	improvement := maxRelBaseline / maxRelRefined
	t.Logf("Goldschmidt refinement: baseline max rel err=%.4f%%, refined=%.6f%% (%.0fx improvement)",
		maxRelBaseline*100, maxRelRefined*100, improvement)
	// Theory says ~(0.05%)^2 = 2.5e-7 plus one Ring63 rounding ~ 1e-6.
	// Tolerance 5e-5 to cover DCF + FP truncation noise.
	if maxRelRefined > 5e-5 {
		t.Errorf("refined max rel err %.6e exceeds 5e-5 target", maxRelRefined)
	}
	if improvement < 10 {
		t.Errorf("expected >=10x improvement from Goldschmidt, got %.1fx", improvement)
	}
}

// TestNewtonLogStep_DocumentsTradeoff records an important finding:
// Newton refinement for log is NOT beneficial in practice at current
// default precisions. The theoretical quadratic convergence is
// bottlenecked by the accuracy of the internal WideSplineExp call
// (~3.5e-3 relative error at default K2ExpIntervals=100), which
// dominates the (2.65e-4)^2 = 7e-8 quadratic term. Net: refined log
// is WORSE than piecewise-linear log alone.
//
// Conclusion: keep WideSplineLog (log-spaced, no Newton) as the
// canonical log primitive. Newton-for-log would require a far more
// accurate (log-spaced or >500-interval) WideSplineExp, which is not
// worth the extra Beaver rounds given log is already 7x better than
// the sigmoid baseline without refinement.
//
// This test is informational (t.Logf, no assertions) so future
// experiments with a higher-precision exp can be measured against
// the recorded baseline.
func TestNewtonLogStep_DocumentsTradeoff(t *testing.T) {
	ring := NewRing63(K2DefaultFracBits)
	numIntervals := 50
	lower := 0.5
	upper := 5.0

	n := 25
	truth := make([]float64, n)
	for i := 0; i < n; i++ {
		logL := math.Log(lower)
		logU := math.Log(upper)
		truth[i] = math.Exp(logL + (logU-logL)*float64(i)/float64(n-1))
	}
	x0, x1 := splitFPShares(ring, truth)

	y0, y1 := WideSplineLog(ring, x0, x1, numIntervals, lower, upper)
	baseline := reconstructFromShares(ring, y0, y1)

	yR0, yR1 := WideSplineLogRefined(ring, x0, x1, numIntervals, lower, upper, 1, K2ExpIntervals)
	refined := reconstructFromShares(ring, yR0, yR1)

	maxBase, maxRef := 0.0, 0.0
	for i, tv := range truth {
		exact := math.Log(tv)
		errBase := math.Abs(baseline[i] - exact)
		errRef := math.Abs(refined[i] - exact)
		if errBase > maxBase {
			maxBase = errBase
		}
		if errRef > maxRef {
			maxRef = errRef
		}
	}
	t.Logf("log baseline max abs err=%.6f, with 1 Newton step=%.6g -- Newton worsens because WideSplineExp's ~3.5e-3 error floor dominates the (baseline)^2 theoretical convergence",
		maxBase, maxRef)
}

// TestWideSplineReciprocal_Clamps verifies clamping behaviour.
func TestWideSplineReciprocal_Clamps(t *testing.T) {
	ring := NewRing63(K2DefaultFracBits)
	lower := 0.5
	upper := 5.0
	truth := []float64{0.1, 0.2, 10.0, 20.0}  // 2 below, 2 above
	x0, x1 := splitFPShares(ring, truth)
	mu0, mu1 := WideSplineReciprocal(ring, x0, x1, 50, lower, upper)
	got := reconstructFromShares(ring, mu0, mu1)

	for i, tv := range truth {
		var expected float64
		if tv < lower {
			expected = 1.0 / lower
		} else if tv > upper {
			expected = 1.0 / upper
		} else {
			expected = 1.0 / tv
		}
		if math.Abs(got[i]-expected) > 0.05 {
			t.Errorf("x=%.2f: got %.4f, expected ~%.4f (clamp)", tv, got[i], expected)
		}
	}
}
