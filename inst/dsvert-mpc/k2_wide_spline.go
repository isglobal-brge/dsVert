// k2_wide_spline.go: Production wide piecewise-linear spline approximations
// for sigmoid and exp, evaluated on secret shares.
//
// These use a single wide spline over the full domain (no Kelkar exp, no Taylor),
// which supports arbitrary fracBits without Ring63 overflow.
//
// Protocol per evaluation (sigmoid):
//   - 2 broad DCF comparisons for saturation (x < -halfRange, x < halfRange)
//   - 1 Beaver AND for I_mid = NOT(c_low) * c_high
//   - (numIntervals-1) sub-interval DCF comparisons
//   - numIntervals individual ScalarVP for slopes and intercepts (NOT deferred)
//   - 1 Hadamard for slope*x
//   - 1 Hadamard for I_mid * spline_value
//   - Addition for final result: I_high + I_mid * spline

package main

import "math"

// computeWideSpline computes a piecewise linear approximation of f over
// [lower, upper) with numIntervals equal-width intervals.
// Returns the slope and intercept for each interval.
func computeWideSpline(f func(float64) float64, numIntervals int, lower, upper float64) (slopes, intercepts []float64) {
	width := (upper - lower) / float64(numIntervals)
	slopes = make([]float64, numIntervals)
	intercepts = make([]float64, numIntervals)
	for j := 0; j < numIntervals; j++ {
		left := lower + float64(j)*width
		right := left + width
		fLeft := f(left)
		fRight := f(right)
		slopes[j] = (fRight - fLeft) / width
		intercepts[j] = fLeft - slopes[j]*left
	}
	return
}

// computeWideSplineLogSpaced computes a piecewise linear approximation of
// f over [lower, upper] with numIntervals geometrically-spaced intervals.
// Requires lower > 0. Returns slopes, intercepts, AND the explicit
// threshold breakpoints (length numIntervals+1) so callers can drive the
// DCF sub-interval comparisons with non-uniform thresholds.
//
// Why log spacing: for functions whose derivative grows like x^{-k} near
// zero (such as 1/x with k=2 and log(x) with k=1), uniform spacing makes
// the linear-approximation error near x -> 0 diverge, so the headline
// relative or absolute error is dominated by one or two small-x buckets.
// Log spacing matches the function's natural scale:
//
//   - For f(x) = 1/x: relative error is uniformly (r-1)^2/4 across the
//     whole domain, where r = (upper/lower)^(1/K).
//   - For f(x) = log(x): absolute error is uniformly (r-1)^2/8.
//
// In both cases K = ceil(log(upper/lower) / log(r)) intervals suffice to
// reach a prescribed error bound, independent of the absolute location.
// With r = 1.063 (K ~= 113 on a 1000x domain) we hit ~0.1% relative error
// for 1/x -- matching the sigmoid primitive baseline -- whereas uniform
// spacing on the same domain gave 100%+ error near x -> 0.
func computeWideSplineLogSpaced(f func(float64) float64, numIntervals int, lower, upper float64) (slopes, intercepts, thresholds []float64) {
	thresholds = make([]float64, numIntervals+1)
	logL := math.Log(lower)
	logU := math.Log(upper)
	for j := 0; j <= numIntervals; j++ {
		thresholds[j] = math.Exp(logL + (logU-logL)*float64(j)/float64(numIntervals))
	}
	// Pin the endpoints exactly to avoid floating-point drift at the clamps.
	thresholds[0] = lower
	thresholds[numIntervals] = upper

	slopes = make([]float64, numIntervals)
	intercepts = make([]float64, numIntervals)
	for j := 0; j < numIntervals; j++ {
		left := thresholds[j]
		right := thresholds[j+1]
		fLeft := f(left)
		fRight := f(right)
		slopes[j] = (fRight - fLeft) / (right - left)
		intercepts[j] = fLeft - slopes[j]*left
	}
	return
}

// WideSigmoidParams returns the piecewise linear spline parameters for sigmoid
// on [-5, 5) with numIntervals intervals.
func WideSigmoidParams(numIntervals int) (slopes, intercepts []float64, halfRange float64) {
	halfRange = 5.0
	sigma := func(x float64) float64 { return 1.0 / (1.0 + math.Exp(-x)) }
	slopes, intercepts = computeWideSpline(sigma, numIntervals, -halfRange, halfRange)
	return
}

// WideExpParams returns the piecewise linear spline parameters for exp(x)
// on [lower, upper] with numIntervals intervals.
// Default range: [-3, 8] for Poisson regression.
func WideExpParams(numIntervals int) (slopes, intercepts []float64, lower, upper float64) {
	lower = -3.0
	upper = 8.0
	slopes, intercepts = computeWideSpline(math.Exp, numIntervals, lower, upper)
	return
}

// WideSoftplusParams returns the piecewise linear spline parameters for
// softplus(x) = log(1 + exp(x)) on [-8, 8) with numIntervals intervals.
// Used for binomial canonical deviance: D = 2·Σ[softplus(η) - y·η].
func WideSoftplusParams(numIntervals int) (slopes, intercepts []float64, halfRange float64) {
	halfRange = 8.0
	softplus := func(x float64) float64 { return math.Log(1.0 + math.Exp(x)) }
	slopes, intercepts = computeWideSpline(softplus, numIntervals, -halfRange, halfRange)
	return
}

// WideReciprocalParams returns piecewise-linear spline parameters for 1/x
// on [K2ReciprocalLower, K2ReciprocalUpper] with numIntervals LOG-SPACED
// intervals. Used as the primitive for Cox 1/S(t_i) in the reverse-cumsum
// gradient reformulation, mixed-effects variance ratios, IPW weights
// 1/p_hat, and multinomial softmax normalisation.
//
// The domain bound K2ReciprocalLower MUST be strictly positive (> 0)
// because 1/x has a pole at 0. Log spacing gives uniform relative error
// (r-1)^2/4 across the whole domain where r = (upper/lower)^(1/numIntervals),
// eliminating the near-pole blow-up of uniform spacing. Returns slopes,
// intercepts, and the explicit threshold breakpoints (length numIntervals+1)
// consumed by the MPC evaluator's sub-interval DCF comparisons.
func WideReciprocalParams(numIntervals int) (slopes, intercepts, thresholds []float64, lower, upper float64) {
	lower = K2ReciprocalLower
	upper = K2ReciprocalUpper
	slopes, intercepts, thresholds = WideReciprocalParamsWithRange(numIntervals, lower, upper)
	return
}

// WideReciprocalParamsWithRange is the caller-parameterised variant of
// WideReciprocalParams with explicit domain bounds. Useful when the caller
// has prior knowledge of the expected range of 1/x inputs (e.g., Cox
// S(t_i) is bounded by the sum of exp(eta) over the risk set, which
// depends on n and the coefficient scale). Uses log-spaced intervals
// unconditionally.
func WideReciprocalParamsWithRange(numIntervals int, lower, upper float64) (slopes, intercepts, thresholds []float64) {
	recip := func(x float64) float64 { return 1.0 / x }
	slopes, intercepts, thresholds = computeWideSplineLogSpaced(recip, numIntervals, lower, upper)
	return
}

// WideLogParams returns piecewise-linear spline parameters for log(x) on
// [K2LogLower, K2LogUpper] with numIntervals LOG-SPACED intervals. Used
// as the primitive for:
//   - negative binomial canonical deviance: D involves log(μ_i + θ^{-1})
//   - mixed-effects log-determinant: log|V_i| in the REML / ML objective
//   - Cox log S(t_i): the partial log-likelihood term
//   - multinomial log-sum-exp: log(Σ e^{η_k}) for softmax normalisation
//
// The lower bound MUST be strictly positive because log has a singularity
// at 0. Log spacing gives uniform absolute error (r-1)^2/8 across the
// whole domain where r = (upper/lower)^(1/numIntervals), eliminating the
// small-x blow-up of uniform spacing. Returns slopes, intercepts, and
// the explicit threshold breakpoints (length numIntervals+1) consumed by
// the MPC evaluator's sub-interval DCF comparisons.
func WideLogParams(numIntervals int) (slopes, intercepts, thresholds []float64, lower, upper float64) {
	lower = K2LogLower
	upper = K2LogUpper
	slopes, intercepts, thresholds = WideLogParamsWithRange(numIntervals, lower, upper)
	return
}

// WideLogParamsWithRange is the caller-parameterised variant of
// WideLogParams. Uses log-spaced intervals unconditionally; for narrow
// domains log spacing degenerates to near-uniform and still gives
// sub-percent accuracy matching the sigmoid primitive baseline.
func WideLogParamsWithRange(numIntervals int, lower, upper float64) (slopes, intercepts, thresholds []float64) {
	slopes, intercepts, thresholds = computeWideSplineLogSpaced(math.Log, numIntervals, lower, upper)
	return
}

// WideSplineLog evaluates log(x) on secret shares using a wide
// piecewise-linear spline with numIntervals intervals on [lower, upper].
// Follows the same structure as WideSplineReciprocal / WideSplineExp
// (asymmetric domain with two finite clamp values).
//
// Clamping:
//   - x < lower: clamp to log(lower) (a negative value for typical domains)
//   - x > upper: clamp to log(upper)
//
// Structure (identical to WideSplineReciprocal / WideSplineExp):
//   - 2 broad DCF comparisons (x < lower, x < upper)
//   - 1 Beaver AND for I_mid = NOT(c_low) * c_high
//   - (numIntervals-1) sub-interval DCF comparisons within [lower, upper)
//   - numIntervals individual ScalarVP for slopes and intercepts
//   - 1 Hadamard for slope*x
//   - 1 Hadamard for I_mid * spline_value
//   - Addition: y = I_low*log(lower) + I_high*log(upper) + I_mid * spline
func WideSplineLog(ring Ring63, x0, x1 []uint64, numIntervals int, lower, upper float64) (y0, y1 []uint64) {
	n := len(x0)
	slopes, intercepts, thresholds := WideLogParamsWithRange(numIntervals, lower, upper)

	// Finite clamp values: log is negative on (0, 1) and positive on (1, ∞)
	clampLowVal := math.Log(lower)  // e.g., log(0.01) = -4.605
	clampHighVal := math.Log(upper) // e.g., log(100)  = +4.605

	// Broad thresholds
	threshLow := ring.FromDouble(lower)
	threshHigh := ring.FromDouble(upper)

	p0PreL, p1PreL := cmpGeneratePreprocess(ring, n, threshLow)
	p0R1L := cmpRound1(ring, 0, x0, p0PreL)
	p1R1L := cmpRound1(ring, 1, x1, p1PreL)
	cmpLow0 := cmpRound2(ring, 0, p0PreL, p0R1L, p1R1L)
	cmpLow1 := cmpRound2(ring, 1, p1PreL, p1R1L, p0R1L)

	p0PreH, p1PreH := cmpGeneratePreprocess(ring, n, threshHigh)
	p0R1H := cmpRound1(ring, 0, x0, p0PreH)
	p1R1H := cmpRound1(ring, 1, x1, p1PreH)
	cmpHigh0 := cmpRound2(ring, 0, p0PreH, p0R1H, p1R1H)
	cmpHigh1 := cmpRound2(ring, 1, p1PreH, p1R1H, p0R1H)

	// I_mid = NOT(c_low) * c_high via Beaver AND
	notLow0 := make([]uint64, n)
	notLow1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		notLow0[i] = ring.Sub(1, cmpLow0.Shares[i])
		notLow1[i] = ring.Sub(0, cmpLow1.Shares[i])
	}
	bt0, bt1 := SampleBeaverTripleVector(n, ring)
	st0, msg0 := GenerateBatchedMultiplicationGateMessage(notLow0, cmpHigh0.Shares, bt0, ring)
	st1, msg1 := GenerateBatchedMultiplicationGateMessage(notLow1, cmpHigh1.Shares, bt1, ring)
	midInd0 := GenerateBatchedMultiplicationOutputPartyZero(st0, bt0, msg1, ring)
	midInd1 := GenerateBatchedMultiplicationOutputPartyOne(st1, bt1, msg0, ring)

	iMid0 := make([]uint64, n)
	iMid1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		iMid0[i] = modMulBig63(midInd0[i], ring.FracMul, ring.Modulus)
		iMid1[i] = modMulBig63(midInd1[i], ring.FracMul, ring.Modulus)
	}

	iLowFP0 := make([]uint64, n)
	iLowFP1 := make([]uint64, n)
	iHighFP0 := make([]uint64, n)
	iHighFP1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		iLowFP0[i] = modMulBig63(cmpLow0.Shares[i], ring.FracMul, ring.Modulus)
		iLowFP1[i] = modMulBig63(cmpLow1.Shares[i], ring.FracMul, ring.Modulus)
		iHighFP0[i] = modMulBig63(ring.Sub(1, cmpHigh0.Shares[i]), ring.FracMul, ring.Modulus)
		iHighFP1[i] = modMulBig63(ring.Sub(0, cmpHigh1.Shares[i]), ring.FracMul, ring.Modulus)
	}

	// Constant branch values via ScalarVP (ScalarVP handles negative scalars
	// correctly because the result is embedded back into the ring).
	lowVal0 := ScalarVectorProductPartyZero(clampLowVal, iLowFP0, ring)
	lowVal1 := ScalarVectorProductPartyOne(clampLowVal, iLowFP1, ring)
	highVal0 := ScalarVectorProductPartyZero(clampHighVal, iHighFP0, ring)
	highVal1 := ScalarVectorProductPartyOne(clampHighVal, iHighFP1, ring)

	// Sub-interval comparisons within [lower, upper) using log-spaced
	// thresholds from computeWideSplineLogSpaced. thresholds[0] = lower and
	// thresholds[numIntervals] = upper are already handled by the broad
	// comparisons above, so the sub-interval cuts consume thresholds[1..K-1].
	numCmp := numIntervals - 1
	subCmp0 := make([]CmpArithResult, numCmp)
	subCmp1 := make([]CmpArithResult, numCmp)
	for j := 0; j < numCmp; j++ {
		threshFP := ring.FromDouble(thresholds[j+1])
		p0Pre, p1Pre := cmpGeneratePreprocess(ring, n, threshFP)
		p0R1 := cmpRound1(ring, 0, x0, p0Pre)
		p1R1 := cmpRound1(ring, 1, x1, p1Pre)
		subCmp0[j] = cmpRound2(ring, 0, p0Pre, p0R1, p1R1)
		subCmp1[j] = cmpRound2(ring, 1, p1Pre, p1R1, p0R1)
	}

	subInd0 := make([][]uint64, numIntervals)
	subInd1 := make([][]uint64, numIntervals)
	for k := 0; k < numIntervals; k++ {
		subInd0[k] = make([]uint64, n)
		subInd1[k] = make([]uint64, n)
	}
	for i := 0; i < n; i++ {
		subInd0[0][i] = subCmp0[0].Shares[i]
		subInd1[0][i] = subCmp1[0].Shares[i]
		for j := 1; j < numCmp; j++ {
			subInd0[j][i] = ring.Sub(subCmp0[j].Shares[i], subCmp0[j-1].Shares[i])
			subInd1[j][i] = ring.Sub(subCmp1[j].Shares[i], subCmp1[j-1].Shares[i])
		}
		subInd0[numIntervals-1][i] = ring.Sub(1, subCmp0[numCmp-1].Shares[i])
		subInd1[numIntervals-1][i] = ring.Sub(0, subCmp1[numCmp-1].Shares[i])
	}
	for k := 0; k < numIntervals; k++ {
		for i := 0; i < n; i++ {
			subInd0[k][i] = modMulBig63(subInd0[k][i], ring.FracMul, ring.Modulus)
			subInd1[k][i] = modMulBig63(subInd1[k][i], ring.FracMul, ring.Modulus)
		}
	}

	aSlope0 := make([]uint64, n)
	aSlope1 := make([]uint64, n)
	bInt0 := make([]uint64, n)
	bInt1 := make([]uint64, n)
	for j := 0; j < numIntervals; j++ {
		sv0 := ScalarVectorProductPartyZero(slopes[j], subInd0[j], ring)
		sv1 := ScalarVectorProductPartyOne(slopes[j], subInd1[j], ring)
		bi0 := ScalarVectorProductPartyZero(intercepts[j], subInd0[j], ring)
		bi1 := ScalarVectorProductPartyOne(intercepts[j], subInd1[j], ring)
		for i := 0; i < n; i++ {
			aSlope0[i] = ring.Add(aSlope0[i], sv0[i])
			aSlope1[i] = ring.Add(aSlope1[i], sv1[i])
			bInt0[i] = ring.Add(bInt0[i], bi0[i])
			bInt1[i] = ring.Add(bInt1[i], bi1[i])
		}
	}

	btA0, btA1 := SampleBeaverTripleVector(n, ring)
	stA0, msgA0 := GenerateBatchedMultiplicationGateMessage(aSlope0, x0, btA0, ring)
	stA1, msgA1 := GenerateBatchedMultiplicationGateMessage(aSlope1, x1, btA1, ring)
	atx0, atx1 := StochasticHadamardProduct(stA0, btA0, msgA1, stA1, btA1, msgA0, ring.FracBits, ring)

	spline0 := make([]uint64, n)
	spline1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		spline0[i] = ring.Add(atx0[i], bInt0[i])
		spline1[i] = ring.Add(atx1[i], bInt1[i])
	}

	btM0, btM1 := SampleBeaverTripleVector(n, ring)
	stM0, msgM0 := GenerateBatchedMultiplicationGateMessage(iMid0, spline0, btM0, ring)
	stM1, msgM1 := GenerateBatchedMultiplicationGateMessage(iMid1, spline1, btM1, ring)
	midSpline0, midSpline1 := StochasticHadamardProduct(stM0, btM0, msgM1, stM1, btM1, msgM0, ring.FracBits, ring)

	y0 = make([]uint64, n)
	y1 = make([]uint64, n)
	for i := 0; i < n; i++ {
		y0[i] = ring.Add(ring.Add(lowVal0[i], highVal0[i]), midSpline0[i])
		y1[i] = ring.Add(ring.Add(lowVal1[i], highVal1[i]), midSpline1[i])
	}
	return
}

// WideSplineReciprocal evaluates 1/x on secret shares using a wide
// piecewise-linear spline with numIntervals intervals on [lower, upper].
// Follows the same structure as WideSplineExp (asymmetric domain with low
// and high clamp values) rather than WideSplineSigmoid (symmetric with
// saturation to 0).
//
// Clamping:
//   - x < lower: clamp to 1/lower (large positive value)
//   - x > upper: clamp to 1/upper (small positive value)
//
// Structure (matches WideSplineExp):
//   - 2 broad DCF comparisons (x < lower, x < upper)
//   - 1 Beaver AND for I_mid = NOT(c_low) * c_high
//   - (numIntervals-1) sub-interval DCF comparisons within [lower, upper)
//   - numIntervals individual ScalarVP for slopes and intercepts
//   - 1 Hadamard for slope*x
//   - 1 Hadamard for I_mid * spline_value
//   - Addition: mu = I_low*clampLow + I_high*clampHigh + I_mid * spline
func WideSplineReciprocal(ring Ring63, x0, x1 []uint64, numIntervals int, lower, upper float64) (mu0, mu1 []uint64) {
	n := len(x0)
	slopes, intercepts, thresholds := WideReciprocalParamsWithRange(numIntervals, lower, upper)

	// Saturation values: reciprocal has LARGE low-clamp, small high-clamp
	clampLowVal := 1.0 / lower  // e.g., 1/0.01 = 100
	clampHighVal := 1.0 / upper // e.g., 1/10 = 0.1

	// === Broad thresholds ===
	// c_low  = 1{x < lower}  (x below lower bound)
	// c_high = 1{x < upper}  (x below upper bound)
	threshLow := ring.FromDouble(lower)
	threshHigh := ring.FromDouble(upper)

	p0PreL, p1PreL := cmpGeneratePreprocess(ring, n, threshLow)
	p0R1L := cmpRound1(ring, 0, x0, p0PreL)
	p1R1L := cmpRound1(ring, 1, x1, p1PreL)
	cmpLow0 := cmpRound2(ring, 0, p0PreL, p0R1L, p1R1L)
	cmpLow1 := cmpRound2(ring, 1, p1PreL, p1R1L, p0R1L)

	p0PreH, p1PreH := cmpGeneratePreprocess(ring, n, threshHigh)
	p0R1H := cmpRound1(ring, 0, x0, p0PreH)
	p1R1H := cmpRound1(ring, 1, x1, p1PreH)
	cmpHigh0 := cmpRound2(ring, 0, p0PreH, p0R1H, p1R1H)
	cmpHigh1 := cmpRound2(ring, 1, p1PreH, p1R1H, p0R1H)

	// For reciprocal:
	// I_low  = c_low                     (x < lower -> clamp to 1/lower)
	// I_high = NOT(c_high)               (x >= upper -> clamp to 1/upper)
	// I_mid  = NOT(c_low) * c_high       (x in [lower, upper))

	// Compute I_mid via Beaver AND: NOT(c_low) * c_high
	notLow0 := make([]uint64, n)
	notLow1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		notLow0[i] = ring.Sub(1, cmpLow0.Shares[i])
		notLow1[i] = ring.Sub(0, cmpLow1.Shares[i])
	}
	bt0, bt1 := SampleBeaverTripleVector(n, ring)
	st0, msg0 := GenerateBatchedMultiplicationGateMessage(notLow0, cmpHigh0.Shares, bt0, ring)
	st1, msg1 := GenerateBatchedMultiplicationGateMessage(notLow1, cmpHigh1.Shares, bt1, ring)
	midInd0 := GenerateBatchedMultiplicationOutputPartyZero(st0, bt0, msg1, ring)
	midInd1 := GenerateBatchedMultiplicationOutputPartyOne(st1, bt1, msg0, ring)

	// Scale I_mid indicator to FP for the Hadamard with spline
	iMid0 := make([]uint64, n)
	iMid1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		iMid0[i] = modMulBig63(midInd0[i], ring.FracMul, ring.Modulus)
		iMid1[i] = modMulBig63(midInd1[i], ring.FracMul, ring.Modulus)
	}

	// I_low and I_high as FP-scaled indicators for ScalarVP
	iLowFP0 := make([]uint64, n)
	iLowFP1 := make([]uint64, n)
	iHighFP0 := make([]uint64, n)
	iHighFP1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		iLowFP0[i] = modMulBig63(cmpLow0.Shares[i], ring.FracMul, ring.Modulus)
		iLowFP1[i] = modMulBig63(cmpLow1.Shares[i], ring.FracMul, ring.Modulus)
		iHighFP0[i] = modMulBig63(ring.Sub(1, cmpHigh0.Shares[i]), ring.FracMul, ring.Modulus)
		iHighFP1[i] = modMulBig63(ring.Sub(0, cmpHigh1.Shares[i]), ring.FracMul, ring.Modulus)
	}

	// Constant branch values via ScalarVP:
	// I_low * clampLowVal (large), I_high * clampHighVal (small)
	lowVal0 := ScalarVectorProductPartyZero(clampLowVal, iLowFP0, ring)
	lowVal1 := ScalarVectorProductPartyOne(clampLowVal, iLowFP1, ring)
	highVal0 := ScalarVectorProductPartyZero(clampHighVal, iHighFP0, ring)
	highVal1 := ScalarVectorProductPartyOne(clampHighVal, iHighFP1, ring)

	// === Sub-interval comparisons within [lower, upper) ===
	// Thresholds come from computeWideSplineLogSpaced so the DCF cut
	// points are geometrically spaced; this yields uniform RELATIVE error
	// across the whole domain for 1/x (see computeWideSplineLogSpaced doc).
	numCmp := numIntervals - 1
	subCmp0 := make([]CmpArithResult, numCmp)
	subCmp1 := make([]CmpArithResult, numCmp)
	for j := 0; j < numCmp; j++ {
		threshFP := ring.FromDouble(thresholds[j+1])
		p0Pre, p1Pre := cmpGeneratePreprocess(ring, n, threshFP)
		p0R1 := cmpRound1(ring, 0, x0, p0Pre)
		p1R1 := cmpRound1(ring, 1, x1, p1Pre)
		subCmp0[j] = cmpRound2(ring, 0, p0Pre, p0R1, p1R1)
		subCmp1[j] = cmpRound2(ring, 1, p1Pre, p1R1, p0R1)
	}

	// Sub-indicators
	subInd0 := make([][]uint64, numIntervals)
	subInd1 := make([][]uint64, numIntervals)
	for k := 0; k < numIntervals; k++ {
		subInd0[k] = make([]uint64, n)
		subInd1[k] = make([]uint64, n)
	}
	for i := 0; i < n; i++ {
		subInd0[0][i] = subCmp0[0].Shares[i]
		subInd1[0][i] = subCmp1[0].Shares[i]
		for j := 1; j < numCmp; j++ {
			subInd0[j][i] = ring.Sub(subCmp0[j].Shares[i], subCmp0[j-1].Shares[i])
			subInd1[j][i] = ring.Sub(subCmp1[j].Shares[i], subCmp1[j-1].Shares[i])
		}
		subInd0[numIntervals-1][i] = ring.Sub(1, subCmp0[numCmp-1].Shares[i])
		subInd1[numIntervals-1][i] = ring.Sub(0, subCmp1[numCmp-1].Shares[i])
	}
	for k := 0; k < numIntervals; k++ {
		for i := 0; i < n; i++ {
			subInd0[k][i] = modMulBig63(subInd0[k][i], ring.FracMul, ring.Modulus)
			subInd1[k][i] = modMulBig63(subInd1[k][i], ring.FracMul, ring.Modulus)
		}
	}

	// Individual ScalarVP per interval for slopes and intercepts
	aSlope0 := make([]uint64, n)
	aSlope1 := make([]uint64, n)
	bInt0 := make([]uint64, n)
	bInt1 := make([]uint64, n)
	for j := 0; j < numIntervals; j++ {
		sv0 := ScalarVectorProductPartyZero(slopes[j], subInd0[j], ring)
		sv1 := ScalarVectorProductPartyOne(slopes[j], subInd1[j], ring)
		bi0 := ScalarVectorProductPartyZero(intercepts[j], subInd0[j], ring)
		bi1 := ScalarVectorProductPartyOne(intercepts[j], subInd1[j], ring)
		for i := 0; i < n; i++ {
			aSlope0[i] = ring.Add(aSlope0[i], sv0[i])
			aSlope1[i] = ring.Add(aSlope1[i], sv1[i])
			bInt0[i] = ring.Add(bInt0[i], bi0[i])
			bInt1[i] = ring.Add(bInt1[i], bi1[i])
		}
	}

	// Hadamard: a_t * x
	btA0, btA1 := SampleBeaverTripleVector(n, ring)
	stA0, msgA0 := GenerateBatchedMultiplicationGateMessage(aSlope0, x0, btA0, ring)
	stA1, msgA1 := GenerateBatchedMultiplicationGateMessage(aSlope1, x1, btA1, ring)
	atx0, atx1 := StochasticHadamardProduct(stA0, btA0, msgA1, stA1, btA1, msgA0, ring.FracBits, ring)

	// Spline value: a_t * x + b_t
	spline0 := make([]uint64, n)
	spline1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		spline0[i] = ring.Add(atx0[i], bInt0[i])
		spline1[i] = ring.Add(atx1[i], bInt1[i])
	}

	// Branch selection: mu = I_low*clampLow + I_high*clampHigh + I_mid * spline
	btM0, btM1 := SampleBeaverTripleVector(n, ring)
	stM0, msgM0 := GenerateBatchedMultiplicationGateMessage(iMid0, spline0, btM0, ring)
	stM1, msgM1 := GenerateBatchedMultiplicationGateMessage(iMid1, spline1, btM1, ring)
	midSpline0, midSpline1 := StochasticHadamardProduct(stM0, btM0, msgM1, stM1, btM1, msgM0, ring.FracBits, ring)

	mu0 = make([]uint64, n)
	mu1 = make([]uint64, n)
	for i := 0; i < n; i++ {
		mu0[i] = ring.Add(ring.Add(lowVal0[i], highVal0[i]), midSpline0[i])
		mu1[i] = ring.Add(ring.Add(lowVal1[i], highVal1[i]), midSpline1[i])
	}
	return
}

// WideSplineSigmoid evaluates sigmoid on secret shares using a wide piecewise-
// linear spline with numIntervals intervals on [-5, 5).
//
// Structure:
//   - 2 broad DCF comparisons for saturation (x < -5, x < 5)
//   - 1 Beaver AND for I_mid = NOT(c_low) * c_high
//   - (numIntervals-1) sub-interval DCF comparisons within [-5, 5)
//   - numIntervals individual ScalarVP for slopes and intercepts
//   - 1 Hadamard for slope*x
//   - 1 Hadamard for I_mid * spline_value
//   - Addition: mu = I_high + I_mid * spline
func WideSplineSigmoid(ring Ring63, x0, x1 []uint64, numIntervals int) (mu0, mu1 []uint64) {
	n := len(x0)
	slopes, intercepts, halfRange := WideSigmoidParams(numIntervals)
	width := 2.0 * halfRange / float64(numIntervals)

	// === Broad thresholds ===
	// c_low = 1{x < -halfRange}, c_high = 1{x < halfRange}
	threshLow := ring.FromDouble(-halfRange)
	threshHigh := ring.FromDouble(halfRange)

	p0PreL, p1PreL := cmpGeneratePreprocess(ring, n, threshLow)
	p0R1L := cmpRound1(ring, 0, x0, p0PreL)
	p1R1L := cmpRound1(ring, 1, x1, p1PreL)
	cmpLow0 := cmpRound2(ring, 0, p0PreL, p0R1L, p1R1L)
	cmpLow1 := cmpRound2(ring, 1, p1PreL, p1R1L, p0R1L)

	p0PreH, p1PreH := cmpGeneratePreprocess(ring, n, threshHigh)
	p0R1H := cmpRound1(ring, 0, x0, p0PreH)
	p1R1H := cmpRound1(ring, 1, x1, p1PreH)
	cmpHigh0 := cmpRound2(ring, 0, p0PreH, p0R1H, p1R1H)
	cmpHigh1 := cmpRound2(ring, 1, p1PreH, p1R1H, p0R1H)

	// DCF gives 1{x < threshold}:
	// c_low = 1{x < -L}  (x is below -L)
	// c_high = 1{x < L}  (x is below L)
	//
	// I_sat_high = NOT(c_high) = (x >= L) -> sigma ~ 1
	// I_sat_low  = c_low       = (x < -L) -> sigma ~ 0
	// I_mid      = NOT(c_low) * c_high = (x >= -L) AND (x < L) = x in [-L, L)

	// Compute I_mid via Beaver AND: NOT(c_low) * c_high
	notLow0 := make([]uint64, n)
	notLow1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		notLow0[i] = ring.Sub(1, cmpLow0.Shares[i])
		notLow1[i] = ring.Sub(0, cmpLow1.Shares[i])
	}
	bt0, bt1 := SampleBeaverTripleVector(n, ring)
	st0, msg0 := GenerateBatchedMultiplicationGateMessage(notLow0, cmpHigh0.Shares, bt0, ring)
	st1, msg1 := GenerateBatchedMultiplicationGateMessage(notLow1, cmpHigh1.Shares, bt1, ring)
	midInd0 := GenerateBatchedMultiplicationOutputPartyZero(st0, bt0, msg1, ring)
	midInd1 := GenerateBatchedMultiplicationOutputPartyOne(st1, bt1, msg0, ring)

	// I_sat_high = NOT(c_high) = 1 - c_high
	// Scale indicators to FP via modMulBig63(indicator, FracMul, Modulus)
	iHigh0 := make([]uint64, n)
	iHigh1 := make([]uint64, n)
	iMid0 := make([]uint64, n)
	iMid1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		// NOT(c_high) = (x >= L) -> saturate to 1
		iHigh0[i] = modMulBig63(ring.Sub(1, cmpHigh0.Shares[i]), ring.FracMul, ring.Modulus)
		iHigh1[i] = modMulBig63(ring.Sub(0, cmpHigh1.Shares[i]), ring.FracMul, ring.Modulus)
		iMid0[i] = modMulBig63(midInd0[i], ring.FracMul, ring.Modulus)
		iMid1[i] = modMulBig63(midInd1[i], ring.FracMul, ring.Modulus)
	}

	// === Sub-interval comparisons within [-L, L) ===
	numCmp := numIntervals - 1
	subCmp0 := make([]CmpArithResult, numCmp)
	subCmp1 := make([]CmpArithResult, numCmp)
	for j := 0; j < numCmp; j++ {
		thresh := -halfRange + float64(j+1)*width
		threshFP := ring.FromDouble(thresh)
		p0Pre, p1Pre := cmpGeneratePreprocess(ring, n, threshFP)
		p0R1 := cmpRound1(ring, 0, x0, p0Pre)
		p1R1 := cmpRound1(ring, 1, x1, p1Pre)
		subCmp0[j] = cmpRound2(ring, 0, p0Pre, p0R1, p1R1)
		subCmp1[j] = cmpRound2(ring, 1, p1Pre, p1R1, p0R1)
	}

	// Sub-indicators from comparisons:
	// subInd[0]    = c[0]
	// subInd[j]    = c[j] - c[j-1]   for 1 <= j < numCmp
	// subInd[last] = 1 - c[numCmp-1]
	subInd0 := make([][]uint64, numIntervals)
	subInd1 := make([][]uint64, numIntervals)
	for k := 0; k < numIntervals; k++ {
		subInd0[k] = make([]uint64, n)
		subInd1[k] = make([]uint64, n)
	}
	for i := 0; i < n; i++ {
		subInd0[0][i] = subCmp0[0].Shares[i]
		subInd1[0][i] = subCmp1[0].Shares[i]
		for j := 1; j < numCmp; j++ {
			subInd0[j][i] = ring.Sub(subCmp0[j].Shares[i], subCmp0[j-1].Shares[i])
			subInd1[j][i] = ring.Sub(subCmp1[j].Shares[i], subCmp1[j-1].Shares[i])
		}
		subInd0[numIntervals-1][i] = ring.Sub(1, subCmp0[numCmp-1].Shares[i])
		subInd1[numIntervals-1][i] = ring.Sub(0, subCmp1[numCmp-1].Shares[i])
	}

	// Scale sub-indicators to FP
	for k := 0; k < numIntervals; k++ {
		for i := 0; i < n; i++ {
			subInd0[k][i] = modMulBig63(subInd0[k][i], ring.FracMul, ring.Modulus)
			subInd1[k][i] = modMulBig63(subInd1[k][i], ring.FracMul, ring.Modulus)
		}
	}

	// === Individual ScalarVP per interval (NOT deferred) ===
	// Deferred truncation would overflow Ring63 at higher fracBits because
	// double-FP products (2*fracBits fractional bits) exceed 63 bits.
	// Individual ScalarVP truncates each product immediately, avoiding overflow.
	aSlope0 := make([]uint64, n)
	aSlope1 := make([]uint64, n)
	bInt0 := make([]uint64, n)
	bInt1 := make([]uint64, n)
	for j := 0; j < numIntervals; j++ {
		sv0 := ScalarVectorProductPartyZero(slopes[j], subInd0[j], ring)
		sv1 := ScalarVectorProductPartyOne(slopes[j], subInd1[j], ring)
		bi0 := ScalarVectorProductPartyZero(intercepts[j], subInd0[j], ring)
		bi1 := ScalarVectorProductPartyOne(intercepts[j], subInd1[j], ring)
		for i := 0; i < n; i++ {
			aSlope0[i] = ring.Add(aSlope0[i], sv0[i])
			aSlope1[i] = ring.Add(aSlope1[i], sv1[i])
			bInt0[i] = ring.Add(bInt0[i], bi0[i])
			bInt1[i] = ring.Add(bInt1[i], bi1[i])
		}
	}

	// Hadamard: a_t * x
	btA0, btA1 := SampleBeaverTripleVector(n, ring)
	stA0, msgA0 := GenerateBatchedMultiplicationGateMessage(aSlope0, x0, btA0, ring)
	stA1, msgA1 := GenerateBatchedMultiplicationGateMessage(aSlope1, x1, btA1, ring)
	atx0, atx1 := StochasticHadamardProduct(stA0, btA0, msgA1, stA1, btA1, msgA0, ring.FracBits, ring)

	// Spline value: a_t * x + b_t
	spline0 := make([]uint64, n)
	spline1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		spline0[i] = ring.Add(atx0[i], bInt0[i])
		spline1[i] = ring.Add(atx1[i], bInt1[i])
	}

	// === Branch selection ===
	// mu = I_high * 1.0 + I_mid * spline_value
	// I_high * 1.0: just iHigh (already in FP, represents 1.0 when active)
	// I_mid * spline_value: Hadamard product
	btM0, btM1 := SampleBeaverTripleVector(n, ring)
	stM0, msgM0 := GenerateBatchedMultiplicationGateMessage(iMid0, spline0, btM0, ring)
	stM1, msgM1 := GenerateBatchedMultiplicationGateMessage(iMid1, spline1, btM1, ring)
	midSpline0, midSpline1 := StochasticHadamardProduct(stM0, btM0, msgM1, stM1, btM1, msgM0, ring.FracBits, ring)

	mu0 = make([]uint64, n)
	mu1 = make([]uint64, n)
	for i := 0; i < n; i++ {
		mu0[i] = ring.Add(iHigh0[i], midSpline0[i])
		mu1[i] = ring.Add(iHigh1[i], midSpline1[i])
	}
	return
}

// WideSplineSoftplus evaluates softplus(x) = log(1+exp(x)) on secret shares
// using a wide piecewise-linear spline with numIntervals intervals on [-8, 8].
// Same pattern as WideSplineSigmoid but with softplus coefficients and
// saturation value softplus(8) ≈ 8.0003 instead of 1.0.
func WideSplineSoftplus(ring Ring63, x0, x1 []uint64, numIntervals int) (mu0, mu1 []uint64) {
	n := len(x0)
	slopes, intercepts, halfRange := WideSoftplusParams(numIntervals)
	width := 2.0 * halfRange / float64(numIntervals)
	satHighFP := ring.FromDouble(math.Log(1.0 + math.Exp(halfRange))) // softplus(8) ≈ 8.0003

	// Broad thresholds
	threshLow := ring.FromDouble(-halfRange)
	threshHigh := ring.FromDouble(halfRange)

	p0PreL, p1PreL := cmpGeneratePreprocess(ring, n, threshLow)
	p0R1L := cmpRound1(ring, 0, x0, p0PreL)
	p1R1L := cmpRound1(ring, 1, x1, p1PreL)
	cmpLow0 := cmpRound2(ring, 0, p0PreL, p0R1L, p1R1L)
	cmpLow1 := cmpRound2(ring, 1, p1PreL, p1R1L, p0R1L)

	p0PreH, p1PreH := cmpGeneratePreprocess(ring, n, threshHigh)
	p0R1H := cmpRound1(ring, 0, x0, p0PreH)
	p1R1H := cmpRound1(ring, 1, x1, p1PreH)
	cmpHigh0 := cmpRound2(ring, 0, p0PreH, p0R1H, p1R1H)
	cmpHigh1 := cmpRound2(ring, 1, p1PreH, p1R1H, p0R1H)

	// I_mid = NOT(c_low) * c_high
	notLow0 := make([]uint64, n)
	notLow1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		notLow0[i] = ring.Sub(1, cmpLow0.Shares[i])
		notLow1[i] = ring.Sub(0, cmpLow1.Shares[i])
	}
	bt0, bt1 := SampleBeaverTripleVector(n, ring)
	st0, msg0 := GenerateBatchedMultiplicationGateMessage(notLow0, cmpHigh0.Shares, bt0, ring)
	st1, msg1 := GenerateBatchedMultiplicationGateMessage(notLow1, cmpHigh1.Shares, bt1, ring)
	midInd0 := GenerateBatchedMultiplicationOutputPartyZero(st0, bt0, msg1, ring)
	midInd1 := GenerateBatchedMultiplicationOutputPartyOne(st1, bt1, msg0, ring)

	// Saturation: I_high * satHigh (not 1.0!)
	iHigh0 := make([]uint64, n)
	iHigh1 := make([]uint64, n)
	iMid0 := make([]uint64, n)
	iMid1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		iHigh0[i] = modMulBig63(ring.Sub(1, cmpHigh0.Shares[i]), satHighFP, ring.Modulus)
		iHigh1[i] = modMulBig63(ring.Sub(0, cmpHigh1.Shares[i]), satHighFP, ring.Modulus)
		iMid0[i] = modMulBig63(midInd0[i], ring.FracMul, ring.Modulus)
		iMid1[i] = modMulBig63(midInd1[i], ring.FracMul, ring.Modulus)
	}

	// Sub-interval comparisons
	numCmp := numIntervals - 1
	subCmp0 := make([]CmpArithResult, numCmp)
	subCmp1 := make([]CmpArithResult, numCmp)
	for j := 0; j < numCmp; j++ {
		thresh := -halfRange + float64(j+1)*width
		threshFP := ring.FromDouble(thresh)
		p0Pre, p1Pre := cmpGeneratePreprocess(ring, n, threshFP)
		p0R1 := cmpRound1(ring, 0, x0, p0Pre)
		p1R1 := cmpRound1(ring, 1, x1, p1Pre)
		subCmp0[j] = cmpRound2(ring, 0, p0Pre, p0R1, p1R1)
		subCmp1[j] = cmpRound2(ring, 1, p1Pre, p1R1, p0R1)
	}

	subInd0 := make([][]uint64, numIntervals)
	subInd1 := make([][]uint64, numIntervals)
	for k := 0; k < numIntervals; k++ {
		subInd0[k] = make([]uint64, n)
		subInd1[k] = make([]uint64, n)
	}
	for i := 0; i < n; i++ {
		subInd0[0][i] = subCmp0[0].Shares[i]
		subInd1[0][i] = subCmp1[0].Shares[i]
		for j := 1; j < numCmp; j++ {
			subInd0[j][i] = ring.Sub(subCmp0[j].Shares[i], subCmp0[j-1].Shares[i])
			subInd1[j][i] = ring.Sub(subCmp1[j].Shares[i], subCmp1[j-1].Shares[i])
		}
		subInd0[numIntervals-1][i] = ring.Sub(1, subCmp0[numCmp-1].Shares[i])
		subInd1[numIntervals-1][i] = ring.Sub(0, subCmp1[numCmp-1].Shares[i])
	}
	for k := 0; k < numIntervals; k++ {
		for i := 0; i < n; i++ {
			subInd0[k][i] = modMulBig63(subInd0[k][i], ring.FracMul, ring.Modulus)
			subInd1[k][i] = modMulBig63(subInd1[k][i], ring.FracMul, ring.Modulus)
		}
	}

	// ScalarVP per interval
	aSlope0 := make([]uint64, n)
	aSlope1 := make([]uint64, n)
	bInt0 := make([]uint64, n)
	bInt1 := make([]uint64, n)
	for j := 0; j < numIntervals; j++ {
		sv0 := ScalarVectorProductPartyZero(slopes[j], subInd0[j], ring)
		sv1 := ScalarVectorProductPartyOne(slopes[j], subInd1[j], ring)
		bi0 := ScalarVectorProductPartyZero(intercepts[j], subInd0[j], ring)
		bi1 := ScalarVectorProductPartyOne(intercepts[j], subInd1[j], ring)
		for i := 0; i < n; i++ {
			aSlope0[i] = ring.Add(aSlope0[i], sv0[i])
			aSlope1[i] = ring.Add(aSlope1[i], sv1[i])
			bInt0[i] = ring.Add(bInt0[i], bi0[i])
			bInt1[i] = ring.Add(bInt1[i], bi1[i])
		}
	}

	// Hadamard: slope * x
	btA0, btA1 := SampleBeaverTripleVector(n, ring)
	stA0, msgA0 := GenerateBatchedMultiplicationGateMessage(aSlope0, x0, btA0, ring)
	stA1, msgA1 := GenerateBatchedMultiplicationGateMessage(aSlope1, x1, btA1, ring)
	atx0, atx1 := StochasticHadamardProduct(stA0, btA0, msgA1, stA1, btA1, msgA0, ring.FracBits, ring)

	// spline = slope*x + intercept
	spline0 := make([]uint64, n)
	spline1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		spline0[i] = ring.Add(atx0[i], bInt0[i])
		spline1[i] = ring.Add(atx1[i], bInt1[i])
	}

	// I_mid * spline
	btM0, btM1 := SampleBeaverTripleVector(n, ring)
	stM0, msgM0 := GenerateBatchedMultiplicationGateMessage(iMid0, spline0, btM0, ring)
	stM1, msgM1 := GenerateBatchedMultiplicationGateMessage(iMid1, spline1, btM1, ring)
	midSpline0, midSpline1 := StochasticHadamardProduct(stM0, btM0, msgM1, stM1, btM1, msgM0, ring.FracBits, ring)

	// result = iHigh + I_mid * spline
	mu0 = make([]uint64, n)
	mu1 = make([]uint64, n)
	for i := 0; i < n; i++ {
		mu0[i] = ring.Add(iHigh0[i], midSpline0[i])
		mu1[i] = ring.Add(iHigh1[i], midSpline1[i])
	}
	return
}

// WideSplineExp evaluates exp(x) on secret shares using a wide piecewise-
// linear spline with numIntervals intervals on [-3, 8].
//
// Clamping:
//   - x < -3: clamp to small positive value (1e-6) to avoid log(0)
//   - x > 8:  clamp to exp(8) ~ 2981
//
// Structure:
//   - 2 broad DCF comparisons (x < lower, x < upper)
//   - 1 Beaver AND for I_mid = NOT(c_low) * c_high
//   - (numIntervals-1) sub-interval DCF comparisons within [lower, upper)
//   - numIntervals individual ScalarVP for slopes and intercepts
//   - 1 Hadamard for slope*x
//   - 1 Hadamard for I_mid * spline_value
//   - Addition: mu = I_low_val + I_high_val + I_mid * spline
func WideSplineExp(ring Ring63, x0, x1 []uint64, numIntervals int) (mu0, mu1 []uint64) {
	n := len(x0)
	slopes, intercepts, lower, upper := WideExpParams(numIntervals)
	width := (upper - lower) / float64(numIntervals)

	// Saturation values
	clampLowVal := 1e-6             // exp(x) -> small positive for x < -3
	clampHighVal := math.Exp(upper) // exp(8) ~ 2981

	// === Broad thresholds ===
	// c_low  = 1{x < lower}  (x below lower bound)
	// c_high = 1{x < upper}  (x below upper bound)
	threshLow := ring.FromDouble(lower)
	threshHigh := ring.FromDouble(upper)

	p0PreL, p1PreL := cmpGeneratePreprocess(ring, n, threshLow)
	p0R1L := cmpRound1(ring, 0, x0, p0PreL)
	p1R1L := cmpRound1(ring, 1, x1, p1PreL)
	cmpLow0 := cmpRound2(ring, 0, p0PreL, p0R1L, p1R1L)
	cmpLow1 := cmpRound2(ring, 1, p1PreL, p1R1L, p0R1L)

	p0PreH, p1PreH := cmpGeneratePreprocess(ring, n, threshHigh)
	p0R1H := cmpRound1(ring, 0, x0, p0PreH)
	p1R1H := cmpRound1(ring, 1, x1, p1PreH)
	cmpHigh0 := cmpRound2(ring, 0, p0PreH, p0R1H, p1R1H)
	cmpHigh1 := cmpRound2(ring, 1, p1PreH, p1R1H, p0R1H)

	// For Poisson exp:
	// I_low  = c_low                     (x < lower -> clamp to small value)
	// I_high = NOT(c_high)               (x >= upper -> clamp to exp(upper))
	// I_mid  = NOT(c_low) * c_high       (x in [lower, upper))

	// Compute I_mid via Beaver AND: NOT(c_low) * c_high
	notLow0 := make([]uint64, n)
	notLow1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		notLow0[i] = ring.Sub(1, cmpLow0.Shares[i])
		notLow1[i] = ring.Sub(0, cmpLow1.Shares[i])
	}
	bt0, bt1 := SampleBeaverTripleVector(n, ring)
	st0, msg0 := GenerateBatchedMultiplicationGateMessage(notLow0, cmpHigh0.Shares, bt0, ring)
	st1, msg1 := GenerateBatchedMultiplicationGateMessage(notLow1, cmpHigh1.Shares, bt1, ring)
	midInd0 := GenerateBatchedMultiplicationOutputPartyZero(st0, bt0, msg1, ring)
	midInd1 := GenerateBatchedMultiplicationOutputPartyOne(st1, bt1, msg0, ring)

	// Scale indicators to FP and compute branch constant contributions.
	//
	// I_low  = c_low          -> value = clampLowVal
	// I_high = NOT(c_high)    -> value = clampHighVal
	// I_mid  = midInd         -> value = spline(x)
	//
	// For the constant branches, we compute I_low * clampLowVal and
	// I_high * clampHighVal via ScalarVP.
	//
	// First, scale I_mid indicator to FP for the Hadamard with spline.
	iMid0 := make([]uint64, n)
	iMid1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		iMid0[i] = modMulBig63(midInd0[i], ring.FracMul, ring.Modulus)
		iMid1[i] = modMulBig63(midInd1[i], ring.FracMul, ring.Modulus)
	}

	// I_low and I_high as FP-scaled indicators for ScalarVP
	iLowFP0 := make([]uint64, n)
	iLowFP1 := make([]uint64, n)
	iHighFP0 := make([]uint64, n)
	iHighFP1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		// I_low = c_low
		iLowFP0[i] = modMulBig63(cmpLow0.Shares[i], ring.FracMul, ring.Modulus)
		iLowFP1[i] = modMulBig63(cmpLow1.Shares[i], ring.FracMul, ring.Modulus)
		// I_high = NOT(c_high) = 1 - c_high
		iHighFP0[i] = modMulBig63(ring.Sub(1, cmpHigh0.Shares[i]), ring.FracMul, ring.Modulus)
		iHighFP1[i] = modMulBig63(ring.Sub(0, cmpHigh1.Shares[i]), ring.FracMul, ring.Modulus)
	}

	// Constant branch values via ScalarVP:
	// I_low * clampLowVal, I_high * clampHighVal
	lowVal0 := ScalarVectorProductPartyZero(clampLowVal, iLowFP0, ring)
	lowVal1 := ScalarVectorProductPartyOne(clampLowVal, iLowFP1, ring)
	highVal0 := ScalarVectorProductPartyZero(clampHighVal, iHighFP0, ring)
	highVal1 := ScalarVectorProductPartyOne(clampHighVal, iHighFP1, ring)

	// === Sub-interval comparisons within [lower, upper) ===
	numCmp := numIntervals - 1
	subCmp0 := make([]CmpArithResult, numCmp)
	subCmp1 := make([]CmpArithResult, numCmp)
	for j := 0; j < numCmp; j++ {
		thresh := lower + float64(j+1)*width
		threshFP := ring.FromDouble(thresh)
		p0Pre, p1Pre := cmpGeneratePreprocess(ring, n, threshFP)
		p0R1 := cmpRound1(ring, 0, x0, p0Pre)
		p1R1 := cmpRound1(ring, 1, x1, p1Pre)
		subCmp0[j] = cmpRound2(ring, 0, p0Pre, p0R1, p1R1)
		subCmp1[j] = cmpRound2(ring, 1, p1Pre, p1R1, p0R1)
	}

	// Sub-indicators from comparisons
	subInd0 := make([][]uint64, numIntervals)
	subInd1 := make([][]uint64, numIntervals)
	for k := 0; k < numIntervals; k++ {
		subInd0[k] = make([]uint64, n)
		subInd1[k] = make([]uint64, n)
	}
	for i := 0; i < n; i++ {
		subInd0[0][i] = subCmp0[0].Shares[i]
		subInd1[0][i] = subCmp1[0].Shares[i]
		for j := 1; j < numCmp; j++ {
			subInd0[j][i] = ring.Sub(subCmp0[j].Shares[i], subCmp0[j-1].Shares[i])
			subInd1[j][i] = ring.Sub(subCmp1[j].Shares[i], subCmp1[j-1].Shares[i])
		}
		subInd0[numIntervals-1][i] = ring.Sub(1, subCmp0[numCmp-1].Shares[i])
		subInd1[numIntervals-1][i] = ring.Sub(0, subCmp1[numCmp-1].Shares[i])
	}

	// Scale sub-indicators to FP
	for k := 0; k < numIntervals; k++ {
		for i := 0; i < n; i++ {
			subInd0[k][i] = modMulBig63(subInd0[k][i], ring.FracMul, ring.Modulus)
			subInd1[k][i] = modMulBig63(subInd1[k][i], ring.FracMul, ring.Modulus)
		}
	}

	// === Individual ScalarVP per interval (NOT deferred) ===
	aSlope0 := make([]uint64, n)
	aSlope1 := make([]uint64, n)
	bInt0 := make([]uint64, n)
	bInt1 := make([]uint64, n)
	for j := 0; j < numIntervals; j++ {
		sv0 := ScalarVectorProductPartyZero(slopes[j], subInd0[j], ring)
		sv1 := ScalarVectorProductPartyOne(slopes[j], subInd1[j], ring)
		bi0 := ScalarVectorProductPartyZero(intercepts[j], subInd0[j], ring)
		bi1 := ScalarVectorProductPartyOne(intercepts[j], subInd1[j], ring)
		for i := 0; i < n; i++ {
			aSlope0[i] = ring.Add(aSlope0[i], sv0[i])
			aSlope1[i] = ring.Add(aSlope1[i], sv1[i])
			bInt0[i] = ring.Add(bInt0[i], bi0[i])
			bInt1[i] = ring.Add(bInt1[i], bi1[i])
		}
	}

	// Hadamard: a_t * x
	btA0, btA1 := SampleBeaverTripleVector(n, ring)
	stA0, msgA0 := GenerateBatchedMultiplicationGateMessage(aSlope0, x0, btA0, ring)
	stA1, msgA1 := GenerateBatchedMultiplicationGateMessage(aSlope1, x1, btA1, ring)
	atx0, atx1 := StochasticHadamardProduct(stA0, btA0, msgA1, stA1, btA1, msgA0, ring.FracBits, ring)

	// Spline value: a_t * x + b_t
	spline0 := make([]uint64, n)
	spline1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		spline0[i] = ring.Add(atx0[i], bInt0[i])
		spline1[i] = ring.Add(atx1[i], bInt1[i])
	}

	// === Branch selection ===
	// mu = I_low * clampLowVal + I_high * clampHighVal + I_mid * spline(x)
	btM0, btM1 := SampleBeaverTripleVector(n, ring)
	stM0, msgM0 := GenerateBatchedMultiplicationGateMessage(iMid0, spline0, btM0, ring)
	stM1, msgM1 := GenerateBatchedMultiplicationGateMessage(iMid1, spline1, btM1, ring)
	midSpline0, midSpline1 := StochasticHadamardProduct(stM0, btM0, msgM1, stM1, btM1, msgM0, ring.FracBits, ring)

	mu0 = make([]uint64, n)
	mu1 = make([]uint64, n)
	for i := 0; i < n; i++ {
		mu0[i] = ring.Add(ring.Add(lowVal0[i], highVal0[i]), midSpline0[i])
		mu1[i] = ring.Add(ring.Add(lowVal1[i], highVal1[i]), midSpline1[i])
	}
	return
}
