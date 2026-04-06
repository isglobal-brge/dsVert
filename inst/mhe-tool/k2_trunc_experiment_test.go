package main

import (
	"math"
	"testing"
)

// ============================================================================
// Truncation alternatives — all take BOTH parties' shares, return BOTH
// ============================================================================

type truncFn func(s0, s1, div, mod uint64) (uint64, uint64)

// floorTruncBoth: current Ring63 asymmetric truncation (reproduces existing behavior)
func floorTruncBoth(s0, s1, div, mod uint64) (uint64, uint64) {
	t0 := TruncateSharePartyZero([]uint64{s0}, div, mod)[0]
	t1 := TruncateSharePartyOne([]uint64{s1}, div, mod)[0]
	return t0, t1
}

// signedTruncate does SIGNED floor division of a Ring63 value.
// Ring63 values >= mod/2 represent negative numbers.
// Unsigned division gives WRONG results for negative values.
func signedTruncate(prod, div, mod uint64) uint64 {
	half := mod / 2
	if prod >= half {
		// Negative: negate, divide, negate back
		negProd := (mod - prod) % mod
		negTr := negProd / div
		return (mod - negTr) % mod
	}
	return prod / div
}

// signedRemainder returns the unsigned remainder for TruncPr.
// For negative Ring63 values, we negate first to get the correct remainder.
func signedRemainder(prod, div, mod uint64) uint64 {
	half := mod / 2
	if prod >= half {
		negProd := (mod - prod) % mod
		return negProd % div
	}
	return prod % div
}

// idealTruncBoth: reconstruct exact product, SIGNED floor divide, re-share.
// ZERO truncation error. NOT secure (requires both shares). For testing only.
func idealTruncBoth(s0, s1, div, mod uint64) (uint64, uint64) {
	prod := (s0 + s1) % mod
	tr := signedTruncate(prod, div, mod)
	t0 := cryptoRandUint64K2() % mod
	t1 := (mod + tr - t0) % mod
	return t0, t1
}

// truncPrBoth: Catrina-Saxena probabilistic truncation. Reconstruct, SIGNED exact floor,
// then round toward zero with probability remainder/divisor. E[result] = exact value (UNBIASED).
// NOT secure in this form (requires reconstruction). For testing only.
func truncPrBoth(s0, s1, div, mod uint64) (uint64, uint64) {
	prod := (s0 + s1) % mod
	tr := signedTruncate(prod, div, mod)
	rem := signedRemainder(prod, div, mod)
	th := cryptoRandUint64K2() % div
	half := mod / 2
	if rem > th {
		if prod >= half {
			// Negative: round toward zero = add 1 (less negative)
			tr = (tr + 1) % mod
		} else {
			// Positive: round toward zero = add 1
			tr = (tr + 1) % mod
		}
	}
	t0 := cryptoRandUint64K2() % mod
	t1 := (mod + tr - t0) % mod
	return t0, t1
}

// ============================================================================
// Hadamard product with pluggable truncation
// ============================================================================

func hadamardBothFn(x0, y0, x1, y1 []uint64, fracBits int, r Ring63, tf truncFn) (res0, res1 []uint64) {
	n := len(x0)
	b0, b1 := SampleBeaverTripleVector(n, r)
	st0, msg0 := GenerateBatchedMultiplicationGateMessage(x0, y0, b0, r)
	st1, msg1 := GenerateBatchedMultiplicationGateMessage(x1, y1, b1, r)
	raw0 := GenerateBatchedMultiplicationOutputPartyZero(st0, b0, msg1, r)
	raw1 := GenerateBatchedMultiplicationOutputPartyOne(st1, b1, msg0, r)

	div := uint64(1) << fracBits
	res0 = make([]uint64, n)
	res1 = make([]uint64, n)
	for i := range raw0 {
		res0[i], res1[i] = tf(raw0[i], raw1[i], div, r.Modulus)
	}
	return
}

// ============================================================================
// Modified evalSplineOnShares with pluggable truncation
// ============================================================================

func evalSplineOnSharesFn(ring Ring63, params SigmoidParams, x0, x1 []uint64, tf truncFn) (res0, res1 []uint64) {
	n := len(x0)
	numInt := params.SplineNumIntervals
	numCmp := numInt - 1
	width := 1.0 / float64(numInt)

	// Sub-interval comparisons (unchanged — no truncation involved)
	subCmp0 := make([]CmpArithResult, numCmp)
	subCmp1 := make([]CmpArithResult, numCmp)
	for j := 0; j < numCmp; j++ {
		tf2 := float64(j+1) * width
		threshFP := ring.FromDouble(tf2)
		p0Pre, p1Pre := cmpGeneratePreprocess(ring, n, threshFP)
		p0R1 := cmpRound1(ring, 0, x0, p0Pre)
		p1R1 := cmpRound1(ring, 1, x1, p1Pre)
		subCmp0[j] = cmpRound2(ring, 0, p0Pre, p0R1, p1R1)
		subCmp1[j] = cmpRound2(ring, 1, p1Pre, p1R1, p0R1)
	}

	// Sub-indicators (unchanged)
	subInd0 := make([][]uint64, numInt)
	subInd1 := make([][]uint64, numInt)
	for k := 0; k < numInt; k++ {
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
		subInd0[numInt-1][i] = ring.Sub(1, subCmp0[numCmp-1].Shares[i])
		subInd1[numInt-1][i] = ring.Sub(0, subCmp1[numCmp-1].Shares[i])
	}

	// Scale to FP (unchanged — exact, no truncation)
	for k := 0; k < numInt; k++ {
		for i := 0; i < n; i++ {
			subInd0[k][i] = modMulBig63(subInd0[k][i], ring.FracMul, ring.Modulus)
			subInd1[k][i] = modMulBig63(subInd1[k][i], ring.FracMul, ring.Modulus)
		}
	}

	// Deferred ScalarVP accumulation (unchanged — no truncation yet)
	aSlope0 := make([]uint64, n)
	aSlope1 := make([]uint64, n)
	bIntercept0 := make([]uint64, n)
	bIntercept1 := make([]uint64, n)
	for j := 0; j < numInt; j++ {
		slopeFP := ring.FromDouble(params.SplineSlopes[j])
		interceptFP := ring.FromDouble(params.SplineIntercepts[j])
		for i := 0; i < n; i++ {
			aSlope0[i] = ring.Add(aSlope0[i], modMulBig63(slopeFP, subInd0[j][i], ring.Modulus))
			aSlope1[i] = ring.Add(aSlope1[i], modMulBig63(slopeFP, subInd1[j][i], ring.Modulus))
			bIntercept0[i] = ring.Add(bIntercept0[i], modMulBig63(interceptFP, subInd0[j][i], ring.Modulus))
			bIntercept1[i] = ring.Add(bIntercept1[i], modMulBig63(interceptFP, subInd1[j][i], ring.Modulus))
		}
	}

	// *** TRUNCATION POINT 1: deferred ScalarVP — uses pluggable tf ***
	divisor := ring.FracMul
	for i := 0; i < n; i++ {
		aSlope0[i], aSlope1[i] = tf(aSlope0[i], aSlope1[i], divisor, ring.Modulus)
		bIntercept0[i], bIntercept1[i] = tf(bIntercept0[i], bIntercept1[i], divisor, ring.Modulus)
	}

	// *** TRUNCATION POINT 2: Hadamard a_t × x — uses pluggable tf ***
	atx0, atx1 := hadamardBothFn(aSlope0, x0, aSlope1, x1, ring.FracBits, ring, tf)

	// Result: a_t * x + b_t
	res0 = make([]uint64, n)
	res1 = make([]uint64, n)
	for i := 0; i < n; i++ {
		res0[i] = ring.Add(atx0[i], bIntercept0[i])
		res1[i] = ring.Add(atx1[i], bIntercept1[i])
	}
	return
}

// ============================================================================
// Modified securePolyEvalLocal with pluggable truncation
// ============================================================================

func securePolyEvalLocalFn(ring Ring63, coeffs []float64, x0, x1 []uint64, tf truncFn) (p0, p1 []uint64) {
	n := len(x0)
	degree := len(coeffs) - 1

	pow0 := make([][]uint64, degree+1)
	pow1 := make([][]uint64, degree+1)

	// x^0
	pow0[0] = make([]uint64, n)
	pow1[0] = make([]uint64, n)
	oneFP := ring.FromDouble(1.0)
	for i := range pow0[0] {
		pow0[0][i] = oneFP
	}

	// x^1
	pow0[1] = make([]uint64, n)
	pow1[1] = make([]uint64, n)
	copy(pow0[1], x0)
	copy(pow1[1], x1)

	// Higher powers via Beaver with pluggable truncation
	for k := 2; k <= degree; k++ {
		a, b := k/2, k-k/2
		if k%2 != 0 {
			a, b = k-1, 1
		}
		pow0[k], pow1[k] = hadamardBothFn(pow0[a], pow0[b], pow1[a], pow1[b], ring.FracBits, ring, tf)
	}

	// Deferred linear combination (no truncation yet)
	p0 = make([]uint64, n)
	p1 = make([]uint64, n)
	for k := 0; k <= degree; k++ {
		coeffFP := ring.FromDouble(coeffs[k])
		for i := 0; i < n; i++ {
			p0[i] = ring.Add(p0[i], modMulBig63(coeffFP, pow0[k][i], ring.Modulus))
			p1[i] = ring.Add(p1[i], modMulBig63(coeffFP, pow1[k][i], ring.Modulus))
		}
	}

	// *** TRUNCATION POINT: deferred ScalarVP — pluggable ***
	divisor := ring.FracMul
	for i := 0; i < n; i++ {
		p0[i], p1[i] = tf(p0[i], p1[i], divisor, ring.Modulus)
	}
	return
}

// ============================================================================
// Modified evalExpTaylorOnShares with pluggable truncation
// (Kelkar exp itself is unchanged — only the Taylor polynomial uses tf)
// ============================================================================

func evalExpTaylorOnSharesFn(ring Ring63, x0, x1 []uint64, tf truncFn) (res0, res1 []uint64) {
	cfg := ExpConfig{Ring: ring, ExponentBound: 3, PrimeQ: 2305843009213693951}
	z0, z1 := SecureExpKelkar(cfg, x0, x1)

	taylorCoeffs := make([]float64, 11)
	for k := 0; k <= 10; k++ {
		if k%2 == 0 {
			taylorCoeffs[k] = 1.0
		} else {
			taylorCoeffs[k] = -1.0
		}
	}

	res0, res1 = securePolyEvalLocalFn(ring, taylorCoeffs, z0, z1, tf)
	return
}

// ============================================================================
// Modified DistributedSigmoidLocalMhe with pluggable truncation
// ============================================================================

func distributedSigmoidFn(ring Ring63, x0, x1 []uint64, tf truncFn) (mu0, mu1 []uint64) {
	n := len(x0)
	params := SigmoidParams{
		Ring: ring, FracBits: ring.FracBits,
		SplineSlopes:       DefaultSigmoidParams().SplineSlopes,
		SplineIntercepts:   DefaultSigmoidParams().SplineIntercepts,
		SplineNumIntervals: 10, TaylorDegree: 10,
		ExpConfig: ExpConfig{Ring: ring, ExponentBound: 3, PrimeQ: 2305843009213693951},
	}
	lfLn2 := float64(params.ExpConfig.ExponentBound)

	// Step 1: 5 comparisons (unchanged)
	thresholds := []float64{-lfLn2, -1.0, 0.0, 1.0, lfLn2}
	cmp0 := make([]CmpArithResult, 5)
	cmp1 := make([]CmpArithResult, 5)
	for j, tf2 := range thresholds {
		threshFP := ring.FromDouble(tf2)
		p0Pre, p1Pre := cmpGeneratePreprocess(ring, n, threshFP)
		p0R1 := cmpRound1(ring, 0, x0, p0Pre)
		p1R1 := cmpRound1(ring, 1, x1, p1Pre)
		cmp0[j] = cmpRound2(ring, 0, p0Pre, p0R1, p1R1)
		cmp1[j] = cmpRound2(ring, 1, p1Pre, p1R1, p0R1)
	}

	// Step 2: Interval indicators via Beaver AND (unchanged — integer products, no truncation)
	notR63 := func(share uint64, partyID int) uint64 {
		if partyID == 0 {
			return ring.Sub(1, share)
		}
		return ring.Sub(0, share)
	}

	type andPair struct{ a0, b0, a1, b1 []uint64 }
	ands := [4]andPair{}
	for i := 0; i < n; i++ {
		if i == 0 {
			for k := range ands {
				ands[k].a0 = make([]uint64, n)
				ands[k].b0 = make([]uint64, n)
				ands[k].a1 = make([]uint64, n)
				ands[k].b1 = make([]uint64, n)
			}
		}
		ands[0].a0[i] = notR63(cmp0[2].Shares[i], 0)
		ands[0].b0[i] = cmp0[3].Shares[i]
		ands[0].a1[i] = notR63(cmp1[2].Shares[i], 1)
		ands[0].b1[i] = cmp1[3].Shares[i]
		ands[1].a0[i] = notR63(cmp0[3].Shares[i], 0)
		ands[1].b0[i] = cmp0[4].Shares[i]
		ands[1].a1[i] = notR63(cmp1[3].Shares[i], 1)
		ands[1].b1[i] = cmp1[4].Shares[i]
		ands[2].a0[i] = notR63(cmp0[0].Shares[i], 0)
		ands[2].b0[i] = cmp0[1].Shares[i]
		ands[2].a1[i] = notR63(cmp1[0].Shares[i], 1)
		ands[2].b1[i] = cmp1[1].Shares[i]
		ands[3].a0[i] = notR63(cmp0[1].Shares[i], 0)
		ands[3].b0[i] = cmp0[2].Shares[i]
		ands[3].a1[i] = notR63(cmp1[1].Shares[i], 1)
		ands[3].b1[i] = cmp1[2].Shares[i]
	}

	andRes0 := [4][]uint64{}
	andRes1 := [4][]uint64{}
	for k := 0; k < 4; k++ {
		t0, t1 := SampleBeaverTripleVector(n, ring)
		st0, msg0 := GenerateBatchedMultiplicationGateMessage(ands[k].a0, ands[k].b0, t0, ring)
		st1, msg1 := GenerateBatchedMultiplicationGateMessage(ands[k].a1, ands[k].b1, t1, ring)
		andRes0[k] = GenerateBatchedMultiplicationOutputPartyZero(st0, t0, msg1, ring)
		andRes1[k] = GenerateBatchedMultiplicationOutputPartyOne(st1, t1, msg0, ring)
	}

	ind0 := [6][]uint64{}
	ind1 := [6][]uint64{}
	ind0[0] = andRes0[0]
	ind1[0] = andRes1[0]
	ind0[1] = andRes0[1]
	ind1[1] = andRes1[1]
	ind0[2] = make([]uint64, n)
	ind1[2] = make([]uint64, n)
	ind0[3] = make([]uint64, n)
	ind1[3] = make([]uint64, n)
	ind0[4] = andRes0[2]
	ind1[4] = andRes1[2]
	ind0[5] = andRes0[3]
	ind1[5] = andRes1[3]
	for i := 0; i < n; i++ {
		ind0[2][i] = notR63(cmp0[4].Shares[i], 0)
		ind1[2][i] = notR63(cmp1[4].Shares[i], 1)
		ind0[3][i] = cmp0[0].Shares[i]
		ind1[3][i] = cmp1[0].Shares[i]
	}

	for k := 0; k < 6; k++ {
		for i := 0; i < n; i++ {
			ind0[k][i] = modMulBig63(ind0[k][i], ring.FracMul, ring.Modulus)
			ind1[k][i] = modMulBig63(ind1[k][i], ring.FracMul, ring.Modulus)
		}
	}

	// Step 3: Evaluate branches
	br0 := [6][]uint64{}
	br1 := [6][]uint64{}

	// I0: spline (uses pluggable tf)
	br0[0], br1[0] = evalSplineOnSharesFn(ring, params, x0, x1, tf)

	// I1: exp(-x) + Taylor (uses pluggable tf for Taylor)
	negX0 := make([]uint64, n)
	negX1 := make([]uint64, n)
	for i := range negX0 {
		negX0[i] = ring.Neg(x0[i])
		negX1[i] = ring.Neg(x1[i])
	}
	br0[1], br1[1] = evalExpTaylorOnSharesFn(ring, negX0, negX1, tf)

	// I2: constant 1
	br0[2] = make([]uint64, n)
	br1[2] = make([]uint64, n)
	oneFP := ring.FromDouble(1.0)
	for i := range br0[2] {
		br0[2][i] = oneFP
		br1[2][i] = 0
	}

	// I3: constant 0
	br0[3] = make([]uint64, n)
	br1[3] = make([]uint64, n)

	// I4: 1 - expTaylor(exp(x)) (uses pluggable tf for Taylor)
	tmp0, tmp1 := evalExpTaylorOnSharesFn(ring, x0, x1, tf)
	br0[4] = make([]uint64, n)
	br1[4] = make([]uint64, n)
	for i := 0; i < n; i++ {
		br0[4][i] = ring.Sub(oneFP, tmp0[i])
		br1[4][i] = ring.Sub(0, tmp1[i])
	}

	// I5: 1 - spline(-x) (uses pluggable tf)
	spl0, spl1 := evalSplineOnSharesFn(ring, params, negX0, negX1, tf)
	br0[5] = make([]uint64, n)
	br1[5] = make([]uint64, n)
	for i := 0; i < n; i++ {
		br0[5][i] = ring.Sub(oneFP, spl0[i])
		br1[5][i] = ring.Sub(0, spl1[i])
	}

	// Step 4: Branch selection — Hadamard indicator × branch (uses pluggable tf)
	mu0 = make([]uint64, n)
	mu1 = make([]uint64, n)
	for k := 0; k < 6; k++ {
		prod0, prod1 := hadamardBothFn(ind0[k], br0[k], ind1[k], br1[k], ring.FracBits, ring, tf)
		for i := 0; i < n; i++ {
			mu0[i] = ring.Add(mu0[i], prod0[i])
			mu1[i] = ring.Add(mu1[i], prod1[i])
		}
	}
	return
}

// ============================================================================
// Parameterized Pima training test
// ============================================================================

func pimaTrainWithTrunc(t *testing.T, label string, sigmoidTF, gradientTF truncFn) {
	t.Helper()
	ring := NewRing63(20)

	n := 155
	p := 6
	X := pimaX()
	y := pimaY()

	xFP := make([]uint64, n*p)
	yFP := make([]uint64, n)
	for i, v := range X {
		xFP[i] = ring.FromDouble(v)
	}
	for i, v := range y {
		yFP[i] = ring.FromDouble(v)
	}
	x0 := make([]uint64, n*p)
	x1 := make([]uint64, n*p)
	y0 := make([]uint64, n)
	y1 := make([]uint64, n)
	for i := range xFP {
		x0[i], x1[i] = ring.SplitShare(xFP[i])
	}
	for i := range yFP {
		y0[i], y1[i] = ring.SplitShare(yFP[i])
	}

	beta := make([]float64, p+1)
	alpha := 0.3
	lambda := 1e-4

	for iter := 1; iter <= 500; iter++ {
		betaFP := make([]uint64, p+1)
		for j := range beta {
			betaFP[j] = ring.FromDouble(beta[j])
		}

		eta0 := make([]uint64, n)
		eta1 := make([]uint64, n)
		for i := 0; i < n; i++ {
			eta0[i] = betaFP[0]
			eta1[i] = 0
			for j := 0; j < p; j++ {
				sv0 := ScalarVectorProductPartyZero(beta[j+1], []uint64{x0[i*p+j]}, ring)
				sv1 := ScalarVectorProductPartyOne(beta[j+1], []uint64{x1[i*p+j]}, ring)
				eta0[i] = ring.Add(eta0[i], sv0[0])
				eta1[i] = ring.Add(eta1[i], sv1[0])
			}
		}

		// Sigmoid with pluggable truncation
		mu0, mu1 := distributedSigmoidFn(ring, eta0, eta1, sigmoidTF)

		r0 := make([]uint64, n)
		r1 := make([]uint64, n)
		for i := range r0 {
			r0[i] = ring.Sub(mu0[i], y0[i])
			r1[i] = ring.Sub(mu1[i], y1[i])
		}
		var sR0, sR1 uint64
		for i := 0; i < n; i++ {
			sR0 = ring.Add(sR0, r0[i])
			sR1 = ring.Add(sR1, r1[i])
		}
		grad := []float64{ring.ToDouble(ring.Add(sR0, sR1))/float64(n) + lambda*beta[0]}
		for j := 0; j < p; j++ {
			xc0 := make([]uint64, n)
			xc1 := make([]uint64, n)
			for i := 0; i < n; i++ {
				xc0[i] = x0[i*p+j]
				xc1[i] = x1[i*p+j]
			}
			// Gradient Hadamard with pluggable truncation
			pr0, pr1 := hadamardBothFn(xc0, r0, xc1, r1, ring.FracBits, ring, gradientTF)
			var s0, s1 uint64
			for i := 0; i < n; i++ {
				s0 = ring.Add(s0, pr0[i])
				s1 = ring.Add(s1, pr1[i])
			}
			grad = append(grad, ring.ToDouble(ring.Add(s0, s1))/float64(n)+lambda*beta[j+1])
		}
		gn := 0.0
		for j := range grad {
			gn += grad[j] * grad[j]
		}
		gn = math.Sqrt(gn)
		sc := 1.0
		if gn > 5.0 {
			sc = 5.0 / gn
		}
		for j := range beta {
			beta[j] -= alpha * grad[j] * sc
		}

		if iter <= 3 || iter%100 == 0 {
			t.Logf("[%s] Iter %3d: beta = [%.4f, %.4f, %.4f, %.4f, %.4f, %.4f, %.4f]",
				label, iter, beta[0], beta[1], beta[2], beta[3], beta[4], beta[5], beta[6])
		}
	}

	ref := []float64{-1.270980, 0.774007, 0.468717, 0.593735, 0.943420, -0.112165, -0.066820}
	maxErr := 0.0
	for j := range beta {
		err := math.Abs(beta[j] - ref[j])
		if err > maxErr {
			maxErr = err
		}
	}
	t.Logf("[%s] Final:  [%.4f, %.4f, %.4f, %.4f, %.4f, %.4f, %.4f]",
		label, beta[0], beta[1], beta[2], beta[3], beta[4], beta[5], beta[6])
	t.Logf("[%s] Max coef error vs centralized GLM: %.2e", label, maxErr)
}

// ============================================================================
// Tests
// ============================================================================

// TestPimaIdealTruncAll: ideal truncation in BOTH sigmoid AND gradient.
// This is the accuracy CEILING — if this doesn't fix the shift, nothing will.
func TestPimaIdealTruncAll(t *testing.T) {
	pimaTrainWithTrunc(t, "IDEAL-ALL", idealTruncBoth, idealTruncBoth)
}

// TestPimaTruncPrAll: Catrina-Saxena TruncPr in both sigmoid and gradient.
// This is the practical solution — unbiased truncation.
func TestPimaTruncPrAll(t *testing.T) {
	pimaTrainWithTrunc(t, "TRUNCPR-ALL", truncPrBoth, truncPrBoth)
}

// TestPimaFloorBaseline: reproduces the current behavior for comparison.
func TestPimaFloorBaseline(t *testing.T) {
	pimaTrainWithTrunc(t, "FLOOR-BASELINE", floorTruncBoth, floorTruncBoth)
}

// TestPimaIdealSigmoidOnly: ideal truncation in sigmoid, floor in gradient.
// Shows how much of the error comes from sigmoid vs gradient truncation.
func TestPimaIdealSigmoidOnly(t *testing.T) {
	pimaTrainWithTrunc(t, "IDEAL-SIGMOID", idealTruncBoth, floorTruncBoth)
}

// pimaTrainWithFracBits: parameterized training with different fracBits.
func pimaTrainWithFracBits(t *testing.T, fracBits int) {
	t.Helper()
	ring := NewRing63(fracBits)
	t.Logf("Ring63 fracBits=%d: FracMul=%d, IntRingMod=%d", fracBits, ring.FracMul, ring.IntRingMod)

	n := 155
	p := 6
	X := pimaX()
	y := pimaY()

	xFP := make([]uint64, n*p)
	yFP := make([]uint64, n)
	for i, v := range X {
		xFP[i] = ring.FromDouble(v)
	}
	for i, v := range y {
		yFP[i] = ring.FromDouble(v)
	}
	x0 := make([]uint64, n*p)
	x1 := make([]uint64, n*p)
	y0 := make([]uint64, n)
	y1 := make([]uint64, n)
	for i := range xFP {
		x0[i], x1[i] = ring.SplitShare(xFP[i])
	}
	for i := range yFP {
		y0[i], y1[i] = ring.SplitShare(yFP[i])
	}

	beta := make([]float64, p+1)
	alpha := 0.3
	lambda := 1e-4

	for iter := 1; iter <= 500; iter++ {
		betaFP := make([]uint64, p+1)
		for j := range beta {
			betaFP[j] = ring.FromDouble(beta[j])
		}

		eta0 := make([]uint64, n)
		eta1 := make([]uint64, n)
		for i := 0; i < n; i++ {
			eta0[i] = betaFP[0]
			eta1[i] = 0
			for j := 0; j < p; j++ {
				sv0 := ScalarVectorProductPartyZero(beta[j+1], []uint64{x0[i*p+j]}, ring)
				sv1 := ScalarVectorProductPartyOne(beta[j+1], []uint64{x1[i*p+j]}, ring)
				eta0[i] = ring.Add(eta0[i], sv0[0])
				eta1[i] = ring.Add(eta1[i], sv1[0])
			}
		}

		mu0, mu1 := distributedSigmoidFn(ring, eta0, eta1, floorTruncBoth)

		r0 := make([]uint64, n)
		r1 := make([]uint64, n)
		for i := range r0 {
			r0[i] = ring.Sub(mu0[i], y0[i])
			r1[i] = ring.Sub(mu1[i], y1[i])
		}
		var sR0, sR1 uint64
		for i := 0; i < n; i++ {
			sR0 = ring.Add(sR0, r0[i])
			sR1 = ring.Add(sR1, r1[i])
		}
		grad := []float64{ring.ToDouble(ring.Add(sR0, sR1))/float64(n) + lambda*beta[0]}
		for j := 0; j < p; j++ {
			xc0 := make([]uint64, n)
			xc1 := make([]uint64, n)
			for i := 0; i < n; i++ {
				xc0[i] = x0[i*p+j]
				xc1[i] = x1[i*p+j]
			}
			bt0, bt1 := SampleBeaverTripleVector(n, ring)
			st0, msg0 := GenerateBatchedMultiplicationGateMessage(xc0, r0, bt0, ring)
			st1, msg1 := GenerateBatchedMultiplicationGateMessage(xc1, r1, bt1, ring)
			pr0 := HadamardProductPartyZero(st0, bt0, msg1, ring.FracBits, ring)
			pr1 := HadamardProductPartyOne(st1, bt1, msg0, ring.FracBits, ring)
			var s0, s1 uint64
			for i := 0; i < n; i++ {
				s0 = ring.Add(s0, pr0[i])
				s1 = ring.Add(s1, pr1[i])
			}
			grad = append(grad, ring.ToDouble(ring.Add(s0, s1))/float64(n)+lambda*beta[j+1])
		}
		gn := 0.0
		for j := range grad {
			gn += grad[j] * grad[j]
		}
		gn = math.Sqrt(gn)
		sc := 1.0
		if gn > 5.0 {
			sc = 5.0 / gn
		}
		for j := range beta {
			beta[j] -= alpha * grad[j] * sc
		}

		if iter <= 3 || iter%100 == 0 {
			t.Logf("Iter %3d: beta = [%.4f, %.4f, %.4f, %.4f, %.4f, %.4f, %.4f]",
				iter, beta[0], beta[1], beta[2], beta[3], beta[4], beta[5], beta[6])
		}
	}

	ref := []float64{-1.270980, 0.774007, 0.468717, 0.593735, 0.943420, -0.112165, -0.066820}
	maxErr := 0.0
	for j := range beta {
		err := math.Abs(beta[j] - ref[j])
		if err > maxErr {
			maxErr = err
		}
	}
	t.Logf("Final:  [%.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f]", beta[0], beta[1], beta[2], beta[3], beta[4], beta[5], beta[6])
	t.Logf("Max coef error vs centralized GLM: %.2e", maxErr)
}

func TestPimaFracBits30(t *testing.T) { pimaTrainWithFracBits(t, 30) }
func TestPimaFracBits25(t *testing.T) { pimaTrainWithFracBits(t, 25) }

// ============================================================================
// Pima data (extracted from TestPimaDistributed)
// ============================================================================

func pimaX() []float64 {
	return []float64{2.06811083, -1.09608107, -0.93780434, 2.24652441, -0.03198927, 0.38129431, 0.28028496, 0.59983315, -0.95986004, -1.45085087, 1.03051140, 1.06751339, -0.52423668, 2.51764269, -0.63532616, 1.30651374, 0.49926107, 1.23906816, -0.79241056, -0.89003542, -1.03232877, -0.51084020, -0.91740649, -0.30492477, 1.79993695, 0.56813382, -0.26037924, -0.82417709, 0.49926107, -0.13337000, -0.61362798, 0.36208817, -0.39271345, -1.26284873, -1.09448993, 0.20973954, -0.70301927, -0.96928374, 0.61239636, 2.18385703, -1.80282371, -1.07692123, 2.78324118, 0.06094452, -0.82122421, 0.58583890, 0.85342795, -1.16269862, -0.07728022, 1.78855807, 2.40520977, 0.14716726, 0.67634451, 0.72440385, 0.10150237, 1.75685874, 5.75767633, 0.42917046, -2.68824093, 0.55284908, 1.17419790, -0.17680046, -0.93465353, 0.96184317, 0.67634451, 0.12396216, 2.42567601, -0.30359779, -0.19736295, 2.05852228, -0.91740649, -0.47647954, 1.08480660, -0.69983943, 1.46626707, -0.98084553, -0.74032305, -1.84891769, -0.97119315, -1.39722472, -0.74875548, -0.76150971, 0.49926107, -1.16269862, -0.97119315, -1.04853207, 1.53243417, -0.44817283, -0.91740649, -1.76314031, 1.71054566, 0.72663048, -0.65108023, 0.61717259, 2.09301207, 0.38129431, -0.97119315, -1.57157104, -0.79916851, 0.49183784, -0.74032305, -0.99114385, -0.43484539, -1.84101535, -0.71094570, -0.76150971, -0.03198927, -1.07692123, 0.90602401, -0.00245414, -0.05242549, -0.73017602, -0.38615616, 0.03818477, 0.19089367, -0.43039511, -0.45257892, -1.26284873, 1.38467829, -0.81958908, -0.97119315, -1.74591736, -0.65738186, -0.69884234, -0.56323960, -0.99114385, -0.70301927, 0.88512713, -0.18791051, -1.13751398, -0.20907271, 0.46707170, 0.01211108, -0.19265013, 1.16693970, 1.27518006, 1.20759484, -0.64803431, -0.97119315, -1.04853207, 0.28471166, -0.76150971, -1.09448993, -1.59158554, 0.10150237, 0.64738215, -0.62272290, -0.47950651, 0.14509418, 1.23906816, -0.43484539, 0.06094452, 0.74788138, -0.41683914, 0.32217762, 0.03818477, -0.79241056, 1.82025740, 0.68486509, -1.38818349, -0.91740649, 1.15329077, -0.88180186, 0.07679419, -0.64477860, 0.77384104, -0.38615616, -0.30492477, 0.10150237, 0.36208817, -0.81177176, -0.07216856, -0.38615616, 0.12396216, -0.25606280, 0.26699017, 0.78884197, -0.57350758, 0.85342795, 1.41062293, 2.24689342, -1.55572137, -0.67943756, 0.67983997, 1.03051140, -0.81958908, -0.88180186, -1.04853207, 0.38553772, -1.38818349, 0.85342795, -0.30492477, -0.88180186, -1.84101535, -0.43367403, -1.63885300, -1.97990716, -0.90536646, -0.43484539, -0.43039511, 0.73842894, -0.66750865, 1.38467829, -0.99114385, -0.88180186, 1.07532312, -0.63532616, -0.13483594, -0.38615616, -0.13337000, 2.33628471, 0.26699017, 0.02004325, 1.65118432, 1.73884518, 0.46707170, -0.88180186, -0.76323809, 1.99875471, -0.82417709, -0.20907271, -0.64803431, -0.07728022, -0.71568909, 0.20909211, 0.17850095, -0.91740649, -1.42003077, -0.97119315, -2.18970800, -0.50929358, -0.82417709, -0.56323960, -0.81958908, -0.61362798, 0.59983315, -0.70149326, -1.16884767, -0.20907271, 0.29551693, -0.07728022, 0.28283984, -1.17411542, 0.05316619, -0.91740649, -0.73381169, -0.34545410, -1.23872806, 3.89869581, -0.98084553, 0.49926107, -0.73381169, -0.70301927, 0.20359151, -0.82437502, 1.49451588, 0.14509418, 0.38129431, -0.88180186, 1.72515941, 2.94084822, 2.37185916, 0.49926107, 1.23906816, -0.70301927, -0.90588508, -1.11424995, -0.22883700, 0.32217762, -1.16269862, -0.88180186, 0.02924519, 0.11456768, -1.26284873, -0.38615616, -0.47647954, 1.17419790, 0.06094452, -0.05557630, 0.96184317, 0.67634451, 0.29551693, -0.97119315, 0.96437546, -0.54080172, -0.29150438, -0.38615616, 0.63862646, -0.88180186, 0.34623850, -1.00397144, -0.54217389, -0.03198927, -0.04759261, -0.16667151, -0.66814010, -1.13630565, 0.02183251, 0.32217762, 0.63862646, -0.52423668, 1.59836209, 0.18703641, -0.00950118, -1.97990716, 0.29551693, -0.97119315, 0.18774185, -0.54080172, -0.85551078, -0.56323960, -0.13337000, 0.63785013, 0.61568282, -0.56915905, 0.17850095, 0.49926107, -0.04759261, 1.26358919, -0.00245414, -1.18356787, -0.98084553, -0.74032305, 0.29551693, -0.61362798, -0.06585280, -0.31394308, 0.49183784, 0.85342795, 0.55284908, -0.25606280, 0.53643449, 0.25635433, 0.33516939, -0.03198927, -0.47647954, -0.25606280, 1.17042111, -0.20681539, 1.08717792, 1.20759484, 1.06751339, -0.61362798, -0.06585280, -0.83067665, -0.35417176, 0.32217762, 0.12396216, -0.79241056, 1.12287212, 1.34023449, -0.07216856, -0.03198927, 0.29551693, 1.79993695, 0.47303583, 1.40009997, 1.40051481, 1.56176173, 0.03818477, 1.26358919, 2.23234871, -0.39586426, 0.64850628, 1.03051140, 1.49640031, -0.79241056, -1.23872806, 0.48321297, -0.69884234, -1.09448993, -0.99114385, -0.52423668, -1.73006769, 0.58718984, -0.85551078, -0.20907271, -1.33425339, -0.79241056, -1.44477371, 0.68486509, -0.51084020, -0.74032305, -1.33425339, 2.69384989, -0.87418575, -0.63532616, -0.07216856, 0.67634451, -0.99114385, -0.97119315, -0.36699645, -0.29188738, -0.73017602, -0.56323960, -0.47647954, 0.45906755, -0.11340180, -0.38641182, 0.96184317, 0.14509418, 0.03818477, 1.53176307, -0.69983943, 0.32882306, 0.05316619, 0.67634451, 0.20973954, -0.52423668, 0.61568282, 0.07045628, -0.04083487, 0.49926107, -0.13337000, -0.61362798, -0.52549311, -1.16151217, -0.29150438, -0.20907271, -0.56225692, 0.01211108, 0.40963716, 0.21539374, -0.26017069, -0.03198927, 0.12396216, -0.97119315, -0.19265013, -0.12489422, -0.26017069, -0.56323960, -0.56225692, -0.97119315, -0.54134277, 0.72897649, 0.20983464, -0.91740649, -0.47647954, -0.88180186, -0.00245414, -0.20366458, -1.38818349, 0.41071934, 0.12396216, 0.54845884, 1.17042111, -0.70779489, -0.35417176, 0.67634451, 0.98173600, 1.97871954, 0.50473516, 0.72897649, 0.83650841, 0.67634451, 0.03818477, -0.79241056, -1.08023140, -0.71409652, -1.01217922, -1.44865682, -0.30492477, -0.43484539, -0.57304210, -1.07959099, -0.41683914, 0.49926107, -0.73381169, -0.79241056, -0.06585280, 0.59349147, -0.91817816, 0.49926107, -0.90536646, -0.97119315, -0.25604879, 1.59860128, -1.23151504, -1.80282371, -0.47647954, 1.26358919, 0.37793783, -0.68573919, -1.95218989, 1.03051140, -0.04759261, -0.16667151, -0.36699645, -0.25407761, -0.19750332, -0.74032305, -1.42003077, -0.79241056, 0.12434318, -0.70464407, 0.96184317, -0.74032305, 0.20973954, -0.70301927, 0.34623850, -0.63217534, -0.38550545, -0.56323960, 0.89595862, -0.97119315, -0.92173475, -0.64477860, 0.61717259, 0.32217762, -0.56225692, 0.01211108, 2.26404804, 2.00190552, -1.32551611, 0.32217762, 1.06751339, 0.45906755, -0.55719244, 0.69116672, 2.05852228, 3.50967962, 0.20973954, 0.45906755, -1.57157104, 0.00743999, -0.22883700, 0.14509418, -1.42003077, 1.79993695, -0.52549311, 0.71322242, 0.02183251, 0.49926107, -0.39070215, 2.42567601, -0.74738843, -0.72354896, 0.42917046, 1.20759484, -0.13337000, 0.36967625, 0.34623850, -0.63217534, -0.35417176, 1.03051140, 0.29551693, -0.88180186, -1.50817238, -0.13749748, -0.94951185, -1.27157338, -1.50580815, -0.70301927, -0.19265013, 1.13543155, -0.51084020, 0.14509418, 0.12396216, 0.54845884, 1.55081309, 0.88651721, 0.86784210, -0.03198927, 0.98173600, -0.16667151, 0.96437546, -0.76450955, -0.82417709, -0.03198927, 0.98173600, 2.33628471, -0.00245414, -0.02721897, 0.64850628, 1.03051140, -0.21914738, -0.34545410, 1.01192446, -0.67628674, -0.35417176, 1.38467829, 1.15329077, -0.97119315, -1.17532940, 0.55568170, -0.76150971, -1.62574027, -1.16269862, -0.79241056, -1.08023140, 1.17324133, -0.44817283, -1.27157338, -0.64803431, 0.81663272, 1.09117279, 2.20985928, -0.10350225, 0.85342795, 1.66795508, 0.81663272, 0.90097680, -0.65108023, 1.99585490, -0.20907271, 0.89595862, 0.01211108, 0.69493115, 1.59860128, 0.17850095, 1.91592862, 1.75373247, 2.51506730, 0.34623850, -0.93465353, 1.74518539, 2.18155379, 0.20973954, 0.81663272, -0.92173475, -0.46518218, -1.35684980, -0.38615616, 0.12396216, -0.61362798, 0.45718616, -0.74245385, -0.57350758, -1.09448993, 0.98173600, 0.19089367, -0.17680046, -0.50929358, 2.12118965, -0.20907271, -1.16269862, -0.34545410, -1.01683274, -0.52504765, -0.76150971, 0.14509418, -0.99114385, -0.97119315, -1.14363007, -1.00082063, 0.42917046, -0.20907271, -1.24847600, -0.97119315, -2.18970800, -0.98821737, -0.82417709, -0.03198927, -1.16269862, -0.07728022, 2.34329637, 1.57969639, -0.73017602, 1.56176173, 2.69728370, 0.10150237, -1.36552538, -0.04297304, 1.36918112, 0.32217762, -0.99114385, 0.28028496, 0.71078081, -0.46203136, 1.77651908, 1.73884518, -0.21914738, -0.43484539, 0.75832981, -0.38011019, -0.04083487, -0.03198927, -0.13337000, -0.70301927, -0.76323809, 0.37608528, -1.04351291, -0.74032305, -1.42003077, -0.16667151, 1.72515941, -0.02721897, -0.10350225, -0.03198927, 0.12396216, -0.43484539, 2.23234871, 0.34772795, 0.96184317, 0.67634451, 1.06751339, -0.88180186, -1.23872806, -0.40531670, -2.10885833, -1.27157338, -0.04759261, -0.52423668, 0.18774185, -0.49038869, 0.02183251, 0.85342795, 0.38129431, 0.90602401, -1.20702873, -1.02287633, -1.20018136, -1.36011510, -0.73381169, -0.34545410, 1.47156476, 0.13032175, 2.34052547, -0.38615616, 0.29551693, -0.88180186, -0.00245414, 0.69746835, 2.02718859, 1.03051140, -1.24847600, -0.52423668, -0.54134277, -0.15640236, 0.49183784, -0.56323960, 0.55284908, 2.69384989, 0.42548683, 0.36033120, 2.30919179, -0.03198927, 6.04260171, 0.63785013, -0.96928374, -0.94095516, 0.08449988, 0.32217762, 0.81018123, -0.70301927, 0.91682646, 0.11771849, -0.73017602, -1.44865682, -0.04759261, 1.62115436, 0.12434318, -0.37695937, 1.27518006, 1.03051140, 1.23906816, -0.34545410, 0.53643449, -0.55655580, -0.88684447, -0.91740649, 0.29551693, -0.34545410, 0.66323181, 1.11967748, -0.04083487, -1.62574027, 1.23906816, -0.34545410, -0.66814010, -0.48723788, -1.20018136, -1.09448993, -0.56225692, -0.70301927, -0.87418575, -0.93150271, -0.51084020, -0.20907271, -0.81958908, 0.72724143, 0.26699017, -0.67943756, -0.26017069, -0.91740649, 0.89595862, -0.34545410, 0.77417947, -0.95040760, -0.57350758, 0.14509418, 0.03818477, 0.81663272, 0.61568282, 0.89596966, 2.21519072, -0.20907271, -0.04759261, -0.07728022, 0.79002914, -0.61957208, 1.90185383, 0.67634451, 0.89595862, 0.45906755, -1.03268241, -0.94410597, 0.02183251, -0.03198927, 0.38129431, -0.79241056, -1.27042739, -1.01657470, -0.38550545, -0.74032305, -1.33425339, 0.63785013, -0.00245414, -0.21941865, 0.42917046, 1.73884518, 1.06751339, -0.16667151, 1.17042111, -1.02917796, 1.05584423, 0.32217762, 0.55284908, -0.88180186, -0.93758441, 0.90542210, -0.88684447, -1.44865682, -1.24847600, 0.81663272, 0.85342780, -0.68258837, 0.52317153, 1.29613657, 0.38129431, -0.88180186, -0.19265013, 0.10196442, -0.19750332, -0.38615616, 0.20973954, 0.72724143, 0.17189218, -0.27298250, -0.00950118, -0.03198927, 1.32484554, -0.97119315, 0.40963716, 0.23114781, 0.46050415, -0.91740649, 0.55284908, 1.26358919, 0.72663048, -0.15325155, -0.73017602, 0.67634451, -0.30492477, -0.88180186, -0.66814010, -0.60381801, -1.54485193, -1.62574027, -1.59158554, 1.17419790, 0.12434318, -0.71409652, 0.30383570, 2.80134584, -0.04759261, -0.79241056, 0.45718616, 0.83295337, -0.13483594, -0.56323960, -0.90536646, 0.19089367, 1.05947345, 0.49896704, 0.99317686, 1.20759484, 1.32484554, -0.70301927, 1.34476744, 0.48006215, 0.14716726, -1.97990716, 1.41062293, -0.79241056, -1.25457773, 1.15748726, 0.52317153, 0.32217762, -0.21914738, -0.70301927, -1.04853207, 0.75103219, 0.55450521, -1.09448993, 0.46707170, 0.99541531, 1.02777412, -0.06817956, 0.17850095, -0.20907271, 1.75373247, -0.88180186, 1.17042111, 0.45485564, -0.54217389, -0.03198927, 0.72440385, -0.79241056, 0.20359151, -0.62902453, -0.16616963, -1.09448993, 0.63862646, 1.26358919, 0.31453917, 0.25950514, 0.99317686, -0.74032305, -0.21914738}
}

func pimaY() []float64 {
	return []float64{1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1}
}
