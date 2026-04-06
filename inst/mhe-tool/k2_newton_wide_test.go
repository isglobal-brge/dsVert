package main

import (
	"math"
	"testing"
)

// ============================================================================
// Wide spline exp: piecewise linear approximation of exp(x)
// for Poisson regression link function.
// ============================================================================

// computeWideExpSpline computes piecewise linear approximation of exp(x)
// over [-halfRange, halfRange) with numIntervals equal-width intervals.
func computeWideExpSpline(numIntervals int, halfRange float64) (slopes, intercepts []float64) {
	width := 2.0 * halfRange / float64(numIntervals)
	slopes = make([]float64, numIntervals)
	intercepts = make([]float64, numIntervals)
	for j := 0; j < numIntervals; j++ {
		left := -halfRange + float64(j)*width
		right := left + width
		eLeft := math.Exp(left)
		eRight := math.Exp(right)
		slopes[j] = (eRight - eLeft) / width
		intercepts[j] = eLeft - slopes[j]*left
	}
	return
}

// wideSplineExpFn evaluates exp(x) using a wide piecewise-linear spline.
// Analogous to wideSplineSigmoidFn but with exp(x) instead of sigmoid(x).
// Range [-halfRange, halfRange): below clamp to exp(-halfRange), above clamp to exp(halfRange).
func wideSplineExpFn(ring Ring63, x0, x1 []uint64, tf truncFn,
	numIntervals int, halfRange float64) (mu0, mu1 []uint64) {

	n := len(x0)
	slopes, intercepts := computeWideExpSpline(numIntervals, halfRange)
	width := 2.0 * halfRange / float64(numIntervals)

	// Saturation values for exp
	expLow := math.Exp(-halfRange)  // clamp below
	expHigh := math.Exp(halfRange)  // clamp above

	// === Broad thresholds ===
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

	// Scale indicators to FP and assign saturation values
	// I_sat_low = c_low (x < -L) -> exp(-L)
	// I_sat_high = NOT(c_high) = (x >= L) -> exp(L)
	iLow0 := make([]uint64, n)
	iLow1 := make([]uint64, n)
	iHigh0 := make([]uint64, n)
	iHigh1 := make([]uint64, n)
	iMid0 := make([]uint64, n)
	iMid1 := make([]uint64, n)
	expLowFP := ring.FromDouble(expLow)
	expHighFP := ring.FromDouble(expHigh)
	for i := 0; i < n; i++ {
		// I_sat_low * exp(-L): scale indicator to FP then multiply by constant
		iLow0[i] = modMulBig63(cmpLow0.Shares[i], expLowFP, ring.Modulus)
		iLow1[i] = modMulBig63(cmpLow1.Shares[i], expLowFP, ring.Modulus)
		// I_sat_high * exp(L)
		notHigh0 := ring.Sub(1, cmpHigh0.Shares[i])
		notHigh1 := ring.Sub(0, cmpHigh1.Shares[i])
		iHigh0[i] = modMulBig63(notHigh0, expHighFP, ring.Modulus)
		iHigh1[i] = modMulBig63(notHigh1, expHighFP, ring.Modulus)
		// I_mid (scale to FP)
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

	// Sub-indicators (same logic as sigmoid spline)
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

	// === Individual ScalarVP per interval ===
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
	atx0, atx1 := hadamardBothFn(aSlope0, x0, aSlope1, x1, ring.FracBits, ring, tf)

	// Spline value: a_t * x + b_t
	spline0 := make([]uint64, n)
	spline1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		spline0[i] = ring.Add(atx0[i], bInt0[i])
		spline1[i] = ring.Add(atx1[i], bInt1[i])
	}

	// === Branch selection ===
	// mu = I_sat_low * exp(-L) + I_sat_high * exp(L) + I_mid * spline_value
	midSpline0, midSpline1 := hadamardBothFn(iMid0, spline0, iMid1, spline1, ring.FracBits, ring, tf)

	mu0 = make([]uint64, n)
	mu1 = make([]uint64, n)
	for i := 0; i < n; i++ {
		mu0[i] = ring.Add(ring.Add(iLow0[i], iHigh0[i]), midSpline0[i])
		mu1[i] = ring.Add(ring.Add(iLow1[i], iHigh1[i]), midSpline1[i])
	}
	return
}

// ============================================================================
// TestPimaNewtonWideSpline: Newton-IRLS with diagonal Fisher preconditioning
// for binomial logistic regression on Pima data.
// ============================================================================

func TestPimaNewtonWideSpline(t *testing.T) {
	ring := NewRing63(20)
	n := 155
	p := 6
	X := pimaX()
	y := pimaY()

	// Share data
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

	tf := floorTruncBoth
	numIntervals := 50
	halfRange := 5.0

	beta := make([]float64, p+1)
	maxIter := 15
	lambda := 1e-4
	nf := float64(n)
	dampingFactor := 0.5 // Damped Newton step to prevent oscillation

	ref := []float64{-1.270980, 0.774007, 0.468717, 0.593735, 0.943420, -0.112165, -0.066820}

	for iter := 1; iter <= maxIter; iter++ {
		betaFP := make([]uint64, p+1)
		for j := range beta {
			betaFP[j] = ring.FromDouble(beta[j])
		}

		// 1. Compute eta = intercept + sum(beta_j * x_j) on shares
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

		// 2. Compute mu via wide spline sigmoid (50 intervals)
		mu0, mu1 := wideSplineSigmoidFn(ring, eta0, eta1, tf, numIntervals, halfRange)

		// 3. Compute residual r = mu - y on shares
		r0 := make([]uint64, n)
		r1 := make([]uint64, n)
		for i := range r0 {
			r0[i] = ring.Sub(mu0[i], y0[i])
			r1[i] = ring.Sub(mu1[i], y1[i])
		}

		// 4. Compute gradient (same as GD)
		var sR0, sR1 uint64
		for i := 0; i < n; i++ {
			sR0 = ring.Add(sR0, r0[i])
			sR1 = ring.Add(sR1, r1[i])
		}
		grad := make([]float64, p+1)
		grad[0] = ring.ToDouble(ring.Add(sR0, sR1))/nf + lambda*beta[0]

		for j := 0; j < p; j++ {
			xc0 := make([]uint64, n)
			xc1 := make([]uint64, n)
			for i := 0; i < n; i++ {
				xc0[i] = x0[i*p+j]
				xc1[i] = x1[i*p+j]
			}
			pr0, pr1 := hadamardBothFn(xc0, r0, xc1, r1, ring.FracBits, ring, tf)
			var s0, s1 uint64
			for i := 0; i < n; i++ {
				s0 = ring.Add(s0, pr0[i])
				s1 = ring.Add(s1, pr1[i])
			}
			grad[j+1] = ring.ToDouble(ring.Add(s0, s1))/nf + lambda*beta[j+1]
		}

		// 5. Compute diagonal Fisher (NEWTON part)
		// one_minus_mu = 1 - mu (on shares)
		oneFP := ring.FromDouble(1.0)
		ommu0 := make([]uint64, n)
		ommu1 := make([]uint64, n)
		for i := 0; i < n; i++ {
			// (1 - mu): party 0 gets 1-mu0, party 1 gets 0-mu1 = -mu1
			ommu0[i] = ring.Sub(oneFP, mu0[i])
			ommu1[i] = ring.Sub(0, mu1[i])
		}

		// w = mu * (1 - mu) via Hadamard
		w0, w1 := hadamardBothFn(mu0, ommu0, mu1, ommu1, ring.FracBits, ring, tf)

		// Diagonal Fisher: d_j for each coefficient
		diag := make([]float64, p+1)

		// Intercept: d_0 = sum(w_i) / n + lambda
		{
			var sw0, sw1 uint64
			for i := 0; i < n; i++ {
				sw0 = ring.Add(sw0, w0[i])
				sw1 = ring.Add(sw1, w1[i])
			}
			diag[0] = ring.ToDouble(ring.Add(sw0, sw1))/nf + lambda
		}

		// Features: d_j = sum(w_i * x_ij^2) / n + lambda
		for j := 0; j < p; j++ {
			xc0 := make([]uint64, n)
			xc1 := make([]uint64, n)
			for i := 0; i < n; i++ {
				xc0[i] = x0[i*p+j]
				xc1[i] = x1[i*p+j]
			}
			// x^2 via Hadamard (features are secret-shared)
			x2_0, x2_1 := hadamardBothFn(xc0, xc0, xc1, xc1, ring.FracBits, ring, tf)
			// w * x^2 via Hadamard
			wx2_0, wx2_1 := hadamardBothFn(w0, x2_0, w1, x2_1, ring.FracBits, ring, tf)
			// Reconstruct sum (disclosed aggregate)
			var s0, s1 uint64
			for i := 0; i < n; i++ {
				s0 = ring.Add(s0, wx2_0[i])
				s1 = ring.Add(s1, wx2_1[i])
			}
			diag[j+1] = ring.ToDouble(ring.Add(s0, s1))/nf + lambda
		}

		// 6. Damped Newton update: beta[j] -= damping * grad[j] / d_j
		// The damping factor prevents oscillation from MPC noise in the Fisher.
		for j := range beta {
			if diag[j] > 1e-8 {
				beta[j] -= dampingFactor * grad[j] / diag[j]
			} else {
				// Fallback to plain GD step if Fisher is degenerate
				beta[j] -= 0.3 * grad[j]
			}
		}

		// Log progress
		gn := 0.0
		for j := range grad {
			gn += grad[j] * grad[j]
		}
		gn = math.Sqrt(gn)
		t.Logf("Iter %2d: ||grad||=%.6f  beta=[%.4f, %.4f, %.4f, %.4f, %.4f, %.4f, %.4f]",
			iter, gn, beta[0], beta[1], beta[2], beta[3], beta[4], beta[5], beta[6])
	}

	// Compare with GLM reference
	maxErr := 0.0
	for j := range beta {
		err := math.Abs(beta[j] - ref[j])
		if err > maxErr {
			maxErr = err
		}
	}
	t.Logf("Final:  [%.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f]", beta[0], beta[1], beta[2], beta[3], beta[4], beta[5], beta[6])
	t.Logf("Ref  :  [%.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f]", ref[0], ref[1], ref[2], ref[3], ref[4], ref[5], ref[6])
	t.Logf("Max coef error vs centralized GLM: %.2e", maxErr)

	if maxErr > 0.15 {
		t.Errorf("Newton-IRLS max coefficient error %.4f exceeds tolerance 0.15", maxErr)
	}
}

// ============================================================================
// TestPoissonWideSpline: Poisson regression with wide spline exp,
// using gradient descent (500 iterations).
// ============================================================================

func TestPoissonWideSpline(t *testing.T) {
	ring := NewRing63(20)
	n := 155
	p := 6
	X := pimaX() // reuse Pima features (standardized)
	tf := floorTruncBoth

	numIntervals := 100
	halfRange := 5.0 // exp range [-5, 5) — 100 intervals for 0.15% relative error

	// Generate synthetic Poisson-like data: y = round(exp(X*beta_true) + noise)
	betaTrue := []float64{0.5, 0.3, -0.2, 0.4, -0.1, 0.2, -0.15}
	yFloat := make([]float64, n)
	for i := 0; i < n; i++ {
		eta := betaTrue[0]
		for j := 0; j < p; j++ {
			eta += betaTrue[j+1] * X[i*p+j]
		}
		// Clamp eta to avoid huge counts
		if eta > 4.0 {
			eta = 4.0
		}
		if eta < -4.0 {
			eta = -4.0
		}
		yFloat[i] = math.Round(math.Exp(eta))
		if yFloat[i] < 0 {
			yFloat[i] = 0
		}
	}

	// Share data
	xFP := make([]uint64, n*p)
	yFP := make([]uint64, n)
	for i, v := range X {
		xFP[i] = ring.FromDouble(v)
	}
	for i, v := range yFloat {
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
	alpha := 0.05
	lambda := 1e-3
	nf := float64(n)
	maxIter := 500

	for iter := 1; iter <= maxIter; iter++ {
		betaFP := make([]uint64, p+1)
		for j := range beta {
			betaFP[j] = ring.FromDouble(beta[j])
		}

		// 1. Compute eta = intercept + sum(beta_j * x_j) on shares
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

		// 2. Compute mu = exp(eta) via wide spline exp
		mu0, mu1 := wideSplineExpFn(ring, eta0, eta1, tf, numIntervals, halfRange)

		// 3. Compute residual r = mu - y on shares
		r0 := make([]uint64, n)
		r1 := make([]uint64, n)
		for i := range r0 {
			r0[i] = ring.Sub(mu0[i], y0[i])
			r1[i] = ring.Sub(mu1[i], y1[i])
		}

		// 4. Compute gradient: same formula as binomial
		var sR0, sR1 uint64
		for i := 0; i < n; i++ {
			sR0 = ring.Add(sR0, r0[i])
			sR1 = ring.Add(sR1, r1[i])
		}
		grad := make([]float64, p+1)
		grad[0] = ring.ToDouble(ring.Add(sR0, sR1))/nf + lambda*beta[0]

		for j := 0; j < p; j++ {
			xc0 := make([]uint64, n)
			xc1 := make([]uint64, n)
			for i := 0; i < n; i++ {
				xc0[i] = x0[i*p+j]
				xc1[i] = x1[i*p+j]
			}
			pr0, pr1 := hadamardBothFn(xc0, r0, xc1, r1, ring.FracBits, ring, tf)
			var s0, s1 uint64
			for i := 0; i < n; i++ {
				s0 = ring.Add(s0, pr0[i])
				s1 = ring.Add(s1, pr1[i])
			}
			grad[j+1] = ring.ToDouble(ring.Add(s0, s1))/nf + lambda*beta[j+1]
		}

		// Gradient clipping
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

		if iter <= 5 || iter%100 == 0 {
			t.Logf("Iter %3d: ||grad||=%.6f  beta=[%.4f, %.4f, %.4f, %.4f, %.4f, %.4f, %.4f]",
				iter, gn, beta[0], beta[1], beta[2], beta[3], beta[4], beta[5], beta[6])
		}
	}

	// Verify convergence: compare with true betas
	maxErr := 0.0
	for j := range beta {
		err := math.Abs(beta[j] - betaTrue[j])
		if err > maxErr {
			maxErr = err
		}
	}
	t.Logf("Final:  [%.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f]", beta[0], beta[1], beta[2], beta[3], beta[4], beta[5], beta[6])
	t.Logf("True :  [%.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f]",
		betaTrue[0], betaTrue[1], betaTrue[2], betaTrue[3], betaTrue[4], betaTrue[5], betaTrue[6])
	t.Logf("Max coef error vs true betas: %.2e", maxErr)

	// Poisson with rounded counts won't perfectly recover true betas,
	// but should be reasonably close (within 0.5).
	if maxErr > 0.5 {
		t.Errorf("Poisson GD max coefficient error %.4f exceeds tolerance 0.5", maxErr)
	}
}

// TestPoissonCentralizedVsMPC: compare MPC Poisson with centralized (float64) Poisson
// to isolate MPC numerical error from statistical error.
func TestPoissonCentralizedVsMPC(t *testing.T) {
	n := 155; p := 6
	X := pimaX()
	betaTrue := []float64{0.5, 0.3, -0.2, 0.4, -0.1, 0.2, -0.15}
	yFloat := make([]float64, n)
	for i := 0; i < n; i++ {
		eta := betaTrue[0]
		for j := 0; j < p; j++ { eta += betaTrue[j+1] * X[i*p+j] }
		if eta > 4.0 { eta = 4.0 }
		if eta < -4.0 { eta = -4.0 }
		yFloat[i] = math.Round(math.Exp(eta))
		if yFloat[i] < 0 { yFloat[i] = 0 }
	}

	// Centralized Poisson GLM (float64, no MPC)
	beta := make([]float64, p+1)
	alpha := 0.05; lambda := 1e-3
	for iter := 1; iter <= 500; iter++ {
		grad := make([]float64, p+1)
		for i := 0; i < n; i++ {
			eta := beta[0]
			for j := 0; j < p; j++ { eta += beta[j+1] * X[i*p+j] }
			if eta > 8 { eta = 8 }; if eta < -3 { eta = -3 }
			mu := math.Exp(eta)
			r := mu - yFloat[i]
			grad[0] += r
			for j := 0; j < p; j++ { grad[j+1] += X[i*p+j] * r }
		}
		gn := 0.0
		for j := range grad { grad[j] = grad[j]/float64(n) + lambda*beta[j]; gn += grad[j]*grad[j] }
		gn = math.Sqrt(gn); sc := 1.0; if gn > 5.0 { sc = 5.0/gn }
		for j := range beta { beta[j] -= alpha * grad[j] * sc }
	}
	t.Logf("Centralized: [%.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f]",
		beta[0], beta[1], beta[2], beta[3], beta[4], beta[5], beta[6])
	t.Logf("True betas:  [%.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f]",
		betaTrue[0], betaTrue[1], betaTrue[2], betaTrue[3], betaTrue[4], betaTrue[5], betaTrue[6])
	maxErr := 0.0
	for j := range beta {
		if e := math.Abs(beta[j]-betaTrue[j]); e > maxErr { maxErr = e }
	}
	t.Logf("Centralized vs true: %.2e (this is STATISTICAL error, not MPC)", maxErr)

	// MPC result (from TestPoissonWideSpline: 0.5029, 0.3054, -0.1606, 0.3890, -0.0992, 0.1977, -0.1702)
	mpcBeta := []float64{0.5029, 0.3054, -0.1606, 0.3890, -0.0992, 0.1977, -0.1702}
	mpcErr := 0.0
	for j := range beta {
		if e := math.Abs(beta[j]-mpcBeta[j]); e > mpcErr { mpcErr = e }
	}
	t.Logf("MPC vs centralized: %.2e (THIS is the MPC numerical error)", mpcErr)
}
