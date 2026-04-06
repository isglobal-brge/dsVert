package main

import (
	"math"
	"testing"
)

// computeWideSigmoidSpline computes piecewise linear approximation of sigmoid
// over [-halfRange, halfRange) with numIntervals equal-width intervals.
func computeWideSigmoidSpline(numIntervals int, halfRange float64) (slopes, intercepts []float64) {
	sigma := func(x float64) float64 { return 1.0 / (1.0 + math.Exp(-x)) }
	width := 2.0 * halfRange / float64(numIntervals)
	slopes = make([]float64, numIntervals)
	intercepts = make([]float64, numIntervals)
	for j := 0; j < numIntervals; j++ {
		left := -halfRange + float64(j)*width
		right := left + width
		sLeft := sigma(left)
		sRight := sigma(right)
		slopes[j] = (sRight - sLeft) / width
		intercepts[j] = sLeft - slopes[j]*left
	}
	return
}

// wideSplineSigmoidFn evaluates sigmoid using ONLY a wide piecewise-linear spline.
// No Kelkar exp, no Taylor polynomial. This allows arbitrary fracBits.
//
// Structure:
//   - 2 broad DCF comparisons (x >= -L, x >= L)
//   - (N-1) sub-interval DCF comparisons within [-L, L)
//   - N ScalarVP for slope/intercept selection
//   - 1 deferred truncation, 1 Hadamard (a_t * x)
//   - Branch selection: I_high + I_mid * spline_value
func wideSplineSigmoidFn(ring Ring63, x0, x1 []uint64, tf truncFn,
	numIntervals int, halfRange float64) (mu0, mu1 []uint64) {

	n := len(x0)
	slopes, intercepts := computeWideSigmoidSpline(numIntervals, halfRange)
	width := 2.0 * halfRange / float64(numIntervals)

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

	// DCF gives 1{x < threshold}:
	// c_low = 1{x < -L} = (x is below -L)
	// c_high = 1{x < L} = (x is below L)
	//
	// I_sat_high = NOT(c_high) = (x >= L) → sigma ≈ 1
	// I_sat_low = c_low = (x < -L) → sigma ≈ 0
	// I_mid = NOT(c_low) * c_high = (x >= -L) * (x < L) = (x ∈ [-L, L))

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
	// Scale indicators to FP
	iHigh0 := make([]uint64, n)
	iHigh1 := make([]uint64, n)
	iMid0 := make([]uint64, n)
	iMid1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		// NOT(c_high) = (x >= L)
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

	// Scale sub-indicators to FP
	for k := 0; k < numIntervals; k++ {
		for i := 0; i < n; i++ {
			subInd0[k][i] = modMulBig63(subInd0[k][i], ring.FracMul, ring.Modulus)
			subInd1[k][i] = modMulBig63(subInd1[k][i], ring.FracMul, ring.Modulus)
		}
	}

	// === Individual ScalarVP per interval (NOT deferred) ===
	// Deferred truncation would overflow Ring63 at high fracBits because
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

	// Hadamard: a_t × x
	atx0, atx1 := hadamardBothFn(aSlope0, x0, aSlope1, x1, ring.FracBits, ring, tf)

	// Spline value: a_t * x + b_t
	spline0 := make([]uint64, n)
	spline1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		spline0[i] = ring.Add(atx0[i], bInt0[i])
		spline1[i] = ring.Add(atx1[i], bInt1[i])
	}

	// === Branch selection ===
	// mu = I_high * 1.0 + I_mid * spline_value
	// I_high * 1.0: just I_high (already in FP, represents 1.0 when active)
	// I_mid * spline_value: Hadamard product
	midSpline0, midSpline1 := hadamardBothFn(iMid0, spline0, iMid1, spline1, ring.FracBits, ring, tf)

	mu0 = make([]uint64, n)
	mu1 = make([]uint64, n)
	for i := 0; i < n; i++ {
		mu0[i] = ring.Add(iHigh0[i], midSpline0[i])
		mu1[i] = ring.Add(iHigh1[i], midSpline1[i])
	}
	return
}

// pimaTrainWideSpline runs the full training with wide spline sigmoid.
func pimaTrainWideSpline(t *testing.T, fracBits, numIntervals int, halfRange float64, tf truncFn) {
	t.Helper()
	ring := NewRing63(fracBits)
	t.Logf("Wide spline: fracBits=%d, intervals=%d, range=[%.0f,%.0f)", fracBits, numIntervals, -halfRange, halfRange)

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

		mu0, mu1 := wideSplineSigmoidFn(ring, eta0, eta1, tf, numIntervals, halfRange)

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
			pr0, pr1 := hadamardBothFn(xc0, r0, xc1, r1, ring.FracBits, ring, tf)
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
	t.Logf("Ref  :  [%.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f]", ref[0], ref[1], ref[2], ref[3], ref[4], ref[5], ref[6])
	t.Logf("Max coef error vs centralized GLM: %.2e", maxErr)
}

// Test: wide spline at fracBits=20 (baseline — same precision, no Kelkar exp)
func TestWideSpline20(t *testing.T) {
	pimaTrainWideSpline(t, 20, 100, 5.0, floorTruncBoth)
}

// Test: wide spline at fracBits=30 (THE KEY TEST — 1000x more precision)
func TestWideSpline30(t *testing.T) {
	pimaTrainWideSpline(t, 30, 100, 5.0, floorTruncBoth)
}

func TestWideSpline22(t *testing.T) {
	pimaTrainWideSpline(t, 22, 100, 5.0, floorTruncBoth)
}

func TestWideSpline25(t *testing.T) {
	pimaTrainWideSpline(t, 25, 100, 5.0, floorTruncBoth)
}

// Test fewer intervals — critical for scalability
func TestWideSpline20_50int(t *testing.T)  { pimaTrainWideSpline(t, 20, 50, 5.0, floorTruncBoth) }
func TestWideSpline20_30int(t *testing.T)  { pimaTrainWideSpline(t, 20, 30, 5.0, floorTruncBoth) }
func TestWideSpline20_20int(t *testing.T)  { pimaTrainWideSpline(t, 20, 20, 5.0, floorTruncBoth) }
