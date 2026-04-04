package main

import (
	"math"
	"testing"
)

// TestSecureGradientCorrectness verifies that the secure Beaver-triple
// gradient matches the plaintext gradient to within polynomial + FP error.
func TestSecureGradientCorrectness(t *testing.T) {
	fracBits := 20
	degree := 21
	coeffs := SigmoidGlobalPoly(degree)
	n := 10
	pA := 2  // party A features
	pB := 1  // party B features

	// Known data
	xA := [][]float64{
		{1.0, -0.5}, {0.3, 1.2}, {-0.7, 0.4}, {1.5, -1.0}, {0.2, 0.8},
		{-0.4, 1.1}, {0.9, -0.3}, {-1.2, 0.6}, {0.6, -0.7}, {1.1, 0.2},
	}
	xB := [][]float64{
		{0.8}, {-0.3}, {1.0}, {-0.5}, {0.7},
		{-0.2}, {0.6}, {-0.8}, {0.4}, {0.9},
	}
	y := []float64{1, 0, 1, 0, 1, 1, 0, 1, 0, 1}
	betaA := []float64{0.3, -0.2}
	betaB := []float64{0.5}

	// --- Plaintext computation (ground truth) ---
	etaPlain := make([]float64, n)
	for i := 0; i < n; i++ {
		for j := 0; j < pA; j++ { etaPlain[i] += xA[i][j] * betaA[j] }
		for j := 0; j < pB; j++ { etaPlain[i] += xB[i][j] * betaB[j] }
	}
	muPlain := make([]float64, n)
	for i := 0; i < n; i++ { muPlain[i] = sigmoid(etaPlain[i]) }

	// Plaintext gradient for party A
	gradAPlain := make([]float64, pA)
	for j := 0; j < pA; j++ {
		for i := 0; i < n; i++ { gradAPlain[j] += xA[i][j] * (y[i] - muPlain[i]) }
	}
	// Plaintext gradient for party B
	gradBPlain := make([]float64, pB)
	for j := 0; j < pB; j++ {
		for i := 0; i < n; i++ { gradBPlain[j] += xB[i][j] * (y[i] - muPlain[i]) }
	}

	t.Logf("Plaintext gradients: A=[%.4f, %.4f], B=[%.4f]",
		gradAPlain[0], gradAPlain[1], gradBPlain[0])

	// --- Secure computation via Beaver triples ---
	etaA := make([]float64, n)
	etaB := make([]float64, n)
	for i := 0; i < n; i++ {
		for j := 0; j < pA; j++ { etaA[i] += xA[i][j] * betaA[j] }
		for j := 0; j < pB; j++ { etaB[i] += xB[i][j] * betaB[j] }
	}

	// Split etas
	etaAFP := FloatVecToFP(etaA, fracBits)
	etaBFP := FloatVecToFP(etaB, fracBits)
	etaA0, etaA1 := SplitVec(etaAFP)
	etaB0, etaB1 := SplitVec(etaBFP)
	shareA := FPVecAdd(etaA0, etaB1) // A's share of eta_total
	shareB := FPVecAdd(etaB0, etaA1) // B's share

	// Power tree
	powA := make([][]FixedPoint, degree)
	powB := make([][]FixedPoint, degree)
	powA[0] = shareA
	powB[0] = shareB

	beaverMulVec := func(a0, a1, b0, b1 []FixedPoint) ([]FixedPoint, []FixedPoint) {
		nn := len(a0)
		c0 := make([]FixedPoint, nn)
		c1 := make([]FixedPoint, nn)
		for i := 0; i < nn; i++ {
			u_fp := FromFloat64(float64(i)*0.037+0.13, fracBits) // pseudo-random triple
			v_fp := FromFloat64(float64(i)*0.041-0.17, fracBits)
			w_fp := FPMulLocal(u_fp, v_fp, fracBits)
			u0, u1 := Split(u_fp)
			v0, v1 := Split(v_fp)
			w0, w1 := Split(w_fp)
			d0, e0 := FPSub(a0[i], u0), FPSub(b0[i], v0)
			d1, e1 := FPSub(a1[i], u1), FPSub(b1[i], v1)
			d, e := FPAdd(d0, d1), FPAdd(e0, e1)
			c0[i] = FPAdd(FPAdd(w0, FPMulLocal(e, u0, fracBits)),
				FPAdd(FPMulLocal(d, v0, fracBits), FPMulLocal(d, e, fracBits)))
			c1[i] = FPAdd(FPAdd(w1, FPMulLocal(e, u1, fracBits)),
				FPMulLocal(d, v1, fracBits))
		}
		return c0, c1
	}

	// Build all powers x^2 through x^degree via sequential multiplication
	for k := 1; k < degree; k++ {
		// x^(k+1) = x^k * x
		powA[k], powB[k] = beaverMulVec(powA[k-1], powB[k-1], powA[0], powB[0])
	}

	// Polynomial eval
	muA := make([]FixedPoint, n)
	muB := make([]FixedPoint, n)
	c0FP := FromFloat64(coeffs[0], fracBits)
	for i := 0; i < n; i++ { muA[i] = c0FP }
	for k := 1; k <= degree; k++ {
		ck := FromFloat64(coeffs[k], fracBits)
		for i := 0; i < n; i++ {
			muA[i] = FPAdd(muA[i], FPMulLocal(ck, powA[k-1][i], fracBits))
			muB[i] = FPAdd(muB[i], FPMulLocal(ck, powB[k-1][i], fracBits))
		}
	}

	// Verify mu shares reconstruct to approx sigmoid
	for i := 0; i < n; i++ {
		muSecure := FPAdd(muA[i], muB[i]).ToFloat64(fracBits)
		muExact := sigmoid(etaPlain[i])
		err := math.Abs(muSecure - muExact)
		if err > 0.01 {
			t.Errorf("mu[%d]: secure=%.6f exact=%.6f err=%.4e", i, muSecure, muExact, err)
		}
	}

	// Residual shares
	residA := make([]FixedPoint, n)
	residB := make([]FixedPoint, n)
	yFP := FloatVecToFP(y, fracBits)
	for i := 0; i < n; i++ {
		residA[i] = FPSub(yFP[i], muA[i])
		residB[i] = FPNeg(muB[i])
	}

	// Gradient shares
	xAFP := make([][]FixedPoint, n)
	for i := 0; i < n; i++ { xAFP[i] = FloatVecToFP(xA[i], fracBits) }
	xBFP := make([][]FixedPoint, n)
	for i := 0; i < n; i++ { xBFP[i] = FloatVecToFP(xB[i], fracBits) }

	gA_fromA := PlaintextMatTVecMul(xAFP, residA, fracBits)
	gA_fromB := PlaintextMatTVecMul(xAFP, residB, fracBits)
	gradASecure := make([]float64, pA)
	for j := range gradASecure {
		gradASecure[j] = FPAdd(gA_fromA[j], gA_fromB[j]).ToFloat64(fracBits)
	}

	gB_fromB := PlaintextMatTVecMul(xBFP, residB, fracBits)
	gB_fromA := PlaintextMatTVecMul(xBFP, residA, fracBits)
	gradBSecure := make([]float64, pB)
	for j := range gradBSecure {
		gradBSecure[j] = FPAdd(gB_fromB[j], gB_fromA[j]).ToFloat64(fracBits)
	}

	t.Logf("Secure  gradients: A=[%.4f, %.4f], B=[%.4f]",
		gradASecure[0], gradASecure[1], gradBSecure[0])

	// Compare
	for j := 0; j < pA; j++ {
		err := math.Abs(gradASecure[j] - gradAPlain[j])
		t.Logf("  gradA[%d]: secure=%.6f plain=%.6f err=%.4e", j, gradASecure[j], gradAPlain[j], err)
		if err > 0.1 {
			t.Errorf("Gradient A[%d] error %.4e too large", j, err)
		}
	}
	for j := 0; j < pB; j++ {
		err := math.Abs(gradBSecure[j] - gradBPlain[j])
		t.Logf("  gradB[%d]: secure=%.6f plain=%.6f err=%.4e", j, gradBSecure[j], gradBPlain[j], err)
		if err > 0.1 {
			t.Errorf("Gradient B[%d] error %.4e too large", j, err)
		}
	}
}
