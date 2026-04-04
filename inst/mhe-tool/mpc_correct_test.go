package main

import (
	"math"
	"testing"
)

// TestCorrectSharing verifies the EXACT FixedPoint sharing approach:
// ALL sharing in FixedPoint (no float64 round-trip).
func TestCorrectSharing(t *testing.T) {
	fracBits := 20
	n := 5
	pA := 2

	xA := [][]float64{{1.0, -0.5}, {0.3, 1.2}, {-0.7, 0.4}, {1.5, -1.0}, {0.2, 0.8}}
	xB := [][]float64{{0.8}, {-0.3}, {1.0}, {-0.5}, {0.7}}
	y := []float64{1, 0, 1, 0, 1}
	betaA := []float64{0.3, -0.2}
	betaB := []float64{0.5}

	// Plaintext
	etaPlain := make([]float64, n)
	for i := 0; i < n; i++ {
		for j := 0; j < pA; j++ { etaPlain[i] += xA[i][j] * betaA[j] }
		etaPlain[i] += xB[i][0] * betaB[0]
	}
	muPlain := make([]float64, n)
	for i := 0; i < n; i++ { muPlain[i] = sigmoid(etaPlain[i]) }
	gradAPlain := make([]float64, pA)
	for j := 0; j < pA; j++ {
		for i := 0; i < n; i++ { gradAPlain[j] += xA[i][j] * (y[i] - muPlain[i]) }
	}
	t.Logf("Plaintext: gradA=[%.4f,%.4f]", gradAPlain[0], gradAPlain[1])

	// --- Secure: ALL FixedPoint sharing ---
	muFP := FloatVecToFP(muPlain, fracBits)
	muA, muB := SplitVec(muFP)

	yFP := FloatVecToFP(y, fracBits)
	residA := make([]FixedPoint, n)
	residB := make([]FixedPoint, n)
	for i := 0; i < n; i++ {
		residA[i] = FPSub(yFP[i], muA[i])
		residB[i] = FPNeg(muB[i])
	}

	// Local gradient
	xAFP := make([][]FixedPoint, n)
	for i := 0; i < n; i++ { xAFP[i] = FloatVecToFP(xA[i], fracBits) }
	localGradA := PlaintextMatTVecMul(xAFP, residA, fracBits)

	// Cross-gradient: X_A^T * residB
	// Convert X to FP FIRST, THEN split (exact in mod 2^64)
	xA_flat_fp := make([]FixedPoint, n*pA)
	for j := 0; j < pA; j++ {
		for i := 0; i < n; i++ {
			xA_flat_fp[j*n+i] = FromFloat64(xA[i][j], fracBits)
		}
	}
	xA_own, xA_peer := SplitVec(xA_flat_fp)  // EXACT: own + peer = xA_flat_fp

	// Residual already in FP, split directly
	residB_own, residB_peer := SplitVec(residB)

	// Expand for pA columns
	residB_own_exp := make([]FixedPoint, n*pA)
	residB_peer_exp := make([]FixedPoint, n*pA)
	for j := 0; j < pA; j++ {
		copy(residB_own_exp[j*n:(j+1)*n], residB_own)
		copy(residB_peer_exp[j*n:(j+1)*n], residB_peer)
	}

	// Beaver multiply (all FixedPoint)
	prodTarget := make([]FixedPoint, n*pA)
	prodPeer := make([]FixedPoint, n*pA)
	for i := 0; i < n*pA; i++ {
		u := FromFloat64(0.1*float64(i)+0.3, fracBits)
		v := FromFloat64(-0.05*float64(i)+0.2, fracBits)
		w := FPMulLocal(u, v, fracBits)
		u0, u1 := Split(u)
		v0, v1 := Split(v)
		w0, w1 := Split(w)
		d0, e0 := FPSub(xA_own[i], u0), FPSub(residB_peer_exp[i], v0)
		d1, e1 := FPSub(xA_peer[i], u1), FPSub(residB_own_exp[i], v1)
		d, e := FPAdd(d0, d1), FPAdd(e0, e1)
		prodTarget[i] = FPAdd(FPAdd(w0, FPMulLocal(e, u0, fracBits)),
			FPAdd(FPMulLocal(d, v0, fracBits), FPMulLocal(d, e, fracBits)))
		prodPeer[i] = FPAdd(FPAdd(w1, FPMulLocal(e, u1, fracBits)),
			FPMulLocal(d, v1, fracBits))
	}

	crossTarget := make([]FixedPoint, pA)
	crossPeer := make([]FixedPoint, pA)
	for j := 0; j < pA; j++ {
		for i := 0; i < n; i++ {
			crossTarget[j] = FPAdd(crossTarget[j], prodTarget[j*n+i])
			crossPeer[j] = FPAdd(crossPeer[j], prodPeer[j*n+i])
		}
	}

	fullGradA := make([]FixedPoint, pA)
	for j := 0; j < pA; j++ {
		fullGradA[j] = FPAdd(localGradA[j], FPAdd(crossTarget[j], crossPeer[j]))
	}
	gradA_f64 := FPVecToFloat(fullGradA, fracBits)

	t.Logf("Secure:    gradA=[%.4f,%.4f]", gradA_f64[0], gradA_f64[1])
	for j := 0; j < pA; j++ {
		err := math.Abs(gradA_f64[j] - gradAPlain[j])
		t.Logf("  gradA[%d]: secure=%.6f plain=%.6f err=%.4e", j, gradA_f64[j], gradAPlain[j], err)
		if err > 0.01 {
			t.Errorf("Gradient error %.4e too large", err)
		}
	}
}
