// k2_pipelines_test.go: end-to-end pipeline tests simulating the two
// DCF parties in-process for the new methods (Cox, weighted GLM,
// multinomial softmax). Reconstructs final outputs from party shares
// and compares to the plaintext computation on the same inputs.
package main

import (
	"math"
	"math/rand"
	"sort"
	"testing"
)

// TestCoxGradient_EndToEnd exercises the full Cox reverse-cumsum
// gradient: sort, exp(eta) via DCF wide-spline, reverse cumsum to S,
// 1/S via Goldschmidt-refined reciprocal, forward cumsum of delta/S
// to G, triple Beaver product x_j*exp(eta_j)*G_j, plus the plaintext
// first term sum_{delta=1} x_j. Compares reconstructed gradient to
// the plaintext Cox gradient on the same cohort.
func TestCoxGradient_EndToEnd(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	ring := NewRing63(K2DefaultFracBits)
	n := 30
	p := 3
	beta := []float64{0.3, -0.2, 0.15}

	X := make([][]float64, n)
	tTimes := make([]float64, n)
	delta := make([]float64, n)
	for i := 0; i < n; i++ {
		X[i] = make([]float64, p)
		for j := 0; j < p; j++ {
			X[i][j] = rng.NormFloat64() * 0.5
		}
		tTimes[i] = rng.ExpFloat64() + 0.1
		delta[i] = 0
		if rng.Float64() < 0.6 {
			delta[i] = 1
		}
	}

	type idxT struct {
		i    int
		t, d float64
	}
	idxs := make([]idxT, n)
	for i := 0; i < n; i++ {
		idxs[i] = idxT{i, tTimes[i], delta[i]}
	}
	sort.SliceStable(idxs, func(a, b int) bool {
		if idxs[a].t != idxs[b].t {
			return idxs[a].t < idxs[b].t
		}
		return idxs[a].d > idxs[b].d
	})
	Xs := make([][]float64, n)
	ds := make([]float64, n)
	for i, e := range idxs {
		Xs[i] = X[e.i]
		ds[i] = delta[e.i]
	}

	eta := make([]float64, n)
	for i := 0; i < n; i++ {
		for j := 0; j < p; j++ {
			eta[i] += Xs[i][j] * beta[j]
		}
	}
	expEta := make([]float64, n)
	for i := 0; i < n; i++ {
		expEta[i] = math.Exp(eta[i])
	}
	S := make([]float64, n)
	acc := 0.0
	for i := n - 1; i >= 0; i-- {
		acc += expEta[i]
		S[i] = acc
	}
	recipS := make([]float64, n)
	for i := 0; i < n; i++ {
		recipS[i] = 1.0 / S[i]
	}
	G := make([]float64, n)
	acc = 0.0
	for j := 0; j < n; j++ {
		acc += ds[j] * recipS[j]
		G[j] = acc
	}
	gradTrue := make([]float64, p)
	for j := 0; j < n; j++ {
		for k := 0; k < p; k++ {
			gradTrue[k] += ds[j] * Xs[j][k]
			gradTrue[k] -= Xs[j][k] * expEta[j] * G[j]
		}
	}

	// --- MPC simulation ---
	eta0, eta1 := splitFPShares(ring, eta)
	expEta0, expEta1 := WideSplineExp(ring, eta0, eta1, K2ExpIntervals)

	SShare0 := make([]uint64, n)
	SShare1 := make([]uint64, n)
	acc0 := uint64(0)
	acc1 := uint64(0)
	for i := n - 1; i >= 0; i-- {
		acc0 = ring.Add(acc0, expEta0[i])
		acc1 = ring.Add(acc1, expEta1[i])
		SShare0[i] = acc0
		SShare1[i] = acc1
	}
	SRec := reconstructFromShares(ring, SShare0, SShare1)
	for i := 0; i < n; i++ {
		if math.Abs(SRec[i]-S[i])/math.Abs(S[i]) > 0.05 {
			t.Errorf("S[%d] reconstruction: got %f want %f", i, SRec[i], S[i])
		}
	}

	Smin := S[n-1]
	Smax := S[0]
	lower := 0.5 * Smin
	upper := 2.0 * Smax
	recipS0, recipS1 := WideSplineReciprocalRefined(ring, SShare0, SShare1,
		200, lower, upper, 1)
	recipRec := reconstructFromShares(ring, recipS0, recipS1)
	maxRecipErr := 0.0
	for i := 0; i < n; i++ {
		e := math.Abs(recipRec[i]-recipS[i]) / recipS[i]
		if e > maxRecipErr {
			maxRecipErr = e
		}
	}
	t.Logf("1/S reconstruction max rel err = %.4f%%", maxRecipErr*100)
	if maxRecipErr > 0.03 {
		t.Errorf("1/S rel err %.4f%% exceeds 3%% tolerance", maxRecipErr*100)
	}

	deltaFP := make([]uint64, n)
	for i := 0; i < n; i++ {
		deltaFP[i] = ring.FromDouble(ds[i])
	}
	maskedR0 := make([]uint64, n)
	maskedR1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		maskedR0[i] = ring.TruncMulSigned(recipS0[i], deltaFP[i])
		maskedR1[i] = ring.TruncMulSigned(recipS1[i], deltaFP[i])
	}
	G0 := make([]uint64, n)
	G1 := make([]uint64, n)
	acc0 = 0
	acc1 = 0
	for i := 0; i < n; i++ {
		acc0 = ring.Add(acc0, maskedR0[i])
		acc1 = ring.Add(acc1, maskedR1[i])
		G0[i] = acc0
		G1[i] = acc1
	}
	GRec := reconstructFromShares(ring, G0, G1)
	maxGErr := 0.0
	for i := 0; i < n; i++ {
		e := math.Abs(GRec[i] - G[i])
		if e > maxGErr {
			maxGErr = e
		}
	}
	t.Logf("G reconstruction max abs err = %.6f (plain G[0]=%.3f, G[n-1]=%.3f)",
		maxGErr, G[0], G[n-1])
	if maxGErr > 0.05 {
		t.Errorf("G abs err %.6f exceeds 0.05 tolerance", maxGErr)
	}

	gradMPC := make([]float64, p)
	for k := 0; k < p; k++ {
		xk := make([]float64, n)
		for j := 0; j < n; j++ {
			xk[j] = Xs[j][k]
		}
		x0, x1 := splitFPShares(ring, xk)
		btA0, btA1 := SampleBeaverTripleVector(n, ring)
		stA0, msgA0 := GenerateBatchedMultiplicationGateMessage(x0, expEta0, btA0, ring)
		stA1, msgA1 := GenerateBatchedMultiplicationGateMessage(x1, expEta1, btA1, ring)
		xExp0, xExp1 := StochasticHadamardProduct(stA0, btA0, msgA1, stA1, btA1, msgA0,
			ring.FracBits, ring)

		btB0, btB1 := SampleBeaverTripleVector(n, ring)
		stB0, msgB0 := GenerateBatchedMultiplicationGateMessage(xExp0, G0, btB0, ring)
		stB1, msgB1 := GenerateBatchedMultiplicationGateMessage(xExp1, G1, btB1, ring)
		triple0, triple1 := StochasticHadamardProduct(stB0, btB0, msgB1, stB1, btB1, msgB0,
			ring.FracBits, ring)

		sum0 := uint64(0)
		sum1 := uint64(0)
		for i := 0; i < n; i++ {
			sum0 = ring.Add(sum0, triple0[i])
			sum1 = ring.Add(sum1, triple1[i])
		}
		term2 := ring.ToDouble(ring.Add(sum0, sum1))
		term1 := 0.0
		for j := 0; j < n; j++ {
			if ds[j] == 1 {
				term1 += xk[j]
			}
		}
		gradMPC[k] = term1 - term2
	}

	maxGradErr := 0.0
	for k := 0; k < p; k++ {
		denom := math.Abs(gradTrue[k]) + 1e-6
		rel := math.Abs(gradMPC[k]-gradTrue[k]) / denom
		t.Logf("Cox grad[%d]: MPC=%.6f plain=%.6f rel_err=%.4f%%",
			k, gradMPC[k], gradTrue[k], rel*100)
		if rel > maxGradErr {
			maxGradErr = rel
		}
	}
	if maxGradErr > 0.05 {
		t.Errorf("Cox gradient max rel err %.4f%% exceeds 5%% tolerance",
			maxGradErr*100)
	}
}

// TestWeightedGradient_EndToEnd exercises the weighted-GLM gradient
// pipeline via local residual scaling + Beaver matvec.
func TestWeightedGradient_EndToEnd(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	ring := NewRing63(K2DefaultFracBits)
	n := 40
	p := 4

	beta := []float64{0.5, -0.3, 0.2, 0.1}
	X := make([][]float64, n)
	y := make([]float64, n)
	w := make([]float64, n)
	for i := 0; i < n; i++ {
		X[i] = make([]float64, p)
		for j := 0; j < p; j++ {
			X[i][j] = rng.NormFloat64() * 0.5
		}
		y[i] = rng.NormFloat64()
		w[i] = 0.5 + rng.Float64()*2.0
	}

	mu := make([]float64, n)
	for i := 0; i < n; i++ {
		for j := 0; j < p; j++ {
			mu[i] += X[i][j] * beta[j]
		}
	}
	gradTrue := make([]float64, p)
	for i := 0; i < n; i++ {
		r := mu[i] - y[i]
		for k := 0; k < p; k++ {
			gradTrue[k] += X[i][k] * w[i] * r
		}
	}

	mu0, mu1 := splitFPShares(ring, mu)
	y0, y1 := splitFPShares(ring, y)
	wFP := make([]uint64, n)
	for i := 0; i < n; i++ {
		wFP[i] = ring.FromDouble(w[i])
	}
	r0 := make([]uint64, n)
	r1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		r0[i] = ring.Sub(mu0[i], y0[i])
		r1[i] = ring.Sub(mu1[i], y1[i])
	}
	rw0 := make([]uint64, n)
	rw1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		rw0[i] = ring.TruncMulSigned(r0[i], wFP[i])
		rw1[i] = ring.TruncMulSigned(r1[i], wFP[i])
	}
	rwRec := reconstructFromShares(ring, rw0, rw1)
	for i := 0; i < n; i++ {
		want := w[i] * (mu[i] - y[i])
		if math.Abs(rwRec[i]-want) > 0.01 {
			t.Errorf("rw[%d] mismatch: got %f want %f", i, rwRec[i], want)
		}
	}

	gradMPC := make([]float64, p)
	for k := 0; k < p; k++ {
		xk := make([]float64, n)
		for i := 0; i < n; i++ {
			xk[i] = X[i][k]
		}
		x0, x1 := splitFPShares(ring, xk)
		bt0, bt1 := SampleBeaverTripleVector(n, ring)
		st0, msg0 := GenerateBatchedMultiplicationGateMessage(x0, rw0, bt0, ring)
		st1, msg1 := GenerateBatchedMultiplicationGateMessage(x1, rw1, bt1, ring)
		prod0, prod1 := StochasticHadamardProduct(st0, bt0, msg1, st1, bt1, msg0,
			ring.FracBits, ring)
		s0 := uint64(0)
		s1 := uint64(0)
		for i := 0; i < n; i++ {
			s0 = ring.Add(s0, prod0[i])
			s1 = ring.Add(s1, prod1[i])
		}
		gradMPC[k] = ring.ToDouble(ring.Add(s0, s1))
	}

	maxErr := 0.0
	for k := 0; k < p; k++ {
		denom := math.Abs(gradTrue[k]) + 1e-6
		rel := math.Abs(gradMPC[k]-gradTrue[k]) / denom
		t.Logf("weighted grad[%d]: MPC=%.6f plain=%.6f rel_err=%.4f%%",
			k, gradMPC[k], gradTrue[k], rel*100)
		if rel > maxErr {
			maxErr = rel
		}
	}
	if maxErr > 0.01 {
		t.Errorf("weighted gradient max rel err %.4f%% exceeds 1%%", maxErr*100)
	}
}

// TestSoftmax_Composition exercises the multinomial softmax pipeline
// via DCF exp + reciprocal refinement + Beaver Hadamard.
func TestSoftmax_Composition(t *testing.T) {
	ring := NewRing63(K2DefaultFracBits)
	n := 20
	K := 4
	rng := rand.New(rand.NewSource(3))

	etaK := make([][]float64, K)
	for k := 0; k < K; k++ {
		etaK[k] = make([]float64, n)
		for i := 0; i < n; i++ {
			etaK[k][i] = rng.NormFloat64()
		}
	}

	pK := make([][]float64, K)
	for k := 0; k < K; k++ {
		pK[k] = make([]float64, n)
	}
	for i := 0; i < n; i++ {
		sum := 0.0
		es := make([]float64, K)
		for k := 0; k < K; k++ {
			es[k] = math.Exp(etaK[k][i])
			sum += es[k]
		}
		for k := 0; k < K; k++ {
			pK[k][i] = es[k] / sum
		}
	}

	expShares0 := make([][]uint64, K)
	expShares1 := make([][]uint64, K)
	for k := 0; k < K; k++ {
		e0, e1 := splitFPShares(ring, etaK[k])
		e0, e1 = WideSplineExp(ring, e0, e1, K2ExpIntervals)
		expShares0[k] = e0
		expShares1[k] = e1
	}
	sum0 := make([]uint64, n)
	sum1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		s0 := uint64(0)
		s1 := uint64(0)
		for k := 0; k < K; k++ {
			s0 = ring.Add(s0, expShares0[k][i])
			s1 = ring.Add(s1, expShares1[k][i])
		}
		sum0[i] = s0
		sum1[i] = s1
	}
	lower := 0.1
	upper := 10.0 * float64(K)
	recipSum0, recipSum1 := WideSplineReciprocalRefined(ring, sum0, sum1, 200,
		lower, upper, 1)

	pShares0 := make([][]uint64, K)
	pShares1 := make([][]uint64, K)
	for k := 0; k < K; k++ {
		bt0, bt1 := SampleBeaverTripleVector(n, ring)
		st0, msg0 := GenerateBatchedMultiplicationGateMessage(expShares0[k], recipSum0, bt0, ring)
		st1, msg1 := GenerateBatchedMultiplicationGateMessage(expShares1[k], recipSum1, bt1, ring)
		pShares0[k], pShares1[k] = StochasticHadamardProduct(st0, bt0, msg1, st1, bt1, msg0,
			ring.FracBits, ring)
	}

	maxErr := 0.0
	for k := 0; k < K; k++ {
		pRec := reconstructFromShares(ring, pShares0[k], pShares1[k])
		for i := 0; i < n; i++ {
			diff := math.Abs(pRec[i] - pK[k][i])
			if diff > maxErr {
				maxErr = diff
			}
		}
	}
	t.Logf("softmax composition: max abs err = %.6f (K=%d classes, n=%d)",
		maxErr, K, n)
	if maxErr > 0.02 {
		t.Errorf("softmax composition max abs err %.6f exceeds 2%%", maxErr)
	}
}

// TestOffsetAddition verifies that adding plaintext to one party's
// share preserves additive-share correctness (k2SetOffsetDS premise).
func TestOffsetAddition(t *testing.T) {
	ring := NewRing63(K2DefaultFracBits)
	n := 10
	eta := []float64{0.1, 0.5, -0.3, 1.2, -0.7, 0.0, 2.1, -1.5, 0.8, -0.2}
	offset := []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0}

	eta0, eta1 := splitFPShares(ring, eta)
	for i := 0; i < n; i++ {
		offFP := ring.FromDouble(offset[i])
		eta0[i] = ring.Add(eta0[i], offFP)
	}
	rec := reconstructFromShares(ring, eta0, eta1)
	maxErr := 0.0
	for i := 0; i < n; i++ {
		want := eta[i] + offset[i]
		err := math.Abs(rec[i] - want)
		if err > maxErr {
			maxErr = err
		}
	}
	t.Logf("offset addition max abs err = %.6e", maxErr)
	if maxErr > 1e-5 {
		t.Errorf("offset addition max abs err %.6e exceeds 1e-5", maxErr)
	}
}
