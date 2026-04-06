package main

import (
	"math"
	"testing"
)

func TestDistributedSigmoidMheTool(t *testing.T) {
	ring := NewRing63(20)

	testX := []float64{-10, -5, -2, -1, -0.5, 0, 0.5, 1, 2, 5, 10}

	xFP := make([]uint64, len(testX))
	for i, v := range testX { xFP[i] = ring.FromDouble(v) }
	x0 := make([]uint64, len(testX)); x1 := make([]uint64, len(testX))
	for i := range xFP { x0[i], x1[i] = ring.SplitShare(xFP[i]) }

	mu0, mu1 := DistributedSigmoidLocalMhe(ring, x0, x1)

	maxErr := 0.0
	for i, x := range testX {
		got := ring.ToDouble(ring.Add(mu0[i], mu1[i]))
		want := 1.0 / (1.0 + math.Exp(-x))
		err := math.Abs(got - want)
		if err > maxErr { maxErr = err }
		t.Logf("sigmoid(%5.1f): got=%.8f want=%.8f err=%.2e", x, got, want, err)
	}
	t.Logf("Max error: %.2e", maxErr)
	if maxErr > 1e-3 { t.Errorf("Max error %.2e exceeds 1e-3", maxErr) }
}

func TestDistributedSigmoidConsistency(t *testing.T) {
	ring := NewRing63(20)
	testX := []float64{-1.54, -0.5, 0.5, 1.54, 2.5}

	for run := 0; run < 10; run++ {
		xFP := make([]uint64, len(testX))
		for i, v := range testX { xFP[i] = ring.FromDouble(v) }
		x0 := make([]uint64, len(testX)); x1 := make([]uint64, len(testX))
		for i := range xFP { x0[i], x1[i] = ring.SplitShare(xFP[i]) }

		mu0, mu1 := DistributedSigmoidLocalMhe(ring, x0, x1)

		maxErr := 0.0
		for i, x := range testX {
			got := ring.ToDouble(ring.Add(mu0[i], mu1[i]))
			want := 1.0 / (1.0 + math.Exp(-x))
			err := math.Abs(got - want)
			if err > maxErr { maxErr = err }
		}
		if maxErr > 0.01 {
			t.Errorf("Run %d: max error %.2e exceeds 0.01", run, maxErr)
		}
	}
	t.Log("10 runs all passed")
}

func TestDistributedSigmoidTraining(t *testing.T) {
	ring := NewRing63(20)
	params := DefaultSigmoidParams()

	n := 10; p := 2
	X := []float64{
		0.5, -0.3, -1.2, 0.8, 0.7, 0.4, -0.4, -0.9, 1.1, 0.2,
		-0.8, 1.3, 0.3, -0.5, -0.1, 0.7, 0.9, -1.1, -0.6, 0.1,
	}
	y := []float64{1, 0, 1, 0, 1, 0, 1, 0, 1, 0}

	xFP := make([]uint64, n*p); yFP := make([]uint64, n)
	for i, v := range X { xFP[i] = ring.FromDouble(v) }
	for i, v := range y { yFP[i] = ring.FromDouble(v) }
	x0 := make([]uint64, n*p); x1 := make([]uint64, n*p)
	y0 := make([]uint64, n); y1 := make([]uint64, n)
	for i := range xFP { x0[i], x1[i] = ring.SplitShare(xFP[i]) }
	for i := range yFP { y0[i], y1[i] = ring.SplitShare(yFP[i]) }

	beta := make([]float64, p+1)
	alpha := 0.5; lambda := 1e-4

	for iter := 1; iter <= 200; iter++ {
		betaOld := make([]float64, p+1); copy(betaOld, beta)
		betaFP := make([]uint64, p+1)
		for j := range beta { betaFP[j] = ring.FromDouble(beta[j]) }

		// Eta = intercept + X*beta (ScalarVectorProduct — beta is public)
		eta0 := make([]uint64, n); eta1 := make([]uint64, n)
		for i := 0; i < n; i++ {
			eta0[i] = betaFP[0]; eta1[i] = 0
			for j := 0; j < p; j++ {
				sv0 := ScalarVectorProductPartyZero(beta[j+1], []uint64{x0[i*p+j]}, ring)
				sv1 := ScalarVectorProductPartyOne(beta[j+1], []uint64{x1[i*p+j]}, ring)
				eta0[i] = ring.Add(eta0[i], sv0[0])
				eta1[i] = ring.Add(eta1[i], sv1[0])
			}
		}

		// Sigmoid (distributed)
		mu0, mu1 := DistributedSigmoidLocalMhe(ring, eta0, eta1)

		// Residual and gradient
		r0 := make([]uint64, n); r1 := make([]uint64, n)
		for i := range r0 { r0[i] = ring.Sub(mu0[i], y0[i]); r1[i] = ring.Sub(mu1[i], y1[i]) }

		var sR0, sR1 uint64
		for i := 0; i < n; i++ { sR0 = ring.Add(sR0, r0[i]); sR1 = ring.Add(sR1, r1[i]) }
		gInt := ring.ToDouble(ring.Add(sR0, sR1)) / float64(n)

		grad := make([]float64, p)
		for j := 0; j < p; j++ {
			xc0 := make([]uint64, n); xc1 := make([]uint64, n)
			for i := 0; i < n; i++ { xc0[i] = x0[i*p+j]; xc1[i] = x1[i*p+j] }
			t0, t1 := SampleBeaverTripleVector(n, ring)
			st0, m0 := GenerateBatchedMultiplicationGateMessage(xc0, r0, t0, ring)
			st1, m1 := GenerateBatchedMultiplicationGateMessage(xc1, r1, t1, ring)
			pr0 := HadamardProductPartyZero(st0, t0, m1, ring.FracBits, ring)
			pr1 := HadamardProductPartyOne(st1, t1, m0, ring.FracBits, ring)
			var s0, s1 uint64
			for i := 0; i < n; i++ { s0 = ring.Add(s0, pr0[i]); s1 = ring.Add(s1, pr1[i]) }
			grad[j] = ring.ToDouble(ring.Add(s0, s1))/float64(n) + lambda*beta[j+1]
		}

		gn := gInt * gInt
		for j := range grad { gn += grad[j] * grad[j] }
		gn = math.Sqrt(gn); sc := 1.0
		if gn > 5.0 { sc = 5.0 / gn }

		beta[0] -= alpha * gInt * sc
		for j := range grad { beta[j+1] -= alpha * grad[j] * sc }

		maxDiff := 0.0
		for j := range beta { d := math.Abs(beta[j] - betaOld[j]); if d > maxDiff { maxDiff = d } }
		if iter%50 == 0 { t.Logf("Iter %d: maxDiff=%.2e", iter, maxDiff) }
		if maxDiff < 1e-4 { t.Logf("Converged at iter %d", iter); break }
	}

	// Compare with plaintext
	plainBeta := make([]float64, p+1)
	for iter := 0; iter < 200; iter++ {
		g := make([]float64, p+1)
		for i := 0; i < n; i++ {
			eta := plainBeta[0]
			for j := 0; j < p; j++ { eta += X[i*p+j] * plainBeta[j+1] }
			mu := EvalPiecewiseSigmoid(eta, params)
			mu = math.Max(1e-10, math.Min(1-1e-10, mu))
			r := mu - y[i]; g[0] += r
			for j := 0; j < p; j++ { g[j+1] += X[i*p+j] * r }
		}
		gn := 0.0
		for j := range g { g[j] = g[j]/float64(n) + lambda*plainBeta[j]; gn += g[j]*g[j] }
		gn = math.Sqrt(gn); sc := 1.0; if gn > 5.0 { sc = 5.0/gn }
		for j := range plainBeta { plainBeta[j] -= alpha * g[j] * sc }
	}

	maxErr := 0.0
	for j := range beta {
		err := math.Abs(beta[j] - plainBeta[j]); if err > maxErr { maxErr = err }
	}
	t.Logf("Distributed: %v", beta)
	t.Logf("Plaintext:   %v", plainBeta)
	t.Logf("Max coef error: %.2e", maxErr)
	if maxErr > 1.0 { t.Errorf("Coefficient error %.2e exceeds 1.0", maxErr) }
}
