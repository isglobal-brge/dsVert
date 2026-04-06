package main

import (
	"math"
	"testing"
)

// TestPiecewiseSigmoidTrainingMheTool runs the full training loop using:
// - Ring63 from mhe-tool (validated)
// - SecureSigmoidLocal (piecewise, validated)
// - Beaver multiplication (validated)
// - SecurePolyEval for Taylor polynomial (validated)
//
// This is the DEFINITIVE test that the protocol works with the mhe-tool Ring63.
func TestPiecewiseSigmoidTrainingMheTool(t *testing.T) {
	ring := NewRing63(20)
	cfg := DefaultExpConfig()

	n := 10
	p := 2
	X := []float64{
		0.5, -0.3, -1.2, 0.8, 0.7, 0.4, -0.4, -0.9, 1.1, 0.2,
		-0.8, 1.3, 0.3, -0.5, -0.1, 0.7, 0.9, -1.1, -0.6, 0.1,
	}
	y := []float64{1, 0, 1, 0, 1, 0, 1, 0, 1, 0}

	// Convert to Ring63 and split
	xFP := make([]uint64, n*p)
	yFP := make([]uint64, n)
	for i, v := range X { xFP[i] = ring.FromDouble(v) }
	for i, v := range y { yFP[i] = ring.FromDouble(v) }

	x0 := make([]uint64, n*p); x1 := make([]uint64, n*p)
	y0 := make([]uint64, n); y1 := make([]uint64, n)
	for i := range xFP { x0[i], x1[i] = ring.SplitShare(xFP[i]) }
	for i := range yFP { y0[i], y1[i] = ring.SplitShare(yFP[i]) }

	beta := make([]float64, p+1) // intercept + features
	alpha := 0.5
	lambda := 1e-4
	params := DefaultSigmoidParams()

	for iter := 1; iter <= 200; iter++ {
		betaOld := make([]float64, p+1)
		copy(betaOld, beta)

		betaFP := make([]uint64, p+1)
		for j := range beta { betaFP[j] = ring.FromDouble(beta[j]) }
		b0 := make([]uint64, p+1); b1 := make([]uint64, p+1)
		for j := range betaFP { b0[j], b1[j] = ring.SplitShare(betaFP[j]) }

		// Eta = X * beta (via Beaver)
		eta0 := make([]uint64, n); eta1 := make([]uint64, n)
		for i := 0; i < n; i++ {
			eta0[i] = b0[0]; eta1[i] = b1[0] // intercept
			for j := 0; j < p; j++ {
				idx := i*p + j
				t0, t1 := SampleBeaverTripleVector(1, ring)
				state0, msg0 := GenerateBatchedMultiplicationGateMessage(
					[]uint64{x0[idx]}, []uint64{b0[j+1]}, t0, ring)
				state1, msg1 := GenerateBatchedMultiplicationGateMessage(
					[]uint64{x1[idx]}, []uint64{b1[j+1]}, t1, ring)
				prod0 := HadamardProductPartyZero(state0, t0, msg1, 20, ring)
				prod1 := HadamardProductPartyOne(state1, t1, msg0, 20, ring)
				eta0[i] = ring.Add(eta0[i], prod0[0])
				eta1[i] = ring.Add(eta1[i], prod1[0])
			}
		}

		// Sigmoid (piecewise, local simulation — uses SecureSigmoidLocal)
		mu0, mu1 := SecureSigmoidLocal(params, eta0, eta1)

		// Residual
		r0 := make([]uint64, n); r1 := make([]uint64, n)
		for i := range r0 {
			r0[i] = ring.Sub(mu0[i], y0[i])
			r1[i] = ring.Sub(mu1[i], y1[i])
		}

		// Gradient (reconstruct — this is what the protocol reveals)
		var sumR0, sumR1 uint64
		for i := 0; i < n; i++ {
			sumR0 = ring.Add(sumR0, r0[i])
			sumR1 = ring.Add(sumR1, r1[i])
		}
		gIntercept := ring.ToDouble(ring.Add(sumR0, sumR1)) / float64(n)

		grad := make([]float64, p)
		for j := 0; j < p; j++ {
			xCol0 := make([]uint64, n); xCol1 := make([]uint64, n)
			for i := 0; i < n; i++ {
				xCol0[i] = x0[i*p+j]; xCol1[i] = x1[i*p+j]
			}
			t0, t1 := SampleBeaverTripleVector(n, ring)
			state0, msg0 := GenerateBatchedMultiplicationGateMessage(xCol0, r0, t0, ring)
			state1, msg1 := GenerateBatchedMultiplicationGateMessage(xCol1, r1, t1, ring)
			prod0 := HadamardProductPartyZero(state0, t0, msg1, 20, ring)
			prod1 := HadamardProductPartyOne(state1, t1, msg0, 20, ring)
			var s0, s1 uint64
			for i := 0; i < n; i++ { s0 = ring.Add(s0, prod0[i]); s1 = ring.Add(s1, prod1[i]) }
			grad[j] = ring.ToDouble(ring.Add(s0, s1))/float64(n) + lambda*beta[j+1]
		}

		// Update
		gradNorm := gIntercept * gIntercept
		for j := range grad { gradNorm += grad[j] * grad[j] }
		gradNorm = math.Sqrt(gradNorm)
		scale := 1.0
		if gradNorm > 5.0 { scale = 5.0 / gradNorm }

		beta[0] -= alpha * gIntercept * scale
		for j := range grad { beta[j+1] -= alpha * grad[j] * scale }

		maxDiff := 0.0
		for j := range beta {
			d := math.Abs(beta[j] - betaOld[j])
			if d > maxDiff { maxDiff = d }
		}
		if iter%50 == 0 || iter <= 3 {
			t.Logf("Iter %d: maxDiff=%.2e beta=%v", iter, maxDiff, beta)
		}
		if maxDiff < 1e-4 {
			t.Logf("Converged at iter %d", iter)
			break
		}
	}

	// Compare with plaintext piecewise sigmoid GD
	sp := DefaultSigmoidParams()
	plainBeta := make([]float64, p+1)
	for iter := 0; iter < 200; iter++ {
		grad := make([]float64, p+1)
		for i := 0; i < n; i++ {
			eta := plainBeta[0]
			for j := 0; j < p; j++ { eta += X[i*p+j] * plainBeta[j+1] }
			mu := EvalPiecewiseSigmoid(eta, sp) // use the same piecewise function
			mu = math.Max(1e-10, math.Min(1-1e-10, mu))
			r := mu - y[i]
			grad[0] += r
			for j := 0; j < p; j++ { grad[j+1] += X[i*p+j] * r }
		}
		gn := 0.0
		for j := range grad {
			grad[j] = grad[j]/float64(n) + lambda*plainBeta[j]
			gn += grad[j] * grad[j]
		}
		gn = math.Sqrt(gn)
		sc := 1.0
		if gn > 5.0 { sc = 5.0 / gn }
		for j := range plainBeta { plainBeta[j] -= alpha * grad[j] * sc }
	}

	t.Logf("Plaintext piecewise beta: %v", plainBeta)

	maxErr := 0.0
	for j := range beta {
		err := math.Abs(beta[j] - plainBeta[j])
		if err > maxErr { maxErr = err }
	}
	t.Logf("Max coefficient error vs plaintext: %.2e", maxErr)

	if maxErr > 0.01 {
		t.Errorf("Coefficient error %.2e exceeds 0.01", maxErr)
	}

	_ = cfg // for future Kelkar exp use
}

// SampleBeaverTripleVector is already defined in k2_beaver_google.go

// EvalPiecewiseSigmoid evaluates the piecewise sigmoid matching evalSpline/evalExpTaylor
func EvalPiecewiseSigmoid(x float64, sp SigmoidParams) float64 {
	lfLn2 := float64(sp.FracBits) * math.Ln2
	if x >= 0 && x < 1.0 {
		return evalSpline(x, sp)
	} else if x >= 1.0 && x < lfLn2 {
		return evalExpTaylor(x, sp)
	} else if x >= lfLn2 {
		return 1.0
	} else if x < -lfLn2 {
		return 0.0
	} else if x >= -lfLn2 && x < -1.0 {
		return 1.0 - evalExpTaylor(-x, sp)
	} else {
		return 1.0 - evalSpline(-x, sp)
	}
}
