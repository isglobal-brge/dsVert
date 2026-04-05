package main

import (
	"math"
	"testing"
)

func TestSecureSigmoidLocalAccuracy(t *testing.T) {
	params := DefaultSigmoidParams()
	r := params.Ring

	// Test sigmoid on a range of values including all 6 intervals
	testValues := []float64{
		0.0, 0.1, 0.5, 0.9,        // Interval 0 (spline)
		1.0, 2.0, 5.0, 10.0, 13.0, // Interval 1 (exp + Taylor)
		14.0, 20.0,                  // Interval 2 (saturate to 1)
		-20.0, -14.0,                // Interval 3 (saturate to 0)
		-10.0, -5.0, -2.0, -1.0,    // Interval 4 (1 - exp Taylor)
		-0.9, -0.5, -0.1,           // Interval 5 (1 - spline)
	}

	maxErr := 0.0
	for _, x := range testValues {
		xFP := r.FromDouble(x)
		x0, x1 := r.SplitShare(xFP)

		sig0, sig1 := SecureSigmoidLocal(params, []uint64{x0}, []uint64{x1})

		result := r.ToDouble(r.Add(sig0[0], sig1[0]))
		expected := 1.0 / (1.0 + math.Exp(-x))

		err := math.Abs(result - expected)
		if err > maxErr {
			maxErr = err
		}

		status := "OK"
		if err > 0.01 {
			status = "FAIL"
			t.Errorf("sigmoid(%.1f) = %.6f, want %.6f (err %.2e)", x, result, expected, err)
		}
		t.Logf("sigmoid(%6.1f) = %.6f (exact %.6f, err %.2e) %s", x, result, expected, err, status)
	}
	t.Logf("Max error: %.2e (C++ tolerance: 0.01)", maxErr)
}

func TestSecureSigmoidBatchAccuracy(t *testing.T) {
	params := DefaultSigmoidParams()
	r := params.Ring

	// 100 random values in [-15, 15]
	n := 100
	xDoubles := make([]float64, n)
	x0 := make([]uint64, n)
	x1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		xDoubles[i] = float64(int(cryptoRandUint64K2()%3000)-1500) / 100.0
		xFP := r.FromDouble(xDoubles[i])
		x0[i], x1[i] = r.SplitShare(xFP)
	}

	sig0, sig1 := SecureSigmoidLocal(params, x0, x1)

	maxErr := 0.0
	for i := 0; i < n; i++ {
		result := r.ToDouble(r.Add(sig0[i], sig1[i]))
		expected := 1.0 / (1.0 + math.Exp(-xDoubles[i]))
		err := math.Abs(result - expected)
		if err > maxErr {
			maxErr = err
		}
	}
	t.Logf("Sigmoid batch n=%d: max error %.2e", n, maxErr)
	if maxErr > 0.01 {
		t.Errorf("Max error %.2e exceeds 0.01 (C++ tolerance)", maxErr)
	}
}

// TestSigmoidTrainingLoop tests a full logistic regression training loop
// using the piecewise sigmoid (instead of Chebyshev polynomial).
func TestSigmoidTrainingLoop(t *testing.T) {
	params := DefaultSigmoidParams()
	r := params.Ring

	// Same test data as k2-mpc-tool training test
	n := 100
	p := 4
	
	seed := uint64(42)
	next := func() float64 {
		seed = seed*6364136223846793005 + 1442695040888963407
		return float64(int64(seed>>33)-int64(1<<30)) / float64(1 << 30)
	}
	
	X := make([]float64, n*p)
	for i := range X { X[i] = next() * 1.5 }
	
	y := make([]float64, n)
	for i := 0; i < n; i++ {
		eta := 0.5 + X[i*p+0] - 0.5*X[i*p+1]
		prob := 1.0 / (1.0 + math.Exp(-eta))
		if next() < prob*2-1 { y[i] = 1 }
	}

	// Train with piecewise sigmoid
	beta := make([]float64, p+1) // intercept + features
	alpha := 0.5
	lambda := 1e-4

	for iter := 0; iter < 500; iter++ {
		grad := make([]float64, p+1)
		for i := 0; i < n; i++ {
			eta := beta[0]
			for j := 0; j < p; j++ { eta += X[i*p+j] * beta[j+1] }
			
			// Use piecewise sigmoid (secret-shared simulation)
			etaFP := r.FromDouble(eta)
			e0, e1 := r.SplitShare(etaFP)
			s0, s1 := SecureSigmoidLocal(params, []uint64{e0}, []uint64{e1})
			mu := r.ToDouble(r.Add(s0[0], s1[0]))
			
			res := mu - y[i]
			grad[0] += res / float64(n)
			for j := 0; j < p; j++ {
				grad[j+1] += X[i*p+j] * res / float64(n)
			}
		}
		for j := 1; j <= p; j++ { grad[j] += lambda * beta[j] }
		
		// Gradient clipping
		gnorm := 0.0
		for _, g := range grad { gnorm += g * g }
		gnorm = math.Sqrt(gnorm)
		scale := 1.0
		if gnorm > 5.0 { scale = 5.0 / gnorm }
		
		for j := range beta { beta[j] -= alpha * grad[j] * scale }
	}

	// Plaintext reference (exact sigmoid)
	betaRef := make([]float64, p+1)
	for iter := 0; iter < 500; iter++ {
		grad := make([]float64, p+1)
		for i := 0; i < n; i++ {
			eta := betaRef[0]
			for j := 0; j < p; j++ { eta += X[i*p+j] * betaRef[j+1] }
			mu := 1.0 / (1.0 + math.Exp(-eta))
			res := mu - y[i]
			grad[0] += res / float64(n)
			for j := 0; j < p; j++ { grad[j+1] += X[i*p+j] * res / float64(n) }
		}
		for j := 1; j <= p; j++ { grad[j] += lambda * betaRef[j] }
		gnorm := 0.0
		for _, g := range grad { gnorm += g * g }
		gnorm = math.Sqrt(gnorm)
		scale := 1.0
		if gnorm > 5.0 { scale = 5.0 / gnorm }
		for j := range betaRef { betaRef[j] -= alpha * grad[j] * scale }
	}

	t.Logf("Piecewise sigmoid: intercept=%.4f beta=%v", beta[0], beta[1:])
	t.Logf("Plaintext sigmoid: intercept=%.4f beta=%v", betaRef[0], betaRef[1:])

	maxErr := 0.0
	for j := range beta {
		err := math.Abs(beta[j] - betaRef[j])
		if err > maxErr { maxErr = err }
	}
	t.Logf("Max coefficient error: %.2e", maxErr)

	if maxErr > 0.01 {
		t.Errorf("Coefficient error %.2e exceeds 0.01", maxErr)
	}
}
