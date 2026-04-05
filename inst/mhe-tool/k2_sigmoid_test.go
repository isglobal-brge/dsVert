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

// TestPoissonTrainingLoop tests Poisson regression with secure exp (Kelkar).
func TestPoissonTrainingLoop(t *testing.T) {
	r := NewRing63(20)
	cfg := DefaultExpConfig()

	n := 100
	p := 4
	
	seed := uint64(42)
	next := func() float64 {
		seed = seed*6364136223846793005 + 1442695040888963407
		return float64(int64(seed>>33)-int64(1<<30)) / float64(1 << 30)
	}
	
	X := make([]float64, n*p)
	for i := range X { X[i] = next() * 1.0 }
	
	y := make([]float64, n)
	for i := 0; i < n; i++ {
		eta := 0.3 + 0.5*X[i*p+0] - 0.3*X[i*p+1]
		mu := math.Exp(eta)
		y[i] = math.Round(mu + next()*0.5)
		if y[i] < 0 { y[i] = 0 }
	}

	// Train with Kelkar secure exp
	beta := make([]float64, p+1)
	alpha := 0.1
	lambda := 1e-4

	for iter := 0; iter < 500; iter++ {
		grad := make([]float64, p+1)
		for i := 0; i < n; i++ {
			eta := beta[0]
			for j := 0; j < p; j++ { eta += X[i*p+j] * beta[j+1] }
			
			// Clamp eta for exp safety
			if eta > 5 { eta = 5 }
			if eta < -5 { eta = -5 }
			
			// Use Kelkar secure exp (secret-shared simulation)
			etaFP := r.FromDouble(eta)
			e0, e1 := r.SplitShare(etaFP)
			exp0, exp1 := SecureExpKelkar(cfg, []uint64{e0}, []uint64{e1})
			mu := r.ToDouble(r.Add(exp0[0], exp1[0]))
			if mu < 1e-10 { mu = 1e-10 }
			
			res := mu - y[i]
			grad[0] += res / float64(n)
			for j := 0; j < p; j++ {
				grad[j+1] += X[i*p+j] * res / float64(n)
			}
		}
		for j := 1; j <= p; j++ { grad[j] += lambda * beta[j] }
		
		gnorm := 0.0
		for _, g := range grad { gnorm += g * g }
		gnorm = math.Sqrt(gnorm)
		scale := 1.0
		if gnorm > 5.0 { scale = 5.0 / gnorm }
		for j := range beta { beta[j] -= alpha * grad[j] * scale }
	}

	// Plaintext reference
	betaRef := make([]float64, p+1)
	for iter := 0; iter < 500; iter++ {
		grad := make([]float64, p+1)
		for i := 0; i < n; i++ {
			eta := betaRef[0]
			for j := 0; j < p; j++ { eta += X[i*p+j] * betaRef[j+1] }
			if eta > 5 { eta = 5 }
			if eta < -5 { eta = -5 }
			mu := math.Exp(eta)
			if mu < 1e-10 { mu = 1e-10 }
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

	t.Logf("Kelkar secure exp: intercept=%.4f beta=%v", beta[0], beta[1:])
	t.Logf("Plaintext exp:     intercept=%.4f beta=%v", betaRef[0], betaRef[1:])

	maxErr := 0.0
	for j := range beta {
		err := math.Abs(beta[j] - betaRef[j])
		if err > maxErr { maxErr = err }
	}
	t.Logf("Max coefficient error: %.2e", maxErr)

	if maxErr > 0.01 {
		t.Errorf("Poisson coefficient error %.2e exceeds 0.01", maxErr)
	}
}

// TestLogisticGoogleCppReference replicates the EXACT test from the C++ code:
// logistic_regression/gradient_descent_test.cc, OneIterationNoRegularization
func TestLogisticGoogleCppReference(t *testing.T) {
	params := DefaultSigmoidParams()
	r := params.Ring

	// C++ test data: 20 examples, 5 features (binary 0/1)
	XRaw := []float64{
		1,0,0,0,1, 1,0,0,0,1, 1,0,0,0,0, 1,0,0,1,1,
		1,0,0,1,0, 1,0,1,0,1, 1,0,1,0,1, 1,0,1,0,0,
		1,0,1,1,1, 1,0,1,1,0, 1,1,0,0,1, 1,1,0,0,1,
		1,1,0,0,0, 1,1,0,1,1, 1,1,0,1,0, 1,1,1,0,1,
		1,1,1,0,1, 1,1,1,0,0, 1,1,1,1,1, 1,1,1,1,0,
	}
	yRaw := []float64{1,1,0,0,0,1,1,0,0,0,1,1,0,0,0,1,1,0,0,0}

	n := 20
	p := 5

	// C++ params: alpha = 18 (as double), 1 iteration, no regularization
	alphaGD := 18.0 / float64(n) // 0.9

	// Train 1 iteration with piecewise sigmoid
	beta := make([]float64, p)
	grad := make([]float64, p)
	for i := 0; i < n; i++ {
		etaVal := 0.0
		for j := 0; j < p; j++ { etaVal += XRaw[i*p+j] * beta[j] }

		// Piecewise sigmoid (secret-shared simulation)
		etaFP := r.FromDouble(etaVal)
		e0, e1 := r.SplitShare(etaFP)
		s0, s1 := SecureSigmoidLocal(params, []uint64{e0}, []uint64{e1})
		mu := r.ToDouble(r.Add(s0[0], s1[0]))

		d := mu - yRaw[i]
		for j := 0; j < p; j++ {
			grad[j] += XRaw[i*p+j] * d
		}
	}
	// Update: theta = theta - (alpha/n) * grad
	for j := 0; j < p; j++ {
		beta[j] -= alphaGD * grad[j]
	}

	// C++ expected after 1 iteration with theta=0, alpha=18:
	// theta = {-1.8, -0.9, -0.9, -3.6, 1.8}
	expected := []float64{-1.8, -0.9, -0.9, -3.6, 1.8}

	t.Logf("Our theta:      %v", beta)
	t.Logf("C++ expected:   %v", expected)

	maxErr := 0.0
	for j := 0; j < p; j++ {
		err := math.Abs(beta[j] - expected[j])
		if err > maxErr { maxErr = err }
	}
	t.Logf("Max error vs C++ expected: %.4e (C++ tolerance: 0.02)", maxErr)

	if maxErr > 0.02 {
		t.Errorf("Error %.4e exceeds C++ tolerance 0.02", maxErr)
	}
}

// TestLogistic5IterGoogleReference replicates the C++ 5-iteration test.
func TestLogistic5IterGoogleReference(t *testing.T) {
	params := DefaultSigmoidParams()
	r := params.Ring

	XRaw := []float64{
		1,0,0,0,1, 1,0,0,0,1, 1,0,0,0,0, 1,0,0,1,1,
		1,0,0,1,0, 1,0,1,0,1, 1,0,1,0,1, 1,0,1,0,0,
		1,0,1,1,1, 1,0,1,1,0, 1,1,0,0,1, 1,1,0,0,1,
		1,1,0,0,0, 1,1,0,1,1, 1,1,0,1,0, 1,1,1,0,1,
		1,1,1,0,1, 1,1,1,0,0, 1,1,1,1,1, 1,1,1,1,0,
	}
	yRaw := []float64{1,1,0,0,0,1,1,0,0,0,1,1,0,0,0,1,1,0,0,0}

	n := 20
	p := 5
	alphaScalar := 18.0
	lambda := 0.1

	beta := make([]float64, p)

	for iter := 0; iter < 5; iter++ {
		grad := make([]float64, p)
		for i := 0; i < n; i++ {
			etaVal := 0.0
			for j := 0; j < p; j++ { etaVal += XRaw[i*p+j] * beta[j] }

			etaFP := r.FromDouble(etaVal)
			e0, e1 := r.SplitShare(etaFP)
			s0, s1 := SecureSigmoidLocal(params, []uint64{e0}, []uint64{e1})
			mu := r.ToDouble(r.Add(s0[0], s1[0]))

			d := mu - yRaw[i]
			for j := 0; j < p; j++ {
				grad[j] += XRaw[i*p+j] * d
			}
		}
		// Update: theta = theta - (alpha/n)*grad - (alpha*lambda/n)*theta
		for j := 0; j < p; j++ {
			beta[j] -= (alphaScalar/float64(n))*grad[j] + (alphaScalar*lambda/float64(n))*beta[j]
		}
	}

	// C++ expected after 5 iterations:
	expected := []float64{-5.209011173974926, -2.6407028538582202, -2.64070285385822, -10.915857622419917, 5.392025544439257}

	t.Logf("Our theta (5 iters):  %v", beta)
	t.Logf("C++ expected:         %v", expected)

	maxErr := 0.0
	for j := 0; j < p; j++ {
		err := math.Abs(beta[j] - expected[j])
		if err > maxErr { maxErr = err }
	}
	t.Logf("Max error vs C++: %.4e (C++ tolerance: 0.5)", maxErr)

	if maxErr > 0.5 {
		t.Errorf("Error %.4e exceeds C++ tolerance 0.5", maxErr)
	}
}
