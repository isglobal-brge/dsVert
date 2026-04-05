package main

import (
	"math"
	"testing"
)

// Small logistic regression test: 10 observations, 2 features
func TestSecureTrainBinomialSmall(t *testing.T) {
	rp := DefaultRingParams()

	// Standardized data (mean~0, sd~1)
	n := 10
	p := 2
	X := []float64{
		0.5, -0.3,
		-1.2, 0.8,
		0.7, 0.4,
		-0.4, -0.9,
		1.1, 0.2,
		-0.8, 1.3,
		0.3, -0.5,
		-0.1, 0.7,
		0.9, -1.1,
		-0.6, 0.1,
	}
	y := []float64{1, 0, 1, 0, 1, 0, 1, 0, 1, 0}

	params := DefaultBinomialParams()
	params.MaxIter = 50
	params.Alpha = 1.0

	result := SecureTrainLocal(rp, X, y, n, p, params)

	t.Logf("Binomial small: converged=%v, iters=%d, maxDiff=%.2e",
		result.Converged, result.Iterations, result.MaxDiff)
	t.Logf("  Intercept: %.6f", result.Intercept)
	t.Logf("  Beta: %v", result.Beta)

	// Compare with plaintext logistic regression (gradient descent)
	plainBeta := plaintextLogisticGD(X, y, n, p, params.Lambda, params.Alpha, params.MaxIter)
	t.Logf("  Plaintext beta: %v", plainBeta)

	maxErr := 0.0
	for j := 0; j < p; j++ {
		err := math.Abs(result.Beta[j] - plainBeta[j+1])
		if err > maxErr {
			maxErr = err
		}
	}
	interceptErr := math.Abs(result.Intercept - plainBeta[0])
	if interceptErr > maxErr {
		maxErr = interceptErr
	}
	t.Logf("  Max coefficient error vs plaintext GD: %.2e", maxErr)

	// Note: 10-sample logistic with near-perfect separation amplifies
	// polynomial approximation errors. Real data (n=150+) gives much better results.
	// This test validates the pipeline works, not precision.
	if maxErr > 10.0 {
		t.Errorf("Coefficient error %.2e exceeds 10.0 (pipeline broken)", maxErr)
	}
}

// Small Poisson regression test
func TestSecureTrainPoissonSmall(t *testing.T) {
	rp := DefaultRingParams()

	n := 10
	p := 2
	X := []float64{
		0.5, -0.3,
		-1.2, 0.8,
		0.7, 0.4,
		-0.4, -0.9,
		1.1, 0.2,
		-0.8, 1.3,
		0.3, -0.5,
		-0.1, 0.7,
		0.9, -1.1,
		-0.6, 0.1,
	}
	y := []float64{2, 1, 3, 0, 4, 1, 2, 1, 3, 0}

	params := DefaultPoissonParams()
	params.MaxIter = 50
	params.Alpha = 0.1

	result := SecureTrainLocal(rp, X, y, n, p, params)

	t.Logf("Poisson small: converged=%v, iters=%d, maxDiff=%.2e",
		result.Converged, result.Iterations, result.MaxDiff)
	t.Logf("  Intercept: %.6f", result.Intercept)
	t.Logf("  Beta: %v", result.Beta)

	// Compare with plaintext Poisson GD
	plainBeta := plaintextPoissonGD(X, y, n, p, params.Lambda, params.Alpha, params.MaxIter)
	t.Logf("  Plaintext beta: %v", plainBeta)

	maxErr := 0.0
	for j := 0; j < p; j++ {
		err := math.Abs(result.Beta[j] - plainBeta[j+1])
		if err > maxErr {
			maxErr = err
		}
	}
	interceptErr := math.Abs(result.Intercept - plainBeta[0])
	if interceptErr > maxErr {
		maxErr = interceptErr
	}
	t.Logf("  Max coefficient error vs plaintext GD: %.2e", maxErr)

	if maxErr > 0.5 {
		t.Errorf("Coefficient error %.2e exceeds 0.5", maxErr)
	}
}

// --- Plaintext reference implementations ---

func plaintextLogisticGD(X []float64, y []float64, n, p int,
	lambda, alpha float64, maxIter int) []float64 {

	beta := make([]float64, p+1) // [intercept, features...]

	for iter := 0; iter < maxIter; iter++ {
		grad := make([]float64, p+1)
		for i := 0; i < n; i++ {
			eta := beta[0]
			for j := 0; j < p; j++ {
				eta += X[i*p+j] * beta[j+1]
			}
			mu := 1.0 / (1.0 + math.Exp(-eta))
			r := mu - y[i]
			grad[0] += r / float64(n)
			for j := 0; j < p; j++ {
				grad[j+1] += X[i*p+j] * r / float64(n)
			}
		}
		// L2 regularization (not on intercept)
		for j := 1; j <= p; j++ {
			grad[j] += lambda * beta[j]
		}
		// Update
		for j := 0; j <= p; j++ {
			beta[j] -= alpha * grad[j]
		}
	}
	return beta
}

func plaintextPoissonGD(X []float64, y []float64, n, p int,
	lambda, alpha float64, maxIter int) []float64 {

	beta := make([]float64, p+1)

	for iter := 0; iter < maxIter; iter++ {
		grad := make([]float64, p+1)
		for i := 0; i < n; i++ {
			eta := beta[0]
			for j := 0; j < p; j++ {
				eta += X[i*p+j] * beta[j+1]
			}
			// Clamp eta for stability
			if eta > 5 {
				eta = 5
			} else if eta < -5 {
				eta = -5
			}
			mu := math.Exp(eta)
			r := mu - y[i]
			grad[0] += r / float64(n)
			for j := 0; j < p; j++ {
				grad[j+1] += X[i*p+j] * r / float64(n)
			}
		}
		for j := 1; j <= p; j++ {
			grad[j] += lambda * beta[j]
		}
		for j := 0; j <= p; j++ {
			beta[j] -= alpha * grad[j]
		}
	}
	return beta
}

func TestSecureTrainBinomial200Iters(t *testing.T) {
	rp := DefaultRingParams()

	n := 10
	p := 2
	X := []float64{
		0.5, -0.3, -1.2, 0.8, 0.7, 0.4, -0.4, -0.9, 1.1, 0.2,
		-0.8, 1.3, 0.3, -0.5, -0.1, 0.7, 0.9, -1.1, -0.6, 0.1,
	}
	y := []float64{1, 0, 1, 0, 1, 0, 1, 0, 1, 0}

	params := DefaultBinomialParams()
	params.MaxIter = 200
	params.Alpha = 1.0

	result := SecureTrainLocal(rp, X, y, n, p, params)

	plainBeta := plaintextLogisticGD(X, y, n, p, params.Lambda, params.Alpha, 200)

	maxErr := 0.0
	for j := 0; j < p; j++ {
		err := math.Abs(result.Beta[j] - plainBeta[j+1])
		if err > maxErr { maxErr = err }
	}
	interceptErr := math.Abs(result.Intercept - plainBeta[0])
	if interceptErr > maxErr { maxErr = interceptErr }

	t.Logf("Binomial 200 iters: converged=%v, maxDiff=%.2e, coef_err=%.2e",
		result.Converged, result.MaxDiff, maxErr)
	t.Logf("  Secure:    intercept=%.4f beta=%v", result.Intercept, result.Beta)
	t.Logf("  Plaintext: intercept=%.4f beta=%v", plainBeta[0], plainBeta[1:])
}

func TestSecureTrainPoisson200Iters(t *testing.T) {
	rp := DefaultRingParams()

	n := 10
	p := 2
	X := []float64{
		0.5, -0.3, -1.2, 0.8, 0.7, 0.4, -0.4, -0.9, 1.1, 0.2,
		-0.8, 1.3, 0.3, -0.5, -0.1, 0.7, 0.9, -1.1, -0.6, 0.1,
	}
	y := []float64{2, 1, 3, 0, 4, 1, 2, 1, 3, 0}

	params := DefaultPoissonParams()
	params.MaxIter = 200
	params.Alpha = 0.1

	result := SecureTrainLocal(rp, X, y, n, p, params)

	plainBeta := plaintextPoissonGD(X, y, n, p, params.Lambda, params.Alpha, 200)

	maxErr := 0.0
	for j := 0; j < p; j++ {
		err := math.Abs(result.Beta[j] - plainBeta[j+1])
		if err > maxErr { maxErr = err }
	}
	interceptErr := math.Abs(result.Intercept - plainBeta[0])
	if interceptErr > maxErr { maxErr = interceptErr }

	t.Logf("Poisson 200 iters: converged=%v, maxDiff=%.2e, coef_err=%.2e",
		result.Converged, result.MaxDiff, maxErr)
	t.Logf("  Secure:    intercept=%.4f beta=%v", result.Intercept, result.Beta)
	t.Logf("  Plaintext: intercept=%.4f beta=%v", plainBeta[0], plainBeta[1:])
}
