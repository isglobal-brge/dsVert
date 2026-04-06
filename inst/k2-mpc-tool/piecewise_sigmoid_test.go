package main

import (
	"math"
	"testing"
)

// TestPiecewiseSigmoidAccuracy validates the piecewise sigmoid matches R's plogis.
func TestPiecewiseSigmoidAccuracy(t *testing.T) {
	sp := DefaultPiecewiseSigmoidParams()

	testCases := []float64{-20, -14, -5, -2, -1, -0.5, 0, 0.5, 1, 2, 5, 14, 20}
	for _, x := range testCases {
		got := EvalPiecewiseSigmoid(x, sp)
		want := 1.0 / (1.0 + math.Exp(-x))
		err := math.Abs(got - want)
		t.Logf("x=%.1f: got=%.10f want=%.10f err=%.2e", x, got, want, err)
		if err > 1e-3 {
			t.Errorf("x=%.1f: error %.2e exceeds 1e-3", x, err)
		}
	}
}

// TestTrainPiecewiseSigmoidSmall runs training with piecewise sigmoid (local simulation).
func TestTrainPiecewiseSigmoidSmall(t *testing.T) {
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
	y := []float64{1, 0, 1, 0, 1, 0, 1, 0, 1, 0}

	result := trainWithPiecewiseSigmoid(rp, X, y, n, p, 0.5, 1e-4, 200)

	t.Logf("Converged=%v, iters=%d, maxDiff=%.2e", result.Converged, result.Iterations, result.MaxDiff)
	t.Logf("Intercept: %.6f", result.Intercept)
	t.Logf("Beta: %v", result.Beta)

	// Compare with plaintext GD using SAME piecewise sigmoid
	plainBeta := plaintextPiecewiseSigmoidGD(X, y, n, p, 1e-4, 0.5, 200)
	t.Logf("Plaintext piecewise beta: %v", plainBeta)

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
	t.Logf("Max coef error vs plaintext piecewise GD: %.2e", maxErr)

	if maxErr > 0.5 {
		t.Errorf("Coefficient error %.2e exceeds 0.5 (piecewise sigmoid not working)", maxErr)
	}
}

// TestTrainPiecewiseSigmoidRealistic uses 20 observations, 3 features.
func TestTrainPiecewiseSigmoidRealistic(t *testing.T) {
	rp := DefaultRingParams()

	n := 20
	p := 3
	// Standardized features
	X := []float64{
		0.5, -0.3, 0.8,
		-1.2, 0.8, -0.5,
		0.7, 0.4, 1.2,
		-0.4, -0.9, 0.1,
		1.1, 0.2, -0.7,
		-0.8, 1.3, 0.3,
		0.3, -0.5, -0.2,
		-0.1, 0.7, 0.9,
		0.9, -1.1, -0.4,
		-0.6, 0.1, 0.6,
		1.3, -0.2, -0.9,
		-0.9, 0.5, 0.4,
		0.2, 0.3, -1.1,
		0.8, -0.7, 0.7,
		-0.3, 1.0, -0.3,
		1.5, -0.4, 0.2,
		-1.1, 0.6, -0.6,
		0.4, -0.8, 1.0,
		-0.7, 0.9, 0.5,
		0.6, -1.0, -0.8,
	}
	y := []float64{1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0}

	result := trainWithPiecewiseSigmoid(rp, X, y, n, p, 0.5, 1e-4, 500)

	t.Logf("Converged=%v, iters=%d, maxDiff=%.2e", result.Converged, result.Iterations, result.MaxDiff)
	t.Logf("Intercept: %.6f", result.Intercept)
	t.Logf("Beta: %v", result.Beta)

	// Compare with R's exact glm (pre-computed)
	// Also compare with plaintext piecewise GD
	plainBeta := plaintextPiecewiseSigmoidGD(X, y, n, p, 1e-4, 0.5, 500)
	t.Logf("Plaintext piecewise beta: %v", plainBeta)

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
	t.Logf("Max coef error vs plaintext piecewise GD: %.2e", maxErr)

	// Key: this should be MUCH better than the Chebyshev version (which was ~2.0)
	if maxErr > 0.1 {
		t.Errorf("Coefficient error %.2e exceeds 0.1", maxErr)
	}
}

// trainWithPiecewiseSigmoid runs the training loop using piecewise sigmoid
// instead of Chebyshev polynomial. Same Beaver protocol for eta and gradient,
// but sigmoid uses the Google piecewise approximation.
func trainWithPiecewiseSigmoid(rp RingParams, X, y []float64, n, p int,
	alpha, lambda float64, maxIter int) TrainResult {

	// Convert data to fixed-point and split into shares
	xFP := rp.VecFromDoubles(X)
	yFP := rp.VecFromDoubles(y)
	x0, x1 := rp.SplitVecShare(xFP)
	y0, y1 := rp.SplitVecShare(yFP)

	// Initialize beta (all zeros)
	betaDoubles := make([]float64, p+1)
	betaFP := rp.VecFromDoubles(betaDoubles)
	beta0, beta1 := rp.SplitVecShare(betaFP)

	var result TrainResult

	for iter := 1; iter <= maxIter; iter++ {
		betaOld := make([]float64, p+1)
		copy(betaOld, betaDoubles)

		// Step 1: Compute [eta] = [X_aug] * [beta] via Beaver
		eta0 := make([]uint64, n)
		eta1 := make([]uint64, n)
		for i := 0; i < n; i++ {
			eta0[i] = beta0[0]
			eta1[i] = beta1[0]
			for j := 0; j < p; j++ {
				idx := i*p + j
				t0, t1 := GenerateBeaverTriples(rp, 1)
				prod0, prod1 := BeaverFixedPointMul(rp,
					[]uint64{x0[idx]}, []uint64{beta0[j+1]},
					[]uint64{x1[idx]}, []uint64{beta1[j+1]},
					t0, t1)
				eta0[i] = rp.ModAdd(eta0[i], prod0[0])
				eta1[i] = rp.ModAdd(eta1[i], prod1[0])
			}
		}

		// Step 2: Compute [mu] = PiecewiseSigmoid([eta])
		// LOCAL SIMULATION — reconstructs eta, evaluates sigmoid, re-shares.
		// Will be replaced by DCF+Beaver distributed protocol in Step 2.
		mu0, mu1 := SecurePiecewiseSigmoidLocal(rp, eta0, eta1)

		// Step 3: [r] = [mu] - [y]
		r0 := rp.VecSub(mu0, y0)
		r1 := rp.VecSub(mu1, y1)

		// Step 4: Gradient computation
		var sumR0, sumR1 uint64
		for i := 0; i < n; i++ {
			sumR0 = rp.ModAdd(sumR0, r0[i])
			sumR1 = rp.ModAdd(sumR1, r1[i])
		}
		sumR := rp.ToDouble(rp.ModAdd(sumR0, sumR1))
		gIntercept := sumR / float64(n)

		grad := make([]float64, p)
		for j := 0; j < p; j++ {
			xCol0 := make([]uint64, n)
			xCol1 := make([]uint64, n)
			for i := 0; i < n; i++ {
				xCol0[i] = x0[i*p+j]
				xCol1[i] = x1[i*p+j]
			}
			t0, t1 := GenerateBeaverTriples(rp, n)
			prod0, prod1 := BeaverFixedPointMul(rp, xCol0, r0, xCol1, r1, t0, t1)

			var s0, s1 uint64
			for i := 0; i < n; i++ {
				s0 = rp.ModAdd(s0, prod0[i])
				s1 = rp.ModAdd(s1, prod1[i])
			}
			gradJ := rp.ToDouble(rp.ModAdd(s0, s1))
			grad[j] = gradJ/float64(n) + lambda*betaDoubles[j+1]
		}

		// Step 5: Update with gradient clipping
		gradNorm := gIntercept * gIntercept
		for j := 0; j < p; j++ {
			gradNorm += grad[j] * grad[j]
		}
		gradNorm = math.Sqrt(gradNorm)
		scale := 1.0
		if gradNorm > 5.0 {
			scale = 5.0 / gradNorm
		}

		betaDoubles[0] -= alpha * gIntercept * scale
		for j := 0; j < p; j++ {
			betaDoubles[j+1] -= alpha * grad[j] * scale
		}

		betaFP = rp.VecFromDoubles(betaDoubles)
		beta0, beta1 = rp.SplitVecShare(betaFP)

		// Step 6: Convergence
		maxDiff := 0.0
		for j := 0; j <= p; j++ {
			d := math.Abs(betaDoubles[j] - betaOld[j])
			if d > maxDiff {
				maxDiff = d
			}
		}
		result.MaxDiff = maxDiff
		result.Iterations = iter
		if maxDiff < 1e-4 {
			result.Converged = true
			break
		}
	}

	result.Beta = betaDoubles[1:]
	result.Intercept = betaDoubles[0]
	return result
}

// plaintextPiecewiseSigmoidGD runs gradient descent using the SAME piecewise sigmoid
// but in plaintext (no secret sharing). This is the reference for accuracy.
func plaintextPiecewiseSigmoidGD(X, y []float64, n, p int,
	lambda, alpha float64, maxIter int) []float64 {

	sp := DefaultPiecewiseSigmoidParams()
	beta := make([]float64, p+1)

	for iter := 0; iter < maxIter; iter++ {
		grad := make([]float64, p+1)

		for i := 0; i < n; i++ {
			eta := beta[0]
			for j := 0; j < p; j++ {
				eta += X[i*p+j] * beta[j+1]
			}
			mu := EvalPiecewiseSigmoid(eta, sp)
			mu = math.Max(1e-10, math.Min(1-1e-10, mu))
			r := mu - y[i]

			grad[0] += r
			for j := 0; j < p; j++ {
				grad[j+1] += X[i*p+j] * r
			}
		}

		gradNorm := 0.0
		for j := 0; j <= p; j++ {
			g := grad[j]/float64(n) + lambda*beta[j]
			grad[j] = g
			gradNorm += g * g
		}
		gradNorm = math.Sqrt(gradNorm)
		scale := 1.0
		if gradNorm > 5.0 {
			scale = 5.0 / gradNorm
		}

		for j := 0; j <= p; j++ {
			beta[j] -= alpha * grad[j] * scale
		}
	}
	return beta
}
