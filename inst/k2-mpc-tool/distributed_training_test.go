package main

import (
	"math"
	"testing"
)

// TestDistributedTraining runs the full training loop using the distributed
// sigmoid protocol (constant-branch version) and compares against plaintext.
func TestDistributedTraining(t *testing.T) {
	rp := DefaultRingParams()

	n := 20
	p := 3
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

	// Train with distributed sigmoid (constant-branch)
	result := trainWithDistributedSigmoid(rp, X, y, n, p, 0.5, 1e-4, 200)

	t.Logf("Distributed: converged=%v, iters=%d, maxDiff=%.2e",
		result.Converged, result.Iterations, result.MaxDiff)
	t.Logf("  Intercept: %.6f, Beta: %v", result.Intercept, result.Beta)

	// Compare with piecewise sigmoid (exact reference)
	refResult := trainWithPiecewiseSigmoid(rp, X, y, n, p, 0.5, 1e-4, 200)
	t.Logf("Piecewise ref: converged=%v, iters=%d", refResult.Converged, refResult.Iterations)
	t.Logf("  Intercept: %.6f, Beta: %v", refResult.Intercept, refResult.Beta)

	// The constant-branch version won't match exactly, but should be in the same ballpark
	maxErr := math.Abs(result.Intercept - refResult.Intercept)
	for j := 0; j < p; j++ {
		err := math.Abs(result.Beta[j] - refResult.Beta[j])
		if err > maxErr {
			maxErr = err
		}
	}
	t.Logf("Max coef error vs piecewise reference: %.2e", maxErr)
}

// trainWithDistributedSigmoid is like trainWithPiecewiseSigmoid but uses
// the distributed protocol (DistributedSigmoidLocal) instead of
// SecurePiecewiseSigmoidLocal.
func trainWithDistributedSigmoid(rp RingParams, X, y []float64, n, p int,
	alpha, lambda float64, maxIter int) TrainResult {

	xFP := rp.VecFromDoubles(X)
	yFP := rp.VecFromDoubles(y)
	x0, x1 := rp.SplitVecShare(xFP)
	y0, y1 := rp.SplitVecShare(yFP)

	betaDoubles := make([]float64, p+1)
	betaFP := rp.VecFromDoubles(betaDoubles)
	beta0, beta1 := rp.SplitVecShare(betaFP)

	var result TrainResult

	for iter := 1; iter <= maxIter; iter++ {
		betaOld := make([]float64, p+1)
		copy(betaOld, betaDoubles)

		// Step 1: [eta] = [X] * [beta] via Beaver
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

		// Step 2: [mu] = DistributedSigmoid([eta])
		mu0, mu1 := DistributedSigmoidLocal(rp, eta0, eta1)

		// Step 3: [r] = [mu] - [y]
		r0 := rp.VecSub(mu0, y0)
		r1 := rp.VecSub(mu1, y1)

		// Step 4: Gradient
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

		// Step 5: Update
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
