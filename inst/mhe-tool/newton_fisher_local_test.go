package main

import (
	"math"
	"testing"
)

// TestNewtonDiagonalFisherLocal: REAL diagonal Fisher Newton-IRLS
// with intercept as beta[0], matching the Opal protocol exactly.
func TestNewtonDiagonalFisherLocal(t *testing.T) {
	ring := NewRing63(20)
	n := 155; p := 6

	X := pimaX()
	y := pimaY()

	xFP := make([]uint64, n*p)
	yFP := make([]uint64, n)
	for i, v := range X { xFP[i] = ring.FromDouble(v) }
	for i, v := range y { yFP[i] = ring.FromDouble(v) }
	x0 := make([]uint64, n*p); x1 := make([]uint64, n*p)
	y0 := make([]uint64, n); y1 := make([]uint64, n)
	for i := range xFP { x0[i], x1[i] = ring.SplitShare(xFP[i]) }
	for i := range yFP { y0[i], y1[i] = ring.SplitShare(yFP[i]) }

	beta := make([]float64, p+1) // beta[0] = intercept
	lambda := 1e-4
	damping := 0.5

	// Pre-compute x² for Fisher
	xSq0 := make([]uint64, n*p); xSq1 := make([]uint64, n*p)
	for j := 0; j < p; j++ {
		xj0 := make([]uint64, n); xj1 := make([]uint64, n)
		for i := 0; i < n; i++ { xj0[i] = x0[i*p+j]; xj1[i] = x1[i*p+j] }
		sq0, sq1 := HadamardProductLocal(xj0, xj0, xj1, xj1, ring.FracBits, ring)
		for i := 0; i < n; i++ { xSq0[i*p+j] = sq0[i]; xSq1[i*p+j] = sq1[i] }
	}
	t.Log("x² pre-computed")

	for iter := 1; iter <= 30; iter++ {
		betaFP := make([]uint64, p+1)
		for j := range beta { betaFP[j] = ring.FromDouble(beta[j]) }

		// Eta = intercept + X*beta[1:]
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

		// Sigmoid via wide spline (50 intervals)
		mu0, mu1 := WideSplineSigmoid(ring, eta0, eta1, 50)

		// Residual r = mu - y
		r0 := make([]uint64, n); r1 := make([]uint64, n)
		for i := range r0 { r0[i] = ring.Sub(mu0[i], y0[i]); r1[i] = ring.Sub(mu1[i], y1[i]) }

		// w = mu*(1-mu) via Hadamard
		oneMinusMu0 := make([]uint64, n); oneMinusMu1 := make([]uint64, n)
		oneFP := ring.FromDouble(1.0)
		for i := 0; i < n; i++ {
			oneMinusMu0[i] = ring.Sub(oneFP, mu0[i])
			oneMinusMu1[i] = ring.Sub(0, mu1[i])
		}
		w0, w1 := HadamardProductLocal(mu0, oneMinusMu0, mu1, oneMinusMu1, ring.FracBits, ring)

		// Diagonal Fisher: d_j = sum(w * x²_j) / n + lambda
		diagFisher := make([]float64, p+1)
		// d_0 (intercept) = sum(w) / n + lambda
		var sumW0, sumW1 uint64
		for i := 0; i < n; i++ {
			sumW0 = ring.Add(sumW0, w0[i])
			sumW1 = ring.Add(sumW1, w1[i])
		}
		diagFisher[0] = ring.ToDouble(ring.Add(sumW0, sumW1)) / float64(n) + lambda

		// d_j for features: sum(w * x²_j) / n + lambda
		for j := 0; j < p; j++ {
			wXSqJ0 := make([]uint64, n); wXSqJ1 := make([]uint64, n)
			xsqJ0 := make([]uint64, n); xsqJ1 := make([]uint64, n)
			for i := 0; i < n; i++ {
				xsqJ0[i] = xSq0[i*p+j]; xsqJ1[i] = xSq1[i*p+j]
			}
			wxsq0, wxsq1 := HadamardProductLocal(w0, xsqJ0, w1, xsqJ1, ring.FracBits, ring)
			_ = wXSqJ0; _ = wXSqJ1
			var s0, s1 uint64
			for i := 0; i < n; i++ {
				s0 = ring.Add(s0, wxsq0[i])
				s1 = ring.Add(s1, wxsq1[i])
			}
			diagFisher[j+1] = ring.ToDouble(ring.Add(s0, s1)) / float64(n) + lambda
		}

		// Gradient: g_0 = sum(r)/n, g_j = sum(x_j * r)/n
		var sR0, sR1 uint64
		for i := 0; i < n; i++ { sR0 = ring.Add(sR0, r0[i]); sR1 = ring.Add(sR1, r1[i]) }
		grad := make([]float64, p+1)
		grad[0] = ring.ToDouble(ring.Add(sR0, sR1))/float64(n) + lambda*beta[0]

		for j := 0; j < p; j++ {
			xc0 := make([]uint64, n); xc1 := make([]uint64, n)
			for i := 0; i < n; i++ { xc0[i] = x0[i*p+j]; xc1[i] = x1[i*p+j] }
			pr0, pr1 := HadamardProductLocal(xc0, r0, xc1, r1, ring.FracBits, ring)
			var s0, s1 uint64
			for i := 0; i < n; i++ { s0 = ring.Add(s0, pr0[i]); s1 = ring.Add(s1, pr1[i]) }
			grad[j+1] = ring.ToDouble(ring.Add(s0, s1))/float64(n) + lambda*beta[j+1]
		}

		// Newton step: beta -= damping * grad / diag_fisher
		gradNorm := 0.0
		for j := range beta {
			step := damping * grad[j] / diagFisher[j]
			beta[j] -= step
			gradNorm += grad[j] * grad[j]
		}
		gradNorm = math.Sqrt(gradNorm)

		if iter <= 5 || iter%10 == 0 {
			t.Logf("Iter %2d: ||grad||=%.6f beta=[%.4f, %.4f, %.4f, %.4f, %.4f, %.4f, %.4f]",
				iter, gradNorm, beta[0], beta[1], beta[2], beta[3], beta[4], beta[5], beta[6])
			t.Logf("         Fisher=[%.4f, %.4f, %.4f, %.4f, %.4f, %.4f, %.4f]",
				diagFisher[0], diagFisher[1], diagFisher[2], diagFisher[3], diagFisher[4], diagFisher[5], diagFisher[6])
		}
	}

	ref := []float64{-1.270980, 0.774007, 0.468717, 0.593735, 0.943420, -0.112165, -0.066820}
	maxErr := 0.0
	for j := range beta {
		err := math.Abs(beta[j] - ref[j])
		if err > maxErr { maxErr = err }
	}
	t.Logf("\nFinal: [%.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f]",
		beta[0], beta[1], beta[2], beta[3], beta[4], beta[5], beta[6])
	t.Logf("Ref:   [%.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f]",
		ref[0], ref[1], ref[2], ref[3], ref[4], ref[5], ref[6])
	t.Logf("Max coef error: %.2e", maxErr)
}
