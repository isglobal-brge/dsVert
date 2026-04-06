package main

import (
	"math"
	"testing"
)

// TestFirstIterationComparison checks if distributed and piecewise sigmoid
// produce the same gradient at iteration 1 (beta=0, eta=0).
func TestFirstIterationComparison(t *testing.T) {
	rp := DefaultRingParams()

	n := 10
	p := 2
	X := []float64{
		0.5, -0.3, -1.2, 0.8, 0.7, 0.4, -0.4, -0.9, 1.1, 0.2,
		-0.8, 1.3, 0.3, -0.5, -0.1, 0.7, 0.9, -1.1, -0.6, 0.1,
	}
	y := []float64{1, 0, 1, 0, 1, 0, 1, 0, 1, 0}

	xFP := rp.VecFromDoubles(X)
	yFP := rp.VecFromDoubles(y)
	x0, x1 := rp.SplitVecShare(xFP)
	y0, y1 := rp.SplitVecShare(yFP)

	// At iter 1, beta=0, so eta=0 for all elements
	eta0 := make([]uint64, n)
	eta1 := make([]uint64, n)
	// beta=0 means eta shares are just shares of 0 (intercept is 0 too)

	// Distributed sigmoid
	dmu0, dmu1 := DistributedSigmoidLocal(rp, eta0, eta1)

	// Piecewise sigmoid (reference)
	pmu0, pmu1 := SecurePiecewiseSigmoidLocal(rp, eta0, eta1)

	maxSigErr := 0.0
	for i := 0; i < n; i++ {
		dval := rp.ToDouble(rp.ModAdd(dmu0[i], dmu1[i]))
		pval := rp.ToDouble(rp.ModAdd(pmu0[i], pmu1[i]))
		err := math.Abs(dval - pval)
		if err > maxSigErr {
			maxSigErr = err
		}
		if i < 3 {
			t.Logf("  mu[%d]: dist=%.8f piecewise=%.8f err=%.2e", i, dval, pval, err)
		}
	}
	t.Logf("Max sigmoid difference at iter 1: %.2e", maxSigErr)

	// Compute gradient for both
	dr0 := rp.VecSub(dmu0, y0)
	dr1 := rp.VecSub(dmu1, y1)
	pr0 := rp.VecSub(pmu0, y0)
	pr1 := rp.VecSub(pmu1, y1)

	// Gradient = X^T * r (just sum, not Beaver, for diagnosis)
	for j := 0; j < p; j++ {
		var dgrad, pgrad float64
		for i := 0; i < n; i++ {
			xval := X[i*p+j]
			dr := rp.ToDouble(rp.ModAdd(dr0[i], dr1[i]))
			pr := rp.ToDouble(rp.ModAdd(pr0[i], pr1[i]))
			dgrad += xval * dr
			pgrad += xval * pr
		}
		t.Logf("Gradient[%d]: dist=%.6f piecewise=%.6f err=%.2e", j, dgrad, pgrad, math.Abs(dgrad-pgrad))
	}

	_ = x0; _ = x1 // used for eta computation in later iters
}
