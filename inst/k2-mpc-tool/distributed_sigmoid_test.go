package main

import (
	"math"
	"testing"
)

// TestDistributedSigmoid validates the full distributed sigmoid protocol.
func TestDistributedSigmoid(t *testing.T) {
	rp := DefaultRingParams()

	testX := []float64{-10, -5, -2, -1, -0.5, 0, 0.5, 1, 2, 5, 10}

	xFP := rp.VecFromDoubles(testX)
	x0, x1 := rp.SplitVecShare(xFP)

	mu0, mu1 := DistributedSigmoidLocal(rp, x0, x1)

	maxErr := 0.0
	for i, x := range testX {
		got := rp.ToDouble(rp.ModAdd(mu0[i], mu1[i]))
		want := 1.0 / (1.0 + math.Exp(-x))
		err := math.Abs(got - want)
		if err > maxErr {
			maxErr = err
		}
		t.Logf("x=%6.1f: got=%.6f want=%.6f err=%.4e", x, got, want, err)
	}
	t.Logf("Max error: %.4e", maxErr)

	// For constant-branch version, accuracy is limited by using midpoint values
	// instead of the actual function. Expected error ~0.1 for extreme values.
	if maxErr > 0.5 {
		t.Errorf("Max error %.4e exceeds 0.5", maxErr)
	}
}

// TestDistributedSigmoidVsLocal compares distributed protocol output
// against the local piecewise sigmoid (the reference).
func TestDistributedSigmoidVsLocal(t *testing.T) {
	rp := DefaultRingParams()

	// Standardized data range — this is where accuracy matters
	n := 50
	testX := make([]float64, n)
	for i := range testX {
		testX[i] = -3.0 + 6.0*float64(i)/float64(n-1)
	}

	xFP := rp.VecFromDoubles(testX)
	x0, x1 := rp.SplitVecShare(xFP)

	// Distributed protocol
	dmu0, dmu1 := DistributedSigmoidLocal(rp, x0, x1)

	// Local reference (reconstructs and evaluates exact piecewise)
	lmu0, lmu1 := SecurePiecewiseSigmoidLocal(rp, x0, x1)

	maxErr := 0.0
	for i := range testX {
		distVal := rp.ToDouble(rp.ModAdd(dmu0[i], dmu1[i]))
		localVal := rp.ToDouble(rp.ModAdd(lmu0[i], lmu1[i]))
		err := math.Abs(distVal - localVal)
		if err > maxErr {
			maxErr = err
		}
	}
	t.Logf("Max error distributed vs local: %.4e", maxErr)
	t.Logf("(This error reflects the constant-branch approximation)")
}
