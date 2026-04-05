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
