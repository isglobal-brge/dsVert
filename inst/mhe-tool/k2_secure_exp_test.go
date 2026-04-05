package main

import (
	"math"
	"testing"
)

func TestMultToAddTupleK2(t *testing.T) {
	q := uint64(2305843009213693951) // 2^61 - 1

	for i := 0; i < 10; i++ {
		mta := GenerateMultToAddTuple(q)
		check := (modMulBig(mta.Alpha0, mta.Alpha1, q) +
			modMulBig(mta.Beta0, mta.Beta1, q)) % q
		if check != 1 {
			t.Errorf("MultToAdd tuple verification failed: got %d, want 1", check)
		}
	}
	t.Log("10 MultToAdd tuples verified")
}

func TestSecureExpKelkarBasic(t *testing.T) {
	cfg := DefaultExpConfig()
	fracBits := cfg.FracBits

	testValues := []float64{0.0, 1.0, -1.0, 2.0, -2.0, 0.5, -0.5}

	for _, x := range testValues {
		xFP := FromFloat64(x, fracBits)

		// Split into shares
		r := FixedPoint(int64(cryptoRandUint64K2()))
		x0 := r
		x1 := xFP - r // wrapping int64 subtraction

		shares0 := []FixedPoint{x0}
		shares1 := []FixedPoint{x1}

		exp0, exp1 := SecureExpKelkar(cfg, shares0, shares1)

		// Reconstruct
		result := exp0[0] + exp1[0] // wrapping int64 addition
		got := result.ToFloat64(fracBits)
		expected := math.Exp(x)

		relErr := math.Abs(got-expected) / math.Max(expected, 1e-10)
		t.Logf("exp(%.1f) = %.6f (expected %.6f, relErr %.2e)", x, got, expected, relErr)

		if relErr > 0.5 {
			t.Errorf("exp(%.1f): relative error %.2e exceeds 0.5", x, relErr)
		}
	}
}
