package main

import (
	"math"
	"testing"
)

// TestSoftplus127Accuracy: plaintext Ring127 Chebyshev softplus vs math
// softplus over eta in [-8,8], target < 1e-4 (the GLM deviance tolerance).
func TestSoftplus127Accuracy(t *testing.T) {
	r := NewRing127(50)
	maxAbs := 0.0
	var worst float64
	for x := -8.0; x <= 8.0+1e-9; x += 0.01 {
		want := math.Max(x, 0) + math.Log1p(math.Exp(-math.Abs(x)))
		got := r.ToDouble(Ring127SoftplusPlaintext(r, r.FromDouble(x)))
		d := math.Abs(got - want)
		if d > maxAbs {
			maxAbs = d
			worst = x
		}
	}
	t.Logf("softplus127 max abs = %.3e at eta = %.3f (degree %d)", maxAbs, worst, Ring127SoftplusDegree)
	if maxAbs > 1e-4 {
		t.Fatalf("softplus127 max abs %.3e exceeds 1e-4 target", maxAbs)
	}
}
