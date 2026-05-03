package main

import (
	"math"
	"testing"
)

func TestRing127LocalScaleShare_ReconstructAccuracy(t *testing.T) {
	r := NewRing127(50)
	values := []float64{-7.25, -1.1, -0.05, 0, 0.25, 3.5, 12.75}
	scalars := []float64{-1.0, -0.5, 0.1, 0.5, 2.25}

	for _, scalar := range scalars {
		for _, value := range values {
			x := r.FromDouble(value)
			s0, s1 := r.SplitShare(x)
			z0 := ScalarVectorProductPartyZero127(scalar, []Uint128{s0}, r)[0]
			z1 := ScalarVectorProductPartyOne127(scalar, []Uint128{s1}, r)[0]
			got := r.ToDouble(r.Add(z0, z1))
			want := scalar * value
			if math.Abs(got-want) > 1e-10 {
				t.Fatalf("scale(%g, %g): got %.17g want %.17g", scalar, value, got, want)
			}
		}
	}
}
