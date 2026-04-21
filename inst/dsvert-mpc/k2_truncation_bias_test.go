// k2_truncation_bias_test.go — investigation of the LMM X4 150× gap.
// Hypothesis (i/ii): TruncateShare / stochastic-carry accumulates a
// systematic bias that 152× exceeds the Gaussian √n·ULP model.
//
// Setup: 200 elements in the LMM cluster-centered magnitude range
// [-40, 40]. Run Beaver vecmul end-to-end and compare to plaintext.
// Measure mean(bias), sd(bias), sum(bias), bias vs |x·y| correlation.

package main

import (
	"math"
	"math/rand"
	"testing"
)

func mean(x []float64) float64 {
	s := 0.0
	for _, v := range x {
		s += v
	}
	return s / float64(len(x))
}
func sd(x []float64) float64 {
	m := mean(x)
	s := 0.0
	for _, v := range x {
		s += (v - m) * (v - m)
	}
	return math.Sqrt(s / float64(len(x)-1))
}
func sum(x []float64) float64 {
	s := 0.0
	for _, v := range x {
		s += v
	}
	return s
}

// Test (A) step (a): deterministic asymmetric truncation bias
// measured on 200 LMM-scale elements.
func TestTruncationBias_Deterministic_200(t *testing.T) {
	r := NewRing63(K2DefaultFracBits)
	n := 200
	rng := rand.New(rand.NewSource(42))
	x := make([]float64, n)
	y := make([]float64, n)
	for i := 0; i < n; i++ {
		// LMM cluster-centered X typical range [-40, 40] (X2 has the widest)
		x[i] = (rng.Float64()*2 - 1) * 40.0
		y[i] = (rng.Float64()*2 - 1) * 40.0
	}
	// Split shares
	x0 := make([]uint64, n); x1 := make([]uint64, n)
	y0 := make([]uint64, n); y1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		xr := r.FromDouble(x[i]); yr := r.FromDouble(y[i])
		x0[i], x1[i] = r.SplitShare(xr); y0[i], y1[i] = r.SplitShare(yr)
	}
	// Beaver end-to-end
	t0, t1 := SampleBeaverTripleVector(n, r)
	st0, m0 := GenerateBatchedMultiplicationGateMessage(x0, y0, t0, r)
	st1, m1 := GenerateBatchedMultiplicationGateMessage(x1, y1, t1, r)
	raw0 := GenerateBatchedMultiplicationOutputPartyZero(st0, t0, m1, r)
	raw1 := GenerateBatchedMultiplicationOutputPartyOne(st1, t1, m0, r)
	// Deterministic asymmetric truncation (what the current Hadamard pipeline uses)
	div := uint64(1) << uint(K2DefaultFracBits)
	out0 := TruncateSharePartyZero(raw0, div, r.Modulus)
	out1 := TruncateSharePartyOne(raw1, div, r.Modulus)
	// Reconstruct + compare
	bias := make([]float64, n)
	abs_err := make([]float64, n)
	scaled_err := make([]float64, n) // bias / |true_product|
	for i := 0; i < n; i++ {
		z := r.Add(out0[i], out1[i])
		got := r.ToDouble(z)
		want := x[i] * y[i]
		bias[i] = got - want
		abs_err[i] = math.Abs(bias[i])
		if math.Abs(want) > 1e-10 {
			scaled_err[i] = bias[i] / math.Abs(want)
		}
	}
	// Stats
	bmean := mean(bias); bsd := sd(bias); bsum := sum(bias)
	amax := 0.0
	for _, v := range abs_err {
		if v > amax {
			amax = v
		}
	}
	t.Logf("[DET-TRUNC] n=%d, |x|,|y| ~ U(-40,40)", n)
	t.Logf("  per-elem bias mean = %.3e", bmean)
	t.Logf("  per-elem bias sd   = %.3e", bsd)
	t.Logf("  per-elem |bias|max = %.3e", amax)
	t.Logf("  sum(bias) over n   = %.3e", bsum)
	t.Logf("  n * bias_mean      = %.3e (if correlated == sum)", float64(n)*bmean)
	t.Logf("  scaled_err (rel) mean = %.3e, max = %.3e",
		mean(scaled_err), func() float64 {
			m := 0.0
			for _, v := range scaled_err {
				if math.Abs(v) > math.Abs(m) {
					m = v
				}
			}
			return m
		}())
	// Interpretation clues:
	//   bmean ~ 0: zero-mean stochastic truncation works
	//   |bmean| > 1e-6: deterministic residual bias per element
	//   sum(bias) ≈ n*bmean: correlated (same sign per element)
	//   sum(bias) ≈ 0 while bmean ≈ 0: independent zero-mean
}

// Test (A) step (b): correlated stochastic truncation — the path
// used by StochasticHadamardProduct in production.
func TestTruncationBias_StochCorrelated_200(t *testing.T) {
	r := NewRing63(K2DefaultFracBits)
	n := 200
	rng := rand.New(rand.NewSource(42))
	x := make([]float64, n); y := make([]float64, n)
	for i := 0; i < n; i++ {
		x[i] = (rng.Float64()*2 - 1) * 40.0
		y[i] = (rng.Float64()*2 - 1) * 40.0
	}
	x0 := make([]uint64, n); x1 := make([]uint64, n)
	y0 := make([]uint64, n); y1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		xr := r.FromDouble(x[i]); yr := r.FromDouble(y[i])
		x0[i], x1[i] = r.SplitShare(xr); y0[i], y1[i] = r.SplitShare(yr)
	}
	t0, t1 := SampleBeaverTripleVector(n, r)
	st0, m0 := GenerateBatchedMultiplicationGateMessage(x0, y0, t0, r)
	st1, m1 := GenerateBatchedMultiplicationGateMessage(x1, y1, t1, r)
	out0, out1 := StochasticHadamardProduct(st0, t0, m1, st1, t1, m0,
		K2DefaultFracBits, r)
	bias := make([]float64, n)
	abs_err := make([]float64, n)
	scaled_err := make([]float64, n)
	for i := 0; i < n; i++ {
		z := r.Add(out0[i], out1[i])
		got := r.ToDouble(z)
		want := x[i] * y[i]
		bias[i] = got - want
		abs_err[i] = math.Abs(bias[i])
		if math.Abs(want) > 1e-10 {
			scaled_err[i] = bias[i] / math.Abs(want)
		}
	}
	bmean := mean(bias); bsd := sd(bias); bsum := sum(bias)
	amax := 0.0
	for _, v := range abs_err {
		if v > amax {
			amax = v
		}
	}
	t.Logf("[STOCH-TRUNC (correlated)] n=%d", n)
	t.Logf("  per-elem bias mean = %.3e", bmean)
	t.Logf("  per-elem bias sd   = %.3e", bsd)
	t.Logf("  per-elem |bias|max = %.3e", amax)
	t.Logf("  sum(bias) over n   = %.3e", bsum)
	t.Logf("  n * bias_mean      = %.3e", float64(n)*bmean)
	t.Logf("  Theoretical random-walk (independent zero-mean): |sum| ~ sqrt(n)*sd = %.3e",
		math.Sqrt(float64(n))*bsd)
	t.Logf("  scaled_err (rel) mean = %.3e, max = %.3e",
		mean(scaled_err), func() float64 {
			m := 0.0
			for _, v := range scaled_err {
				if math.Abs(v) > math.Abs(m) {
					m = v
				}
			}
			return m
		}())
}

// Test (A) step (c): aggregate dot product bias across different scales.
// Measures if per-element bias is MULTIPLICATIVE (scales with |x|,|y|).
func TestTruncationBias_ScaleSweep(t *testing.T) {
	r := NewRing63(K2DefaultFracBits)
	n := 200
	scales := []float64{1.0, 10.0, 40.0, 100.0, 200.0, 500.0}
	rng := rand.New(rand.NewSource(42))
	xu := make([]float64, n); yu := make([]float64, n)
	for i := 0; i < n; i++ {
		xu[i] = rng.Float64()*2 - 1
		yu[i] = rng.Float64()*2 - 1
	}
	t.Logf("Scale sweep (%d elements, det-truncate):", n)
	t.Logf("%10s %15s %15s %15s %15s", "scale", "|dot_err|", "dot_rel_err",
		"per-elem rel", "x·y mean")
	for _, s := range scales {
		x := make([]float64, n); y := make([]float64, n)
		for i := 0; i < n; i++ {
			x[i] = xu[i] * s
			y[i] = yu[i] * s
		}
		// Check per-element headroom
		maxProd := 0.0
		for i := 0; i < n; i++ {
			p := math.Abs(x[i] * y[i])
			if p > maxProd {
				maxProd = p
			}
		}
		if maxProd > float64(int64(1)<<22) {
			t.Logf("[scale=%g] per-elem max prod %.3e exceeds 2^22=%d, skipping",
				s, maxProd, int64(1)<<22)
			continue
		}
		x0 := make([]uint64, n); x1 := make([]uint64, n)
		y0 := make([]uint64, n); y1 := make([]uint64, n)
		for i := 0; i < n; i++ {
			x0[i], x1[i] = r.SplitShare(r.FromDouble(x[i]))
			y0[i], y1[i] = r.SplitShare(r.FromDouble(y[i]))
		}
		t0, t1 := SampleBeaverTripleVector(n, r)
		st0, m0 := GenerateBatchedMultiplicationGateMessage(x0, y0, t0, r)
		st1, m1 := GenerateBatchedMultiplicationGateMessage(x1, y1, t1, r)
		raw0 := GenerateBatchedMultiplicationOutputPartyZero(st0, t0, m1, r)
		raw1 := GenerateBatchedMultiplicationOutputPartyOne(st1, t1, m0, r)
		div := uint64(1) << uint(K2DefaultFracBits)
		o0 := TruncateSharePartyZero(raw0, div, r.Modulus)
		o1 := TruncateSharePartyOne(raw1, div, r.Modulus)
		// Dot product bias
		got_sum := 0.0; want_sum := 0.0
		per_elem_rel := 0.0; cnt := 0
		for i := 0; i < n; i++ {
			z := r.Add(o0[i], o1[i])
			g := r.ToDouble(z)
			w := x[i] * y[i]
			got_sum += g; want_sum += w
			if math.Abs(w) > 1e-10 {
				per_elem_rel += math.Abs((g - w) / w); cnt++
			}
		}
		dot_err := got_sum - want_sum
		dot_rel := dot_err / want_sum
		avg_rel := per_elem_rel / float64(cnt)
		t.Logf("%10g %15.3e %15.3e %15.3e %15.3e",
			s, dot_err, dot_rel, avg_rel, want_sum/float64(n))
	}
}
