// k2_sum_residual_ring127_e2e_test.go — round-trip probe for the
// Ring127 sum_residual_fp pipeline used by ds.vertMultinomJointNewton
// per reviewer-directive 2026-04-28 mnl_joint-K2-fix RANK 1 hypothesis
// (Beaver triples / encoding bound to wrong ring).
//
// Builds a known residual vector r, encodes it as Ring127 fracBits=50
// FP, simulates the 2-party additive share split (k2-split-fp-share),
// passes each share through k2-fp-sum (Ring127), then aggregates the
// two scalar sum-shares via k2-ring63-aggregate ring=ring127. The
// final reconstructed sum should equal Σr_i to Ring127 ULP precision.
//
// This isolates the SUM + AGGREGATE pipeline and brackets the bug
// hunt: pass → bug is downstream (Beaver vecmul orchestration); fail →
// bug is in the encoding/aggregate primitives themselves.
//
// References:
//   Catrina-Saxena 2010 §3.3 (FP secret-share encoding bounds)
//   Demmler-Schneider-Zohner ABY 2015 §III.B (K=2 OT-Beaver dispatcher)
//   Mohassel-Zhang SecureML 2017 §IV.B (eprint 2017/396)
//   Escudero et al. LNCS 6280 (Improved Primitives for ring extension)

package main

import (
	"math"
	"testing"
)

func TestSumResidualRing127RoundTrip(t *testing.T) {
	const fracBits = 50
	r := NewRing127(fracBits)

	// Test vectors: positive, negative, mixed-magnitude, and the
	// kind of r-distribution the multinomial residual sees in the
	// fixture (r_i = y_ind_i - p_i ∈ [-1, 1]). Plus some larger-
	// magnitude vectors to test for sign-extension or wraparound.
	cases := []struct {
		name string
		vals []float64
	}{
		{"unit_pos", []float64{0.3, 0.5, 0.2}},
		{"unit_mixed_signs", []float64{0.3, -0.5, 0.2, -0.7}},
		{"all_neg", []float64{-0.3, -0.5, -0.2}},
		{"large_values", []float64{1e3, -2e3, 3e3, -4e3}},
		{"residual_like_n80", makeResidualLikeVec(80)},
		{"residual_like_n189", makeResidualLikeVec(189)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vals := tc.vals
			n := len(vals)
			expected := 0.0
			for _, v := range vals {
				expected += v
			}

			// Encode as Ring127 fracBits=50 FP vector.
			encoded := make([]Uint128, n)
			for i, v := range vals {
				encoded[i] = r.FromDouble(v)
			}

			// Simulate 2-party additive share split (matches
			// handleK2SplitFPShare ring127 path: SplitShare element-wise).
			s0 := make([]Uint128, n)
			s1 := make([]Uint128, n)
			for i := range encoded {
				s0[i], s1[i] = r.SplitShare(encoded[i])
			}

			// k2-fp-sum (Ring127) on each share independently
			// (mirrors handleK2FPSum127 — pure additive sum).
			sumShare0 := Uint128{}
			sumShare1 := Uint128{}
			for i := 0; i < n; i++ {
				sumShare0 = r.Add(sumShare0, s0[i])
				sumShare1 = r.Add(sumShare1, s1[i])
			}

			// k2-ring63-aggregate (ring127 path) — add the two
			// scalar sum-shares and ToDouble at fracBits=50.
			reconstructedRing := r.Add(sumShare0, sumShare1)
			reconstructed := r.ToDouble(reconstructedRing)

			absErr := math.Abs(reconstructed - expected)
			relErr := 0.0
			if math.Abs(expected) > 1e-12 {
				relErr = absErr / math.Abs(expected)
			}
			t.Logf("%s: n=%d, expected=%.6e, got=%.6e, abs=%.3e, rel=%.3e",
				tc.name, n, expected, reconstructed, absErr, relErr)

			// Ring127 fracBits=50 ULP ≈ 9e-16 absolute per element;
			// pure additive accumulation of n terms has at most
			// n·9e-16 absolute drift, no Beaver multiplications.
			tol := float64(n) * 1e-14 // 100× the theoretical n-term sum-ULP
			if math.Abs(expected) > 1.0 {
				tol = math.Abs(expected) * 1e-12
			}
			if absErr > tol {
				t.Errorf("%s: round-trip abs error %.3e exceeds %.3e tolerance",
					tc.name, absErr, tol)
			}
		})
	}
}

// makeResidualLikeVec produces a multinomial-residual-like vector:
// r_i = y_ind_i - p_i with y_ind_i ∈ {0,1} (one-hot) and p_i ∈ [0, 1]
// so r_i ∈ [-1, 1]. Mimics the dsvertComputeResidualShareDS output.
func makeResidualLikeVec(n int) []float64 {
	out := make([]float64, n)
	for i := 0; i < n; i++ {
		// Deterministic, vaguely realistic: half samples have y_ind=1
		// and p ∈ [0.3, 0.7]; other half have y_ind=0 and p ∈ [0.1, 0.5].
		base := float64(i) / float64(n)
		if i%2 == 0 {
			out[i] = 1.0 - (0.3 + 0.4*base) // r ∈ [0.0, 0.7]
		} else {
			out[i] = 0.0 - (0.1 + 0.4*base) // r ∈ [-0.5, -0.1]
		}
	}
	return out
}

// TestSumResidualRing127_DoubleSplitMidpoint stress-tests the
// SplitShare uniformity assumption: if SplitShare returns a non-uniform
// pair (e.g., zero-extension instead of mod-2^127 wrap on negative
// values), the recovered sum will systematically deviate.
func TestSumResidualRing127_DoubleSplitMidpoint(t *testing.T) {
	const fracBits = 50
	r := NewRing127(fracBits)

	// Single negative value: tests sign-extension path.
	neg := -0.42
	encoded := r.FromDouble(neg)
	s0, s1 := r.SplitShare(encoded)
	reconstructed := r.ToDouble(r.Add(s0, s1))
	absErr := math.Abs(reconstructed - neg)
	t.Logf("Single negative round-trip: input=%g, recovered=%g, abs=%.3e",
		neg, reconstructed, absErr)
	if absErr > 1e-13 {
		t.Errorf("single-negative round-trip abs %.3e > 1e-13 — possible sign-extension bug",
			absErr)
	}

	// Boundary tests: |x| close to fracBits=50 representational max.
	// Ring127 with fracBits=50 represents x ∈ [-2^(127-50-1), 2^(127-50-1))
	// = [-2^76, 2^76). 2^76 ≈ 7.5e22. Test at 1e10, well inside.
	for _, v := range []float64{1e1, 1e3, 1e6, 1e9, -1e9, -1e6, -1e3, -1e1} {
		enc := r.FromDouble(v)
		dec := r.ToDouble(enc)
		abs := math.Abs(dec - v)
		t.Logf("FromDouble→ToDouble  %g → %g (abs %.3e)", v, dec, abs)
		// Relative ULP at fracBits=50: 1/2^50 ≈ 9e-16; for x of
		// magnitude M, absolute = M·9e-16 plus integer rounding.
		tol := math.Abs(v)*1e-14 + 1e-13
		if abs > tol {
			t.Errorf("FromDouble→ToDouble round-trip at %g lost precision: abs=%.3e > %.3e",
				v, abs, tol)
		}
	}
}
