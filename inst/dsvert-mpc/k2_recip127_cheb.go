// k2_recip127_cheb.go — Ring127 plaintext reciprocal 1/x via Chebyshev
// polynomial initial guess + Newton-Raphson refinement (no range reduction).
//
// Purpose (task #116 step 5c(I-c-6)): provide a 0-bit-disclosure Ring127
// 1/x primitive. Unlike the Goldschmidt variant in k2_recip127.go which
// requires revealing an integer shift `s` per element to parties (P3
// regression vs current 0-bit wide-spline), this hybrid keeps x in shares
// throughout the MPC orchestration:
//
//   1. Chebyshev Horner on t = (x - mid)/halfRange ∈ [-1, 1] produces a
//      rough approximation y_0 ≈ 1/x with max rel err ~33% on the default
//      domain [1, 3000].
//   2. Newton-Raphson refinement y_{k+1} = y_k · (2 - x · y_k) converges
//      quadratically: rel_err_{k+1} = -rel_err_k^2. From 33% rel err,
//      5 iters reach ~4e-16 (Ring127 ULP at fracBits=50). No range
//      reduction needed because NR basin is (0, 2/x) and 33% rel err
//      always satisfies that bound.
//
// MPC orchestration in dsVertClient:::.recip127_round mirrors this
// plaintext routine step-by-step over shares, using the existing
// k2BeaverVecmulR1/R2DS + k2Ring127AffineCombineDS + k2Ring127LocalScaleDS
// primitives. No new DS wrapper is needed.
//
// Relationship to k2_recip127.go (Goldschmidt): that file is retained as
// a plaintext reference for the shift-reveal algorithm but is NOT used
// by the MPC recip path. Chebyshev + NR is the production path.

package main

import "math"

// Ring127RecipChebDegree: Chebyshev polynomial degree for the 1/x initial
// guess. Matches Ring127ExpChebDegree for consistency.
const Ring127RecipChebDegree = 30

// Ring127RecipChebXMin, Ring127RecipChebXMax: domain of validity. Chosen
// to cover Cox S(t) across typical scenarios:
//   NCCTG lung : S(t) ∈ [~5, ~1500]
//   Pima       : S(t) ∈ [~10, ~800]
//   synthetic  : S(t) ∈ [~1, ~2500]
// A single [1, 3000] domain handles all without per-element bucket reveal.
const (
	Ring127RecipChebXMin = 1.0
	Ring127RecipChebXMax = 3000.0
)

// Ring127RecipChebNRSteps: number of Newton-Raphson refinements applied
// after Chebyshev initial guess. Empirical worst-case rel err of the
// Chebyshev initial guess on [1, 3000] is ~0.58 at domain ENDPOINTS
// (pole at x=0 closest in Bernstein-ellipse sense).
//
// For x INSIDE [1, 3000] the convergence trajectory squares:
//
//	iter 0 : 0.584          (Chebyshev alone at worst grid endpoint)
//	iter 1 : 0.341
//	iter 2 : 0.116
//	iter 3 : 1.35e-2
//	iter 4 : 1.83e-4
//	iter 5 : 3.36e-8
//	iter 6 : 1.62e-12       (noise-floor limited)
//
// However for x BELOW 1 (Cox S(t) can dip into [0.03, 1) for strong-signal
// scenarios — diagnosed 2026-04-20 from strong_synth failure), the
// Chebyshev polynomial extrapolates to ~1 at the domain boundary, giving
// rel_err_0 ≈ x − 1 (deeply negative). NR from a near-100%-below guess
// needs more iterations before the quadratic phase kicks in:
//
//	x = 0.03: rel_err trajectory {0.97, 0.94, 0.88, 0.77, 0.60, 0.36,
//	          0.13, 0.017, 2.9e-4, 8.4e-8, 7e-15}  → 10 iters to ULP
//	x = 0.46: {0.54, 0.29, 0.085, 7.2e-3, 5.2e-5, 2.7e-9, ULP}  → 6 iters
//	x = 0.73: {0.27, 0.073, 5.3e-3, 2.8e-5, 8e-10, ULP}          → 5 iters
//
// Setting 12 NR iters handles x down to ~0.005 at ULP precision, with
// safety margin vs the strong-signal S_min = 0.03 observed empirically.
// Cost: +12 Beaver rounds per recip call vs 6 iters (≈ 50% wall time
// increase for recip, ~25% for a full Path B iter, ~15 % overall for
// scenarios that stay inside [1, 3000] the convergence is just faster
// — trajectory still terminates at the noise floor around iter 6).
const Ring127RecipChebNRSteps = 12

// Ring127RecipChebCoeffsFP computes the Chebyshev expansion coefficients
// for 1/x on [Ring127RecipChebXMin, Ring127RecipChebXMax] at fracBits =
// r.FracBits, plus the affine mapping constants needed to transform x
// into the Chebyshev domain t ∈ [-1, 1]:
//
//   t = (x - mid) / halfRange
//     = x · (1 / halfRange)   +   (-mid / halfRange)
//
// where mid = (xMax + xMin)/2 and halfRange = (xMax - xMin)/2.
//
// Returns:
//
//	coeffs              : degree+1 FP-encoded Chebyshev coefficients
//	                      c_0, c_1, ..., c_N in the representation
//	                      f(x) ≈ sum_{k=0..N} c_k T_k(t(x)).
//	oneOverHalfRange    : FP scalar = 1/halfRange. Applied to x via
//	                      LocalScale in the MPC protocol.
//	negMidOverHalfRange : FP scalar = -mid/halfRange. Added as public
//	                      constant (party 0 only) via Ring127AffineCombine.
//	degree              : polynomial degree N.
//
// Coefficients are computed via the discrete Chebyshev transform at
// N+1 Chebyshev-of-first-kind nodes, which gives the near-optimal
// least-squares (in Chebyshev-weighted inner product) polynomial
// approximation on the interval.
func Ring127RecipChebCoeffsFP(r Ring127) (coeffs []Uint128,
	oneOverHalfRange, negMidOverHalfRange Uint128, degree int) {

	degree = Ring127RecipChebDegree
	xMin, xMax := Ring127RecipChebXMin, Ring127RecipChebXMax
	mid := (xMax + xMin) / 2.0
	halfRange := (xMax - xMin) / 2.0

	// Sample f(t_j) = 1/x_j at Chebyshev-first-kind nodes:
	//   t_j = cos(pi·(j + 0.5) / (N+1)),  j = 0, 1, ..., N
	//   x_j = halfRange · t_j + mid
	N := degree + 1
	f := make([]float64, N)
	for j := 0; j < N; j++ {
		tj := math.Cos(math.Pi * (float64(j) + 0.5) / float64(N))
		xj := halfRange*tj + mid
		f[j] = 1.0 / xj
	}
	// Discrete Chebyshev transform (orthogonality at the nodes):
	//   c_k = (2/N) · sum_j f(t_j) · cos(pi · k · (j + 0.5) / N)
	//   c_0 has an extra 1/2 factor (standard Chebyshev convention).
	cF := make([]float64, degree+1)
	for k := 0; k <= degree; k++ {
		s := 0.0
		for j := 0; j < N; j++ {
			s += f[j] * math.Cos(math.Pi*float64(k)*(float64(j)+0.5)/float64(N))
		}
		ck := (2.0 / float64(N)) * s
		if k == 0 {
			ck *= 0.5
		}
		cF[k] = ck
	}
	coeffs = make([]Uint128, degree+1)
	for k := range cF {
		coeffs[k] = r.FromDouble(cF[k])
	}
	oneOverHalfRange = r.FromDouble(1.0 / halfRange)
	negMidOverHalfRange = r.FromDouble(-mid / halfRange)
	return
}

// Ring127RecipChebPlaintext is the plaintext reference for the Chebyshev +
// NR MPC recip protocol. Each arithmetic step is performed in Ring127 FP
// exactly as the MPC orchestration does it, so the output is bit-identical
// to what dsVertClient:::.recip127_round produces over simulated shares.
//
// Algorithm:
//
//	a. Affine map  t   = x · (1/halfRange) + (-mid/halfRange)
//	b. Local ×2   twoT = t + t
//	c. Clenshaw   b_{N+1} = 0,  b_N = c_N
//	              for k = N-1..1:  b_k = c_k + twoT · b_{k+1} − b_{k+2}
//	              y_0 = c_0 + t · b_1 − b_2
//	d. NR refine  for i = 1..Ring127RecipChebNRSteps:
//	              y ← y · (2 − x · y)
//
// Cox S(t) is always positive, but a defensive sign branch is retained
// so the primitive is safe for arbitrary signed input.
//
// Panics on x = 0.
func Ring127RecipChebPlaintext(r Ring127, xRing Uint128) Uint128 {
	if (xRing == Uint128{}) {
		panic("Ring127RecipChebPlaintext: division by zero")
	}
	neg := r.IsNeg(xRing)
	x := xRing
	if neg {
		x = r.Neg(xRing)
	}

	coeffs, oneOverHalfRange, negMidOverHalfRange, degree :=
		Ring127RecipChebCoeffsFP(r)

	// (a) t = x · (1/halfRange) + (-mid/halfRange).
	t := r.Add(r.TruncMulSigned(x, oneOverHalfRange), negMidOverHalfRange)

	// (b) twoT = 2 · t.
	twoT := r.Add(t, t)

	// (c) Clenshaw Horner loop.
	//   bNext holds b_{k+2},  bCur holds b_{k+1}.
	//   Initial: b_{N+1} = 0 = bNext,  b_N = c_N = bCur.
	bNext := Uint128{}
	bCur := coeffs[degree]
	for k := degree - 1; k >= 1; k-- {
		// b_k = c_k + twoT · b_{k+1} − b_{k+2}
		bk := r.Sub(r.Add(coeffs[k], r.TruncMulSigned(twoT, bCur)), bNext)
		bNext = bCur
		bCur = bk
	}
	// y_0 = c_0 + t · b_1 − b_2
	y := r.Sub(r.Add(coeffs[0], r.TruncMulSigned(t, bCur)), bNext)

	// (d) Newton-Raphson refinement. No range reduction: basin is (0, 2/x)
	// and Chebyshev worst-case rel err ~0.33 always stays in basin.
	two := r.FromDouble(2.0)
	for i := 0; i < Ring127RecipChebNRSteps; i++ {
		xy := r.TruncMulSigned(x, y)
		twoMinusXy := r.Sub(two, xy)
		y = r.TruncMulSigned(y, twoMinusXy)
	}

	if neg {
		y = r.Neg(y)
	}
	return y
}
