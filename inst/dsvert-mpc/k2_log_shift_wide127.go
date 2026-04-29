// k2_log_shift_wide127.go — Ring127 wide-Chebyshev log seed for NR-LOG.
//
// Wide Chebyshev fit on [0.1, 1000] at degree 60 to serve as the
// share-side initial guess for Newton-Raphson refinement
//   y_{n+1} = y_n + x·exp(-y_n) - 1
// (quadratic convergence on f(y) = exp(y) - x; Goldschmidt 1964 NR-
// division pattern; Pugh 2004 PhD §3 NR-on-Chebyshev for log).
//
// The narrow [1, 10] core primitive (k2_log_shift127.go) achieves
// rel ≲ 1e-12 in core via Bernstein-ellipse convergence at ρ≈1.94,
// but degrades catastrophically (Runge phenomenon) for inputs outside
// [1, 10]. The NB full-regression θ MLE pipeline operates on (μ+θ) ∈
// [θ, θ + e^η_max] with η_max ≈ 5 → range [0.5, 153] for typical
// biomedical NB θ ∈ [0.5, 5]. Single-scale plaintext rescale leaves
// most elements outside [1, 10] core (Marginal 11.6× sub-noise ratio
// in 2026-04-29 probe).
//
// This wide-domain seed approach mirrors Ring127RecipChebX's wide
// [1, 3000] domain at degree 30 + 6 NR iters: even with poor Chebyshev
// initial precision (rel ~25% in core for the recip), quadratic
// NR convergence drives the error to ULP precision in O(log log) iters.
// For log on [0.1, 1000] at degree 60: Bernstein ρ = 1 + sqrt((mid/half)²-1)
// for mid/half ≈ 1.0002 gives ρ ≈ 1.020, so ρ^-60 ≈ 0.30 (30% initial).
// With NR convergence factor 1/2 (since f''(y)/(2·f'(y)) = 1/2 at the
// root), 5 NR iters drive ε_n: 0.30 → 0.045 → 0.001 → 5e-7 → 1.25e-13
// → 7.8e-27 — well below ULP 2^-50 ≈ 8.9e-16.
//
// Refs: Goldschmidt 1964 *PhD MIT* (NR division at hardware level);
//       Trefethen & Bau 1997 *Numerical Linear Algebra* §16 (Newton's
//       method for nonlinear equations); Pugh 2004 *PhD UWaterloo*
//       chap. 3 (NR-on-Chebyshev seed for elementary functions);
//       Catrina & Saxena 2010 *Financial Cryptography* §3.3 (fixed-
//       point ULP); Trefethen 2013 *ATAP* §8 (Bernstein-ellipse
//       Chebyshev convergence rate).

package main

import "math"

const (
	Ring127LogShiftWideMin    = 0.1
	Ring127LogShiftWideMax    = 1000.0
	Ring127LogShiftWideDegree = 60
)

var ring127LogShiftWideCoeffs [Ring127LogShiftWideDegree + 1]float64

func init() {
	N := Ring127LogShiftWideDegree
	a := Ring127LogShiftWideMin
	b := Ring127LogShiftWideMax
	half := (b - a) / 2.0
	mid := (b + a) / 2.0
	nodes := make([]float64, N+1)
	vals := make([]float64, N+1)
	for j := 0; j <= N; j++ {
		nodes[j] = math.Cos(math.Pi * (2*float64(j) + 1) / (2*float64(N) + 2))
		vals[j] = math.Log(half*nodes[j] + mid)
	}
	for k := 0; k <= N; k++ {
		sum := 0.0
		for j := 0; j <= N; j++ {
			sum += vals[j] * math.Cos(math.Pi*float64(k)*(2*float64(j)+1)/(2*float64(N)+2))
		}
		if k == 0 {
			ring127LogShiftWideCoeffs[k] = sum / float64(N+1)
		} else {
			ring127LogShiftWideCoeffs[k] = 2.0 * sum / float64(N+1)
		}
	}
}

// Ring127LogShiftWidePlaintext evaluates log(x) for x ∈ [0.1, 1000]
// via Clenshaw recurrence on the wide Chebyshev fit. Returns the
// initial NR seed; caller iterates the share-side NR refinement
// y_{n+1} = y_n + x·exp(-y_n) - 1 to drive the rel error to ULP.
func Ring127LogShiftWidePlaintext(r Ring127, sumRing Uint128) Uint128 {
	sumF := r.ToDouble(sumRing)
	half := (Ring127LogShiftWideMax - Ring127LogShiftWideMin) / 2.0
	mid := (Ring127LogShiftWideMax + Ring127LogShiftWideMin) / 2.0
	yF := (sumF - mid) / half
	y := r.FromDouble(yF)

	var bKp1, bKp2 Uint128
	for k := Ring127LogShiftWideDegree; k >= 1; k-- {
		twoY := r.Add(y, y)
		twoYbKp1 := r.TruncMulSigned(twoY, bKp1)
		cK := r.FromDouble(ring127LogShiftWideCoeffs[k])
		bK := r.Sub(r.Add(cK, twoYbKp1), bKp2)
		bKp2 = bKp1
		bKp1 = bK
	}
	yb1 := r.TruncMulSigned(y, bKp1)
	c0 := r.FromDouble(ring127LogShiftWideCoeffs[0])
	return r.Sub(r.Add(c0, yb1), bKp2)
}

// Ring127LogShiftWideCoeffsFP returns the wide-domain affine constants
// + Chebyshev coefficients for share-side Clenshaw orchestration.
// Mirrors Ring127LogShiftCoeffsFP shape; the R client uses these to
// drive the wide initial guess before NR iteration on shares.
func Ring127LogShiftWideCoeffsFP(r Ring127) (oneOverHalf Uint128, midShift Uint128,
	coeffs [Ring127LogShiftWideDegree + 1]Uint128, degree int) {
	half := (Ring127LogShiftWideMax - Ring127LogShiftWideMin) / 2.0
	mid := (Ring127LogShiftWideMax + Ring127LogShiftWideMin) / 2.0
	oneOverHalf = r.FromDouble(1.0 / half)
	midShift = r.FromDouble(mid)
	for k := 0; k <= Ring127LogShiftWideDegree; k++ {
		coeffs[k] = r.FromDouble(ring127LogShiftWideCoeffs[k])
	}
	degree = Ring127LogShiftWideDegree
	return
}
