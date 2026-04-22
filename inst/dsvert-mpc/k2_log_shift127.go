// k2_log_shift127.go — Ring127 plaintext log(x + c) via Chebyshev wide spline.
//
// Step 5c(I-d) new primitive for NB full-regression θ MLE. Evaluates
// log(x + c) for x a Ring127 FP value (plaintext here; MPC share variant
// via same Clenshaw recurrence is a thin R wrapper on top using
// k2-beaver-vecmul-ring127 + k2Ring127AffineCombineDS primitives that
// already exist for the exp Chebyshev pipeline).
//
// Target: rel error < 1e-10 on x + c ∈ [0.1, 250] (NB μ+θ operating range
// when η ∈ [-5, 5] and θ ∈ [0.1, 100]). At Ring127 fracBits=50 the TruncMul
// ULP floor is 2^{-50} / |log(x+c)| ≈ 9e-16 / 5 ≈ 2e-16, so the rel target
// is bound by Chebyshev truncation not arithmetic.
//
// Algorithm: Chebyshev series of log((b-a)/2 · y + (b+a)/2) for y ∈ [-1, 1]
// where a = logShiftMin, b = logShiftMax.

package main

import "math"

// Domain narrowed to [1, 10] because log is not entire → Chebyshev
// convergence rate on wider domains is too slow for the target
// (Bernstein ellipse radius ρ = |mid/half| + sqrt((mid/half)² − 1)
// shrinks as half grows; on [0.1, 250] ρ ≈ 1.002 giving ρ⁻N ≈ 1
// even at N=100 — unusable).
//
// For the NB full-regression θ MLE pipeline, the caller applies
// argument reduction on shares via DCF comparison to map (μ+θ) into
// [1, 10], then adds a plaintext-known log-base correction. That
// reduction is step 5c(I-d-2) orchestration in the R client, not
// here. This file ships the [1, 10] core primitive at full Ring127
// fracBits=50 rel accuracy.
const (
	Ring127LogShiftMin    = 1.0  // x+c lower bound
	Ring127LogShiftMax    = 10.0 // x+c upper bound
	Ring127LogShiftDegree = 40   // degree 40 on [1,10]: ρ≈1.94, rel≲1e-12
)

var ring127LogShiftCoeffs [Ring127LogShiftDegree + 1]float64

func init() {
	N := Ring127LogShiftDegree
	a := Ring127LogShiftMin
	b := Ring127LogShiftMax
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
			ring127LogShiftCoeffs[k] = sum / float64(N+1)
		} else {
			ring127LogShiftCoeffs[k] = 2.0 * sum / float64(N+1)
		}
	}
}

// Ring127LogShiftPlaintext evaluates log(x + c) where (x + c) is the already-
// summed Ring127 FP value in [Ring127LogShiftMin, Ring127LogShiftMax].
// Clenshaw recurrence on y = (2·sum - (a+b)) / (b-a) ∈ [-1, 1].
func Ring127LogShiftPlaintext(r Ring127, sumRing Uint128) Uint128 {
	sumF := r.ToDouble(sumRing)
	half := (Ring127LogShiftMax - Ring127LogShiftMin) / 2.0
	mid := (Ring127LogShiftMax + Ring127LogShiftMin) / 2.0
	yF := (sumF - mid) / half
	y := r.FromDouble(yF)

	var bKp1, bKp2 Uint128
	for k := Ring127LogShiftDegree; k >= 1; k-- {
		twoY := r.Add(y, y)
		twoYbKp1 := r.TruncMulSigned(twoY, bKp1)
		cK := r.FromDouble(ring127LogShiftCoeffs[k])
		bK := r.Sub(r.Add(cK, twoYbKp1), bKp2)
		bKp2 = bKp1
		bKp1 = bK
	}
	yb1 := r.TruncMulSigned(y, bKp1)
	c0 := r.FromDouble(ring127LogShiftCoeffs[0])
	return r.Sub(r.Add(c0, yb1), bKp2)
}

// Ring127LogShiftCoeffsFP returns the rescale + coefficients for MPC Horner.
// The caller receives half-width 1/a, midpoint-shift (a+b)/2 encoded as
// Ring127 FP, and c_0..c_N. Share-side orchestration:
//   mid_share  = sum_share − (a+b)/2    (local affine-combine with plaintext)
//   y_share    = mid_share · (2/(b−a))  (local scale)
//   Clenshaw via K+1 Beaver vecmul rounds identical to the exp127 pipeline.
func Ring127LogShiftCoeffsFP(r Ring127) (oneOverHalf Uint128, midShift Uint128,
	coeffs [Ring127LogShiftDegree + 1]Uint128, degree int) {
	half := (Ring127LogShiftMax - Ring127LogShiftMin) / 2.0
	mid := (Ring127LogShiftMax + Ring127LogShiftMin) / 2.0
	oneOverHalf = r.FromDouble(1.0 / half)
	midShift = r.FromDouble(mid)
	for k := 0; k <= Ring127LogShiftDegree; k++ {
		coeffs[k] = r.FromDouble(ring127LogShiftCoeffs[k])
	}
	degree = Ring127LogShiftDegree
	return
}
