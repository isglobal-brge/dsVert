// k2_exp127.go — Ring127 plaintext exp(x) via Chebyshev polynomial approximation.
//
// Purpose (task #116 step 5c(I-a)): provide a Ring127 `exp(x)` primitive
// with rel error < 1e-14 on [-5, 5] (NCCTG eta range), as a structural
// replacement for the wide-spline path at ring=127. The spline approach
// has a noise floor of ~1e-4 per element that accumulates to O(n·1e-4)
// additive Fisher bias across observations (see oracle-β diagnostic
// 2026-04-20). A global polynomial approximation on Ring127 FP removes
// that noise source entirely; the only residual error is Ring127 ULP
// (~2^-50 per op) plus Chebyshev truncation (~1e-18 at degree 30).
//
// This file ships the PLAINTEXT primitive + exhaustive accuracy test
// vs math.Exp. The MPC variant — evaluating the same polynomial on
// Ring127 shares via Beaver vecmul Horner steps — is step 5c(I-c)
// integration (R client orchestrates Beaver rounds using 5c(A)
// primitives; Go just provides the public coefficients + plaintext
// ground truth).
//
// Algorithm: Chebyshev series of exp(5y) = Σ_n a_n T_n(y) for y = x/5.
// Coefficients precomputed at init() via Clenshaw-Curtis quadrature
// (DCT-III over exp evaluated at Chebyshev nodes). Evaluation uses the
// Clenshaw recurrence, which is numerically stable for degree ≥ 20.

package main

import "math"

// Domain + degree chosen to hit rel <1e-14 for exp on [-5, 5].
// Chebyshev series truncation error at degree N on [-a, a] for exp:
//   |err| ≲ 2 · a_{N+1} · e^a,  a_n ≈ (a/2)^n / n! · {1 for n≥1, 1/2 for n=0}.
// For a=5, N=30: a_31 ≈ 2.5^31 / 31! ≈ 6e-23, err ≈ 2·6e-23·148 ≈ 2e-20 — well
// below 1e-14 target. Leaves headroom for Ring127 fracBits=50 truncation drift
// (N sequential TruncMul steps × 2^-50 ≈ N·9e-16 absolute).
const (
	Ring127ExpDomainA = 5.0 // domain half-width; x ∈ [-5, 5]
	Ring127ExpDegree  = 30  // Chebyshev polynomial degree
)

// ring127ExpCoeffs holds the Chebyshev coefficients a_n of exp(5y) for
// y ∈ [-1, 1], indexed by degree. Computed once at init().
var ring127ExpCoeffs [Ring127ExpDegree + 1]float64

func init() {
	// Generate Chebyshev coefficients of exp(a·y) on [-1, 1] via DCT-III
	// over exp evaluated at Chebyshev nodes y_j = cos((2j+1)π / (2N+2)).
	// Formula:
	//   a_k = (2/(N+1)) · Σ_j exp(a·y_j) · cos(k·(2j+1)π / (2N+2))  (k>0)
	//   a_0 = (1/(N+1)) · Σ_j exp(a·y_j)
	N := Ring127ExpDegree
	a := Ring127ExpDomainA
	nodes := make([]float64, N+1)
	vals := make([]float64, N+1)
	for j := 0; j <= N; j++ {
		nodes[j] = math.Cos(math.Pi * (2*float64(j) + 1) / (2*float64(N) + 2))
		vals[j] = math.Exp(a * nodes[j])
	}
	for k := 0; k <= N; k++ {
		sum := 0.0
		for j := 0; j <= N; j++ {
			sum += vals[j] * math.Cos(math.Pi*float64(k)*(2*float64(j)+1)/(2*float64(N)+2))
		}
		if k == 0 {
			ring127ExpCoeffs[k] = sum / float64(N+1)
		} else {
			ring127ExpCoeffs[k] = 2.0 * sum / float64(N+1)
		}
	}
}

// Ring127ExpPlaintext evaluates exp(x) where x is a Ring127 FP value
// (plaintext, NOT a share). Used as the ground-truth reference for the
// MPC Horner protocol and to validate coefficient correctness via tests.
//
// Algorithm: Clenshaw recurrence for Chebyshev polynomials on y = x/a.
// All intermediate values stay in Ring127 FP; final result is also
// Ring127 FP. Accuracy target: rel error < 1e-14 over x ∈ [-5, 5].
//
// Clenshaw recurrence (stable for degree ≥ 20):
//   b_{N+1} = b_{N+2} = 0
//   for k = N, N-1, ..., 1:
//     b_k = c_k + 2·y·b_{k+1} - b_{k+2}
//   result = c_0 + y·b_1 - b_2
func Ring127ExpPlaintext(r Ring127, xRing Uint128) Uint128 {
	// Rescale x → y = x / a  (a = 5); y ∈ [-1, 1] for x ∈ [-a, a].
	oneOverA := r.FromDouble(1.0 / Ring127ExpDomainA)
	y := r.TruncMulSigned(xRing, oneOverA)

	// Clenshaw recurrence on Ring127 FP.
	var bKp1, bKp2 Uint128
	for k := Ring127ExpDegree; k >= 1; k-- {
		twoY := r.Add(y, y)
		twoYbKp1 := r.TruncMulSigned(twoY, bKp1)
		cK := r.FromDouble(ring127ExpCoeffs[k])
		// b_k = c_k + 2·y·b_{k+1} - b_{k+2}
		bK := r.Sub(r.Add(cK, twoYbKp1), bKp2)
		bKp2 = bKp1
		bKp1 = bK
	}
	// result = c_0 + y·b_1 - b_2
	yb1 := r.TruncMulSigned(y, bKp1)
	c0 := r.FromDouble(ring127ExpCoeffs[0])
	return r.Sub(r.Add(c0, yb1), bKp2)
}

// Ring127ExpCoeffsFP returns the Chebyshev coefficients encoded as Ring127
// FP values. Intended for the MPC Horner protocol (step 5c(I-c)): the R
// client fetches these once, then orchestrates n-parallel Beaver vecmul
// Horner steps on shares using the existing k2-beaver-vecmul-* handlers.
//
// The caller receives 1/a (for rescaling), c_0..c_N (coefficients), and
// the degree. The Horner protocol on shares is:
//
//   y_share   = TruncMulSigned(x_share, 1/a)   (local, 1/a public)
//   b_{N+2}   = 0  (both parties)
//   b_{N+1}   = 0  (both parties)
//   for k = N downto 1:
//       twoY     = 2·y   (local, double-share)
//       twoYbKp1 = Beaver(twoY, b_{k+1})  ← Beaver vecmul round
//       b_k      = (party 0 adds c_k plaintext) + twoYbKp1 - b_{k+2}
//   yb1       = Beaver(y, b_1)  ← Beaver vecmul round
//   result    = (party 0 adds c_0) + yb1 - b_2
//
// Total Beaver rounds: N (one per Horner step) + 1 (final y·b_1). At
// Ring127 with degree=30, ~31 Beaver vecmul rounds per exp call.
func Ring127ExpCoeffsFP(r Ring127) (oneOverA Uint128, coeffs [Ring127ExpDegree + 1]Uint128, degree int) {
	oneOverA = r.FromDouble(1.0 / Ring127ExpDomainA)
	for k := 0; k <= Ring127ExpDegree; k++ {
		coeffs[k] = r.FromDouble(ring127ExpCoeffs[k])
	}
	degree = Ring127ExpDegree
	return
}
