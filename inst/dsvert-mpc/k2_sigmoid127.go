// k2_sigmoid127.go — Ring127 direct sigmoid(x)=1/(1+exp(-x)) via Chebyshev.
//
// SPEED primitive (2026-07-03): a GLM-specific, reveal-free, dealer-free
// share-domain logistic link that replaces the exp127+recip127 composition
// (~85 Beaver rounds) with a SINGLE Chebyshev Clenshaw pass (~29 rounds,
// ~2.9x fewer). sigmoid is smooth + bounded on [-8, 8], so a degree-29
// Chebyshev reaches max-abs ~6.5e-6 — far tighter than the ~1e-4 a GLM
// coefficient needs, and far looser than exp/recip's 3.45e-14 overkill.
//
// This primitive DOES NOT touch exp127/recip127, which stay at degree 30
// (rel 3.45e-14) for the high-accuracy Newton family (NB / ordinal /
// multinomial / Cox). It is a structural clone of Ring127ExpPlaintext, so it
// inherits that path's reveal-free MPC orchestration.
//
// sigmoid(x) - 0.5 is an ODD function, so the even-index Chebyshev
// coefficients are ~0 (numerical zero) and c_0 carries the +0.5 baseline —
// no separate affine round is needed. Degree 29 is odd and clears the
// documented Clenshaw stability guardrail (degree >= 20).

package main

import "math"

const (
	Ring127SigmoidDomainA = 8.0 // domain half-width; x in [-8, 8]
	Ring127SigmoidDegree  = 29  // Chebyshev degree (odd; sigmoid-0.5 is odd)
)

// ring127SigmoidCoeffs holds the Chebyshev coefficients a_n of sigmoid(a*y)
// for y in [-1, 1], indexed by degree. Computed once at init().
var ring127SigmoidCoeffs [Ring127SigmoidDegree + 1]float64

func init() {
	// DCT-III over sigmoid evaluated at Chebyshev nodes (same construction
	// as ring127ExpCoeffs, with vals = sigmoid instead of exp).
	N := Ring127SigmoidDegree
	a := Ring127SigmoidDomainA
	nodes := make([]float64, N+1)
	vals := make([]float64, N+1)
	for j := 0; j <= N; j++ {
		nodes[j] = math.Cos(math.Pi * (2*float64(j) + 1) / (2*float64(N) + 2))
		vals[j] = 1.0 / (1.0 + math.Exp(-a*nodes[j]))
	}
	for k := 0; k <= N; k++ {
		sum := 0.0
		for j := 0; j <= N; j++ {
			sum += vals[j] * math.Cos(math.Pi*float64(k)*(2*float64(j)+1)/(2*float64(N)+2))
		}
		if k == 0 {
			ring127SigmoidCoeffs[k] = sum / float64(N+1)
		} else {
			ring127SigmoidCoeffs[k] = 2.0 * sum / float64(N+1)
		}
	}
}

// Ring127SigmoidPlaintext evaluates sigmoid(x) where x is a Ring127 FP value
// (plaintext, NOT a share). Ground-truth reference for the MPC Clenshaw
// protocol and coefficient-correctness tests. Clenshaw recurrence on
// y = x/a (a = 8), stable for degree >= 20. The +0.5 baseline is carried by
// c_0, so no extra affine term is added.
func Ring127SigmoidPlaintext(r Ring127, xRing Uint128) Uint128 {
	oneOverA := r.FromDouble(1.0 / Ring127SigmoidDomainA)
	y := r.TruncMulSigned(xRing, oneOverA)

	var bKp1, bKp2 Uint128
	for k := Ring127SigmoidDegree; k >= 1; k-- {
		twoY := r.Add(y, y)
		twoYbKp1 := r.TruncMulSigned(twoY, bKp1)
		cK := r.FromDouble(ring127SigmoidCoeffs[k])
		bK := r.Sub(r.Add(cK, twoYbKp1), bKp2)
		bKp2 = bKp1
		bKp1 = bK
	}
	yb1 := r.TruncMulSigned(y, bKp1)
	c0 := r.FromDouble(ring127SigmoidCoeffs[0])
	return r.Sub(r.Add(c0, yb1), bKp2)
}

// Ring127SigmoidCoeffsFP returns 1/a + the Chebyshev coefficients encoded as
// Ring127 FP, for the MPC Clenshaw protocol: the R client fetches these once,
// then orchestrates `degree` n-parallel Beaver vecmul rounds on shares
// (identical Clenshaw structure to the exp127 Horner protocol). Total Beaver
// rounds: degree (one per Clenshaw step) = 29 per sigmoid call.
func Ring127SigmoidCoeffsFP(r Ring127) (oneOverA Uint128, coeffs [Ring127SigmoidDegree + 1]Uint128, degree int) {
	oneOverA = r.FromDouble(1.0 / Ring127SigmoidDomainA)
	for k := 0; k <= Ring127SigmoidDegree; k++ {
		coeffs[k] = r.FromDouble(ring127SigmoidCoeffs[k])
	}
	degree = Ring127SigmoidDegree
	return
}
