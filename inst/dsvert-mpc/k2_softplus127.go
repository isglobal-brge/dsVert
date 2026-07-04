// k2_softplus127.go — Ring127 direct softplus(x)=log(1+exp(x)) via Chebyshev.
//
// Reveal-free, dealer-free share-domain link for the binomial deviance
// D_binomial = 2*(sum softplus(eta) - y^T eta). softplus is smooth + bounded
// on [-8, 8] (range ~[3.4e-4, 8.0]), so a single Chebyshev Clenshaw pass gives
// a per-observation softplus share without ever relaying a masked eta.
// Structural clone of k2_sigmoid127.go / k2_exp127.go; independent of
// exp127/recip127 (which the Newton family uses).
//
// The -log(1-mu) identity is avoided: 1-mu reaches ~3.4e-4 at eta=8, below the
// wide-log Chebyshev domain [0.1, 1000], so a direct softplus poly is cleaner.

package main

import "math"

const (
	Ring127SoftplusDomainA = 8.0 // domain half-width; x in [-8, 8]
	Ring127SoftplusDegree  = 36  // Chebyshev degree (softplus less smooth than sigmoid)
)

var ring127SoftplusCoeffs [Ring127SoftplusDegree + 1]float64

func init() {
	N := Ring127SoftplusDegree
	a := Ring127SoftplusDomainA
	nodes := make([]float64, N+1)
	vals := make([]float64, N+1)
	for j := 0; j <= N; j++ {
		nodes[j] = math.Cos(math.Pi * (2*float64(j) + 1) / (2*float64(N) + 2))
		// softplus(x) = log(1+exp(x)); use the numerically-stable max form.
		x := a * nodes[j]
		vals[j] = math.Max(x, 0) + math.Log1p(math.Exp(-math.Abs(x)))
	}
	for k := 0; k <= N; k++ {
		sum := 0.0
		for j := 0; j <= N; j++ {
			sum += vals[j] * math.Cos(math.Pi*float64(k)*(2*float64(j)+1)/(2*float64(N)+2))
		}
		if k == 0 {
			ring127SoftplusCoeffs[k] = sum / float64(N+1)
		} else {
			ring127SoftplusCoeffs[k] = 2.0 * sum / float64(N+1)
		}
	}
}

// Ring127SoftplusPlaintext evaluates softplus(x) for Ring127 FP x (plaintext),
// ground truth for the MPC Clenshaw protocol. Clenshaw on y = x/a (a = 8).
func Ring127SoftplusPlaintext(r Ring127, xRing Uint128) Uint128 {
	oneOverA := r.FromDouble(1.0 / Ring127SoftplusDomainA)
	y := r.TruncMulSigned(xRing, oneOverA)
	var bKp1, bKp2 Uint128
	for k := Ring127SoftplusDegree; k >= 1; k-- {
		twoY := r.Add(y, y)
		twoYbKp1 := r.TruncMulSigned(twoY, bKp1)
		cK := r.FromDouble(ring127SoftplusCoeffs[k])
		bK := r.Sub(r.Add(cK, twoYbKp1), bKp2)
		bKp2 = bKp1
		bKp1 = bK
	}
	yb1 := r.TruncMulSigned(y, bKp1)
	c0 := r.FromDouble(ring127SoftplusCoeffs[0])
	return r.Sub(r.Add(c0, yb1), bKp2)
}

// Ring127SoftplusCoeffsFP returns 1/a + coefficients as Ring127 FP for the MPC
// Clenshaw protocol (degree Beaver vecmul rounds on shares).
func Ring127SoftplusCoeffsFP(r Ring127) (oneOverA Uint128, coeffs [Ring127SoftplusDegree + 1]Uint128, degree int) {
	oneOverA = r.FromDouble(1.0 / Ring127SoftplusDomainA)
	for k := 0; k <= Ring127SoftplusDegree; k++ {
		coeffs[k] = r.FromDouble(ring127SoftplusCoeffs[k])
	}
	degree = Ring127SoftplusDegree
	return
}
