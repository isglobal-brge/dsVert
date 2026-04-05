// secure_poly_eval.go: Secure polynomial evaluation on secret shares via Beaver triples.
//
// Given shares [x]_0, [x]_1 and public polynomial coefficients a_0, ..., a_d,
// computes shares [p(x)]_0, [p(x)]_1 where p(x) = a_0 + a_1*x + ... + a_d*x^d.
//
// Protocol (4 batched Beaver rounds for degree 13):
//   Round 1: [x^2] = BeaverMul([x], [x])
//   Round 2: [x^4] = BeaverMul([x^2], [x^2]),  [x^3] = BeaverMul([x^2], [x])
//   Round 3: [x^8] = BeaverMul([x^4], [x^4]),  [x^5..7] = BeaverMul([x^4], [x^{1..3}])
//   Round 4: [x^9..13] = BeaverMul([x^8], [x^{1..5}])
//   Local:   [p(x)]_i = sum_k a_k * [x^k]_i (party 0 adds a_0)
//
// All operations are on vectors (n observations evaluated in parallel).

package main

// SecurePolyEval evaluates a polynomial on secret-shared vectors using Beaver triples.
// Returns shares of p(x) for both parties.
//
// coeffs: monomial coefficients [a_0, a_1, ..., a_d]
// x0, x1: secret shares of the input vector (length n)
//
// This function simulates both parties locally (for testing).
// In production, rounds 1-4 are mediated by the client relay.
func SecurePolyEval(rp RingParams, coeffs []float64, x0, x1 []uint64) (p0, p1 []uint64) {
	n := len(x0)
	degree := len(coeffs) - 1

	// Convert coefficients to fixed-point (public)
	fpCoeffs := make([]uint64, len(coeffs))
	for i, c := range coeffs {
		fpCoeffs[i] = rp.FromDouble(c)
	}

	// Build power shares: powers0[k] and powers1[k] are shares of x^k
	powers0 := make([][]uint64, degree+1)
	powers1 := make([][]uint64, degree+1)

	// x^0 = 1 (party 0 holds 1, party 1 holds 0)
	powers0[0] = make([]uint64, n)
	powers1[0] = make([]uint64, n)
	one := rp.FromDouble(1.0)
	for i := 0; i < n; i++ {
		powers0[0][i] = one
		powers1[0][i] = 0
	}

	// x^1 = x (already shared)
	powers0[1] = make([]uint64, n)
	powers1[1] = make([]uint64, n)
	copy(powers0[1], x0)
	copy(powers1[1], x1)

	// Build remaining powers via Beaver multiplication
	// We use the square-and-multiply tree to minimize rounds
	for k := 2; k <= degree; k++ {
		// Find the best decomposition k = a + b where a, b < k and both already computed
		a, b := bestDecomp(k)
		t0, t1 := GenerateBeaverTriples(rp, n)
		powers0[k], powers1[k] = BeaverFixedPointMul(rp,
			powers0[a], powers0[b],
			powers1[a], powers1[b],
			t0, t1)
	}

	// Linear combination: p(x) = sum_k a_k * x^k
	// Party i computes: [p]_i = sum_k a_k * [x^k]_i
	// Party 0 adds a_0 (the constant term is added only by party 0)
	p0 = make([]uint64, n)
	p1 = make([]uint64, n)

	for k := 0; k <= degree; k++ {
		for i := 0; i < n; i++ {
			// a_k * [x^k]_i: public scalar × share.
			// Uses ASYMMETRIC truncation (P0 vs P1) to ensure the sum of
			// truncated products equals the truncated sum (up to 1 ULP).
			// This matches the C++ ScalarVectorProduct in secret_sharing_mpc/gates/.
			term0 := rp.ScalarShareMulP0(fpCoeffs[k], powers0[k][i])
			term1 := rp.ScalarShareMulP1(fpCoeffs[k], powers1[k][i])
			p0[i] = rp.ModAdd(p0[i], term0)
			p1[i] = rp.ModAdd(p1[i], term1)
		}
	}

	return
}

// bestDecomp finds the best a + b = k where a >= b and both a, b are available
// (i.e., we can compute x^k from x^a * x^b using one Beaver multiplication).
// Uses the doubling strategy: prefer k = k/2 + k/2 when k is even,
// or k = (k-1) + 1 otherwise.
func bestDecomp(k int) (int, int) {
	if k%2 == 0 {
		return k / 2, k / 2
	}
	return k - 1, 1
}

// SecureSigmoidPoly evaluates sigmoid on secret-shared values using Chebyshev
// polynomial approximation via Beaver triples.
// Inputs are clamped to [lower, upper] before evaluation (clamping happens
// on the reconstructed value, which the coordinator would see anyway in the
// pragmatic path — but for strict mode, clamping is pre-applied to standardized
// data so eta stays bounded).
func SecureSigmoidPoly(rp RingParams, x0, x1 []uint64,
	degree int, lower, upper float64) (sig0, sig1 []uint64) {

	coeffs := SigmoidChebyshev(degree, lower, upper)
	return SecurePolyEval(rp, coeffs, x0, x1)
}

// SecureExpPoly evaluates exp on secret-shared values using Chebyshev
// polynomial approximation via Beaver triples.
func SecureExpPoly(rp RingParams, x0, x1 []uint64,
	degree int, lower, upper float64) (exp0, exp1 []uint64) {

	coeffs := ExpChebyshev(degree, lower, upper)
	return SecurePolyEval(rp, coeffs, x0, x1)
}
