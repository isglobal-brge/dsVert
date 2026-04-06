// k2_distributed_sigmoid.go: Full distributed piecewise sigmoid — Google C++ protocol.
//
// Uses the VALIDATED mhe-tool Ring63 for all arithmetic.
// Local simulation: both parties computed in one process.
// Same Ring63 operations as the distributed protocol.

package main

// No additional imports needed

// DistributedSigmoidLocal evaluates sigmoid on secret shares.
// Both parties simulated locally (same Ring63 as when distributed).
//
// Protocol (matching C++ secure_sigmoid.cc):
//   1. 5 DCF comparisons for interval selection
//   2. Beaver Hadamard AND for 4 interval indicators
//   3. Evaluate 6 branches on shares:
//      I0 [0,1): spline a_t*x+b_t (ScalarVectorProduct + Hadamard)
//      I1 [1,L): Kelkar exp(-x) + Taylor 1/(1+z)
//      I2 [L,∞): saturate 1
//      I3 (-∞,-L): saturate 0
//      I4 [-L,-1): Kelkar exp(x) + Taylor, then 1 - result
//      I5 [-1,0): 1 - spline(-x)
//   4. Branch selection: Hadamard indicator_k × branch_k, sum all 6
func DistributedSigmoidLocalMhe(ring Ring63, x0, x1 []uint64) (mu0, mu1 []uint64) {
	n := len(x0)
	params := SigmoidParams{
		Ring: ring, FracBits: ring.FracBits,
		SplineSlopes: DefaultSigmoidParams().SplineSlopes,
		SplineIntercepts: DefaultSigmoidParams().SplineIntercepts,
		SplineNumIntervals: 10, TaylorDegree: 10,
		ExpConfig: ExpConfig{Ring: ring, ExponentBound: 3, PrimeQ: 2305843009213693951},
	}
	// L = ExponentBound — for |x| >= L, saturate to 0 or 1.
	lfLn2 := float64(params.ExpConfig.ExponentBound) // 10 for default

	// === Step 1: 5 comparisons ===
	thresholds := []float64{-lfLn2, -1.0, 0.0, 1.0, lfLn2}
	cmp0 := make([]CmpArithResult, 5)
	cmp1 := make([]CmpArithResult, 5)
	for j, tf := range thresholds {
		threshFP := ring.FromDouble(tf)
		p0Pre, p1Pre := cmpGeneratePreprocess(ring, n, threshFP)
		p0R1 := cmpRound1(ring, 0, x0, p0Pre)
		p1R1 := cmpRound1(ring, 1, x1, p1Pre)
		cmp0[j] = cmpRound2(ring, 0, p0Pre, p0R1, p1R1)
		cmp1[j] = cmpRound2(ring, 1, p1Pre, p1R1, p0R1)
	}

	// === Step 2: Interval indicators via Beaver AND ===
	// NOT(c) = 1 - c. Party 0: 1-share, Party 1: 0-share = Modulus-share
	notR63 := func(share uint64, partyID int) uint64 {
		if partyID == 0 {
			return ring.Sub(1, share)
		}
		return ring.Sub(0, share)
	}

	// 4 AND operations: I0=NOT(c2)*c3, I1=NOT(c3)*c4, I4=NOT(c0)*c1, I5=NOT(c1)*c2
	type andPair struct{ a0, b0, a1, b1 []uint64 }
	ands := [4]andPair{}
	for i := 0; i < n; i++ {
		if i == 0 {
			for k := range ands {
				ands[k].a0 = make([]uint64, n)
				ands[k].b0 = make([]uint64, n)
				ands[k].a1 = make([]uint64, n)
				ands[k].b1 = make([]uint64, n)
			}
		}
		ands[0].a0[i] = notR63(cmp0[2].Shares[i], 0); ands[0].b0[i] = cmp0[3].Shares[i]
		ands[0].a1[i] = notR63(cmp1[2].Shares[i], 1); ands[0].b1[i] = cmp1[3].Shares[i]
		ands[1].a0[i] = notR63(cmp0[3].Shares[i], 0); ands[1].b0[i] = cmp0[4].Shares[i]
		ands[1].a1[i] = notR63(cmp1[3].Shares[i], 1); ands[1].b1[i] = cmp1[4].Shares[i]
		ands[2].a0[i] = notR63(cmp0[0].Shares[i], 0); ands[2].b0[i] = cmp0[1].Shares[i]
		ands[2].a1[i] = notR63(cmp1[0].Shares[i], 1); ands[2].b1[i] = cmp1[1].Shares[i]
		ands[3].a0[i] = notR63(cmp0[1].Shares[i], 0); ands[3].b0[i] = cmp0[2].Shares[i]
		ands[3].a1[i] = notR63(cmp1[1].Shares[i], 1); ands[3].b1[i] = cmp1[2].Shares[i]
	}

	andRes0 := [4][]uint64{}
	andRes1 := [4][]uint64{}
	for k := 0; k < 4; k++ {
		t0, t1 := SampleBeaverTripleVector(n, ring)
		st0, msg0 := GenerateBatchedMultiplicationGateMessage(ands[k].a0, ands[k].b0, t0, ring)
		st1, msg1 := GenerateBatchedMultiplicationGateMessage(ands[k].a1, ands[k].b1, t1, ring)
		// NO truncation — integer product of {0,1} values
		andRes0[k] = GenerateBatchedMultiplicationOutputPartyZero(st0, t0, msg1, ring)
		andRes1[k] = GenerateBatchedMultiplicationOutputPartyOne(st1, t1, msg0, ring)
	}

	// Build 6 indicators
	ind0 := [6][]uint64{}; ind1 := [6][]uint64{}
	ind0[0] = andRes0[0]; ind1[0] = andRes1[0] // I0: NOT(c2)*c3
	ind0[1] = andRes0[1]; ind1[1] = andRes1[1] // I1: NOT(c3)*c4
	ind0[2] = make([]uint64, n); ind1[2] = make([]uint64, n) // I2: NOT(c4)
	ind0[3] = make([]uint64, n); ind1[3] = make([]uint64, n) // I3: c0
	ind0[4] = andRes0[2]; ind1[4] = andRes1[2] // I4: NOT(c0)*c1
	ind0[5] = andRes0[3]; ind1[5] = andRes1[3] // I5: NOT(c1)*c2
	for i := 0; i < n; i++ {
		ind0[2][i] = notR63(cmp0[4].Shares[i], 0)
		ind1[2][i] = notR63(cmp1[4].Shares[i], 1)
		ind0[3][i] = cmp0[0].Shares[i]
		ind1[3][i] = cmp1[0].Shares[i]
	}

	// Scale indicators: integer → FP (multiply by FracMul)
	for k := 0; k < 6; k++ {
		for i := 0; i < n; i++ {
			ind0[k][i] = modMulBig63(ind0[k][i], ring.FracMul, ring.Modulus)
			ind1[k][i] = modMulBig63(ind1[k][i], ring.FracMul, ring.Modulus)
		}
	}

	// === Step 3: Evaluate branches ===
	br0 := [6][]uint64{}; br1 := [6][]uint64{}

	// I0: spline(x) for x in [0,1) — 10-interval piecewise linear
	br0[0], br1[0] = evalSplineOnShares(ring, params, x0, x1)

	// I1: exp(-x) + Taylor 1/(1+z) for x in [1, L)
	negX0 := make([]uint64, n); negX1 := make([]uint64, n)
	for i := range negX0 { negX0[i] = ring.Neg(x0[i]); negX1[i] = ring.Neg(x1[i]) }
	br0[1], br1[1] = evalExpTaylorOnShares(ring, negX0, negX1) // exp(-x), Taylor

	// I2: constant 1
	br0[2] = make([]uint64, n); br1[2] = make([]uint64, n)
	oneFP := ring.FromDouble(1.0)
	for i := range br0[2] { br0[2][i] = oneFP; br1[2][i] = 0 }

	// I3: constant 0
	br0[3] = make([]uint64, n); br1[3] = make([]uint64, n)

	// I4: 1 - expTaylor(exp(x)) for x in [-L, -1) — exp(x) is small since x<-1
	tmp0, tmp1 := evalExpTaylorOnShares(ring, x0, x1) // exp(x), Taylor
	br0[4] = make([]uint64, n); br1[4] = make([]uint64, n)
	for i := 0; i < n; i++ {
		br0[4][i] = ring.Sub(oneFP, tmp0[i])
		br1[4][i] = ring.Sub(0, tmp1[i])
	}

	// I5: 1 - spline(-x) for x in [-1, 0)
	spl0, spl1 := evalSplineOnShares(ring, params, negX0, negX1)
	br0[5] = make([]uint64, n); br1[5] = make([]uint64, n)
	for i := 0; i < n; i++ {
		br0[5][i] = ring.Sub(oneFP, spl0[i])
		br1[5][i] = ring.Sub(0, spl1[i])
	}

	_ = lfLn2

	// === Step 4: Branch selection — Hadamard indicator × branch ===
	mu0 = make([]uint64, n); mu1 = make([]uint64, n)
	for k := 0; k < 6; k++ {
		t0, t1 := SampleBeaverTripleVector(n, ring)
		st0, msg0 := GenerateBatchedMultiplicationGateMessage(ind0[k], br0[k], t0, ring)
		st1, msg1 := GenerateBatchedMultiplicationGateMessage(ind1[k], br1[k], t1, ring)
prod0, prod1 := StochasticHadamardProduct(st0, t0, msg1, st1, t1, msg0, ring.FracBits, ring)
		for i := 0; i < n; i++ {
			mu0[i] = ring.Add(mu0[i], prod0[i])
			mu1[i] = ring.Add(mu1[i], prod1[i])
		}
	}

	return
}

// evalSplineOnShares evaluates the piecewise linear spline on shares.
// Uses (numIntervals-1) DCF comparisons + ScalarVectorProduct for coefficients.
func evalSplineOnShares(ring Ring63, params SigmoidParams, x0, x1 []uint64) (res0, res1 []uint64) {
	n := len(x0)
	numInt := params.SplineNumIntervals
	numCmp := numInt - 1
	width := 1.0 / float64(numInt)

	// (numInt-1) sub-interval comparisons
	subCmp0 := make([]CmpArithResult, numCmp)
	subCmp1 := make([]CmpArithResult, numCmp)
	for j := 0; j < numCmp; j++ {
		tf := float64(j+1) * width
		threshFP := ring.FromDouble(tf)
		p0Pre, p1Pre := cmpGeneratePreprocess(ring, n, threshFP)
		p0R1 := cmpRound1(ring, 0, x0, p0Pre)
		p1R1 := cmpRound1(ring, 1, x1, p1Pre)
		subCmp0[j] = cmpRound2(ring, 0, p0Pre, p0R1, p1R1)
		subCmp1[j] = cmpRound2(ring, 1, p1Pre, p1R1, p0R1)
	}

	// Build numInt sub-indicators from comparisons:
	// ind[0] = c[0], ind[j] = c[j] - c[j-1], ind[last] = 1 - c[last_cmp]
	subInd0 := make([][]uint64, numInt); subInd1 := make([][]uint64, numInt)
	for k := 0; k < numInt; k++ {
		subInd0[k] = make([]uint64, n); subInd1[k] = make([]uint64, n)
	}
	for i := 0; i < n; i++ {
		subInd0[0][i] = subCmp0[0].Shares[i]
		subInd1[0][i] = subCmp1[0].Shares[i]
		for j := 1; j < numCmp; j++ {
			subInd0[j][i] = ring.Sub(subCmp0[j].Shares[i], subCmp0[j-1].Shares[i])
			subInd1[j][i] = ring.Sub(subCmp1[j].Shares[i], subCmp1[j-1].Shares[i])
		}
		subInd0[numInt-1][i] = ring.Sub(1, subCmp0[numCmp-1].Shares[i])
		subInd1[numInt-1][i] = ring.Sub(0, subCmp1[numCmp-1].Shares[i])
	}

	// Scale to FP
	for k := 0; k < numInt; k++ {
		for i := 0; i < n; i++ {
			subInd0[k][i] = modMulBig63(subInd0[k][i], ring.FracMul, ring.Modulus)
			subInd1[k][i] = modMulBig63(subInd1[k][i], ring.FracMul, ring.Modulus)
		}
	}

	// DEFERRED TRUNCATION (Keller & Sun, ICML 2022):
	// Instead of truncating each ScalarVP independently (20 truncations),
	// accumulate ring products WITHOUT truncation, then truncate ONCE.
	// This reduces truncation bias from ~20 ULP to ~1 ULP per spline eval.
	//
	// [a_t] = truncate_once(sum_j ring_slope_j * indicator_j_fp)
	// [b_t] = truncate_once(sum_j ring_intercept_j * indicator_j_fp)
	//
	// The intermediate sums are in "double FP" (2*fracBits bits) but
	// still fit in Ring63 (63 bits) since 2*20 = 40 < 63.

	aSlope0 := make([]uint64, n); aSlope1 := make([]uint64, n)
	bIntercept0 := make([]uint64, n); bIntercept1 := make([]uint64, n)
	for j := 0; j < numInt; j++ {
		slopeFP := ring.FromDouble(params.SplineSlopes[j])
		interceptFP := ring.FromDouble(params.SplineIntercepts[j])
		for i := 0; i < n; i++ {
			// Ring multiply WITHOUT truncation (accumulate in double-FP)
			aSlope0[i] = ring.Add(aSlope0[i], modMulBig63(slopeFP, subInd0[j][i], ring.Modulus))
			aSlope1[i] = ring.Add(aSlope1[i], modMulBig63(slopeFP, subInd1[j][i], ring.Modulus))
			bIntercept0[i] = ring.Add(bIntercept0[i], modMulBig63(interceptFP, subInd0[j][i], ring.Modulus))
			bIntercept1[i] = ring.Add(bIntercept1[i], modMulBig63(interceptFP, subInd1[j][i], ring.Modulus))
		}
	}

	// SINGLE truncation: divide by FracMul to go from double-FP back to FP
	divisor := ring.FracMul
	for i := 0; i < n; i++ {
		aSlope0[i] = TruncateSharePartyZero([]uint64{aSlope0[i]}, divisor, ring.Modulus)[0]
		aSlope1[i] = TruncateSharePartyOne([]uint64{aSlope1[i]}, divisor, ring.Modulus)[0]
		bIntercept0[i] = TruncateSharePartyZero([]uint64{bIntercept0[i]}, divisor, ring.Modulus)[0]
		bIntercept1[i] = TruncateSharePartyOne([]uint64{bIntercept1[i]}, divisor, ring.Modulus)[0]
	}

	// Hadamard: [a_t * x] = Beaver([a_t], [x])
	t0, t1 := SampleBeaverTripleVector(n, ring)
	st0, msg0 := GenerateBatchedMultiplicationGateMessage(aSlope0, x0, t0, ring)
	st1, msg1 := GenerateBatchedMultiplicationGateMessage(aSlope1, x1, t1, ring)
atx0, atx1 := StochasticHadamardProduct(st0, t0, msg1, st1, t1, msg0, ring.FracBits, ring)

	// Result: [a_t * x + b_t]
	res0 = make([]uint64, n); res1 = make([]uint64, n)
	for i := 0; i < n; i++ {
		res0[i] = ring.Add(atx0[i], bIntercept0[i])
		res1[i] = ring.Add(atx1[i], bIntercept1[i])
	}
	return
}

// evalExpTaylorOnShares computes exp(x) then Taylor 1/(1+z) on shares.
// x should be negative (so exp(x) is small and Taylor converges).
func evalExpTaylorOnShares(ring Ring63, x0, x1 []uint64) (res0, res1 []uint64) {
	// Kelkar exp on shares — use the ring's fracBits
	cfg := ExpConfig{Ring: ring, ExponentBound: 3, PrimeQ: 2305843009213693951}
	z0, z1 := SecureExpKelkar(cfg, x0, x1)

	// Taylor polynomial: 1/(1+z) = sum_{k=0}^{10} (-1)^k * z^k
	taylorCoeffs := make([]float64, 11)
	for k := 0; k <= 10; k++ {
		if k%2 == 0 {
			taylorCoeffs[k] = 1.0
		} else {
			taylorCoeffs[k] = -1.0
		}
	}

	// SecurePolyEval using the mhe-tool's implementation
	res0, res1 = securePolyEvalLocal(ring, taylorCoeffs, z0, z1)
	return
}

// securePolyEvalLocal evaluates a polynomial on secret shares using Beaver powers.
// Matches the mhe-tool's mpc_beaver.go handleMpcSecurePolyEval logic.
func securePolyEvalLocal(ring Ring63, coeffs []float64, x0, x1 []uint64) (p0, p1 []uint64) {
	n := len(x0)
	degree := len(coeffs) - 1

	// Build power shares: powers[k] = x^k for k=0..degree
	pow0 := make([][]uint64, degree+1); pow1 := make([][]uint64, degree+1)

	// x^0: party 0 = 1 (FP), party 1 = 0
	pow0[0] = make([]uint64, n); pow1[0] = make([]uint64, n)
	oneFP := ring.FromDouble(1.0)
	for i := range pow0[0] { pow0[0][i] = oneFP }

	// x^1 = x
	pow0[1] = make([]uint64, n); pow1[1] = make([]uint64, n)
	copy(pow0[1], x0); copy(pow1[1], x1)

	// Higher powers via Beaver
	for k := 2; k <= degree; k++ {
		a, b := k/2, k-k/2
		if k%2 != 0 { a, b = k-1, 1 }
		t0, t1 := SampleBeaverTripleVector(n, ring)
		st0, msg0 := GenerateBatchedMultiplicationGateMessage(pow0[a], pow0[b], t0, ring)
		st1, msg1 := GenerateBatchedMultiplicationGateMessage(pow1[a], pow1[b], t1, ring)
pow0[k], pow1[k] = StochasticHadamardProduct(st0, t0, msg1, st1, t1, msg0, ring.FracBits, ring)
	}

	// DEFERRED TRUNCATION for linear combination: p(x) = sum_k c_k * x^k
	// Accumulate ring products WITHOUT truncation, truncate ONCE at the end.
	// Reduces 11 truncations to 1.
	p0 = make([]uint64, n); p1 = make([]uint64, n)
	for k := 0; k <= degree; k++ {
		coeffFP := ring.FromDouble(coeffs[k])
		for i := 0; i < n; i++ {
			// Ring multiply WITHOUT truncation
			p0[i] = ring.Add(p0[i], modMulBig63(coeffFP, pow0[k][i], ring.Modulus))
			p1[i] = ring.Add(p1[i], modMulBig63(coeffFP, pow1[k][i], ring.Modulus))
		}
	}
	// Single truncation
	divisor := ring.FracMul
	for i := 0; i < n; i++ {
		p0[i] = TruncateSharePartyZero([]uint64{p0[i]}, divisor, ring.Modulus)[0]
		p1[i] = TruncateSharePartyOne([]uint64{p1[i]}, divisor, ring.Modulus)[0]
	}
	return
}
