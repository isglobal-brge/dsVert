// k2_sigmoid_e2e_test.go — D1 PHASE-0 micro-diagnostic: end-to-end
// composition of the share-domain sigmoid pipeline σ(η) = 1/(1+exp(-η))
// over a grid η ∈ [-8, 8], measured against the math.Exp ground truth.
//
// Purpose: PHASE-0 D1 from docs/error_bounds/strict_rd_ranking_2026-04-27.md.
// The previous-session diagnosis attributed the observed 5e-5 abs β floor on
// #A ord_joint and #D Cox to "Chebyshev sigmoid bias". The existing
// k2_exp127_test.go and k2_recip127_cheb_test.go test gates already prove
// the σ pipeline is at ≤6e-12 rel in plaintext-equivalent share-domain
// composition (per the documented "simulateBeaverVecmul preserves exact
// products" invariant in k2_recip127_e2e_test.go:137-141). This file makes
// the COMPOSED σ measurement explicit in one place, on a 1000-point
// uniform grid, so the empirical bound can be cited as "we measured it"
// rather than "it follows from algebra over the two upstream test gates".
//
// If this test PASSES at ≤1e-10 abs uniformly on [-8, 8], hypothesis (H1)
// from the ranking doc is FALSIFIED — the share-domain σ pipeline is NOT
// the floor — and PHASE 1 should focus on (H2) Newton conditioning amplifier
// or (H3) Hessian assembly noise rather than ring/spline rewrite.
//
// If this test FAILS at some η bucket with abs ≥ 1e-5, (H1) is confirmed
// and PHASE 1 = option (b) piecewise-spline targeted at that specific
// bucket, per Cody-Hillstrom 1973 + Mächler 2012 nmath/plogis.c precedent.
//
// References:
//   Catrina-Saxena 2010 §3.3 fixed-point κ=40 statistical security floor
//   Trefethen ATAP 2013 §8 Chebyshev coefficient growth
//   Demmler-ABY 2015 §III.B K=2 OT-Beaver disclosure model

package main

import (
	"math"
	"testing"
)

// simExpExtendedShares mirrors dsVertClient:::.ring127_exp_round_keyed_extended
// over simulated 2-party Ring127 shares: scale eta by 1/2 locally, run the
// degree-30 Clenshaw Horner core on the half-input via simulateBeaverVecmul,
// then square via one final Beaver vecmul (exp(eta) = exp(eta/2)^2). Returns
// (out0, out1) shares of exp(eta).
//
// Step-by-step identical to TestExp127EndToEnd_Orchestration:77-152 except
// the input is eta/2 (locally scaled) and the output is squared at the end.
func simExpExtendedShares(r Ring127, eta0, eta1 []Uint128) (out0, out1 []Uint128) {
	n := len(eta0)
	half := r.FromDouble(0.5)

	// Step 1: halfEta = eta · 0.5 (local TruncMulSigned each party).
	halfEta0 := make([]Uint128, n)
	halfEta1 := make([]Uint128, n)
	for i := 0; i < n; i++ {
		halfEta0[i] = r.TruncMulSigned(eta0[i], half)
		halfEta1[i] = r.TruncMulSigned(eta1[i], half)
	}

	// Step 2: run the [-5, 5] Clenshaw Horner on halfEta.
	expHalf0, expHalf1 := simExpClenshawShares(r, halfEta0, halfEta1)

	// Step 3: square — exp(eta) = exp(eta/2) · exp(eta/2).
	out0, out1 = simulateBeaverVecmul(r, expHalf0, expHalf1, expHalf0, expHalf1,
		0xe0e1e2e3)
	return
}

// simExpClenshawShares is the [-5, 5] interior Clenshaw Horner over shares.
// Mirror of TestExp127EndToEnd_Orchestration:77-152 step-by-step.
func simExpClenshawShares(r Ring127, eta0, eta1 []Uint128) (out0, out1 []Uint128) {
	n := len(eta0)
	oneOverA, coeffs, degree := Ring127ExpCoeffsFP(r)

	// y = eta · (1/a)
	y0 := make([]Uint128, n)
	y1 := make([]Uint128, n)
	for i := 0; i < n; i++ {
		y0[i] = r.TruncMulSigned(eta0[i], oneOverA)
		y1[i] = r.TruncMulSigned(eta1[i], oneOverA)
	}
	twoY0 := simulateAffineCombine(r, y0, +1, y0, +1, nil, true, n)
	twoY1 := simulateAffineCombine(r, y1, +1, y1, +1, nil, false, n)

	cN := coeffs[degree]
	bB_0 := simulateAffineCombine(r, nil, 0, nil, 0, &cN, true, n)
	bB_1 := simulateAffineCombine(r, nil, 0, nil, 0, nil, false, n)
	bA_0 := simulateAffineCombine(r, nil, 0, nil, 0, nil, true, n)
	bA_1 := simulateAffineCombine(r, nil, 0, nil, 0, nil, false, n)

	slotBIsBA := false
	for k := degree - 1; k >= 1; k-- {
		var sB0, sB1, sA0, sA1 []Uint128
		if !slotBIsBA {
			sB0, sB1, sA0, sA1 = bB_0, bB_1, bA_0, bA_1
		} else {
			sB0, sB1, sA0, sA1 = bA_0, bA_1, bB_0, bB_1
		}
		tmp0, tmp1 := simulateBeaverVecmul(r, twoY0, twoY1, sB0, sB1,
			uint64(k*101+17))
		cK := coeffs[k]
		new_sA0 := simulateAffineCombine(r, tmp0, +1, sA0, -1, &cK, true, n)
		new_sA1 := simulateAffineCombine(r, tmp1, +1, sA1, -1, nil, false, n)
		if !slotBIsBA {
			bA_0, bA_1 = new_sA0, new_sA1
		} else {
			bB_0, bB_1 = new_sA0, new_sA1
		}
		slotBIsBA = !slotBIsBA
	}
	var sB0, sB1, sA0, sA1 []Uint128
	if !slotBIsBA {
		sB0, sB1, sA0, sA1 = bB_0, bB_1, bA_0, bA_1
	} else {
		sB0, sB1, sA0, sA1 = bA_0, bA_1, bB_0, bB_1
	}
	tmp0, tmp1 := simulateBeaverVecmul(r, y0, y1, sB0, sB1, 0xdeadbeef)
	c0 := coeffs[0]
	out0 = simulateAffineCombine(r, tmp0, +1, sA0, -1, &c0, true, n)
	out1 = simulateAffineCombine(r, tmp1, +1, sA1, -1, nil, false, n)
	return
}

// simRecipChebShares mirrors dsVertClient:::.ring127_recip_round_keyed
// (Chebyshev + NR). Mirror of TestRecip127EndToEnd_Orchestration:30-122.
func simRecipChebShares(r Ring127, x0, x1 []Uint128) (out0, out1 []Uint128) {
	n := len(x0)
	coeffs, oneOverHalfRange, negMidOverHalfRange, degree :=
		Ring127RecipChebCoeffsFP(r)
	twoFp := r.FromDouble(2.0)

	tPre0 := make([]Uint128, n)
	tPre1 := make([]Uint128, n)
	for i := 0; i < n; i++ {
		tPre0[i] = r.TruncMulSigned(x0[i], oneOverHalfRange)
		tPre1[i] = r.TruncMulSigned(x1[i], oneOverHalfRange)
	}
	t0 := simulateAffineCombine(r, tPre0, +1, nil, 0,
		&negMidOverHalfRange, true, n)
	t1 := simulateAffineCombine(r, tPre1, +1, nil, 0,
		&negMidOverHalfRange, false, n)
	twoT0 := simulateAffineCombine(r, t0, +1, t0, +1, nil, true, n)
	twoT1 := simulateAffineCombine(r, t1, +1, t1, +1, nil, false, n)

	cN := coeffs[degree]
	bB_0 := simulateAffineCombine(r, nil, 0, nil, 0, &cN, true, n)
	bB_1 := simulateAffineCombine(r, nil, 0, nil, 0, nil, false, n)
	bA_0 := simulateAffineCombine(r, nil, 0, nil, 0, nil, true, n)
	bA_1 := simulateAffineCombine(r, nil, 0, nil, 0, nil, false, n)

	slotBIsBA := false
	for k := degree - 1; k >= 1; k-- {
		var sB0, sB1, sA0, sA1 []Uint128
		if !slotBIsBA {
			sB0, sB1, sA0, sA1 = bB_0, bB_1, bA_0, bA_1
		} else {
			sB0, sB1, sA0, sA1 = bA_0, bA_1, bB_0, bB_1
		}
		tmp0, tmp1 := simulateBeaverVecmul(r, twoT0, twoT1, sB0, sB1,
			uint64(k*131+29))
		cK := coeffs[k]
		new_sA0 := simulateAffineCombine(r, tmp0, +1, sA0, -1, &cK, true, n)
		new_sA1 := simulateAffineCombine(r, tmp1, +1, sA1, -1, nil, false, n)
		if !slotBIsBA {
			bA_0, bA_1 = new_sA0, new_sA1
		} else {
			bB_0, bB_1 = new_sA0, new_sA1
		}
		slotBIsBA = !slotBIsBA
	}
	var sB0, sB1, sA0, sA1 []Uint128
	if !slotBIsBA {
		sB0, sB1, sA0, sA1 = bB_0, bB_1, bA_0, bA_1
	} else {
		sB0, sB1, sA0, sA1 = bA_0, bA_1, bB_0, bB_1
	}
	tmp0, tmp1 := simulateBeaverVecmul(r, t0, t1, sB0, sB1, 0x7aa1c011)
	c0 := coeffs[0]
	y0_0 := simulateAffineCombine(r, tmp0, +1, sA0, -1, &c0, true, n)
	y0_1 := simulateAffineCombine(r, tmp1, +1, sA1, -1, nil, false, n)

	yCur0, yCur1 := y0_0, y0_1
	for iter := 0; iter < Ring127RecipChebNRSteps; iter++ {
		xy0, xy1 := simulateBeaverVecmul(r, x0, x1, yCur0, yCur1,
			uint64(0xc0de+iter*97))
		tmxy0 := simulateAffineCombine(r, nil, 0, xy0, -1, &twoFp, true, n)
		tmxy1 := simulateAffineCombine(r, nil, 0, xy1, -1, nil, false, n)
		yNew0, yNew1 := simulateBeaverVecmul(r, yCur0, yCur1, tmxy0, tmxy1,
			uint64(0xbeef+iter*53))
		yCur0, yCur1 = yNew0, yNew1
	}
	out0, out1 = yCur0, yCur1
	return
}

// TestSigmoidE2E_Grid_PhaseD1 is the PHASE-0 D1 micro-diagnostic. Composes
// share-domain σ(η) = 1/(1+exp(-η)) on η ∈ [-8, 8] (the production envelope
// where both exp_extended and recip_cheb are in-domain) and measures abs/rel
// error vs the math ground truth on a 401-point grid (step 0.04).
//
// Domain rationale:
//   - exp_extended valid on |η| ≤ 8 (Ring127ExpExtendedDomainA).
//   - recip_cheb valid on x ∈ [1, 3000] (Ring127RecipChebXMin/Max). For
//     x = 1 + exp(-η), η ∈ [-8, 8] gives x ∈ [1.000335, 2981.96] — fully
//     inside [1, 3000].
//
// Bucketed report: maximum abs error per η bucket (width 1.0 each from -8
// to +8). This makes the diagnostic directly comparable to the alleged
// "5e-5 absolute on σ(η)" floor from the previous-session diagnosis. If
// any bucket shows abs ≥ 1e-5, (H1) is confirmed. If all buckets are at
// ≤ 1e-10, (H1) is falsified and the β floor must come from (H2) Newton
// conditioning amplifier or (H3) Hessian assembly Beaver chain.
func TestSigmoidE2E_Grid_PhaseD1(t *testing.T) {
	r := NewRing127(50)

	const (
		etaMin = -8.0
		etaMax = 8.0
		step   = 0.04
	)
	nGrid := int((etaMax-etaMin)/step) + 1
	etas := make([]float64, nGrid)
	for i := 0; i < nGrid; i++ {
		etas[i] = etaMin + float64(i)*step
	}

	// Encode each η as Ring127 FP and split into two-party shares.
	eta0 := make([]Uint128, nGrid)
	eta1 := make([]Uint128, nGrid)
	for i, eta := range etas {
		etaRing := r.FromDouble(eta)
		mask := Uint128{Lo: uint64(i*23 + 5)}.ModPow127()
		eta0[i] = mask
		eta1[i] = r.Sub(etaRing, mask)
	}

	// Step 1: negate to get -η in shares.
	negEta0 := make([]Uint128, nGrid)
	negEta1 := make([]Uint128, nGrid)
	for i := 0; i < nGrid; i++ {
		negEta0[i] = r.Neg(eta0[i])
		negEta1[i] = r.Neg(eta1[i])
	}

	// Step 2: exp(-η) in shares via the extended-domain pipeline.
	exp0, exp1 := simExpExtendedShares(r, negEta0, negEta1)

	// Step 3: 1 + exp(-η) — affine combine adds public 1.0 on party 0.
	one := r.FromDouble(1.0)
	denom0 := simulateAffineCombine(r, exp0, +1, nil, 0, &one, true, nGrid)
	denom1 := simulateAffineCombine(r, exp1, +1, nil, 0, nil, false, nGrid)

	// Step 4: 1 / (1 + exp(-η)) via Cheb + NR recip pipeline.
	sig0, sig1 := simRecipChebShares(r, denom0, denom1)

	// Reconstruct and bucket-report.
	const nBuckets = 16 // bucket width 1.0 from η = -8 to +8
	bucketMaxAbs := make([]float64, nBuckets)
	bucketMaxRel := make([]float64, nBuckets)
	bucketCount := make([]int, nBuckets)
	var globalMaxAbs, globalMaxRel float64
	var globalMaxAbsEta, globalMaxRelEta float64

	for i, eta := range etas {
		got := r.ToDouble(r.Add(sig0[i], sig1[i]))
		want := 1.0 / (1.0 + math.Exp(-eta))
		abs := math.Abs(got - want)
		rel := abs / math.Min(want, 1.0-want) // rel to the smaller of σ or 1-σ (worst case)
		bucketIdx := int(math.Min(math.Floor(eta-etaMin), float64(nBuckets-1)))
		if bucketIdx < 0 {
			bucketIdx = 0
		}
		if abs > bucketMaxAbs[bucketIdx] {
			bucketMaxAbs[bucketIdx] = abs
		}
		if rel > bucketMaxRel[bucketIdx] {
			bucketMaxRel[bucketIdx] = rel
		}
		bucketCount[bucketIdx]++
		if abs > globalMaxAbs {
			globalMaxAbs = abs
			globalMaxAbsEta = eta
		}
		if rel > globalMaxRel {
			globalMaxRel = rel
			globalMaxRelEta = eta
		}
	}

	t.Logf("=== PHASE-0 D1 sigmoid e2e on η ∈ [%g, %g], step %g (%d points) ===",
		etaMin, etaMax, step, nGrid)
	t.Logf("Per-bucket abs/rel max:")
	for b := 0; b < nBuckets; b++ {
		bLo := etaMin + float64(b)
		bHi := bLo + 1.0
		t.Logf("  η ∈ [%+.0f, %+.0f] (n=%d): max |σ - σ̂| = %.3e, max rel = %.3e",
			bLo, bHi, bucketCount[b], bucketMaxAbs[b], bucketMaxRel[b])
	}
	t.Logf("Global: max abs = %.3e at η = %+.3f", globalMaxAbs, globalMaxAbsEta)
	t.Logf("Global: max rel = %.3e at η = %+.3f", globalMaxRel, globalMaxRelEta)

	// Decision-gate output for the ranking doc:
	//
	//   PASS ≤ 1e-10 abs uniformly → (H1) FALSIFIED → focus PHASE 1 on
	//                                  (H2)/(H3), NOT ring/spline rewrite.
	//   FAIL with bucket ≥ 1e-5    → (H1) CONFIRMED → PHASE 1 = option (b)
	//                                  piecewise-spline targeted at that
	//                                  specific bucket.
	//   middle (1e-10 < g < 1e-5) → "partial" — needs D2/D3 to disambiguate
	//                                  the amplifier.
	//
	// Threshold 1e-10 is 100× above the theoretical Ring127 fracBits=50
	// floor (≈9e-16 absolute) and 5 orders below the alleged 5e-5 floor
	// from the previous-session diagnosis — clean signal either way.
	const decisionThreshold = 1e-10
	if globalMaxAbs > decisionThreshold {
		t.Logf("DIAGNOSTIC: max abs %.3e > %e → (H1) candidate, share-domain σ contributes ≥%e",
			globalMaxAbs, decisionThreshold, decisionThreshold)
	} else {
		t.Logf("DIAGNOSTIC: max abs %.3e ≤ %e → (H1) FALSIFIED, σ pipeline is NOT the floor",
			globalMaxAbs, decisionThreshold)
	}

	// Hard test gate: alert at the alleged 5e-5 level, since a regression
	// past that would mean we've lost what already works.
	const hardGate = 5e-5
	if globalMaxAbs > hardGate {
		t.Errorf("REGRESSION: max abs %.3e > hard gate %e — share-domain σ pipeline degraded",
			globalMaxAbs, hardGate)
	}
}
