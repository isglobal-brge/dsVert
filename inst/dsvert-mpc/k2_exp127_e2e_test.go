// k2_exp127_e2e_test.go — end-to-end simulation of the R-orchestrated
// Chebyshev Horner path for Ring127 exp.
//
// The test mirrors, step-by-step, what `dsVertClient:::.exp127_round`
// does in production: local scale for y = eta · (1/a), local affine for
// twoY, bootstrap of Clenshaw shares, Horner loop with a "Beaver vecmul"
// that is simulated as (true-mul + fresh random mask split), and the
// final y · b_1 + c_0 − b_2 assembly. Two-party correctness is checked by
// reconstructing the output shares and comparing with math.Exp at rel
// <1e-12 across the NCCTG eta range.
//
// This is the protocol-level validation promised by 5c(I-c-5): any
// orchestration-level bug in the R client (wrong sign, wrong coefficient
// index, mis-ordered slot rotation) would show up here.

package main

import (
	"math"
	"testing"
)

// simulateBeaverVecmul: Beaver exactly computes shares of the true
// element-wise product, so for protocol-correctness tests we just compute
// the plaintext product and re-split with a fresh mask. Real Beaver adds
// randomness + rounds but semantically matches this.
func simulateBeaverVecmul(r Ring127, a0, a1, b0, b1 []Uint128,
	maskSeed uint64) (out0, out1 []Uint128) {
	n := len(a0)
	out0 = make([]Uint128, n)
	out1 = make([]Uint128, n)
	for i := 0; i < n; i++ {
		aTrue := r.Add(a0[i], a1[i])
		bTrue := r.Add(b0[i], b1[i])
		prod := r.TruncMulSigned(aTrue, bTrue)
		mask := Uint128{Lo: maskSeed + uint64(i)*131 + 7}.ModPow127()
		out0[i] = mask
		out1[i] = r.Sub(prod, mask)
	}
	return
}

// simulateAffineCombine: party-side local combine identical to what
// handleK2Ring127AffineCombine does. Invoked per-party.
func simulateAffineCombine(r Ring127, a []Uint128, signA int,
	b []Uint128, signB int, publicConst *Uint128, isParty0 bool,
	n int) []Uint128 {
	out := make([]Uint128, n)
	for i := 0; i < n; i++ {
		var ta, tb Uint128
		switch signA {
		case 1:
			ta = a[i]
		case -1:
			ta = r.Neg(a[i])
		}
		switch signB {
		case 1:
			tb = b[i]
		case -1:
			tb = r.Neg(b[i])
		}
		s := r.Add(ta, tb)
		if isParty0 && publicConst != nil {
			s = r.Add(s, *publicConst)
		}
		out[i] = s
	}
	return out
}

// TestExp127EndToEnd_Orchestration: full R-client Horner sequence
// reproduced in Go over simulated two-party Ring127 shares. Validates
// that the sign conventions, coefficient indexing, slot rotation, and
// bootstrap steps in `.exp127_round` reconstruct exp(eta) at Ring127
// ULP precision.
func TestExp127EndToEnd_Orchestration(t *testing.T) {
	r := NewRing127(50)
	oneOverA, coeffs, degree := Ring127ExpCoeffsFP(r)

	// NCCTG eta range + a few values outside the typical oracle-β span
	// so we cover boundary / mid / extreme.
	etas := []float64{-3.5, -2.0, -0.5, -0.01, 0.0, 0.01, 0.5, 2.0, 3.5}
	n := len(etas)

	// Encode eta values as Ring127 FP and split into two-party shares.
	eta0 := make([]Uint128, n)
	eta1 := make([]Uint128, n)
	for i, x := range etas {
		xRing := r.FromDouble(x)
		mask := Uint128{Lo: uint64(i*17 + 3)}.ModPow127()
		eta0[i] = mask
		eta1[i] = r.Sub(xRing, mask)
	}

	// --- Step 2: y = eta · (1/a)  (local scale; TruncMulSigned per element).
	y0 := make([]Uint128, n)
	y1 := make([]Uint128, n)
	for i := 0; i < n; i++ {
		y0[i] = r.TruncMulSigned(eta0[i], oneOverA)
		y1[i] = r.TruncMulSigned(eta1[i], oneOverA)
	}

	// --- Step 3: twoY = y + y (affine sign_a=+1 sign_b=+1).
	twoY0 := simulateAffineCombine(r, y0, +1, y0, +1, nil, true, n)
	twoY1 := simulateAffineCombine(r, y1, +1, y1, +1, nil, false, n)

	// --- Step 4: bootstrap b_N (party0: c_N, party1: 0) + b_{N+1} = 0.
	cN := coeffs[degree]
	bB_0 := simulateAffineCombine(r, nil, 0, nil, 0, &cN, true, n)
	bB_1 := simulateAffineCombine(r, nil, 0, nil, 0, nil, false, n)
	bA_0 := simulateAffineCombine(r, nil, 0, nil, 0, nil, true, n)
	bA_1 := simulateAffineCombine(r, nil, 0, nil, 0, nil, false, n)

	// --- Step 5: Horner loop k = N-1 downto 1.
	slotB_is_bA := false // false → slot_B is bB_*, slot_A is bA_*; true → swapped.
	for k := degree - 1; k >= 1; k-- {
		var sB0, sB1, sA0, sA1 []Uint128
		if !slotB_is_bA {
			sB0, sB1, sA0, sA1 = bB_0, bB_1, bA_0, bA_1
		} else {
			sB0, sB1, sA0, sA1 = bA_0, bA_1, bB_0, bB_1
		}
		// Beaver(twoY, slot_B) → tmp (shares of twoY * b_{k+1}).
		tmp0, tmp1 := simulateBeaverVecmul(r, twoY0, twoY1, sB0, sB1,
			uint64(k*101+17))
		// b_k = tmp + c_k_party0 − slot_A, store into slot_A.
		cK := coeffs[k]
		new_sA0 := simulateAffineCombine(r, tmp0, +1, sA0, -1, &cK, true, n)
		new_sA1 := simulateAffineCombine(r, tmp1, +1, sA1, -1, nil, false, n)
		if !slotB_is_bA {
			bA_0, bA_1 = new_sA0, new_sA1
		} else {
			bB_0, bB_1 = new_sA0, new_sA1
		}
		// Swap slot labels: previous slot_A (now holding b_k) becomes slot_B.
		slotB_is_bA = !slotB_is_bA
	}

	// Post-loop: slot_B holds b_1, slot_A holds b_2.
	var sB0, sB1, sA0, sA1 []Uint128
	if !slotB_is_bA {
		sB0, sB1, sA0, sA1 = bB_0, bB_1, bA_0, bA_1
	} else {
		sB0, sB1, sA0, sA1 = bA_0, bA_1, bB_0, bB_1
	}

	// --- Step 6: final y · b_1 → tmp;  result = tmp + c_0_party0 − b_2.
	tmp0, tmp1 := simulateBeaverVecmul(r, y0, y1, sB0, sB1, 0xdeadbeef)
	c0 := coeffs[0]
	mu0 := simulateAffineCombine(r, tmp0, +1, sA0, -1, &c0, true, n)
	mu1 := simulateAffineCombine(r, tmp1, +1, sA1, -1, nil, false, n)

	// Reconstruct mu = mu0 + mu1 and compare to math.Exp(eta).
	for i, eta := range etas {
		muRing := r.Add(mu0[i], mu1[i])
		got := r.ToDouble(muRing)
		want := math.Exp(eta)
		rel := math.Abs(got-want) / want
		// Same threshold structure as TestRing127Exp_Grid: |eta|<=4 → 1e-12.
		threshold := 1e-12
		if math.Abs(eta) > 4.0 {
			threshold = 1e-11
		}
		if rel > threshold {
			t.Errorf("E2E exp(%g): got %g want %g rel=%e (threshold %e)",
				eta, got, want, rel, threshold)
		}
	}
}

// TestExp127EndToEnd_MatchesPlaintext: the two-party simulated
// orchestration should produce bit-identical output to the plaintext
// Ring127ExpPlaintext when Beaver rounds preserve exact products (which
// they do; simulateBeaverVecmul models this). Sanity check that the
// protocol has no arithmetic discrepancy from Clenshaw.
func TestExp127EndToEnd_MatchesPlaintext(t *testing.T) {
	r := NewRing127(50)
	oneOverA, coeffs, degree := Ring127ExpCoeffsFP(r)

	// Single eta, deterministic shares.
	x := 0.37
	xRing := r.FromDouble(x)
	eta0 := []Uint128{Uint128{Lo: 0x12345}.ModPow127()}
	eta1 := []Uint128{r.Sub(xRing, eta0[0])}
	n := 1

	// Orchestration (same as above, collapsed).
	y0 := []Uint128{r.TruncMulSigned(eta0[0], oneOverA)}
	y1 := []Uint128{r.TruncMulSigned(eta1[0], oneOverA)}
	twoY0 := simulateAffineCombine(r, y0, +1, y0, +1, nil, true, n)
	twoY1 := simulateAffineCombine(r, y1, +1, y1, +1, nil, false, n)
	cN := coeffs[degree]
	bB_0 := simulateAffineCombine(r, nil, 0, nil, 0, &cN, true, n)
	bB_1 := simulateAffineCombine(r, nil, 0, nil, 0, nil, false, n)
	bA_0 := make([]Uint128, n)
	bA_1 := make([]Uint128, n)
	slotBIsBA := false
	for k := degree - 1; k >= 1; k-- {
		var sB0, sB1, sA0, sA1 []Uint128
		if !slotBIsBA {
			sB0, sB1, sA0, sA1 = bB_0, bB_1, bA_0, bA_1
		} else {
			sB0, sB1, sA0, sA1 = bA_0, bA_1, bB_0, bB_1
		}
		tmp0, tmp1 := simulateBeaverVecmul(r, twoY0, twoY1, sB0, sB1,
			uint64(k*101))
		cK := coeffs[k]
		nsA0 := simulateAffineCombine(r, tmp0, +1, sA0, -1, &cK, true, n)
		nsA1 := simulateAffineCombine(r, tmp1, +1, sA1, -1, nil, false, n)
		if !slotBIsBA {
			bA_0, bA_1 = nsA0, nsA1
		} else {
			bB_0, bB_1 = nsA0, nsA1
		}
		slotBIsBA = !slotBIsBA
	}
	var sB0, sB1, sA0, sA1 []Uint128
	if !slotBIsBA {
		sB0, sB1, sA0, sA1 = bB_0, bB_1, bA_0, bA_1
	} else {
		sB0, sB1, sA0, sA1 = bA_0, bA_1, bB_0, bB_1
	}
	tmp0, tmp1 := simulateBeaverVecmul(r, y0, y1, sB0, sB1, 0xabc)
	c0 := coeffs[0]
	mu0 := simulateAffineCombine(r, tmp0, +1, sA0, -1, &c0, true, n)
	mu1 := simulateAffineCombine(r, tmp1, +1, sA1, -1, nil, false, n)
	orchResult := r.Add(mu0[0], mu1[0])

	plaintextResult := Ring127ExpPlaintext(r, xRing)

	if orchResult != plaintextResult {
		gotF := r.ToDouble(orchResult)
		wantF := r.ToDouble(plaintextResult)
		t.Errorf("orchestration vs plaintext mismatch at x=%g: got %g want %g (rel %e)",
			x, gotF, wantF, math.Abs(gotF-wantF)/math.Abs(wantF))
	}
}
