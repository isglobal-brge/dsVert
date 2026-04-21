// k2_recip127_e2e_test.go — end-to-end simulation of the R-orchestrated
// Chebyshev + NR recip path for Ring127.
//
// Mirrors the exp-client E2E test (k2_exp127_e2e_test.go): every step
// done by dsVertClient:::.recip127_round is reproduced on simulated
// 2-party Ring127 shares, using the same `simulateBeaverVecmul` and
// `simulateAffineCombine` helpers. Correctness is proven by:
//
//   1. Bit-identical reconstruction vs Ring127RecipChebPlaintext — any
//      sign / coefficient-index / slot-rotation bug in the R client
//      would surface here.
//   2. Rel error vs math.1/x on the Cox S(t) range (NCCTG S in [5,
//      1500] plus broader [1, 3000] for margin).
//
// Because Beaver is exactly multiplicative on shares
// (simulateBeaverVecmul uses true-product + fresh-mask re-split), the
// protocol output is arithmetically identical to the plaintext primitive.

package main

import (
	"math"
	"testing"
)

// TestRecip127EndToEnd_Orchestration exercises the full Chebyshev +
// NR sequence across a grid spanning [1, 3000]. Validates that party0
// + party1 shares reconstruct 1/x to Ring127 ULP precision after the
// 6-iter NR refinement.
func TestRecip127EndToEnd_Orchestration(t *testing.T) {
	r := NewRing127(50)
	coeffs, oneOverHalfRange, negMidOverHalfRange, degree :=
		Ring127RecipChebCoeffsFP(r)
	twoFp := r.FromDouble(2.0)

	xs := []float64{
		Ring127RecipChebXMin, 3.0, 5.0, 17.0, 60.0, 200.0,
		500.0, 1000.0, 1500.0, 2500.0, Ring127RecipChebXMax,
	}
	n := len(xs)

	// Split each x into two-party shares with per-index masks.
	x0 := make([]Uint128, n)
	x1 := make([]Uint128, n)
	for i, v := range xs {
		vRing := r.FromDouble(v)
		mask := Uint128{Lo: uint64(i*37 + 11)}.ModPow127()
		x0[i] = mask
		x1[i] = r.Sub(vRing, mask)
	}

	// Step A1: tPre = x · (1/halfRange)  (local TruncMulSigned each party).
	tPre0 := make([]Uint128, n)
	tPre1 := make([]Uint128, n)
	for i := 0; i < n; i++ {
		tPre0[i] = r.TruncMulSigned(x0[i], oneOverHalfRange)
		tPre1[i] = r.TruncMulSigned(x1[i], oneOverHalfRange)
	}
	// Step A2: t = tPre + (-mid/halfRange) on party 0 only.
	t0 := simulateAffineCombine(r, tPre0, +1, nil, 0,
		&negMidOverHalfRange, true, n)
	t1 := simulateAffineCombine(r, tPre1, +1, nil, 0,
		&negMidOverHalfRange, false, n)

	// Step B: twoT = t + t.
	twoT0 := simulateAffineCombine(r, t0, +1, t0, +1, nil, true, n)
	twoT1 := simulateAffineCombine(r, t1, +1, t1, +1, nil, false, n)

	// Step C: bootstrap b_N = c_N (party0), b_{N+1} = 0.
	cN := coeffs[degree]
	bB_0 := simulateAffineCombine(r, nil, 0, nil, 0, &cN, true, n)
	bB_1 := simulateAffineCombine(r, nil, 0, nil, 0, nil, false, n)
	bA_0 := simulateAffineCombine(r, nil, 0, nil, 0, nil, true, n)
	bA_1 := simulateAffineCombine(r, nil, 0, nil, 0, nil, false, n)

	// Step D: Horner loop.
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
	// slot_B = b_1, slot_A = b_2.
	var sB0, sB1, sA0, sA1 []Uint128
	if !slotBIsBA {
		sB0, sB1, sA0, sA1 = bB_0, bB_1, bA_0, bA_1
	} else {
		sB0, sB1, sA0, sA1 = bA_0, bA_1, bB_0, bB_1
	}

	// Step E: y_0 = c_0 + t · b_1 − b_2.
	tmp0, tmp1 := simulateBeaverVecmul(r, t0, t1, sB0, sB1, 0x7aa1c011)
	c0 := coeffs[0]
	y0_0 := simulateAffineCombine(r, tmp0, +1, sA0, -1, &c0, true, n)
	y0_1 := simulateAffineCombine(r, tmp1, +1, sA1, -1, nil, false, n)

	// Step F: 6 NR iters  y ← y · (2 − x · y).
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

	// Reconstruct and compare to math and to the plaintext primitive.
	for i, xv := range xs {
		muRing := r.Add(yCur0[i], yCur1[i])
		got := r.ToDouble(muRing)
		want := 1.0 / xv
		rel := math.Abs(got-want) / want
		if rel > 5e-12 {
			t.Errorf("E2E 1/%g: got %g want %g rel=%e (threshold 5e-12)",
				xv, got, want, rel)
		}
	}
}

// TestRecip127EndToEnd_MatchesPlaintext proves the two-party simulated
// orchestration is BIT-IDENTICAL to Ring127RecipChebPlaintext. Since
// simulateBeaverVecmul preserves exact products (Beaver is exactly
// multiplicative on shares), any bit difference between this test and
// the plaintext primitive is a protocol bug — wrong sign, wrong index,
// wrong iter count, etc.
func TestRecip127EndToEnd_MatchesPlaintext(t *testing.T) {
	r := NewRing127(50)
	coeffs, oneOverHalfRange, negMidOverHalfRange, degree :=
		Ring127RecipChebCoeffsFP(r)
	twoFp := r.FromDouble(2.0)

	x := 17.29
	xRing := r.FromDouble(x)
	x0 := []Uint128{Uint128{Lo: 0xdec0de}.ModPow127()}
	x1 := []Uint128{r.Sub(xRing, x0[0])}
	n := 1

	// Full orchestration, single-element version (same sequence as above,
	// collapsed for brevity).
	tPre0 := []Uint128{r.TruncMulSigned(x0[0], oneOverHalfRange)}
	tPre1 := []Uint128{r.TruncMulSigned(x1[0], oneOverHalfRange)}
	t0 := simulateAffineCombine(r, tPre0, +1, nil, 0,
		&negMidOverHalfRange, true, n)
	t1 := simulateAffineCombine(r, tPre1, +1, nil, 0,
		&negMidOverHalfRange, false, n)
	twoT0 := simulateAffineCombine(r, t0, +1, t0, +1, nil, true, n)
	twoT1 := simulateAffineCombine(r, t1, +1, t1, +1, nil, false, n)

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
		tmp0, tmp1 := simulateBeaverVecmul(r, twoT0, twoT1, sB0, sB1,
			uint64(k*131))
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
	tmp0, tmp1 := simulateBeaverVecmul(r, t0, t1, sB0, sB1, 0x5a7e)
	c0 := coeffs[0]
	y0_0 := simulateAffineCombine(r, tmp0, +1, sA0, -1, &c0, true, n)
	y0_1 := simulateAffineCombine(r, tmp1, +1, sA1, -1, nil, false, n)
	yCur0, yCur1 := y0_0, y0_1
	for iter := 0; iter < Ring127RecipChebNRSteps; iter++ {
		xy0, xy1 := simulateBeaverVecmul(r, x0, x1, yCur0, yCur1,
			uint64(0x1000+iter))
		tmxy0 := simulateAffineCombine(r, nil, 0, xy0, -1, &twoFp, true, n)
		tmxy1 := simulateAffineCombine(r, nil, 0, xy1, -1, nil, false, n)
		yNew0, yNew1 := simulateBeaverVecmul(r, yCur0, yCur1, tmxy0, tmxy1,
			uint64(0x2000+iter))
		yCur0, yCur1 = yNew0, yNew1
	}
	orchResult := r.Add(yCur0[0], yCur1[0])

	plaintextResult := Ring127RecipChebPlaintext(r, xRing)

	if orchResult != plaintextResult {
		gotF := r.ToDouble(orchResult)
		wantF := r.ToDouble(plaintextResult)
		t.Errorf("orchestration vs plaintext mismatch at x=%g: "+
			"got %g want %g (rel %e)",
			x, gotF, wantF, math.Abs(gotF-wantF)/math.Abs(wantF))
	}
}
