// k2_log_shift_wide_handler_test.go — round-trip + accuracy checks for
// the `k2-log-shift-coeffs-wide` handler.
//
// Wide Chebyshev fit on [0.1, 1000] degree 60 gives initial rel ~30%
// (Bernstein ρ ≈ 1.020 → ρ^-60 ≈ 0.30). This is intentionally loose —
// the NR refinement on shares (Pugh 2004 PhD §3) drives the rel error
// to ULP precision in 5 iterations. Tests check the wide Chebyshev
// reconstruction sits within rel < 1 (i.e., not exploding) across the
// full [0.1, 1000] domain so NR converges from the seed.

package main

import (
	"math"
	"testing"
)

// TestLogShiftWideHandler_B64RoundTrip: encode/decode equality on
// oneOverHalfRange + negMidOverHalfRange + 61 coefficients.
func TestLogShiftWideHandler_B64RoundTrip(t *testing.T) {
	r := NewRing127(K2DefaultFracBits127)
	oneOverHalfWant, _, coeffsWant, degreeWant := Ring127LogShiftWideCoeffsFP(r)
	a := Ring127LogShiftWideMin
	b := Ring127LogShiftWideMax
	negMidOverHalfWant := r.FromDouble(-(a + b) / (b - a))

	oneOverHalfB64 := Uint128VecToB64([]Uint128{oneOverHalfWant})
	negMidOverHalfB64 := Uint128VecToB64([]Uint128{negMidOverHalfWant})
	coeffsB64 := Uint128VecToB64(coeffsWant[:])

	oneOverHalfGot := b64Uint128Vec(oneOverHalfB64)
	negMidOverHalfGot := b64Uint128Vec(negMidOverHalfB64)
	coeffsGot := b64Uint128Vec(coeffsB64)

	if len(oneOverHalfGot) != 1 || oneOverHalfGot[0] != oneOverHalfWant {
		t.Errorf("oneOverHalf roundtrip mismatch")
	}
	if len(negMidOverHalfGot) != 1 || negMidOverHalfGot[0] != negMidOverHalfWant {
		t.Errorf("negMidOverHalf roundtrip mismatch")
	}
	if len(coeffsGot) != degreeWant+1 {
		t.Fatalf("coeffs decode: got len %d, want %d",
			len(coeffsGot), degreeWant+1)
	}
	for k := 0; k <= degreeWant; k++ {
		if coeffsGot[k] != coeffsWant[k] {
			t.Errorf("c_%d roundtrip mismatch", k)
		}
	}
}

// TestLogShiftWideHandler_CoeffsAccuracy: decode + Clenshaw across
// [0.1, 1000] sweep. Wide-domain Bernstein-ellipse rel target < 1
// (initial NR seed; refinement drives to ULP).
func TestLogShiftWideHandler_CoeffsAccuracy(t *testing.T) {
	r := NewRing127(K2DefaultFracBits127)
	oneOverHalf, _, coeffs, degree := Ring127LogShiftWideCoeffsFP(r)
	a := Ring127LogShiftWideMin
	b := Ring127LogShiftWideMax
	negMidOverHalf := r.FromDouble(-(a + b) / (b - a))

	oneOverHalfDec := b64Uint128Vec(Uint128VecToB64([]Uint128{oneOverHalf}))[0]
	negMidOverHalfDec :=
		b64Uint128Vec(Uint128VecToB64([]Uint128{negMidOverHalf}))[0]
	coeffsDec := b64Uint128Vec(Uint128VecToB64(coeffs[:]))

	// Test points across [0.1, 1000] — full operating range for NB
	// full-regression θ MLE. Wide-Chebyshev rel target: < 1 (any
	// initial that lets NR converge in O(log log) iters is OK).
	for _, x := range []float64{
		0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 50.0, 100.0, 200.0, 500.0, 1000.0,
	} {
		xRing := r.FromDouble(x)
		yPre := r.TruncMulSigned(xRing, oneOverHalfDec)
		y := r.Add(yPre, negMidOverHalfDec)

		var bKp1, bKp2 Uint128
		for k := degree; k >= 1; k-- {
			twoY := r.Add(y, y)
			twoYbKp1 := r.TruncMulSigned(twoY, bKp1)
			bK := r.Sub(r.Add(coeffsDec[k], twoYbKp1), bKp2)
			bKp2 = bKp1
			bKp1 = bK
		}
		yb1 := r.TruncMulSigned(y, bKp1)
		result := r.Sub(r.Add(coeffsDec[0], yb1), bKp2)
		got := r.ToDouble(result)
		want := math.Log(x)

		var relErr float64
		if math.Abs(want) < 1e-3 {
			relErr = math.Abs(got - want)
		} else {
			relErr = math.Abs(got-want) / math.Abs(want)
		}
		// NR seed: rel target < 1.0 (within NR basin of attraction).
		// Tighter target < 0.5 confirms the seed is good enough that
		// NR converges in 5 iters per the analysis.
		if relErr > 0.5 {
			t.Errorf("wide-Cheb seed log(%g): got %g want %g rel=%e (NR basin require <0.5)",
				x, got, want, relErr)
		}
	}
}

// TestLogShiftWideHandler_DomainConstants: invariant guards.
func TestLogShiftWideHandler_DomainConstants(t *testing.T) {
	if Ring127LogShiftWideMin != 0.1 {
		t.Errorf("Ring127LogShiftWideMin: got %g want 0.1",
			Ring127LogShiftWideMin)
	}
	if Ring127LogShiftWideMax != 1000.0 {
		t.Errorf("Ring127LogShiftWideMax: got %g want 1000.0",
			Ring127LogShiftWideMax)
	}
	if Ring127LogShiftWideDegree != 60 {
		t.Errorf("Ring127LogShiftWideDegree: got %d want 60",
			Ring127LogShiftWideDegree)
	}
}

// TestLogShiftWide_NRConvergenceAudit: simulates the share-side NR
// refinement plaintext to verify quadratic convergence to ULP.
// Pugh 2004 §3: y_{n+1} = y_n + x·exp(-y_n) - 1 with f(y) = exp(y) - x;
// ε_{n+1} ≈ -ε_n²/2. Starting from rel ~30% wide-Cheb seed, 5 iters
// drive ε to ~10^-27 ≪ ULP 2^-50 ≈ 8.9e-16.
func TestLogShiftWide_NRConvergenceAudit(t *testing.T) {
	r := NewRing127(K2DefaultFracBits127)
	for _, x := range []float64{0.1, 1.0, 10.0, 100.0, 1000.0} {
		xRing := r.FromDouble(x)

		// Initial Cheb seed.
		y := Ring127LogShiftWidePlaintext(r, xRing)

		// 5 NR iters: y_{n+1} = y_n + x·exp(-y_n) - 1
		for iter := 1; iter <= 5; iter++ {
			negY := r.Neg(y)
			expNegYf := math.Exp(r.ToDouble(negY))
			expNegY := r.FromDouble(expNegYf)
			xExpNegY := r.TruncMulSigned(xRing, expNegY)
			one := r.FromDouble(1.0)
			y = r.Sub(r.Add(y, xExpNegY), one)
		}
		got := r.ToDouble(y)
		want := math.Log(x)
		relErr := math.Abs(got-want) / math.Max(math.Abs(want), 1e-3)
		// After 5 NR iters, rel should be ≪ 1e-10 (well below ULP).
		// Loose check: 1e-8 to absorb FP-roundtrip / ToDouble noise.
		if relErr > 1e-8 {
			t.Errorf("NR-LOG plaintext audit log(%g): got %g want %g rel=%e (5 iters)",
				x, got, want, relErr)
		}
	}
}
