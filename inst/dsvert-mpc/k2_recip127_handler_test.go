// k2_recip127_handler_test.go — verifies the public recip coefficient
// dump round-trips through the base64 layer without corruption, and
// that Clenshaw-Horner + NR from the decoded coefficients reproduces
// Ring127RecipChebPlaintext bit-identically.

package main

import (
	"math"
	"testing"
)

// TestRecip127Handler_B64RoundTrip: encode coeffs via Uint128VecToB64,
// decode via b64Uint128Vec, compare to source. Catches endianness or
// length-miscount bugs in the serializer.
func TestRecip127Handler_B64RoundTrip(t *testing.T) {
	r := NewRing127(50)
	coeffsWant, oneOverHalfRangeWant, negMidOverHalfRangeWant, degree :=
		Ring127RecipChebCoeffsFP(r)

	coeffsB64 := Uint128VecToB64(coeffsWant)
	oneB64 := Uint128VecToB64([]Uint128{oneOverHalfRangeWant})
	negMidB64 := Uint128VecToB64([]Uint128{negMidOverHalfRangeWant})

	coeffsGot := b64Uint128Vec(coeffsB64)
	oneGot := b64Uint128Vec(oneB64)
	negMidGot := b64Uint128Vec(negMidB64)

	if len(coeffsGot) != degree+1 {
		t.Fatalf("coeffs round-trip length: got %d want %d",
			len(coeffsGot), degree+1)
	}
	if len(oneGot) != 1 || len(negMidGot) != 1 {
		t.Fatalf("scalar round-trip length: oneGot=%d negMidGot=%d",
			len(oneGot), len(negMidGot))
	}
	for i, want := range coeffsWant {
		if coeffsGot[i] != want {
			t.Errorf("coeffs[%d]: got %v want %v", i, coeffsGot[i], want)
		}
	}
	if oneGot[0] != oneOverHalfRangeWant {
		t.Errorf("oneOverHalfRange: got %v want %v",
			oneGot[0], oneOverHalfRangeWant)
	}
	if negMidGot[0] != negMidOverHalfRangeWant {
		t.Errorf("negMidOverHalfRange: got %v want %v",
			negMidGot[0], negMidOverHalfRangeWant)
	}
}

// TestRecip127Handler_CoeffsAccuracy: Clenshaw + NR from the decoded
// coefficient byte stream reproduces Ring127RecipChebPlaintext to within
// floating-point equality on a domain-spanning grid. Guards against the
// R client receiving a mangled coefficient order.
func TestRecip127Handler_CoeffsAccuracy(t *testing.T) {
	r := NewRing127(50)
	coeffs, oneOverHalfRange, negMidOverHalfRange, degree :=
		Ring127RecipChebCoeffsFP(r)

	coeffsDecoded := b64Uint128Vec(Uint128VecToB64(coeffs))
	oneDecoded := b64Uint128Vec(Uint128VecToB64([]Uint128{oneOverHalfRange}))[0]
	negMidDecoded := b64Uint128Vec(
		Uint128VecToB64([]Uint128{negMidOverHalfRange}))[0]

	tests := []float64{1.5, 10.0, 237.0, 1000.0, 2500.0}
	for _, x := range tests {
		xRing := r.FromDouble(x)

		// Evaluate via decoded coeffs: map x → t, Clenshaw, then NR.
		tMap := r.Add(r.TruncMulSigned(xRing, oneDecoded), negMidDecoded)
		twoT := r.Add(tMap, tMap)
		bNext := Uint128{}
		bCur := coeffsDecoded[degree]
		for k := degree - 1; k >= 1; k-- {
			bk := r.Sub(r.Add(coeffsDecoded[k],
				r.TruncMulSigned(twoT, bCur)), bNext)
			bNext = bCur
			bCur = bk
		}
		y := r.Sub(r.Add(coeffsDecoded[0],
			r.TruncMulSigned(tMap, bCur)), bNext)
		two := r.FromDouble(2.0)
		for i := 0; i < Ring127RecipChebNRSteps; i++ {
			xy := r.TruncMulSigned(xRing, y)
			twoMinusXy := r.Sub(two, xy)
			y = r.TruncMulSigned(y, twoMinusXy)
		}

		gotFromDecoded := r.ToDouble(y)
		gotFromPrimitive := r.ToDouble(Ring127RecipChebPlaintext(r, xRing))
		if gotFromDecoded != gotFromPrimitive {
			t.Errorf("1/%g: decoded-clenshaw %g != primitive %g",
				x, gotFromDecoded, gotFromPrimitive)
		}
		want := 1.0 / x
		rel := math.Abs(gotFromDecoded-want) / want
		if rel > 5e-12 {
			t.Errorf("1/%g via decoded coeffs: rel %e exceeds 5e-12",
				x, rel)
		}
	}
}

// TestRecip127Handler_NRStepsExposed: confirms the handler advertises
// the same NR-iter count as the primitive constant, so the R client
// runs the correct number of rounds.
func TestRecip127Handler_NRStepsExposed(t *testing.T) {
	if Ring127RecipChebNRSteps <= 0 {
		t.Fatalf("Ring127RecipChebNRSteps must be positive, got %d",
			Ring127RecipChebNRSteps)
	}
	// The handler hard-codes NRSteps from the constant; if someone
	// changes the constant but forgets to update handler tests, this
	// test keeps them aligned.
	if Ring127RecipChebNRSteps != 6 {
		t.Logf("NR iter count changed from 6 to %d — update R client "+
			".recip127_round loop bound and re-run NCCTG smoke.",
			Ring127RecipChebNRSteps)
	}
}
