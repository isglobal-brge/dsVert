// k2_log_shift_handler_test.go — round-trip check for the
// `k2-log-shift-coeffs` handler's base64 serialization. The underlying
// Chebyshev-log primitive is validated by Ring127LogShiftPlaintext in
// k2_log_shift127.go; this file only covers the b64 encoding layer that
// the R client decodes.

package main

import (
	"math"
	"testing"
)

// TestLogShiftHandler_B64RoundTrip: the handler emits b64(Uint128) blobs
// for oneOverHalfRange + negMidOverHalfRange + (degree+1) coefficients.
// Decode and compare against the plaintext primitive.
func TestLogShiftHandler_B64RoundTrip(t *testing.T) {
	r := NewRing127(K2DefaultFracBits127)
	oneOverHalfWant, _, coeffsWant, degreeWant := Ring127LogShiftCoeffsFP(r)
	a := Ring127LogShiftMin
	b := Ring127LogShiftMax
	negMidOverHalfWant := r.FromDouble(-(a + b) / (b - a))

	// Simulate handler's encode step.
	oneOverHalfB64 := Uint128VecToB64([]Uint128{oneOverHalfWant})
	negMidOverHalfB64 := Uint128VecToB64([]Uint128{negMidOverHalfWant})
	coeffsB64 := Uint128VecToB64(coeffsWant[:])

	// R client would decode via b64 → []Uint128.
	oneOverHalfGot := b64Uint128Vec(oneOverHalfB64)
	negMidOverHalfGot := b64Uint128Vec(negMidOverHalfB64)
	coeffsGot := b64Uint128Vec(coeffsB64)

	if len(oneOverHalfGot) != 1 {
		t.Fatalf("oneOverHalf decode: got len %d, want 1", len(oneOverHalfGot))
	}
	if oneOverHalfGot[0] != oneOverHalfWant {
		t.Errorf("oneOverHalf roundtrip mismatch: got %+v want %+v",
			oneOverHalfGot[0], oneOverHalfWant)
	}
	if len(negMidOverHalfGot) != 1 {
		t.Fatalf("negMidOverHalf decode: got len %d, want 1", len(negMidOverHalfGot))
	}
	if negMidOverHalfGot[0] != negMidOverHalfWant {
		t.Errorf("negMidOverHalf roundtrip mismatch: got %+v want %+v",
			negMidOverHalfGot[0], negMidOverHalfWant)
	}
	if len(coeffsGot) != degreeWant+1 {
		t.Fatalf("coeffs decode: got len %d, want %d",
			len(coeffsGot), degreeWant+1)
	}
	for k := 0; k <= degreeWant; k++ {
		if coeffsGot[k] != coeffsWant[k] {
			t.Errorf("c_%d roundtrip mismatch: got %+v want %+v",
				k, coeffsGot[k], coeffsWant[k])
		}
	}
}

// TestLogShiftHandler_CoeffsAccuracy: R-client-level sanity check.
// Decode the handler output, reconstruct log(x) via the documented
// "scale + affine then Clenshaw" recipe used by .ring127_log_round_keyed,
// and confirm rel < 1e-10 across the [1, 10] core domain. Guards against
// a serialization bug that preserves the first element but corrupts later
// coefficients — and against an off-by-one or sign error in the composed
// negMidOverHalfRange constant.
func TestLogShiftHandler_CoeffsAccuracy(t *testing.T) {
	r := NewRing127(K2DefaultFracBits127)
	oneOverHalf, _, coeffs, degree := Ring127LogShiftCoeffsFP(r)
	a := Ring127LogShiftMin
	b := Ring127LogShiftMax
	negMidOverHalf := r.FromDouble(-(a + b) / (b - a))

	// Round-trip through the handler encoding layer.
	oneOverHalfDec := b64Uint128Vec(Uint128VecToB64([]Uint128{oneOverHalf}))[0]
	negMidOverHalfDec :=
		b64Uint128Vec(Uint128VecToB64([]Uint128{negMidOverHalf}))[0]
	coeffsDec := b64Uint128Vec(Uint128VecToB64(coeffs[:]))

	// Reconstruct log(x) via "scale + affine then Clenshaw" using decoded
	// b64 values, mirroring the R orchestration. Test points sweep [1, 10].
	for _, x := range []float64{1.0, 1.5, 2.0, 3.0, 5.0, 7.5, 10.0} {
		xRing := r.FromDouble(x)
		// y_pre = x · oneOverHalf
		yPre := r.TruncMulSigned(xRing, oneOverHalfDec)
		// y = y_pre + negMidOverHalf  (party-0 absorbs the constant)
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
		// At x=1.0 want=0, use abs tol; otherwise rel tol.
		if math.Abs(want) < 1e-3 {
			if math.Abs(got-want) > 1e-10 {
				t.Errorf("decoded-coeffs Clenshaw log(%g): got %g want %g abs=%e",
					x, got, want, math.Abs(got-want))
			}
		} else {
			rel := math.Abs(got-want) / math.Abs(want)
			if rel > 1e-10 {
				t.Errorf("decoded-coeffs Clenshaw log(%g): got %g want %g rel=%e",
					x, got, want, rel)
			}
		}
	}
}

// TestLogShiftHandler_DomainConstants: verifies the documented public
// domain constants ([1, 10]) match the in-binary primitive bounds. This
// catches accidental drift between the handler-exposed metadata and the
// underlying Chebyshev evaluator.
func TestLogShiftHandler_DomainConstants(t *testing.T) {
	if Ring127LogShiftMin != 1.0 {
		t.Errorf("Ring127LogShiftMin: got %g want 1.0", Ring127LogShiftMin)
	}
	if Ring127LogShiftMax != 10.0 {
		t.Errorf("Ring127LogShiftMax: got %g want 10.0", Ring127LogShiftMax)
	}
	if Ring127LogShiftDegree != 40 {
		t.Errorf("Ring127LogShiftDegree: got %d want 40", Ring127LogShiftDegree)
	}
}
