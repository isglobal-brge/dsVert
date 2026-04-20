// k2_exp127_handler_test.go — round-trip check for the `k2-exp127-get-coeffs`
// handler's base64 serialization. The underlying coefficient math is
// validated by TestRing127ExpCoeffsFP in k2_exp127_test.go; this file only
// covers the b64-encoding layer that the R client will decode.

package main

import (
	"math"
	"testing"
)

// TestExp127Handler_B64RoundTrip: the handler emits b64(Uint128) blobs for
// 1/a + 31 coefficients. Decode and compare against the plaintext primitive.
func TestExp127Handler_B64RoundTrip(t *testing.T) {
	r := NewRing127(K2DefaultFracBits127)
	oneOverAWant, coeffsWant, degreeWant := Ring127ExpCoeffsFP(r)

	// Simulate handler's encode step.
	oneOverAB64 := Uint128VecToB64([]Uint128{oneOverAWant})
	coeffsB64 := Uint128VecToB64(coeffsWant[:])

	// R client would decode via b64 → []Uint128.
	oneOverAGot := b64Uint128Vec(oneOverAB64)
	coeffsGot := b64Uint128Vec(coeffsB64)

	if len(oneOverAGot) != 1 {
		t.Fatalf("oneOverA decode: got len %d, want 1", len(oneOverAGot))
	}
	if oneOverAGot[0] != oneOverAWant {
		t.Errorf("oneOverA roundtrip mismatch: got %+v want %+v",
			oneOverAGot[0], oneOverAWant)
	}
	if len(coeffsGot) != degreeWant+1 {
		t.Fatalf("coeffs decode: got len %d, want %d", len(coeffsGot), degreeWant+1)
	}
	for k := 0; k <= degreeWant; k++ {
		if coeffsGot[k] != coeffsWant[k] {
			t.Errorf("c_%d roundtrip mismatch: got %+v want %+v",
				k, coeffsGot[k], coeffsWant[k])
		}
	}
}

// TestExp127Handler_CoeffsAccuracy: an R-client-level sanity check —
// decode the handler output, reconstruct exp(x) via Clenshaw using the
// decoded coefficients directly, and confirm rel <1e-12 across NCCTG
// eta range. This guards against a serialization bug that happens to
// preserve the first element but corrupts later coefficients.
func TestExp127Handler_CoeffsAccuracy(t *testing.T) {
	r := NewRing127(K2DefaultFracBits127)
	oneOverA, coeffs, degree := Ring127ExpCoeffsFP(r)

	// Round-trip through the handler encoding layer.
	oneOverADecoded := b64Uint128Vec(Uint128VecToB64([]Uint128{oneOverA}))[0]
	coeffsDecoded := b64Uint128Vec(Uint128VecToB64(coeffs[:]))

	// Reconstruct exp(x) via Clenshaw using decoded b64 values.
	for _, x := range []float64{-3.0, -1.0, -0.1, 0.0, 0.5, 1.5, 3.0} {
		xRing := r.FromDouble(x)
		y := r.TruncMulSigned(xRing, oneOverADecoded)

		var bKp1, bKp2 Uint128
		for k := degree; k >= 1; k-- {
			twoY := r.Add(y, y)
			twoYbKp1 := r.TruncMulSigned(twoY, bKp1)
			bK := r.Sub(r.Add(coeffsDecoded[k], twoYbKp1), bKp2)
			bKp2 = bKp1
			bKp1 = bK
		}
		yb1 := r.TruncMulSigned(y, bKp1)
		result := r.Sub(r.Add(coeffsDecoded[0], yb1), bKp2)
		got := r.ToDouble(result)
		want := math.Exp(x)
		rel := math.Abs(got-want) / want
		if rel > 1e-12 {
			t.Errorf("decoded-coeffs Clenshaw exp(%g): got %g want %g rel=%e",
				x, got, want, rel)
		}
	}
}
