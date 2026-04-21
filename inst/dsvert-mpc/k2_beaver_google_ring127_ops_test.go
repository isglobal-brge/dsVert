// k2_beaver_google_ring127_ops_test.go — tests for the Ring127 Beaver op
// primitives added in step 4a: TruncateSharePartyZero/One127, Hadamard
// ProductPartyZero/One127, ScalarVectorProductPartyZero/One127.

package main

import (
	"math"
	"math/rand"
	"testing"
)

// TestTruncateShare127_ReconstructAccuracy: split a known value x (positive
// and negative) into shares, truncate both shares by 2^fracBits, reconstruct,
// and check the reconstruction equals floor(x / 2^fracBits) within ±1 ULP
// (the known SecureML truncation bias).
func TestTruncateShare127_ReconstructAccuracy(t *testing.T) {
	ring := NewRing127(50)
	n := 100
	rng := rand.New(rand.NewSource(11))

	// Test values span the useful range for Beaver products at fracBits=50.
	// |x| up to 2^80 ≈ 1.2e24 as a signed Ring127 value — plenty of headroom.
	xFloats := make([]float64, n)
	for i := 0; i < n; i++ {
		// Mix of small and larger values, both signs.
		scale := math.Pow(10, rng.Float64()*4-2) // 0.01 to 100
		sign := 1.0
		if rng.Float32() < 0.5 {
			sign = -1.0
		}
		xFloats[i] = sign * scale
	}

	maxUlpBias := int64(0)
	// We're testing truncation at a FURTHER fracBits (call it shift), so
	// the "product at 2*fracBits" reduces back to fracBits.
	shift := ring.FracBits

	for i := 0; i < n; i++ {
		// x at 2*fracBits of FP scaling (as a Beaver output would be).
		x2FP := ring.FromDouble(xFloats[i]) // at fracBits
		// Promote to "2*fracBits" by leftshift
		xRaw := x2FP.Shl(uint(shift)).ModPow127()
		// Split into shares
		s0, s1 := ring.SplitShare(xRaw)

		// Each party truncates its share
		t0 := TruncateSharePartyZero127([]Uint128{s0}, shift, ring)[0]
		t1 := TruncateSharePartyOne127([]Uint128{s1}, shift, ring)[0]

		// Reconstruct: t0 + t1 should equal (xRaw >> shift) within ±1 ULP.
		recon := ring.Add(t0, t1)
		expected := x2FP // since we shifted left by shift then right by shift

		// Compute signed difference in ULPs.
		diff := ring.Sub(recon, expected)
		if ring.IsNeg(diff) {
			diff = ring.Neg(diff)
		}
		// Should be 0 or 1 ULP.
		ulp := Uint128{Lo: 1}
		if diff.Cmp(ulp) > 0 {
			t.Fatalf("i=%d x=%g: truncation off by > 1 ULP. recon={%x,%x} expected={%x,%x}",
				i, xFloats[i], recon.Hi, recon.Lo, expected.Hi, expected.Lo)
		}
		if diff.Cmp(Uint128{}) != 0 {
			maxUlpBias = 1
		}
	}
	t.Logf("Ring127 truncation max ULP bias across %d tests: %d (expected ≤ 1)", n, maxUlpBias)
}

// TestHadamardProduct127_ReconstructAccuracy: full vector product via
// Beaver at Ring127. x·y reconstructed from shares should match truth
// within 1 ULP × fracBits (i.e., relative error ~2^-fracBits).
func TestHadamardProduct127_ReconstructAccuracy(t *testing.T) {
	fracBits := 50
	ring := NewRing127(fracBits)
	n := 100

	xFloat := make([]float64, n)
	yFloat := make([]float64, n)
	for i := 0; i < n; i++ {
		xFloat[i] = 0.5 + float64(i)*0.01  // 0.50 .. 1.49
		yFloat[i] = -1.0 + float64(i)*0.02 // -1.0 .. 0.98
	}

	// FP encode + split
	xSh0 := make([]Uint128, n)
	xSh1 := make([]Uint128, n)
	ySh0 := make([]Uint128, n)
	ySh1 := make([]Uint128, n)
	for i := 0; i < n; i++ {
		xFP := ring.FromDouble(xFloat[i])
		yFP := ring.FromDouble(yFloat[i])
		xSh0[i], xSh1[i] = ring.SplitShare(xFP)
		ySh0[i], ySh1[i] = ring.SplitShare(yFP)
	}

	// Sample Beaver triples
	p0Trip, p1Trip := SampleBeaverTripleVector127(n, ring)

	// Round 1
	p0State, p0Msg := GenerateBatchedMultiplicationGateMessage127(xSh0, ySh0, p0Trip, ring)
	p1State, p1Msg := GenerateBatchedMultiplicationGateMessage127(xSh1, ySh1, p1Trip, ring)

	// HadamardProduct (round 2 + truncation)
	z0 := HadamardProductPartyZero127(p0State, p0Trip, p1Msg, fracBits, ring)
	z1 := HadamardProductPartyOne127(p1State, p1Trip, p0Msg, fracBits, ring)

	// Reconstruct and compare
	maxRelErr := 0.0
	for i := 0; i < n; i++ {
		zFP := ring.Add(z0[i], z1[i])
		zFloat := ring.ToDouble(zFP)
		truth := xFloat[i] * yFloat[i]
		if math.Abs(truth) < 1e-10 {
			continue
		}
		relErr := math.Abs(zFloat-truth) / math.Abs(truth)
		if relErr > maxRelErr {
			maxRelErr = relErr
		}
	}

	// Expected: 2^-fracBits ≈ 8.9e-16 per element, but truncation adds up to
	// ~1 ULP of bias. Give a generous bound: 1e-12.
	if maxRelErr > 1e-12 {
		t.Errorf("Ring127 HadamardProduct max rel err %.3e > 1e-12", maxRelErr)
	}
	t.Logf("Ring127 HadamardProduct n=%d: max relative error = %.3e", n, maxRelErr)
}

// TestHadamardProduct127_VsRing63: compare full Hadamard accuracy.
// Expect Ring127 to be ~9 orders of magnitude more accurate than Ring63.
func TestHadamardProduct127_VsRing63(t *testing.T) {
	n := 80
	r127 := NewRing127(50)
	r63 := NewRing63(20)

	xFloat := make([]float64, n)
	yFloat := make([]float64, n)
	for i := 0; i < n; i++ {
		xFloat[i] = 0.3 + float64(i)*0.013
		yFloat[i] = 1.7 - float64(i)*0.005
	}

	// Ring127
	xSh0_127 := make([]Uint128, n)
	xSh1_127 := make([]Uint128, n)
	ySh0_127 := make([]Uint128, n)
	ySh1_127 := make([]Uint128, n)
	for i := 0; i < n; i++ {
		xSh0_127[i], xSh1_127[i] = r127.SplitShare(r127.FromDouble(xFloat[i]))
		ySh0_127[i], ySh1_127[i] = r127.SplitShare(r127.FromDouble(yFloat[i]))
	}
	p0t127, p1t127 := SampleBeaverTripleVector127(n, r127)
	p0s127, p0m127 := GenerateBatchedMultiplicationGateMessage127(xSh0_127, ySh0_127, p0t127, r127)
	p1s127, p1m127 := GenerateBatchedMultiplicationGateMessage127(xSh1_127, ySh1_127, p1t127, r127)
	z0_127 := HadamardProductPartyZero127(p0s127, p0t127, p1m127, r127.FracBits, r127)
	z1_127 := HadamardProductPartyOne127(p1s127, p1t127, p0m127, r127.FracBits, r127)

	// Ring63
	xSh0_63 := make([]uint64, n)
	xSh1_63 := make([]uint64, n)
	ySh0_63 := make([]uint64, n)
	ySh1_63 := make([]uint64, n)
	for i := 0; i < n; i++ {
		xSh0_63[i], xSh1_63[i] = r63.SplitShare(r63.FromDouble(xFloat[i]))
		ySh0_63[i], ySh1_63[i] = r63.SplitShare(r63.FromDouble(yFloat[i]))
	}
	p0t63, p1t63 := SampleBeaverTripleVector(n, r63)
	p0s63, p0m63 := GenerateBatchedMultiplicationGateMessage(xSh0_63, ySh0_63, p0t63, r63)
	p1s63, p1m63 := GenerateBatchedMultiplicationGateMessage(xSh1_63, ySh1_63, p1t63, r63)
	z0_63 := HadamardProductPartyZero(p0s63, p0t63, p1m63, r63.FracBits, r63)
	z1_63 := HadamardProductPartyOne(p1s63, p1t63, p0m63, r63.FracBits, r63)

	max127, max63 := 0.0, 0.0
	for i := 0; i < n; i++ {
		z127 := r127.ToDouble(r127.Add(z0_127[i], z1_127[i]))
		z63 := r63.ToDouble(r63.Add(z0_63[i], z1_63[i]))
		truth := xFloat[i] * yFloat[i]
		e127 := math.Abs(z127 - truth)
		e63 := math.Abs(z63 - truth)
		if e127 > max127 {
			max127 = e127
		}
		if e63 > max63 {
			max63 = e63
		}
	}
	improvement := max63 / math.Max(max127, 1e-30)
	t.Logf("HadamardProduct n=%d: Ring127 max|err|=%.3e, Ring63 max|err|=%.3e, improvement=%.1fx",
		n, max127, max63, improvement)
	if max127 >= max63 {
		t.Errorf("Ring127 not more accurate than Ring63")
	}
}

// TestScalarVectorProduct127_ReconstructAccuracy: a · b for public scalar a
// and secret-shared Ring127 vector b. Party-zero + party-one shares should
// reconstruct to a · b within FP precision.
func TestScalarVectorProduct127_ReconstructAccuracy(t *testing.T) {
	ring := NewRing127(50)
	n := 60
	scalars := []float64{1.0, -1.0, 2.5, -3.7, 0.1, -0.01, 1234.5}

	bFloat := make([]float64, n)
	for i := 0; i < n; i++ {
		bFloat[i] = -2.0 + float64(i)*0.07
	}

	// Split b
	bSh0 := make([]Uint128, n)
	bSh1 := make([]Uint128, n)
	for i := 0; i < n; i++ {
		bSh0[i], bSh1[i] = ring.SplitShare(ring.FromDouble(bFloat[i]))
	}

	for _, a := range scalars {
		res0 := ScalarVectorProductPartyZero127(a, bSh0, ring)
		res1 := ScalarVectorProductPartyOne127(a, bSh1, ring)

		maxRelErr := 0.0
		for i := 0; i < n; i++ {
			recon := ring.Add(res0[i], res1[i])
			reconFloat := ring.ToDouble(recon)
			truth := a * bFloat[i]
			if math.Abs(truth) < 1e-10 {
				if math.Abs(reconFloat) > 1e-12 {
					t.Errorf("a=%g i=%d: expected ~0, got %g", a, i, reconFloat)
				}
				continue
			}
			relErr := math.Abs(reconFloat-truth) / math.Abs(truth)
			if relErr > maxRelErr {
				maxRelErr = relErr
			}
		}
		// Bound 1e-10: at small scalars (a=0.01, truth ~0.01 * b) the
		// float64 truth carries its own rep error (0.01 is not exact binary),
		// inflating the measured relative gap. Ring127 arithmetic itself
		// delivers ~2^-50 ≈ 1e-15 per op; 1e-10 is comfortably above floor
		// and still 4 orders of magnitude better than Ring63's ~1e-6.
		if maxRelErr > 1e-10 {
			t.Errorf("a=%g: ScalarVectorProduct127 max rel err %.3e > 1e-10", a, maxRelErr)
		}
		t.Logf("a=%g: max rel err = %.3e", a, maxRelErr)
	}
}

// TestScalarVectorProduct127_ZeroShareGuard: when b has a zero share, the
// guard returns 0 (matching Ring63 behavior). This is the Scalar×0=0 case.
func TestScalarVectorProduct127_ZeroShareGuard(t *testing.T) {
	ring := NewRing127(50)
	// Share vector with explicit zero entries
	b0 := []Uint128{{}, ring.FromDouble(1.5), {}, ring.FromDouble(-2.5)}
	res0 := ScalarVectorProductPartyZero127(3.0, b0, ring)
	// At i=0 and i=2 the share is zero → result[i] must be zero.
	if res0[0].Cmp(Uint128{}) != 0 {
		t.Errorf("zero-share guard failed at i=0: got {%x,%x}", res0[0].Hi, res0[0].Lo)
	}
	if res0[2].Cmp(Uint128{}) != 0 {
		t.Errorf("zero-share guard failed at i=2: got {%x,%x}", res0[2].Hi, res0[2].Lo)
	}
}
