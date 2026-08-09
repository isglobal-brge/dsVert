package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math"
	"math/big"
	"math/rand"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeRingAndFracBits(t *testing.T) {
	tests := []struct {
		name     string
		ring     string
		fracBits int
		wantRing string
		wantFrac int
		wantErr  bool
	}{
		{name: "ring63 defaults", wantRing: "ring63", wantFrac: K2DefaultFracBits},
		{name: "ring127 defaults", ring: "ring127", wantRing: "ring127", wantFrac: K2DefaultFracBits127},
		{name: "ring63 upper boundary", ring: "ring63", fracBits: 62, wantRing: "ring63", wantFrac: 62},
		{name: "ring127 upper boundary", ring: "ring127", fracBits: 126, wantRing: "ring127", wantFrac: 126},
		{name: "unknown ring", ring: "ring64", fracBits: 20, wantErr: true},
		{name: "negative frac bits", ring: "ring63", fracBits: -1, wantErr: true},
		{name: "ring63 frac bits overflow", ring: "ring63", fracBits: 63, wantErr: true},
		{name: "ring127 frac bits overflow", ring: "ring127", fracBits: 127, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRing, gotFrac, err := normalizeRingAndFracBits(tt.ring, tt.fracBits)
			if (err != nil) != tt.wantErr {
				t.Fatalf("normalizeRingAndFracBits() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if gotRing != tt.wantRing || gotFrac != tt.wantFrac {
				t.Fatalf("normalizeRingAndFracBits() = (%q, %d), want (%q, %d)",
					gotRing, gotFrac, tt.wantRing, tt.wantFrac)
			}
		})
	}
}

func TestCheckedFloatEncodingRejectsNonFiniteAndWrap(t *testing.T) {
	invalid := []float64{math.NaN(), math.Inf(1), math.Inf(-1)}
	for _, ringName := range []string{"ring63", "ring127"} {
		t.Run(ringName, func(t *testing.T) {
			for _, v := range invalid {
				if _, err := encodeK2FloatToFP(K2FloatToFPInput{
					Values: []float64{v}, Ring: ringName,
				}); err == nil {
					t.Fatalf("accepted non-finite value %v", v)
				}
			}

			fracBits := K2DefaultFracBits
			ringBits := 63
			if ringName == "ring127" {
				fracBits = K2DefaultFracBits127
				ringBits = 127
			}
			limit := math.Ldexp(1, ringBits-1-fracBits)
			for _, v := range []float64{limit, -math.Nextafter(limit, math.Inf(1))} {
				if _, err := encodeK2FloatToFP(K2FloatToFPInput{
					Values: []float64{v}, FracBits: fracBits, Ring: ringName,
				}); err == nil {
					t.Fatalf("accepted out-of-range value %g (limit %g)", v, limit)
				}
			}
		})
	}
}

func TestCheckedFloatEncodingRoundTrip(t *testing.T) {
	values := []float64{-1234.5, -1, -0.125, 0, 0.125, 1, 1234.5}
	for _, ringName := range []string{"ring63", "ring127"} {
		t.Run(ringName, func(t *testing.T) {
			out, err := encodeK2FloatToFP(K2FloatToFPInput{Values: values, Ring: ringName})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := base64.StdEncoding.DecodeString(out.FPData)
			if err != nil {
				t.Fatal(err)
			}
			if ringName == "ring63" {
				r := NewRing63(K2DefaultFracBits)
				got, err := decodeRing63FPVector(out.FPData, len(values))
				if err != nil {
					t.Fatal(err)
				}
				for i := range values {
					if diff := math.Abs(r.ToDouble(got[i]) - values[i]); diff > math.Ldexp(1, -K2DefaultFracBits) {
						t.Fatalf("value[%d] diff %g exceeds one ULP", i, diff)
					}
				}
				return
			}
			r := NewRing127(K2DefaultFracBits127)
			got := bytesToUint128Vec(raw)
			for i := range values {
				if diff := math.Abs(r.ToDouble(got[i]) - values[i]); diff > math.Ldexp(1, -K2DefaultFracBits127) {
					t.Fatalf("value[%d] diff %g exceeds one ULP", i, diff)
				}
			}
		})
	}
}

func TestSignedRingBoundaries(t *testing.T) {
	t.Run("Ring63", func(t *testing.T) {
		r := NewRing63(K2DefaultFracBits)
		positiveMax := r.SignThreshold - 1
		negativeMin := r.SignThreshold
		if r.IsNeg(positiveMax) || !r.IsNeg(negativeMin) {
			t.Fatal("Ring63 signed threshold classification is inconsistent")
		}
		limit := math.Ldexp(1, k2Ring63Bits-1-r.FracBits)
		got, err := r.FromDoubleChecked(-limit)
		if err != nil || got != negativeMin {
			t.Fatalf("negative boundary = (%d, %v), want (%d, nil)", got, err, negativeMin)
		}
		if _, err := r.FromDoubleChecked(limit); err == nil {
			t.Fatal("accepted positive Ring63 boundary that would wrap negative")
		}
	})

	t.Run("Ring127", func(t *testing.T) {
		r := NewRing127(K2DefaultFracBits127)
		positiveMax := r.Sub(r.SignThreshold, U128FromUint64(1))
		negativeMin := r.SignThreshold
		if r.IsNeg(positiveMax) || !r.IsNeg(negativeMin) {
			t.Fatal("Ring127 signed threshold classification is inconsistent")
		}
		limit := math.Ldexp(1, k2Ring127Bits-1-r.FracBits)
		got, err := r.FromDoubleChecked(-limit)
		if err != nil || got.Cmp(negativeMin) != 0 {
			t.Fatalf("negative boundary = (%v, %v), want (%v, nil)", got, err, negativeMin)
		}
		if _, err := r.FromDoubleChecked(limit); err == nil {
			t.Fatal("accepted positive Ring127 boundary that would wrap negative")
		}
	})
}

func TestRingArithmeticMatchesBigIntModuloReference(t *testing.T) {
	rng := rand.New(rand.NewSource(0x12763))

	t.Run("Ring63", func(t *testing.T) {
		ring := NewRing63(K2DefaultFracBits)
		modulus := new(big.Int).Lsh(big.NewInt(1), k2Ring63Bits)
		mask := ring.Modulus - 1
		values := [][2]uint64{
			{0, 0}, {mask, 1}, {ring.SignThreshold, ring.SignThreshold},
			{ring.SignThreshold - 1, mask},
		}
		for i := 0; i < 2_000; i++ {
			values = append(values, [2]uint64{rng.Uint64() & mask, rng.Uint64() & mask})
		}
		for i, pair := range values {
			a, b := pair[0], pair[1]
			for name, got := range map[string]uint64{
				"add": ring.Add(a, b),
				"sub": ring.Sub(a, b),
				"mul": modMulBig63(a, b, ring.Modulus),
			} {
				left := new(big.Int).SetUint64(a)
				right := new(big.Int).SetUint64(b)
				var want *big.Int
				switch name {
				case "add":
					want = new(big.Int).Add(left, right)
				case "sub":
					want = new(big.Int).Sub(left, right)
				default:
					want = new(big.Int).Mul(left, right)
				}
				want.Mod(want, modulus)
				if got != want.Uint64() {
					t.Fatalf("sample %d %s = %d want %d", i, name, got, want.Uint64())
				}
			}
		}
	})

	t.Run("Ring127", func(t *testing.T) {
		ring := NewRing127(K2DefaultFracBits127)
		modulus := new(big.Int).Lsh(big.NewInt(1), k2Ring127Bits)
		max := ring.Neg(U128FromUint64(1))
		values := [][2]Uint128{
			{U128Zero(), U128Zero()}, {max, U128FromUint64(1)},
			{ring.SignThreshold, ring.SignThreshold},
			{ring.Sub(ring.SignThreshold, U128FromUint64(1)), max},
		}
		for i := 0; i < 2_000; i++ {
			values = append(values, [2]Uint128{
				{Hi: rng.Uint64() & (math.MaxUint64 >> 1), Lo: rng.Uint64()},
				{Hi: rng.Uint64() & (math.MaxUint64 >> 1), Lo: rng.Uint64()},
			})
		}
		for i, pair := range values {
			a, b := pair[0], pair[1]
			for name, got := range map[string]Uint128{
				"add": ring.Add(a, b),
				"sub": ring.Sub(a, b),
				"mul": a.Mul(b).ModPow127(),
			} {
				var want *big.Int
				switch name {
				case "add":
					want = new(big.Int).Add(a.ToBig(), b.ToBig())
				case "sub":
					want = new(big.Int).Sub(a.ToBig(), b.ToBig())
				default:
					want = new(big.Int).Mul(a.ToBig(), b.ToBig())
				}
				want.Mod(want, modulus)
				if got.Cmp(U128FromBig(want)) != 0 {
					t.Fatalf("sample %d %s = %v want %v", i, name, got, U128FromBig(want))
				}
			}
		}
	})
}

func TestUncheckedFloatEncodersFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   func()
	}{
		{name: "Ring63 NaN", fn: func() { NewRing63(20).FromDouble(math.NaN()) }},
		{name: "Ring63 overflow", fn: func() { NewRing63(20).FromDouble(math.Ldexp(1, 42)) }},
		{name: "Ring127 infinity", fn: func() { NewRing127(50).FromDouble(math.Inf(1)) }},
		{name: "Ring127 overflow", fn: func() { NewRing127(50).FromDouble(math.Ldexp(1, 76)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("encoder silently accepted invalid input")
				}
			}()
			tc.fn()
		})
	}
}

func TestDecodeRingVectorRejectsMalformedAndNonCanonical(t *testing.T) {
	badWidth := base64.StdEncoding.EncodeToString(make([]byte, 7))
	if _, err := decodeRing63FPVector(badWidth, -1); err == nil {
		t.Fatal("Ring63 decoder accepted a partial record")
	}
	if _, err := decodeRing127Vector("not-base64", -1); err == nil {
		t.Fatal("Ring127 decoder accepted invalid base64")
	}
	nonCanonical := make([]byte, 16)
	nonCanonical[15] = 0x80 // bit 127 is outside Z_(2^127)
	if _, err := decodeRing127Vector(base64.StdEncoding.EncodeToString(nonCanonical), 1); err == nil {
		t.Fatal("Ring127 decoder accepted a non-canonical element")
	}

	canonicalNegative := make([]byte, 8)
	binary.LittleEndian.PutUint64(canonicalNegative, math.MaxUint64)
	decodedNegative, err := decodeRing63FPVector(
		base64.StdEncoding.EncodeToString(canonicalNegative), 1,
	)
	if err != nil || len(decodedNegative) != 1 || decodedNegative[0] != (uint64(1)<<63)-1 {
		t.Fatalf("Ring63 signed decoder rejected canonical -1: %v %v", decodedNegative, err)
	}
	nonCanonicalSigned := make([]byte, 8)
	binary.LittleEndian.PutUint64(nonCanonicalSigned, uint64(1)<<62)
	if _, err := decodeRing63FPVector(base64.StdEncoding.EncodeToString(nonCanonicalSigned), 1); err == nil {
		t.Fatal("Ring63 signed decoder accepted a non-canonical positive representation")
	}

	rawResidues := make([]byte, 16)
	binary.LittleEndian.PutUint64(rawResidues[0:8], (uint64(1)<<63)-1)
	binary.LittleEndian.PutUint64(rawResidues[8:16], uint64(1)<<63)
	if _, err := decodeRing63ResidueVector(base64.StdEncoding.EncodeToString(rawResidues[:8]), 1); err != nil {
		t.Fatalf("Ring63 residue decoder rejected the canonical maximum: %v", err)
	}
	if _, err := decodeRing63ResidueVector(base64.StdEncoding.EncodeToString(rawResidues[8:]), 1); err == nil {
		t.Fatal("Ring63 residue decoder accepted a value outside the ring")
	}
}

func TestPublicBitMaskIsExactAndRejectsWeights(t *testing.T) {
	t.Run("Ring63", func(t *testing.T) {
		ring := NewRing63(K2DefaultFracBits)
		shares := []uint64{ring.Modulus - 1, ring.SignThreshold, 17, 0}
		mask := []uint64{ring.FracMul, 0, ring.FracMul, 0}
		got, err := applyPublicBitMask63(shares, mask, ring)
		if err != nil {
			t.Fatal(err)
		}
		want := []uint64{shares[0], 0, shares[2], 0}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("masked share %d = %d want %d", i, got[i], want[i])
			}
		}
		if _, err := applyPublicBitMask63(
			[]uint64{shares[0]}, []uint64{ring.FracMul / 2}, ring,
		); err == nil {
			t.Fatal("accepted a non-binary Ring63 weight")
		}
		for name, invalid := range map[string]uint64{
			"minus one": ring.Neg(ring.FracMul),
			"two":       ring.Add(ring.FracMul, ring.FracMul),
			"raw max":   ring.Modulus - 1,
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := applyPublicBitMask63(
					[]uint64{shares[0]}, []uint64{invalid}, ring,
				); err == nil {
					t.Fatalf("accepted non-bit Ring63 value %d", invalid)
				}
			})
		}
		boundaryRing := NewRing63(k2Ring63Bits - 1)
		if _, err := applyPublicBitMask63(
			[]uint64{shares[0]}, []uint64{boundaryRing.FracMul}, boundaryRing,
		); err == nil {
			t.Fatal("accepted Ring63 sign-threshold alias as public bit 1")
		}
	})

	t.Run("Ring127", func(t *testing.T) {
		ring := NewRing127(K2DefaultFracBits127)
		shares := []Uint128{
			ring.Neg(U128FromUint64(1)), ring.SignThreshold, U128FromUint64(17), U128Zero(),
		}
		mask := []Uint128{ring.FracMul, U128Zero(), ring.FracMul, U128Zero()}
		got, err := applyPublicBitMask127(shares, mask, ring)
		if err != nil {
			t.Fatal(err)
		}
		want := []Uint128{shares[0], U128Zero(), shares[2], U128Zero()}
		for i := range want {
			if got[i].Cmp(want[i]) != 0 {
				t.Fatalf("masked share %d = %v want %v", i, got[i], want[i])
			}
		}
		if _, err := applyPublicBitMask127(
			[]Uint128{shares[0]}, []Uint128{ring.FracMul.Shr(1)}, ring,
		); err == nil {
			t.Fatal("accepted a non-binary Ring127 weight")
		}
		for name, invalid := range map[string]Uint128{
			"minus one": ring.Neg(ring.FracMul),
			"two":       ring.Add(ring.FracMul, ring.FracMul),
			"raw max":   ring.Neg(U128FromUint64(1)),
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := applyPublicBitMask127(
					[]Uint128{shares[0]}, []Uint128{invalid}, ring,
				); err == nil {
					t.Fatalf("accepted non-bit Ring127 value %v", invalid)
				}
			})
		}
		boundaryRing := NewRing127(k2Ring127Bits - 1)
		if _, err := applyPublicBitMask127(
			[]Uint128{shares[0]}, []Uint128{boundaryRing.FracMul}, boundaryRing,
		); err == nil {
			t.Fatal("accepted Ring127 sign-threshold alias as public bit 1")
		}
	})
}

func TestCheckedProductRejectsOverflow(t *testing.T) {
	if got, err := checkedProduct("matrix", 3, 7, 11); err != nil || got != 231 {
		t.Fatalf("checkedProduct valid = (%d, %v), want (231, nil)", got, err)
	}
	if _, err := checkedProduct("matrix", math.MaxInt, 2); err == nil {
		t.Fatal("checkedProduct accepted integer overflow")
	}
	if _, err := checkedProduct("matrix", 3, -1); err == nil {
		t.Fatal("checkedProduct accepted a negative dimension")
	}
	if got, err := checkedSum("columns", 3, 7, 11); err != nil || got != 21 {
		t.Fatalf("checkedSum valid = (%d, %v), want (21, nil)", got, err)
	}
	if _, err := checkedSum("columns", math.MaxInt, 1); err == nil {
		t.Fatal("checkedSum accepted integer overflow")
	}
	if _, err := checkedSum("columns", 3, -1); err == nil {
		t.Fatal("checkedSum accepted a negative term")
	}
}

func TestOppositeCarryCannotChangeTruncationReconstruction(t *testing.T) {
	r := NewRing63(K2DefaultFracBits)
	divisor := r.FracMul
	rng := rand.New(rand.NewSource(20260731))
	for i := 0; i < 10_000; i++ {
		value := rng.Uint64() % r.Modulus
		share0 := rng.Uint64() % r.Modulus
		share1 := r.Sub(value, share0)

		trunc0, trunc1 := AsymmetricLocalTruncatePair(share0, share1, divisor, r.Modulus)
		carry := rng.Uint64() & 1
		withCarry0 := r.Add(trunc0, carry)
		withCarry1 := r.Sub(trunc1, carry)
		if r.Add(trunc0, trunc1) != r.Add(withCarry0, withCarry1) {
			t.Fatalf("opposite carry changed reconstruction at sample %d", i)
		}
	}
}

func TestAsymmetricLocalTruncationErrorBoundOutsideWrapFailure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fracBits int
	}{
		{name: "Ring63-default", fracBits: K2DefaultFracBits},
		{name: "Ring63-boundary", fracBits: 62},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRing63(tc.fracBits)
			d := r.FracMul
			rng := rand.New(rand.NewSource(int64(tc.fracBits)))
			for i := 0; i < 20_000; i++ {
				value := rng.Uint64() % r.SignThreshold
				// For a non-negative secret, local truncation is correct when the
				// additive split wraps modulo q. Force that condition so this test
				// verifies the advertised normal-path one-unit error bound.
				share0 := value + 1 + rng.Uint64()%(r.Modulus-value-1)
				share1 := r.Sub(value, share0)
				t0, t1 := AsymmetricLocalTruncatePair(share0, share1, d, r.Modulus)
				got := r.Add(t0, t1)
				want := value / d
				delta := r.Sub(got, want)
				if delta != 0 && delta != 1 && delta != r.Modulus-1 {
					t.Fatalf("sample %d: truncation error = %d ring units, want <= 1", i, delta)
				}
			}
		})
	}
}

func TestAsymmetricLocalTruncationDocumentsRareWrapFailure(t *testing.T) {
	r := NewRing63(K2DefaultFracBits)
	d := r.FracMul
	value := uint64(4) * d
	share0 := uint64(0) // non-wrapping split for a non-negative secret
	share1 := value
	t0, t1 := AsymmetricLocalTruncatePair(share0, share1, d, r.Modulus)
	got := r.Add(t0, t1)
	if got == value/d || got == value/d+1 {
		t.Fatal("test fixture did not exercise the documented wrap failure")
	}
}

func TestAsymmetricLocalTruncationRing127ErrorBoundOutsideWrapFailure(t *testing.T) {
	r := NewRing127(K2DefaultFracBits127)
	rng := rand.New(rand.NewSource(12750))
	for i := 0; i < 20_000; i++ {
		value := Uint128{Hi: rng.Uint64() & ((uint64(1) << 61) - 1), Lo: rng.Uint64()}
		// signThreshold is greater than every generated non-negative value,
		// so this share choice forces the normal modulo-wrap case.
		share0 := r.SignThreshold
		share1 := r.Sub(value, share0)
		t0 := TruncateSharePartyZero127([]Uint128{share0}, r.FracBits, r)[0]
		t1 := TruncateSharePartyOne127([]Uint128{share1}, r.FracBits, r)[0]
		got := r.Add(t0, t1)
		want := value.Shr(uint(r.FracBits))
		delta := r.Sub(got, want)
		if delta.Cmp(U128Zero()) != 0 && delta.Cmp(U128FromUint64(1)) != 0 &&
			delta.Cmp(r.Neg(U128FromUint64(1))) != 0 {
			t.Fatalf("sample %d: Ring127 truncation error exceeds one unit: %v", i, delta)
		}
	}
}

func TestAsymmetricLocalTruncationRing127DocumentsRareWrapFailure(t *testing.T) {
	ring := NewRing127(K2DefaultFracBits127)
	value := ring.FracMul.Shl(2)
	share0 := U128Zero() // non-wrapping split for a non-negative secret
	share1 := value
	t0 := TruncateSharePartyZero127([]Uint128{share0}, ring.FracBits, ring)[0]
	t1 := TruncateSharePartyOne127([]Uint128{share1}, ring.FracBits, ring)[0]
	got := ring.Add(t0, t1)
	want := value.Shr(uint(ring.FracBits))
	if got.Cmp(want) == 0 || got.Cmp(ring.Add(want, U128FromUint64(1))) == 0 {
		t.Fatal("test fixture did not exercise the documented Ring127 wrap failure")
	}
}

func TestQuarterRingDCFMaskHasDifferentialWrapCounterexample(t *testing.T) {
	t.Run("Ring63", func(t *testing.T) {
		ring := NewRing63(K2DefaultFracBits)
		threshold := uint64(0)
		x := ring.SignThreshold - 1 // largest non-negative signed residue
		mask := uint64(1)           // valid historical mask in [0, q/4)

		shiftedX := ring.Add(x, ring.SignThreshold)
		shiftedThreshold := ring.Add(threshold, ring.SignThreshold)
		maskedX := ring.Add(shiftedX, mask)
		maskedThreshold := ring.Add(shiftedThreshold, mask)
		if !(maskedX < maskedThreshold) || x < threshold {
			t.Fatal("fixture does not reverse the intended comparison")
		}

		key0, key1 := DCFGen(maskedThreshold, 1, 63)
		share0 := uint64(DCFEval(0, key0, maskedX)) % ring.Modulus
		share1 := uint64(DCFEval(1, key1, maskedX)) % ring.Modulus
		if got := ring.Add(share0, share1); got != 1 {
			t.Fatalf("masked DCF predicate = %d want 1", got)
		}
		// The intended predicate is x < 0, which is false. The DCF faithfully
		// evaluates the wrong masked ordering after differential wrap.
	})

	t.Run("Ring127", func(t *testing.T) {
		ring := NewRing127(K2DefaultFracBits127)
		threshold := U128Zero()
		x := ring.Sub(ring.SignThreshold, U128FromUint64(1))
		mask := U128FromUint64(1)

		shiftedX := ring.Add(x, ring.SignThreshold)
		shiftedThreshold := ring.Add(threshold, ring.SignThreshold)
		maskedX := ring.Add(shiftedX, mask)
		maskedThreshold := ring.Add(shiftedThreshold, mask)
		if maskedX.Cmp(maskedThreshold) >= 0 || x.Cmp(threshold) < 0 {
			t.Fatal("fixture does not reverse the intended comparison")
		}

		key0, key1 := DCFGen127(maskedThreshold, U128FromUint64(1), 127)
		share0 := DCFEval127(0, key0, maskedX)
		share1 := DCFEval127(1, key1, maskedX)
		if got := ring.Add(share0, share1); got.Cmp(U128FromUint64(1)) != 0 {
			t.Fatalf("masked DCF predicate = %v want 1", got)
		}
	})
}

func TestQuarterRingDCFMaskLeaksCoarseRange(t *testing.T) {
	// For shifted input U=0, every possible opened m=U+r lies below q/4.
	// For U=q/2, every possible m lies in [q/2, 3q/4). The supports are
	// disjoint, so one opened masked value distinguishes these inputs with
	// certainty. Ring width changes cost, not this leakage argument.
	ring63 := NewRing63(K2DefaultFracBits)
	maskMax63 := ring63.Modulus/4 - 1
	if maskMax63 >= ring63.SignThreshold {
		t.Fatal("Ring63 quarter-mask supports unexpectedly overlap")
	}

	ring127 := NewRing127(K2DefaultFracBits127)
	maskMax127 := Uint128{Hi: (uint64(1) << 61) - 1, Lo: math.MaxUint64}
	if maskMax127.Cmp(ring127.SignThreshold) >= 0 {
		t.Fatal("Ring127 quarter-mask supports unexpectedly overlap")
	}
}

func TestLocalTruncationHeadroomFailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		proof   LocalTruncationHeadroom
		wantErr bool
	}{
		{
			name: "unproven bound",
			proof: LocalTruncationHeadroom{
				RingBits: 127, FracBits: 38, MaxAbsTruncatedValue: 1024,
				MaxTruncations: 1, MinFailureBits: 40, SharesAreFreshUniform: true,
			},
			wantErr: true,
		},
		{
			name: "non-uniform shares",
			proof: LocalTruncationHeadroom{
				RingBits: 127, FracBits: 38, MaxAbsTruncatedValue: 1024,
				MaxTruncations: 1, MinFailureBits: 40, BoundIsServerProven: true,
			},
			wantErr: true,
		},
		{
			name: "missing analysis count",
			proof: LocalTruncationHeadroom{
				RingBits: 127, FracBits: 38, MaxAbsTruncatedValue: 1024,
				MinFailureBits: 40, BoundIsServerProven: true, SharesAreFreshUniform: true,
			},
			wantErr: true,
		},
		{
			name: "Ring63 insufficient",
			proof: LocalTruncationHeadroom{
				RingBits: 63, FracBits: 20, MaxAbsTruncatedValue: 1024,
				MaxTruncations: 1, MinFailureBits: 40, BoundIsServerProven: true,
				SharesAreFreshUniform: true,
			},
			wantErr: true,
		},
		{
			name: "Ring127 frac50 insufficient",
			proof: LocalTruncationHeadroom{
				RingBits: 127, FracBits: 50, MaxAbsTruncatedValue: 1024,
				MaxTruncations: 1, MinFailureBits: 40, BoundIsServerProven: true,
				SharesAreFreshUniform: true,
			},
			wantErr: true,
		},
		{
			name: "Ring127 frac38 sufficient",
			proof: LocalTruncationHeadroom{
				RingBits: 127, FracBits: 38, MaxAbsTruncatedValue: 1024,
				MaxTruncations: 1, MinFailureBits: 40, BoundIsServerProven: true,
				SharesAreFreshUniform: true,
			},
		},
		{
			name: "Ring127 aggregate budget insufficient",
			proof: LocalTruncationHeadroom{
				RingBits: 127, FracBits: 38, MaxAbsTruncatedValue: 1024,
				MaxTruncations: 3, MinFailureBits: 40, BoundIsServerProven: true,
				SharesAreFreshUniform: true,
			},
			wantErr: true,
		},
		{
			name: "non finite bound",
			proof: LocalTruncationHeadroom{
				RingBits: 127, FracBits: 38, MaxAbsTruncatedValue: math.Inf(1),
				MaxTruncations: 1, MinFailureBits: 40, BoundIsServerProven: true,
				SharesAreFreshUniform: true,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.proof.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLocalTruncationHeadroomIsConservativeAtPowerOfTwoBoundary(t *testing.T) {
	base := LocalTruncationHeadroom{
		RingBits: 127, FracBits: 38, MaxTruncations: 1,
		MinFailureBits: 41, BoundIsServerProven: true,
		SharesAreFreshUniform: true,
	}
	base.MaxAbsTruncatedValue = 1024
	if err := base.Validate(); err != nil {
		t.Fatalf("exact power-of-two bound should prove 41 bits: %v", err)
	}
	base.MaxAbsTruncatedValue = math.Nextafter(1024, math.Inf(1))
	if err := base.Validate(); err == nil {
		t.Fatal("bound immediately above 2^10 was rounded down optimistically")
	}
}

func TestSelectLocalTruncationRingRoutesOrRejects(t *testing.T) {
	got, err := SelectLocalTruncationRing(10, 1, 1, 40, true, true)
	if err != nil || got != "ring63" {
		t.Fatalf("selection = (%q, %v), want (ring63, nil)", got, err)
	}
	got, err = SelectLocalTruncationRing(20, 1600, 1_000_000, 40, true, true)
	if err != nil || got != "ring127" {
		t.Fatalf("selection = (%q, %v), want (ring127, nil)", got, err)
	}
	if _, err := SelectLocalTruncationRing(50, 1600, 1, 40, true, true); err == nil {
		t.Fatal("selection accepted frac50 without enough Ring127 headroom")
	} else if !strings.Contains(err.Error(), "exact interactive fallback is unavailable") {
		t.Fatalf("selection did not identify the unavailable exact fallback: %v", err)
	}
	if _, err := SelectLocalTruncationRing(20, 1, 1, 40, false, true); err == nil {
		t.Fatal("selection accepted an analyst/unproven bound")
	}
	if _, err := SelectLocalTruncationRing(20, 1, 1, 40, true, false); err == nil {
		t.Fatal("selection accepted non-uniform shares")
	}
}

func TestNumericValidationErrorsAreSafeForJSON(t *testing.T) {
	_, err := encodeK2FloatToFP(K2FloatToFPInput{Values: []float64{math.NaN()}})
	if err == nil {
		t.Fatal("expected validation error")
	}
	if strings.ContainsAny(err.Error(), "\n\r\"") {
		t.Fatalf("validation error contains unsafe control/quote characters: %q", err)
	}
}

func TestCLIInputFailuresReturnOnlyCleanJSON(t *testing.T) {
	binaryPath := filepath.Join(t.TempDir(), "dsvert-mpc-test")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}

	nonCanonical := make([]byte, 16)
	nonCanonical[15] = 0x80
	nonCanonicalB64 := base64.StdEncoding.EncodeToString(nonCanonical)
	nonCanonical63 := make([]byte, 8)
	binary.LittleEndian.PutUint64(nonCanonical63, uint64(1)<<62)
	nonCanonical63B64 := base64.StdEncoding.EncodeToString(nonCanonical63)
	ring63NegativeOneAtBoundary := make([]byte, 8)
	binary.LittleEndian.PutUint64(ring63NegativeOneAtBoundary, uint64(3)<<62)
	ring63NegativeOneAtBoundaryB64 := base64.StdEncoding.EncodeToString(ring63NegativeOneAtBoundary)
	ring127NegativeOneAtBoundary := make([]byte, 16)
	binary.LittleEndian.PutUint64(ring127NegativeOneAtBoundary[8:], uint64(1)<<62)
	ring127NegativeOneAtBoundaryB64 := base64.StdEncoding.EncodeToString(ring127NegativeOneAtBoundary)
	one63, err := encodeK2FloatToFP(K2FloatToFPInput{
		Values: []float64{1}, FracBits: K2DefaultFracBits, Ring: "ring63",
	})
	if err != nil {
		t.Fatal(err)
	}
	half63, err := encodeK2FloatToFP(K2FloatToFPInput{
		Values: []float64{0.5}, FracBits: K2DefaultFracBits, Ring: "ring63",
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		command string
		input   string
	}{
		{
			name: "float overflow", command: "k2-float-to-fp",
			input: `{"values":[1e100],"ring":"ring63","frac_bits":20}`,
		},
		{
			name: "unknown ring", command: "k2-float-to-fp",
			input: `{"values":[1],"ring":"ring64"}`,
		},
		{
			name: "partial Ring63 record", command: "k2-fp-add",
			input: `{"a":"AAAA","b":"","ring":"ring63"}`,
		},
		{
			name: "non canonical Ring127", command: "k2-fp-add",
			input: `{"a":"` + nonCanonicalB64 + `","b":"` + nonCanonicalB64 + `","ring":"ring127"}`,
		},
		{
			name: "non canonical Ring63", command: "k2-fp-add",
			input: `{"a":"` + nonCanonical63B64 + `","b":"` + nonCanonical63B64 + `","ring":"ring63"}`,
		},
		{
			name: "non binary public mask", command: "k2-fp-vec-mul",
			input: `{"a":"` + one63.FPData + `","b":"` + half63.FPData + `","ring":"ring63","frac_bits":20}`,
		},
		{
			name: "Ring63 negative one cannot alias bit one", command: "k2-fp-vec-mul",
			input: `{"a":"` + one63.FPData + `","b":"` + ring63NegativeOneAtBoundaryB64 + `","ring":"ring63","frac_bits":62}`,
		},
		{
			name: "Ring127 negative one cannot alias bit one", command: "k2-fp-vec-mul",
			input: `{"a":"` + base64.StdEncoding.EncodeToString(make([]byte, 16)) + `","b":"` + ring127NegativeOneAtBoundaryB64 + `","ring":"ring127","frac_bits":126}`,
		},
		{
			name: "negative permutation dimensions", command: "k2-fp-permute-share",
			input: `{"a":"","perm":[],"n":0,"cols":-1,"ring":"ring63"}`,
		},
		{
			name: "permutation n mismatch", command: "k2-fp-permute-share",
			input: `{"a":"AAAAAAAAAAA=","perm":[0],"n":2,"cols":1,"ring":"ring63"}`,
		},
		{
			name: "malformed JSON", command: "k2-float-to-fp",
			input: `{"values":[1],`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(binaryPath, tt.command)
			cmd.Stdin = strings.NewReader(tt.input)
			output, _ := cmd.CombinedOutput()
			trimmed := bytes.TrimSpace(output)
			var parsed ErrorOutput
			if err := json.Unmarshal(trimmed, &parsed); err != nil {
				t.Fatalf("response is not one JSON error object: %v\n%s", err, output)
			}
			if parsed.Error == "" {
				t.Fatalf("empty JSON error: %s", output)
			}
			lower := strings.ToLower(string(output))
			if strings.Contains(lower, "panic") || strings.Contains(lower, "goroutine") {
				t.Fatalf("response exposed a Go failure trace: %s", output)
			}
		})
	}
}
