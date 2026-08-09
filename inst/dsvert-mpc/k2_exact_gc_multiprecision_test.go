package main

import (
	"encoding/base64"
	"math/big"
	"math/rand"
	"testing"
)

func TestExactGCTypeWidthBoundaries(t *testing.T) {
	tests := []struct {
		ring int
		wire int
	}{
		{2, 64}, {63, 64}, {64, 64},
		{65, 128}, {127, 128}, {128, 128},
		{129, 256}, {255, 256}, {256, 256},
		{257, 512}, {511, 512}, {512, 512},
		{513, 1024}, {1023, 1024}, {1024, 1024},
		{1025, 2048}, {2048, 2048},
		{2049, 4096}, {4095, 4096}, {4096, 4096},
	}
	for _, test := range tests {
		if got := exactGCTypeBits(test.ring); got != test.wire {
			t.Fatalf("Ring%d: wire=%d want=%d", test.ring, got, test.wire)
		}
	}
}

func TestExactGCMultiprecisionCanonicalEncoding(t *testing.T) {
	for _, bits := range []int{
		64, 65, 128, 129, 256, 257, 511, 512, 513, 1024, 2049, 4096,
	} {
		spec := exactGCCircuitSpec{Operation: exactGCTruncateFloor,
			RingBits: bits, FracBits: 1, VectorLen: 4}
		values := []*big.Int{
			big.NewInt(0), big.NewInt(1), exactGCMask(bits),
			new(big.Int).Lsh(big.NewInt(1), uint(bits-1)),
		}
		encoded, err := exactGCEncodeWorkerCanonicalShares(values, spec)
		if err != nil {
			t.Fatalf("Ring%d encode: %v", bits, err)
		}
		decoded, err := exactGCDecodeWorkerCanonicalShares(encoded, spec)
		if err != nil {
			t.Fatalf("Ring%d decode: %v", bits, err)
		}
		for i := range values {
			if decoded[i].Cmp(values[i]) != 0 {
				t.Fatalf("Ring%d[%d]: got %s want %s", bits, i, decoded[i], values[i])
			}
		}

		if bits != exactGCTypeBits(bits) {
			raw, _ := base64.StdEncoding.DecodeString(encoded)
			recordBytes := exactGCRecordBytes(bits)
			usedBytes := (bits + 7) / 8
			if bits%8 != 0 {
				raw[usedBytes-1] |= 1 << uint(bits%8)
			} else {
				raw[usedBytes] = 1
			}
			if _, err := exactGCDecodeWorkerCanonicalShares(
				base64.StdEncoding.EncodeToString(raw), spec); err == nil {
				t.Fatalf("Ring%d accepted non-zero unused high bits (record=%d)",
					bits, recordBytes)
			}
		}
	}
}

func TestExactGCMultiprecisionCircuitsMatchReference(t *testing.T) {
	rng := rand.New(rand.NewSource(20260731))
	for _, bits := range []int{64, 65, 128, 129, 256, 257, 512, 513} {
		values := []*big.Int{
			big.NewInt(0), big.NewInt(1), exactGCMaxSigned(bits),
			new(big.Int).Lsh(big.NewInt(1), uint(bits-1)), exactGCMask(bits),
		}
		values = append(values, exactGCTestRandomResidue(rng, bits))

		t.Run("truncate/Ring"+big.NewInt(int64(bits)).String(), func(t *testing.T) {
			spec := exactGCCircuitSpec{Operation: exactGCTruncateFloor,
				RingBits: bits, FracBits: bits / 3, VectorLen: 1}
			circ, err := exactGCCompileCircuit(spec)
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range values {
				a := exactGCTestRandomResidue(rng, bits)
				b := new(big.Int).Sub(value, a)
				b.Mod(b, exactGCModulus(bits))
				masks := []*big.Int{
					exactGCTestRandomResidue(rng, bits),
				}
				got := exactGCTestComputeTruncateCircuit(t, circ, spec,
					[]*big.Int{a}, []*big.Int{b}, masks)[0]
				want := exactGCReferenceTruncateFloor(a, b, bits, spec.FracBits)
				if got.Cmp(want) != 0 {
					t.Fatalf("x=%s: got %s want %s", value, got, want)
				}
			}
		})

		t.Run("compare/Ring"+big.NewInt(int64(bits)).String(), func(t *testing.T) {
			threshold := big.NewInt(-1)
			spec := exactGCCircuitSpec{Operation: exactGCCompareSigned,
				RingBits: bits, Threshold: threshold, VectorLen: 1}
			circ, err := exactGCCompileCircuit(spec)
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range values {
				a := exactGCTestRandomResidue(rng, bits)
				b := new(big.Int).Sub(value, a)
				b.Mod(b, exactGCModulus(bits))
				mask := exactGCTestRandomResidue(rng, bits)
				got, err := circ.Compute([]*big.Int{
					exactGCPackGarblerInput([]*big.Int{a}, []*big.Int{mask}, spec),
					exactGCPackChunks([]*big.Int{b}, exactGCTypeBits(bits)),
				})
				if err != nil {
					t.Fatal(err)
				}
				reconstructed := exactGCReferenceReconstruct(mask, got[0], bits)
				want := big.NewInt(0)
				if exactGCReferenceCompare(a, b, threshold, bits) {
					want.SetInt64(1)
				}
				if reconstructed.Cmp(want) != 0 {
					t.Fatalf("x=%s: got=%s want=%s", value, reconstructed, want)
				}
			}
		})
	}
}

func TestExactGCMultiprecisionCountGuard(t *testing.T) {
	rng := rand.New(rand.NewSource(20260801))
	for _, bits := range []int{64, 65, 128, 129, 256, 257, 512, 513} {
		spec := exactGCCircuitSpec{Operation: exactGCCountGuard,
			RingBits: bits, Threshold: big.NewInt(5), VectorLen: 3}
		circ, err := exactGCCompileCircuit(spec)
		if err != nil {
			t.Fatalf("Ring%d compile: %v", bits, err)
		}
		for _, counts := range [][]*big.Int{
			{big.NewInt(0), big.NewInt(5), exactGCMaxSigned(bits)},
			{big.NewInt(0), big.NewInt(4), big.NewInt(5)},
			{big.NewInt(5), new(big.Int).Lsh(big.NewInt(1), uint(bits-1)), big.NewInt(8)},
		} {
			a, b := exactGCTestSplit(rng, counts, bits)
			mask := big.NewInt(int64(bits & 1))
			got, err := circ.Compute([]*big.Int{
				exactGCPackGarblerInput(a, []*big.Int{mask}, spec),
				exactGCPackChunks(b, exactGCTypeBits(bits)),
			})
			if err != nil {
				t.Fatal(err)
			}
			want := exactGCReferenceCountGuard(a, b, spec.Threshold, bits) !=
				(mask.Sign() != 0)
			if (got[0].Bit(0) == 1) != want {
				t.Fatalf("Ring%d counts=%v: got=%s want=%v", bits, counts, got[0], want)
			}
		}
	}
}

func TestExactGCRing4096TwoPeerTruncateAndCompare(t *testing.T) {
	const bits = 4096
	rng := rand.New(rand.NewSource(4096))
	signed := new(big.Int).Neg(new(big.Int).Add(
		new(big.Int).Lsh(big.NewInt(1), 3000), big.NewInt(12345)))
	residue := exactGCEncodeSigned(signed, bits)
	a, b := exactGCTestSplit(rng, []*big.Int{residue}, bits)

	truncate := exactGCCircuitSpec{
		Operation: exactGCTruncateFloor, RingBits: bits,
		FracBits: 1200, VectorLen: 1,
	}
	gShares, eShares := exactGCTestRunProtocol(t, truncate, a, b)
	got := exactGCReferenceReconstruct(gShares[0], eShares[0], bits)
	want := exactGCReferenceTruncateFloor(a[0], b[0], bits, truncate.FracBits)
	if got.Cmp(want) != 0 {
		t.Fatalf("Ring4096 truncation got %s want %s", got, want)
	}

	compare := exactGCCircuitSpec{
		Operation: exactGCCompareSigned, RingBits: bits,
		Threshold: big.NewInt(-1), VectorLen: 1,
	}
	gShares, eShares = exactGCTestRunProtocol(t, compare, a, b)
	got = exactGCReferenceReconstruct(gShares[0], eShares[0], bits)
	if got.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("Ring4096 signed comparison got %s want 1", got)
	}
}
