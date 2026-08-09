package main

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"net"
	"testing"
	"time"
)

var exactGCCRTTestPrimes = []uint64{
	2134733507, 1696126469, 1801551287,
	1806117659, 1940934407, 2080116407,
	1923065063, 1914461657, 2138348489,
}

func exactGCCRTTestSpec(bits, custodians, total, start, count int,
	bound *big.Int) exactGCCRTToRingSpec {
	lanes := 3
	if bits == 127 {
		lanes = 5
	} else if bits == 257 {
		lanes = 9
	}
	return exactGCCRTToRingSpec{
		RingBits:           bits,
		Moduli:             append([]uint64(nil), exactGCCRTTestPrimes[:lanes]...),
		MagnitudeBound:     new(big.Int).Set(bound),
		CustodianCount:     custodians,
		TotalCoordinates:   total,
		ChunkStart:         start,
		VectorLen:          count,
		ReleaseBinding:     sha256.Sum256([]byte("release-binding")),
		SourceSnapshotHMAC: sha256.Sum256([]byte("opaque-source-snapshot-hmac")),
		PinsetHash:         sha256.Sum256([]byte("pinned-compute-peer-set")),
		ArithmeticCertHash: sha256.Sum256([]byte("server-derived-no-wrap-certificate")),
	}
}

func exactGCCRTTestSplit(values []*big.Int,
	spec exactGCCRTToRingSpec) ([][]uint64, [][]uint64) {
	first := make([][]uint64, len(values))
	second := make([][]uint64, len(values))
	for coordinate, value := range values {
		first[coordinate] = make([]uint64, len(spec.Moduli))
		second[coordinate] = make([]uint64, len(spec.Moduli))
		for lane, modulus := range spec.Moduli {
			q := new(big.Int).SetUint64(modulus)
			residue := new(big.Int).Mod(new(big.Int).Set(value), q).Uint64()
			share := (uint64(7919*(coordinate+1)) + uint64(104729*(lane+1))) % modulus
			first[coordinate][lane] = share
			second[coordinate][lane] = (residue + modulus - share) % modulus
		}
	}
	return first, second
}

func TestExactGCCRTReferenceSignedWidthsAndCustodianCounts(t *testing.T) {
	for _, tc := range []struct {
		bits       int
		custodians int
	}{
		{63, 2}, {127, 3}, {257, 5},
	} {
		bound := exactGCMaxSigned(tc.bits)
		values := []*big.Int{
			new(big.Int).Neg(new(big.Int).Set(bound)), big.NewInt(-1),
			big.NewInt(0), big.NewInt(1), new(big.Int).Set(bound),
		}
		spec := exactGCCRTTestSpec(tc.bits, tc.custodians,
			len(values), 0, len(values), bound)
		first, second := exactGCCRTTestSplit(values, spec)
		got, valid, err := exactGCCRTReference(first, second, spec)
		if err != nil {
			t.Fatalf("Ring%d K=%d: %v", tc.bits, tc.custodians, err)
		}
		if !valid {
			t.Fatalf("Ring%d K=%d: valid tuple was rejected", tc.bits, tc.custodians)
		}
		for i, value := range values {
			want := new(big.Int).Mod(new(big.Int).Set(value), exactGCModulus(tc.bits))
			if got[i].Cmp(want) != 0 {
				t.Fatalf("Ring%d K=%d coordinate %d: got %s want %s",
					tc.bits, tc.custodians, i, got[i], want)
			}
		}
	}
}

func TestExactGCCRTCircuitMatchesOracleAndNeutralisesTuple(t *testing.T) {
	bound := exactGCMaxSigned(63)
	values := []*big.Int{
		new(big.Int).Neg(new(big.Int).Set(bound)), new(big.Int).Set(bound),
	}
	spec := exactGCCRTTestSpec(63, 5, len(values), 0, len(values), bound)
	first, second := exactGCCRTTestSplit(values, spec)
	got, valid := exactGCCRTTestComputeCircuit(t, spec, first, second)
	if !valid {
		t.Fatal("valid signed boundary tuple was rejected")
	}
	for i, value := range values {
		want := new(big.Int).Mod(new(big.Int).Set(value), exactGCModulus(63))
		if got[i].Cmp(want) != 0 {
			t.Fatalf("coordinate %d: got %s want %s", i, got[i], want)
		}
	}

	invalidSpec := exactGCCRTTestSpec(63, 3, 2, 0, 2, big.NewInt(100))
	invalidFirst, invalidSecond := exactGCCRTTestSplit(
		[]*big.Int{big.NewInt(7), big.NewInt(101)}, invalidSpec)
	neutral, accepted := exactGCCRTTestComputeCircuit(
		t, invalidSpec, invalidFirst, invalidSecond)
	if accepted || neutral[0].Sign() != 0 || neutral[1].Sign() != 0 {
		t.Fatalf("invalid tuple was not privately neutralised: valid=%v values=%v",
			accepted, neutral)
	}
}

func TestExactGCCRTCircuitWideRingBoundaries(t *testing.T) {
	for _, bits := range []int{127, 257} {
		bound := exactGCMaxSigned(bits)
		for _, value := range []*big.Int{
			new(big.Int).Neg(new(big.Int).Set(bound)), new(big.Int).Set(bound),
		} {
			spec := exactGCCRTTestSpec(bits, 5, 1, 0, 1, bound)
			first, second := exactGCCRTTestSplit([]*big.Int{value}, spec)
			got, valid := exactGCCRTTestComputeCircuit(t, spec, first, second)
			want := new(big.Int).Mod(new(big.Int).Set(value), exactGCModulus(bits))
			if !valid || got[0].Cmp(want) != 0 {
				t.Fatalf("Ring%d value=%s: valid=%v got=%s want=%s",
					bits, value, valid, got[0], want)
			}
		}
	}
}

func TestExactGCCRTStickyMasksSurviveRetryRestartAndRechunk(t *testing.T) {
	bound := big.NewInt(1_000_000)
	firstChunk := exactGCCRTTestSpec(63, 3, 4, 0, 2, bound)
	overlapChunk := exactGCCRTTestSpec(63, 3, 4, 1, 2, bound)
	seed := sha256.Sum256([]byte("persistent-custodian-output-mask-root"))
	first, firstValidity, err := exactGCCRTDeterministicMasks(seed, firstChunk)
	if err != nil {
		t.Fatal(err)
	}
	retry, retryValidity, err := exactGCCRTDeterministicMasks(seed, firstChunk)
	if err != nil {
		t.Fatal(err)
	}
	if first[0].Cmp(retry[0]) != 0 || first[1].Cmp(retry[1]) != 0 ||
		firstValidity != retryValidity {
		t.Fatal("retry/restart changed deterministic CRT output shares")
	}
	overlap, _, err := exactGCCRTDeterministicMasks(seed, overlapChunk)
	if err != nil {
		t.Fatal(err)
	}
	if first[1].Cmp(overlap[0]) != 0 {
		t.Fatal("transparent rechunk changed the global-coordinate output share")
	}
	firstPads, err := exactGCCRTDeterministicPads(seed, firstChunk)
	if err != nil {
		t.Fatal(err)
	}
	overlapPads, err := exactGCCRTDeterministicPads(seed, overlapChunk)
	if err != nil {
		t.Fatal(err)
	}
	if firstPads[1].Cmp(overlapPads[0]) != 0 {
		t.Fatal("transparent rechunk changed the global-coordinate CRT pad")
	}
	if firstChunk.purpose() == overlapChunk.purpose() {
		t.Fatal("chunk interval is not bound into the authenticated purpose")
	}

	rotatedSeed := sha256.Sum256([]byte("rotated-custodian-output-mask-root"))
	rotated, _, err := exactGCCRTDeterministicMasks(rotatedSeed, firstChunk)
	if err != nil {
		t.Fatal(err)
	}
	if first[0].Cmp(rotated[0]) == 0 && first[1].Cmp(rotated[1]) == 0 {
		t.Fatal("root rotation did not produce a new output-sharing epoch")
	}
	mutated := firstChunk
	mutated.ReleaseBinding[0] ^= 1
	changed, _, err := exactGCCRTDeterministicMasks(seed, mutated)
	if err != nil {
		t.Fatal(err)
	}
	if first[0].Cmp(changed[0]) == 0 && first[1].Cmp(changed[1]) == 0 {
		t.Fatal("release mutation reused output masks")
	}
}

func TestExactGCCRTMaskedOpeningIsExactOneTimePadAndAuthenticated(t *testing.T) {
	spec := exactGCCRTTestSpec(63, 3, 2, 0, 2, big.NewInt(1_000_000))
	values := []*big.Int{big.NewInt(-999999), big.NewInt(777777)}
	first, second := exactGCCRTTestSplit(values, spec)
	seed := sha256.Sum256([]byte("private-crt-conversion-pad-root"))
	pads, err := exactGCCRTDeterministicPads(seed, spec)
	if err != nil {
		t.Fatal(err)
	}
	for i, pad := range pads {
		if pad.Sign() < 0 || pad.Cmp(spec.product()) >= 0 {
			t.Fatalf("pad %d is outside [0,P)", i)
		}
	}
	masked := exactGCCRTMaskLocalResidues(first, pads, spec)
	encoded := exactGCCRTEncodeMaskedBundle(masked, spec)
	decoded, err := exactGCCRTDecodeMaskedBundle(encoded, spec)
	if err != nil {
		t.Fatal(err)
	}
	openings, err := exactGCCRTCombineMaskedOpening(decoded, second, spec)
	if err != nil {
		t.Fatal(err)
	}
	for i, value := range values {
		want := new(big.Int).Sub(new(big.Int).Set(value), pads[i])
		want.Mod(want, spec.product())
		if openings[i].Cmp(want) != 0 {
			t.Fatalf("masked opening %d: got %s want %s", i, openings[i], want)
		}
	}

	tampered := append([]byte(nil), encoded...)
	tampered[20] ^= 1
	if _, err := exactGCCRTDecodeMaskedBundle(tampered, spec); err == nil {
		t.Fatal("accepted a bundle with a tampered contract digest")
	}
	tampered = append([]byte(nil), encoded...)
	binary.BigEndian.PutUint64(tampered[exactGCCRTMaskedHeaderBytes:], spec.Moduli[0])
	if _, err := exactGCCRTDecodeMaskedBundle(tampered, spec); err == nil {
		t.Fatal("accepted a non-canonical masked CRT residue")
	}
	if _, err := exactGCCRTDecodeMaskedBundle(append(encoded, 0), spec); err == nil {
		t.Fatal("accepted trailing bytes in the masked CRT bundle")
	}

	// For every fixed x, r -> (x-r mod P) is a permutation of Z/PZ.  This
	// exhaustive small-domain certificate is the information-theoretic reason
	// the evaluator's opening is independent of the protected x.
	const smallProduct = 15
	for x := 0; x < smallProduct; x++ {
		seen := make([]bool, smallProduct)
		for r := 0; r < smallProduct; r++ {
			opening := (x - r + smallProduct) % smallProduct
			seen[opening] = true
		}
		for opening, present := range seen {
			if !present {
				t.Fatalf("x=%d masked opening %d is not reachable", x, opening)
			}
		}
	}
}

func TestExactGCCRTRealYaoKOSProtocolReturnsOnlyShares(t *testing.T) {
	spec := exactGCCRTTestSpec(63, 5, 1, 0, 1, big.NewInt(1_000_000))
	first, second := exactGCCRTTestSplit([]*big.Int{big.NewInt(-424242)}, spec)
	base := exactGCTestSession(exactGCCircuitSpec{
		Operation: exactGCTruncateFloor, RingBits: 63, VectorLen: 1,
	})
	session := exactGCCRTToRingSession(base, spec)
	seed := sha256.Sum256([]byte("persistent-private-mask-root"))
	garbler, evaluator := exactGCCRTTestRunProtocol(
		t, session, spec, first, second, seed)
	combined := exactGCReferenceReconstruct(garbler[0], evaluator[0], 63)
	want := new(big.Int).Mod(big.NewInt(-424242), exactGCModulus(63))
	if combined.Cmp(want) != 0 {
		t.Fatalf("protocol result: got %s want %s", combined, want)
	}
	if (garbler[1].Uint64()^evaluator[1].Uint64())&1 != 1 {
		t.Fatal("protocol validity shares do not reconstruct true")
	}
}

func TestExactGCCRTCircuitCostIsExplicitAndChunkable(t *testing.T) {
	for _, bits := range []int{63, 127, 257} {
		spec := exactGCCRTTestSpec(bits, 5, 1, 0, 1, big.NewInt(1_000_000))
		circ, err := exactGCCRTCompile(spec)
		if err != nil {
			t.Fatal(err)
		}
		var nonXOR uint64
		for _, gate := range circ.Gates {
			if exactGCGarbledRowSize(gate.Op) > 0 {
				nonXOR++
			}
		}
		if circ.Inputs.Size() != spec.typeBits()*(3*spec.VectorLen+1) {
			t.Fatalf("Ring%d circuit input accounting mismatch: got %d bits",
				bits, circ.Inputs.Size())
		}
		t.Logf("Ring%d lanes=%d coordinates=%d: gates=%d non-XOR=%d wires=%d input_bits=%d",
			spec.RingBits, len(spec.Moduli), spec.VectorLen, circ.NumGates,
			nonXOR, circ.NumWires, circ.Inputs.Size())
	}
}

func TestExactGCCRTRejectsUnboundAndMalformedInputs(t *testing.T) {
	spec := exactGCCRTTestSpec(63, 2, 1, 0, 1, big.NewInt(100))
	if err := spec.validate(); err != nil {
		t.Fatal(err)
	}
	invalid := spec
	invalid.ReleaseBinding = [32]byte{}
	if err := invalid.validate(); err == nil {
		t.Fatal("accepted an unbound release")
	}
	invalid = spec
	invalid.CustodianCount = 1
	if err := invalid.validate(); err == nil {
		t.Fatal("accepted fewer than two custodians")
	}
	invalid = spec
	invalid.ArithmeticCertHash = [32]byte{}
	if err := invalid.validate(); err == nil {
		t.Fatal("accepted a missing no-wrap arithmetic certificate")
	}
	invalid = spec
	invalid.Moduli[1] = invalid.Moduli[0]
	if err := invalid.validate(); err == nil {
		t.Fatal("accepted duplicate CRT primes")
	}
	first, _ := exactGCCRTTestSplit([]*big.Int{big.NewInt(1)}, spec)
	first[0][0] = spec.Moduli[0]
	if err := exactGCCRTValidateLocalShares(first, spec); err == nil {
		t.Fatal("accepted a non-canonical local residue")
	}
	if _, err := exactGCCompileCircuit(exactGCCircuitSpec{
		Operation: exactGCCRTToRingChecked, RingBits: 63, VectorLen: 1,
	}); err == nil {
		t.Fatal("generic exact-GC compiler accepted the specialised operation")
	}
}

func exactGCCRTTestComputeCircuit(t *testing.T, spec exactGCCRTToRingSpec,
	first, second [][]uint64) ([]*big.Int, bool) {
	t.Helper()
	circ, err := exactGCCRTCompile(spec)
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("direct-circuit-test-mask-root"))
	pads, err := exactGCCRTDeterministicPads(seed, spec)
	if err != nil {
		t.Fatal(err)
	}
	masks, validityMask, err := exactGCCRTDeterministicMasks(seed, spec)
	if err != nil {
		t.Fatal(err)
	}
	masked := exactGCCRTMaskLocalResidues(first, pads, spec)
	openings, err := exactGCCRTCombineMaskedOpening(masked, second, spec)
	if err != nil {
		t.Fatal(err)
	}
	inputs := []*big.Int{
		exactGCCRTPackCircuitInput(pads, masks, validityMask, spec, true),
		exactGCCRTPackCircuitInput(openings, nil, false, spec, false),
	}
	outputs, err := circ.Compute(inputs)
	if err != nil {
		t.Fatal(err)
	}
	if len(outputs) != 1 {
		t.Fatalf("got %d circuit outputs, want one packed array", len(outputs))
	}
	decoded := exactGCCRTUnpackOutputs(outputs[0], spec)
	values := make([]*big.Int, spec.VectorLen)
	for i := range values {
		values[i] = exactGCReferenceReconstruct(masks[i], decoded[i], spec.RingBits)
	}
	valid := (boolToUint64(validityMask)^decoded[spec.VectorLen].Uint64())&1 == 1
	return values, valid
}

func exactGCCRTTestRunProtocol(t *testing.T, session exactGCSession,
	spec exactGCCRTToRingSpec, first, second [][]uint64,
	seed [32]byte) ([]*big.Int, []*big.Int) {
	t.Helper()
	left, right := net.Pipe()
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})
	type result struct {
		shares []*big.Int
		err    error
	}
	done := make(chan result, 1)
	go func() {
		shares, err := exactGCCRTRunGarbler(left, session, spec, first, seed)
		done <- result{shares: shares, err: err}
	}()
	evaluator, err := exactGCCRTRunEvaluator(right, session, spec, second)
	if err != nil {
		t.Fatalf("evaluator: %v", err)
	}
	select {
	case garbler := <-done:
		if garbler.err != nil {
			t.Fatalf("garbler: %v", garbler.err)
		}
		return garbler.shares, evaluator
	case <-time.After(90 * time.Second):
		t.Fatal("CRT-to-Ring garbler did not complete")
	}
	return nil, nil
}
