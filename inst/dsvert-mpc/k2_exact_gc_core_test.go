package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/markkurossi/mpc/circuit"
)

func TestExactGCReferenceExhaustiveSmallRings(t *testing.T) {
	for bits := 2; bits <= 7; bits++ {
		mod := 1 << uint(bits)
		min := -(1 << uint(bits-1))
		max := (1 << uint(bits-1)) - 1
		for ai := 0; ai < mod; ai++ {
			for bi := 0; bi < mod; bi++ {
				residue := (ai + bi) & (mod - 1)
				signed := residue
				if residue&(1<<uint(bits-1)) != 0 {
					signed -= mod
				}
				a, b := big.NewInt(int64(ai)), big.NewInt(int64(bi))
				for threshold := min; threshold <= max; threshold++ {
					got := exactGCReferenceCompare(a, b, big.NewInt(int64(threshold)), bits)
					if got != (signed < threshold) {
						t.Fatalf("Ring%d compare: %d+%d (%d) < %d: got %v",
							bits, ai, bi, signed, threshold, got)
					}
				}
				for frac := 0; frac < bits; frac++ {
					want := floorDivPow2Int(signed, frac) & (mod - 1)
					got := exactGCReferenceTruncateFloor(a, b, bits, frac)
					if got.Cmp(big.NewInt(int64(want))) != 0 {
						t.Fatalf("Ring%d truncate: floor(%d/2^%d): got %s want %d",
							bits, signed, frac, got, want)
					}
					wantNearest := nearestEvenDivPow2Int(signed, frac) & (mod - 1)
					gotNearest := exactGCReferenceTruncateNearestEven(
						a, b, bits, frac)
					if gotNearest.Cmp(big.NewInt(int64(wantNearest))) != 0 {
						t.Fatalf("Ring%d nearest-even(%d/2^%d): got %s want %d",
							bits, signed, frac, gotNearest, wantNearest)
					}
				}
			}
		}
	}
}

func TestExactGCNearestEvenCircuitExhaustiveSmallRings(t *testing.T) {
	for bits := 2; bits <= 6; bits++ {
		modulus := 1 << uint(bits)
		for frac := 0; frac < bits; frac++ {
			spec := exactGCCircuitSpec{
				Operation: exactGCTruncateNearestEven, RingBits: bits,
				FracBits: frac, VectorLen: 1,
			}
			circ, err := exactGCCompileCircuit(spec)
			if err != nil {
				t.Fatalf("Ring%d frac=%d compile: %v", bits, frac, err)
			}
			for ai := 0; ai < modulus; ai++ {
				for bi := 0; bi < modulus; bi++ {
					a, b := big.NewInt(int64(ai)), big.NewInt(int64(bi))
					masks := []*big.Int{big.NewInt(int64((bi + 1) % modulus))}
					got := exactGCTestComputeTruncateCircuit(
						t, circ, spec, []*big.Int{a}, []*big.Int{b}, masks)[0]
					want := exactGCReferenceTruncateNearestEven(a, b, bits, frac)
					if got.Cmp(want) != 0 {
						t.Fatalf("Ring%d frac=%d a=%d b=%d: got %s want %s",
							bits, frac, ai, bi, got, want)
					}
				}
			}
		}
	}
}

func TestExactGCNearestEvenWideBoundariesHalvesAndProtocol(t *testing.T) {
	rng := rand.New(rand.NewSource(20260804))
	for _, bits := range []int{63, 127, 256, 512} {
		for _, frac := range []int{0, 1, bits / 2, bits - 1} {
			spec := exactGCCircuitSpec{
				Operation: exactGCTruncateNearestEven, RingBits: bits,
				FracBits: frac, VectorLen: 1,
			}
			circ, err := exactGCCompileCircuit(spec)
			if err != nil {
				t.Fatalf("Ring%d frac=%d compile: %v", bits, frac, err)
			}
			values := exactGCBoundaryValues(bits)
			if frac > 0 {
				half := new(big.Int).Lsh(big.NewInt(1), uint(frac-1))
				denom := new(big.Int).Lsh(big.NewInt(1), uint(frac))
				for _, q := range []int64{0, 1, 2} {
					positive := new(big.Int).Add(
						new(big.Int).Mul(big.NewInt(q), denom), half)
					for _, signed := range []*big.Int{positive,
						new(big.Int).Neg(new(big.Int).Set(positive))} {
						if exactGCFitsSigned(signed, bits) {
							values = append(values, exactGCEncodeSigned(signed, bits))
						}
					}
				}
			}
			for _, value := range values {
				a := exactGCTestRandomResidue(rng, bits)
				b := new(big.Int).Sub(value, a)
				b.Mod(b, exactGCModulus(bits))
				mask := []*big.Int{exactGCTestRandomResidue(rng, bits)}
				got := exactGCTestComputeTruncateCircuit(
					t, circ, spec, []*big.Int{a}, []*big.Int{b}, mask)[0]
				want := exactGCReferenceTruncateNearestEven(a, b, bits, frac)
				if got.Cmp(want) != 0 {
					t.Fatalf("Ring%d frac=%d value=%s: got %s want %s",
						bits, frac, exactGCReferenceSigned(value, bits), got, want)
				}
			}
		}
	}

	spec := exactGCCircuitSpec{Operation: exactGCTruncateNearestEven,
		RingBits: 127, FracBits: 50, VectorLen: 7}
	denom := new(big.Int).Lsh(big.NewInt(1), 50)
	half := new(big.Int).Rsh(new(big.Int).Set(denom), 1)
	values := []*big.Int{
		big.NewInt(0), new(big.Int).Set(half), new(big.Int).Neg(new(big.Int).Set(half)),
		new(big.Int).Add(new(big.Int).Set(denom), half),
		new(big.Int).Neg(new(big.Int).Add(new(big.Int).Set(denom), half)),
		exactGCMaxSigned(127),
		new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 126)),
	}
	residues := make([]*big.Int, len(values))
	for i, value := range values {
		residues[i] = exactGCEncodeSigned(value, 127)
	}
	a, b := exactGCTestSplit(rng, residues, 127)
	garbler, evaluator := exactGCTestRunProtocol(t, spec, a, b)
	for i := range residues {
		got := exactGCReferenceReconstruct(garbler[i], evaluator[i], 127)
		want := exactGCReferenceTruncateNearestEven(a[i], b[i], 127, 50)
		if got.Cmp(want) != 0 {
			t.Fatalf("Ring127 protocol value %d: got %s want %s", i, got, want)
		}
	}
}

func TestExactGCRoundingErrorCertificatesAndContextBinding(t *testing.T) {
	for frac := 1; frac <= 8; frac++ {
		denom := 1 << uint(frac)
		floorErrorSum := 0
		nearestErrorSum := 0
		maxFloorNumerator := 0
		maxNearestNumerator := 0
		for quotient := 0; quotient < 2; quotient++ {
			for remainder := 0; remainder < denom; remainder++ {
				x := quotient*denom + remainder
				floorError := floorDivPow2Int(x, frac)*denom - x
				nearestError := nearestEvenDivPow2Int(x, frac)*denom - x
				if quotient == 0 {
					floorErrorSum += floorError
				}
				nearestErrorSum += nearestError
				maxFloorNumerator = maxInt(maxFloorNumerator, absInt(floorError))
				maxNearestNumerator = maxInt(maxNearestNumerator, absInt(nearestError))
			}
		}
		if floorErrorSum != -denom*(denom-1)/2 ||
			maxFloorNumerator != denom-1 {
			t.Fatalf("floor certificate failed for f=%d", frac)
		}
		if nearestErrorSum != 0 || maxNearestNumerator != denom/2 {
			t.Fatalf("nearest-even certificate failed for f=%d", frac)
		}
	}

	floorSession := exactGCTestSession(exactGCCircuitSpec{
		Operation: exactGCTruncateFloor, RingBits: 127, FracBits: 50, VectorLen: 1})
	nearestSession := floorSession
	nearestSession.Spec.Operation = exactGCTruncateNearestEven
	if exactGCRoundingMode(floorSession.Spec) != "floor" ||
		exactGCRoundingMode(nearestSession.Spec) != "nearest-ties-to-even" ||
		exactGCContextDigest(floorSession) == exactGCContextDigest(nearestSession) {
		t.Fatal("rounding mode is not bound into the exact-gc context")
	}
}

func TestExactGCReferenceCountGuardExhaustiveSmallRing(t *testing.T) {
	const bits = 5
	mod := 1 << bits
	for ai := 0; ai < mod; ai++ {
		for bi := 0; bi < mod; bi++ {
			residue := (ai + bi) & (mod - 1)
			for threshold := 1; threshold < 1<<(bits-1); threshold++ {
				got := exactGCReferenceCountGuard(
					[]*big.Int{big.NewInt(int64(ai))},
					[]*big.Int{big.NewInt(int64(bi))},
					big.NewInt(int64(threshold)), bits)
				want := residue == 0 || (residue < 1<<(bits-1) && residue >= threshold)
				if got != want {
					t.Fatalf("guard(%d+%d mod %d, threshold=%d): got %v want %v",
						ai, bi, mod, threshold, got, want)
				}
			}
		}
	}
}

func TestExactGCClampCountExhaustiveSmallRings(t *testing.T) {
	for bits := 2; bits <= 7; bits++ {
		modulus := 1 << uint(bits)
		for upper := 1; upper < 1<<(uint(bits)-1); upper++ {
			spec := exactGCCircuitSpec{
				Operation: exactGCClampCount, RingBits: bits,
				Threshold: big.NewInt(int64(upper)), VectorLen: 1,
			}
			circ, err := exactGCCompileCircuit(spec)
			if err != nil {
				t.Fatalf("Ring%d upper=%d compile: %v", bits, upper, err)
			}
			for ai := 0; ai < modulus; ai++ {
				for bi := 0; bi < modulus; bi++ {
					a := big.NewInt(int64(ai))
					b := big.NewInt(int64(bi))
					mask := []*big.Int{big.NewInt(int64((3*ai + bi + 1) % modulus))}
					got := exactGCTestComputeTruncateCircuit(
						t, circ, spec, []*big.Int{a}, []*big.Int{b}, mask)[0]
					want := exactGCReferenceClampCount(
						a, b, spec.Threshold, bits)
					if got.Cmp(want) != 0 {
						t.Fatalf("Ring%d upper=%d a=%d b=%d: got %s want %s",
							bits, upper, ai, bi, got, want)
					}
				}
			}
		}
	}
}

func TestExactGCClampCountRing128SignedBoundaries(t *testing.T) {
	const bits = 128
	upper := big.NewInt(9007199254740991)
	spec := exactGCCircuitSpec{
		Operation: exactGCClampCount, RingBits: bits,
		Threshold: upper, VectorLen: 1,
	}
	values := []*big.Int{
		new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 127)),
		new(big.Int).Mul(big.NewInt(2), big.NewInt(-9223372036854775808)),
		big.NewInt(-1), big.NewInt(0), big.NewInt(1),
		new(big.Int).Sub(new(big.Int).Set(upper), big.NewInt(1)),
		new(big.Int).Set(upper),
		new(big.Int).Add(new(big.Int).Set(upper), big.NewInt(1)),
		new(big.Int).Mul(big.NewInt(2), big.NewInt(9223372036854775807)),
		exactGCMaxSigned(bits),
	}
	rng := rand.New(rand.NewSource(20260801))
	for _, signed := range values {
		residue := exactGCEncodeSigned(signed, bits)
		a := exactGCTestRandomResidue(rng, bits)
		b := new(big.Int).Sub(residue, a)
		b.Mod(b, exactGCModulus(bits))
		garbler, evaluator := exactGCTestRunProtocol(
			t, spec, []*big.Int{a}, []*big.Int{b})
		got := exactGCReferenceReconstruct(garbler[0], evaluator[0], bits)
		want := exactGCReferenceClampCount(a, b, upper, bits)
		if got.Cmp(want) != 0 {
			t.Fatalf("Ring128 signed=%s: got %s want %s", signed, got, want)
		}
	}
}

func TestExactGCSpecializedTruncateExhaustiveSmallRings(t *testing.T) {
	for bits := 2; bits <= 6; bits++ {
		modulus := 1 << uint(bits)
		for frac := 0; frac < bits; frac++ {
			spec := exactGCCircuitSpec{
				Operation: exactGCTruncateFloor, RingBits: bits,
				FracBits: frac, VectorLen: 1,
			}
			circ, err := exactGCCompileCircuit(spec)
			if err != nil {
				t.Fatalf("Ring%d frac=%d compile: %v", bits, frac, err)
			}
			for ai := 0; ai < modulus; ai++ {
				for bi := 0; bi < modulus; bi++ {
					a, b := big.NewInt(int64(ai)), big.NewInt(int64(bi))
					masks := []*big.Int{
						big.NewInt(int64((ai + 1) % modulus)),
					}
					got := exactGCTestComputeTruncateCircuit(
						t, circ, spec, []*big.Int{a}, []*big.Int{b}, masks)[0]
					want := exactGCReferenceTruncateFloor(a, b, bits, frac)
					if got.Cmp(want) != 0 {
						t.Fatalf("Ring%d frac=%d a=%d b=%d: got %s want %s",
							bits, frac, ai, bi, got, want)
					}
				}
			}
		}
	}
}

func TestExactGCSpecializedTruncatePropertiesWideRings(t *testing.T) {
	rng := rand.New(rand.NewSource(20260803))
	for _, bits := range []int{63, 127, 256, 512} {
		values := exactGCBoundaryValues(bits)
		values = append(values,
			exactGCEncodeSigned(big.NewInt(-1), bits),
			exactGCEncodeSigned(big.NewInt(-2), bits),
			exactGCEncodeSigned(
				new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), uint(bits-2))), bits))
		for i := 0; i < 32; i++ {
			values = append(values, exactGCTestRandomResidue(rng, bits))
		}
		fracs := []int{0, 1, bits / 2, bits - 1}
		for _, frac := range fracs {
			spec := exactGCCircuitSpec{
				Operation: exactGCTruncateFloor, RingBits: bits,
				FracBits: frac, VectorLen: 1,
			}
			circ, err := exactGCCompileCircuit(spec)
			if err != nil {
				t.Fatalf("Ring%d frac=%d compile: %v", bits, frac, err)
			}
			for _, value := range values {
				a := exactGCTestRandomResidue(rng, bits)
				b := new(big.Int).Sub(value, a)
				b.Mod(b, exactGCModulus(bits))
				masks := []*big.Int{
					exactGCTestRandomResidue(rng, bits),
				}
				got := exactGCTestComputeTruncateCircuit(
					t, circ, spec, []*big.Int{a}, []*big.Int{b}, masks)[0]
				want := exactGCReferenceTruncateFloor(a, b, bits, frac)
				if got.Cmp(want) != 0 {
					t.Fatalf("Ring%d frac=%d value=%s: got %s want %s",
						bits, frac, value, got, want)
				}
			}
		}
	}
}

func TestExactGCSpecializedTruncateCircuitBoundN180(t *testing.T) {
	const vectorLen = 180
	spec := exactGCCircuitSpec{
		Operation: exactGCTruncateFloor, RingBits: 127,
		FracBits: 50, VectorLen: vectorLen,
	}
	if got, want := exactGCCircuitInputBits(spec), 128*3*vectorLen; got != want {
		t.Fatalf("input bits=%d want=%d", got, want)
	}
	circ, err := exactGCCompileCircuit(spec)
	if err != nil {
		t.Fatal(err)
	}
	andGates := 0
	for _, gate := range circ.Gates {
		if gate.Op == circuit.AND {
			andGates++
		}
	}
	t.Logf("Ring127 specialized truncate n=%d: gates=%d AND=%d wires=%d",
		vectorLen, circ.NumGates, andGates, circ.NumWires)
	if circ.NumGates > 2_000_000 || andGates > 500_000 {
		t.Fatalf("specialized truncation exceeded linear circuit budget")
	}
}

func TestExactGCCircuitsMatchBigIntReference(t *testing.T) {
	rng := rand.New(rand.NewSource(20260731))
	for _, bits := range []int{63, 127} {
		values := exactGCBoundaryValues(bits)
		for i := 0; i < 64; i++ {
			values = append(values, exactGCTestRandomResidue(rng, bits))
		}

		t.Run(fmt.Sprintf("Ring%d/compare", bits), func(t *testing.T) {
			thresholds := []*big.Int{
				new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), uint(bits-1))),
				big.NewInt(-1), big.NewInt(0), big.NewInt(1), exactGCMaxSigned(bits),
			}
			for _, threshold := range thresholds {
				spec := exactGCCircuitSpec{
					Operation: exactGCCompareSigned,
					RingBits:  bits,
					Threshold: threshold,
					VectorLen: 1,
				}
				circ, err := exactGCCompileCircuit(spec)
				if err != nil {
					t.Fatal(err)
				}
				for _, x := range values {
					a := exactGCTestRandomResidue(rng, bits)
					b := new(big.Int).Sub(x, a)
					b.Mod(b, exactGCModulus(bits))
					mask := exactGCTestRandomResidue(rng, bits)
					g := exactGCPackGarblerInput([]*big.Int{a}, []*big.Int{mask}, spec)
					e := exactGCPackChunks([]*big.Int{b}, exactGCTypeBits(bits))
					got, err := circ.Compute([]*big.Int{g, e})
					if err != nil {
						t.Fatal(err)
					}
					reconstructed := exactGCReferenceReconstruct(mask, got[0], bits)
					want := big.NewInt(0)
					if exactGCReferenceCompare(a, b, threshold, bits) {
						want.SetInt64(1)
					}
					if reconstructed.Cmp(want) != 0 {
						t.Fatalf("x=%s threshold=%s mask=%s: got %s want %s",
							exactGCReferenceSigned(x, bits), threshold, mask, got[0], want)
					}
				}
			}
		})

		t.Run(fmt.Sprintf("Ring%d/truncate", bits), func(t *testing.T) {
			for _, frac := range []int{0, 1, bits / 2, bits - 1} {
				spec := exactGCCircuitSpec{
					Operation: exactGCTruncateFloor,
					RingBits:  bits,
					FracBits:  frac,
					VectorLen: 1,
				}
				circ, err := exactGCCompileCircuit(spec)
				if err != nil {
					t.Fatal(err)
				}
				for _, x := range values {
					a := exactGCTestRandomResidue(rng, bits)
					b := new(big.Int).Sub(x, a)
					b.Mod(b, exactGCModulus(bits))
					masks := []*big.Int{
						exactGCTestRandomResidue(rng, bits),
					}
					got := exactGCTestComputeTruncateCircuit(t, circ, spec,
						[]*big.Int{a}, []*big.Int{b}, masks)[0]
					want := exactGCReferenceTruncateFloor(a, b, bits, frac)
					if got.Cmp(want) != 0 {
						t.Fatalf("x=%s frac=%d: got %s want %s",
							exactGCReferenceSigned(x, bits), frac, got, want)
					}
				}
			}
		})

		t.Run(fmt.Sprintf("Ring%d/count-guard", bits), func(t *testing.T) {
			spec := exactGCCircuitSpec{
				Operation: exactGCCountGuard,
				RingBits:  bits,
				Threshold: big.NewInt(5),
				VectorLen: 5,
			}
			circ, err := exactGCCompileCircuit(spec)
			if err != nil {
				t.Fatal(err)
			}
			counts := []*big.Int{
				big.NewInt(0), big.NewInt(4), big.NewInt(5), exactGCMaxSigned(bits),
				new(big.Int).Lsh(big.NewInt(1), uint(bits-1)),
			}
			for bad := -1; bad < len(counts); bad++ {
				x := make([]*big.Int, spec.VectorLen)
				for i := range x {
					x[i] = big.NewInt(5)
				}
				if bad >= 0 {
					x[bad] = counts[bad]
				}
				a, b := exactGCTestSplit(rng, x, bits)
				mask := big.NewInt(int64((bad + 1) & 1))
				g := exactGCPackGarblerInput(a, []*big.Int{mask}, spec)
				e := exactGCPackChunks(b, exactGCTypeBits(bits))
				got, err := circ.Compute([]*big.Int{g, e})
				if err != nil {
					t.Fatal(err)
				}
				want := exactGCReferenceCountGuard(a, b, spec.Threshold, bits) !=
					(mask.Sign() != 0)
				if (got[0].Bit(0) == 1) != want {
					t.Fatalf("case %d mask=%s: got %s want %v", bad, mask, got[0], want)
				}
			}
		})
	}
}

func TestExactGCProtocolEndToEnd(t *testing.T) {
	tests := []struct {
		name string
		spec exactGCCircuitSpec
		x    []*big.Int
	}{
		{
			name: "Ring63 signed comparison vector",
			spec: exactGCCircuitSpec{Operation: exactGCCompareSigned, RingBits: 63,
				Threshold: big.NewInt(0), VectorLen: 4},
			x: []*big.Int{exactGCEncodeSigned(big.NewInt(-2), 63), big.NewInt(0),
				big.NewInt(1), exactGCMaxSigned(63)},
		},
		{
			name: "Ring127 exact floor truncation",
			spec: exactGCCircuitSpec{Operation: exactGCTruncateFloor, RingBits: 127,
				FracBits: 17, VectorLen: 4},
			x: []*big.Int{exactGCEncodeSigned(big.NewInt(-131073), 127),
				exactGCEncodeSigned(big.NewInt(-1), 127), big.NewInt(0),
				new(big.Int).Lsh(big.NewInt(1), 100)},
		},
		{
			name: "Ring127 exact count guard",
			spec: exactGCCircuitSpec{Operation: exactGCCountGuard, RingBits: 127,
				Threshold: big.NewInt(5), VectorLen: 5},
			x: []*big.Int{big.NewInt(0), big.NewInt(5), big.NewInt(6),
				new(big.Int).Lsh(big.NewInt(1), 80), exactGCMaxSigned(127)},
		},
		{
			name: "Ring128 private count clamp",
			spec: exactGCCircuitSpec{Operation: exactGCClampCount, RingBits: 128,
				Threshold: big.NewInt(1000), VectorLen: 5},
			x: []*big.Int{exactGCEncodeSigned(big.NewInt(-1), 128), big.NewInt(0),
				big.NewInt(999), big.NewInt(1000), big.NewInt(1001)},
		},
	}

	rng := rand.New(rand.NewSource(90125))
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a, b := exactGCTestSplit(rng, test.x, test.spec.RingBits)
			gOut, eOut := exactGCTestRunProtocol(t, test.spec, a, b)
			switch test.spec.Operation {
			case exactGCCompareSigned:
				for i := range gOut {
					got := exactGCReferenceReconstruct(
						gOut[i], eOut[i], test.spec.RingBits)
					want := big.NewInt(0)
					if exactGCReferenceCompare(a[i], b[i], test.spec.Threshold,
						test.spec.RingBits) {
						want.SetInt64(1)
					}
					if got.Cmp(want) != 0 {
						t.Fatalf("comparison %d: got %s want %s", i, got, want)
					}
				}
			case exactGCTruncateFloor:
				for i := range gOut {
					got := exactGCReferenceReconstruct(gOut[i], eOut[i], test.spec.RingBits)
					want := exactGCReferenceTruncateFloor(a[i], b[i], test.spec.RingBits,
						test.spec.FracBits)
					if got.Cmp(want) != 0 {
						t.Fatalf("truncation %d: got %s want %s", i, got, want)
					}
				}
			case exactGCCountGuard:
				got := gOut[0].Bit(0) != eOut[0].Bit(0)
				want := exactGCReferenceCountGuard(a, b, test.spec.Threshold,
					test.spec.RingBits)
				if got != want {
					t.Fatalf("guard: got %v want %v", got, want)
				}
			case exactGCClampCount:
				for i := range gOut {
					got := exactGCReferenceReconstruct(
						gOut[i], eOut[i], test.spec.RingBits)
					want := exactGCReferenceClampCount(
						a[i], b[i], test.spec.Threshold, test.spec.RingBits)
					if got.Cmp(want) != 0 {
						t.Fatalf("count clamp %d: got %s want %s", i, got, want)
					}
				}
			}
		})
	}
}

func TestExactGCProtocolFreshArithmeticShares(t *testing.T) {
	spec := exactGCCircuitSpec{
		Operation: exactGCTruncateFloor,
		RingBits:  63,
		FracBits:  9,
		VectorLen: 4,
	}
	x := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}
	rng := rand.New(rand.NewSource(72))
	a, b := exactGCTestSplit(rng, x, spec.RingBits)
	g0, _ := exactGCTestRunProtocol(t, spec, a, b)
	g1, _ := exactGCTestRunProtocol(t, spec, a, b)
	allEqual := true
	for i := range g0 {
		allEqual = allEqual && g0[i].Cmp(g1[i]) == 0
	}
	if allEqual {
		t.Fatal("fresh executions unexpectedly reused every arithmetic output share")
	}
}

func TestExactGCCountOutputMaskIsStableOnlyForItsBoundSeedAndContract(t *testing.T) {
	session := exactGCTestSession(exactGCCircuitSpec{
		Operation: exactGCClampCount, RingBits: 128,
		Threshold: big.NewInt(1000), VectorLen: 3,
	})
	seed := sha256.Sum256([]byte("durable-count-output-mask"))
	first, err := exactGCDeterministicOutputShares(session, seed)
	if err != nil {
		t.Fatal(err)
	}
	second, err := exactGCDeterministicOutputShares(session, seed)
	if err != nil {
		t.Fatal(err)
	}
	for i := range first {
		if first[i].Cmp(second[i]) != 0 || first[i].Sign() < 0 ||
			first[i].Cmp(exactGCModulus(128)) >= 0 {
			t.Fatalf("coordinate %d was not a stable canonical Ring128 mask", i)
		}
	}
	otherSeed := sha256.Sum256([]byte("different-count-output-mask"))
	changedSeed, err := exactGCDeterministicOutputShares(session, otherSeed)
	if err != nil {
		t.Fatal(err)
	}
	changedContract := session
	changedContract.Spec.Threshold = big.NewInt(999)
	changedThreshold, err := exactGCDeterministicOutputShares(changedContract, seed)
	if err != nil {
		t.Fatal(err)
	}
	allSeedEqual, allThresholdEqual := true, true
	for i := range first {
		allSeedEqual = allSeedEqual && first[i].Cmp(changedSeed[i]) == 0
		allThresholdEqual = allThresholdEqual &&
			first[i].Cmp(changedThreshold[i]) == 0
	}
	if allSeedEqual || allThresholdEqual {
		t.Fatal("Count output-mask derivation ignored its seed or clamp contract")
	}
}

func TestExactGCCountDeterministicSharesSurviveTransportRestart(t *testing.T) {
	spec := exactGCCircuitSpec{
		Operation: exactGCClampCount, RingBits: 128,
		Threshold: big.NewInt(1000), VectorLen: 1,
	}
	rng := rand.New(rand.NewSource(20260805))
	want := big.NewInt(73)
	a, b := exactGCTestSplit(rng, []*big.Int{want}, spec.RingBits)
	seed := sha256.Sum256([]byte("durable-count-release-seed"))

	firstSession := exactGCTestSession(spec)
	secondSession := firstSession
	secondSession.SessionID = sha256.Sum256([]byte("restarted-transport-session"))
	firstG, firstE := exactGCTestRunProtocolWithSeed(
		t, firstSession, a, b, seed)
	secondG, secondE := exactGCTestRunProtocolWithSeed(
		t, secondSession, a, b, seed)
	if firstG[0].Cmp(secondG[0]) != 0 || firstE[0].Cmp(secondE[0]) != 0 {
		t.Fatal("transport restart changed deterministic Count output shares")
	}
	if got := exactGCReferenceReconstruct(firstG[0], firstE[0], 128); got.Cmp(want) != 0 {
		t.Fatalf("restarted Count shares reconstruct %s, want %s", got, want)
	}

	otherSeed := sha256.Sum256([]byte("different-durable-count-release-seed"))
	thirdG, thirdE := exactGCTestRunProtocolWithSeed(
		t, secondSession, a, b, otherSeed)
	if thirdG[0].Cmp(firstG[0]) == 0 || thirdE[0].Cmp(firstE[0]) == 0 {
		t.Fatal("a distinct Count release seed unexpectedly reused an output share")
	}
	if got := exactGCReferenceReconstruct(thirdG[0], thirdE[0], 128); got.Cmp(want) != 0 {
		t.Fatalf("changed output mask changed Count result: got %s want %s", got, want)
	}
}

func TestExactGCProtocolFZeroIsExactAndRefreshesShares(t *testing.T) {
	spec := exactGCCircuitSpec{
		Operation: exactGCTruncateFloor,
		RingBits:  127,
		FracBits:  0,
		VectorLen: 5,
	}
	x := []*big.Int{
		big.NewInt(0), big.NewInt(1), exactGCEncodeSigned(big.NewInt(-1), 127),
		exactGCMaxSigned(127),
		exactGCEncodeSigned(new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 126)), 127),
	}
	rng := rand.New(rand.NewSource(721))
	a, b := exactGCTestSplit(rng, x, spec.RingBits)
	g0, e0 := exactGCTestRunProtocol(t, spec, a, b)
	g1, e1 := exactGCTestRunProtocol(t, spec, a, b)
	allGarblerSharesEqual := true
	for i := range x {
		for run, shares := range [][2][]*big.Int{{g0, e0}, {g1, e1}} {
			got := exactGCReferenceReconstruct(shares[0][i], shares[1][i], spec.RingBits)
			if got.Cmp(x[i]) != 0 {
				t.Fatalf("f=0 run %d value %d: got %s want %s", run, i, got, x[i])
			}
		}
		allGarblerSharesEqual = allGarblerSharesEqual && g0[i].Cmp(g1[i]) == 0
	}
	if allGarblerSharesEqual {
		t.Fatal("f=0 executions unexpectedly reused every arithmetic output share")
	}
}

func TestExactGCRejectsInvalidInputsBeforeProtocol(t *testing.T) {
	valid := exactGCTestSession(exactGCCircuitSpec{
		Operation: exactGCTruncateFloor, RingBits: 63, FracBits: 4, VectorLen: 1,
	})
	cases := []struct {
		name    string
		session exactGCSession
		shares  []*big.Int
	}{
		{"zero session", func() exactGCSession { s := valid; s.SessionID = [32]byte{}; return s }(), []*big.Int{big.NewInt(0)}},
		{"same identity", func() exactGCSession { s := valid; s.EvaluatorID = s.GarblerID; return s }(), []*big.Int{big.NewInt(0)}},
		{"control purpose", func() exactGCSession { s := valid; s.Purpose = "bad\ncontext"; return s }(), []*big.Int{big.NewInt(0)}},
		{"negative share", valid, []*big.Int{big.NewInt(-1)}},
		{"noncanonical share", valid, []*big.Int{exactGCModulus(63)}},
		{"wrong vector length", valid, nil},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := exactGCRunGarbler(nilReadWriter{}, test.session, test.shares); err == nil {
				t.Fatal("expected fail-closed validation error")
			}
		})
	}
}

func TestExactGCSpecValidation(t *testing.T) {
	invalid := []exactGCCircuitSpec{
		{Operation: exactGCCompareSigned, RingBits: exactGCMaxRingBits + 1, Threshold: big.NewInt(0), VectorLen: 1},
		{Operation: exactGCCompareSigned, RingBits: 63, Threshold: new(big.Int).Lsh(big.NewInt(1), 62), VectorLen: 1},
		{Operation: exactGCTruncateFloor, RingBits: 127, FracBits: 127, VectorLen: 1},
		{Operation: exactGCCountGuard, RingBits: 63, Threshold: big.NewInt(0), VectorLen: 1},
		{Operation: exactGCCountGuard, RingBits: 63, Threshold: big.NewInt(1), VectorLen: exactGCMaxVectorLen + 1},
		{Operation: exactGCTruncateFloor, RingBits: 512, FracBits: 1,
			VectorLen: exactGCMaxCircuitTypeBits/exactGCTypeBits(512) + 1},
		{Operation: exactGCTruncateFloor, RingBits: 4096, FracBits: 1,
			VectorLen: exactGCMaxCircuitTypeBits/(3*exactGCTypeBits(4096)) + 1},
		{Operation: "unknown", RingBits: 63, VectorLen: 1},
	}
	for _, spec := range invalid {
		if err := spec.validate(); err == nil {
			t.Fatalf("expected invalid spec: %+v", spec)
		}
	}
}

func exactGCTestRunProtocol(t *testing.T, spec exactGCCircuitSpec,
	a, b []*big.Int) ([]*big.Int, []*big.Int) {
	t.Helper()
	return exactGCTestRunProtocolSession(t, exactGCTestSession(spec), a, b, nil)
}

func exactGCTestRunProtocolWithSeed(t *testing.T, session exactGCSession,
	a, b []*big.Int, seed [32]byte) ([]*big.Int, []*big.Int) {
	t.Helper()
	return exactGCTestRunProtocolSession(t, session, a, b, &seed)
}

func exactGCTestRunProtocolSession(t *testing.T, session exactGCSession,
	a, b []*big.Int, seed *[32]byte) ([]*big.Int, []*big.Int) {
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
	garbler := make(chan result, 1)
	go func() {
		var shares []*big.Int
		var err error
		if seed == nil {
			shares, err = exactGCRunGarbler(left, session, a)
		} else {
			shares, err = exactGCRunGarblerWithDeterministicOutputSeed(
				left, session, a, *seed)
		}
		garbler <- result{shares, err}
	}()
	eShares, eErr := exactGCRunEvaluator(right, session, b)
	if eErr != nil {
		t.Fatalf("evaluator: %v", eErr)
	}
	select {
	case g := <-garbler:
		if g.err != nil {
			t.Fatalf("garbler: %v", g.err)
		}
		return g.shares, eShares
	case <-time.After(20 * time.Second):
		t.Fatal("garbler did not complete")
	}
	return nil, nil
}

func exactGCTestComputeTruncateCircuit(t *testing.T, circ *circuit.Circuit,
	spec exactGCCircuitSpec, a, b, masks []*big.Int) []*big.Int {

	t.Helper()
	width := exactGCTypeBits(spec.RingBits)
	garblerPacked := exactGCPackGarblerInput(a, masks, spec)
	inputs := make([]*big.Int, 0, 3*spec.VectorLen)
	for i := 0; i < 2*spec.VectorLen; i++ {
		chunk := new(big.Int).Rsh(new(big.Int).Set(garblerPacked), uint(i*width))
		inputs = append(inputs, chunk.And(chunk, exactGCMask(width)))
	}
	inputs = append(inputs, b...)
	outputs, err := circ.Compute(inputs)
	if err != nil {
		t.Fatal(err)
	}
	if len(outputs) != spec.VectorLen {
		t.Fatalf("got %d circuit outputs, want %d", len(outputs), spec.VectorLen)
	}
	result := make([]*big.Int, spec.VectorLen)
	for i := range result {
		result[i] = exactGCReferenceReconstruct(masks[i], outputs[i], spec.RingBits)
	}
	return result
}

func exactGCTestSession(spec exactGCCircuitSpec) exactGCSession {
	sid := sha256.Sum256([]byte(fmt.Sprintf("session/%s/%d/%d/%d",
		spec.Operation, spec.RingBits, spec.FracBits, time.Now().UnixNano())))
	key := sha256.Sum256([]byte("test-only exact-gc master key"))
	return exactGCSession{
		SessionID: sid, MasterKey: key,
		GarblerID: "peer-a-pinned-key", EvaluatorID: "peer-b-pinned-key",
		Purpose: "unit-test/vertical-inference",
		Spec:    spec,
	}
}

func exactGCTestSplit(rng *rand.Rand, x []*big.Int, bits int) ([]*big.Int, []*big.Int) {
	a := make([]*big.Int, len(x))
	b := make([]*big.Int, len(x))
	for i := range x {
		a[i] = exactGCTestRandomResidue(rng, bits)
		b[i] = new(big.Int).Sub(x[i], a[i])
		b[i].Mod(b[i], exactGCModulus(bits))
	}
	return a, b
}

func exactGCTestRandomResidue(rng *rand.Rand, bits int) *big.Int {
	buf := make([]byte, (bits+7)/8)
	_, _ = rng.Read(buf)
	result := new(big.Int).SetBytes(buf)
	return result.And(result, exactGCMask(bits))
}

func exactGCBoundaryValues(bits int) []*big.Int {
	sign := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	return []*big.Int{
		big.NewInt(0), big.NewInt(1),
		new(big.Int).Sub(new(big.Int).Set(sign), big.NewInt(1)),
		new(big.Int).Set(sign),
		new(big.Int).Add(new(big.Int).Set(sign), big.NewInt(1)),
		new(big.Int).Sub(exactGCModulus(bits), big.NewInt(1)),
	}
}

func exactGCEncodeSigned(x *big.Int, bits int) *big.Int {
	result := new(big.Int).Set(x)
	if result.Sign() < 0 {
		result.Add(result, exactGCModulus(bits))
	}
	return result
}

func floorDivPow2Int(x, frac int) int {
	if frac == 0 {
		return x
	}
	denom := 1 << uint(frac)
	if x >= 0 {
		return x / denom
	}
	return -((-x + denom - 1) / denom)
}

func nearestEvenDivPow2Int(x, frac int) int {
	if frac == 0 {
		return x
	}
	negative := x < 0
	if negative {
		x = -x
	}
	denom := 1 << uint(frac)
	quotient, remainder := x/denom, x%denom
	if 2*remainder > denom || (2*remainder == denom && quotient&1 == 1) {
		quotient++
	}
	if negative {
		return -quotient
	}
	return quotient
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

type nilReadWriter struct{}

func (nilReadWriter) Read([]byte) (int, error)  { return 0, fmt.Errorf("unexpected read") }
func (nilReadWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("unexpected write") }

func TestExactGCCircuitSourceContainsNoCleartextEscapeHatch(t *testing.T) {
	spec := exactGCCircuitSpec{
		Operation: exactGCCompareSigned, RingBits: 127,
		Threshold: big.NewInt(0), VectorLen: 1,
	}
	source := exactGCCircuitSource(spec)
	for _, forbidden := range []string{"native(", "print(", "panic("} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("generated circuit contains forbidden construct %q", forbidden)
		}
	}
}
