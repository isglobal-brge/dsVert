package main

import (
	"crypto/sha256"
	"math/big"
	"math/rand"
	"testing"
)

func exactGCAlignmentTestDigestLimbs(value [32]byte) []*big.Int {
	return []*big.Int{
		new(big.Int).SetBytes(value[:16]),
		new(big.Int).SetBytes(value[16:]),
	}
}

func exactGCAlignmentTestInputs(t *testing.T, k int, mismatch int,
	zero bool) (exactGCCircuitSpec, []*big.Int, []*big.Int, []*big.Int) {
	t.Helper()
	spec := exactGCCircuitSpec{
		Operation: exactGCAlignmentMaskRing128,
		RingBits:  128,
		FracBits:  0,
		Threshold: big.NewInt(int64(k)),
		VectorLen: 3,
	}
	values := []*big.Int{
		big.NewInt(0),
		new(big.Int).SetUint64(0x0123456789abcdef),
		new(big.Int).Sub(exactGCModulus(128), big.NewInt(17)),
	}
	rng := rand.New(rand.NewSource(int64(2000 + 31*k + mismatch)))
	leftValues, rightValues := exactGCTestSplit(rng, values, 128)
	left := append([]*big.Int(nil), leftValues...)
	right := append([]*big.Int(nil), rightValues...)
	for source := 0; source < k; source++ {
		digest := sha256.Sum256([]byte("canonical private alignment"))
		if mismatch == source {
			digest = sha256.Sum256([]byte("different private alignment"))
		}
		if zero {
			digest = [32]byte{}
		}
		for _, limb := range exactGCAlignmentTestDigestLimbs(digest) {
			mask := exactGCTestRandomResidue(rng, 128)
			left = append(left, mask)
			right = append(right, new(big.Int).Xor(mask, limb))
		}
	}
	return spec, left, right, values
}

func TestExactGCAlignmentMaskRing128K2K3K5(t *testing.T) {
	for _, k := range []int{2, 3, 5} {
		t.Run("K"+big.NewInt(int64(k)).String(), func(t *testing.T) {
			spec, left, right, values := exactGCAlignmentTestInputs(t, k, -1, false)
			garbler, evaluator := exactGCTestRunProtocol(t, spec, left, right)
			if len(garbler) != spec.VectorLen+1 || len(evaluator) != spec.VectorLen+1 {
				t.Fatal("alignment-mask protocol returned the wrong shape")
			}
			for i := range values {
				got := exactGCReferenceReconstruct(garbler[i], evaluator[i], 128)
				if got.Cmp(values[i]) != 0 {
					t.Fatalf("valid coordinate %d changed: got %s want %s", i, got, values[i])
				}
			}
			if garbler[spec.VectorLen].Bit(0) == evaluator[spec.VectorLen].Bit(0) {
				t.Fatal("valid alignment did not reconstruct the terminal success bit")
			}

			for mismatch := 0; mismatch < k; mismatch++ {
				badSpec, badLeft, badRight, _ := exactGCAlignmentTestInputs(
					t, k, mismatch, false)
				badGarbler, badEvaluator := exactGCTestRunProtocol(
					t, badSpec, badLeft, badRight)
				for i := 0; i < badSpec.VectorLen; i++ {
					got := exactGCReferenceReconstruct(
						badGarbler[i], badEvaluator[i], 128)
					if got.Sign() != 0 {
						t.Fatalf("mismatch at source %d left coordinate %d unmasked", mismatch, i)
					}
				}
				if badGarbler[badSpec.VectorLen].Bit(0) !=
					badEvaluator[badSpec.VectorLen].Bit(0) {
					t.Fatalf("mismatch at source %d reconstructed success", mismatch)
				}
			}

			zeroSpec, zeroLeft, zeroRight, _ := exactGCAlignmentTestInputs(
				t, k, -1, true)
			zeroGarbler, zeroEvaluator := exactGCTestRunProtocol(
				t, zeroSpec, zeroLeft, zeroRight)
			for i := 0; i < zeroSpec.VectorLen; i++ {
				if exactGCReferenceReconstruct(
					zeroGarbler[i], zeroEvaluator[i], 128).Sign() != 0 {
					t.Fatal("the absent all-zero consensus was not masked")
				}
			}
		})
	}
}

func TestExactGCAlignmentMismatchLocationHasOneFixedCircuitShape(t *testing.T) {
	for _, k := range []int{2, 3, 5} {
		spec, _, _, _ := exactGCAlignmentTestInputs(t, k, -1, false)
		source := exactGCAlignmentMaskCircuitSource(spec)
		circuit, err := exactGCCompileCircuit(spec)
		if err != nil {
			t.Fatal(err)
		}
		session := exactGCTestSession(spec)
		context := exactGCContextDigest(session)
		for mismatch := 0; mismatch < k; mismatch++ {
			other, _, _, _ := exactGCAlignmentTestInputs(t, k, mismatch, false)
			otherCircuit, err := exactGCCompileCircuit(other)
			if err != nil {
				t.Fatal(err)
			}
			otherSession := session
			otherSession.Spec = other
			if exactGCAlignmentMaskCircuitSource(other) != source ||
				otherCircuit.NumGates != circuit.NumGates ||
				otherCircuit.NumWires != circuit.NumWires ||
				exactGCContextDigest(otherSession) != context {
				t.Fatalf("mismatch location %d changed public transcript shape for K=%d", mismatch, k)
			}
		}
	}
}

func TestExactGCAlignmentMaskRejectsTypeConfusionAndOversize(t *testing.T) {
	valid := exactGCCircuitSpec{
		Operation: exactGCAlignmentMaskRing128, RingBits: 128,
		Threshold: big.NewInt(2), VectorLen: 1,
	}
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	invalid := []exactGCCircuitSpec{
		{Operation: exactGCAlignmentMaskRing128, RingBits: 127, Threshold: big.NewInt(2), VectorLen: 1},
		{Operation: exactGCAlignmentMaskRing128, RingBits: 128, FracBits: 1, Threshold: big.NewInt(2), VectorLen: 1},
		{Operation: exactGCAlignmentMaskRing128, RingBits: 128, Threshold: big.NewInt(1), VectorLen: 1},
		{Operation: exactGCAlignmentMaskRing128, RingBits: 128, Threshold: big.NewInt(65), VectorLen: 1},
		{Operation: exactGCAlignmentMaskRing128, RingBits: 128, Threshold: nil, VectorLen: 1},
		{Operation: exactGCAlignmentMaskRing128, RingBits: 128, Threshold: big.NewInt(5), VectorLen: 1400},
	}
	for _, spec := range invalid {
		if err := spec.validate(); err == nil {
			t.Fatalf("accepted invalid alignment-mask spec: %+v", spec)
		}
	}
}

func TestExactGCAlignmentMaskUsesFullRingOutputMasks(t *testing.T) {
	spec, _, _, _ := exactGCAlignmentTestInputs(t, 2, -1, false)
	masks, err := exactGCRandomOutputShares(spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(masks) != spec.VectorLen+1 {
		t.Fatal("alignment-mask output mask shape changed")
	}
	for i := 0; i < spec.VectorLen; i++ {
		if masks[i].BitLen() <= 1 {
			t.Fatalf("value output mask %d was reduced to one bit", i)
		}
	}
	if masks[spec.VectorLen].BitLen() > 1 {
		t.Fatal("terminal validity mask was not a single XOR bit")
	}
}
