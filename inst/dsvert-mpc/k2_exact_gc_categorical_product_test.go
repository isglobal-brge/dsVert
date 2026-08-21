package main

import (
	"math/big"
	"math/rand"
	"testing"
)

func exactGCCategoricalProductTestInputs(t *testing.T, x, y []*big.Int) (
	exactGCCircuitSpec, []*big.Int, []*big.Int, []*big.Int,
) {
	t.Helper()
	if len(x) != len(y) || len(x) == 0 {
		t.Fatal("categorical product test inputs have the wrong shape")
	}
	scale := new(big.Int).Lsh(big.NewInt(1), 8)
	spec := exactGCCircuitSpec{
		Operation:  exactGCCategoricalProductRing128,
		RingBits:   128,
		FracBits:   8,
		BoundX:     new(big.Int).Set(scale),
		BoundY:     new(big.Int).Set(scale),
		MulBackend: exactGCMulBackendDirect,
		VectorLen:  len(x),
	}
	rng := rand.New(rand.NewSource(8128))
	leftX, rightX := exactGCTestSplit(rng, x, 128)
	leftY, rightY := exactGCTestSplit(rng, y, 128)
	left := append(leftX, leftY...)
	right := append(rightX, rightY...)
	want := make([]*big.Int, len(x))
	for i := range want {
		want[i] = big.NewInt(0)
		if x[i].Cmp(scale) == 0 && y[i].Cmp(scale) == 0 {
			want[i] = new(big.Int).Set(scale)
		}
	}
	return spec, left, right, want
}

func TestExactGCCategoricalProductRing128ExactAndFailClosed(t *testing.T) {
	scale := new(big.Int).Lsh(big.NewInt(1), 8)
	zero := big.NewInt(0)
	validX := []*big.Int{zero, zero, scale, scale}
	validY := []*big.Int{zero, scale, zero, scale}
	spec, left, right, want := exactGCCategoricalProductTestInputs(
		t, validX, validY)
	garbler, evaluator := exactGCTestRunProtocol(t, spec, left, right)
	if len(garbler) != spec.VectorLen+1 || len(evaluator) != spec.VectorLen+1 {
		t.Fatal("categorical product returned the wrong output shape")
	}
	for i := range want {
		got := exactGCReferenceReconstruct(garbler[i], evaluator[i], 128)
		if got.Cmp(want[i]) != 0 {
			t.Fatalf("coordinate %d: got %s want %s", i, got, want[i])
		}
	}
	if garbler[spec.VectorLen].Bit(0) == evaluator[spec.VectorLen].Bit(0) {
		t.Fatal("valid categorical product did not reconstruct success")
	}

	invalid := new(big.Int).Rsh(new(big.Int).Set(scale), 1)
	badSpec, badLeft, badRight, _ := exactGCCategoricalProductTestInputs(
		t, []*big.Int{scale, invalid}, []*big.Int{scale, scale})
	badGarbler, badEvaluator := exactGCTestRunProtocol(
		t, badSpec, badLeft, badRight)
	for i := 0; i < badSpec.VectorLen; i++ {
		if got := exactGCReferenceReconstruct(badGarbler[i], badEvaluator[i], 128); got.Sign() != 0 {
			t.Fatalf("invalid categorical input leaked output %d: %s", i, got)
		}
	}
	if badGarbler[badSpec.VectorLen].Bit(0) != badEvaluator[badSpec.VectorLen].Bit(0) {
		t.Fatal("invalid categorical input reconstructed success")
	}
}

func TestExactGCCategoricalProductRing128RejectsTypeConfusion(t *testing.T) {
	scale := new(big.Int).Lsh(big.NewInt(1), 8)
	valid := exactGCCircuitSpec{
		Operation:  exactGCCategoricalProductRing128,
		RingBits:   128,
		FracBits:   8,
		BoundX:     new(big.Int).Set(scale),
		BoundY:     new(big.Int).Set(scale),
		MulBackend: exactGCMulBackendDirect,
		VectorLen:  1,
	}
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	invalid := []exactGCCircuitSpec{
		{Operation: exactGCCategoricalProductRing128, RingBits: 127, FracBits: 8, BoundX: scale, BoundY: scale, MulBackend: exactGCMulBackendDirect, VectorLen: 1},
		{Operation: exactGCCategoricalProductRing128, RingBits: 128, FracBits: 7, BoundX: scale, BoundY: scale, MulBackend: exactGCMulBackendDirect, VectorLen: 1},
		{Operation: exactGCCategoricalProductRing128, RingBits: 128, FracBits: 8, BoundX: big.NewInt(255), BoundY: scale, MulBackend: exactGCMulBackendDirect, VectorLen: 1},
		{Operation: exactGCCategoricalProductRing128, RingBits: 128, FracBits: 8, BoundX: scale, BoundY: scale, MulBackend: exactGCMulBackendHybrid, VectorLen: 1},
	}
	for _, spec := range invalid {
		if err := spec.validate(); err == nil {
			t.Fatalf("accepted invalid categorical product spec: %+v", spec)
		}
	}
}
