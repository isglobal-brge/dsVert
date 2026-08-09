package main

import (
	"math/big"
	"math/rand"
	"strings"
	"testing"
)

func exactGCTestPow2(bit uint) string {
	return new(big.Int).Lsh(big.NewInt(1), bit).String()
}

func TestExactGCMulPlannerChoosesMinimumRingAndBackend(t *testing.T) {
	tests := []struct {
		name     string
		input    exactGCMulPlanInput
		ring     int
		backend  exactGCMulBackend
		rawFits  bool
		maxChunk int
	}{
		{
			name: "minimum Ring63 direct",
			input: exactGCMulPlanInput{BoundX: exactGCTestPow2(30),
				BoundY: exactGCTestPow2(30), FracBits: 20},
			ring: 63, backend: exactGCMulBackendDirect, rawFits: true,
			maxChunk: exactGCMaxDirectMulLen,
		},
		{
			name: "Ring127 OT fast path",
			input: exactGCMulPlanInput{BoundX: exactGCTestPow2(60),
				BoundY: exactGCTestPow2(60), FracBits: 50, FixedRingBits: 127},
			ring: 127, backend: exactGCMulBackendHybrid, rawFits: true,
			maxChunk: exactGCMaxHybridVectorLen,
		},
		{
			name: "Ring127 exact wide-product fallback",
			input: exactGCMulPlanInput{BoundX: exactGCTestPow2(80),
				BoundY: exactGCTestPow2(80), FracBits: 50, FixedRingBits: 127},
			ring: 127, backend: exactGCMulBackendDirect, rawFits: false,
			maxChunk: exactGCMaxDirectMulLen,
		},
		{
			name: "arbitrary minimum wide ring",
			input: exactGCMulPlanInput{BoundX: exactGCTestPow2(400),
				BoundY: exactGCTestPow2(100), FracBits: 50},
			ring: 452, backend: exactGCMulBackendDirect, rawFits: false,
			maxChunk: exactGCMaxDirectMulLen,
		},
		{
			name: "above Ring512 minimum dynamic ring",
			input: exactGCMulPlanInput{BoundX: exactGCTestPow2(511),
				BoundY: exactGCTestPow2(511), FracBits: 0},
			ring: 1024, backend: exactGCMulBackendDirect, rawFits: true,
			maxChunk: 16,
		},
		{
			name: "Ring4096 container resource boundary",
			input: exactGCMulPlanInput{BoundX: exactGCTestPow2(2000),
				BoundY: exactGCTestPow2(2000), FracBits: 0},
			ring: 4002, backend: exactGCMulBackendDirect, rawFits: true,
			maxChunk: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := exactGCPlanMul(test.input)
			if err != nil {
				t.Fatal(err)
			}
			if plan.RingBits != test.ring ||
				plan.Backend != string(test.backend) ||
				plan.RoundingMode != "floor" ||
				plan.RawProductHeadroom != test.rawFits ||
				plan.MaxChunk != test.maxChunk || !plan.OutputHeadroom {
				t.Fatalf("unexpected plan: %#v", plan)
			}
			if len(plan.PlanID) != 64 || plan.Version != exactGCMulPlanVersion {
				t.Fatalf("unbound plan identity: %#v", plan)
			}
		})
	}
}

func TestExactGCMulPlannerRejectsImpossibleOrNonCanonicalBounds(t *testing.T) {
	for _, input := range []exactGCMulPlanInput{
		{BoundX: "01", BoundY: "1", FracBits: 0},
		{BoundX: "-1", BoundY: "1", FracBits: 0},
		{BoundX: strings.Repeat("9", exactGCMaxDecimalBoundDigits),
			BoundY: strings.Repeat("9", exactGCMaxDecimalBoundDigits), FracBits: 0},
		{BoundX: strings.Repeat("9", exactGCMaxDecimalBoundDigits+1),
			BoundY: "1", FracBits: 0},
		{BoundX: "1", BoundY: "1", FracBits: exactGCMaxRingBits},
		{BoundX: "1", BoundY: "1", FracBits: 0, FixedRingBits: 62},
	} {
		if _, err := exactGCPlanMul(input); err == nil {
			t.Fatalf("planner accepted invalid input: %#v", input)
		}
	}
}

func TestExactGCMulPlannerAcceptsFullPublishedDecimalDomain(t *testing.T) {
	bound := strings.Repeat("9", exactGCMaxDecimalBoundDigits)
	plan, err := exactGCPlanMul(exactGCMulPlanInput{
		BoundX: bound, BoundY: "1", FracBits: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.RingBits <= 512 || plan.RingBits > exactGCMaxRingBits ||
		plan.ContainerBits != 4096 || plan.MaxChunk != 1 {
		t.Fatalf("published maximum bound produced an invalid plan: %#v", plan)
	}
}

func TestExactGCMulPlannerRandomMinimumRingProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(20260801))
	for trial := 0; trial < 500; trial++ {
		xBits := 1 + rng.Intn(2500)
		yBits := 1 + rng.Intn(2500)
		fracBits := rng.Intn(700)
		x := new(big.Int).Rand(rng, new(big.Int).Lsh(big.NewInt(1), uint(xBits)))
		y := new(big.Int).Rand(rng, new(big.Int).Lsh(big.NewInt(1), uint(yBits)))
		x.SetBit(x, xBits-1, 1)
		y.SetBit(y, yBits-1, 1)

		product := new(big.Int).Mul(new(big.Int).Set(x), y)
		denominator := new(big.Int).Lsh(big.NewInt(1), uint(fracBits))
		truncated := exactGCCeilDiv(product, denominator)
		wantRing := 63
		for _, value := range []*big.Int{x, y, truncated} {
			if required := value.BitLen() + 1; required > wantRing {
				wantRing = required
			}
		}
		if fracBits+1 > wantRing {
			wantRing = fracBits + 1
		}

		plan, err := exactGCPlanMul(exactGCMulPlanInput{
			BoundX: x.String(), BoundY: y.String(), FracBits: fracBits,
		})
		if wantRing > exactGCMaxRingBits || exactGCMaxDirectMulChunk(wantRing) < 1 {
			if err == nil {
				t.Fatalf("trial %d: unrepresentable Ring%d received plan %#v",
					trial, wantRing, plan)
			}
			continue
		}
		if err != nil {
			t.Fatalf("trial %d: Ring%d planning failed: %v", trial, wantRing, err)
		}
		if plan.RingBits != wantRing || plan.BoundX != x.String() ||
			plan.BoundY != y.String() || plan.TruncatedBound != truncated.String() ||
			!plan.OutputHeadroom {
			t.Fatalf("trial %d: non-minimal or unbound plan: %#v", trial, plan)
		}
		rawFits := product.Cmp(exactGCMaxSigned(wantRing)) <= 0
		if plan.RawProductHeadroom != rawFits {
			t.Fatalf("trial %d: raw-product headroom=%v want %v",
				trial, plan.RawProductHeadroom, rawFits)
		}
		backend := exactGCMulBackendDirect
		maxChunk := exactGCMaxDirectMulChunk(wantRing)
		if wantRing == 127 && fracBits == 50 && rawFits {
			backend = exactGCMulBackendHybrid
			maxChunk = exactGCMaxHybridVectorLen
		}
		if plan.Backend != string(backend) || plan.MaxChunk != maxChunk {
			t.Fatalf("trial %d: backend/chunk mismatch: %#v", trial, plan)
		}
		spec := exactGCCircuitSpec{
			Operation: exactGCMulTruncateChecked,
			RingBits:  plan.RingBits, FracBits: plan.FracBits,
			VectorLen: plan.MaxChunk, MulBackend: backend,
			BoundX: new(big.Int).Set(x), BoundY: new(big.Int).Set(y),
		}
		if err := spec.validate(); err != nil {
			t.Fatalf("trial %d: emitted plan is not executable: %v", trial, err)
		}
		replayed, err := exactGCPlanMul(exactGCMulPlanInput{
			BoundX: x.String(), BoundY: y.String(), FracBits: fracBits,
		})
		if err != nil || replayed != plan {
			t.Fatalf("trial %d: planner is not deterministic", trial)
		}
	}
}

func TestExactGCDirectMulChunkTracksCircuitResources(t *testing.T) {
	for _, test := range []struct {
		ring, want int
	}{
		{63, 64}, {512, 64}, {513, 16}, {1024, 16},
		{1025, 4}, {2048, 4}, {2049, 1}, {4096, 1},
	} {
		if got := exactGCMaxDirectMulChunk(test.ring); got != test.want {
			t.Fatalf("Ring%d chunk=%d want=%d", test.ring, got, test.want)
		}
		bound := exactGCDefaultMulBound(test.ring, 0)
		spec := exactGCCircuitSpec{
			Operation: exactGCMulTruncateChecked,
			RingBits:  test.ring, FracBits: 0, VectorLen: test.want,
			MulBackend: exactGCMulBackendDirect,
			BoundX:     new(big.Int).Set(bound), BoundY: new(big.Int).Set(bound),
		}
		if err := spec.validate(); err != nil {
			t.Fatalf("Ring%d maximum planned chunk was rejected: %v", test.ring, err)
		}
		spec.VectorLen++
		if err := spec.validate(); err == nil {
			t.Fatalf("Ring%d accepted one element beyond its resource plan", test.ring)
		}
	}
}

func TestExactGCDirectWideProductSpecRejectsOnlyOutputOverflow(t *testing.T) {
	spec := exactGCCircuitSpec{
		Operation: exactGCMulTruncateChecked,
		RingBits:  127, FracBits: 50, VectorLen: 1,
		MulBackend: exactGCMulBackendDirect,
		BoundX:     new(big.Int).Lsh(big.NewInt(1), 80),
		BoundY:     new(big.Int).Lsh(big.NewInt(1), 80),
	}
	if err := spec.validate(); err != nil {
		t.Fatalf("direct wide product with fitting quotient was rejected: %v", err)
	}
	spec.BoundY = new(big.Int).Lsh(big.NewInt(1), 110)
	if err := spec.validate(); err == nil {
		t.Fatal("direct wide product accepted a quotient outside Ring127")
	}
}
