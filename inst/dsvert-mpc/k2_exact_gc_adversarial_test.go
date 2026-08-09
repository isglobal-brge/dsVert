package main

import (
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
)

func TestExactGCMulPlannerRing127BoundaryAndDynamicFallback(t *testing.T) {
	max127 := exactGCMaxSigned(127)
	fast, err := exactGCPlanMul(exactGCMulPlanInput{
		BoundX: max127.String(), BoundY: "1", FracBits: 50,
		FixedRingBits: 127,
	})
	if err != nil {
		t.Fatal(err)
	}
	if fast.Backend != string(exactGCMulBackendHybrid) ||
		!fast.RawProductHeadroom {
		t.Fatalf("Ring127 raw-product boundary did not use the guarded fast path: %#v",
			fast)
	}

	wide, err := exactGCPlanMul(exactGCMulPlanInput{
		BoundX: max127.String(), BoundY: "2", FracBits: 50,
		FixedRingBits: 127,
	})
	if err != nil {
		t.Fatal(err)
	}
	if wide.Backend != string(exactGCMulBackendDirect) ||
		wide.RawProductHeadroom || !wide.OutputHeadroom {
		t.Fatalf("Ring127 did not switch to its exact wide-product fallback: %#v",
			wide)
	}

	insufficient := exactGCMulPlanInput{
		BoundX: max127.String(), BoundY: "3", FracBits: 1,
		FixedRingBits: 127,
	}
	if _, err := exactGCPlanMul(insufficient); err == nil {
		t.Fatal("fixed Ring127 accepted a truncated result outside its signed range")
	}
	insufficient.FixedRingBits = 0
	dynamic, err := exactGCPlanMul(insufficient)
	if err != nil {
		t.Fatal(err)
	}
	if dynamic.RingBits != 128 ||
		dynamic.Backend != string(exactGCMulBackendDirect) ||
		dynamic.RawProductHeadroom || !dynamic.OutputHeadroom {
		t.Fatalf("Ring127 insufficiency did not produce the minimum dynamic ring: %#v",
			dynamic)
	}
}

func FuzzExactGCMulPlannerContract(f *testing.F) {
	f.Add("1", "1", 0, 0)
	f.Add(new(big.Int).Lsh(big.NewInt(1), 80).String(),
		new(big.Int).Lsh(big.NewInt(1), 80).String(), 50, 127)
	f.Add(strings.Repeat("9", exactGCMaxDecimalBoundDigits), "1", 4095, 0)
	f.Fuzz(func(t *testing.T, xString, yString string, fracBits, fixedRing int) {
		// Keep corpus entries bounded even before the production parser applies
		// its stricter canonical-decimal limit.
		if len(xString) > exactGCMaxDecimalBoundDigits+1 ||
			len(yString) > exactGCMaxDecimalBoundDigits+1 {
			return
		}
		input := exactGCMulPlanInput{
			BoundX: xString, BoundY: yString, FracBits: fracBits,
			FixedRingBits: fixedRing,
		}
		plan, err := exactGCPlanMul(input)
		if err != nil {
			return
		}
		x, xOK := new(big.Int).SetString(plan.BoundX, 10)
		y, yOK := new(big.Int).SetString(plan.BoundY, 10)
		truncated, truncatedOK := new(big.Int).SetString(plan.TruncatedBound, 10)
		if !xOK || !yOK || !truncatedOK {
			t.Fatalf("successful plan emitted non-decimal bounds: %#v", plan)
		}
		denominator := new(big.Int).Lsh(big.NewInt(1), uint(plan.FracBits))
		wantTruncated := exactGCCeilDiv(new(big.Int).Mul(x, y), denominator)
		if truncated.Cmp(wantTruncated) != 0 {
			t.Fatalf("successful plan understated its truncated bound: %#v", plan)
		}
		backend := exactGCMulBackend(plan.Backend)
		spec := exactGCCircuitSpec{
			Operation: exactGCMulTruncateChecked,
			RingBits:  plan.RingBits, FracBits: plan.FracBits,
			VectorLen: plan.MaxChunk, MulBackend: backend,
			BoundX: new(big.Int).Set(x), BoundY: new(big.Int).Set(y),
		}
		if err := spec.validate(); err != nil {
			t.Fatalf("planner emitted a non-executable contract: %v; %#v", err, plan)
		}
		replayed, err := exactGCPlanMul(input)
		if err != nil || replayed != plan {
			t.Fatalf("planner contract was not deterministic: %#v / %#v / %v",
				plan, replayed, err)
		}
	})
}

func FuzzExactGCCanonicalRecordDecoder(f *testing.F) {
	f.Add(uint16(0), make([]byte, 8))
	f.Add(uint16(64), make([]byte, 16))
	f.Add(uint16(66), append(make([]byte, 15), byte(0x80)))
	f.Fuzz(func(t *testing.T, ringOffset uint16, raw []byte) {
		ringBits := 63 + int(ringOffset)%(exactGCMaxRingBits-63+1)
		if len(raw) > 1024 {
			return
		}
		spec := exactGCCircuitSpec{
			Operation: exactGCTruncateFloor, RingBits: ringBits,
			FracBits: 0, VectorLen: 1,
		}
		wire := base64.StdEncoding.EncodeToString(raw)
		decoded, err := exactGCDecodeWorkerCanonicalShares(wire, spec)
		if err != nil {
			return
		}
		if err := exactGCValidateShares(decoded, spec); err != nil {
			t.Fatalf("decoder accepted a non-canonical residue: %v", err)
		}
		reencoded, err := exactGCEncodeWorkerCanonicalShares(decoded, spec)
		if err != nil {
			t.Fatal(err)
		}
		if reencoded != wire {
			t.Fatalf("canonical record round-trip changed Ring%d bytes", ringBits)
		}
	})
}
