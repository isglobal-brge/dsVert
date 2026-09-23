package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

func jointDPVectorConvolutionV4TestInput(t testing.TB) jointDPVectorConvolutionShareInput {
	input := jointDPVectorConvolutionTestInput(t, "exact-peer", sha256.Sum256([]byte("exact-production-seed")),
		[]*big.Int{big.NewInt(2), big.NewInt(3), big.NewInt(7)}, []int64{10, 20, 30}, []int{0, 1, 2})
	input.Version, input.AllocatedDelta = jointDPVectorConvolutionInputVersionV4, "0"
	return input
}

func TestJointDPVectorConvolutionV4PlanningAndAdmission(t *testing.T) {
	input := jointDPVectorPlanInput{Epsilon: "1", Delta: "0", SensitivitySteps: "256", TotalCoordinateCount: 3}
	plan, err := jointDPPlanVectorConvolutionLaplaceV4(input)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Version != jointDPVectorConvolutionPlanVersionV4 || plan.Guarantee != "pure-dp-under-ideal-bits" || plan.Randomness != "keyed-stream-computational" ||
		plan.ImplementationDeltaBound != "0" || plan.PerPeerImplementationDeltaBound != "0" || plan.TwoPeerIdealTransferDeltaBound != "0" ||
		plan.MaximumNoiseMagnitude != "unbounded" || !plan.WrapBoundCertified || plan.RepresentabilityBound == "0" || plan.WrapBound != plan.RepresentabilityBound || plan.AdmittedRanges.RingBits != 128 {
		t.Fatalf("incorrect exact production certificate: %+v", plan)
	}
	if _, err := jointDPPlanVectorConvolutionLaplace(input); err == nil {
		t.Fatal("legacy finite sampler accepted zero delta")
	}
	input.Delta = ".01"
	positive, err := jointDPPlanVectorConvolutionLaplaceV4(input)
	if err != nil || !reflect.DeepEqual(plan, positive) {
		t.Fatal("allocated positive delta changed exact mechanism")
	}
	for name, change := range map[string]func(*jointDPVectorPlanInput){
		"zero epsilon":           func(x *jointDPVectorPlanInput) { x.Epsilon = "0" },
		"negative epsilon":       func(x *jointDPVectorPlanInput) { x.Epsilon = "-1" },
		"large epsilon":          func(x *jointDPVectorPlanInput) { x.Epsilon = "10000.0001" },
		"fractional sensitivity": func(x *jointDPVectorPlanInput) { x.SensitivitySteps = "1.1" },
		"zero sensitivity":       func(x *jointDPVectorPlanInput) { x.SensitivitySteps = "0" },
		"small rate": func(x *jointDPVectorPlanInput) {
			x.SensitivitySteps = new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 100), big.NewInt(1)).String()
		},
		"zero dimensions":  func(x *jointDPVectorPlanInput) { x.TotalCoordinateCount = 0 },
		"large dimensions": func(x *jointDPVectorPlanInput) { x.TotalCoordinateCount = 1000001 },
		"negative delta":   func(x *jointDPVectorPlanInput) { x.Delta = "-1" },
		"unit delta":       func(x *jointDPVectorPlanInput) { x.Delta = "1" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := input
			change(&bad)
			if _, err := jointDPPlanVectorConvolutionLaplaceV4(bad); err == nil {
				t.Fatal("out of range plan accepted")
			}
		})
	}
	input.SensitivitySteps, input.TotalCoordinateCount = new(big.Int).Lsh(big.NewInt(1), 100).String(), 1000000
	boundary, err := jointDPPlanVectorConvolutionLaplaceV4(input)
	if err != nil || boundary.RepresentabilityBound != "1e-44739235" {
		t.Fatalf("minimum-rate boundary: %+v %v", boundary, err)
	}
	input.Epsilon, input.SensitivitySteps = "10000", "1"
	if _, err := jointDPPlanVectorConvolutionLaplaceV4(input); err != nil {
		t.Fatal(err)
	}
}

func TestJointDPVectorConvolutionV4ProductionReplayAndCertificates(t *testing.T) {
	input := jointDPVectorConvolutionV4TestInput(t)
	first, err := jointDPVectorConvolutionSampleShare(input)
	if err != nil {
		t.Fatal(err)
	}
	again, err := jointDPVectorConvolutionSampleShare(input)
	if err != nil || !reflect.DeepEqual(first, again) {
		t.Fatal("exact production replay changed", err)
	}
	if first.Version != jointDPVectorConvolutionOutputVersionV4 || first.Backend != jointDPVectorConvolutionBackendV4 || first.NoWrapHeadroomCertified ||
		!first.WrapBoundCertified || first.SumWrapBound == "" || first.SumWrapThreshold == "" || first.MaximumNoiseMagnitudePerPeer != "unbounded" {
		t.Fatalf("incorrect exact share certificate: %+v", first)
	}
	encoded, err := json.Marshal(first)
	if err != nil || strings.Contains(string(encoded), "no_wrap_headroom_certified") {
		t.Fatal("v4 emitted a no-wrap claim")
	}
	changed := input
	changed.ReleaseContractHash = strings.Repeat("e", 64)
	next, err := jointDPVectorConvolutionSampleShare(changed)
	if err != nil || next.SamplerContractHash == first.SamplerContractHash || next.NoisedShare == first.NoisedShare {
		t.Fatal("release context not bound", err)
	}
	changed = input
	changed.RingBits = 64
	if _, err := jointDPVectorConvolutionSampleShare(changed); err == nil {
		t.Fatal("non-Ring128 accepted")
	}
	changed = input
	changed.RawUpperBounds = []string{exactGCMaxSigned(128).String(), "20", "30"}
	edge, err := jointDPVectorConvolutionSampleShare(changed)
	if err != nil || edge.SumWrapBound != "1" || edge.SumWrapThreshold != "0" {
		t.Fatal("large public bound not represented honestly", err)
	}
	changed.RawUpperBounds[0] = new(big.Int).Lsh(big.NewInt(1), 127).String()
	if _, err := jointDPVectorConvolutionSampleShare(changed); err == nil {
		t.Fatal("unrepresentable source bound accepted")
	}
}

func TestJointDPVectorConvolutionV4ArbitraryPrecisionModularAdditionAndDecode(t *testing.T) {
	input := jointDPVectorConvolutionV4TestInput(t)
	input.ScaleShifts = []int{0, 0, 0}
	input.RawUpperBounds = []string{"10", "20", "30"}
	share, _ := base64.StdEncoding.DecodeString(input.SourceShare)
	large := new(big.Int).Lsh(big.NewInt(1), 300)
	noise := []*big.Int{
		new(big.Int).Add(new(big.Int).Set(large), big.NewInt(3)),
		new(big.Int).Neg(new(big.Int).Add(new(big.Int).Set(large), big.NewInt(5))),
		new(big.Int).Add(new(big.Int).Set(large), new(big.Int).Lsh(big.NewInt(1), 127)),
	}
	before := []string{noise[0].String(), noise[1].String(), noise[2].String()}
	noised := jointDPVectorConvolutionAddExactNoise(share, input.ScaleShifts, noise)
	for i, text := range before {
		if noise[i].String() != text {
			t.Fatal("modular commitment changed unbounded draw")
		}
	}
	final := jointDPVectorConvolutionFinalizerInput{
		Version: jointDPVectorConvolutionFinalizerInputVersionV4, RingBits: 128, FracBits: 0,
		TotalCoordinateCount: input.TotalCoordinateCount, CoordinateCount: input.CoordinateCount, OutputLatticeBits: input.OutputLatticeBits,
		Epsilon: input.Epsilon, AllocatedDelta: input.AllocatedDelta, SensitivitySteps: input.SensitivitySteps,
		ScaleShifts: input.ScaleShifts, RawUpperBounds: input.RawUpperBounds, ReleaseContractHash: input.ReleaseContractHash, TranscriptHash: input.TranscriptHash,
		LeftNoisedShare: base64.StdEncoding.EncodeToString(noised), RightNoisedShare: base64.StdEncoding.EncodeToString(make([]byte, len(noised))),
	}
	out, err := jointDPVectorConvolutionFinalize(final)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out.ClampedScaledValues, []string{"5", "0", "0"}) || out.SignedDecode != jointDPVectorConvolutionSignedDecodeV4 || out.NoWrapHeadroomCertified || !out.WrapBoundCertified {
		t.Fatalf("modular fixed decode/clamp incorrect: %+v", out)
	}
}

func TestJointDPVectorConvolutionV4ContractBindsMetadata(t *testing.T) {
	input := jointDPVectorConvolutionV4TestInput(t)
	spec, err := jointDPVectorConvolutionParseSpec(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*jointDPVectorConvolutionPlanOutput){
		func(p *jointDPVectorConvolutionPlanOutput) { p.Guarantee = "different" },
		func(p *jointDPVectorConvolutionPlanOutput) { p.RepresentabilityBound = "0" },
		func(p *jointDPVectorConvolutionPlanOutput) { p.WrapBoundCertified = false },
		func(p *jointDPVectorConvolutionPlanOutput) { p.NoiseCommitment = "capped" },
	} {
		changed := spec.plan
		mutate(&changed)
		if jointDPVectorConvolutionContractDigest(input, changed) == spec.contractDigest {
			t.Fatal("v4 metadata omitted from sampler commitment")
		}
	}
}
