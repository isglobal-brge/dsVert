package main

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"
)

func jointDPVectorSamplerOracleFixture() jointDPVectorSamplerOracleInput {
	return jointDPVectorSamplerOracleInput{
		Version: "dsvert-dp-statistical-noise-oracle-input-v1", Epsilon: "1", SensitivitySteps: "256", CoordinateCount: 3, Replicates: 2,
		GarblerSeed: strings.Repeat("a", 64), EvaluatorSeed: strings.Repeat("b", 64), ReleaseContractHash: strings.Repeat("c", 64), TranscriptHash: strings.Repeat("d", 64),
	}
}

func TestJointDPVectorSamplerOracleCallsProductionAndReplays(t *testing.T) {
	input := jointDPVectorSamplerOracleFixture()
	first, err := jointDPVectorSamplerOracle(input)
	if err != nil {
		t.Fatal(err)
	}
	again, err := jointDPVectorSamplerOracle(input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, again) {
		t.Fatal("synthetic oracle replay changed")
	}
	if first.PlanVersion != jointDPVectorConvolutionPlanVersionV4 || first.Sampler != jointDPVectorConvolutionSamplerVersionV4 || first.Backend != jointDPVectorConvolutionBackendV4 ||
		first.SeedScope != "public-synthetic-test-fixture" || first.ImplementationDelta != first.Plan.ImplementationDeltaBound {
		t.Fatal("oracle mislabeled production plan")
	}
	if first.Draws[0].TranscriptHash == first.Draws[1].TranscriptHash {
		t.Fatal("replicate stream reused")
	}
	for _, draw := range first.Draws {
		for peer, shareInput := range []jointDPVectorConvolutionShareInput{draw.GarblerInput, draw.EvaluatorInput} {
			out, err := jointDPVectorConvolutionSampleShare(shareInput)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := base64.StdEncoding.DecodeString(out.NoisedShare)
			if err != nil {
				t.Fatal(err)
			}
			values := draw.Garbler
			if peer == 1 {
				values = draw.Evaluator
			}
			for i, text := range values {
				want, _ := new(big.Int).SetString(text, 10)
				want.Mod(want, exactGCModulus(128))
				got := exactGCLittleEndianBig(raw[16*i : 16*(i+1)])
				if got.Cmp(want) != 0 {
					t.Fatal("oracle draw differs from productive share sampler")
				}
			}
		}
		for i, text := range draw.Sum {
			left, _ := new(big.Int).SetString(draw.Garbler[i], 10)
			right, _ := new(big.Int).SetString(draw.Evaluator[i], 10)
			if left.Add(left, right).String() != text {
				t.Fatal("oracle sum changed")
			}
		}
	}
	input.Replicates = 0
	preflight, err := jointDPVectorSamplerOracle(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(preflight.Draws) != 0 || !reflect.DeepEqual(preflight.Plan, first.Plan) {
		t.Fatal("plan-only preflight sampled or changed plan")
	}
}

func TestJointDPVectorSamplerOracleRejectsMalformedFixtures(t *testing.T) {
	for _, mutate := range []func(*jointDPVectorSamplerOracleInput){
		func(i *jointDPVectorSamplerOracleInput) { i.Version = "production" },
		func(i *jointDPVectorSamplerOracleInput) { i.CoordinateCount = 0 },
		func(i *jointDPVectorSamplerOracleInput) { i.Replicates = -1 },
		func(i *jointDPVectorSamplerOracleInput) { i.CoordinateCount = 8192; i.Replicates = 100000 },
		func(i *jointDPVectorSamplerOracleInput) { i.GarblerSeed = "secret-root-name" },
		func(i *jointDPVectorSamplerOracleInput) { i.TranscriptHash = strings.Repeat("0", 64) },
	} {
		input := jointDPVectorSamplerOracleFixture()
		mutate(&input)
		if _, err := jointDPVectorSamplerOracle(input); err == nil {
			t.Fatal("invalid fixture accepted")
		}
	}
}

func TestJointDPVectorSamplerOracleKnownAnswerV4(t *testing.T) {
	data, err := os.ReadFile("testdata/joint-dp-vector-convolution-v4.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Input  jointDPVectorSamplerOracleInput  `json:"input"`
		Output jointDPVectorSamplerOracleOutput `json:"output"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	got, err := jointDPVectorSamplerOracle(fixture.Input)
	if err != nil || !reflect.DeepEqual(got, fixture.Output) {
		t.Fatal("v4 production known-answer changed", err)
	}
}

func TestJointDPVectorSamplerOracleLegacyV3Selection(t *testing.T) {
	input := jointDPVectorSamplerOracleFixture()
	input.SamplerVersion = jointDPVectorConvolutionSamplerVersion
	result, err := jointDPVectorSamplerOracle(input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Sampler != jointDPVectorConvolutionSamplerVersion || result.Guarantee != "approximate-dp-under-ideal-bits" || result.ImplementationDelta == "0" {
		t.Fatal("legacy oracle lost v3 semantics")
	}
	input.SamplerVersion = "unknown"
	if _, err := jointDPVectorSamplerOracle(input); err == nil {
		t.Fatal("unknown oracle version accepted")
	}
}
