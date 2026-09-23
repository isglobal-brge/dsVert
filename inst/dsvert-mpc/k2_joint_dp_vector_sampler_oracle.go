package main

// Local CLI oracle for public synthetic evaluations. It never reads a server
// noise root or persistent seed: every key and context is supplied explicitly
// by the harness. This command is not registered as a DataSHIELD endpoint.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
)

type jointDPVectorSamplerOracleInput struct {
	Version             string `json:"version"`
	Epsilon             string `json:"epsilon"`
	AllocatedDelta      string `json:"allocated_delta,omitempty"`
	SensitivitySteps    string `json:"sensitivity_steps"`
	CoordinateCount     int    `json:"coordinate_count"`
	Replicates          int    `json:"replicates"`
	GarblerSeed         string `json:"garbler_seed"`
	EvaluatorSeed       string `json:"evaluator_seed"`
	ReleaseContractHash string `json:"release_contract_hash"`
	TranscriptHash      string `json:"transcript_hash"`
}

type jointDPVectorSamplerOracleDraw struct {
	Garbler                      []string                           `json:"garbler"`
	Evaluator                    []string                           `json:"evaluator"`
	Sum                          []string                           `json:"sum"`
	TranscriptHash               string                             `json:"transcript_hash"`
	GarblerInput                 jointDPVectorConvolutionShareInput `json:"garbler_input"`
	EvaluatorInput               jointDPVectorConvolutionShareInput `json:"evaluator_input"`
	GarblerSamplerContractHash   string                             `json:"garbler_sampler_contract_hash"`
	EvaluatorSamplerContractHash string                             `json:"evaluator_sampler_contract_hash"`
}

type jointDPVectorSamplerOracleOutput struct {
	Version             string                             `json:"version"`
	Sampler             string                             `json:"sampler"`
	PlanVersion         string                             `json:"plan_version"`
	Backend             string                             `json:"backend"`
	Guarantee           string                             `json:"guarantee"`
	Randomness          string                             `json:"randomness"`
	SeedScope           string                             `json:"seed_scope"`
	ImplementationDelta string                             `json:"implementation_delta"`
	Plan                jointDPVectorConvolutionPlanOutput `json:"plan"`
	Draws               []jointDPVectorSamplerOracleDraw   `json:"draws"`
}

func jointDPVectorSamplerOracle(input jointDPVectorSamplerOracleInput) (jointDPVectorSamplerOracleOutput, error) {
	var zero jointDPVectorSamplerOracleOutput
	if input.Version != "dsvert-dp-statistical-noise-oracle-input-v1" ||
		input.CoordinateCount < 1 || input.CoordinateCount > jointDPVectorConvolutionMaxChunk ||
		input.Replicates < 0 || input.Replicates > 100000 ||
		input.Replicates > jointDPVectorMaxTotal/input.CoordinateCount {
		return zero, fmt.Errorf("invalid synthetic sampler oracle shape")
	}
	if input.AllocatedDelta == "" {
		input.AllocatedDelta = "7.888609052210118e-31"
	}
	plan, err := jointDPPlanVectorConvolutionLaplace(jointDPVectorPlanInput{
		Epsilon: input.Epsilon, Delta: input.AllocatedDelta,
		SensitivitySteps: input.SensitivitySteps, TotalCoordinateCount: input.CoordinateCount,
	})
	if err != nil {
		return zero, err
	}
	transcript, err := jointDPDecodeHex32(input.TranscriptHash, "synthetic transcript")
	if err != nil || transcript == ([32]byte{}) {
		return zero, fmt.Errorf("invalid synthetic transcript")
	}
	if release, err := jointDPDecodeHex32(input.ReleaseContractHash, "synthetic release"); err != nil || release == ([32]byte{}) {
		return zero, fmt.Errorf("invalid synthetic release contract")
	}
	var seeds [2][32]byte
	for i, seed := range []string{input.GarblerSeed, input.EvaluatorSeed} {
		if !jointDPVectorConvolutionCanonicalSeedHex(seed) {
			return zero, fmt.Errorf("invalid public synthetic seed")
		}
		seeds[i], err = jointDPDecodeHex32(seed, "public synthetic seed")
		if err != nil {
			return zero, err
		}
	}
	guarantee := "approximate-dp-under-ideal-bits"
	if plan.ImplementationDeltaNumerator == "0" {
		guarantee = "pure-dp-under-ideal-bits"
	}
	result := jointDPVectorSamplerOracleOutput{
		Version: "dsvert-dp-statistical-noise-oracle-output-v1",
		Sampler: plan.Sampler, PlanVersion: plan.Version, Backend: jointDPVectorConvolutionBackend,
		Guarantee: guarantee, Randomness: "keyed-stream-computational",
		SeedScope:           "public-synthetic-test-fixture",
		ImplementationDelta: plan.ImplementationDeltaBound, Plan: plan,
		Draws: make([]jointDPVectorSamplerOracleDraw, input.Replicates),
	}
	for replicate := range result.Draws {
		h := sha256.New()
		h.Write([]byte("dsVert/joint-dp/statistical-oracle-transcript/v1/"))
		h.Write(transcript[:])
		var index [8]byte
		binary.BigEndian.PutUint64(index[:], uint64(replicate))
		h.Write(index[:])
		var currentTranscript [32]byte
		copy(currentTranscript[:], h.Sum(nil))
		draw := jointDPVectorSamplerOracleDraw{TranscriptHash: hex.EncodeToString(currentTranscript[:]), Sum: make([]string, input.CoordinateCount)}
		for peer, name := range []string{"oracle-garbler", "oracle-evaluator"} {
			context := jointDPCommitmentContext(currentTranscript, "convolution", name)
			commitment := jointDPSeedCommitment(context, seeds[peer])
			upper := make([]string, input.CoordinateCount)
			for i := range upper {
				upper[i] = "1"
			}
			shareInput := jointDPVectorConvolutionShareInput{
				Version: jointDPVectorConvolutionInputVersion, RingBits: 128, FracBits: 0,
				TotalCoordinateCount: input.CoordinateCount, ChunkStart: 0, CoordinateCount: input.CoordinateCount,
				OutputLatticeBits: 8, Epsilon: input.Epsilon, AllocatedDelta: input.AllocatedDelta,
				SensitivitySteps: input.SensitivitySteps, ScaleShifts: make([]int, input.CoordinateCount), RawUpperBounds: upper,
				ReleaseContractHash: input.ReleaseContractHash, TranscriptHash: draw.TranscriptHash, PeerName: name,
				CommitmentContext: hex.EncodeToString(context[:]), SeedCommitment: hex.EncodeToString(commitment[:]),
				PrivateSeed: hex.EncodeToString(seeds[peer][:]), SourceShare: base64.StdEncoding.EncodeToString(make([]byte, 16*input.CoordinateCount)),
			}
			spec, err := jointDPVectorConvolutionParseSpec(shareInput)
			if err != nil {
				return zero, err
			}
			noise, err := jointDPVectorConvolutionNoise(seeds[peer], spec)
			if err != nil {
				return zero, err
			}
			values := make([]string, len(noise))
			for i, value := range noise {
				values[i] = fmt.Sprint(value)
			}
			if peer == 0 {
				draw.Garbler, draw.GarblerInput, draw.GarblerSamplerContractHash = values, shareInput, hex.EncodeToString(spec.contractDigest[:])
			} else {
				draw.Evaluator, draw.EvaluatorInput, draw.EvaluatorSamplerContractHash = values, shareInput, hex.EncodeToString(spec.contractDigest[:])
			}
		}
		for i := range draw.Sum {
			left, _ := new(big.Int).SetString(draw.Garbler[i], 10)
			right, _ := new(big.Int).SetString(draw.Evaluator[i], 10)
			draw.Sum[i] = left.Add(left, right).String()
		}
		result.Draws[replicate] = draw
	}
	return result, nil
}

func handleJointDPVectorSamplerOracle() {
	input, err := jointDPVectorConvolutionDecode[jointDPVectorSamplerOracleInput](os.Stdin)
	if err != nil {
		mpcFatalError(err.Error())
	}
	result, err := jointDPVectorSamplerOracle(input)
	if err != nil {
		mpcFatalError(err.Error())
	}
	mpcWriteOutput(result)
}
