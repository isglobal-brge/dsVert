package main

// This command compiles only the public, purpose-bound Count sampler contract.
// It deliberately has no fields for a statistic share, transport key, master
// key or private seed.  Those values enter only the unlink-before-ready exact
// GC worker configuration on each pinned server.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
)

const (
	jointDPWorkerContractInputVersion  = "dsvert-joint-dp-laplace-worker-contract-input-v2"
	jointDPWorkerContractOutputVersion = "dsvert-joint-dp-laplace-worker-contract-v2"
	jointDPCountExactGCCapabilityID    = "joint_dp_count_exact_gc_v1"
	jointDPWorkerContractMaxBytes      = 64 << 10
)

type jointDPWorkerContractInput struct {
	Version                    string `json:"version"`
	RingBits                   int    `json:"ring_bits"`
	FracBits                   int    `json:"frac_bits"`
	CoordinateCount            int    `json:"coordinate_count"`
	Epsilon                    string `json:"epsilon"`
	AllocatedDelta             string `json:"allocated_delta"`
	SensitivitySteps           string `json:"sensitivity_steps"`
	EncodedLower               string `json:"encoded_lower"`
	EncodedUpper               string `json:"encoded_upper"`
	BernoulliBits              int    `json:"bernoulli_bits"`
	MaxSteps                   int    `json:"max_steps"`
	TranscriptHash             string `json:"transcript_hash"`
	GarblerCommitmentContext   string `json:"garbler_commitment_context"`
	EvaluatorCommitmentContext string `json:"evaluator_commitment_context"`
	GarblerSeedCommitment      string `json:"garbler_seed_commitment"`
	EvaluatorSeedCommitment    string `json:"evaluator_seed_commitment"`
}

type jointDPWorkerContractOutput struct {
	Version                 string                `json:"version"`
	CapabilityID            string                `json:"capability_id"`
	Operation               string                `json:"operation"`
	Purpose                 string                `json:"purpose"`
	CircuitDigest           string                `json:"circuit_digest"`
	InputContract           string                `json:"input_contract"`
	ProtectedInputsAccepted bool                  `json:"protected_inputs_accepted"`
	PrivateSeedAccepted     bool                  `json:"private_seed_accepted"`
	WorkerPolicy            jointDPGCWorkerPolicy `json:"worker_policy"`
	CapabilityAvailable     bool                  `json:"capability_available"`
}

func jointDPDecodeWorkerContractInput(reader io.Reader) (jointDPWorkerContractInput, error) {
	var input jointDPWorkerContractInput
	data, err := io.ReadAll(io.LimitReader(reader, jointDPWorkerContractMaxBytes+1))
	if err != nil || len(data) == 0 || len(data) > jointDPWorkerContractMaxBytes {
		return input, fmt.Errorf("invalid joint-DP worker contract input")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return input, fmt.Errorf("invalid joint-DP worker contract input")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return input, fmt.Errorf("invalid joint-DP worker contract input")
	}
	return input, nil
}

func jointDPCompileWorkerContract(input jointDPWorkerContractInput) (jointDPWorkerContractOutput, error) {
	var zero jointDPWorkerContractOutput
	// This promoted route is intentionally a scalar Count capability, not a
	// generic analyst-selected joint-DP circuit compiler.
	if input.Version != jointDPWorkerContractInputVersion ||
		input.RingBits != 127 || input.FracBits != 0 ||
		input.CoordinateCount != 1 || input.SensitivitySteps != "1" ||
		input.EncodedLower != "0" || input.MaxSteps < 1 ||
		input.MaxSteps > jointDPMaxGeometricSteps {
		return zero, fmt.Errorf("unsupported purpose-bound Count contract")
	}
	upper := new(big.Int)
	if _, ok := upper.SetString(input.EncodedUpper, 10); !ok || upper.Sign() <= 0 ||
		!exactGCFitsSigned(upper, input.RingBits) {
		return zero, fmt.Errorf("invalid Count release upper bound")
	}
	transcript, err := jointDPDecodeHex32(input.TranscriptHash, "transcript hash")
	if err != nil {
		return zero, err
	}
	gctx, err := jointDPDecodeHex32(input.GarblerCommitmentContext,
		"garbler commitment context")
	if err != nil {
		return zero, err
	}
	ectx, err := jointDPDecodeHex32(input.EvaluatorCommitmentContext,
		"evaluator commitment context")
	if err != nil {
		return zero, err
	}
	gcommit, err := jointDPDecodeHex32(input.GarblerSeedCommitment,
		"garbler seed commitment")
	if err != nil {
		return zero, err
	}
	ecommit, err := jointDPDecodeHex32(input.EvaluatorSeedCommitment,
		"evaluator seed commitment")
	if err != nil {
		return zero, err
	}
	plan, err := jointDPPlanLaplace(jointDPLaplacePlanInput{
		Epsilon: input.Epsilon, Delta: input.AllocatedDelta,
		SensitivitySteps: input.SensitivitySteps,
		CoordinateCount:  input.CoordinateCount,
		BernoulliBits:    input.BernoulliBits, MaxSteps: input.MaxSteps,
	})
	if err != nil {
		return zero, err
	}
	stop, err := strconv.ParseUint(plan.StopNumerator, 10, 32)
	if err != nil {
		return zero, fmt.Errorf("invalid planned stop numerator")
	}
	spec := jointDPGCLaplaceSpec{
		RingBits: input.RingBits, FracBits: input.FracBits,
		CoordinateCount: input.CoordinateCount,
		BernoulliBits:   input.BernoulliBits,
		StopNumerator:   uint32(stop), MaxGeometricSteps: plan.MaxGeometricSteps,
		SensitivitySteps: big.NewInt(1), EncodedLower: big.NewInt(0),
		EncodedUpper: upper, TranscriptHash: transcript,
		GarblerCommitmentContext: gctx, EvaluatorCommitmentContext: ectx,
		GarblerSeedCommitment: gcommit, EvaluatorSeedCommitment: ecommit,
	}
	if err := spec.validate(); err != nil {
		return zero, err
	}
	digest := spec.digest()
	digestHex := hex.EncodeToString(digest[:])
	policy := jointDPGCWorkerPolicy{
		Version: jointDPGCTemplateVersion, Sampler: jointDPSamplerVersion,
		BernoulliBits:     plan.BernoulliBits,
		StopNumerator:     plan.StopNumerator,
		MaxGeometricSteps: plan.MaxGeometricSteps,
		SensitivitySteps:  plan.SensitivitySteps,
		Epsilon:           input.Epsilon, AllocatedDelta: input.AllocatedDelta,
		EncodedLower: input.EncodedLower, EncodedUpper: input.EncodedUpper,
		TranscriptHash:                 input.TranscriptHash,
		GarblerCommitmentContext:       input.GarblerCommitmentContext,
		EvaluatorCommitmentContext:     input.EvaluatorCommitmentContext,
		GarblerSeedCommitment:          input.GarblerSeedCommitment,
		EvaluatorSeedCommitment:        input.EvaluatorSeedCommitment,
		CircuitDigest:                  digestHex,
		ImplementationDeltaNumerator:   plan.ImplementationDeltaNumerator,
		ImplementationDeltaDenominator: plan.ImplementationDeltaDenom,
	}
	return jointDPWorkerContractOutput{
		Version:      jointDPWorkerContractOutputVersion,
		CapabilityID: jointDPCountExactGCCapabilityID,
		Operation:    string(exactGCJointDPLaplace), Purpose: spec.purpose(),
		CircuitDigest: digestHex, InputContract: "public-data-free-count-v1",
		ProtectedInputsAccepted: false, PrivateSeedAccepted: false,
		WorkerPolicy: policy, CapabilityAvailable: true,
	}, nil
}

func handleJointDPLaplaceWorkerContract() {
	input, err := jointDPDecodeWorkerContractInput(os.Stdin)
	if err != nil {
		outputError("joint-DP Count worker contract unavailable")
		return
	}
	result, err := jointDPCompileWorkerContract(input)
	if err != nil {
		outputError("joint-DP Count worker contract unavailable")
		return
	}
	mpcWriteOutput(result)
}
