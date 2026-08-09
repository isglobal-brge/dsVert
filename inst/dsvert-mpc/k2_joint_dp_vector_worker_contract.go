package main

// Data-free compiler for one purpose-bound biomedical vector chunk.  The
// command accepts only public capsule metadata and public per-coordinate
// bounds.  Protected Ring128 shares and the private sticky seed enter only the
// unlink-before-ready exact-GC worker configuration on each pinned peer.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
)

const (
	jointDPVectorWorkerContractInputVersion  = "dsvert-joint-dp-vector-worker-contract-input-v3"
	jointDPVectorWorkerContractOutputVersion = "dsvert-joint-dp-vector-worker-contract-v3"
	jointDPVectorExactGCCapabilityID         = "joint_dp_biomedical_vector_exact_gc_v1"
	jointDPVectorWorkerContractMaxBytes      = 256 << 10
)

type jointDPVectorWorkerContractInput struct {
	Version                    string   `json:"version"`
	RingBits                   int      `json:"ring_bits"`
	FracBits                   int      `json:"frac_bits"`
	TotalCoordinateCount       int      `json:"total_coordinate_count"`
	ChunkStart                 int      `json:"chunk_start"`
	CoordinateCount            int      `json:"coordinate_count"`
	OutputLatticeBits          int      `json:"output_lattice_bits"`
	Epsilon                    string   `json:"epsilon"`
	AllocatedDelta             string   `json:"allocated_delta"`
	SensitivitySteps           string   `json:"sensitivity_steps"`
	ScaleShifts                []int    `json:"scale_shifts"`
	RawUpperBounds             []string `json:"raw_upper_bounds"`
	TranscriptHash             string   `json:"transcript_hash"`
	GarblerCommitmentContext   string   `json:"garbler_commitment_context"`
	EvaluatorCommitmentContext string   `json:"evaluator_commitment_context"`
	GarblerSeedCommitment      string   `json:"garbler_seed_commitment"`
	EvaluatorSeedCommitment    string   `json:"evaluator_seed_commitment"`
}

type jointDPVectorWorkerContractOutput struct {
	Version                 string                    `json:"version"`
	CapabilityID            string                    `json:"capability_id"`
	Operation               string                    `json:"operation"`
	Purpose                 string                    `json:"purpose"`
	CircuitDigest           string                    `json:"circuit_digest"`
	InputContract           string                    `json:"input_contract"`
	ProtectedInputsAccepted bool                      `json:"protected_inputs_accepted"`
	PrivateSeedAccepted     bool                      `json:"private_seed_accepted"`
	WorkerPolicy            jointDPVectorWorkerPolicy `json:"worker_policy"`
	Plan                    jointDPVectorPlanOutput   `json:"plan"`
	CapabilityAvailable     bool                      `json:"capability_available"`
}

func jointDPVectorDecodeWorkerContractInput(
	reader io.Reader,
) (jointDPVectorWorkerContractInput, error) {
	var input jointDPVectorWorkerContractInput
	data, err := io.ReadAll(io.LimitReader(
		reader, jointDPVectorWorkerContractMaxBytes+1))
	if err != nil || len(data) == 0 || len(data) > jointDPVectorWorkerContractMaxBytes {
		return input, fmt.Errorf("invalid joint-DP vector worker contract input")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return input, fmt.Errorf("invalid joint-DP vector worker contract input")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return input, fmt.Errorf("invalid joint-DP vector worker contract input")
	}
	return input, nil
}

func jointDPVectorParseInt(value, name string, positive bool) (*big.Int, error) {
	result := new(big.Int)
	if _, ok := result.SetString(value, 10); !ok ||
		(positive && result.Sign() <= 0) || (!positive && result.Sign() < 0) {
		return nil, fmt.Errorf("joint-dp-vector-gc: invalid %s", name)
	}
	return result, nil
}

func jointDPVectorSpecFromPolicy(policy jointDPVectorWorkerPolicy,
	session exactGCSession) (jointDPVectorSpec, error) {
	var zero jointDPVectorSpec
	if policy.Version != jointDPVectorTemplateVersion ||
		policy.Sampler != jointDPVectorSamplerVersion ||
		policy.CoordinateCount != session.Spec.VectorLen {
		return zero, fmt.Errorf("joint-dp-vector-gc: missing public worker contract")
	}
	sensitivity, err := jointDPVectorParseInt(
		policy.SensitivitySteps, "sensitivity steps", true)
	if err != nil {
		return zero, err
	}
	stop, err := jointDPVectorParseInt(policy.StopNumerator, "stop numerator", true)
	if err != nil {
		return zero, err
	}
	thresholds := make([]*big.Int, len(policy.BernoulliThresholds))
	for index, value := range policy.BernoulliThresholds {
		thresholds[index], err = jointDPVectorParseInt(
			value, "Bernoulli threshold", false)
		if err != nil {
			return zero, err
		}
	}
	upper := make([]*big.Int, len(policy.RawUpperBounds))
	for index, value := range policy.RawUpperBounds {
		upper[index], err = jointDPVectorParseInt(value, "raw upper bound", false)
		if err != nil {
			return zero, err
		}
	}
	transcript, err := jointDPDecodeHex32(policy.TranscriptHash, "transcript hash")
	if err != nil {
		return zero, err
	}
	gctx, err := jointDPDecodeHex32(
		policy.GarblerCommitmentContext, "garbler commitment context")
	if err != nil {
		return zero, err
	}
	ectx, err := jointDPDecodeHex32(
		policy.EvaluatorCommitmentContext, "evaluator commitment context")
	if err != nil {
		return zero, err
	}
	gcommit, err := jointDPDecodeHex32(
		policy.GarblerSeedCommitment, "garbler seed commitment")
	if err != nil {
		return zero, err
	}
	ecommit, err := jointDPDecodeHex32(
		policy.EvaluatorSeedCommitment, "evaluator seed commitment")
	if err != nil {
		return zero, err
	}
	spec := jointDPVectorSpec{
		RingBits: 128, FracBits: 0,
		OutputLatticeBits:    policy.OutputLatticeBits,
		TotalCoordinateCount: policy.TotalCoordinateCount,
		ChunkStart:           policy.ChunkStart, CoordinateCount: policy.CoordinateCount,
		SensitivitySteps: sensitivity, StopNumerator: stop,
		StopBits: policy.StopBits, UniformBits: policy.UniformBits,
		BinaryGeometricBits: policy.BinaryGeometricBits,
		BernoulliThresholds: thresholds,
		ScaleShifts:         append([]int(nil), policy.ScaleShifts...),
		RawUpperBounds:      upper,
		TranscriptHash:      transcript, GarblerCommitmentContext: gctx,
		EvaluatorCommitmentContext: ectx, GarblerSeedCommitment: gcommit,
		EvaluatorSeedCommitment: ecommit,
	}
	if err := spec.validate(); err != nil {
		return zero, err
	}
	plan, err := jointDPPlanVectorLaplace(jointDPVectorPlanInput{
		Epsilon: policy.Epsilon, Delta: policy.AllocatedDelta,
		SensitivitySteps:     policy.SensitivitySteps,
		TotalCoordinateCount: policy.TotalCoordinateCount,
	})
	if err != nil || plan.StopBits != policy.StopBits ||
		plan.StopNumerator != policy.StopNumerator ||
		plan.UniformBits != policy.UniformBits ||
		plan.BinaryGeometricBits != policy.BinaryGeometricBits ||
		!equalStrings(plan.BernoulliThresholds, policy.BernoulliThresholds) ||
		plan.ImplementationDeltaNumerator != policy.ImplementationDeltaNumerator ||
		plan.ImplementationDeltaDenominator != policy.ImplementationDeltaDenominator {
		return zero, fmt.Errorf("joint-dp-vector-gc: invalid global privacy certificate")
	}
	digest := spec.digest()
	if policy.CircuitDigest != hex.EncodeToString(digest[:]) ||
		session.Purpose != spec.purpose() {
		return zero, fmt.Errorf("joint-dp-vector-gc: worker circuit digest mismatch")
	}
	return spec, nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func jointDPVectorWorkerInputs(config exactGCWorkerConfig,
	session exactGCSession) (jointDPVectorSpec, [32]byte, error) {
	var zeroSpec jointDPVectorSpec
	var zeroSeed [32]byte
	if config.JointDPVector == nil {
		return zeroSpec, zeroSeed, fmt.Errorf("joint-dp-vector-gc: missing worker policy")
	}
	spec, err := jointDPVectorSpecFromPolicy(*config.JointDPVector, session)
	if err != nil {
		return zeroSpec, zeroSeed, err
	}
	seedBytes, err := exactGCStrictBase64(config.PrivateSeed, 32)
	if err != nil {
		return zeroSpec, zeroSeed, fmt.Errorf("joint-dp-vector-gc: invalid private seed")
	}
	var seed [32]byte
	copy(seed[:], seedBytes)
	commitment := spec.GarblerSeedCommitment
	context := spec.GarblerCommitmentContext
	if config.Role == "evaluator" {
		commitment = spec.EvaluatorSeedCommitment
		context = spec.EvaluatorCommitmentContext
	} else if config.Role != "garbler" {
		return zeroSpec, zeroSeed, fmt.Errorf("joint-dp-vector-gc: invalid worker role")
	}
	if jointDPSeedCommitment(context, seed) != commitment {
		clear(seed[:])
		return zeroSpec, zeroSeed, fmt.Errorf("joint-dp-vector-gc: local seed commitment mismatch")
	}
	return spec, seed, nil
}

func jointDPCompileVectorWorkerContract(
	input jointDPVectorWorkerContractInput,
) (jointDPVectorWorkerContractOutput, error) {
	var zero jointDPVectorWorkerContractOutput
	if input.Version != jointDPVectorWorkerContractInputVersion ||
		input.RingBits != 128 || input.FracBits != 0 ||
		input.OutputLatticeBits < 1 || input.OutputLatticeBits > 62 ||
		input.TotalCoordinateCount < 1 ||
		input.TotalCoordinateCount > jointDPVectorMaxTotal ||
		input.CoordinateCount != len(input.ScaleShifts) ||
		input.CoordinateCount != len(input.RawUpperBounds) ||
		input.CoordinateCount < 1 ||
		input.ChunkStart < 0 ||
		input.ChunkStart > input.TotalCoordinateCount-input.CoordinateCount {
		return zero, fmt.Errorf("unsupported purpose-bound vector contract")
	}
	plan, err := jointDPPlanVectorLaplace(jointDPVectorPlanInput{
		Epsilon: input.Epsilon, Delta: input.AllocatedDelta,
		SensitivitySteps:     input.SensitivitySteps,
		TotalCoordinateCount: input.TotalCoordinateCount,
	})
	if err != nil || input.CoordinateCount > plan.MaximumChunkCoordinates {
		return zero, fmt.Errorf("unsupported purpose-bound vector chunk")
	}
	policy := jointDPVectorWorkerPolicy{
		Version: jointDPVectorTemplateVersion, Sampler: jointDPVectorSamplerVersion,
		TotalCoordinateCount: input.TotalCoordinateCount,
		ChunkStart:           input.ChunkStart, CoordinateCount: input.CoordinateCount,
		OutputLatticeBits: input.OutputLatticeBits,
		SensitivitySteps:  input.SensitivitySteps,
		Epsilon:           input.Epsilon, AllocatedDelta: input.AllocatedDelta,
		StopBits: plan.StopBits, StopNumerator: plan.StopNumerator,
		UniformBits:                    plan.UniformBits,
		BinaryGeometricBits:            plan.BinaryGeometricBits,
		BernoulliThresholds:            append([]string(nil), plan.BernoulliThresholds...),
		ScaleShifts:                    append([]int(nil), input.ScaleShifts...),
		RawUpperBounds:                 append([]string(nil), input.RawUpperBounds...),
		TranscriptHash:                 input.TranscriptHash,
		GarblerCommitmentContext:       input.GarblerCommitmentContext,
		EvaluatorCommitmentContext:     input.EvaluatorCommitmentContext,
		GarblerSeedCommitment:          input.GarblerSeedCommitment,
		EvaluatorSeedCommitment:        input.EvaluatorSeedCommitment,
		ImplementationDeltaNumerator:   plan.ImplementationDeltaNumerator,
		ImplementationDeltaDenominator: plan.ImplementationDeltaDenominator,
	}
	dummySession := exactGCSession{
		SessionID: [32]byte{1}, MasterKey: [32]byte{1},
		GarblerID: "contract-garbler", EvaluatorID: "contract-evaluator",
		Purpose: "pending",
		Spec: exactGCCircuitSpec{Operation: jointDPVectorOperation,
			RingBits: 128, FracBits: 0, VectorLen: input.CoordinateCount},
	}
	spec, err := jointDPVectorSpecFromPolicyWithoutDigest(policy, dummySession)
	if err != nil {
		return zero, err
	}
	digest := spec.digest()
	policy.CircuitDigest = hex.EncodeToString(digest[:])
	return jointDPVectorWorkerContractOutput{
		Version:      jointDPVectorWorkerContractOutputVersion,
		CapabilityID: jointDPVectorExactGCCapabilityID,
		Operation:    string(jointDPVectorOperation), Purpose: spec.purpose(),
		CircuitDigest:           policy.CircuitDigest,
		InputContract:           "public-data-free-biomedical-vector-chunk-v1",
		ProtectedInputsAccepted: false, PrivateSeedAccepted: false,
		WorkerPolicy: policy, Plan: plan, CapabilityAvailable: true,
	}, nil
}

// Build and validate the public spec before its own digest has been filled.
func jointDPVectorSpecFromPolicyWithoutDigest(policy jointDPVectorWorkerPolicy,
	session exactGCSession) (jointDPVectorSpec, error) {
	digest := policy.CircuitDigest
	policy.CircuitDigest = ""
	session.Purpose = "pending"
	// Reuse the parser while deliberately bypassing only the final self-digest
	// comparison; all arithmetic and shape checks below are identical.
	policy.CircuitDigest = digest
	sensitivity, err := jointDPVectorParseInt(policy.SensitivitySteps,
		"sensitivity steps", true)
	if err != nil {
		return jointDPVectorSpec{}, err
	}
	stop, err := jointDPVectorParseInt(policy.StopNumerator,
		"stop numerator", true)
	if err != nil {
		return jointDPVectorSpec{}, err
	}
	thresholds := make([]*big.Int, len(policy.BernoulliThresholds))
	for index, value := range policy.BernoulliThresholds {
		thresholds[index], err = jointDPVectorParseInt(value,
			"Bernoulli threshold", false)
		if err != nil {
			return jointDPVectorSpec{}, err
		}
	}
	upper := make([]*big.Int, len(policy.RawUpperBounds))
	for index, value := range policy.RawUpperBounds {
		upper[index], err = jointDPVectorParseInt(value, "raw upper bound", false)
		if err != nil {
			return jointDPVectorSpec{}, err
		}
	}
	transcript, err := jointDPDecodeHex32(policy.TranscriptHash, "transcript hash")
	if err != nil {
		return jointDPVectorSpec{}, err
	}
	gctx, err := jointDPDecodeHex32(policy.GarblerCommitmentContext,
		"garbler commitment context")
	if err != nil {
		return jointDPVectorSpec{}, err
	}
	ectx, err := jointDPDecodeHex32(policy.EvaluatorCommitmentContext,
		"evaluator commitment context")
	if err != nil {
		return jointDPVectorSpec{}, err
	}
	gcommit, err := jointDPDecodeHex32(policy.GarblerSeedCommitment,
		"garbler seed commitment")
	if err != nil {
		return jointDPVectorSpec{}, err
	}
	ecommit, err := jointDPDecodeHex32(policy.EvaluatorSeedCommitment,
		"evaluator seed commitment")
	if err != nil {
		return jointDPVectorSpec{}, err
	}
	spec := jointDPVectorSpec{
		RingBits: 128, FracBits: 0,
		OutputLatticeBits:    policy.OutputLatticeBits,
		TotalCoordinateCount: policy.TotalCoordinateCount,
		ChunkStart:           policy.ChunkStart, CoordinateCount: policy.CoordinateCount,
		SensitivitySteps: sensitivity, StopNumerator: stop,
		StopBits: policy.StopBits, UniformBits: policy.UniformBits,
		BinaryGeometricBits: policy.BinaryGeometricBits,
		BernoulliThresholds: thresholds,
		ScaleShifts:         append([]int(nil), policy.ScaleShifts...),
		RawUpperBounds:      upper,
		TranscriptHash:      transcript, GarblerCommitmentContext: gctx,
		EvaluatorCommitmentContext: ectx, GarblerSeedCommitment: gcommit,
		EvaluatorSeedCommitment: ecommit,
	}
	return spec, spec.validate()
}

func handleJointDPVectorWorkerContract() {
	input, err := jointDPVectorDecodeWorkerContractInput(os.Stdin)
	if err != nil {
		outputError("joint-DP vector worker contract unavailable")
		return
	}
	result, err := jointDPCompileVectorWorkerContract(input)
	if err != nil {
		outputError("joint-DP vector worker contract unavailable")
		return
	}
	mpcWriteOutput(result)
}
