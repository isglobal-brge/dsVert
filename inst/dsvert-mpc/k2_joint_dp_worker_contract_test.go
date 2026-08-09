package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func jointDPWorkerContractTestInput() jointDPWorkerContractInput {
	return jointDPWorkerContractInput{
		Version:  jointDPWorkerContractInputVersion,
		RingBits: 127, FracBits: 0, CoordinateCount: 1,
		Epsilon: "1e+00", AllocatedDelta: "7.888609052210118e-31",
		SensitivitySteps: "1", EncodedLower: "0", EncodedUpper: "1000",
		BernoulliBits: 8, MaxSteps: jointDPMaxGeometricSteps,
		TranscriptHash:             strings.Repeat("1", 64),
		GarblerCommitmentContext:   strings.Repeat("2", 64),
		EvaluatorCommitmentContext: strings.Repeat("3", 64),
		GarblerSeedCommitment:      strings.Repeat("4", 64),
		EvaluatorSeedCommitment:    strings.Repeat("5", 64),
	}
}

func TestJointDPWorkerContractIsDataFreeAndPurposeBound(t *testing.T) {
	input := jointDPWorkerContractTestInput()
	result, err := jointDPCompileWorkerContract(input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Version != jointDPWorkerContractOutputVersion ||
		result.CapabilityID != jointDPCountExactGCCapabilityID ||
		result.Operation != string(exactGCJointDPLaplace) ||
		!result.CapabilityAvailable || result.ProtectedInputsAccepted ||
		result.PrivateSeedAccepted || result.InputContract != "public-data-free-count-v1" ||
		result.Purpose != "joint-dp-laplace-v2/"+result.CircuitDigest ||
		result.WorkerPolicy.CircuitDigest != result.CircuitDigest {
		t.Fatalf("invalid purpose-bound worker contract: %+v", result)
	}
	if result.WorkerPolicy.MaxGeometricSteps >= input.MaxSteps ||
		result.WorkerPolicy.StopNumerator != "161" {
		t.Fatalf("the exact planner was not applied: %+v", result.WorkerPolicy)
	}
	encodedInput, _ := json.Marshal(input)
	encodedOutput, _ := json.Marshal(result)
	for _, forbidden := range []string{
		"source_share", "share", "private_seed", "master_key", "noise_value",
	} {
		if bytes.Contains(encodedInput, []byte(`"`+forbidden+`"`)) ||
			bytes.Contains(encodedOutput, []byte(`"`+forbidden+`"`)) {
			t.Fatalf("data-free contract contains %q", forbidden)
		}
	}
}

func TestJointDPWorkerContractStrictlyRejectsExtraOrNonCountFields(t *testing.T) {
	input := jointDPWorkerContractTestInput()
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	withSeed := append(encoded[:len(encoded)-1], []byte(`,"private_seed":"attacker"}`)...)
	if _, err := jointDPDecodeWorkerContractInput(bytes.NewReader(withSeed)); err == nil {
		t.Fatal("unknown private seed field was accepted")
	}
	input.CoordinateCount = 2
	if _, err := jointDPCompileWorkerContract(input); err == nil {
		t.Fatal("generic vector workload was accepted by Count capability")
	}
	input = jointDPWorkerContractTestInput()
	input.RingBits = 128
	if _, err := jointDPCompileWorkerContract(input); err == nil {
		t.Fatal("unsupported Count ring was accepted")
	}
}
