package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
)

func formalGLMPreSourceProjectionTestContext(t testing.TB, family string,
	custodians int,
) (formalGLMPhase15Plan, []formalGLMPhase15StepReceipt,
	formalGLMPhase15TestIdentities, formalGLMPhase15DPBridgePlan,
	formalGLMPhase16CapsuleBinding) {
	t.Helper()
	plan := formalGLMPhase15TestPlan(t, family, custodians, 1, 2, 2, 1)
	identities := formalGLMPhase15TestIdentitySet(t, plan.Kernel.CustodianPeers)
	pinset, err := formalGLMPhase16PinsetSHA256(identities.public)
	if err != nil {
		t.Fatal(err)
	}
	plan.Kernel.PinsetSHA256 = pinset
	beta := make(map[string][]*big.Int, 2)
	for index, peer := range plan.Kernel.ComputePeers {
		beta[peer] = []*big.Int{
			big.NewInt(int64(3 + index)), big.NewInt(int64(7 + index)),
		}
	}
	transcript, attempt := formalGLMPhase15TestExecutionTranscript(
		t, plan, t.Name())
	receipts := formalGLMPhase15TestFinalReceipts(
		t, plan, identities, transcript, attempt, beta)
	bridge, err := buildFormalGLMPhase15DPBridgePlan(
		plan, receipts, identities.public, plan.Kernel.FracBits)
	if err != nil {
		t.Fatal(err)
	}
	capsule := formalGLMPhase16TestCapsule(t, plan, identities.public, t.Name())
	return plan, receipts, identities, bridge, capsule
}

func TestFormalGLMPreSourceProjectionEqualsPhase16BytesK2K3K5(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		for _, custodians := range []int{2, 3, 5} {
			t.Run(fmt.Sprintf("%s/K%d", family, custodians), func(t *testing.T) {
				plan, receipts, identities, bridge, capsule :=
					formalGLMPreSourceProjectionTestContext(
						t, family, custodians)
				binding, err := buildFormalGLMPhase16ReleaseBinding(
					plan, receipts, identities.public, bridge, capsule)
				if err != nil {
					t.Fatal(err)
				}
				preSource, err := buildFormalGLMPreSourceDPProjectionV1(plan)
				if err != nil {
					t.Fatal(err)
				}
				phase16 := formalGLMPreSourceDPProjectionFromPhase16V1(
					bridge, binding)
				preBytes, _ := json.Marshal(preSource)
				phase16Bytes, _ := json.Marshal(phase16)
				if string(preBytes) != string(phase16Bytes) {
					t.Fatalf("pre-source projection diverged from Phase16:\n%s\n%s",
						preBytes, phase16Bytes)
				}
			})
		}
	}
}

func TestFormalGLMPreSourceProjectionContainsNoExecutionOrSourceState(t *testing.T) {
	plan, _, _, _, _ := formalGLMPreSourceProjectionTestContext(
		t, "binomial", 3)
	projection, err := buildFormalGLMPreSourceDPProjectionV1(plan)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(projection)
	for _, forbidden := range [][]byte{
		[]byte(`"final_receipt`), []byte(`"execution_transcript`),
		[]byte(`"attempt`), []byte(`"source_path`), []byte(`"secret`),
		[]byte(`"formal_analysis_id`),
	} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatalf("pre-source projection contains forbidden state %q", forbidden)
		}
	}
}

func TestFormalGLMCanonicalPreSourceDPIsRunIDInvariant(t *testing.T) {
	plan, _, _, _, _ := formalGLMPreSourceProjectionTestContext(
		t, "poisson", 5)
	first, err := buildFormalGLMCanonicalPreSourceDPV1(plan)
	if err != nil {
		t.Fatal(err)
	}
	changed := plan
	changed.RunID = fmt.Sprintf("%x", sha256.Sum256([]byte("another-run")))
	second, err := buildFormalGLMCanonicalPreSourceDPV1(changed)
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, _ := json.Marshal(first)
	secondBytes, _ := json.Marshal(second)
	firstSHA256, _ := formalGLMCanonicalPreSourceDPSHA256V1(first)
	secondSHA256, _ := formalGLMCanonicalPreSourceDPSHA256V1(second)
	if !bytes.Equal(firstBytes, secondBytes) || firstSHA256 != secondSHA256 {
		t.Fatal("execution RunID split the canonical pre-source DP identity")
	}
}
