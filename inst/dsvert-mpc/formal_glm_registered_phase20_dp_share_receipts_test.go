package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type formalGLMRegisteredPhase20DPShareReceiptTestFixtureV1 struct {
	evidence  formalGLMRegisteredPhase20EvidenceTestFixtureV1
	accept    formalGLMRegisteredPhase19ClaimAcceptV1
	garbler   formalGLMRegisteredPhase20PreparedEvidenceV1
	evaluator formalGLMRegisteredPhase20PreparedEvidenceV1
}

func formalGLMRegisteredPhase20DPShareReceiptTestCloneV1[T any](
	t testing.TB, value T,
) T {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var cloned T
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func formalGLMRegisteredPhase20DPShareReceiptTestBuildV1(
	t *testing.T,
) formalGLMRegisteredPhase20DPShareReceiptTestFixtureV1 {
	t.Helper()
	fixture := formalGLMRegisteredPhase20EvidenceTestBuildV1(t)
	plan := fixture.source.plan
	peers := plan.DesignatedComputePeers
	evaluatorStore, err := newFormalGLMRegisteredPhase19AttemptStoreV1(
		filepath.Join(t.TempDir(), "evaluator-attempt-rock"),
		fixture.record, fixture.source.contract,
		fixture.source.inputs.identities.public, peers[1],
		fixture.source.inputs.identities.private[peers[1]])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(evaluatorStore.Close)
	accept, _, err := evaluatorStore.Accept(fixture.proposal)
	if err != nil {
		t.Fatal(err)
	}
	binding := fixture.proposal.Binding
	garblerRaw := formalGLMRegisteredPhase20EvidenceTestRawV1(
		t, fixture.source, fixture.runtime, binding, "receipt-common")
	evaluatorRaw := formalGLMRegisteredPhase20DPShareReceiptTestCloneV1(
		t, garblerRaw)
	evaluatorRaw.Peer = peers[1]
	spec := exactGCCircuitSpec{
		Operation: exactGCFormalGLMDPBridge, RingBits: 128, FracBits: 0,
		VectorLen: fixture.runtime.legacyPlan.Kernel.CoefficientCount,
	}
	garblerShares, err := exactGCDecodeWorkerCanonicalShares(
		garblerRaw.DPShare, spec)
	if err != nil {
		t.Fatal(err)
	}
	evaluatorShares := make([]*big.Int, len(garblerShares))
	for index, garblerShare := range garblerShares {
		shifted, ok := new(big.Int).SetString(
			garblerRaw.DPBridge.ShiftedUpperBounds[index], 10)
		if !ok {
			t.Fatal("invalid test DP-bridge shifted output")
		}
		evaluatorShares[index] = new(big.Int).Sub(shifted, garblerShare)
		evaluatorShares[index].Mod(evaluatorShares[index], exactGCModulus(128))
		if exactGCReferenceReconstruct(
			garblerShare, evaluatorShares[index], 128).Cmp(shifted) != 0 {
			t.Fatal("test DP shares did not reconstruct their bound output")
		}
	}
	evaluatorRaw.DPShare, err = exactGCEncodeWorkerCanonicalShares(
		evaluatorShares, spec)
	exactGCZeroBigInts(garblerShares)
	exactGCZeroBigInts(evaluatorShares)
	if err != nil {
		t.Fatal(err)
	}
	pins := fixture.source.inputs.identities.public
	garbler, err := formalGLMRegisteredPhase20BuildPreparedEvidenceV1(
		fixture.runtime, fixture.record, fixture.source.contract,
		binding, garblerRaw, pins)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := formalGLMRegisteredPhase20BuildPreparedEvidenceV1(
		fixture.runtime, fixture.record, fixture.source.contract,
		binding, evaluatorRaw, pins)
	if err != nil {
		t.Fatal(err)
	}
	return formalGLMRegisteredPhase20DPShareReceiptTestFixtureV1{
		evidence: fixture, accept: accept, garbler: garbler,
		evaluator: evaluator,
	}
}

func TestFormalGLMRegisteredPhase20DPShareReceiptsK2Binding(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase20DPShareReceiptTestBuildV1(t)
	base := fixture.evidence
	runtime, record, contract := base.runtime, base.record, base.source.contract
	proposal, accept := base.proposal, fixture.accept
	pins := base.source.inputs.identities.public
	private := base.source.inputs.identities.private
	peers := base.source.plan.DesignatedComputePeers

	garblerReceipt, err := formalGLMRegisteredPhase20BuildDPShareReceiptV1(
		runtime, record, contract, pins, proposal, accept, fixture.garbler,
		private[peers[0]])
	if err != nil {
		t.Fatal(err)
	}
	evaluatorReceipt, err := formalGLMRegisteredPhase20BuildDPShareReceiptV1(
		runtime, record, contract, pins, proposal, accept, fixture.evaluator,
		private[peers[1]])
	if err != nil {
		t.Fatal(err)
	}
	if garblerReceipt.Role != "garbler" || evaluatorReceipt.Role != "evaluator" ||
		garblerReceipt.SecurityModel !=
			formalGLMRegisteredPhase20DPShareReceiptSecurityModelV1 ||
		evaluatorReceipt.SecurityModel !=
			formalGLMRegisteredPhase20DPShareReceiptSecurityModelV1 ||
		garblerReceipt.MaliciousSecurityClaim ||
		evaluatorReceipt.MaliciousSecurityClaim ||
		garblerReceipt.ProtectedPayloadExposed ||
		evaluatorReceipt.ProtectedPayloadExposed {
		t.Fatal("registered DP-share receipts misstated their security boundary")
	}
	if garblerReceipt.CommonEvidenceSHA256 !=
		evaluatorReceipt.CommonEvidenceSHA256 ||
		garblerReceipt.DPBridgeSessionContextSHA256 !=
			evaluatorReceipt.DPBridgeSessionContextSHA256 ||
		garblerReceipt.LocalEvidenceSHA256 ==
			evaluatorReceipt.LocalEvidenceSHA256 ||
		garblerReceipt.OutputShareSHA256 == evaluatorReceipt.OutputShareSHA256 {
		t.Fatal("registered DP-share receipts did not bind one common execution and two local outputs")
	}

	pair, err := formalGLMRegisteredPhase20PairDPShareReceiptsV1(
		runtime, record, contract, pins, proposal, accept, fixture.garbler,
		garblerReceipt, evaluatorReceipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := formalGLMRegisteredPhase20ValidateDPShareReceiptPairV1(
		runtime, record, contract, pins, proposal, accept,
		fixture.garbler, pair); err != nil {
		t.Fatal(err)
	}
	if err := formalGLMRegisteredPhase20ValidateDPShareReceiptPairV1(
		runtime, record, contract, pins, proposal, accept,
		fixture.evaluator, pair); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(pair)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		fixture.garbler.CanonicalDPShare,
		fixture.evaluator.CanonicalDPShare,
		base.runtime.runAlias, base.runtime.artifactAlias,
		base.runtime.capsuleAlias, base.runtime.preExecutionAlias,
		`"canonical_dp_share"`, `"evidence_seal_sha256"`,
		`"path"`, `"key"`, `"secret"`,
	} {
		if forbidden != "" && bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("registered DP-share pair exposed forbidden material %q", forbidden)
		}
	}
	var canonical formalGLMRegisteredPhase20DPShareReceiptPairV1
	if err := json.Unmarshal(encoded, &canonical); err != nil {
		t.Fatal(err)
	}
	reencoded, err := json.Marshal(canonical)
	if err != nil || !bytes.Equal(encoded, reencoded) ||
		!reflect.DeepEqual(pair, canonical) {
		t.Fatal("registered DP-share pair was not canonical JSON")
	}

	changed := strings.Repeat("0", 64)
	if changed == evaluatorReceipt.CommonEvidenceSHA256 {
		changed = strings.Repeat("1", 64)
	}
	remoteCases := []struct {
		name   string
		mutate func(*formalGLMRegisteredPhase20DPShareReceiptV1)
	}{
		{"role", func(v *formalGLMRegisteredPhase20DPShareReceiptV1) { v.Role = "garbler" }},
		{"claim", func(v *formalGLMRegisteredPhase20DPShareReceiptV1) { v.ClaimAcceptSHA256 = changed }},
		{"session", func(v *formalGLMRegisteredPhase20DPShareReceiptV1) { v.DPBridgeSessionContextSHA256 = changed }},
		{"common-evidence", func(v *formalGLMRegisteredPhase20DPShareReceiptV1) { v.CommonEvidenceSHA256 = changed }},
		{"local-evidence", func(v *formalGLMRegisteredPhase20DPShareReceiptV1) { v.LocalEvidenceSHA256 = changed }},
		{"output-share", func(v *formalGLMRegisteredPhase20DPShareReceiptV1) { v.OutputShareSHA256 = changed }},
		{"security-model", func(v *formalGLMRegisteredPhase20DPShareReceiptV1) { v.SecurityModel = "malicious" }},
		{"malicious-claim", func(v *formalGLMRegisteredPhase20DPShareReceiptV1) { v.MaliciousSecurityClaim = true }},
		{"payload-exposed", func(v *formalGLMRegisteredPhase20DPShareReceiptV1) { v.ProtectedPayloadExposed = true }},
		{"signature", func(v *formalGLMRegisteredPhase20DPShareReceiptV1) { v.Signature[0] ^= 1 }},
	}
	for _, test := range remoteCases {
		t.Run(test.name, func(t *testing.T) {
			modified := formalGLMRegisteredPhase20DPShareReceiptTestCloneV1(
				t, evaluatorReceipt)
			test.mutate(&modified)
			if _, err := formalGLMRegisteredPhase20PairDPShareReceiptsV1(
				runtime, record, contract, pins, proposal, accept,
				fixture.garbler, garblerReceipt, modified); err == nil {
				t.Fatal("modified remote DP-share receipt was accepted")
			}
		})
	}

	t.Run("peer-claim", func(t *testing.T) {
		modified := formalGLMRegisteredPhase20DPShareReceiptTestCloneV1(t, accept)
		modified.EvaluatorPeerName = peers[0]
		if _, err := formalGLMRegisteredPhase20PairDPShareReceiptsV1(
			runtime, record, contract, pins, proposal, modified,
			fixture.garbler, garblerReceipt, evaluatorReceipt); err == nil {
			t.Fatal("receipt pair accepted a modified claim peer")
		}
	})
	t.Run("attempt", func(t *testing.T) {
		modified := formalGLMRegisteredPhase20DPShareReceiptTestCloneV1(
			t, fixture.garbler)
		modified.Attempt.AttemptID = changed
		if err := formalGLMRegisteredPhase20ValidateDPShareReceiptPairV1(
			runtime, record, contract, pins, proposal, accept,
			modified, pair); err == nil {
			t.Fatal("receipt pair accepted another attempt")
		}
	})
	t.Run("share", func(t *testing.T) {
		modified := formalGLMRegisteredPhase20DPShareReceiptTestCloneV1(
			t, fixture.garbler)
		decoded, err := hex.DecodeString(changed)
		if err != nil {
			t.Fatal(err)
		}
		modified.CanonicalDPShare = string(decoded)
		if err := formalGLMRegisteredPhase20ValidateDPShareReceiptPairV1(
			runtime, record, contract, pins, proposal, accept,
			modified, pair); err == nil {
			t.Fatal("receipt pair accepted another local share")
		}
	})
	t.Run("transcript", func(t *testing.T) {
		modified := formalGLMRegisteredPhase20DPShareReceiptTestCloneV1(
			t, fixture.garbler)
		modified.PostEvidence.FinalCheckpointTranscriptSHA256 = changed
		if err := formalGLMRegisteredPhase20ValidateDPShareReceiptPairV1(
			runtime, record, contract, pins, proposal, accept,
			modified, pair); err == nil {
			t.Fatal("receipt pair accepted another transcript")
		}
	})
	t.Run("pair-order", func(t *testing.T) {
		modified := formalGLMRegisteredPhase20DPShareReceiptTestCloneV1(t, pair)
		modified.Garbler, modified.Evaluator = modified.Evaluator, modified.Garbler
		if err := formalGLMRegisteredPhase20ValidateDPShareReceiptPairV1(
			runtime, record, contract, pins, proposal, accept,
			fixture.garbler, modified); err == nil {
			t.Fatal("receipt pair accepted swapped roles")
		}
	})
	t.Run("pair-hash", func(t *testing.T) {
		modified := formalGLMRegisteredPhase20DPShareReceiptTestCloneV1(t, pair)
		modified.PairSHA256 = changed
		if err := formalGLMRegisteredPhase20ValidateDPShareReceiptPairV1(
			runtime, record, contract, pins, proposal, accept,
			fixture.garbler, modified); err == nil {
			t.Fatal("receipt pair accepted another pair hash")
		}
	})

	secondaryRaw := formalGLMRegisteredPhase20EvidenceTestRawV1(
		t, base.source, runtime, proposal.Binding, "receipt-other-common")
	secondaryRaw.Peer = peers[1]
	secondaryEvidence, err := formalGLMRegisteredPhase20BuildPreparedEvidenceV1(
		runtime, record, contract, proposal.Binding, secondaryRaw, pins)
	if err != nil {
		t.Fatal(err)
	}
	secondaryReceipt, err := formalGLMRegisteredPhase20BuildDPShareReceiptV1(
		runtime, record, contract, pins, proposal, accept, secondaryEvidence,
		private[peers[1]])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := formalGLMRegisteredPhase20PairDPShareReceiptsV1(
		runtime, record, contract, pins, proposal, accept, fixture.garbler,
		garblerReceipt, secondaryReceipt); err == nil {
		t.Fatal("receipt pair mixed two common executions")
	}
}
