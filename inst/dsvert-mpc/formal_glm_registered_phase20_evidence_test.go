package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func formalGLMRegisteredPhase20EvidenceTestDigestV1(label string) string {
	digest := sha256.Sum256([]byte("registered-phase20-evidence-test/" + label))
	return hex.EncodeToString(digest[:])
}

type formalGLMRegisteredPhase20EvidenceTestFixtureV1 struct {
	source   formalGLMSourceContractTestFixtureV1
	record   formalGLMRegisteredPhase19BindingRecordV1
	runtime  *formalGLMRegisteredPhase19EphemeralRuntimeV1
	proposal formalGLMRegisteredPhase19ClaimProposalV1
}

func formalGLMRegisteredPhase20EvidenceTestBuildV1(
	t *testing.T,
) formalGLMRegisteredPhase20EvidenceTestFixtureV1 {
	t.Helper()
	base := formalGLMRegisteredExecutionTestInputsV1(
		t, "binomial", 2, 2, 1)
	lattice := base.plan.Kernel.FracBits / 2
	if lattice < 1 || lattice >= base.plan.Kernel.FracBits {
		t.Fatal("registered Phase20 test did not choose a distinct output lattice")
	}
	dp, err := formalGLMPhase19CanonicalPreSourceDPForLatticeV1(
		base.plan, lattice)
	if err != nil {
		t.Fatal(err)
	}
	dpSHA256, err := formalGLMCanonicalPreSourceDPSHA256V1(dp)
	if err != nil {
		t.Fatal(err)
	}
	inputs := formalGLMRegisteredExecutionTestInputsForPlan(
		t, base.plan, base.identities,
		func(core *formalGLMPreSourceModelCoreV1) {
			core.CanonicalDP = dp
			core.CanonicalDPSHA256 = dpSHA256
		}, nil)
	registered := formalGLMRegisteredExecutionTestBuild(t, inputs)
	pins := inputs.identities.public
	core, err := formalGLMBuildSourceContractCoreV1(
		inputs.entry, inputs.context.receipts, registered,
		inputs.contract, pins)
	if err != nil {
		t.Fatal(err)
	}
	approvals := make([]jointDPBiomedicalGaussianSignature, 0,
		len(registered.CustodianPeers))
	for _, peer := range registered.CustodianPeers {
		approval, err := formalGLMSignSourceContractV1(
			core, peer, inputs.identities.private[peer], pins)
		if err != nil {
			t.Fatal(err)
		}
		approvals = append(approvals, approval)
	}
	contract, err := formalGLMSealSourceContractV1(core, approvals, pins)
	if err != nil {
		t.Fatal(err)
	}
	source := formalGLMSourceContractTestFixtureV1{
		inputs: inputs, plan: registered, core: core, contract: contract,
	}
	tickets := make([]formalGLMRegisteredPhase18RecipientTicketV1, 0, 2)
	for _, peer := range registered.DesignatedComputePeers {
		transport, err := ecdh.X25519().GenerateKey(crand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		unsigned, err := formalGLMRegisteredPhase18BuildRecipientTicketV1(
			contract, peer, transport.PublicKey().Bytes(), pins)
		if err != nil {
			t.Fatal(err)
		}
		ticket, err := formalGLMRegisteredPhase18SignRecipientTicketV1(
			unsigned, contract, inputs.identities.private[peer], pins)
		if err != nil {
			t.Fatal(err)
		}
		tickets = append(tickets, ticket)
	}
	record := formalGLMRegisteredPhase19PairKeyTestRecord(t, source, tickets)
	backend := sha256.Sum256([]byte(t.Name() + "/backend"))
	runtime, err := newFormalGLMRegisteredPhase19EphemeralRuntimeV1(
		record, contract, pins, backend)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	garbler := registered.DesignatedComputePeers[0]
	store, err := newFormalGLMRegisteredPhase19AttemptStoreV1(
		filepath.Join(t.TempDir(), "attempt-rock"),
		record, contract, pins, garbler,
		inputs.identities.private[garbler])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	proposal, _, err := store.Begin(nil)
	if err != nil {
		t.Fatal(err)
	}
	return formalGLMRegisteredPhase20EvidenceTestFixtureV1{
		source: source, record: record, runtime: runtime, proposal: proposal,
	}
}

func formalGLMRegisteredPhase20EvidenceTestRawV1(
	t *testing.T,
	source formalGLMSourceContractTestFixtureV1,
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	binding formalGLMRegisteredPhase19AttemptBindingV1,
	variant string,
) formalGLMPhase19ScheduleResult {
	t.Helper()
	plan, ctx := runtime.legacyPlan, runtime.context
	pins := source.inputs.identities.public
	private := source.inputs.identities.private
	legacyAttempt, finalStep, err :=
		formalGLMRegisteredPhase20FinalLegacyAttemptV1(
			plan, binding.ScheduleRootSHA256)
	if err != nil {
		t.Fatal(err)
	}
	planDigest, err := formalGLMPhase15PlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	transcript := formalGLMRegisteredPhase20EvidenceTestDigestV1(
		variant + "/final-transcript")
	receipts := make([]formalGLMPhase15StepReceipt, len(ctx.ComputePeers))
	for index, peer := range ctx.ComputePeers {
		receipts[index] = formalGLMPhase15StepReceipt{
			Version:    formalGLMPhase15ReceiptVersion,
			PlanSHA256: hex.EncodeToString(planDigest[:]), Peer: peer,
			StepIndex: finalStep, AttemptID: legacyAttempt,
			StateSHA256: formalGLMRegisteredPhase20EvidenceTestDigestV1(
				variant + "/state/" + peer),
			TranscriptSHA256: transcript,
		}
		receipts[index].Signature = ed25519.Sign(
			private[peer], formalGLMPhase15ReceiptUnsigned(receipts[index]))
	}
	if err := formalGLMPhase15VerifyReceiptPair(plan, receipts, pins); err != nil {
		t.Fatal(err)
	}
	bridge, err := buildFormalGLMPhase15DPBridgePlan(
		plan, receipts, pins, source.plan.CanonicalDP.OutputLatticeBits)
	if err != nil {
		t.Fatal(err)
	}
	pair := formalGLMPhase19ExecutionReceiptPair{
		Version:       formalGLMPhase19ExecVersion + "-receipt-pair",
		ContextSHA256: ctx.ContextSHA256ForPhase19(),
		AccumulatorRoot: formalGLMRegisteredPhase20EvidenceTestDigestV1(
			variant + "/accumulator"),
		GarblerReceiptSHA256: formalGLMRegisteredPhase20EvidenceTestDigestV1(
			variant + "/garbler-receipt"),
		EvaluatorReceiptSHA256: formalGLMRegisteredPhase20EvidenceTestDigestV1(
			variant + "/evaluator-receipt"),
		ExecutionReceiptPairSHA256: formalGLMRegisteredPhase20EvidenceTestDigestV1(
			variant + "/execution-pair"),
		ExecutionValidSealed: true, ExecutionValidityOpened: false,
		OpeningsPerformed: 0, ProductionReady: false, verified: true,
	}
	pairMessage, err := formalGLMPhase19ExecutionPairMessage(pair)
	if err != nil {
		t.Fatal(err)
	}
	pair.seal = formalGLMPhase19MAC(runtime.backendKey,
		formalGLMPhase19ExecDomain+"/receipt-pair-seal", pairMessage)

	token := formalGLMPhase19PostExecutionToken{
		Version:                 formalGLMPhase19PostTokenVersion,
		ContextSHA256:           ctx.ContextSHA256ForPhase19(),
		CapsuleSHA256:           ctx.CapsuleSHA256,
		Phase15PlanSHA256:       ctx.Phase15PlanSHA256,
		PreExecutionTokenSHA256: ctx.PreExecutionTokenSHA256,
		RunID:                   ctx.RunID, PinsetSHA256: ctx.PinsetSHA256,
		GlobalMaterializationRoot: ctx.GlobalMaterializationRoot,
		FanInTranscriptSHA256: formalGLMRegisteredPhase20EvidenceTestDigestV1(
			variant + "/fan-in"),
		BlockCommitmentRootSHA256: formalGLMRegisteredPhase20EvidenceTestDigestV1(
			variant + "/block-commitment"),
		BlockReceiptRootSHA256: formalGLMRegisteredPhase20EvidenceTestDigestV1(
			variant + "/block-receipt"),
		AccumulatorRoot:            pair.AccumulatorRoot,
		ExecutionReceiptPairSHA256: pair.ExecutionReceiptPairSHA256,
		FinalReceiptSetSeal: formalGLMRegisteredPhase20EvidenceTestDigestV1(
			variant + "/final-receipt-seal"),
		CheckpointEvidenceSeal: formalGLMRegisteredPhase20EvidenceTestDigestV1(
			variant + "/checkpoint-seal"),
		Phase15ExecutionTranscriptSHA256: transcript,
		FinalCheckpointTranscriptSHA256:  transcript,
		WorkerTranscriptSHA256: formalGLMRegisteredPhase20EvidenceTestDigestV1(
			variant + "/worker-transcript"),
		PostExecutionRootSHA256: formalGLMRegisteredPhase20EvidenceTestDigestV1(
			variant + "/post-root"),
		CustodianCount: len(ctx.CustodianPeers),
		ComputePeers:   append([]string(nil), ctx.ComputePeers...),
		FanInExecuted:  true, ExactAllKValidityInsideGC: true,
		ConsensusComparedInsideGC: true, FullTupleMaskInsideGC: true,
		ExecutionValidSealed: true, ExecutionValidityOpened: false,
		PatientDependentDigestsExposed: false,
		ProtectedDataE2EVerified:       false, OpeningAuthorized: false,
		OpeningsPerformed: 0,
		DPReleaseStatus:   "blocked_until_joint_dp_release_consumes_hidden_execution_validity_v1",
		RemainingBlockers: []string{
			"registered_r_dsi_lifecycle_and_real_multiprocess_e2e_unavailable_v1",
			"joint_dp_release_consuming_hidden_execution_validity_v1",
		},
		ProductionReady: false, verified: true,
	}
	preimage, err := formalGLMPhase19PostTokenPreimage(token)
	if err != nil {
		t.Fatal(err)
	}
	tokenDigest := sha256.Sum256(append(
		[]byte(formalGLMPhase19PostTokenDomain+"|"), preimage...))
	token.TokenSHA256 = hex.EncodeToString(tokenDigest[:])
	token.seal = formalGLMPhase19MAC(runtime.backendKey,
		formalGLMPhase19PostTokenDomain+"/seal", tokenDigest[:])
	if err := formalGLMPhase19VerifyPostExecutionToken(
		token, runtime.backendKey); err != nil {
		t.Fatal(err)
	}

	shares := make([]*big.Int, plan.Kernel.CoefficientCount)
	for index := range shares {
		shares[index] = new(big.Int)
	}
	if variant != "primary" {
		shares[0].SetInt64(1)
	}
	dpShare, err := exactGCEncodeWorkerCanonicalShares(shares, exactGCCircuitSpec{
		Operation: exactGCFormalGLMDPBridge, RingBits: 128, FracBits: 0,
		VectorLen: plan.Kernel.CoefficientCount,
	})
	exactGCZeroBigInts(shares)
	if err != nil {
		t.Fatal(err)
	}
	contextDigest, err := formalGLMPhase19ContextDigest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return formalGLMPhase19ScheduleResult{
		Version:            formalGLMPhase19ScheduleResultVersion,
		Kind:               formalGLMPhase19ScheduleResultKind,
		ContextSHA256:      hex.EncodeToString(contextDigest[:]),
		PlanSHA256:         hex.EncodeToString(planDigest[:]),
		SemanticRootSHA256: binding.SemanticRootSHA256,
		ScheduleRootSHA256: binding.ScheduleRootSHA256,
		Peer:               ctx.ComputePeers[0], AttemptID: binding.AttemptID,
		FinalReceipts: receipts, DPBridge: bridge, DPShare: dpShare,
		PostExecutionToken:       token,
		PostExecutionTokenSeal:   hex.EncodeToString(token.seal[:]),
		ExecutionReceiptPair:     pair,
		ExecutionReceiptPairSeal: hex.EncodeToString(pair.seal[:]),
		ExecutionValidSealed:     true, ExecutionValidityOpened: false,
		OpeningsPerformed: 0, ProductionReady: false,
	}
}

func formalGLMRegisteredPhase20EvidenceTestCloneV1(
	t *testing.T, value formalGLMRegisteredPhase20PreparedEvidenceV1,
) formalGLMRegisteredPhase20PreparedEvidenceV1 {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var cloned formalGLMRegisteredPhase20PreparedEvidenceV1
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func TestFormalGLMRegisteredPhase20EvidenceK2RoundTripAndTamper(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase20EvidenceTestBuildV1(t)
	runtime := fixture.runtime
	binding := fixture.proposal.Binding
	contract := fixture.source.contract
	registered := contract.Core.RegisteredExecutionPlan
	pins := fixture.source.inputs.identities.public
	if binding.BindingRecordSHA256 == runtime.bindingRecordSHA256 {
		t.Fatal("attempt and ephemeral binding-record domains unexpectedly coincide")
	}
	if registered.CanonicalDP.OutputLatticeBits >=
		runtime.legacyPlan.Kernel.FracBits {
		t.Fatal("registered evidence test did not preserve a lower output lattice")
	}
	raw := formalGLMRegisteredPhase20EvidenceTestRawV1(
		t, fixture.source, runtime, binding, "primary")
	evidence, err := formalGLMRegisteredPhase20BuildPreparedEvidenceV1(
		runtime, fixture.record, contract, binding, raw, pins)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(encoded))
	for _, forbidden := range []string{
		"capsule", "run_id", "pre_execution", "preexecution", "legacy",
		`"phase15_plan_sha256"`, `"context_sha256"`, `"dp_bridge"`,
		"dp_release_status", "remaining_blockers", "path", "secret", "backend",
	} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("registered Phase20 evidence exposed %q: %s", forbidden, encoded)
		}
	}
	for _, alias := range []string{
		runtime.runAlias, runtime.artifactAlias,
		runtime.capsuleAlias, runtime.preExecutionAlias,
	} {
		if bytes.Contains(encoded, []byte(alias)) {
			t.Fatal("registered Phase20 evidence persisted an ephemeral alias")
		}
	}
	var canonical formalGLMRegisteredPhase20PreparedEvidenceV1
	if err := json.Unmarshal(encoded, &canonical); err != nil {
		t.Fatal(err)
	}
	reencoded, err := json.Marshal(canonical)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		t.Fatal("registered Phase20 evidence JSON is not a canonical round trip")
	}
	trusted, err := formalGLMRegisteredPhase20RehydrateEvidenceV1(
		runtime, fixture.record, contract, binding, canonical, pins)
	if err != nil {
		t.Fatal(err)
	}
	if len(trusted.source.DPShares) != runtime.legacyPlan.Kernel.CoefficientCount ||
		trusted.source.Result.DPShare != raw.DPShare ||
		trusted.source.Result.ScheduleRootSHA256 != binding.ScheduleRootSHA256 ||
		trusted.source.Result.AttemptID != binding.AttemptID {
		trusted.clear()
		t.Fatal("registered Phase20 evidence changed its trust source")
	}
	trustJSON, err := json.Marshal(trusted)
	trusted.clear()
	if err != nil || string(trustJSON) != "{}" {
		t.Fatalf("registered Phase20 trust source became serializable: %s", trustJSON)
	}

	tamperedShare := make([]*big.Int, runtime.legacyPlan.Kernel.CoefficientCount)
	for index := range tamperedShare {
		tamperedShare[index] = new(big.Int)
	}
	tamperedShare[0].SetInt64(1)
	otherShare, err := exactGCEncodeWorkerCanonicalShares(
		tamperedShare, exactGCCircuitSpec{
			Operation: exactGCFormalGLMDPBridge, RingBits: 128, FracBits: 0,
			VectorLen: runtime.legacyPlan.Kernel.CoefficientCount,
		})
	exactGCZeroBigInts(tamperedShare)
	if err != nil {
		t.Fatal(err)
	}
	changed := formalGLMRegisteredPhase20EvidenceTestDigestV1("tampered")
	cases := []struct {
		name   string
		mutate func(*formalGLMRegisteredPhase20PreparedEvidenceV1)
	}{
		{"semantic-root", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) { v.Attempt.SemanticRootSHA256 = changed }},
		{"binding-root", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) { v.Attempt.BindingRecordSHA256 = changed }},
		{"registered-plan-root", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) {
			v.Attempt.RegisteredExecutionPlanSHA256 = changed
		}},
		{"previous-abandon", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) { v.Attempt.PreviousAbandonSHA256 = changed }},
		{"attempt", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) { v.Attempt.AttemptID = changed }},
		{"schedule", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) { v.Attempt.ScheduleRootSHA256 = changed }},
		{"pair-accumulator-root", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) { v.ExecutionPair.AccumulatorRoot = changed }},
		{"garbler-receipt", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) { v.ExecutionPair.GarblerReceiptSHA256 = changed }},
		{"evaluator-receipt", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) {
			v.ExecutionPair.EvaluatorReceiptSHA256 = changed
		}},
		{"execution-pair-root", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) {
			v.ExecutionPair.ExecutionReceiptPairSHA256 = changed
		}},
		{"execution-pair-seal", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) { v.ExecutionPair.SealSHA256 = changed }},
		{"fan-in-root", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) { v.PostEvidence.FanInTranscriptSHA256 = changed }},
		{"block-commitment-root", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) {
			v.PostEvidence.BlockCommitmentRootSHA256 = changed
		}},
		{"block-receipt-root", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) { v.PostEvidence.BlockReceiptRootSHA256 = changed }},
		{"post-accumulator-root", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) { v.PostEvidence.AccumulatorRoot = changed }},
		{"post-execution-pair-root", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) {
			v.PostEvidence.ExecutionReceiptPairSHA256 = changed
		}},
		{"final-receipt-seal", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) { v.PostEvidence.FinalReceiptSetSeal = changed }},
		{"checkpoint-seal", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) { v.PostEvidence.CheckpointEvidenceSeal = changed }},
		{"phase15-transcript", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) {
			v.PostEvidence.Phase15ExecutionTranscriptSHA256 = changed
		}},
		{"final-transcript", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) {
			v.PostEvidence.FinalCheckpointTranscriptSHA256 = changed
		}},
		{"worker-root", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) { v.PostEvidence.WorkerTranscriptSHA256 = changed }},
		{"post-root", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) {
			v.PostEvidence.PostExecutionRootSHA256 = changed
		}},
		{"token-root", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) { v.PostEvidence.TokenSHA256 = changed }},
		{"post-token-seal", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) { v.PostEvidence.SealSHA256 = changed }},
		{"dp-share", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) { v.CanonicalDPShare = otherShare }},
		{"evidence-seal", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) { v.EvidenceSealSHA256 = changed }},
		{"receipt-peer", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) {
			v.FinalReceipts[0].Peer = v.FinalReceipts[1].Peer
		}},
		{"receipt-state", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) { v.FinalReceipts[0].StateSHA256 = changed }},
		{"receipt-transcript", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) { v.FinalReceipts[0].TranscriptSHA256 = changed }},
		{"receipt-signature", func(v *formalGLMRegisteredPhase20PreparedEvidenceV1) { v.FinalReceipts[0].Signature[0] ^= 1 }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			modified := formalGLMRegisteredPhase20EvidenceTestCloneV1(t, evidence)
			test.mutate(&modified)
			source, err := formalGLMRegisteredPhase20RehydrateEvidenceV1(
				runtime, fixture.record, contract, binding, modified, pins)
			if err == nil {
				source.clear()
				t.Fatal("modified registered Phase20 evidence was accepted")
			}
		})
	}

	secondaryRaw := formalGLMRegisteredPhase20EvidenceTestRawV1(
		t, fixture.source, runtime, binding, "secondary")
	secondary, err := formalGLMRegisteredPhase20BuildPreparedEvidenceV1(
		runtime, fixture.record, contract, binding, secondaryRaw, pins)
	if err != nil {
		t.Fatal(err)
	}
	mixed := formalGLMRegisteredPhase20EvidenceTestCloneV1(t, evidence)
	mixed.CanonicalDPShare = secondary.CanonicalDPShare
	mixed.EvidenceSealSHA256 = secondary.EvidenceSealSHA256
	if source, err := formalGLMRegisteredPhase20RehydrateEvidenceV1(
		runtime, fixture.record, contract, binding, mixed, pins); err == nil {
		source.clear()
		t.Fatal("share and seal from another terminal projection were accepted")
	}

	reseal := func(value *formalGLMRegisteredPhase20PreparedEvidenceV1) {
		t.Helper()
		value.EvidenceSealSHA256 = ""
		seal, err := formalGLMRegisteredPhase20EvidenceSealV1(
			*value, runtime.backendKey)
		if err != nil {
			t.Fatal(err)
		}
		value.EvidenceSealSHA256 = hex.EncodeToString(seal[:])
		clear(seal[:])
	}
	wrongDomain := binding
	wrongDomain.BindingRecordSHA256 = runtime.bindingRecordSHA256
	wrongDomainEvidence := formalGLMRegisteredPhase20EvidenceTestCloneV1(t, evidence)
	wrongDomainEvidence.Attempt = wrongDomain
	reseal(&wrongDomainEvidence)
	if source, err := formalGLMRegisteredPhase20RehydrateEvidenceV1(
		runtime, fixture.record, contract, wrongDomain,
		wrongDomainEvidence, pins); err == nil {
		source.clear()
		t.Fatal("ephemeral binding-record hash was accepted as an attempt hash")
	}
	forgedAttempt := binding
	forgedAttempt.AttemptID = changed
	forgedAttempt.ScheduleRootSHA256, err =
		formalGLMRegisteredPhase19AttemptScheduleRootV1(
			forgedAttempt.SemanticRootSHA256, forgedAttempt.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	forgedAttemptEvidence := formalGLMRegisteredPhase20EvidenceTestCloneV1(t, evidence)
	forgedAttemptEvidence.Attempt = forgedAttempt
	reseal(&forgedAttemptEvidence)
	if source, err := formalGLMRegisteredPhase20RehydrateEvidenceV1(
		runtime, fixture.record, contract, forgedAttempt,
		forgedAttemptEvidence, pins); err == nil {
		source.clear()
		t.Fatal("arbitrary rehashed attempt was accepted")
	}
	forgedSchedule := binding
	forgedSchedule.ScheduleRootSHA256 = changed
	forgedScheduleEvidence := formalGLMRegisteredPhase20EvidenceTestCloneV1(t, evidence)
	forgedScheduleEvidence.Attempt = forgedSchedule
	reseal(&forgedScheduleEvidence)
	if source, err := formalGLMRegisteredPhase20RehydrateEvidenceV1(
		runtime, fixture.record, contract, forgedSchedule,
		forgedScheduleEvidence, pins); err == nil {
		source.clear()
		t.Fatal("arbitrary schedule root was accepted")
	}

	wrongRaw := raw
	wrongRaw.FinalReceipts = append(
		[]formalGLMPhase15StepReceipt(nil), raw.FinalReceipts...)
	wrongRaw.FinalReceipts[0].AttemptID = changed
	if _, err := formalGLMRegisteredPhase20BuildPreparedEvidenceV1(
		runtime, fixture.record, contract, binding, wrongRaw, pins); err == nil {
		t.Fatal("raw final receipt from another attempt was accepted")
	}
	if reflect.DeepEqual(evidence, formalGLMRegisteredPhase20PreparedEvidenceV1{}) {
		t.Fatal("valid evidence projection is empty")
	}
}
