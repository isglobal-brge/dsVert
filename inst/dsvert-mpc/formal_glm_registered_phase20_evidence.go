package main

// Alias-free terminal evidence for the registered Phase19 -> Phase20 handoff.
// Legacy plans, contexts and execution tokens are reconstructed only in memory.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

const (
	formalGLMRegisteredPhase20EvidenceVersionV1 = "dsvert-formal-glm-registered-phase20-evidence-v1"
	formalGLMRegisteredPhase20EvidencePurposeV1 = "formal_glm_registered_phase20_prepared_evidence_v1"
	formalGLMRegisteredPhase20EvidenceDomainV1  = "dsVert/formal-glm/registered-phase20/evidence/v1"

	formalGLMRegisteredPhase20PreparedStateV1 = "prepared_not_selected"
)

type formalGLMRegisteredPhase20FinalReceiptV1 struct {
	Peer             string `json:"peer"`
	StateSHA256      string `json:"state_sha256"`
	TranscriptSHA256 string `json:"transcript_sha256"`
	Signature        []byte `json:"signature"`
}

type formalGLMRegisteredPhase20ExecutionPairV1 struct {
	AccumulatorRoot            string `json:"accumulator_root"`
	GarblerReceiptSHA256       string `json:"garbler_receipt_sha256"`
	EvaluatorReceiptSHA256     string `json:"evaluator_receipt_sha256"`
	ExecutionReceiptPairSHA256 string `json:"execution_receipt_pair_sha256"`
	SealSHA256                 string `json:"seal_sha256"`
}

type formalGLMRegisteredPhase20PostEvidenceV1 struct {
	FanInTranscriptSHA256            string `json:"fan_in_transcript_sha256"`
	BlockCommitmentRootSHA256        string `json:"block_commitment_root_sha256"`
	BlockReceiptRootSHA256           string `json:"block_receipt_root_sha256"`
	AccumulatorRoot                  string `json:"accumulator_root"`
	ExecutionReceiptPairSHA256       string `json:"execution_receipt_pair_sha256"`
	FinalReceiptSetSeal              string `json:"final_receipt_set_seal"`
	CheckpointEvidenceSeal           string `json:"checkpoint_evidence_seal"`
	Phase15ExecutionTranscriptSHA256 string `json:"phase15_execution_transcript_sha256"`
	FinalCheckpointTranscriptSHA256  string `json:"final_checkpoint_transcript_sha256"`
	WorkerTranscriptSHA256           string `json:"worker_transcript_sha256"`
	PostExecutionRootSHA256          string `json:"post_execution_root_sha256"`
	TokenSHA256                      string `json:"token_sha256"`
	SealSHA256                       string `json:"seal_sha256"`
}

type formalGLMRegisteredPhase20PreparedEvidenceV1 struct {
	Version                 string                                      `json:"version"`
	Purpose                 string                                      `json:"purpose"`
	Attempt                 formalGLMRegisteredPhase19AttemptBindingV1  `json:"attempt_binding"`
	Peer                    string                                      `json:"peer"`
	State                   string                                      `json:"state"`
	FinalReceipts           [2]formalGLMRegisteredPhase20FinalReceiptV1 `json:"final_receipts"`
	ExecutionPair           formalGLMRegisteredPhase20ExecutionPairV1   `json:"execution_pair"`
	PostEvidence            formalGLMRegisteredPhase20PostEvidenceV1    `json:"post_evidence"`
	CanonicalDPShare        string                                      `json:"canonical_dp_share"`
	EvidenceSealSHA256      string                                      `json:"evidence_seal_sha256"`
	ExecutionValidSealed    bool                                        `json:"execution_valid_sealed"`
	ExecutionValidityOpened bool                                        `json:"execution_validity_opened"`
	OpeningsPerformed       int                                         `json:"openings_performed"`
	ProductionReady         bool                                        `json:"production_ready"`
}

// The compatibility source has no exported fields and therefore no JSON
// representation. Phase21 may consume source only inside this package.
type formalGLMRegisteredPhase20TrustSourceV1 struct {
	source formalGLMPhase20HandoffSource
}

func (source *formalGLMRegisteredPhase20TrustSourceV1) clear() {
	if source != nil {
		source.source.clear()
		*source = formalGLMRegisteredPhase20TrustSourceV1{}
	}
}

func formalGLMRegisteredPhase20ValidateAttemptBindingLockedV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	binding formalGLMRegisteredPhase19AttemptBindingV1,
	pins map[string]ed25519.PublicKey,
) error {
	if runtime == nil || formalGLMValidateRegisteredPhase19BindingRecordV1(
		record, contract, pins) != nil {
		return fmt.Errorf("formal-glm registered Phase20: invalid attempt binding")
	}
	contractSHA256, err := formalGLMSourceContractSHA256V1(contract)
	if err != nil {
		return err
	}
	attemptRecordSHA256, err := formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase19AttemptDomainV1+"/binding-record", record)
	if err != nil {
		return err
	}
	ephemeralRecordSHA256, err := formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase19EphemeralDomainV1+"/validated-binding-record",
		record)
	if err != nil {
		return err
	}
	if binding.ArtifactID != record.Binding.ArtifactID ||
		binding.SourceContractCoreSHA256 != record.Binding.SourceContractCoreSHA256 ||
		binding.SourceContractSHA256 != contractSHA256 ||
		binding.SourceContractSHA256 != record.Binding.SourceContractSHA256 ||
		binding.RegisteredExecutionPlanSHA256 !=
			record.Binding.RegisteredExecutionPlanSHA256 ||
		binding.PinsetSHA256 != record.Binding.PinsetSHA256 ||
		binding.BindingRecordSHA256 != attemptRecordSHA256 ||
		binding.SemanticRootSHA256 != record.Binding.SemanticRootSHA256 ||
		binding.SemanticRootSHA256 != runtime.semanticRootSHA256 ||
		ephemeralRecordSHA256 != runtime.bindingRecordSHA256 ||
		record.Binding.ReceiptSetSHA256 != runtime.receiptSetSHA256 ||
		binding.RegisteredExecutionPlanSHA256 !=
			runtime.registeredExecutionPlanSHA256 ||
		binding.OpeningsPerformed != 0 || binding.ProductionReady {
		return fmt.Errorf("formal-glm registered Phase20: attempt/record mismatch")
	}
	for _, digest := range []string{
		binding.ArtifactID, binding.SourceContractCoreSHA256,
		binding.SourceContractSHA256, binding.RegisteredExecutionPlanSHA256,
		binding.PinsetSHA256, binding.BindingRecordSHA256,
		binding.SemanticRootSHA256, binding.PreviousAbandonSHA256,
		binding.PreviousAttemptID, binding.AttemptID, binding.ScheduleRootSHA256,
	} {
		if !formalGLMIsSHA256(digest) {
			return fmt.Errorf("formal-glm registered Phase20: invalid attempt digest")
		}
	}
	genesisAbandon := binding.PreviousAbandonSHA256 ==
		formalGLMRegisteredPhase19AttemptZeroPreviousV1
	genesisAttempt := binding.PreviousAttemptID ==
		formalGLMRegisteredPhase19AttemptZeroPreviousV1
	if genesisAbandon != genesisAttempt {
		return fmt.Errorf("formal-glm registered Phase20: invalid attempt predecessor")
	}
	wantAttempt, err := formalGLMRegisteredPhase19AttemptIDV1(
		binding.SemanticRootSHA256, binding.PreviousAbandonSHA256)
	if err != nil || binding.AttemptID != wantAttempt {
		return fmt.Errorf("formal-glm registered Phase20: invalid derived attempt")
	}
	wantSchedule, err := formalGLMRegisteredPhase19AttemptScheduleRootV1(
		binding.SemanticRootSHA256, binding.AttemptID)
	if err != nil || binding.ScheduleRootSHA256 != wantSchedule {
		return fmt.Errorf("formal-glm registered Phase20: invalid derived schedule")
	}
	return nil
}

func formalGLMRegisteredPhase20ValidatePlanLockedV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) error {
	registered := contract.Core.RegisteredExecutionPlan
	if runtime == nil ||
		formalGLMValidateRegisteredExecutionPlanV1(registered, pins) != nil ||
		registered.PlanSHA256 != runtime.registeredExecutionPlanSHA256 {
		return fmt.Errorf("formal-glm registered Phase20: invalid registered plan")
	}
	legacy, run, artifact, capsule, preExecution, err :=
		formalGLMRegisteredPhase19LegacyRuntimePlanV1(
			registered, runtime.semanticRootSHA256)
	if err != nil || !reflect.DeepEqual(legacy, runtime.legacyPlan) ||
		run != runtime.runAlias || artifact != runtime.artifactAlias ||
		capsule != runtime.capsuleAlias || preExecution != runtime.preExecutionAlias {
		return fmt.Errorf("formal-glm registered Phase20: registered plan/runtime mismatch")
	}
	return nil
}

func formalGLMRegisteredPhase20FinalLegacyAttemptV1(
	plan formalGLMPhase15Plan, scheduleRootSHA256 string,
) (string, int, error) {
	if !formalGLMIsSHA256(scheduleRootSHA256) || plan.Iterations < 1 ||
		plan.TotalBlocks < 1 {
		return "", 0,
			fmt.Errorf("formal-glm registered Phase20: invalid final attempt source")
	}
	decoded, err := hex.DecodeString(scheduleRootSHA256)
	if err != nil || len(decoded) != sha256.Size {
		clear(decoded)
		return "", 0,
			fmt.Errorf("formal-glm registered Phase20: invalid schedule root")
	}
	var root [32]byte
	copy(root[:], decoded)
	clear(decoded)
	attempt := formalGLMPhase19RuntimeAttempt(
		root, "phase15-checkpoint", plan.Iterations-1, -1)
	clear(root[:])
	finalStep := plan.Iterations*(plan.TotalBlocks+1) - 1
	if finalStep != plan.ScheduleSteps-1 || finalStep < 0 {
		clear(attempt[:])
		return "", 0,
			fmt.Errorf("formal-glm registered Phase20: invalid final checkpoint")
	}
	encoded := hex.EncodeToString(attempt[:])
	clear(attempt[:])
	return encoded, finalStep, nil
}

func formalGLMRegisteredPhase20ProjectReceiptsV1(
	receipts []formalGLMPhase15StepReceipt,
) ([2]formalGLMRegisteredPhase20FinalReceiptV1, error) {
	var result [2]formalGLMRegisteredPhase20FinalReceiptV1
	if len(receipts) != len(result) {
		return result,
			fmt.Errorf("formal-glm registered Phase20: incomplete final receipts")
	}
	ordered := append([]formalGLMPhase15StepReceipt(nil), receipts...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Peer < ordered[j].Peer })
	for index, receipt := range ordered {
		result[index] = formalGLMRegisteredPhase20FinalReceiptV1{
			Peer: receipt.Peer, StateSHA256: receipt.StateSHA256,
			TranscriptSHA256: receipt.TranscriptSHA256,
			Signature:        append([]byte(nil), receipt.Signature...),
		}
	}
	return result, nil
}

func formalGLMRegisteredPhase20ProjectValidatedV1(
	binding formalGLMRegisteredPhase19AttemptBindingV1,
	result formalGLMPhase19ScheduleResult, backend [32]byte,
) (formalGLMRegisteredPhase20PreparedEvidenceV1, error) {
	var zero formalGLMRegisteredPhase20PreparedEvidenceV1
	receipts, err := formalGLMRegisteredPhase20ProjectReceiptsV1(
		result.FinalReceipts)
	if err != nil {
		return zero, err
	}
	projected := formalGLMRegisteredPhase20PreparedEvidenceV1{
		Version: formalGLMRegisteredPhase20EvidenceVersionV1,
		Purpose: formalGLMRegisteredPhase20EvidencePurposeV1,
		Attempt: binding, Peer: result.Peer,
		State:         formalGLMRegisteredPhase20PreparedStateV1,
		FinalReceipts: receipts,
		ExecutionPair: formalGLMRegisteredPhase20ExecutionPairV1{
			AccumulatorRoot:            result.ExecutionReceiptPair.AccumulatorRoot,
			GarblerReceiptSHA256:       result.ExecutionReceiptPair.GarblerReceiptSHA256,
			EvaluatorReceiptSHA256:     result.ExecutionReceiptPair.EvaluatorReceiptSHA256,
			ExecutionReceiptPairSHA256: result.ExecutionReceiptPair.ExecutionReceiptPairSHA256,
			SealSHA256:                 result.ExecutionReceiptPairSeal,
		},
		PostEvidence: formalGLMRegisteredPhase20PostEvidenceV1{
			FanInTranscriptSHA256:            result.PostExecutionToken.FanInTranscriptSHA256,
			BlockCommitmentRootSHA256:        result.PostExecutionToken.BlockCommitmentRootSHA256,
			BlockReceiptRootSHA256:           result.PostExecutionToken.BlockReceiptRootSHA256,
			AccumulatorRoot:                  result.PostExecutionToken.AccumulatorRoot,
			ExecutionReceiptPairSHA256:       result.PostExecutionToken.ExecutionReceiptPairSHA256,
			FinalReceiptSetSeal:              result.PostExecutionToken.FinalReceiptSetSeal,
			CheckpointEvidenceSeal:           result.PostExecutionToken.CheckpointEvidenceSeal,
			Phase15ExecutionTranscriptSHA256: result.PostExecutionToken.Phase15ExecutionTranscriptSHA256,
			FinalCheckpointTranscriptSHA256:  result.PostExecutionToken.FinalCheckpointTranscriptSHA256,
			WorkerTranscriptSHA256:           result.PostExecutionToken.WorkerTranscriptSHA256,
			PostExecutionRootSHA256:          result.PostExecutionToken.PostExecutionRootSHA256,
			TokenSHA256:                      result.PostExecutionToken.TokenSHA256,
			SealSHA256:                       result.PostExecutionTokenSeal,
		},
		CanonicalDPShare:     result.DPShare,
		ExecutionValidSealed: true, ExecutionValidityOpened: false,
		OpeningsPerformed: 0, ProductionReady: false,
	}
	seal, err := formalGLMRegisteredPhase20EvidenceSealV1(projected, backend)
	if err != nil {
		return zero, err
	}
	projected.EvidenceSealSHA256 = hex.EncodeToString(seal[:])
	clear(seal[:])
	return projected, nil
}

func formalGLMRegisteredPhase20EvidenceSealV1(
	value formalGLMRegisteredPhase20PreparedEvidenceV1,
	backend [32]byte,
) ([32]byte, error) {
	var zero [32]byte
	if !formalGLMPhase19KeyValid(backend) || value.CanonicalDPShare == "" {
		return zero, fmt.Errorf("formal-glm registered Phase20: invalid evidence seal input")
	}
	value.EvidenceSealSHA256 = ""
	encoded, err := json.Marshal(value)
	if err != nil {
		return zero, err
	}
	defer clear(encoded)
	return formalGLMPhase19MAC(
		backend, formalGLMRegisteredPhase20EvidenceDomainV1+"/prepared", encoded), nil
}

func formalGLMRegisteredPhase20RehydrateReceiptsLockedV1(
	plan formalGLMPhase15Plan,
	binding formalGLMRegisteredPhase19AttemptBindingV1,
	projected [2]formalGLMRegisteredPhase20FinalReceiptV1,
	pins map[string]ed25519.PublicKey,
) ([]formalGLMPhase15StepReceipt, error) {
	legacyAttempt, finalStep, err :=
		formalGLMRegisteredPhase20FinalLegacyAttemptV1(
			plan, binding.ScheduleRootSHA256)
	if err != nil {
		return nil, err
	}
	planDigest, err := formalGLMPhase15PlanDigest(plan)
	if err != nil {
		return nil, err
	}
	if projected[0].Peer >= projected[1].Peer {
		return nil,
			fmt.Errorf("formal-glm registered Phase20: non-canonical receipt order")
	}
	receipts := make([]formalGLMPhase15StepReceipt, len(projected))
	for index, receipt := range projected {
		receipts[index] = formalGLMPhase15StepReceipt{
			Version:    formalGLMPhase15ReceiptVersion,
			PlanSHA256: hex.EncodeToString(planDigest[:]), Peer: receipt.Peer,
			StepIndex: finalStep, AttemptID: legacyAttempt,
			StateSHA256:      receipt.StateSHA256,
			TranscriptSHA256: receipt.TranscriptSHA256,
			Signature:        append([]byte(nil), receipt.Signature...),
		}
	}
	if err := formalGLMPhase15VerifyReceiptPair(plan, receipts, pins); err != nil {
		return nil, err
	}
	return receipts, nil
}

func formalGLMRegisteredPhase20RehydrateExecutionPairV1(
	ctx formalGLMPhase19Context,
	value formalGLMRegisteredPhase20ExecutionPairV1,
) (formalGLMPhase19ExecutionReceiptPair, error) {
	seal, err := formalGLMPhase20DecodeSeal(value.SealSHA256, "registered execution-pair seal")
	if err != nil {
		return formalGLMPhase19ExecutionReceiptPair{}, err
	}
	return formalGLMPhase19ExecutionReceiptPair{
		Version:                    formalGLMPhase19ExecVersion + "-receipt-pair",
		ContextSHA256:              ctx.ContextSHA256ForPhase19(),
		AccumulatorRoot:            value.AccumulatorRoot,
		GarblerReceiptSHA256:       value.GarblerReceiptSHA256,
		EvaluatorReceiptSHA256:     value.EvaluatorReceiptSHA256,
		ExecutionReceiptPairSHA256: value.ExecutionReceiptPairSHA256,
		ExecutionValidSealed:       true, ExecutionValidityOpened: false,
		OpeningsPerformed: 0, ProductionReady: false,
		seal: seal, verified: true,
	}, nil
}

func formalGLMRegisteredPhase20RehydratePostTokenV1(
	plan formalGLMPhase15Plan, ctx formalGLMPhase19Context,
	value formalGLMRegisteredPhase20PostEvidenceV1,
) (formalGLMPhase19PostExecutionToken, error) {
	seal, err := formalGLMPhase20DecodeSeal(value.SealSHA256, "registered post-execution seal")
	if err != nil {
		return formalGLMPhase19PostExecutionToken{}, err
	}
	return formalGLMPhase19PostExecutionToken{
		Version:                 formalGLMPhase19PostTokenVersion,
		ContextSHA256:           ctx.ContextSHA256ForPhase19(),
		CapsuleSHA256:           ctx.CapsuleSHA256,
		Phase15PlanSHA256:       ctx.Phase15PlanSHA256,
		PreExecutionTokenSHA256: ctx.PreExecutionTokenSHA256,
		RunID:                   ctx.RunID, PinsetSHA256: ctx.PinsetSHA256,
		GlobalMaterializationRoot:        ctx.GlobalMaterializationRoot,
		FanInTranscriptSHA256:            value.FanInTranscriptSHA256,
		BlockCommitmentRootSHA256:        value.BlockCommitmentRootSHA256,
		BlockReceiptRootSHA256:           value.BlockReceiptRootSHA256,
		AccumulatorRoot:                  value.AccumulatorRoot,
		ExecutionReceiptPairSHA256:       value.ExecutionReceiptPairSHA256,
		FinalReceiptSetSeal:              value.FinalReceiptSetSeal,
		CheckpointEvidenceSeal:           value.CheckpointEvidenceSeal,
		Phase15ExecutionTranscriptSHA256: value.Phase15ExecutionTranscriptSHA256,
		FinalCheckpointTranscriptSHA256:  value.FinalCheckpointTranscriptSHA256,
		WorkerTranscriptSHA256:           value.WorkerTranscriptSHA256,
		PostExecutionRootSHA256:          value.PostExecutionRootSHA256,
		TokenSHA256:                      value.TokenSHA256,
		CustodianCount:                   len(ctx.CustodianPeers),
		ComputePeers:                     append([]string(nil), ctx.ComputePeers...),
		FanInExecuted:                    true, ExactAllKValidityInsideGC: true,
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
		ProductionReady: false, seal: seal, verified: true,
	}, nil
}

func formalGLMRegisteredPhase20ValidatePreparedIdentityLockedV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	expected formalGLMRegisteredPhase19AttemptBindingV1,
	value formalGLMRegisteredPhase20PreparedEvidenceV1,
	pins map[string]ed25519.PublicKey,
) error {
	if err := formalGLMRegisteredPhase20ValidatePlanLockedV1(
		runtime, contract, pins); err != nil {
		return err
	}
	if err := formalGLMRegisteredPhase20ValidateAttemptBindingLockedV1(
		runtime, record, contract, expected, pins); err != nil {
		return err
	}
	if value.Version != formalGLMRegisteredPhase20EvidenceVersionV1 ||
		value.Purpose != formalGLMRegisteredPhase20EvidencePurposeV1 ||
		!reflect.DeepEqual(value.Attempt, expected) ||
		(value.Peer != runtime.context.ComputePeers[0] &&
			value.Peer != runtime.context.ComputePeers[1]) ||
		value.State != formalGLMRegisteredPhase20PreparedStateV1 ||
		!value.ExecutionValidSealed || value.ExecutionValidityOpened ||
		value.OpeningsPerformed != 0 || value.ProductionReady ||
		value.CanonicalDPShare == "" ||
		!formalGLMIsSHA256(value.EvidenceSealSHA256) {
		return fmt.Errorf("formal-glm registered Phase20: invalid prepared evidence")
	}
	for _, digest := range []string{
		value.ExecutionPair.AccumulatorRoot,
		value.ExecutionPair.GarblerReceiptSHA256,
		value.ExecutionPair.EvaluatorReceiptSHA256,
		value.ExecutionPair.ExecutionReceiptPairSHA256,
		value.ExecutionPair.SealSHA256,
		value.PostEvidence.FanInTranscriptSHA256,
		value.PostEvidence.BlockCommitmentRootSHA256,
		value.PostEvidence.BlockReceiptRootSHA256,
		value.PostEvidence.AccumulatorRoot,
		value.PostEvidence.ExecutionReceiptPairSHA256,
		value.PostEvidence.FinalReceiptSetSeal,
		value.PostEvidence.CheckpointEvidenceSeal,
		value.PostEvidence.Phase15ExecutionTranscriptSHA256,
		value.PostEvidence.FinalCheckpointTranscriptSHA256,
		value.PostEvidence.WorkerTranscriptSHA256,
		value.PostEvidence.PostExecutionRootSHA256,
		value.PostEvidence.TokenSHA256,
		value.PostEvidence.SealSHA256,
	} {
		if !formalGLMIsSHA256(digest) {
			return fmt.Errorf("formal-glm registered Phase20: invalid evidence digest")
		}
	}
	evidenceSeal, err := formalGLMRegisteredPhase20EvidenceSealV1(
		value, runtime.backendKey)
	if err != nil {
		return err
	}
	wantEvidenceSeal := hex.EncodeToString(evidenceSeal[:])
	clear(evidenceSeal[:])
	if !hmac.Equal([]byte(wantEvidenceSeal), []byte(value.EvidenceSealSHA256)) {
		return fmt.Errorf("formal-glm registered Phase20: evidence authentication failed")
	}
	return nil
}

func formalGLMRegisteredPhase20RehydrateLockedV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	expected formalGLMRegisteredPhase19AttemptBindingV1,
	value formalGLMRegisteredPhase20PreparedEvidenceV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase20TrustSourceV1, error) {
	var zero formalGLMRegisteredPhase20TrustSourceV1
	if err := formalGLMRegisteredPhase20ValidatePreparedIdentityLockedV1(
		runtime, record, contract, expected, value, pins); err != nil {
		return zero, err
	}
	plan, ctx := runtime.legacyPlan, runtime.context
	receipts, err := formalGLMRegisteredPhase20RehydrateReceiptsLockedV1(
		plan, expected, value.FinalReceipts, pins)
	if err != nil {
		return zero, err
	}
	bridge, err := buildFormalGLMPhase15DPBridgePlan(
		plan, receipts, pins,
		contract.Core.RegisteredExecutionPlan.CanonicalDP.OutputLatticeBits)
	if err != nil {
		return zero, err
	}
	pair, err := formalGLMRegisteredPhase20RehydrateExecutionPairV1(
		ctx, value.ExecutionPair)
	if err != nil {
		return zero, err
	}
	token, err := formalGLMRegisteredPhase20RehydratePostTokenV1(
		plan, ctx, value.PostEvidence)
	if err != nil {
		return zero, err
	}
	planDigest, err := formalGLMPhase15PlanDigest(plan)
	if err != nil {
		return zero, err
	}
	contextDigest, err := formalGLMPhase19ContextDigest(ctx)
	if err != nil {
		return zero, err
	}
	legacy := formalGLMPhase19ScheduleResult{
		Version:            formalGLMPhase19ScheduleResultVersion,
		Kind:               formalGLMPhase19ScheduleResultKind,
		ContextSHA256:      hex.EncodeToString(contextDigest[:]),
		PlanSHA256:         hex.EncodeToString(planDigest[:]),
		SemanticRootSHA256: expected.SemanticRootSHA256,
		ScheduleRootSHA256: expected.ScheduleRootSHA256,
		Peer:               value.Peer, AttemptID: expected.AttemptID,
		FinalReceipts: receipts, DPBridge: bridge,
		DPShare:                  value.CanonicalDPShare,
		PostExecutionToken:       token,
		PostExecutionTokenSeal:   value.PostEvidence.SealSHA256,
		ExecutionReceiptPair:     pair,
		ExecutionReceiptPairSeal: value.ExecutionPair.SealSHA256,
		ExecutionValidSealed:     true, ExecutionValidityOpened: false,
		OpeningsPerformed: 0, ProductionReady: false,
	}
	validated, shares, err := formalGLMPhase20ValidateScheduleResult(
		plan, ctx, expected.SemanticRootSHA256, value.Peer,
		legacy, pins, runtime.backendKey)
	if err != nil {
		return zero, err
	}
	return formalGLMRegisteredPhase20TrustSourceV1{
		source: formalGLMPhase20HandoffSource{
			Plan: plan, Context: ctx, Result: validated,
			DPShares: shares, backend: runtime.backendKey,
		},
	}, nil
}

func formalGLMRegisteredPhase20CanonicalEvidenceV1(
	value formalGLMRegisteredPhase20PreparedEvidenceV1,
) ([]byte, error) {
	return json.Marshal(value)
}

func formalGLMRegisteredPhase20BuildPreparedEvidenceV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	binding formalGLMRegisteredPhase19AttemptBindingV1,
	raw formalGLMPhase19ScheduleResult,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase20PreparedEvidenceV1, error) {
	var zero formalGLMRegisteredPhase20PreparedEvidenceV1
	if runtime == nil {
		return zero, fmt.Errorf("formal-glm registered Phase20: missing runtime")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if err := runtime.validateLocked(); err != nil {
		return zero, err
	}
	if err := formalGLMRegisteredPhase20ValidatePlanLockedV1(
		runtime, contract, pins); err != nil {
		return zero, err
	}
	if err := formalGLMRegisteredPhase20ValidateAttemptBindingLockedV1(
		runtime, record, contract, binding, pins); err != nil {
		return zero, err
	}
	if raw.SemanticRootSHA256 != binding.SemanticRootSHA256 ||
		raw.ScheduleRootSHA256 != binding.ScheduleRootSHA256 ||
		raw.AttemptID != binding.AttemptID ||
		raw.DPBridge.OutputLatticeBits !=
			contract.Core.RegisteredExecutionPlan.CanonicalDP.OutputLatticeBits {
		return zero, fmt.Errorf("formal-glm registered Phase20: raw attempt mismatch")
	}
	legacyAttempt, finalStep, err :=
		formalGLMRegisteredPhase20FinalLegacyAttemptV1(
			runtime.legacyPlan, binding.ScheduleRootSHA256)
	if err != nil {
		return zero, err
	}
	for _, receipt := range raw.FinalReceipts {
		if receipt.AttemptID != legacyAttempt || receipt.StepIndex != finalStep {
			return zero,
				fmt.Errorf("formal-glm registered Phase20: raw final receipt mismatch")
		}
	}
	validated, shares, err := formalGLMPhase20ValidateScheduleResult(
		runtime.legacyPlan, runtime.context, binding.SemanticRootSHA256,
		raw.Peer, raw, pins, runtime.backendKey)
	if err != nil {
		return zero, err
	}
	exactGCZeroBigInts(shares)
	projected, err := formalGLMRegisteredPhase20ProjectValidatedV1(
		binding, validated, runtime.backendKey)
	if err != nil {
		return zero, err
	}
	trusted, err := formalGLMRegisteredPhase20RehydrateLockedV1(
		runtime, record, contract, binding, projected, pins)
	if err != nil {
		return zero, err
	}
	defer trusted.clear()
	roundTrip, err := formalGLMRegisteredPhase20ProjectValidatedV1(
		binding, trusted.source.Result, runtime.backendKey)
	if err != nil {
		return zero, err
	}
	want, err := formalGLMRegisteredPhase20CanonicalEvidenceV1(projected)
	if err != nil {
		return zero, err
	}
	got, err := formalGLMRegisteredPhase20CanonicalEvidenceV1(roundTrip)
	if err != nil || !bytes.Equal(got, want) {
		return zero,
			fmt.Errorf("formal-glm registered Phase20: evidence round trip changed")
	}
	return projected, nil
}

func formalGLMRegisteredPhase20RehydrateEvidenceV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	binding formalGLMRegisteredPhase19AttemptBindingV1,
	value formalGLMRegisteredPhase20PreparedEvidenceV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase20TrustSourceV1, error) {
	var zero formalGLMRegisteredPhase20TrustSourceV1
	if runtime == nil {
		return zero, fmt.Errorf("formal-glm registered Phase20: missing runtime")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if err := runtime.validateLocked(); err != nil {
		return zero, err
	}
	trusted, err := formalGLMRegisteredPhase20RehydrateLockedV1(
		runtime, record, contract, binding, value, pins)
	if err != nil {
		return zero, err
	}
	roundTrip, err := formalGLMRegisteredPhase20ProjectValidatedV1(
		binding, trusted.source.Result, runtime.backendKey)
	if err != nil {
		trusted.clear()
		return zero, err
	}
	want, err := formalGLMRegisteredPhase20CanonicalEvidenceV1(value)
	if err != nil {
		trusted.clear()
		return zero, err
	}
	got, err := formalGLMRegisteredPhase20CanonicalEvidenceV1(roundTrip)
	if err != nil || !bytes.Equal(got, want) {
		trusted.clear()
		return zero,
			fmt.Errorf("formal-glm registered Phase20: modified prepared evidence")
	}
	return trusted, nil
}
