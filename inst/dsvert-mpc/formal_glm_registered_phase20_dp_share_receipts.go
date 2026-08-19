package main

// Signed commitments to the two private registered DP-bridge outputs. These
// receipts bind honest-but-curious peers to the outputs they obtained; they do
// not claim malicious-secure computation or serialize either output share.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
)

const (
	formalGLMRegisteredPhase20DPShareReceiptVersionV1 = "dsvert-formal-glm-registered-phase20-dp-share-receipt-v1"
	formalGLMRegisteredPhase20DPShareReceiptPurposeV1 = "formal_glm_registered_phase20_private_dp_share_commitment_v1"
	formalGLMRegisteredPhase20DPShareReceiptDomainV1  = "dsVert/formal-glm/registered-phase20/dp-share-receipt/v1"

	formalGLMRegisteredPhase20DPShareReceiptPairVersionV1 = "dsvert-formal-glm-registered-phase20-dp-share-receipt-pair-v1"
	formalGLMRegisteredPhase20DPShareReceiptPairPurposeV1 = "formal_glm_registered_phase20_k2_dp_share_commitment_pair_v1"

	formalGLMRegisteredPhase20DPShareReceiptSecurityModelV1 = "authenticated_pinned_semi_honest_two_compute_peers_with_at_least_one_honest_noncolluding_noise_peer_v1"
)

type formalGLMRegisteredPhase20DPShareReceiptV1 struct {
	Version                      string `json:"version"`
	Purpose                      string `json:"purpose"`
	SecurityModel                string `json:"security_model"`
	MaliciousSecurityClaim       bool   `json:"malicious_security_claim"`
	ClaimAcceptSHA256            string `json:"claim_accept_sha256"`
	Role                         string `json:"role"`
	DPBridgeSessionContextSHA256 string `json:"dp_bridge_session_context_sha256"`
	CommonEvidenceSHA256         string `json:"common_evidence_sha256"`
	LocalEvidenceSHA256          string `json:"local_evidence_sha256"`
	OutputShareSHA256            string `json:"output_share_sha256"`
	ProtectedPayloadExposed      bool   `json:"protected_payload_exposed"`
	Signature                    []byte `json:"signature"`
}

type formalGLMRegisteredPhase20DPShareReceiptPairV1 struct {
	Version    string                                     `json:"version"`
	Purpose    string                                     `json:"purpose"`
	Garbler    formalGLMRegisteredPhase20DPShareReceiptV1 `json:"garbler"`
	Evaluator  formalGLMRegisteredPhase20DPShareReceiptV1 `json:"evaluator"`
	PairSHA256 string                                     `json:"pair_sha256"`
}

type formalGLMRegisteredPhase20DPShareReceiptContextV1 struct {
	claimAcceptSHA256            string
	role                         string
	peer                         string
	dpBridgeSessionContextSHA256 string
	commonEvidenceSHA256         string
	localEvidenceSHA256          string
	outputShareSHA256            string
}

func formalGLMRegisteredPhase20ValidateClaimPairV1(
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
) (string, error) {
	if formalGLMValidateRegisteredPhase19BindingRecordV1(
		record, contract, pins) != nil {
		return "", fmt.Errorf(
			"formal-glm registered Phase20 DP share: invalid registered binding")
	}
	plan := contract.Core.RegisteredExecutionPlan
	if len(plan.NoiseAuthorities) != 2 ||
		len(plan.DesignatedComputePeers) != 2 ||
		plan.NoiseAuthorities[0].Role != "garbler" ||
		plan.NoiseAuthorities[1].Role != "evaluator" ||
		plan.NoiseAuthorities[0].PeerName != plan.DesignatedComputePeers[0] ||
		plan.NoiseAuthorities[1].PeerName != plan.DesignatedComputePeers[1] {
		return "", fmt.Errorf(
			"formal-glm registered Phase20 DP share: invalid K2 authorities")
	}
	binding := proposal.Binding
	genesisAbandon := binding.PreviousAbandonSHA256 ==
		formalGLMRegisteredPhase19AttemptZeroPreviousV1
	genesisAttempt := binding.PreviousAttemptID ==
		formalGLMRegisteredPhase19AttemptZeroPreviousV1
	if genesisAbandon != genesisAttempt || (!genesisAbandon &&
		(!formalGLMIsSHA256(binding.PreviousAbandonSHA256) ||
			!formalGLMIsSHA256(binding.PreviousAttemptID) ||
			binding.PreviousAbandonSHA256 ==
				formalGLMRegisteredPhase19AttemptZeroPreviousV1 ||
			binding.PreviousAttemptID ==
				formalGLMRegisteredPhase19AttemptZeroPreviousV1)) {
		return "", fmt.Errorf(
			"formal-glm registered Phase20 DP share: invalid attempt predecessor")
	}
	contractSHA256, err := formalGLMSourceContractSHA256V1(contract)
	if err != nil {
		return "", err
	}
	recordSHA256, err := formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase19AttemptDomainV1+"/binding-record", record)
	if err != nil {
		return "", err
	}
	attemptID, err := formalGLMRegisteredPhase19AttemptIDV1(
		record.Binding.SemanticRootSHA256, binding.PreviousAbandonSHA256)
	if err != nil {
		return "", err
	}
	scheduleRootSHA256, err := formalGLMRegisteredPhase19AttemptScheduleRootV1(
		record.Binding.SemanticRootSHA256, attemptID)
	if err != nil {
		return "", err
	}
	wantBinding := formalGLMRegisteredPhase19AttemptBindingV1{
		ArtifactID:                    record.Binding.ArtifactID,
		SourceContractCoreSHA256:      record.Binding.SourceContractCoreSHA256,
		SourceContractSHA256:          contractSHA256,
		RegisteredExecutionPlanSHA256: record.Binding.RegisteredExecutionPlanSHA256,
		PinsetSHA256:                  record.Binding.PinsetSHA256,
		BindingRecordSHA256:           recordSHA256,
		SemanticRootSHA256:            record.Binding.SemanticRootSHA256,
		PreviousAbandonSHA256:         binding.PreviousAbandonSHA256,
		PreviousAttemptID:             binding.PreviousAttemptID,
		AttemptID:                     attemptID,
		ScheduleRootSHA256:            scheduleRootSHA256,
		OpeningsPerformed:             0,
		ProductionReady:               false,
	}
	garbler := plan.NoiseAuthorities[0]
	wantProposal := formalGLMRegisteredPhase19ClaimProposalV1{
		Version: formalGLMRegisteredPhase19ClaimProposalVersionV1,
		Purpose: formalGLMRegisteredPhase19ClaimProposalPurposeV1,
		Binding: wantBinding, GarblerPeerName: garbler.PeerName,
		GarblerPeerID: garbler.PeerID,
	}
	unsignedProposal := proposal
	unsignedProposal.Signature = nil
	proposalMessage, err := formalGLMRegisteredPhase19AttemptSignatureMessageV1(
		formalGLMRegisteredPhase19ClaimProposalDomainV1, unsignedProposal)
	if err != nil || !reflect.DeepEqual(unsignedProposal, wantProposal) ||
		len(proposal.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pins[garbler.PeerName], proposalMessage,
			proposal.Signature) {
		clear(proposalMessage)
		return "", fmt.Errorf(
			"formal-glm registered Phase20 DP share: invalid claim proposal")
	}
	clear(proposalMessage)
	proposalSHA256, err := formalGLMRegisteredPhase19ClaimProposalSHA256V1(
		proposal)
	if err != nil {
		return "", err
	}
	evaluator := plan.NoiseAuthorities[1]
	wantAccept := formalGLMRegisteredPhase19ClaimAcceptV1{
		Version: formalGLMRegisteredPhase19ClaimAcceptVersionV1,
		Purpose: formalGLMRegisteredPhase19ClaimAcceptPurposeV1,
		Binding: wantBinding, ClaimProposalSHA256: proposalSHA256,
		EvaluatorPeerName: evaluator.PeerName,
		EvaluatorPeerID:   evaluator.PeerID,
	}
	unsignedAccept := accept
	unsignedAccept.Signature = nil
	acceptMessage, err := formalGLMRegisteredPhase19AttemptSignatureMessageV1(
		formalGLMRegisteredPhase19ClaimAcceptDomainV1, unsignedAccept)
	if err != nil || !reflect.DeepEqual(unsignedAccept, wantAccept) ||
		len(accept.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pins[evaluator.PeerName], acceptMessage,
			accept.Signature) {
		clear(acceptMessage)
		return "", fmt.Errorf(
			"formal-glm registered Phase20 DP share: invalid claim accept")
	}
	clear(acceptMessage)
	return formalGLMRegisteredPhase19ClaimAcceptSHA256V1(accept)
}

func formalGLMRegisteredPhase20DPShareCommonEvidenceSHA256V1(
	evidence formalGLMRegisteredPhase20PreparedEvidenceV1,
) (string, error) {
	evidence.Peer = ""
	evidence.CanonicalDPShare = ""
	evidence.EvidenceSealSHA256 = ""
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase20DPShareReceiptDomainV1+"/common-evidence",
		evidence)
}

func formalGLMRegisteredPhase20DeriveDPShareReceiptContextV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	evidence formalGLMRegisteredPhase20PreparedEvidenceV1,
) (formalGLMRegisteredPhase20DPShareReceiptContextV1, error) {
	var zero formalGLMRegisteredPhase20DPShareReceiptContextV1
	claimAcceptSHA256, err := formalGLMRegisteredPhase20ValidateClaimPairV1(
		record, contract, pins, proposal, accept)
	if err != nil || !reflect.DeepEqual(evidence.Attempt, proposal.Binding) {
		return zero, fmt.Errorf(
			"formal-glm registered Phase20 DP share: evidence/claim mismatch")
	}
	trusted, err := formalGLMRegisteredPhase20RehydrateEvidenceV1(
		runtime, record, contract, proposal.Binding, evidence, pins)
	if err != nil {
		return zero, err
	}
	defer trusted.clear()
	plan := contract.Core.RegisteredExecutionPlan
	bridge := trusted.source.Result.DPBridge
	if bridge.GarblerPeerName != plan.NoiseAuthorities[0].PeerName ||
		bridge.GarblerPeerID != plan.NoiseAuthorities[0].PeerID ||
		bridge.EvaluatorPeerName != plan.NoiseAuthorities[1].PeerName ||
		bridge.EvaluatorPeerID != plan.NoiseAuthorities[1].PeerID {
		return zero, fmt.Errorf(
			"formal-glm registered Phase20 DP share: bridge role mismatch")
	}
	role, peer := "", evidence.Peer
	for _, authority := range plan.NoiseAuthorities {
		if authority.PeerName == peer {
			role = authority.Role
		}
	}
	if role != "garbler" && role != "evaluator" {
		return zero, fmt.Errorf(
			"formal-glm registered Phase20 DP share: invalid local role")
	}
	scheduleRoot, err := hex.DecodeString(proposal.Binding.ScheduleRootSHA256)
	if err != nil || len(scheduleRoot) != sha256.Size {
		clear(scheduleRoot)
		return zero, fmt.Errorf(
			"formal-glm registered Phase20 DP share: invalid schedule root")
	}
	var root [32]byte
	copy(root[:], scheduleRoot)
	clear(scheduleRoot)
	bridgeAttempt := formalGLMPhase19RuntimeAttempt(
		root, "phase15-dp-bridge", 0, -1)
	clear(root[:])
	session, err := formalGLMPhase15DPBridgeSession(
		trusted.source.Plan, bridge, bridgeAttempt, trusted.source.backend)
	clear(bridgeAttempt[:])
	if err != nil {
		return zero, err
	}
	sessionContext := exactGCContextDigest(session)
	clear(session.MasterKey[:])
	commonEvidenceSHA256, err :=
		formalGLMRegisteredPhase20DPShareCommonEvidenceSHA256V1(evidence)
	if err != nil {
		return zero, err
	}
	localEvidenceSHA256, err := formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase20DPShareReceiptDomainV1+"/local-evidence",
		evidence)
	if err != nil {
		return zero, err
	}
	spec := exactGCCircuitSpec{
		Operation: exactGCFormalGLMDPBridge, RingBits: 128, FracBits: 0,
		VectorLen: trusted.source.Plan.Kernel.CoefficientCount,
	}
	canonicalShare, err := exactGCEncodeWorkerCanonicalShares(
		trusted.source.DPShares, spec)
	if err != nil || canonicalShare != evidence.CanonicalDPShare {
		return zero, fmt.Errorf(
			"formal-glm registered Phase20 DP share: non-canonical local output")
	}
	outputShareSHA256, err := formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase20DPShareReceiptDomainV1+"/output-share",
		struct {
			ClaimAcceptSHA256            string `json:"claim_accept_sha256"`
			Role                         string `json:"role"`
			DPBridgeSessionContextSHA256 string `json:"dp_bridge_session_context_sha256"`
			CommonEvidenceSHA256         string `json:"common_evidence_sha256"`
			CanonicalDPShare             string `json:"canonical_dp_share"`
		}{claimAcceptSHA256, role, hex.EncodeToString(sessionContext[:]),
			commonEvidenceSHA256, canonicalShare})
	if err != nil {
		return zero, err
	}
	return formalGLMRegisteredPhase20DPShareReceiptContextV1{
		claimAcceptSHA256: claimAcceptSHA256, role: role, peer: peer,
		dpBridgeSessionContextSHA256: hex.EncodeToString(sessionContext[:]),
		commonEvidenceSHA256:         commonEvidenceSHA256,
		localEvidenceSHA256:          localEvidenceSHA256,
		outputShareSHA256:            outputShareSHA256,
	}, nil
}

func formalGLMRegisteredPhase20DPShareReceiptFromContextV1(
	context formalGLMRegisteredPhase20DPShareReceiptContextV1,
) formalGLMRegisteredPhase20DPShareReceiptV1 {
	return formalGLMRegisteredPhase20DPShareReceiptV1{
		Version:                formalGLMRegisteredPhase20DPShareReceiptVersionV1,
		Purpose:                formalGLMRegisteredPhase20DPShareReceiptPurposeV1,
		SecurityModel:          formalGLMRegisteredPhase20DPShareReceiptSecurityModelV1,
		MaliciousSecurityClaim: false,
		ClaimAcceptSHA256:      context.claimAcceptSHA256, Role: context.role,
		DPBridgeSessionContextSHA256: context.dpBridgeSessionContextSHA256,
		CommonEvidenceSHA256:         context.commonEvidenceSHA256,
		LocalEvidenceSHA256:          context.localEvidenceSHA256,
		OutputShareSHA256:            context.outputShareSHA256,
		ProtectedPayloadExposed:      false,
	}
}

func formalGLMRegisteredPhase20DPShareReceiptMessageV1(
	receipt formalGLMRegisteredPhase20DPShareReceiptV1,
) ([]byte, error) {
	if receipt.Version != formalGLMRegisteredPhase20DPShareReceiptVersionV1 ||
		receipt.Purpose != formalGLMRegisteredPhase20DPShareReceiptPurposeV1 ||
		receipt.SecurityModel !=
			formalGLMRegisteredPhase20DPShareReceiptSecurityModelV1 ||
		receipt.MaliciousSecurityClaim || receipt.ProtectedPayloadExposed ||
		(receipt.Role != "garbler" && receipt.Role != "evaluator") ||
		!formalGLMIsSHA256(receipt.ClaimAcceptSHA256) ||
		!formalGLMIsSHA256(receipt.DPBridgeSessionContextSHA256) ||
		!formalGLMIsSHA256(receipt.CommonEvidenceSHA256) ||
		!formalGLMIsSHA256(receipt.LocalEvidenceSHA256) ||
		!formalGLMIsSHA256(receipt.OutputShareSHA256) {
		return nil, fmt.Errorf(
			"formal-glm registered Phase20 DP share: invalid receipt")
	}
	unsigned := receipt
	unsigned.Signature = nil
	encoded, err := json.Marshal(unsigned)
	if err != nil {
		return nil, err
	}
	return append([]byte(
		formalGLMRegisteredPhase20DPShareReceiptDomainV1+"|"), encoded...), nil
}

func formalGLMRegisteredPhase20ValidateDPShareReceiptSignatureV1(
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
	receipt formalGLMRegisteredPhase20DPShareReceiptV1,
) error {
	plan := contract.Core.RegisteredExecutionPlan
	index := -1
	if receipt.Role == "garbler" {
		index = 0
	} else if receipt.Role == "evaluator" {
		index = 1
	}
	if len(plan.NoiseAuthorities) != 2 || index < 0 ||
		plan.NoiseAuthorities[index].Role != receipt.Role {
		return fmt.Errorf(
			"formal-glm registered Phase20 DP share: invalid receipt role")
	}
	peer := plan.NoiseAuthorities[index].PeerName
	message, err := formalGLMRegisteredPhase20DPShareReceiptMessageV1(receipt)
	if err != nil || len(receipt.Signature) != ed25519.SignatureSize ||
		len(pins[peer]) != ed25519.PublicKeySize ||
		!ed25519.Verify(pins[peer], message, receipt.Signature) {
		clear(message)
		return fmt.Errorf(
			"formal-glm registered Phase20 DP share: invalid receipt signature")
	}
	clear(message)
	return nil
}

func formalGLMRegisteredPhase20BuildDPShareReceiptV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	evidence formalGLMRegisteredPhase20PreparedEvidenceV1,
	signingKey ed25519.PrivateKey,
) (formalGLMRegisteredPhase20DPShareReceiptV1, error) {
	var zero formalGLMRegisteredPhase20DPShareReceiptV1
	context, err := formalGLMRegisteredPhase20DeriveDPShareReceiptContextV1(
		runtime, record, contract, pins, proposal, accept, evidence)
	if err != nil {
		return zero, err
	}
	if len(signingKey) != ed25519.PrivateKeySize ||
		!bytes.Equal(signingKey.Public().(ed25519.PublicKey),
			pins[context.peer]) {
		return zero, fmt.Errorf(
			"formal-glm registered Phase20 DP share: signer is not pinned")
	}
	receipt := formalGLMRegisteredPhase20DPShareReceiptFromContextV1(context)
	message, err := formalGLMRegisteredPhase20DPShareReceiptMessageV1(receipt)
	if err != nil {
		return zero, err
	}
	receipt.Signature = ed25519.Sign(signingKey, message)
	clear(message)
	return receipt, nil
}

func formalGLMRegisteredPhase20ValidateLocalDPShareReceiptV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	evidence formalGLMRegisteredPhase20PreparedEvidenceV1,
	receipt formalGLMRegisteredPhase20DPShareReceiptV1,
) error {
	context, err := formalGLMRegisteredPhase20DeriveDPShareReceiptContextV1(
		runtime, record, contract, pins, proposal, accept, evidence)
	if err != nil {
		return err
	}
	want := formalGLMRegisteredPhase20DPShareReceiptFromContextV1(context)
	got := receipt
	got.Signature = nil
	if !reflect.DeepEqual(got, want) ||
		formalGLMRegisteredPhase20ValidateDPShareReceiptSignatureV1(
			contract, pins, receipt) != nil {
		return fmt.Errorf(
			"formal-glm registered Phase20 DP share: local receipt mismatch")
	}
	return nil
}

func formalGLMRegisteredPhase20DPShareReceiptPairSHA256V1(
	pair formalGLMRegisteredPhase20DPShareReceiptPairV1,
) (string, error) {
	if pair.Version != formalGLMRegisteredPhase20DPShareReceiptPairVersionV1 ||
		pair.Purpose != formalGLMRegisteredPhase20DPShareReceiptPairPurposeV1 ||
		pair.Garbler.Role != "garbler" || pair.Evaluator.Role != "evaluator" ||
		(pair.PairSHA256 != "" && !formalGLMIsSHA256(pair.PairSHA256)) {
		return "", fmt.Errorf(
			"formal-glm registered Phase20 DP share: invalid receipt pair")
	}
	pair.PairSHA256 = ""
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase20DPShareReceiptDomainV1+"/pair", pair)
}

func formalGLMRegisteredPhase20ValidateAndOrderDPShareReceiptsV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	localEvidence formalGLMRegisteredPhase20PreparedEvidenceV1,
	left, right formalGLMRegisteredPhase20DPShareReceiptV1,
) (formalGLMRegisteredPhase20DPShareReceiptV1,
	formalGLMRegisteredPhase20DPShareReceiptV1, error,
) {
	var zero formalGLMRegisteredPhase20DPShareReceiptV1
	claimAcceptSHA256, err := formalGLMRegisteredPhase20ValidateClaimPairV1(
		record, contract, pins, proposal, accept)
	if err != nil {
		return zero, zero, err
	}
	for _, receipt := range []formalGLMRegisteredPhase20DPShareReceiptV1{
		left, right,
	} {
		if receipt.ClaimAcceptSHA256 != claimAcceptSHA256 ||
			formalGLMRegisteredPhase20ValidateDPShareReceiptSignatureV1(
				contract, pins, receipt) != nil {
			return zero, zero, fmt.Errorf(
				"formal-glm registered Phase20 DP share: inadmissible receipt")
		}
	}
	garbler, evaluator := left, right
	if garbler.Role == "evaluator" && evaluator.Role == "garbler" {
		garbler, evaluator = evaluator, garbler
	}
	if garbler.Role != "garbler" || evaluator.Role != "evaluator" ||
		garbler.DPBridgeSessionContextSHA256 !=
			evaluator.DPBridgeSessionContextSHA256 ||
		garbler.CommonEvidenceSHA256 != evaluator.CommonEvidenceSHA256 {
		return zero, zero, fmt.Errorf(
			"formal-glm registered Phase20 DP share: receipts do not form one K2 output")
	}
	local := garbler
	if localEvidence.Peer == contract.Core.RegisteredExecutionPlan.
		NoiseAuthorities[1].PeerName {
		local = evaluator
	}
	if err := formalGLMRegisteredPhase20ValidateLocalDPShareReceiptV1(
		runtime, record, contract, pins, proposal, accept,
		localEvidence, local); err != nil {
		return zero, zero, err
	}
	return garbler, evaluator, nil
}

func formalGLMRegisteredPhase20PairDPShareReceiptsV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	localEvidence formalGLMRegisteredPhase20PreparedEvidenceV1,
	left, right formalGLMRegisteredPhase20DPShareReceiptV1,
) (formalGLMRegisteredPhase20DPShareReceiptPairV1, error) {
	var zero formalGLMRegisteredPhase20DPShareReceiptPairV1
	garbler, evaluator, err :=
		formalGLMRegisteredPhase20ValidateAndOrderDPShareReceiptsV1(
			runtime, record, contract, pins, proposal, accept,
			localEvidence, left, right)
	if err != nil {
		return zero, err
	}
	pair := formalGLMRegisteredPhase20DPShareReceiptPairV1{
		Version: formalGLMRegisteredPhase20DPShareReceiptPairVersionV1,
		Purpose: formalGLMRegisteredPhase20DPShareReceiptPairPurposeV1,
		Garbler: garbler, Evaluator: evaluator,
	}
	pair.PairSHA256, err =
		formalGLMRegisteredPhase20DPShareReceiptPairSHA256V1(pair)
	if err != nil {
		return zero, err
	}
	return pair, nil
}

func formalGLMRegisteredPhase20ValidateDPShareReceiptPairV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	localEvidence formalGLMRegisteredPhase20PreparedEvidenceV1,
	pair formalGLMRegisteredPhase20DPShareReceiptPairV1,
) error {
	if !formalGLMIsSHA256(pair.PairSHA256) {
		return fmt.Errorf(
			"formal-glm registered Phase20 DP share: invalid pair hash")
	}
	want, err := formalGLMRegisteredPhase20PairDPShareReceiptsV1(
		runtime, record, contract, pins, proposal, accept, localEvidence,
		pair.Garbler, pair.Evaluator)
	if err != nil || !reflect.DeepEqual(pair, want) {
		return fmt.Errorf(
			"formal-glm registered Phase20 DP share: receipt pair mismatch")
	}
	return nil
}
