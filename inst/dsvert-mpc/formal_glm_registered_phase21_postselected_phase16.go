package main

// The registered Phase20 terminal is deliberately the first point at which a
// Phase16 binding can name the final receipt pair and post-execution capsule.
// This file derives that binding from one Selected handoff and a policy which
// every custodian signed before source work began.  It does not publish, open,
// or sign a DP result; the returned proposal is the public, deterministic
// object that a later K-of-K signing relay must carry to every custodian.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	formalGLMRegisteredPhase21PostSelectedPhase16PolicyVersionV1 = "dsvert-formal-glm-registered-phase21-postselected-phase16-policy-v1"
	formalGLMRegisteredPhase21PostSelectedPhase16PolicyPurposeV1 = "formal_glm_registered_phase21_postselected_phase16_policy_v1"
	formalGLMRegisteredPhase21PostSelectedPhase16PolicyDomainV1  = "dsVert/formal-glm/registered-phase21/postselected-phase16-policy/v1"

	formalGLMRegisteredPhase21PostSelectedPhase16VersionV1 = "dsvert-formal-glm-registered-phase21-postselected-phase16-v1"
	formalGLMRegisteredPhase21PostSelectedPhase16PurposeV1 = "formal_glm_registered_phase21_postselected_phase16_v1"
	formalGLMRegisteredPhase21PostSelectedPhase16DomainV1  = "dsVert/formal-glm/registered-phase21/postselected-phase16/v1"

	formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentVersionV1 = "dsvert-formal-glm-registered-phase21-postselected-authority-commitment-v1"
	formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentPurposeV1 = "formal_glm_registered_phase21_postselected_authority_commitment_v1"
	formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentDomainV1  = "dsVert/formal-glm/registered-phase21/postselected-authority-commitment/v1"
)

// formalGLMRegisteredPhase21PostSelectedPhase16PolicyV1 is fixed and
// K-of-K-signed before Phase18 ingress.  Its only variable release values are
// derived after Selected from the signed policy digest and the Selected hash,
// so a retry cannot obtain an independent Phase16 release instance.
type formalGLMRegisteredPhase21PostSelectedPhase16PolicyV1 struct {
	Version                    string                                      `json:"version"`
	Purpose                    string                                      `json:"purpose"`
	ArtifactID                 string                                      `json:"artifact_id"`
	SourceContractCoreSHA256   string                                      `json:"source_contract_core_sha256"`
	ManifestSHA256             string                                      `json:"manifest_sha256"`
	WorkloadSHA256             string                                      `json:"workload_sha256"`
	PrivacyEpochSHA256         string                                      `json:"privacy_epoch_sha256"`
	WorkerImplementationSHA256 string                                      `json:"worker_implementation_sha256"`
	ReceiptReferences          []jointDPBiomedicalGaussianReceiptReference `json:"receipt_references"`
	Epsilon                    string                                      `json:"epsilon"`
	AllocatedDelta             string                                      `json:"allocated_delta"`
	ProductionReady            bool                                        `json:"production_ready"`
	CustodianSignatures        []jointDPBiomedicalGaussianSignature        `json:"custodian_signatures"`
}

// formalGLMRegisteredPhase21PostSelectedPhase16V1 is public admission
// material only. It contains neither PreparedEvidence nor a DP share; the
// terminal remains the sole owner of the sealed source used to derive it.
type formalGLMRegisteredPhase21PostSelectedPhase16V1 struct {
	Version           string                                          `json:"version"`
	Purpose           string                                          `json:"purpose"`
	SelectedSHA256    string                                          `json:"selected_sha256"`
	PolicySHA256      string                                          `json:"policy_sha256"`
	Capsule           formalGLMPhase16CapsuleBinding                  `json:"capsule"`
	Request           formalGLMPhase16ProductiveRequest               `json:"request"`
	BackendSelection  formalGLMPhase16BackendSelectionContract        `json:"backend_selection"`
	WorkerPreimage    jointDPBiomedicalGaussianWorkerEnvelopePreimage `json:"worker_preimage"`
	ProposalSHA256    string                                          `json:"proposal_sha256"`
	OpeningsPerformed int                                             `json:"openings_performed"`
	ProductionReady   bool                                            `json:"production_ready"`
}

// Each designated authority derives this record from its Rock-local sampler
// root only after Selected.  The commitment is signed before it can be used
// in the Phase16 capsule; the seed never leaves the authority.
type formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1 struct {
	Version               string                             `json:"version"`
	Purpose               string                             `json:"purpose"`
	SelectedSHA256        string                             `json:"selected_sha256"`
	PolicySHA256          string                             `json:"policy_sha256"`
	ReleaseContractSHA256 string                             `json:"release_contract_sha256"`
	Role                  string                             `json:"role"`
	PeerName              string                             `json:"peer_name"`
	PeerID                string                             `json:"peer_id"`
	ContextSHA256         string                             `json:"context_sha256"`
	SeedSHA256            string                             `json:"seed_sha256"`
	ProductionReady       bool                               `json:"production_ready"`
	Signature             jointDPBiomedicalGaussianSignature `json:"signature"`
}

func formalGLMRegisteredPhase21PostSelectedPhase16PolicyUnsignedV1(
	policy formalGLMRegisteredPhase21PostSelectedPhase16PolicyV1,
) formalGLMRegisteredPhase21PostSelectedPhase16PolicyV1 {
	policy.ReceiptReferences = append(
		[]jointDPBiomedicalGaussianReceiptReference(nil), policy.ReceiptReferences...)
	policy.CustodianSignatures = nil
	return policy
}

func formalGLMRegisteredPhase21PostSelectedPhase16PolicyMessageV1(
	policy formalGLMRegisteredPhase21PostSelectedPhase16PolicyV1,
) ([]byte, error) {
	return jointDPBiomedicalGaussianDomainMessage(
		formalGLMRegisteredPhase21PostSelectedPhase16PolicyDomainV1,
		formalGLMRegisteredPhase21PostSelectedPhase16PolicyUnsignedV1(policy))
}

func formalGLMRegisteredPhase21SignPostSelectedPhase16PolicyV1(
	policy formalGLMRegisteredPhase21PostSelectedPhase16PolicyV1,
	signer string,
	privateKey ed25519.PrivateKey,
) (jointDPBiomedicalGaussianSignature, error) {
	if len(policy.CustodianSignatures) != 0 || len(privateKey) != ed25519.PrivateKeySize {
		return jointDPBiomedicalGaussianSignature{},
			fmt.Errorf("formal-glm registered Phase21 post-Selected policy: invalid unsigned policy")
	}
	return jointDPBiomedicalGaussianSign(
		formalGLMRegisteredPhase21PostSelectedPhase16PolicyDomainV1,
		formalGLMRegisteredPhase21PostSelectedPhase16PolicyUnsignedV1(policy), signer, privateKey)
}

func formalGLMRegisteredPhase21ValidatePostSelectedPhase16PolicyV1(
	policy formalGLMRegisteredPhase21PostSelectedPhase16PolicyV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) error {
	plan := contract.Core.RegisteredExecutionPlan
	if policy.Version != formalGLMRegisteredPhase21PostSelectedPhase16PolicyVersionV1 ||
		policy.Purpose != formalGLMRegisteredPhase21PostSelectedPhase16PolicyPurposeV1 ||
		policy.ProductionReady ||
		policy.ArtifactID != contract.Core.ArtifactID ||
		policy.SourceContractCoreSHA256 != contract.CoreSHA256 ||
		!formalGLMIsSHA256(policy.ManifestSHA256) ||
		!formalGLMIsSHA256(policy.WorkloadSHA256) ||
		!formalGLMIsSHA256(policy.PrivacyEpochSHA256) ||
		!formalGLMIsSHA256(policy.WorkerImplementationSHA256) ||
		jointDPBiomedicalGaussianValidateReceiptReferences(policy.ReceiptReferences) != nil ||
		formalGLMValidateSourceContractV1(contract, pins) != nil ||
		formalGLMValidateRegisteredExecutionPlanV1(plan, pins) != nil {
		return fmt.Errorf("formal-glm registered Phase21 post-Selected policy: invalid policy")
	}
	epsilon, epsilonErr := jointDPBiomedicalGaussianCanonicalDecimal(policy.Epsilon, "epsilon")
	delta, deltaErr := jointDPBiomedicalGaussianCanonicalDecimal(policy.AllocatedDelta, "allocated_delta")
	if epsilonErr != nil || deltaErr != nil || delta.Sign() <= 0 || delta.Cmp(epsilon) == 0 ||
		epsilon.RatString() != plan.Artifact.EpsilonRational ||
		delta.RatString() != plan.Artifact.DeltaRational {
		return fmt.Errorf("formal-glm registered Phase21 post-Selected policy: DP policy differs from artifact")
	}
	message, err := formalGLMRegisteredPhase21PostSelectedPhase16PolicyMessageV1(policy)
	if err != nil {
		return err
	}
	if err := jointDPBiomedicalGaussianVerifySignatures(
		message, policy.CustodianSignatures, plan.CustodianPeers, pins,
		"formal GLM post-Selected Phase16 policy"); err != nil {
		return err
	}
	return nil
}

func formalGLMRegisteredPhase21PostSelectedPhase16PolicySHA256V1(
	policy formalGLMRegisteredPhase21PostSelectedPhase16PolicyV1,
) (string, error) {
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase21PostSelectedPhase16PolicyDomainV1+"/policy",
		formalGLMRegisteredPhase21PostSelectedPhase16PolicyUnsignedV1(policy))
}

func formalGLMRegisteredPhase21PostSelectedPhase16HashV1(
	proposal formalGLMRegisteredPhase21PostSelectedPhase16V1,
) (string, error) {
	proposal.ProposalSHA256 = ""
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase21PostSelectedPhase16DomainV1+"/proposal", proposal)
}

func formalGLMRegisteredPhase21PostSelectedPhase16DeriveSHA256V1(
	label, policySHA256, selectedSHA256 string,
) (string, error) {
	if !formalGLMIsSHA256(policySHA256) || !formalGLMIsSHA256(selectedSHA256) {
		return "", fmt.Errorf("formal-glm registered Phase21 post-Selected proposal: invalid identity")
	}
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase21PostSelectedPhase16DomainV1+"/"+label,
		struct {
			PolicySHA256   string `json:"policy_sha256"`
			SelectedSHA256 string `json:"selected_sha256"`
		}{PolicySHA256: policySHA256, SelectedSHA256: selectedSHA256})
}

func formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentUnsignedV1(
	record formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1,
) formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1 {
	record.Signature = jointDPBiomedicalGaussianSignature{}
	return record
}

func formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentMessageV1(
	record formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1,
) ([]byte, error) {
	return jointDPBiomedicalGaussianDomainMessage(
		formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentDomainV1,
		formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentUnsignedV1(record))
}

func formalGLMRegisteredPhase21DerivePostSelectedAuthorityCommitmentV1(
	authorityRoot [32]byte,
	selectedSHA256, policySHA256, releaseContractSHA256 string,
	authority formalGLMRegisteredExecutionAuthorityV1,
	privateKey ed25519.PrivateKey,
) (formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1, error) {
	var zero formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1
	if !formalGLMPhase19KeyValid(authorityRoot) ||
		!formalGLMIsSHA256(selectedSHA256) || !formalGLMIsSHA256(policySHA256) ||
		!formalGLMIsSHA256(releaseContractSHA256) ||
		(authority.Role != "garbler" && authority.Role != "evaluator") ||
		!formalGLMRegistryLabelV1(authority.PeerName, 128) ||
		!formalGLMRegistryLabelV1(authority.PeerID, 256) ||
		len(privateKey) != ed25519.PrivateKeySize {
		return zero, fmt.Errorf("formal-glm registered Phase21 post-Selected authority: invalid commitment input")
	}
	releaseBytes, err := hex.DecodeString(releaseContractSHA256)
	if err != nil || len(releaseBytes) != sha256.Size {
		clear(releaseBytes)
		return zero, fmt.Errorf("formal-glm registered Phase21 post-Selected authority: invalid release contract")
	}
	var release [32]byte
	copy(release[:], releaseBytes)
	clear(releaseBytes)
	info := []byte(formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentDomainV1 +
		"/seed/" + selectedSHA256 + "/" + policySHA256 + "/" + authority.Role + "/" + authority.PeerID)
	reader := hkdf.New(sha256.New, authorityRoot[:], release[:], info)
	var seed [32]byte
	if _, err = io.ReadFull(reader, seed[:]); err != nil || !formalGLMPhase19KeyValid(seed) {
		clear(seed[:])
		return zero, fmt.Errorf("formal-glm registered Phase21 post-Selected authority: seed derivation failed")
	}
	context := jointDPCommitmentContext(release,
		jointDPGaussianOneDrawCommitmentPurpose+"/"+authority.Role, authority.PeerID)
	commitment := jointDPSeedCommitment(context, seed)
	clear(seed[:])
	record := formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1{
		Version:               formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentVersionV1,
		Purpose:               formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentPurposeV1,
		SelectedSHA256:        selectedSHA256,
		PolicySHA256:          policySHA256,
		ReleaseContractSHA256: releaseContractSHA256,
		Role:                  authority.Role,
		PeerName:              authority.PeerName,
		PeerID:                authority.PeerID,
		ContextSHA256:         hex.EncodeToString(context[:]),
		SeedSHA256:            hex.EncodeToString(commitment[:]),
		ProductionReady:       false,
	}
	signature, err := jointDPBiomedicalGaussianSign(
		formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentDomainV1,
		formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentUnsignedV1(record),
		authority.PeerName, privateKey)
	if err != nil {
		return zero, err
	}
	record.Signature = signature
	return record, nil
}

func formalGLMRegisteredPhase21ValidatePostSelectedAuthorityCommitmentsV1(
	authorityCommitments []formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1,
	selectedSHA256, policySHA256, releaseContractSHA256 string,
	plan formalGLMRegisteredExecutionPlanV1,
	pins map[string]ed25519.PublicKey,
) error {
	if len(authorityCommitments) != 2 || !formalGLMIsSHA256(selectedSHA256) ||
		!formalGLMIsSHA256(policySHA256) || !formalGLMIsSHA256(releaseContractSHA256) {
		return fmt.Errorf("formal-glm registered Phase21 post-Selected authority: incomplete commitments")
	}
	expected := make(map[string]formalGLMRegisteredExecutionAuthorityV1, 2)
	for _, authority := range plan.NoiseAuthorities {
		expected[authority.Role] = authority
	}
	if len(expected) != 2 || expected["garbler"].Role != "garbler" ||
		expected["evaluator"].Role != "evaluator" {
		return fmt.Errorf("formal-glm registered Phase21 post-Selected authority: invalid authority plan")
	}
	releaseBytes, err := hex.DecodeString(releaseContractSHA256)
	if err != nil || len(releaseBytes) != sha256.Size {
		clear(releaseBytes)
		return fmt.Errorf("formal-glm registered Phase21 post-Selected authority: invalid release contract")
	}
	var release [32]byte
	copy(release[:], releaseBytes)
	clear(releaseBytes)
	seen := make(map[string]bool, 2)
	for _, record := range authorityCommitments {
		authority, ok := expected[record.Role]
		if !ok || seen[record.Role] ||
			record.Version != formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentVersionV1 ||
			record.Purpose != formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentPurposeV1 ||
			record.SelectedSHA256 != selectedSHA256 || record.PolicySHA256 != policySHA256 ||
			record.ReleaseContractSHA256 != releaseContractSHA256 ||
			record.PeerName != authority.PeerName || record.PeerID != authority.PeerID ||
			record.ProductionReady || record.Signature.Signer != authority.PeerName ||
			len(record.Signature.Signature) != ed25519.SignatureSize ||
			len(pins[authority.PeerName]) != ed25519.PublicKeySize {
			return fmt.Errorf("formal-glm registered Phase21 post-Selected authority: invalid commitment")
		}
		context := jointDPCommitmentContext(release,
			jointDPGaussianOneDrawCommitmentPurpose+"/"+authority.Role, authority.PeerID)
		if record.ContextSHA256 != hex.EncodeToString(context[:]) || !formalGLMIsSHA256(record.SeedSHA256) {
			return fmt.Errorf("formal-glm registered Phase21 post-Selected authority: commitment context mismatch")
		}
		message, messageErr := formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentMessageV1(record)
		if messageErr != nil || !ed25519.Verify(pins[authority.PeerName], message, record.Signature.Signature) {
			return fmt.Errorf("formal-glm registered Phase21 post-Selected authority: invalid commitment signature")
		}
		seen[record.Role] = true
	}
	return nil
}

func formalGLMRegisteredPhase21PostSelectedPhase16CapsuleV1(
	selected formalGLMRegisteredPhase20SelectedV1,
	source formalGLMPhase20HandoffSource,
	policy formalGLMRegisteredPhase21PostSelectedPhase16PolicyV1,
	contract formalGLMSourceContractV1,
	authorityCommitments []formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMPhase16CapsuleBinding, formalGLMPhase16ProductiveRequest, string, error) {
	var zeroCapsule formalGLMPhase16CapsuleBinding
	var zeroRequest formalGLMPhase16ProductiveRequest
	if _, err := formalGLMRegisteredPhase20SelectedSHA256V1(selected); err != nil ||
		selected.SelectedSHA256 == "" ||
		formalGLMRegisteredPhase21ValidatePostSelectedPhase16PolicyV1(policy, contract, pins) != nil {
		return zeroCapsule, zeroRequest, "", fmt.Errorf("formal-glm registered Phase21 post-Selected proposal: invalid signed inputs")
	}
	plan := contract.Core.RegisteredExecutionPlan
	if validateFormalGLMPhase15Plan(source.Plan) != nil ||
		source.Plan.Kernel.Family != plan.Family ||
		source.Plan.Kernel.PinsetSHA256 != plan.PinsetSHA256 ||
		source.Plan.Kernel.SnapshotSHA256 != plan.SnapshotSHA256 ||
		source.Result.PostExecutionToken.CapsuleSHA256 == "" {
		return zeroCapsule, zeroRequest, "", fmt.Errorf("formal-glm registered Phase21 post-Selected proposal: Selected source differs from contract")
	}
	policySHA256, err := formalGLMRegisteredPhase21PostSelectedPhase16PolicySHA256V1(policy)
	if err != nil {
		return zeroCapsule, zeroRequest, "", err
	}
	releaseInstance, err := formalGLMRegisteredPhase21PostSelectedPhase16DeriveSHA256V1(
		"release-instance", policySHA256, selected.SelectedSHA256)
	if err != nil {
		return zeroCapsule, zeroRequest, "", err
	}
	runNonce, err := formalGLMRegisteredPhase21PostSelectedPhase16DeriveSHA256V1(
		"run-nonce", policySHA256, selected.SelectedSHA256)
	if err != nil {
		return zeroCapsule, zeroRequest, "", err
	}
	receiptDigest, err := formalGLMPhase15FinalReceiptPairDigest(source.Result.FinalReceipts)
	if err != nil {
		return zeroCapsule, zeroRequest, "", err
	}
	if err := formalGLMRegisteredPhase21ValidatePostSelectedAuthorityCommitmentsV1(
		authorityCommitments, selected.SelectedSHA256, policySHA256,
		hex.EncodeToString(receiptDigest[:]), plan, pins); err != nil {
		return zeroCapsule, zeroRequest, "", err
	}
	noiseCommitments := make(map[string]formalGLMPhase16NoiseCommitment,
		len(authorityCommitments))
	for _, commitment := range authorityCommitments {
		noiseCommitments[commitment.PeerID] = formalGLMPhase16NoiseCommitment{
			ContextSHA256: commitment.ContextSHA256,
			SeedSHA256:    commitment.SeedSHA256,
		}
	}
	capsule := formalGLMPhase16CapsuleBinding{
		CapsuleID:             source.Result.PostExecutionToken.CapsuleSHA256,
		ManifestSHA256:        policy.ManifestSHA256,
		SchemaManifestSHA256:  plan.Artifact.SchemaManifestSHA256,
		WorkloadSHA256:        policy.WorkloadSHA256,
		SourceContextSHA256:   contract.CoreSHA256,
		CoordinateOrderSHA256: plan.Artifact.CoordinateOrderSHA256,
		ReleaseInstanceID:     releaseInstance,
		ReleaseContractSHA256: hex.EncodeToString(receiptDigest[:]),
		Mechanism:             plan.Artifact.Mechanism,
		Allocation:            plan.Artifact.Allocation,
		Epsilon:               policy.Epsilon,
		AllocatedDelta:        policy.AllocatedDelta,
		NoiseCommitments:      noiseCommitments,
	}
	request := formalGLMPhase16ProductiveRequest{
		LogicalSnapshotHandleSHA256: contract.Core.SourceBindingSet.LogicalSnapshotSHA256,
		PrivacyEpochSHA256:          policy.PrivacyEpochSHA256,
		RunNonceSHA256:              runNonce,
		WorkerImplementationSHA256:  policy.WorkerImplementationSHA256,
		ReceiptReferences: append([]jointDPBiomedicalGaussianReceiptReference(nil),
			policy.ReceiptReferences...),
	}
	return capsule, request, policySHA256, nil
}

// formalGLMRegisteredPhase21BuildPostSelectedPhase16V1 derives exactly the
// same public Phase16 contracts at the two designated compute peers after
// their K2 terminal reaches Selected. The caller must immediately clear source.
func formalGLMRegisteredPhase21BuildPostSelectedPhase16V1(
	selected formalGLMRegisteredPhase20SelectedV1,
	source formalGLMPhase20HandoffSource,
	policy formalGLMRegisteredPhase21PostSelectedPhase16PolicyV1,
	contract formalGLMSourceContractV1,
	commitments []formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase21PostSelectedPhase16V1, error) {
	var zero formalGLMRegisteredPhase21PostSelectedPhase16V1
	capsule, request, policySHA256, err := formalGLMRegisteredPhase21PostSelectedPhase16CapsuleV1(
		selected, source, policy, contract, commitments, pins)
	if err != nil {
		return zero, err
	}
	admission, err := formalGLMPhase16BuildProductiveEnvelope(
		source.Plan, source.Result.FinalReceipts, pins, source.Result.DPBridge,
		capsule, source.Result.PostExecutionToken, source.backend, request)
	if err != nil {
		return zero, err
	}
	if admission.BackendSelection.Contract.SelectedBackend != formalGLMPhase16BackendOneDraw {
		return zero, fmt.Errorf("formal-glm registered Phase21 post-Selected proposal: one-draw admission unavailable")
	}
	proposal := formalGLMRegisteredPhase21PostSelectedPhase16V1{
		Version:           formalGLMRegisteredPhase21PostSelectedPhase16VersionV1,
		Purpose:           formalGLMRegisteredPhase21PostSelectedPhase16PurposeV1,
		SelectedSHA256:    selected.SelectedSHA256,
		PolicySHA256:      policySHA256,
		Capsule:           capsule,
		Request:           request,
		BackendSelection:  admission.BackendSelection.Contract,
		WorkerPreimage:    admission.Envelope.Preimage,
		OpeningsPerformed: 0,
		ProductionReady:   false,
	}
	proposal.ProposalSHA256, err = formalGLMRegisteredPhase21PostSelectedPhase16HashV1(proposal)
	if err != nil {
		return zero, err
	}
	return proposal, nil
}

func formalGLMRegisteredPhase21ValidatePostSelectedPhase16V1(
	proposal formalGLMRegisteredPhase21PostSelectedPhase16V1,
	policy formalGLMRegisteredPhase21PostSelectedPhase16PolicyV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) error {
	if proposal.Version != formalGLMRegisteredPhase21PostSelectedPhase16VersionV1 ||
		proposal.Purpose != formalGLMRegisteredPhase21PostSelectedPhase16PurposeV1 ||
		proposal.OpeningsPerformed != 0 || proposal.ProductionReady ||
		!formalGLMIsSHA256(proposal.SelectedSHA256) ||
		!formalGLMIsSHA256(proposal.PolicySHA256) ||
		!formalGLMIsSHA256(proposal.ProposalSHA256) ||
		formalGLMRegisteredPhase21ValidatePostSelectedPhase16PolicyV1(policy, contract, pins) != nil {
		return fmt.Errorf("formal-glm registered Phase21 post-Selected proposal: invalid proposal")
	}
	policySHA256, err := formalGLMRegisteredPhase21PostSelectedPhase16PolicySHA256V1(policy)
	if err != nil || proposal.PolicySHA256 != policySHA256 {
		return fmt.Errorf("formal-glm registered Phase21 post-Selected proposal: policy mismatch")
	}
	want, err := formalGLMRegisteredPhase21PostSelectedPhase16HashV1(proposal)
	if err != nil || want != proposal.ProposalSHA256 {
		return fmt.Errorf("formal-glm registered Phase21 post-Selected proposal: proposal hash mismatch")
	}
	return nil
}
