package main

// K-of-K signing for the public Phase16 proposal derived after a registered
// Phase20 Selected record.  Only a designated compute peer may attest that it
// rebuilt the proposal from its sealed source; every custodian, including a
// non-compute witness, signs the existing Phase16 contracts only after both
// compute attestations verify against the pinned consortium.

import (
	"crypto/ed25519"
	"fmt"
	"reflect"
)

const (
	formalGLMRegisteredPhase21PostSelectedComputeAttestationVersionV1 = "dsvert-formal-glm-registered-phase21-postselected-compute-attestation-v1"
	formalGLMRegisteredPhase21PostSelectedComputeAttestationPurposeV1 = "formal_glm_registered_phase21_postselected_compute_attestation_v1"
	formalGLMRegisteredPhase21PostSelectedComputeAttestationDomainV1  = "dsVert/formal-glm/registered-phase21/postselected-compute-attestation/v1"
)

type formalGLMRegisteredPhase21PostSelectedComputeAttestationV1 struct {
	Version           string                             `json:"version"`
	Purpose           string                             `json:"purpose"`
	ProposalSHA256    string                             `json:"proposal_sha256"`
	SelectedSHA256    string                             `json:"selected_sha256"`
	PolicySHA256      string                             `json:"policy_sha256"`
	Role              string                             `json:"role"`
	PeerName          string                             `json:"peer_name"`
	PeerID            string                             `json:"peer_id"`
	OpeningsPerformed int                                `json:"openings_performed"`
	ProductionReady   bool                               `json:"production_ready"`
	Signature         jointDPBiomedicalGaussianSignature `json:"signature"`
}

func formalGLMRegisteredPhase21PostSelectedComputeAttestationUnsignedV1(
	attestation formalGLMRegisteredPhase21PostSelectedComputeAttestationV1,
) formalGLMRegisteredPhase21PostSelectedComputeAttestationV1 {
	attestation.Signature = jointDPBiomedicalGaussianSignature{}
	return attestation
}

func formalGLMRegisteredPhase21PostSelectedComputeAuthorityV1(
	plan formalGLMRegisteredExecutionPlanV1, peer string,
) (formalGLMRegisteredExecutionAuthorityV1, error) {
	for _, authority := range plan.NoiseAuthorities {
		if authority.PeerName == peer &&
			(authority.Role == "garbler" || authority.Role == "evaluator") {
			return authority, nil
		}
	}
	return formalGLMRegisteredExecutionAuthorityV1{},
		fmt.Errorf("formal-glm registered Phase21 post-Selected signing: signer is not a compute authority")
}

func formalGLMRegisteredPhase21SignPostSelectedComputeAttestationV1(
	proposal formalGLMRegisteredPhase21PostSelectedPhase16V1,
	selected formalGLMRegisteredPhase20SelectedV1,
	source formalGLMPhase20HandoffSource,
	policy formalGLMRegisteredPhase21PostSelectedPhase16PolicyV1,
	contract formalGLMSourceContractV1,
	commitments []formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1,
	signer string,
	privateKey ed25519.PrivateKey,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase21PostSelectedComputeAttestationV1, error) {
	var zero formalGLMRegisteredPhase21PostSelectedComputeAttestationV1
	if len(privateKey) != ed25519.PrivateKeySize ||
		formalGLMRegisteredPhase21ValidatePostSelectedPhase16V1(
			proposal, policy, contract, pins) != nil {
		return zero, fmt.Errorf("formal-glm registered Phase21 post-Selected signing: invalid proposal")
	}
	want, err := formalGLMRegisteredPhase21BuildPostSelectedPhase16V1(
		selected, source, policy, contract, commitments, pins)
	if err != nil || !reflect.DeepEqual(want, proposal) {
		return zero, fmt.Errorf("formal-glm registered Phase21 post-Selected signing: proposal differs from Selected")
	}
	authority, err := formalGLMRegisteredPhase21PostSelectedComputeAuthorityV1(
		contract.Core.RegisteredExecutionPlan, signer)
	if err != nil || len(pins[signer]) != ed25519.PublicKeySize ||
		!ed25519.PublicKey(privateKey.Public().(ed25519.PublicKey)).Equal(pins[signer]) {
		return zero, fmt.Errorf("formal-glm registered Phase21 post-Selected signing: invalid compute signer")
	}
	attestation := formalGLMRegisteredPhase21PostSelectedComputeAttestationV1{
		Version:           formalGLMRegisteredPhase21PostSelectedComputeAttestationVersionV1,
		Purpose:           formalGLMRegisteredPhase21PostSelectedComputeAttestationPurposeV1,
		ProposalSHA256:    proposal.ProposalSHA256,
		SelectedSHA256:    proposal.SelectedSHA256,
		PolicySHA256:      proposal.PolicySHA256,
		Role:              authority.Role,
		PeerName:          authority.PeerName,
		PeerID:            authority.PeerID,
		OpeningsPerformed: 0,
		ProductionReady:   false,
	}
	signature, err := jointDPBiomedicalGaussianSign(
		formalGLMRegisteredPhase21PostSelectedComputeAttestationDomainV1,
		formalGLMRegisteredPhase21PostSelectedComputeAttestationUnsignedV1(attestation),
		signer, privateKey)
	if err != nil {
		return zero, err
	}
	attestation.Signature = signature
	return attestation, nil
}

func formalGLMRegisteredPhase21ValidatePostSelectedComputeAttestationsV1(
	proposal formalGLMRegisteredPhase21PostSelectedPhase16V1,
	policy formalGLMRegisteredPhase21PostSelectedPhase16PolicyV1,
	contract formalGLMSourceContractV1,
	attestations []formalGLMRegisteredPhase21PostSelectedComputeAttestationV1,
	pins map[string]ed25519.PublicKey,
) error {
	if formalGLMRegisteredPhase21ValidatePostSelectedPhase16V1(
		proposal, policy, contract, pins) != nil || len(attestations) != 2 {
		return fmt.Errorf("formal-glm registered Phase21 post-Selected signing: invalid compute attestations")
	}
	plan := contract.Core.RegisteredExecutionPlan
	expected := make(map[string]formalGLMRegisteredExecutionAuthorityV1, 2)
	for _, authority := range plan.NoiseAuthorities {
		expected[authority.Role] = authority
	}
	if len(expected) != 2 || expected["garbler"].Role != "garbler" ||
		expected["evaluator"].Role != "evaluator" {
		return fmt.Errorf("formal-glm registered Phase21 post-Selected signing: invalid compute authority set")
	}
	seen := make(map[string]bool, 2)
	for _, attestation := range attestations {
		authority, ok := expected[attestation.Role]
		if !ok || seen[attestation.Role] ||
			attestation.Version != formalGLMRegisteredPhase21PostSelectedComputeAttestationVersionV1 ||
			attestation.Purpose != formalGLMRegisteredPhase21PostSelectedComputeAttestationPurposeV1 ||
			attestation.ProposalSHA256 != proposal.ProposalSHA256 ||
			attestation.SelectedSHA256 != proposal.SelectedSHA256 ||
			attestation.PolicySHA256 != proposal.PolicySHA256 ||
			attestation.PeerName != authority.PeerName || attestation.PeerID != authority.PeerID ||
			attestation.OpeningsPerformed != 0 || attestation.ProductionReady ||
			attestation.Signature.Signer != authority.PeerName ||
			len(attestation.Signature.Signature) != ed25519.SignatureSize ||
			len(pins[authority.PeerName]) != ed25519.PublicKeySize {
			return fmt.Errorf("formal-glm registered Phase21 post-Selected signing: malformed compute attestation")
		}
		message, err := jointDPBiomedicalGaussianDomainMessage(
			formalGLMRegisteredPhase21PostSelectedComputeAttestationDomainV1,
			formalGLMRegisteredPhase21PostSelectedComputeAttestationUnsignedV1(attestation))
		if err != nil || !ed25519.Verify(
			pins[authority.PeerName], message, attestation.Signature.Signature) {
			return fmt.Errorf("formal-glm registered Phase21 post-Selected signing: invalid compute attestation signature")
		}
		seen[attestation.Role] = true
	}
	return nil
}

// formalGLMRegisteredPhase21SignPostSelectedPhase16V1 signs both existing
// Phase16 contracts only after the two designated peers attested the exact
// candidate. It is safe for a non-compute witness because the candidate and
// attestations contain no sealed evidence or DP share.
func formalGLMRegisteredPhase21SignPostSelectedPhase16V1(
	proposal formalGLMRegisteredPhase21PostSelectedPhase16V1,
	policy formalGLMRegisteredPhase21PostSelectedPhase16PolicyV1,
	contract formalGLMSourceContractV1,
	attestations []formalGLMRegisteredPhase21PostSelectedComputeAttestationV1,
	signer string,
	privateKey ed25519.PrivateKey,
	pins map[string]ed25519.PublicKey,
) (jointDPBiomedicalGaussianSignature, jointDPBiomedicalGaussianSignature, error) {
	var zero jointDPBiomedicalGaussianSignature
	if len(privateKey) != ed25519.PrivateKeySize || len(pins[signer]) != ed25519.PublicKeySize ||
		!ed25519.PublicKey(privateKey.Public().(ed25519.PublicKey)).Equal(pins[signer]) ||
		formalGLMRegisteredPhase21ValidatePostSelectedComputeAttestationsV1(
			proposal, policy, contract, attestations, pins) != nil {
		return zero, zero, fmt.Errorf("formal-glm registered Phase21 post-Selected signing: unsigned candidate rejected")
	}
	found := false
	for _, peer := range contract.Core.RegisteredExecutionPlan.CustodianPeers {
		found = found || peer == signer
	}
	if !found || proposal.BackendSelection.SelectedBackend != formalGLMPhase16BackendOneDraw {
		return zero, zero, fmt.Errorf("formal-glm registered Phase21 post-Selected signing: signer is not a custodian")
	}
	backend, err := formalGLMPhase16SignBackendSelection(
		proposal.BackendSelection, signer, privateKey)
	if err != nil {
		return zero, zero, err
	}
	worker, err := formalGLMPhase16SignProductiveEnvelope(
		proposal.WorkerPreimage, signer, privateKey)
	if err != nil {
		return zero, zero, err
	}
	return backend, worker, nil
}

// formalGLMRegisteredPhase21AdmitPostSelectedPhase16V1 is run only at a
// designated compute peer. It rebuilds the proposal from its sealed Selected
// source before accepting K-of-K Phase16 signatures, preventing a relay from
// substituting a candidate that witnesses merely saw as public bytes.
func formalGLMRegisteredPhase21AdmitPostSelectedPhase16V1(
	proposal formalGLMRegisteredPhase21PostSelectedPhase16V1,
	selected formalGLMRegisteredPhase20SelectedV1,
	source formalGLMPhase20HandoffSource,
	policy formalGLMRegisteredPhase21PostSelectedPhase16PolicyV1,
	contract formalGLMSourceContractV1,
	commitments []formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1,
	attestations []formalGLMRegisteredPhase21PostSelectedComputeAttestationV1,
	backendSignatures, workerSignatures []jointDPBiomedicalGaussianSignature,
	pins map[string]ed25519.PublicKey,
) (formalGLMPhase16ProductiveAdmission, error) {
	var zero formalGLMPhase16ProductiveAdmission
	want, err := formalGLMRegisteredPhase21BuildPostSelectedPhase16V1(
		selected, source, policy, contract, commitments, pins)
	if err != nil || !reflect.DeepEqual(want, proposal) ||
		formalGLMRegisteredPhase21ValidatePostSelectedComputeAttestationsV1(
			proposal, policy, contract, attestations, pins) != nil {
		return zero, fmt.Errorf("formal-glm registered Phase21 post-Selected signing: admission candidate mismatch")
	}
	admission, err := formalGLMPhase16BuildProductiveEnvelope(
		source.Plan, source.Result.FinalReceipts, pins, source.Result.DPBridge,
		proposal.Capsule, source.Result.PostExecutionToken, source.backend, proposal.Request)
	if err != nil || !reflect.DeepEqual(admission.BackendSelection.Contract, proposal.BackendSelection) ||
		!reflect.DeepEqual(admission.Envelope.Preimage, proposal.WorkerPreimage) {
		return zero, fmt.Errorf("formal-glm registered Phase21 post-Selected signing: admission source mismatch")
	}
	admission, err = formalGLMPhase16AdmitProductiveBackendSignatures(admission, backendSignatures)
	if err != nil {
		return zero, err
	}
	return formalGLMPhase16AdmitProductiveSignatures(admission, workerSignatures)
}
