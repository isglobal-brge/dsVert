package main

// Admission adapter from the machine-proven formal-GLM release binding into
// the scalable independent-full Gaussian backend.  This deliberately does
// not manufacture a biomedical contribution layout: the authoritative
// sensitivity remains the Phase-1.5 certificate, and both that certificate
// and the automatic backend choice are K-of-K signed.

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"reflect"
)

const (
	formalGLMPhase16FullFallbackContractDomain = "dsVert/formal-glm/phase16/independent-full-contract/v1"
	formalGLMPhase16FullFallbackManifestDomain = "dsVert/formal-glm/phase16/independent-full-manifest-authority/v1"
)

type formalGLMPhase16FullFallbackRequest struct {
	LogicalReleaseSHA256        string
	PrivacyEpochSHA256          string
	LogicalSnapshotHandleSHA256 string
	NoiseRootEpochs             []jointDPBiomedicalGaussianNoiseRootEpoch
	NoiseCommitments            []jointDPBiomedicalGaussianFullNoiseCommitment
	ReceiptReferences           []jointDPBiomedicalGaussianReceiptReference
}

type formalGLMPhase16FullFallbackContractAttestation struct {
	Contract   jointDPBiomedicalGaussianFullSelectionContract
	Signatures []jointDPBiomedicalGaussianSignature
}

func formalGLMPhase16FullFallbackManifestSHA256(
	binding formalGLMPhase16ReleaseBinding,
	selection formalGLMPhase16BackendSelectionAttestation,
) (string, error) {
	selectionSHA256, err := formalGLMPhase16BackendSelectionSHA256(selection)
	if err != nil {
		return "", err
	}
	return formalGLMPhase16DomainDigest(
		formalGLMPhase16FullFallbackManifestDomain, struct {
			BindingSHA256   string `json:"binding_sha256"`
			SelectionSHA256 string `json:"selection_sha256"`
		}{binding.BindingSHA256, selectionSHA256})
}

func formalGLMPhase16FullFallbackIdentity(
	selection formalGLMPhase16BackendSelectionAttestation,
	binding formalGLMPhase16ReleaseBinding,
	token formalGLMPhase19PostExecutionToken,
	pins map[string]ed25519.PublicKey,
	request formalGLMPhase16FullFallbackRequest,
) (jointDPBiomedicalGaussianFullReleaseIdentity, error) {
	var zero jointDPBiomedicalGaussianFullReleaseIdentity
	plans, err := formalGLMPhase16ValidateBackendSelection(
		selection, binding, token, pins)
	if err != nil || selection.Contract.SelectedBackend !=
		formalGLMPhase16BackendFull || !plans.Full.CapabilityAvailable {
		if err == nil {
			err = fmt.Errorf("formal-glm: independent-full was not the signed backend")
		}
		return zero, err
	}
	for _, value := range []string{
		request.LogicalReleaseSHA256, request.PrivacyEpochSHA256,
		request.LogicalSnapshotHandleSHA256,
	} {
		if !formalGLMIsSHA256(value) {
			return zero, fmt.Errorf("formal-glm: invalid full-fallback release identity")
		}
	}
	peers := selection.Contract.DesignatedComputePeers
	if err := jointDPBiomedicalGaussianFullValidateEpochs(
		request.NoiseRootEpochs, peers); err != nil {
		return zero, err
	}
	if err := jointDPBiomedicalGaussianValidateReceiptReferences(
		request.ReceiptReferences); err != nil {
		return zero, err
	}
	ledger, err := jointDPBiomedicalGaussianFullReceipt(
		request.ReceiptReferences,
		jointDPBiomedicalGaussianReceiptPrivacyLedger)
	if err != nil {
		return zero, err
	}
	manifestSHA256, err := formalGLMPhase16FullFallbackManifestSHA256(
		binding, selection)
	if err != nil {
		return zero, err
	}
	identity := jointDPBiomedicalGaussianFullReleaseIdentity{
		Backend:                     jointDPGaussianBackend,
		ManifestAttestationSHA256:   manifestSHA256,
		ManifestSHA256:              binding.ManifestSHA256,
		WorkloadSHA256:              binding.WorkloadSHA256,
		PinsetSHA256:                binding.PinsetSHA256,
		DesignatedComputePeers:      append([]string(nil), peers...),
		LogicalReleaseSHA256:        request.LogicalReleaseSHA256,
		PrivacyEpochSHA256:          request.PrivacyEpochSHA256,
		LogicalSnapshotHandleSHA256: request.LogicalSnapshotHandleSHA256,
		SourceContractHandleSHA256:  binding.SourceContextSHA256,
		MaterializationRootSHA256:   token.GlobalMaterializationRoot,
		ReservationSHA256:           ledger.SHA256,
		Epsilon:                     binding.Epsilon, Delta: binding.AllocatedDelta,
		PlanRequestBindingSHA256: plans.Full.RequestBindingSHA256,
		NoiseRootEpochs: append([]jointDPBiomedicalGaussianNoiseRootEpoch(nil),
			request.NoiseRootEpochs...),
		ReceiptReferences: append([]jointDPBiomedicalGaussianReceiptReference(nil),
			request.ReceiptReferences...),
	}
	releaseDigest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianFullReleaseInstanceDomain, identity)
	if err != nil {
		return zero, err
	}
	identity.ReleaseInstanceID = hex.EncodeToString(releaseDigest[:])
	transcriptDigest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianFullWorkerTranscriptDomain, identity)
	if err != nil {
		return zero, err
	}
	identity.WorkerTranscriptSHA256 = hex.EncodeToString(transcriptDigest[:])
	return identity, nil
}

func formalGLMPhase16BuildFullFallbackContract(
	selection formalGLMPhase16BackendSelectionAttestation,
	binding formalGLMPhase16ReleaseBinding,
	token formalGLMPhase19PostExecutionToken,
	pins map[string]ed25519.PublicKey,
	request formalGLMPhase16FullFallbackRequest,
) (jointDPBiomedicalGaussianFullSelectionContract, error) {
	var zero jointDPBiomedicalGaussianFullSelectionContract
	plans, err := formalGLMPhase16ValidateBackendSelection(
		selection, binding, token, pins)
	if err != nil || selection.Contract.SelectedBackend !=
		formalGLMPhase16BackendFull {
		if err == nil {
			err = fmt.Errorf("formal-glm: independent-full was not selected")
		}
		return zero, err
	}
	identity, err := formalGLMPhase16FullFallbackIdentity(
		selection, binding, token, pins, request)
	if err != nil {
		return zero, err
	}
	if len(request.NoiseCommitments) != 2 {
		return zero, fmt.Errorf("formal-glm: full fallback requires two noise commitments")
	}
	transcript, err := jointDPDecodeHex32(
		identity.WorkerTranscriptSHA256, "formal full worker transcript")
	if err != nil {
		return zero, err
	}
	for index, peer := range identity.DesignatedComputePeers {
		commitment := request.NoiseCommitments[index]
		context := jointDPCommitmentContext(
			transcript, jointDPGaussianCommitmentPurpose, peer)
		if commitment.PeerName != peer ||
			commitment.ContextSHA256 != hex.EncodeToString(context[:]) ||
			!formalGLMIsSHA256(commitment.SeedSHA256) {
			return zero, fmt.Errorf("formal-glm: invalid full-fallback sticky commitment")
		}
	}
	planSHA256, err := jointDPBiomedicalGaussianHash(plans.Full)
	if err != nil {
		return zero, err
	}
	contract := jointDPBiomedicalGaussianFullSelectionContract{
		Version:                   jointDPBiomedicalGaussianFullSelectionVersion,
		Backend:                   jointDPGaussianBackend,
		BackendSelection:          formalGLMPhase16BackendSelectionPolicy,
		PublicIdentifierContract:  jointDPBiomedicalGaussianPublicIdentifierRule,
		ManifestAttestationSHA256: identity.ManifestAttestationSHA256,
		CapsuleID:                 binding.CapsuleID,
		ManifestSHA256:            binding.ManifestSHA256,
		WorkloadSHA256:            binding.WorkloadSHA256,
		PinsetSHA256:              binding.PinsetSHA256,
		CustodianPeers:            append([]string(nil), selection.Contract.CustodianPeers...),
		CustodianCount:            binding.CustodianCount,
		DesignatedComputePeers: append([]string(nil),
			identity.DesignatedComputePeers...),
		LogicalReleaseSHA256:        identity.LogicalReleaseSHA256,
		PrivacyEpochSHA256:          identity.PrivacyEpochSHA256,
		LogicalSnapshotHandleSHA256: identity.LogicalSnapshotHandleSHA256,
		LogicalSnapshotHandleKind:   jointDPBiomedicalGaussianOpaqueSnapshotHandle,
		SourceContractHandleSHA256:  identity.SourceContractHandleSHA256,
		SourceContractHandleKind:    jointDPBiomedicalGaussianOpaqueSourceContract,
		MaterializationRootSHA256:   identity.MaterializationRootSHA256,
		MaterializationRootKind:     jointDPBiomedicalGaussianOpaqueSourceRoot,
		ReservationSHA256:           identity.ReservationSHA256,
		ReservationDigestKind:       jointDPBiomedicalGaussianReceiptDigestRule,
		ReleaseInstanceID:           identity.ReleaseInstanceID,
		WorkerTranscriptSHA256:      identity.WorkerTranscriptSHA256,
		Epsilon:                     binding.Epsilon, Delta: binding.AllocatedDelta,
		PlanSHA256:                   planSHA256,
		PlanRequestBindingSHA256:     plans.Full.RequestBindingSHA256,
		SensitivityCertificateSHA256: binding.SensitivityCertificateSHA256,
		RingBits:                     128, OutputLatticeBits: binding.OutputLatticeBits,
		TotalCoordinateCount:    binding.CoordinateCount,
		MaximumChunkCoordinates: plans.Full.MaximumChunkCoordinates,
		NoiseRootEpochs: append([]jointDPBiomedicalGaussianNoiseRootEpoch(nil),
			request.NoiseRootEpochs...),
		NoiseCommitments: append([]jointDPBiomedicalGaussianFullNoiseCommitment(nil),
			request.NoiseCommitments...),
		ReceiptReferences: append([]jointDPBiomedicalGaussianReceiptReference(nil),
			request.ReceiptReferences...),
		LedgerAppendBeforeReleaseReserved: true,
		ExactlyOnceFinalizerReserved:      true,
		OperationLimit:                    false, RequestLimit: false,
		HistoryCanDenyOperation: false, OpeningsAuthorized: 0,
	}
	contractDigest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianFullReleaseIdentityDomain, contract)
	if err != nil {
		return zero, err
	}
	contract.ReleaseContractSHA256 = hex.EncodeToString(contractDigest[:])
	return contract, nil
}

func formalGLMPhase16SignFullFallbackContract(
	contract jointDPBiomedicalGaussianFullSelectionContract,
	signer string, privateKey ed25519.PrivateKey,
) (jointDPBiomedicalGaussianSignature, error) {
	return jointDPBiomedicalGaussianSign(
		formalGLMPhase16FullFallbackContractDomain,
		contract, signer, privateKey)
}

func formalGLMPhase16AdmitFullFallback(
	selection formalGLMPhase16BackendSelectionAttestation,
	binding formalGLMPhase16ReleaseBinding,
	token formalGLMPhase19PostExecutionToken,
	pins map[string]ed25519.PublicKey,
	request formalGLMPhase16FullFallbackRequest,
	attestation formalGLMPhase16FullFallbackContractAttestation,
) (jointDPBiomedicalGaussianFullAdmission, error) {
	var zero jointDPBiomedicalGaussianFullAdmission
	plans, err := formalGLMPhase16ValidateBackendSelection(
		selection, binding, token, pins)
	if err != nil {
		return zero, err
	}
	expected, err := formalGLMPhase16BuildFullFallbackContract(
		selection, binding, token, pins, request)
	if err != nil {
		return zero, err
	}
	if !reflect.DeepEqual(attestation.Contract, expected) {
		return zero, fmt.Errorf("formal-glm: modified independent-full fallback contract")
	}
	message, err := jointDPBiomedicalGaussianDomainMessage(
		formalGLMPhase16FullFallbackContractDomain, expected)
	if err != nil {
		return zero, err
	}
	if err := jointDPBiomedicalGaussianVerifySignatures(
		message, attestation.Signatures, expected.CustodianPeers, pins,
		"formal GLM independent-full release contract"); err != nil {
		return zero, err
	}
	privateCertificate := jointDPBiomedicalGaussianSensitivityCertificate{
		Version: formalGLMPhase15DPSensitivityCertificateVersion,
		Kind:    binding.SensitivityCertificateKind,
		Status:  "machine_proven", Norm: "l2",
		Proof:                  binding.SensitivityProof,
		ManifestSHA256:         binding.ManifestSHA256,
		WorkloadSHA256:         binding.WorkloadSHA256,
		LatticeTransformSHA256: binding.QuantizationSHA256,
		Adjacency:              binding.Adjacency,
		CoordinateCount:        binding.CoordinateCount,
		OutputLatticeBits:      binding.OutputLatticeBits,
		SelectedBoundSteps:     binding.SensitivitySteps,
		ShiftedUpperBounds:     append([]string(nil), binding.ShiftedUpperBounds...),
		NoWrapCertificate:      binding.NoWrapCertificate,
	}
	publicCertificate := jointDPBiomedicalGaussianFullPublicCertificate(
		expected, privateCertificate, plans.Full)
	publicCertificate.BackendSelection = formalGLMPhase16BackendSelectionPolicy
	publicCertificate.SensitivityCertificateSHA256 =
		binding.SensitivityCertificateSHA256
	publicCertificate.AutomaticFallbackUsed = true
	publicCertificate.OneDrawSubstituted = true
	publicCertificate.ThreatModel = selection.Contract.SelectedThreatModel
	publicCertificate.NoWrapCertificate =
		"formal_phase15_machine_proven_bounds_plus_two_finite_noise_support_ring128_v1"
	selectionDigest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianFullSelectionDomain, expected)
	if err != nil {
		return zero, err
	}
	planSHA256, err := jointDPBiomedicalGaussianHash(plans.Full)
	if err != nil {
		return zero, err
	}
	publicSHA256, err := jointDPBiomedicalGaussianHash(publicCertificate)
	if err != nil {
		return zero, err
	}
	formalSelection := selection
	formalBinding := binding
	formalToken := token
	admission := jointDPBiomedicalGaussianFullAdmission{
		Version:                 jointDPBiomedicalGaussianFullAdmissionVersion,
		SelectionContractSHA256: hex.EncodeToString(selectionDigest[:]),
		Certificate:             publicCertificate,
		selection: jointDPBiomedicalGaussianFullSelectionAttestation{
			Contract: expected,
			Signatures: jointDPBiomedicalGaussianFullCloneSignatures(
				attestation.Signatures),
		},
		certificate:               privateCertificate,
		plan:                      plans.Full,
		manifestAttestationSHA256: expected.ManifestAttestationSHA256,
		planSHA256:                planSHA256,
		publicCertificateSHA256:   publicSHA256,
		formalSelection:           &formalSelection,
		formalBinding:             &formalBinding,
		formalToken:               &formalToken,
	}
	admission.seal, err = jointDPBiomedicalGaussianFullAdmissionSeal(admission)
	if err != nil {
		return zero, err
	}
	if err := jointDPBiomedicalGaussianValidateFullAdmissionCached(
		admission, pins); err != nil {
		return zero, err
	}
	return admission, nil
}
