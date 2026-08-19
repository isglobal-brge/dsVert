package main

import (
	"crypto/ed25519"
	"fmt"
	"reflect"
)

// formalGLMPhase21RockLoadPublicTerminalEvidenceV1 rehydrates a completed
// Phase21 release exclusively from the immutable owner-only Rock records. A
// caller receives evidence only after both authorities have staged, committed,
// acknowledged, and cleaned the exact same public certificate.
func formalGLMPhase21RockLoadPublicTerminalEvidenceV1(
	root string,
	contract formalGLMPhase21SamplerV2Contract,
	pins map[string]ed25519.PublicKey,
	resolution formalGLMArtifactRegistryResolutionV1,
) (formalGLMPublicTerminalEvidenceV1, error) {
	var zero formalGLMPublicTerminalEvidenceV1
	if formalGLMPhase21ValidateSamplerV2Contract(contract, pins) != nil ||
		resolution.ArtifactID != contract.ArtifactID ||
		formalGLMValidatePublicDescriptorAgainstArtifactV1(
			resolution.Descriptor, contract.Artifact) != nil {
		return zero, fmt.Errorf("formal-glm lifecycle: invalid public terminal context")
	}
	context := formalGLMPhase21RockContext{
		contract: contract, pins: pins, artifactID: contract.ArtifactID,
	}
	var stagePaths [2]string
	var commitPaths [2]string
	var cleanupPaths [2]string
	for index, authority := range contract.Artifact.NoiseAuthorities {
		var err error
		stagePaths[index], err = formalGLMPhase21RockStageRecordPath(
			root, contract.ArtifactID, authority.Role)
		if err != nil {
			return zero, err
		}
		commitPaths[index], err = formalGLMPhase21RockCommitRecordPath(
			root, contract.ArtifactID, authority.Role)
		if err != nil {
			return zero, err
		}
		cleanupPaths[index], err = formalGLMPhase21RockCleanupRecordPath(
			root, contract.ArtifactID, authority.Role)
		if err != nil {
			return zero, err
		}
	}
	_, binding, err := formalGLMPhase21RockLoadStagePair(root, stagePaths, context)
	if err != nil {
		return zero, err
	}
	ticketPath, err := formalGLMPhase21RockTicketRecordPath(root, contract.ArtifactID)
	if err != nil {
		return zero, err
	}
	var ticketRecord formalGLMPhase21RockTicketRecord
	if err := formalGLMPhase21RockReadJSON(
		root, ticketPath, formalGLMPhase21RockMaxRecord, &ticketRecord); err != nil ||
		formalGLMPhase21RockValidateTicketRecord(ticketRecord, context) != nil ||
		!reflect.DeepEqual(ticketRecord.Binding, binding) {
		return zero, fmt.Errorf("formal-glm lifecycle: invalid terminal ticket")
	}

	var first formalGLMPhase21RockCommitRecord
	firstAuthority := contract.Artifact.NoiseAuthorities[0]
	firstLocal := formalFinalizerHandoffAuthority{
		PeerName: firstAuthority.PeerName, PeerID: firstAuthority.PeerID,
		Role: firstAuthority.Role,
	}
	if err := formalGLMPhase21RockReadJSON(
		root, commitPaths[0], formalGLMPhase21RockMaxRecord, &first); err != nil ||
		formalGLMPhase21RockValidateCommitRecord(first, context, firstLocal) != nil {
		return zero, fmt.Errorf("formal-glm lifecycle: invalid terminal commit")
	}
	certificateSHA256, err := formalGLMPhase21RockPublicCertificateDigest(first.Publication)
	if err != nil {
		return zero, err
	}
	commits, err := formalGLMPhase21RockLoadCommitPair(
		root, commitPaths, context, certificateSHA256)
	if err != nil {
		return zero, err
	}
	publication := commits[0].Publication
	if !reflect.DeepEqual(commits[1].Publication, publication) ||
		publication.PublicDescriptor == nil ||
		!reflect.DeepEqual(*publication.PublicDescriptor, resolution.Descriptor) {
		return zero, fmt.Errorf("formal-glm lifecycle: terminal publication differs")
	}
	ackPath, err := formalGLMPhase21RockAckRecordPath(root, contract.ArtifactID)
	if err != nil {
		return zero, err
	}
	var ack formalGLMPhase21RockAckRecord
	if err := formalGLMPhase21RockReadJSON(
		root, ackPath, formalGLMPhase21RockMaxRecord, &ack); err != nil ||
		formalGLMPhase21RockValidateAckRecord(
			ack, context, binding, ticketRecord.Ticket, certificateSHA256) != nil {
		return zero, fmt.Errorf("formal-glm lifecycle: invalid terminal ACK")
	}
	var cleanups [2]formalGLMPhase21RockCleanupRecord
	for index, authority := range contract.Artifact.NoiseAuthorities {
		local := formalFinalizerHandoffAuthority{
			PeerName: authority.PeerName, PeerID: authority.PeerID,
			Role: authority.Role,
		}
		if err := formalGLMPhase21RockReadJSON(
			root, cleanupPaths[index], formalGLMPhase21RockMaxRecord,
			&cleanups[index]); err != nil ||
			formalGLMPhase21RockValidateCleanupRecord(
				cleanups[index], context, local) != nil ||
			!reflect.DeepEqual(cleanups[index].Publication, publication) {
			return zero, fmt.Errorf("formal-glm lifecycle: invalid terminal cleanup")
		}
	}
	return formalGLMPublicTerminalEvidenceV1{
		Contract: contract, Binding: binding, Ticket: ticketRecord.Ticket,
		Publication: publication, Commits: commits, Ack: ack, Cleanups: cleanups,
	}, nil
}
