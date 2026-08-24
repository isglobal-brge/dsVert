package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
)

const formalGLMRegisteredPhase21CleanupSecretFileV1 = "registered-phase21-cleanup-secret.json"

func formalGLMRegisteredPhase21AckInboxPathV1(root, artifactID string) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || !formalGLMIsSHA256(artifactID) {
		return "", fmt.Errorf("formal-glm registered Phase21 cleanup: invalid ACK inbox")
	}
	return filepath.Join(root, "inbox-v1", "ack-"+artifactID+".json"), nil
}

func formalGLMRegisteredPhase21CleanupInboxPathV1(root, artifactID, role string) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || !formalGLMIsSHA256(artifactID) || (role != "garbler" && role != "evaluator") {
		return "", fmt.Errorf("formal-glm registered Phase21 cleanup: invalid inbox")
	}
	return filepath.Join(root, "inbox-v1", "cleanup-"+role+".json"), nil
}

func formalGLMRegisteredPhase21ImportPeerCleanupV1(state formalGLMRegisteredPhase21StageHostStateV1, record formalGLMPhase21RockCleanupRecord) error {
	context, _, _, _, local, _, _, _, _, err := formalGLMRegisteredPhase21AuthorizationStateV1(state)
	if err != nil || record.Receipt.PeerName == local.PeerName {
		return fmt.Errorf("formal-glm registered Phase21 cleanup: invalid peer record")
	}
	peer, peerErr := formalGLMPhase21RockAuthority(context.contract.Artifact, record.Receipt.PeerName)
	if peerErr != nil || formalGLMPhase21RockValidateCleanupRecord(record, context, peer) != nil {
		return fmt.Errorf("formal-glm registered Phase21 cleanup: invalid peer record")
	}
	path, err := formalGLMRegisteredPhase21CleanupInboxPathV1(state.rockRoot, context.artifactID, record.Receipt.Role)
	if err != nil {
		return err
	}
	_, _, err = formalGLMPhase21RockWriteJSON(state.rockRoot, path, record)
	return err
}

func formalGLMRegisteredPhase21ImportPeerAckV1(state formalGLMRegisteredPhase21StageHostStateV1, record formalGLMPhase21RockAckRecord, publication formalGLMPhase21PublicCertificateV2) error {
	context, _, _, binding, local, ticket, _, _, _, err := formalGLMRegisteredPhase21AuthorizationStateV1(state)
	sha, shaErr := formalGLMPhase21RockPublicCertificateDigest(publication)
	if err != nil || shaErr != nil || formalFinalizerHandoffAuthorityEqual(local, binding.Finalizer) || formalGLMPhase21RockValidateAckRecord(record, context, binding, ticket.Ticket, sha) != nil {
		return fmt.Errorf("formal-glm registered Phase21 cleanup: invalid peer ACK")
	}
	path, err := formalGLMRegisteredPhase21AckInboxPathV1(state.rockRoot, context.artifactID)
	if err != nil {
		return err
	}
	_, _, err = formalGLMPhase21RockWriteJSON(state.rockRoot, path, record)
	return err
}

func formalGLMRegisteredPhase21CleanupAfterAckV1(state formalGLMRegisteredPhase21StageHostStateV1, publication formalGLMPhase21PublicCertificateV2) (formalGLMPhase21RockCleanupRecord, error) {
	var zero formalGLMPhase21RockCleanupRecord
	context, stagePaths, _, binding, local, _, _, _, _, err := formalGLMRegisteredPhase21AuthorizationStateV1(state)
	if err != nil || formalGLMPhase21ValidatePublicCertificateV2(publication, context.pins) != nil || publication.ArtifactID != context.artifactID {
		return zero, fmt.Errorf("formal-glm registered Phase21 cleanup: invalid publication")
	}
	commitPath, err := formalGLMPhase21RockCommitRecordPath(state.rockRoot, context.artifactID, local.Role)
	if err != nil {
		return zero, err
	}
	ackPath := ""
	if formalFinalizerHandoffAuthorityEqual(local, binding.Finalizer) {
		ackPath, err = formalGLMPhase21RockAckRecordPath(state.rockRoot, context.artifactID)
	} else {
		ackPath, err = formalGLMRegisteredPhase21AckInboxPathV1(state.rockRoot, context.artifactID)
	}
	if err != nil {
		return zero, err
	}
	secretPath := filepath.Join(state.rockRoot, "commands-v1", formalGLMRegisteredPhase21CleanupSecretFileV1)
	_, _, err = formalGLMPhase21RockWriteJSON(state.rockRoot, secretPath, formalGLMPhase21RockAckSecret{Version: formalGLMPhase21RockSecretVersion, Family: formalFinalizerHandoffFamilyGLM, Purpose: formalGLMPhase21RockPurpose, Action: formalGLMPhase21RockActionAck, StickyStorageRoot: base64.StdEncoding.EncodeToString(state.stickyRoot[:]), Phase20StorageRoot: base64.StdEncoding.EncodeToString(state.phase20StorageRoot[:]), BackendKey: base64.StdEncoding.EncodeToString(state.backendKey[:]), TransportStorageRoot: base64.StdEncoding.EncodeToString(state.transportRoot[:]), SigningPrivateKey: base64.StdEncoding.EncodeToString(state.signing)})
	if err != nil {
		return zero, err
	}
	ticketPath, err := formalGLMRegisteredPhase21TicketRecordPathV1(state, binding, local)
	if err != nil {
		return zero, err
	}
	op, err := json.Marshal(formalGLMPhase21RockAckOperation{ArtifactContractPath: state.operation.ArtifactContractPath, PinsetPath: state.operation.PinsetPath, RegistryResolutionPath: state.operation.RegistryResolutionPath, StageRecordPaths: stagePaths, TicketRecordPath: ticketPath, CommitRecordPath: commitPath, AckRecordPath: ackPath, PeerName: local.PeerName, Publication: publication, Phase20SemanticRootSHA256: state.semanticRoot, CapsulePath: state.operation.CapsulePath, RequestPath: state.operation.RequestPath, BackendSignaturesPath: state.operation.BackendSignaturesPath, WorkerSignaturesPath: state.operation.WorkerSignaturesPath, SecretBundlePath: secretPath})
	if err != nil {
		return zero, err
	}
	defer clear(op)
	response, err := formalGLMPhase21RockRun(state.rockRoot, false, formalGLMPhase21RockActionAck, op)
	if err != nil || response.Cleanup == nil || response.State != formalGLMPhase21RockStateCleaned || response.ProductionReady || formalGLMPhase21RockValidateCleanupRecord(*response.Cleanup, context, local) != nil {
		return zero, fmt.Errorf("formal-glm registered Phase21 cleanup: lifecycle failed")
	}
	encoded, err := json.Marshal(*response.Cleanup)
	if err != nil {
		return zero, err
	}
	defer clear(encoded)
	var clone formalGLMPhase21RockCleanupRecord
	if err := formalGLMPhase21RockStrictDecode(encoded, &clone); err != nil {
		return zero, err
	}
	return clone, nil
}
