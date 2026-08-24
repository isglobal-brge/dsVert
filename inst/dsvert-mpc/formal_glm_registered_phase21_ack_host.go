package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
)

const formalGLMRegisteredPhase21AckSecretFileV1 = "registered-phase21-finalizer-ack-secret.json"

func formalGLMRegisteredPhase21FinalizeAckV1(state formalGLMRegisteredPhase21StageHostStateV1) (formalGLMPhase21RockAckRecord, error) {
	var zero formalGLMPhase21RockAckRecord
	context, stagePaths, _, binding, local, ticket, _, _, _, err := formalGLMRegisteredPhase21AuthorizationStateV1(state)
	if err != nil || !formalFinalizerHandoffAuthorityEqual(local, binding.Finalizer) {
		return zero, fmt.Errorf("formal-glm registered Phase21 ACK: local finalizer unavailable")
	}
	readyPath, err := formalGLMPhase21RockPublicationReadyRecordPath(state.rockRoot, context.artifactID)
	if err != nil {
		return zero, err
	}
	var ready formalGLMPhase21RockPublicationReadyRecord
	if err := formalGLMPhase21RockReadJSON(state.rockRoot, readyPath, formalGLMPhase21RockMaxRecord, &ready); err != nil || formalGLMPhase21RockValidatePublicationReadyRecord(ready, context, binding, ticket.Ticket) != nil {
		return zero, fmt.Errorf("formal-glm registered Phase21 ACK: publication unavailable")
	}
	var commitPaths [2]string
	for index, authority := range binding.Authorities {
		if authority.PeerName == local.PeerName {
			commitPaths[index], err = formalGLMPhase21RockCommitRecordPath(state.rockRoot, context.artifactID, authority.Role)
		} else {
			commitPaths[index], err = formalGLMRegisteredPhase21CommitInboxPathV1(state.rockRoot, context.artifactID, authority.Role)
		}
		if err != nil {
			return zero, err
		}
	}
	secretPath := filepath.Join(state.rockRoot, "commands-v1", formalGLMRegisteredPhase21AckSecretFileV1)
	_, _, err = formalGLMPhase21RockWriteJSON(state.rockRoot, secretPath, formalGLMPhase21RockFinalizeAckSecret{
		Version: formalGLMPhase21RockSecretVersion, Family: formalFinalizerHandoffFamilyGLM, Purpose: formalGLMPhase21RockPurpose, Action: formalGLMPhase21RockActionFinalizeAck,
		StickyStorageRoot: base64.StdEncoding.EncodeToString(state.stickyRoot[:]), TransportStorageRoot: base64.StdEncoding.EncodeToString(state.transportRoot[:]), SigningPrivateKey: base64.StdEncoding.EncodeToString(state.signing),
	})
	if err != nil {
		return zero, err
	}
	ticketPath, err := formalGLMRegisteredPhase21TicketRecordPathV1(state, binding, local)
	if err != nil {
		return zero, err
	}
	op, err := json.Marshal(formalGLMPhase21RockFinalizeAckOperation{ArtifactContractPath: state.operation.ArtifactContractPath, PinsetPath: state.operation.PinsetPath, StageRecordPaths: stagePaths, TicketRecordPath: ticketPath, PublicationReadyRecordPath: readyPath, CommitRecordPaths: commitPaths, PeerName: local.PeerName, SecretBundlePath: secretPath})
	if err != nil {
		return zero, err
	}
	defer clear(op)
	response, err := formalGLMPhase21RockRun(state.rockRoot, false, formalGLMPhase21RockActionFinalizeAck, op)
	if err != nil || response.Ack == nil || response.State != formalGLMPhase21RockStateAckReady || response.ArtifactID != context.artifactID || response.ProductionReady {
		return zero, fmt.Errorf("formal-glm registered Phase21 ACK: lifecycle failed")
	}
	sha, err := formalGLMPhase21RockPublicCertificateDigest(ready.PublicCertificate)
	if err != nil || formalGLMPhase21RockValidateAckRecord(*response.Ack, context, binding, ticket.Ticket, sha) != nil {
		return zero, fmt.Errorf("formal-glm registered Phase21 ACK: invalid record")
	}
	encoded, err := json.Marshal(*response.Ack)
	if err != nil {
		return zero, err
	}
	defer clear(encoded)
	var clone formalGLMPhase21RockAckRecord
	if err := formalGLMPhase21RockStrictDecode(encoded, &clone); err != nil {
		return zero, err
	}
	return clone, nil
}
