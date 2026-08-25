package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
)

const formalGLMRegisteredPhase21PublicationSecretFileV1 = "registered-phase21-publication-secret.json"

func formalGLMRegisteredPhase21RunPublicationReadyV1(state formalGLMRegisteredPhase21StageHostStateV1) (formalGLMPhase21PublicCertificateV2, error) {
	var zero formalGLMPhase21PublicCertificateV2
	context, stagePaths, _, binding, local, ticket, _, candidatePath, basePath, err :=
		formalGLMRegisteredPhase21AuthorizationStateV1(state)
	if err != nil || !formalFinalizerHandoffAuthorityEqual(local, binding.Finalizer) {
		return zero, fmt.Errorf("formal-glm registered Phase21 publication: local finalizer unavailable")
	}
	var authorizationPaths [2]string
	for index, authority := range binding.Authorities {
		if authority.PeerName == local.PeerName {
			authorizationPaths[index], err = formalGLMPhase21RockAuthorizationRecordPath(state.rockRoot, context.artifactID, authority.Role)
		} else {
			authorizationPaths[index], err = formalGLMRegisteredPhase21AuthorizationInboxPathV1(state.rockRoot, context.artifactID, authority.Role)
		}
		if err != nil {
			return zero, err
		}
	}
	var base formalGLMPhase21RockBaseCertificateRecord
	if err := formalGLMPhase21RockReadJSON(state.rockRoot, basePath, formalGLMPhase21RockMaxRecord, &base); err != nil {
		return zero, err
	}
	resolution, err := formalGLMPhase21RockLoadRegistryResolution(state.rockRoot, state.operation.RegistryResolutionPath, context)
	if err != nil {
		return zero, err
	}
	var records [2]formalGLMPhase21RockAuthorizationRecord
	for index := range records {
		if err := formalGLMPhase21RockReadJSON(state.rockRoot, authorizationPaths[index], formalGLMPhase21RockMaxRecord, &records[index]); err != nil {
			return zero, err
		}
		var predecessor *formalGLMPhase21RockAuthorizationRecord
		if index == 1 {
			predecessor = &records[0]
		}
		if formalGLMPhase21RockValidateAuthorizationRecord(records[index], context, binding, ticket.Ticket, base, resolution, predecessor) != nil {
			return zero, fmt.Errorf("formal-glm registered Phase21 publication: invalid authorization pair")
		}
	}
	secretPath := filepath.Join(state.rockRoot, "commands-v1", formalGLMRegisteredPhase21PublicationSecretFileV1)
	_, _, err = formalGLMPhase21RockWriteJSON(state.rockRoot, secretPath, formalGLMPhase21RockPreparePublicationSecret{
		Version: formalGLMPhase21RockSecretVersion, Family: formalFinalizerHandoffFamilyGLM,
		Purpose: formalGLMPhase21RockPurpose, Action: formalGLMPhase21RockActionPreparePublication,
		TransportStorageRoot: base64.StdEncoding.EncodeToString(state.transportRoot[:]),
		SigningPrivateKey:    base64.StdEncoding.EncodeToString(state.signing),
	})
	if err != nil {
		return zero, err
	}
	ticketPath, err := formalGLMRegisteredPhase21TicketRecordPathV1(state, binding, local)
	if err != nil {
		return zero, err
	}
	operation, err := json.Marshal(formalGLMPhase21RockPreparePublicationOperation{
		ArtifactContractPath: state.operation.ArtifactContractPath, PinsetPath: state.operation.PinsetPath,
		RegistryResolutionPath: state.operation.RegistryResolutionPath, PreflightRecordPaths: state.operation.PreflightRecordPaths,
		StageRecordPaths: stagePaths, TicketRecordPath: ticketPath, CandidateRecordPath: candidatePath,
		BaseCertificateRecordPath: basePath, AuthorizationRecordPaths: authorizationPaths,
		PeerName: local.PeerName, SecretBundlePath: secretPath,
	})
	if err != nil {
		return zero, err
	}
	defer clear(operation)
	response, err := formalGLMPhase21RockRun(state.rockRoot, false, formalGLMPhase21RockActionPreparePublication, operation)
	if err != nil || response.Publication == nil || response.State != formalGLMPhase21RockStatePublicationReady || response.ArtifactID != context.artifactID || response.ProductionReady {
		return zero, fmt.Errorf("formal-glm registered Phase21 publication: lifecycle failed")
	}
	recordPath, err := formalGLMPhase21RockPublicationReadyRecordPath(state.rockRoot, context.artifactID)
	if err != nil {
		return zero, err
	}
	var record formalGLMPhase21RockPublicationReadyRecord
	if err := formalGLMPhase21RockReadJSON(state.rockRoot, recordPath, formalGLMPhase21RockMaxRecord, &record); err != nil ||
		formalGLMPhase21RockValidatePublicationReadyRecord(record, context, binding, ticket.Ticket) != nil {
		return zero, fmt.Errorf("formal-glm registered Phase21 publication: durable record unavailable")
	}
	encoded, err := json.Marshal(record.PublicCertificate)
	if err != nil {
		return zero, err
	}
	defer clear(encoded)
	var cloned formalGLMPhase21PublicCertificateV2
	if err := formalGLMPhase21RockStrictDecode(encoded, &cloned); err != nil {
		return zero, err
	}
	return cloned, nil
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) RunPhase21PublicationV1() (
	formalGLMPhase21PublicCertificateV2, error,
) {
	owner, done, err := host.beginOpV1()
	if err != nil {
		return formalGLMPhase21PublicCertificateV2{}, err
	}
	defer done()
	state, err := host.phase21StageStateV1(owner)
	if err != nil {
		return formalGLMPhase21PublicCertificateV2{}, err
	}
	defer state.clearV1()
	return formalGLMRegisteredPhase21RunPublicationReadyV1(state)
}
