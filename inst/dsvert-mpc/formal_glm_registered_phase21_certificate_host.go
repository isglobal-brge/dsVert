package main

// The finalizer turns the two independently verified local releases into one
// signed base certificate.  The generic Rock action does the protected
// reconstruction; this bridge only fixes durable paths and peer import.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
)

const formalGLMRegisteredPhase21CertificateSecretFileV1 = "registered-phase21-certificate-secret.json"

func formalGLMRegisteredPhase21BaseCertificateInboxPathV1(
	root, artifactID string,
) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		!formalGLMIsSHA256(artifactID) {
		return "", fmt.Errorf("formal-glm registered Phase21 certificate: invalid inbox")
	}
	return filepath.Join(root, "inbox-v1", "base-certificate-"+artifactID+".json"), nil
}

func formalGLMRegisteredPhase21CertificateStateV1(
	state formalGLMRegisteredPhase21StageHostStateV1,
) (formalGLMPhase21RockContext, [2]string, [2]string,
	formalFinalizerHandoffBinding, formalFinalizerHandoffAuthority,
	formalGLMPhase21RockTicketRecord, formalGLMPhase21RockCandidateRecord,
	string, error) {
	var zeroContext formalGLMPhase21RockContext
	var zeroStagePaths, zeroReleasePaths [2]string
	var zeroBinding formalFinalizerHandoffBinding
	var zeroAuthority formalFinalizerHandoffAuthority
	var zeroTicket formalGLMPhase21RockTicketRecord
	var zeroCandidate formalGLMPhase21RockCandidateRecord
	context, stagePaths, binding, local, ticket, candidate, candidatePath, err :=
		formalGLMRegisteredPhase21VerifyStateV1(state)
	if err != nil {
		return zeroContext, zeroStagePaths, zeroReleasePaths, zeroBinding,
			zeroAuthority, zeroTicket, zeroCandidate, "", err
	}
	var releasePaths [2]string
	for index, authority := range binding.Authorities {
		if authority.PeerName == local.PeerName {
			releasePaths[index], err = formalGLMPhase21RockLocalReleaseRecordPath(
				state.rockRoot, context.artifactID, authority.Role)
		} else {
			releasePaths[index], err = formalGLMRegisteredPhase21LocalReleaseInboxPathV1(
				state.rockRoot, context.artifactID, authority.Role)
		}
		if err != nil {
			return zeroContext, zeroStagePaths, zeroReleasePaths, zeroBinding,
				zeroAuthority, zeroTicket, zeroCandidate, "", err
		}
	}
	if _, err := formalGLMPhase21RockLoadLocalReleasePair(
		state.rockRoot, releasePaths, context, binding, ticket.Ticket, candidate); err != nil {
		return zeroContext, zeroStagePaths, zeroReleasePaths, zeroBinding,
			zeroAuthority, zeroTicket, zeroCandidate, "",
			fmt.Errorf("formal-glm registered Phase21 certificate: signed local-release pair unavailable")
	}
	return context, stagePaths, releasePaths, binding, local, ticket, candidate,
		candidatePath, nil
}

func formalGLMRegisteredPhase21CloneBaseCertificateV1(
	record formalGLMPhase21RockBaseCertificateRecord,
) (formalGLMPhase21RockBaseCertificateRecord, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return formalGLMPhase21RockBaseCertificateRecord{}, err
	}
	defer clear(encoded)
	var cloned formalGLMPhase21RockBaseCertificateRecord
	if err := formalGLMPhase21RockStrictDecode(encoded, &cloned); err != nil {
		return formalGLMPhase21RockBaseCertificateRecord{}, err
	}
	return cloned, nil
}

func formalGLMRegisteredPhase21RunBaseCertificateV1(
	state formalGLMRegisteredPhase21StageHostStateV1,
) (formalGLMPhase21RockBaseCertificateRecord, error) {
	var zero formalGLMPhase21RockBaseCertificateRecord
	context, stagePaths, releasePaths, binding, local, ticket, candidate, candidatePath, err :=
		formalGLMRegisteredPhase21CertificateStateV1(state)
	if err != nil || !formalFinalizerHandoffAuthorityEqual(local, binding.Finalizer) {
		return zero, fmt.Errorf("formal-glm registered Phase21 certificate: local finalizer unavailable")
	}
	secretPath := filepath.Join(state.rockRoot, "commands-v1",
		formalGLMRegisteredPhase21CertificateSecretFileV1)
	_, _, err = formalGLMPhase21RockWriteJSON(state.rockRoot, secretPath,
		formalGLMPhase21RockPrepareCertificateSecret{
			Version:              formalGLMPhase21RockSecretVersion,
			Family:               formalFinalizerHandoffFamilyGLM,
			Purpose:              formalGLMPhase21RockPurpose,
			Action:               formalGLMPhase21RockActionPrepareCertificate,
			Phase20StorageRoot:   base64.StdEncoding.EncodeToString(state.phase20StorageRoot[:]),
			BackendKey:           base64.StdEncoding.EncodeToString(state.backendKey[:]),
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
	operation, err := json.Marshal(formalGLMPhase21RockPrepareCertificateOperation{
		ArtifactContractPath:      state.operation.ArtifactContractPath,
		PinsetPath:                state.operation.PinsetPath,
		RegistryResolutionPath:    state.operation.RegistryResolutionPath,
		PreflightRecordPaths:      state.operation.PreflightRecordPaths,
		StageRecordPaths:          stagePaths,
		TicketRecordPath:          ticketPath,
		CandidateRecordPath:       candidatePath,
		LocalReleaseRecordPaths:   releasePaths,
		PeerName:                  local.PeerName,
		Phase20SemanticRootSHA256: state.semanticRoot,
		CapsulePath:               state.operation.CapsulePath,
		RequestPath:               state.operation.RequestPath,
		BackendSignaturesPath:     state.operation.BackendSignaturesPath,
		WorkerSignaturesPath:      state.operation.WorkerSignaturesPath,
		SecretBundlePath:          secretPath,
	})
	if err != nil {
		return zero, err
	}
	defer clear(operation)
	response, err := formalGLMPhase21RockRun(
		state.rockRoot, false, formalGLMPhase21RockActionPrepareCertificate, operation)
	if err != nil || response.BaseCertificate == nil ||
		response.State != formalGLMPhase21RockStateCertificateReady ||
		response.ArtifactID != context.artifactID || response.ProductionReady ||
		formalGLMPhase21RockValidateBaseCertificateRecord(
			*response.BaseCertificate, context, binding, ticket.Ticket, candidate) != nil {
		return zero, fmt.Errorf("formal-glm registered Phase21 certificate: lifecycle failed")
	}
	return formalGLMRegisteredPhase21CloneBaseCertificateV1(*response.BaseCertificate)
}

func formalGLMRegisteredPhase21ImportPeerBaseCertificateV1(
	state formalGLMRegisteredPhase21StageHostStateV1,
	record formalGLMPhase21RockBaseCertificateRecord,
) error {
	context, _, _, binding, local, ticket, candidate, _, err :=
		formalGLMRegisteredPhase21CertificateStateV1(state)
	if err != nil || formalFinalizerHandoffAuthorityEqual(local, binding.Finalizer) ||
		formalGLMPhase21RockValidateBaseCertificateRecord(
			record, context, binding, ticket.Ticket, candidate) != nil {
		return fmt.Errorf("formal-glm registered Phase21 certificate: invalid peer record")
	}
	path, err := formalGLMRegisteredPhase21BaseCertificateInboxPathV1(
		state.rockRoot, context.artifactID)
	if err != nil {
		return err
	}
	_, _, err = formalGLMPhase21RockWriteJSON(state.rockRoot, path, record)
	return err
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) RunPhase21BaseCertificateV1() (
	formalGLMPhase21RockBaseCertificateRecord, error,
) {
	owner, done, err := host.beginOpV1()
	if err != nil {
		return formalGLMPhase21RockBaseCertificateRecord{}, err
	}
	defer done()
	state, err := host.phase21StageStateV1(owner)
	if err != nil {
		return formalGLMPhase21RockBaseCertificateRecord{}, err
	}
	defer state.clearV1()
	return formalGLMRegisteredPhase21RunBaseCertificateV1(state)
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) ImportPhase21PeerBaseCertificateV1(
	record formalGLMPhase21RockBaseCertificateRecord,
) error {
	owner, done, err := host.beginOpV1()
	if err != nil {
		return err
	}
	defer done()
	state, err := host.phase21StageStateV1(owner)
	if err != nil {
		return err
	}
	defer state.clearV1()
	return formalGLMRegisteredPhase21ImportPeerBaseCertificateV1(state, record)
}
