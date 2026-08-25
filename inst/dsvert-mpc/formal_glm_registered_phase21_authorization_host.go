package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
)

const formalGLMRegisteredPhase21AuthorizationSecretFileV1 = "registered-phase21-authorization-secret.json"

func formalGLMRegisteredPhase21AuthorizationInboxPathV1(root, artifactID, role string) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || !formalGLMIsSHA256(artifactID) ||
		(role != "garbler" && role != "evaluator") {
		return "", fmt.Errorf("formal-glm registered Phase21 authorization: invalid inbox")
	}
	return filepath.Join(root, "inbox-v1", "authorization-"+role+".json"), nil
}

func formalGLMRegisteredPhase21AuthorizationStateV1(state formalGLMRegisteredPhase21StageHostStateV1) (
	formalGLMPhase21RockContext, [2]string, [2]string, formalFinalizerHandoffBinding,
	formalFinalizerHandoffAuthority, formalGLMPhase21RockTicketRecord,
	formalGLMPhase21RockCandidateRecord, string, string, error,
) {
	var zeroContext formalGLMPhase21RockContext
	var zeroStage, zeroRelease [2]string
	var zeroBinding formalFinalizerHandoffBinding
	var zeroAuthority formalFinalizerHandoffAuthority
	var zeroTicket formalGLMPhase21RockTicketRecord
	var zeroCandidate formalGLMPhase21RockCandidateRecord
	context, stagePaths, releasePaths, binding, local, ticket, candidate, candidatePath, err :=
		formalGLMRegisteredPhase21CertificateStateV1(state)
	if err != nil {
		return zeroContext, zeroStage, zeroRelease, zeroBinding, zeroAuthority, zeroTicket, zeroCandidate, "", "", err
	}
	basePath := ""
	if formalFinalizerHandoffAuthorityEqual(local, binding.Finalizer) {
		basePath, err = formalGLMPhase21RockBaseCertificateRecordPath(state.rockRoot, context.artifactID)
	} else {
		basePath, err = formalGLMRegisteredPhase21BaseCertificateInboxPathV1(state.rockRoot, context.artifactID)
	}
	if err != nil {
		return zeroContext, zeroStage, zeroRelease, zeroBinding, zeroAuthority, zeroTicket, zeroCandidate, "", "", err
	}
	var base formalGLMPhase21RockBaseCertificateRecord
	if err := formalGLMPhase21RockReadJSON(state.rockRoot, basePath, formalGLMPhase21RockMaxRecord, &base); err != nil ||
		formalGLMPhase21RockValidateBaseCertificateRecord(base, context, binding, ticket.Ticket, candidate) != nil {
		return zeroContext, zeroStage, zeroRelease, zeroBinding, zeroAuthority, zeroTicket, zeroCandidate, "", "",
			fmt.Errorf("formal-glm registered Phase21 authorization: base certificate unavailable")
	}
	return context, stagePaths, releasePaths, binding, local, ticket, candidate, candidatePath, basePath, nil
}

func formalGLMRegisteredPhase21CloneAuthorizationV1(record formalGLMPhase21RockAuthorizationRecord) (formalGLMPhase21RockAuthorizationRecord, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return formalGLMPhase21RockAuthorizationRecord{}, err
	}
	defer clear(encoded)
	var cloned formalGLMPhase21RockAuthorizationRecord
	if err := formalGLMPhase21RockStrictDecode(encoded, &cloned); err != nil {
		return formalGLMPhase21RockAuthorizationRecord{}, err
	}
	return cloned, nil
}

func formalGLMRegisteredPhase21ReadAuthorizationV1(root, path string, context formalGLMPhase21RockContext,
	binding formalFinalizerHandoffBinding, ticket formalGLMPhase21RockTicketRecord, candidate formalGLMPhase21RockCandidateRecord,
	base formalGLMPhase21RockBaseCertificateRecord, resolution *formalGLMArtifactRegistryResolutionV1,
	predecessor *formalGLMPhase21RockAuthorizationRecord,
) (formalGLMPhase21RockAuthorizationRecord, error) {
	var record formalGLMPhase21RockAuthorizationRecord
	if err := formalGLMPhase21RockReadJSON(root, path, formalGLMPhase21RockMaxRecord, &record); err != nil ||
		formalGLMPhase21RockValidateAuthorizationRecord(record, context, binding, ticket.Ticket, base, resolution, predecessor) != nil {
		return formalGLMPhase21RockAuthorizationRecord{}, fmt.Errorf("formal-glm registered Phase21 authorization: unavailable")
	}
	return record, nil
}

func formalGLMRegisteredPhase21SignAuthorizationV1(state formalGLMRegisteredPhase21StageHostStateV1) (formalGLMPhase21RockAuthorizationRecord, error) {
	var zero formalGLMPhase21RockAuthorizationRecord
	context, stagePaths, releasePaths, binding, local, ticket, candidate, candidatePath, basePath, err :=
		formalGLMRegisteredPhase21AuthorizationStateV1(state)
	if err != nil {
		return zero, err
	}
	resolution, err := formalGLMPhase21RockLoadRegistryResolution(
		state.rockRoot, state.operation.RegistryResolutionPath, context)
	if err != nil {
		return zero, err
	}
	var base formalGLMPhase21RockBaseCertificateRecord
	if err := formalGLMPhase21RockReadJSON(state.rockRoot, basePath, formalGLMPhase21RockMaxRecord, &base); err != nil {
		return zero, err
	}
	var predecessorPath *string
	var predecessor *formalGLMPhase21RockAuthorizationRecord
	if local.Role == "evaluator" {
		path, pathErr := formalGLMRegisteredPhase21AuthorizationInboxPathV1(state.rockRoot, context.artifactID, "garbler")
		if pathErr != nil {
			return zero, pathErr
		}
		value, valueErr := formalGLMRegisteredPhase21ReadAuthorizationV1(state.rockRoot, path, context, binding, ticket, candidate, base, resolution, nil)
		if valueErr != nil || value.Role != "garbler" {
			return zero, fmt.Errorf("formal-glm registered Phase21 authorization: garbler authorization unavailable")
		}
		predecessorPath, predecessor = &path, &value
	} else if local.Role != "garbler" {
		return zero, fmt.Errorf("formal-glm registered Phase21 authorization: invalid local role")
	}
	secretPath := filepath.Join(state.rockRoot, "commands-v1", formalGLMRegisteredPhase21AuthorizationSecretFileV1)
	_, _, err = formalGLMPhase21RockWriteJSON(state.rockRoot, secretPath, formalGLMPhase21RockSignCertificateSecret{
		Version: formalGLMPhase21RockSecretVersion, Family: formalFinalizerHandoffFamilyGLM,
		Purpose: formalGLMPhase21RockPurpose, Action: formalGLMPhase21RockActionSignCertificate,
		StickyStorageRoot:    base64.StdEncoding.EncodeToString(state.stickyRoot[:]),
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
	operation, err := json.Marshal(formalGLMPhase21RockSignCertificateOperation{
		ArtifactContractPath: state.operation.ArtifactContractPath, PinsetPath: state.operation.PinsetPath,
		RegistryResolutionPath: state.operation.RegistryResolutionPath, PreflightRecordPaths: state.operation.PreflightRecordPaths,
		StageRecordPaths: stagePaths, TicketRecordPath: ticketPath, CandidateRecordPath: candidatePath,
		LocalReleaseRecordPaths: releasePaths, BaseCertificateRecordPath: basePath,
		PredecessorAuthorizationPath: predecessorPath, PeerName: local.PeerName,
		Phase20SemanticRootSHA256: state.semanticRoot, CapsulePath: state.operation.CapsulePath,
		RequestPath: state.operation.RequestPath, BackendSignaturesPath: state.operation.BackendSignaturesPath,
		WorkerSignaturesPath: state.operation.WorkerSignaturesPath, SecretBundlePath: secretPath,
	})
	if err != nil {
		return zero, err
	}
	defer clear(operation)
	response, err := formalGLMPhase21RockRun(state.rockRoot, false, formalGLMPhase21RockActionSignCertificate, operation)
	if err != nil || response.Authorization == nil || response.State != formalGLMPhase21RockStateAuthorized || response.ArtifactID != context.artifactID || response.ProductionReady ||
		formalGLMPhase21RockValidateAuthorizationRecord(*response.Authorization, context, binding, ticket.Ticket, base, resolution, predecessor) != nil || response.Authorization.Role != local.Role {
		return zero, fmt.Errorf("formal-glm registered Phase21 authorization: lifecycle failed")
	}
	return formalGLMRegisteredPhase21CloneAuthorizationV1(*response.Authorization)
}

func formalGLMRegisteredPhase21ImportPeerAuthorizationV1(state formalGLMRegisteredPhase21StageHostStateV1, record formalGLMPhase21RockAuthorizationRecord) error {
	context, _, _, binding, local, ticket, candidate, _, basePath, err := formalGLMRegisteredPhase21AuthorizationStateV1(state)
	if err != nil || record.Role == local.Role {
		return fmt.Errorf("formal-glm registered Phase21 authorization: invalid peer record")
	}
	resolution, err := formalGLMPhase21RockLoadRegistryResolution(
		state.rockRoot, state.operation.RegistryResolutionPath, context)
	if err != nil {
		return err
	}
	var base formalGLMPhase21RockBaseCertificateRecord
	if err := formalGLMPhase21RockReadJSON(state.rockRoot, basePath, formalGLMPhase21RockMaxRecord, &base); err != nil {
		return fmt.Errorf("formal-glm registered Phase21 authorization: unavailable")
	}
	var predecessor *formalGLMPhase21RockAuthorizationRecord
	if record.Role == "evaluator" {
		path, pathErr := formalGLMPhase21RockAuthorizationRecordPath(state.rockRoot, context.artifactID, "garbler")
		if pathErr != nil {
			return pathErr
		}
		value, valueErr := formalGLMRegisteredPhase21ReadAuthorizationV1(state.rockRoot, path, context, binding, ticket, candidate, base, resolution, nil)
		if valueErr != nil {
			return valueErr
		}
		predecessor = &value
	}
	if formalGLMPhase21RockValidateAuthorizationRecord(record, context, binding, ticket.Ticket, base, resolution, predecessor) != nil {
		return fmt.Errorf("formal-glm registered Phase21 authorization: invalid peer record")
	}
	path, err := formalGLMRegisteredPhase21AuthorizationInboxPathV1(state.rockRoot, context.artifactID, record.Role)
	if err != nil {
		return err
	}
	_, _, err = formalGLMPhase21RockWriteJSON(state.rockRoot, path, record)
	return err
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) RunPhase21AuthorizationV1() (
	formalGLMPhase21RockAuthorizationRecord, error,
) {
	owner, done, err := host.beginOpV1()
	if err != nil {
		return formalGLMPhase21RockAuthorizationRecord{}, err
	}
	defer done()
	state, err := host.phase21StageStateV1(owner)
	if err != nil {
		return formalGLMPhase21RockAuthorizationRecord{}, err
	}
	defer state.clearV1()
	return formalGLMRegisteredPhase21SignAuthorizationV1(state)
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) ImportPhase21PeerAuthorizationV1(
	record formalGLMPhase21RockAuthorizationRecord,
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
	return formalGLMRegisteredPhase21ImportPeerAuthorizationV1(state, record)
}
