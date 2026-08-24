package main

// Candidate is finalizer-only.  The generic Rock action owns the one-draw
// reconstruction and signs the common release; this bridge supplies its
// already-authenticated local inputs and carries the signed record to the
// other designated authority.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
)

const formalGLMRegisteredPhase21CandidateSecretFileV1 = "registered-phase21-candidate-secret.json"

func formalGLMRegisteredPhase21CandidateInboxPathV1(root, artifactID string) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		!formalGLMIsSHA256(artifactID) {
		return "", fmt.Errorf("formal-glm registered Phase21 candidate: invalid inbox")
	}
	return filepath.Join(root, "inbox-v1", "candidate-"+artifactID+".json"), nil
}

func formalGLMRegisteredPhase21CandidateStateV1(
	state formalGLMRegisteredPhase21StageHostStateV1,
) (formalGLMPhase21RockContext, [2]string, [2]string,
	formalFinalizerHandoffBinding, formalFinalizerHandoffAuthority,
	formalGLMPhase21RockTicketRecord, error) {
	var zeroContext formalGLMPhase21RockContext
	var zeroStagePaths, zeroSealPaths [2]string
	var zeroBinding formalFinalizerHandoffBinding
	var zeroAuthority formalFinalizerHandoffAuthority
	var zeroTicket formalGLMPhase21RockTicketRecord
	context, stagePaths, binding, local, ticket, err :=
		formalGLMRegisteredPhase21SealStateV1(state)
	if err != nil {
		return zeroContext, zeroStagePaths, zeroSealPaths, zeroBinding,
			zeroAuthority, zeroTicket, err
	}
	var sealPaths [2]string
	for index, authority := range binding.Authorities {
		if authority.PeerName == local.PeerName {
			sealPaths[index], err = formalGLMPhase21RockSealRecordPath(
				state.rockRoot, context.artifactID, authority.Role)
		} else {
			sealPaths[index], err = formalGLMRegisteredPhase21SealInboxPathV1(
				state.rockRoot, context.artifactID, authority.Role)
		}
		if err != nil {
			return zeroContext, zeroStagePaths, zeroSealPaths, zeroBinding,
				zeroAuthority, zeroTicket, err
		}
	}
	if _, err := formalGLMPhase21RockLoadSealPair(
		state.rockRoot, sealPaths, context, binding, ticket.Ticket); err != nil {
		return zeroContext, zeroStagePaths, zeroSealPaths, zeroBinding,
			zeroAuthority, zeroTicket,
			fmt.Errorf("formal-glm registered Phase21 candidate: signed seal pair unavailable")
	}
	return context, stagePaths, sealPaths, binding, local, ticket, nil
}

func formalGLMRegisteredPhase21CloneCandidateV1(
	record formalGLMPhase21RockCandidateRecord,
) (formalGLMPhase21RockCandidateRecord, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return formalGLMPhase21RockCandidateRecord{}, err
	}
	defer clear(encoded)
	var cloned formalGLMPhase21RockCandidateRecord
	if err := formalGLMPhase21RockStrictDecode(encoded, &cloned); err != nil {
		return formalGLMPhase21RockCandidateRecord{}, err
	}
	return cloned, nil
}

func formalGLMRegisteredPhase21RunCandidateV1(
	state formalGLMRegisteredPhase21StageHostStateV1,
) (formalGLMPhase21RockCandidateRecord, error) {
	var zero formalGLMPhase21RockCandidateRecord
	context, stagePaths, sealPaths, binding, local, ticket, err :=
		formalGLMRegisteredPhase21CandidateStateV1(state)
	if err != nil || !formalFinalizerHandoffAuthorityEqual(local, binding.Finalizer) {
		return zero, fmt.Errorf("formal-glm registered Phase21 candidate: local finalizer unavailable")
	}
	secretPath := filepath.Join(state.rockRoot, "commands-v1",
		formalGLMRegisteredPhase21CandidateSecretFileV1)
	_, _, err = formalGLMPhase21RockWriteJSON(state.rockRoot, secretPath,
		formalGLMPhase21RockCandidateSecret{
			Version:              formalGLMPhase21RockSecretVersion,
			Family:               formalFinalizerHandoffFamilyGLM,
			Purpose:              formalGLMPhase21RockPurpose,
			Action:               formalGLMPhase21RockActionPrepareCandidate,
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
	operation, err := json.Marshal(formalGLMPhase21RockPrepareCandidateOperation{
		ArtifactContractPath:      state.operation.ArtifactContractPath,
		PinsetPath:                state.operation.PinsetPath,
		RegistryResolutionPath:    state.operation.RegistryResolutionPath,
		PreflightRecordPaths:      state.operation.PreflightRecordPaths,
		StageRecordPaths:          stagePaths,
		TicketRecordPath:          ticketPath,
		SealRecordPaths:           sealPaths,
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
		state.rockRoot, false, formalGLMPhase21RockActionPrepareCandidate, operation)
	if err != nil || response.Candidate == nil ||
		response.State != formalGLMPhase21RockStateCandidateReady ||
		response.ArtifactID != context.artifactID || response.ProductionReady ||
		formalGLMPhase21RockValidateCandidateRecord(
			*response.Candidate, context, binding, ticket.Ticket) != nil {
		return zero, fmt.Errorf("formal-glm registered Phase21 candidate: lifecycle failed")
	}
	return formalGLMRegisteredPhase21CloneCandidateV1(*response.Candidate)
}

func formalGLMRegisteredPhase21ImportPeerCandidateV1(
	state formalGLMRegisteredPhase21StageHostStateV1,
	record formalGLMPhase21RockCandidateRecord,
) error {
	context, _, _, binding, local, ticket, err :=
		formalGLMRegisteredPhase21CandidateStateV1(state)
	if err != nil || formalFinalizerHandoffAuthorityEqual(local, binding.Finalizer) ||
		formalGLMPhase21RockValidateCandidateRecord(record, context, binding, ticket.Ticket) != nil {
		return fmt.Errorf("formal-glm registered Phase21 candidate: invalid peer record")
	}
	path, err := formalGLMRegisteredPhase21CandidateInboxPathV1(
		state.rockRoot, context.artifactID)
	if err != nil {
		return err
	}
	_, _, err = formalGLMPhase21RockWriteJSON(state.rockRoot, path, record)
	return err
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) RunPhase21CandidateV1() (
	formalGLMPhase21RockCandidateRecord, error,
) {
	owner, done, err := host.beginOpV1()
	if err != nil {
		return formalGLMPhase21RockCandidateRecord{}, err
	}
	defer done()
	state, err := host.phase21StageStateV1(owner)
	if err != nil {
		return formalGLMPhase21RockCandidateRecord{}, err
	}
	defer state.clearV1()
	return formalGLMRegisteredPhase21RunCandidateV1(state)
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) ImportPhase21PeerCandidateV1(
	record formalGLMPhase21RockCandidateRecord,
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
	return formalGLMRegisteredPhase21ImportPeerCandidateV1(state, record)
}
