package main

// Candidate verification is performed separately by each designated
// authority.  The existing Rock action reconstructs only that authority's
// local output and emits a signed local-release record; this bridge carries
// the peer record forward without exposing a share.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
)

const formalGLMRegisteredPhase21VerifyCandidateSecretFileV1 = "registered-phase21-verify-candidate-secret.json"

func formalGLMRegisteredPhase21LocalReleaseInboxPathV1(
	root, artifactID, role string,
) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		!formalGLMIsSHA256(artifactID) ||
		(role != "garbler" && role != "evaluator") {
		return "", fmt.Errorf("formal-glm registered Phase21 verification: invalid inbox")
	}
	return filepath.Join(root, "inbox-v1", "local-release-"+role+".json"), nil
}

func formalGLMRegisteredPhase21CandidateRecordPathV1(
	state formalGLMRegisteredPhase21StageHostStateV1,
	binding formalFinalizerHandoffBinding,
	local formalFinalizerHandoffAuthority,
) (string, error) {
	if formalFinalizerHandoffAuthorityEqual(local, binding.Finalizer) {
		return formalGLMPhase21RockCandidateRecordPath(state.rockRoot, state.artifactID)
	}
	return formalGLMRegisteredPhase21CandidateInboxPathV1(state.rockRoot, state.artifactID)
}

func formalGLMRegisteredPhase21VerifyStateV1(
	state formalGLMRegisteredPhase21StageHostStateV1,
) (formalGLMPhase21RockContext, [2]string, formalFinalizerHandoffBinding,
	formalFinalizerHandoffAuthority, formalGLMPhase21RockTicketRecord,
	formalGLMPhase21RockCandidateRecord, string, error) {
	var zeroContext formalGLMPhase21RockContext
	var zeroPaths [2]string
	var zeroBinding formalFinalizerHandoffBinding
	var zeroAuthority formalFinalizerHandoffAuthority
	var zeroTicket formalGLMPhase21RockTicketRecord
	var zeroCandidate formalGLMPhase21RockCandidateRecord
	context, stagePaths, _, binding, local, ticket, err :=
		formalGLMRegisteredPhase21CandidateStateV1(state)
	if err != nil {
		return zeroContext, zeroPaths, zeroBinding, zeroAuthority, zeroTicket,
			zeroCandidate, "", err
	}
	candidatePath, err := formalGLMRegisteredPhase21CandidateRecordPathV1(
		state, binding, local)
	if err != nil {
		return zeroContext, zeroPaths, zeroBinding, zeroAuthority, zeroTicket,
			zeroCandidate, "", err
	}
	var candidate formalGLMPhase21RockCandidateRecord
	if err := formalGLMPhase21RockReadJSON(
		state.rockRoot, candidatePath, formalGLMPhase21RockMaxRecord, &candidate); err != nil ||
		formalGLMPhase21RockValidateCandidateRecord(
			candidate, context, binding, ticket.Ticket) != nil {
		return zeroContext, zeroPaths, zeroBinding, zeroAuthority, zeroTicket,
			zeroCandidate, "", fmt.Errorf("formal-glm registered Phase21 verification: signed candidate unavailable")
	}
	return context, stagePaths, binding, local, ticket, candidate, candidatePath, nil
}

func formalGLMRegisteredPhase21CloneLocalReleaseV1(
	record formalGLMPhase21RockLocalReleaseRecord,
) (formalGLMPhase21RockLocalReleaseRecord, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return formalGLMPhase21RockLocalReleaseRecord{}, err
	}
	defer clear(encoded)
	var cloned formalGLMPhase21RockLocalReleaseRecord
	if err := formalGLMPhase21RockStrictDecode(encoded, &cloned); err != nil {
		return formalGLMPhase21RockLocalReleaseRecord{}, err
	}
	return cloned, nil
}

func formalGLMRegisteredPhase21VerifyCandidateV1(
	state formalGLMRegisteredPhase21StageHostStateV1,
) (formalGLMPhase21RockLocalReleaseRecord, error) {
	var zero formalGLMPhase21RockLocalReleaseRecord
	context, stagePaths, binding, local, ticket, candidate, candidatePath, err :=
		formalGLMRegisteredPhase21VerifyStateV1(state)
	if err != nil {
		return zero, err
	}
	secretPath := filepath.Join(state.rockRoot, "commands-v1",
		formalGLMRegisteredPhase21VerifyCandidateSecretFileV1)
	_, _, err = formalGLMPhase21RockWriteJSON(state.rockRoot, secretPath,
		formalGLMPhase21RockVerifyCandidateSecret{
			Version:              formalGLMPhase21RockSecretVersion,
			Family:               formalFinalizerHandoffFamilyGLM,
			Purpose:              formalGLMPhase21RockPurpose,
			Action:               formalGLMPhase21RockActionVerifyCandidate,
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
	operation, err := json.Marshal(formalGLMPhase21RockVerifyCandidateOperation{
		ArtifactContractPath:      state.operation.ArtifactContractPath,
		PinsetPath:                state.operation.PinsetPath,
		RegistryResolutionPath:    state.operation.RegistryResolutionPath,
		PreflightRecordPaths:      state.operation.PreflightRecordPaths,
		StageRecordPaths:          stagePaths,
		TicketRecordPath:          ticketPath,
		CandidateRecordPath:       candidatePath,
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
		state.rockRoot, false, formalGLMPhase21RockActionVerifyCandidate, operation)
	if err != nil || response.LocalRelease == nil ||
		response.State != formalGLMPhase21RockStateCandidateVerified ||
		response.ArtifactID != context.artifactID || response.ProductionReady ||
		formalGLMPhase21RockValidateLocalReleaseRecord(
			*response.LocalRelease, context, binding, ticket.Ticket, candidate) != nil ||
		response.LocalRelease.Binding.PeerName != local.PeerName ||
		response.LocalRelease.Binding.Role != local.Role {
		return zero, fmt.Errorf("formal-glm registered Phase21 verification: lifecycle failed")
	}
	return formalGLMRegisteredPhase21CloneLocalReleaseV1(*response.LocalRelease)
}

func formalGLMRegisteredPhase21ImportPeerLocalReleaseV1(
	state formalGLMRegisteredPhase21StageHostStateV1,
	record formalGLMPhase21RockLocalReleaseRecord,
) error {
	context, _, binding, local, ticket, candidate, _, err :=
		formalGLMRegisteredPhase21VerifyStateV1(state)
	if err != nil || record.Binding.PeerName == local.PeerName ||
		formalGLMPhase21RockValidateLocalReleaseRecord(
			record, context, binding, ticket.Ticket, candidate) != nil {
		return fmt.Errorf("formal-glm registered Phase21 verification: invalid peer release")
	}
	path, err := formalGLMRegisteredPhase21LocalReleaseInboxPathV1(
		state.rockRoot, context.artifactID, record.Binding.Role)
	if err != nil {
		return err
	}
	_, _, err = formalGLMPhase21RockWriteJSON(state.rockRoot, path, record)
	return err
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) VerifyPhase21CandidateV1() (
	formalGLMPhase21RockLocalReleaseRecord, error,
) {
	owner, done, err := host.beginOpV1()
	if err != nil {
		return formalGLMPhase21RockLocalReleaseRecord{}, err
	}
	defer done()
	state, err := host.phase21StageStateV1(owner)
	if err != nil {
		return formalGLMPhase21RockLocalReleaseRecord{}, err
	}
	defer state.clearV1()
	return formalGLMRegisteredPhase21VerifyCandidateV1(state)
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) ImportPhase21PeerLocalReleaseV1(
	record formalGLMPhase21RockLocalReleaseRecord,
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
	return formalGLMRegisteredPhase21ImportPeerLocalReleaseV1(state, record)
}
