package main

// Seal follows Ticket for both designated authorities.  The lifecycle action
// reconstructs only its local encrypted spool and emits a signed receipt; the
// bridge below merely pins the canonical record locations and local secret.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
)

const formalGLMRegisteredPhase21SealSecretFileV1 = "registered-phase21-seal-secret.json"

func formalGLMRegisteredPhase21SealInboxPathV1(
	root, artifactID, role string,
) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		!formalGLMIsSHA256(artifactID) ||
		(role != "garbler" && role != "evaluator") {
		return "", fmt.Errorf("formal-glm registered Phase21 seal: invalid inbox")
	}
	return filepath.Join(root, "inbox-v1", "seal-"+role+".json"), nil
}

func formalGLMRegisteredPhase21TicketRecordPathV1(
	state formalGLMRegisteredPhase21StageHostStateV1,
	binding formalFinalizerHandoffBinding,
	local formalFinalizerHandoffAuthority,
) (string, error) {
	if formalFinalizerHandoffAuthorityEqual(local, binding.Finalizer) {
		return formalGLMPhase21RockTicketRecordPath(state.rockRoot, state.artifactID)
	}
	return formalGLMRegisteredPhase21TicketInboxPathV1(state.rockRoot, state.artifactID)
}

func formalGLMRegisteredPhase21SealStateV1(
	state formalGLMRegisteredPhase21StageHostStateV1,
) (formalGLMPhase21RockContext, [2]string, formalFinalizerHandoffBinding,
	formalFinalizerHandoffAuthority, formalGLMPhase21RockTicketRecord, error) {
	var zeroContext formalGLMPhase21RockContext
	var zeroPaths [2]string
	var zeroBinding formalFinalizerHandoffBinding
	var zeroAuthority formalFinalizerHandoffAuthority
	var zeroTicket formalGLMPhase21RockTicketRecord
	context, paths, binding, local, err := formalGLMRegisteredPhase21TicketStateV1(state)
	if err != nil {
		return zeroContext, zeroPaths, zeroBinding, zeroAuthority, zeroTicket, err
	}
	ticketPath, err := formalGLMRegisteredPhase21TicketRecordPathV1(state, binding, local)
	if err != nil {
		return zeroContext, zeroPaths, zeroBinding, zeroAuthority, zeroTicket, err
	}
	var ticket formalGLMPhase21RockTicketRecord
	if err := formalGLMPhase21RockReadJSON(
		state.rockRoot, ticketPath, formalGLMPhase21RockMaxRecord, &ticket); err != nil ||
		formalGLMPhase21RockValidateTicketRecord(ticket, context) != nil ||
		!reflect.DeepEqual(ticket.Binding, binding) {
		return zeroContext, zeroPaths, zeroBinding, zeroAuthority, zeroTicket,
			fmt.Errorf("formal-glm registered Phase21 seal: signed ticket unavailable")
	}
	return context, paths, binding, local, ticket, nil
}

func formalGLMRegisteredPhase21CloneSealV1(
	record formalGLMPhase21RockSealRecord,
) (formalGLMPhase21RockSealRecord, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return formalGLMPhase21RockSealRecord{}, err
	}
	defer clear(encoded)
	var cloned formalGLMPhase21RockSealRecord
	if err := formalGLMPhase21RockStrictDecode(encoded, &cloned); err != nil {
		return formalGLMPhase21RockSealRecord{}, err
	}
	return cloned, nil
}

func formalGLMRegisteredPhase21RunSealV1(
	state formalGLMRegisteredPhase21StageHostStateV1,
) (formalGLMPhase21RockSealRecord, error) {
	var zero formalGLMPhase21RockSealRecord
	context, paths, binding, local, ticket, err := formalGLMRegisteredPhase21SealStateV1(state)
	if err != nil {
		return zero, err
	}
	secretPath := filepath.Join(state.rockRoot, "commands-v1",
		formalGLMRegisteredPhase21SealSecretFileV1)
	_, _, err = formalGLMPhase21RockWriteJSON(state.rockRoot, secretPath,
		formalGLMPhase21RockSealSecret{
			Version:              formalGLMPhase21RockSecretVersion,
			Family:               formalFinalizerHandoffFamilyGLM,
			Purpose:              formalGLMPhase21RockPurpose,
			Action:               formalGLMPhase21RockActionSeal,
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
	operation, err := json.Marshal(formalGLMPhase21RockSealOperation{
		ArtifactContractPath:      state.operation.ArtifactContractPath,
		PinsetPath:                state.operation.PinsetPath,
		RegistryResolutionPath:    state.operation.RegistryResolutionPath,
		PreflightRecordPaths:      state.operation.PreflightRecordPaths,
		StageRecordPaths:          paths,
		TicketRecordPath:          ticketPath,
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
		state.rockRoot, false, formalGLMPhase21RockActionSeal, operation)
	if err != nil || response.Seal == nil ||
		response.State != formalGLMPhase21RockStateSealed ||
		response.ArtifactID != context.artifactID || response.ProductionReady ||
		formalGLMPhase21RockValidateSealRecord(*response.Seal, context, binding, ticket.Ticket) != nil ||
		response.Seal.Receipt.PeerName != local.PeerName ||
		response.Seal.Receipt.Role != local.Role {
		return zero, fmt.Errorf("formal-glm registered Phase21 seal: lifecycle failed")
	}
	return formalGLMRegisteredPhase21CloneSealV1(*response.Seal)
}

func formalGLMRegisteredPhase21ImportPeerSealV1(
	state formalGLMRegisteredPhase21StageHostStateV1,
	record formalGLMPhase21RockSealRecord,
) error {
	context, _, binding, local, ticket, err := formalGLMRegisteredPhase21SealStateV1(state)
	if err != nil || record.Receipt.PeerName == local.PeerName ||
		formalGLMPhase21RockValidateSealRecord(record, context, binding, ticket.Ticket) != nil {
		return fmt.Errorf("formal-glm registered Phase21 seal: invalid peer record")
	}
	path, err := formalGLMRegisteredPhase21SealInboxPathV1(
		state.rockRoot, state.artifactID, record.Receipt.Role)
	if err != nil {
		return err
	}
	_, _, err = formalGLMPhase21RockWriteJSON(state.rockRoot, path, record)
	return err
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) RunPhase21SealV1() (
	formalGLMPhase21RockSealRecord, error,
) {
	owner, done, err := host.beginOpV1()
	if err != nil {
		return formalGLMPhase21RockSealRecord{}, err
	}
	defer done()
	state, err := host.phase21StageStateV1(owner)
	if err != nil {
		return formalGLMPhase21RockSealRecord{}, err
	}
	defer state.clearV1()
	return formalGLMRegisteredPhase21RunSealV1(state)
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) ImportPhase21PeerSealV1(
	record formalGLMPhase21RockSealRecord,
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
	return formalGLMRegisteredPhase21ImportPeerSealV1(state, record)
}
