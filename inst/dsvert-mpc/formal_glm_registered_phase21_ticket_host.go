package main

// Phase21 Ticket is the first post-Stage lifecycle record.  The generic Rock
// action already owns the cryptography and one-draw state; this bridge only
// admits canonical signed peer records into the authority-local inbox and
// supplies the action's local secret bundle.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
)

const formalGLMRegisteredPhase21TicketSecretFileV1 = "registered-phase21-ticket-secret.json"

func formalGLMRegisteredPhase21StageInboxPathV1(
	root, artifactID, role string,
) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		!formalGLMIsSHA256(artifactID) ||
		(role != "garbler" && role != "evaluator") {
		return "", fmt.Errorf("formal-glm registered Phase21 ticket: invalid stage inbox")
	}
	return filepath.Join(root, "inbox-v1", "stage-"+role+".json"), nil
}

func formalGLMRegisteredPhase21TicketInboxPathV1(
	root, artifactID string,
) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		!formalGLMIsSHA256(artifactID) {
		return "", fmt.Errorf("formal-glm registered Phase21 ticket: invalid ticket inbox")
	}
	return filepath.Join(root, "inbox-v1", "ticket-"+artifactID+".json"), nil
}

func formalGLMRegisteredPhase21TicketStateV1(
	state formalGLMRegisteredPhase21StageHostStateV1,
) (formalGLMPhase21RockContext, [2]string, formalFinalizerHandoffBinding,
	formalFinalizerHandoffAuthority, error) {
	var zeroContext formalGLMPhase21RockContext
	var zeroPaths [2]string
	var zeroBinding formalFinalizerHandoffBinding
	var zeroAuthority formalFinalizerHandoffAuthority
	if state.rockRoot == "" || !formalGLMIsSHA256(state.artifactID) ||
		state.peer == "" || len(state.signing) != ed25519.PrivateKeySize ||
		!formalGLMPhase19KeyValid(state.transportRoot) {
		return zeroContext, zeroPaths, zeroBinding, zeroAuthority,
			fmt.Errorf("formal-glm registered Phase21 ticket: invalid state")
	}
	context, err := formalGLMPhase21RockLoadContext(
		state.rockRoot, state.operation.ArtifactContractPath, state.operation.PinsetPath)
	if err != nil || context.artifactID != state.artifactID {
		return zeroContext, zeroPaths, zeroBinding, zeroAuthority,
			fmt.Errorf("formal-glm registered Phase21 ticket: durable context unavailable")
	}
	local, err := formalGLMPhase21RockAuthority(context.contract.Artifact, state.peer)
	if err != nil || !reflect.DeepEqual(
		state.signing.Public().(ed25519.PublicKey), context.pins[state.peer]) {
		return zeroContext, zeroPaths, zeroBinding, zeroAuthority,
			fmt.Errorf("formal-glm registered Phase21 ticket: invalid local authority")
	}
	var paths [2]string
	for index, authority := range context.contract.Artifact.NoiseAuthorities {
		if authority.PeerName == state.peer {
			paths[index], err = formalGLMPhase21RockStageRecordPath(
				state.rockRoot, context.artifactID, authority.Role)
		} else {
			paths[index], err = formalGLMRegisteredPhase21StageInboxPathV1(
				state.rockRoot, context.artifactID, authority.Role)
		}
		if err != nil {
			return zeroContext, zeroPaths, zeroBinding, zeroAuthority, err
		}
	}
	_, binding, err := formalGLMPhase21RockLoadStagePair(
		state.rockRoot, paths, context)
	if err != nil {
		return zeroContext, zeroPaths, zeroBinding, zeroAuthority,
			fmt.Errorf("formal-glm registered Phase21 ticket: signed Stage pair unavailable")
	}
	return context, paths, binding, local, nil
}

func formalGLMRegisteredPhase21ImportPeerStageV1(
	state formalGLMRegisteredPhase21StageHostStateV1,
	record formalGLMPhase21RockStageRecord,
) error {
	if state.rockRoot == "" || !formalGLMIsSHA256(state.artifactID) {
		return fmt.Errorf("formal-glm registered Phase21 ticket: unavailable")
	}
	context, err := formalGLMPhase21RockLoadContext(
		state.rockRoot, state.operation.ArtifactContractPath, state.operation.PinsetPath)
	if err != nil || context.artifactID != state.artifactID ||
		formalGLMPhase21RockValidateStageRecord(
			record, context.contract, context.pins) != nil ||
		record.Receipt.PeerName == state.peer {
		return fmt.Errorf("formal-glm registered Phase21 ticket: invalid peer Stage")
	}
	path, err := formalGLMRegisteredPhase21StageInboxPathV1(
		state.rockRoot, state.artifactID, record.Receipt.Role)
	if err != nil {
		return err
	}
	_, _, err = formalGLMPhase21RockWriteJSON(state.rockRoot, path, record)
	return err
}

func formalGLMRegisteredPhase21CloneTicketV1(
	record formalGLMPhase21RockTicketRecord,
) (formalGLMPhase21RockTicketRecord, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return formalGLMPhase21RockTicketRecord{}, err
	}
	defer clear(encoded)
	var cloned formalGLMPhase21RockTicketRecord
	if err := formalGLMPhase21RockStrictDecode(encoded, &cloned); err != nil {
		return formalGLMPhase21RockTicketRecord{}, err
	}
	return cloned, nil
}

func formalGLMRegisteredPhase21RunTicketV1(
	state formalGLMRegisteredPhase21StageHostStateV1,
) (formalGLMPhase21RockTicketRecord, error) {
	var zero formalGLMPhase21RockTicketRecord
	context, paths, binding, local, err := formalGLMRegisteredPhase21TicketStateV1(state)
	if err != nil || !formalFinalizerHandoffAuthorityEqual(local, binding.Finalizer) {
		return zero, fmt.Errorf("formal-glm registered Phase21 ticket: local finalizer unavailable")
	}
	secretPath := filepath.Join(state.rockRoot, "commands-v1",
		formalGLMRegisteredPhase21TicketSecretFileV1)
	_, _, err = formalGLMPhase21RockWriteJSON(state.rockRoot, secretPath,
		formalGLMPhase21RockTicketSecret{
			Version:              formalGLMPhase21RockSecretVersion,
			Family:               formalFinalizerHandoffFamilyGLM,
			Purpose:              formalGLMPhase21RockPurpose,
			Action:               formalGLMPhase21RockActionTicket,
			TransportStorageRoot: base64.StdEncoding.EncodeToString(state.transportRoot[:]),
			SigningPrivateKey:    base64.StdEncoding.EncodeToString(state.signing),
		})
	if err != nil {
		return zero, err
	}
	operation, err := json.Marshal(formalGLMPhase21RockTicketOperation{
		ArtifactContractPath: state.operation.ArtifactContractPath,
		PinsetPath:           state.operation.PinsetPath,
		PreflightRecordPaths: state.operation.PreflightRecordPaths,
		StageRecordPaths:     paths,
		PeerName:             local.PeerName,
		SecretBundlePath:     secretPath,
	})
	if err != nil {
		return zero, err
	}
	defer clear(operation)
	response, err := formalGLMPhase21RockRun(
		state.rockRoot, false, formalGLMPhase21RockActionTicket, operation)
	if err != nil || response.Ticket == nil ||
		response.State != formalGLMPhase21RockStateTicketReady ||
		response.ArtifactID != context.artifactID || response.ProductionReady ||
		formalGLMPhase21RockValidateTicketRecord(*response.Ticket, context) != nil ||
		!reflect.DeepEqual(response.Ticket.Binding, binding) {
		return zero, fmt.Errorf("formal-glm registered Phase21 ticket: lifecycle failed")
	}
	return formalGLMRegisteredPhase21CloneTicketV1(*response.Ticket)
}

func formalGLMRegisteredPhase21ImportPeerTicketV1(
	state formalGLMRegisteredPhase21StageHostStateV1,
	record formalGLMPhase21RockTicketRecord,
) error {
	context, _, binding, local, err := formalGLMRegisteredPhase21TicketStateV1(state)
	if err != nil || formalFinalizerHandoffAuthorityEqual(local, binding.Finalizer) ||
		formalGLMPhase21RockValidateTicketRecord(record, context) != nil ||
		!reflect.DeepEqual(record.Binding, binding) {
		return fmt.Errorf("formal-glm registered Phase21 ticket: invalid peer ticket")
	}
	path, err := formalGLMRegisteredPhase21TicketInboxPathV1(
		state.rockRoot, state.artifactID)
	if err != nil {
		return err
	}
	_, _, err = formalGLMPhase21RockWriteJSON(state.rockRoot, path, record)
	return err
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) ImportPhase21PeerStageV1(
	record formalGLMPhase21RockStageRecord,
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
	return formalGLMRegisteredPhase21ImportPeerStageV1(state, record)
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) RunPhase21TicketV1() (
	formalGLMPhase21RockTicketRecord, error,
) {
	owner, done, err := host.beginOpV1()
	if err != nil {
		return formalGLMPhase21RockTicketRecord{}, err
	}
	defer done()
	state, err := host.phase21StageStateV1(owner)
	if err != nil {
		return formalGLMPhase21RockTicketRecord{}, err
	}
	defer state.clearV1()
	return formalGLMRegisteredPhase21RunTicketV1(state)
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) ImportPhase21PeerTicketV1(
	record formalGLMPhase21RockTicketRecord,
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
	return formalGLMRegisteredPhase21ImportPeerTicketV1(state, record)
}
