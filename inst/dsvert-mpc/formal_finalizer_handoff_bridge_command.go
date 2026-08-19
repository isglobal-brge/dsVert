package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	formalFinalizerHandoffBridgeCommandVersion  = "dsvert-formal-finalizer-handoff-bridge-command-v1"
	formalFinalizerHandoffBridgeCommandMaxBytes = formalFinalizerHandoffMaxOuterPayloadChars + 2<<20
)

type formalFinalizerHandoffBridgeCommand struct {
	Version              string                          `json:"version"`
	Binding              formalFinalizerHandoffBinding   `json:"binding"`
	LocalAuthority       formalFinalizerHandoffAuthority `json:"local_authority"`
	Pins                 map[string]string               `json:"pins"`
	TransportStorageRoot string                          `json:"transport_storage_root"`
	EnvelopeBase64URL    string                          `json:"envelope_base64url,omitempty"`
}

func formalFinalizerHandoffDecodeBridgeCommand(encoded []byte) (
	formalFinalizerHandoffBridgeCommand, map[string]ed25519.PublicKey,
	[32]byte, error,
) {
	var zeroCommand formalFinalizerHandoffBridgeCommand
	var zeroRoot [32]byte
	if len(encoded) < 2 || int64(len(encoded)) > formalFinalizerHandoffBridgeCommandMaxBytes {
		return zeroCommand, nil, zeroRoot,
			fmt.Errorf("typed-finalizer-handoff: invalid command size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var command formalFinalizerHandoffBridgeCommand
	if err := decoder.Decode(&command); err != nil {
		return zeroCommand, nil, zeroRoot,
			fmt.Errorf("typed-finalizer-handoff: invalid command")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF ||
		command.Version != formalFinalizerHandoffBridgeCommandVersion {
		return zeroCommand, nil, zeroRoot,
			fmt.Errorf("typed-finalizer-handoff: invalid command")
	}
	if len(command.Pins) < 2 {
		return zeroCommand, nil, zeroRoot,
			fmt.Errorf("typed-finalizer-handoff: invalid command pins")
	}
	pins := make(map[string]ed25519.PublicKey, len(command.Pins))
	for peer, encodedPin := range command.Pins {
		decoded, err := base64.StdEncoding.Strict().DecodeString(encodedPin)
		if err != nil || len(decoded) != ed25519.PublicKeySize ||
			base64.StdEncoding.EncodeToString(decoded) != encodedPin {
			clear(decoded)
			return zeroCommand, nil, zeroRoot,
				fmt.Errorf("typed-finalizer-handoff: invalid command pins")
		}
		pins[peer] = ed25519.PublicKey(append([]byte(nil), decoded...))
		clear(decoded)
	}
	decodedRoot, err := base64.StdEncoding.Strict().DecodeString(
		command.TransportStorageRoot)
	if err != nil || len(decodedRoot) != len(zeroRoot) ||
		base64.StdEncoding.EncodeToString(decodedRoot) != command.TransportStorageRoot {
		clear(decodedRoot)
		return zeroCommand, nil, zeroRoot,
			fmt.Errorf("typed-finalizer-handoff: invalid storage root")
	}
	copy(zeroRoot[:], decodedRoot)
	clear(decodedRoot)
	if !formalGLMPhase19KeyValid(zeroRoot) ||
		formalFinalizerHandoffValidateBinding(command.Binding, pins) != nil ||
		!formalFinalizerHandoffBindingHasAuthority(
			command.Binding, command.LocalAuthority) {
		clear(zeroRoot[:])
		return zeroCommand, nil, [32]byte{},
			fmt.Errorf("typed-finalizer-handoff: invalid command binding")
	}
	return command, pins, zeroRoot, nil
}

func formalFinalizerHandoffOpenBridgeStore(command formalFinalizerHandoffBridgeCommand,
	stateRoot string, storageRoot [32]byte, pins map[string]ed25519.PublicKey,
	production bool,
) (*formalFinalizerHandoffStore, error) {
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot ||
		production && stateRoot != formalFinalizerHandoffStateRoot {
		return nil, fmt.Errorf("typed-finalizer-handoff: invalid bridge state root")
	}
	dir := filepath.Join(stateRoot, command.LocalAuthority.PeerName)
	if production {
		return newFormalFinalizerHandoffAuthorityStore(
			dir, command.Binding, command.LocalAuthority, storageRoot, pins)
	}
	return newFormalFinalizerHandoffAuthorityStoreForTest(
		dir, command.Binding, command.LocalAuthority, storageRoot, pins)
}

func formalFinalizerHandoffRunSourceDescriptorAtRoot(encoded []byte,
	stateRoot string, production bool,
) (formalFinalizerHandoffOutboxDescriptor, error) {
	var zero formalFinalizerHandoffOutboxDescriptor
	command, pins, storageRoot, err :=
		formalFinalizerHandoffDecodeBridgeCommand(encoded)
	defer clear(storageRoot[:])
	if err != nil || command.EnvelopeBase64URL != "" ||
		command.LocalAuthority.Role != "evaluator" {
		return zero, fmt.Errorf(
			"typed-finalizer-handoff: invalid source descriptor command")
	}
	store, err := formalFinalizerHandoffOpenBridgeStore(
		command, stateRoot, storageRoot, pins, production)
	if err != nil {
		return zero, err
	}
	defer store.Close()
	return store.DescribeOutboxCanonical("evaluator")
}

func formalFinalizerHandoffRunImportIngressAtRoot(encoded []byte,
	stateRoot string, production bool,
) (formalFinalizerHandoffIngressReceipt, error) {
	var zero formalFinalizerHandoffIngressReceipt
	command, pins, storageRoot, err :=
		formalFinalizerHandoffDecodeBridgeCommand(encoded)
	defer clear(storageRoot[:])
	if err != nil || command.EnvelopeBase64URL == "" ||
		!formalFinalizerHandoffAuthorityEqual(
			command.LocalAuthority, command.Binding.Finalizer) ||
		int64(len(command.EnvelopeBase64URL)) >
			formalFinalizerHandoffMaxOuterPayloadChars {
		return zero, fmt.Errorf(
			"typed-finalizer-handoff: invalid ingress command")
	}
	envelope, err := base64.RawURLEncoding.Strict().DecodeString(
		command.EnvelopeBase64URL)
	if err != nil || len(envelope) < 64 ||
		len(envelope) > formalFinalizerHandoffMaxRecord ||
		base64.RawURLEncoding.EncodeToString(envelope) !=
			command.EnvelopeBase64URL {
		clear(envelope)
		return zero, fmt.Errorf(
			"typed-finalizer-handoff: invalid ingress envelope")
	}
	defer clear(envelope)
	store, err := formalFinalizerHandoffOpenBridgeStore(
		command, stateRoot, storageRoot, pins, production)
	if err != nil {
		return zero, err
	}
	defer store.Close()
	return store.ImportIngressCanonical("evaluator", envelope)
}

func formalFinalizerHandoffReadBridgeCommand() ([]byte, error) {
	reader := io.LimitReader(os.Stdin,
		formalFinalizerHandoffBridgeCommandMaxBytes+1)
	encoded, err := io.ReadAll(reader)
	if err != nil || int64(len(encoded)) > formalFinalizerHandoffBridgeCommandMaxBytes {
		clear(encoded)
		return nil, fmt.Errorf("typed-finalizer-handoff: invalid command input")
	}
	return encoded, nil
}

func handleFormalFinalizerHandoffSourceDescriptor() {
	encoded, err := formalFinalizerHandoffReadBridgeCommand()
	if err != nil {
		outputError("Typed finalizer handoff source failed")
		return
	}
	defer clear(encoded)
	descriptor, err := formalFinalizerHandoffRunSourceDescriptorAtRoot(
		encoded, formalFinalizerHandoffStateRoot, true)
	if err != nil {
		outputError("Typed finalizer handoff source failed")
		return
	}
	output(descriptor)
}

func handleFormalFinalizerHandoffImportIngress() {
	encoded, err := formalFinalizerHandoffReadBridgeCommand()
	if err != nil {
		outputError("Typed finalizer handoff import failed")
		return
	}
	defer clear(encoded)
	receipt, err := formalFinalizerHandoffRunImportIngressAtRoot(
		encoded, formalFinalizerHandoffStateRoot, true)
	if err != nil {
		outputError("Typed finalizer handoff import failed")
		return
	}
	output(receipt)
}
