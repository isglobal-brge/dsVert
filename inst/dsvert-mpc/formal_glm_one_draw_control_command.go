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
	"time"
)

const (
	formalGLMControlCommandVersion = "dsvert-formal-glm-one-draw-control-command-v1"
	formalGLMControlCommandMax     = ((formalGLMControlMaxEnvelopeJSON+2)/3)*4 + 256<<10
)

type formalGLMOneDrawControlCommand struct {
	Version                     string                          `json:"version"`
	Binding                     formalFinalizerHandoffBinding   `json:"binding"`
	LocalAuthority              formalFinalizerHandoffAuthority `json:"local_authority"`
	Pins                        map[string]string               `json:"pins"`
	RecipientTransportPublic    string                          `json:"recipient_transport_public,omitempty"`
	RecipientTransportSignature string                          `json:"recipient_transport_signature,omitempty"`
	RecipientTransportSecret    string                          `json:"recipient_transport_secret,omitempty"`
	EnvelopeBase64URL           string                          `json:"envelope_base64url,omitempty"`
	EnvelopeSHA256              string                          `json:"envelope_sha256,omitempty"`
	ReceiptSHA256               string                          `json:"receipt_sha256,omitempty"`
}

func formalGLMOneDrawControlDecodeCommand(encoded []byte) (
	formalGLMOneDrawControlCommand, map[string]ed25519.PublicKey, error,
) {
	var zero formalGLMOneDrawControlCommand
	if len(encoded) < 64 || len(encoded) > formalGLMControlCommandMax {
		return zero, nil, fmt.Errorf("formal-glm control: invalid command size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var command formalGLMOneDrawControlCommand
	if err := decoder.Decode(&command); err != nil {
		return zero, nil, fmt.Errorf("formal-glm control: invalid command")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF ||
		command.Version != formalGLMControlCommandVersion ||
		len(command.Pins) < 2 ||
		!formalFinalizerHandoffBindingHasAuthority(
			command.Binding, command.LocalAuthority) {
		return zero, nil, fmt.Errorf("formal-glm control: invalid command")
	}
	pins := make(map[string]ed25519.PublicKey, len(command.Pins))
	for peer, encodedPin := range command.Pins {
		decoded, err := base64.StdEncoding.Strict().DecodeString(encodedPin)
		if err != nil || len(decoded) != ed25519.PublicKeySize ||
			base64.StdEncoding.EncodeToString(decoded) != encodedPin {
			clear(decoded)
			return zero, nil, fmt.Errorf("formal-glm control: invalid command pins")
		}
		pins[peer] = ed25519.PublicKey(append([]byte(nil), decoded...))
		clear(decoded)
	}
	if formalFinalizerHandoffValidateBinding(command.Binding, pins) != nil ||
		command.Binding.Family != formalFinalizerHandoffFamilyGLM ||
		command.Binding.Purpose != formalFinalizerHandoffGLMPurpose {
		return zero, nil, fmt.Errorf("formal-glm control: invalid command binding")
	}
	return command, pins, nil
}

func formalGLMOneDrawControlOpenCommandStore(
	command formalGLMOneDrawControlCommand,
	pins map[string]ed25519.PublicKey, stateRoot string, production bool,
) (*formalGLMOneDrawControlStore, error) {
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot ||
		production && stateRoot != formalFinalizerHandoffStateRoot {
		return nil, fmt.Errorf("formal-glm control: invalid Rock state root")
	}
	root := filepath.Join(stateRoot, command.LocalAuthority.PeerName)
	if production && root != filepath.Join(
		formalFinalizerHandoffStateRoot, command.LocalAuthority.PeerName) {
		return nil, fmt.Errorf("formal-glm control: invalid authority root")
	}
	return newFormalGLMOneDrawControlStore(
		root, command.Binding, command.LocalAuthority, pins, production)
}

func formalGLMControlDecodeStandard(value string, size int,
	what string,
) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != size ||
		base64.StdEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, fmt.Errorf("formal-glm control: invalid %s", what)
	}
	return decoded, nil
}

func formalGLMOneDrawControlRunSourceAtRoot(encoded []byte,
	stateRoot string, production bool, now time.Time,
) (formalGLMOneDrawControlSourceDescriptor, error) {
	var zero formalGLMOneDrawControlSourceDescriptor
	command, pins, err := formalGLMOneDrawControlDecodeCommand(encoded)
	if err != nil || command.RecipientTransportPublic == "" ||
		command.RecipientTransportSignature == "" ||
		command.RecipientTransportSecret != "" ||
		command.EnvelopeBase64URL != "" || command.EnvelopeSHA256 != "" ||
		command.ReceiptSHA256 != "" {
		return zero, fmt.Errorf("formal-glm control: invalid source command")
	}
	public, err := formalGLMControlDecodeStandard(
		command.RecipientTransportPublic, 32, "recipient transport public key")
	if err != nil {
		return zero, err
	}
	defer clear(public)
	signature, err := formalGLMControlDecodeStandard(
		command.RecipientTransportSignature, ed25519.SignatureSize,
		"recipient transport signature")
	if err != nil {
		return zero, err
	}
	defer clear(signature)
	store, err := formalGLMOneDrawControlOpenCommandStore(
		command, pins, stateRoot, production)
	if err != nil {
		return zero, err
	}
	defer store.Close()
	return store.DescribeNextSource(public, signature, now)
}

func formalGLMOneDrawControlRunImportAtRoot(encoded []byte,
	stateRoot string, production bool, now time.Time,
) (formalGLMOneDrawControlIngressReceipt, error) {
	var zero formalGLMOneDrawControlIngressReceipt
	command, pins, err := formalGLMOneDrawControlDecodeCommand(encoded)
	if err != nil || command.RecipientTransportPublic != "" ||
		command.RecipientTransportSignature != "" ||
		command.RecipientTransportSecret == "" ||
		command.EnvelopeBase64URL == "" || command.EnvelopeSHA256 != "" ||
		command.ReceiptSHA256 != "" ||
		len(command.EnvelopeBase64URL) >
			((formalGLMControlMaxEnvelopeJSON+2)/3)*4 {
		return zero, fmt.Errorf("formal-glm control: invalid import command")
	}
	secret, err := formalGLMControlDecodeStandard(
		command.RecipientTransportSecret, 32, "recipient transport secret")
	if err != nil {
		return zero, err
	}
	defer clear(secret)
	envelope, err := base64.RawURLEncoding.Strict().DecodeString(
		command.EnvelopeBase64URL)
	if err != nil || len(envelope) < 64 ||
		len(envelope) > formalGLMControlMaxEnvelopeJSON ||
		base64.RawURLEncoding.EncodeToString(envelope) !=
			command.EnvelopeBase64URL {
		clear(envelope)
		return zero, fmt.Errorf("formal-glm control: invalid import envelope")
	}
	defer clear(envelope)
	store, err := formalGLMOneDrawControlOpenCommandStore(
		command, pins, stateRoot, production)
	if err != nil {
		return zero, err
	}
	defer store.Close()
	return store.ImportCanonical(envelope, secret, now)
}

func formalGLMOneDrawControlRunDeliveryAtRoot(encoded []byte,
	stateRoot string, production bool, now time.Time,
) (formalGLMOneDrawControlDeliveryReceipt, error) {
	var zero formalGLMOneDrawControlDeliveryReceipt
	command, pins, err := formalGLMOneDrawControlDecodeCommand(encoded)
	if err != nil || command.RecipientTransportPublic != "" ||
		command.RecipientTransportSignature != "" ||
		command.RecipientTransportSecret != "" ||
		command.EnvelopeBase64URL != "" ||
		!formalGLMIsSHA256(command.EnvelopeSHA256) ||
		!formalGLMIsSHA256(command.ReceiptSHA256) {
		return zero, fmt.Errorf("formal-glm control: invalid delivery command")
	}
	store, err := formalGLMOneDrawControlOpenCommandStore(
		command, pins, stateRoot, production)
	if err != nil {
		return zero, err
	}
	defer store.Close()
	return store.MarkNextDelivered(
		command.EnvelopeSHA256, command.ReceiptSHA256, now)
}

func formalGLMOneDrawControlReadCommand() ([]byte, error) {
	encoded, err := io.ReadAll(io.LimitReader(
		os.Stdin, int64(formalGLMControlCommandMax)+1))
	if err != nil || len(encoded) > formalGLMControlCommandMax {
		clear(encoded)
		return nil, fmt.Errorf("formal-glm control: invalid command input")
	}
	return encoded, nil
}

func handleFormalGLMOneDrawControlSource() {
	encoded, err := formalGLMOneDrawControlReadCommand()
	if err != nil {
		outputError("Formal GLM control source failed")
		return
	}
	defer clear(encoded)
	value, err := formalGLMOneDrawControlRunSourceAtRoot(
		encoded, formalFinalizerHandoffStateRoot, true, time.Now())
	if err != nil {
		outputError("Formal GLM control source failed")
		return
	}
	output(value)
}

func handleFormalGLMOneDrawControlImport() {
	encoded, err := formalGLMOneDrawControlReadCommand()
	if err != nil {
		outputError("Formal GLM control import failed")
		return
	}
	defer clear(encoded)
	value, err := formalGLMOneDrawControlRunImportAtRoot(
		encoded, formalFinalizerHandoffStateRoot, true, time.Now())
	if err != nil {
		outputError("Formal GLM control import failed")
		return
	}
	output(value)
}

func handleFormalGLMOneDrawControlDelivery() {
	encoded, err := formalGLMOneDrawControlReadCommand()
	if err != nil {
		outputError("Formal GLM control delivery failed")
		return
	}
	defer clear(encoded)
	value, err := formalGLMOneDrawControlRunDeliveryAtRoot(
		encoded, formalFinalizerHandoffStateRoot, true, time.Now())
	if err != nil {
		outputError("Formal GLM control delivery failed")
		return
	}
	output(value)
}
