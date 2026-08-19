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
	formalCoxControlCommandVersion = "dsvert-formal-cox-blockwise-control-command-v1"
	formalCoxControlCommandMax     = ((formalCoxControlMaxEnvelopeJSON+2)/3)*4 + 256<<10
)

// The Rock wrapper supplies a signed plan and pinned authority identity set.
// No lifecycle record type, path, direction, or action is caller-selectable;
// the store derives the next exact record from its durable state.
type formalCoxBlockwiseControlCommand struct {
	Version                     string                          `json:"version"`
	Plan                        formalCoxBlockwisePlan          `json:"plan"`
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

func formalCoxBlockwiseControlDecodeCommand(encoded []byte) (
	formalCoxBlockwiseControlCommand, formalCoxBlockwiseControlContext, error,
) {
	var zeroCommand formalCoxBlockwiseControlCommand
	var zeroContext formalCoxBlockwiseControlContext
	if len(encoded) < 64 || len(encoded) > formalCoxControlCommandMax {
		return zeroCommand, zeroContext,
			fmt.Errorf("formal-cox control: invalid command size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var command formalCoxBlockwiseControlCommand
	if err := decoder.Decode(&command); err != nil {
		return zeroCommand, zeroContext,
			fmt.Errorf("formal-cox control: invalid command")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF ||
		command.Version != formalCoxControlCommandVersion ||
		len(command.Pins) < 2 {
		return zeroCommand, zeroContext,
			fmt.Errorf("formal-cox control: invalid command")
	}
	pins := make(map[string]ed25519.PublicKey, len(command.Pins))
	for peer, encodedPin := range command.Pins {
		decoded, err := base64.StdEncoding.Strict().DecodeString(encodedPin)
		if err != nil || len(decoded) != ed25519.PublicKeySize ||
			base64.StdEncoding.EncodeToString(decoded) != encodedPin {
			clear(decoded)
			return zeroCommand, zeroContext,
				fmt.Errorf("formal-cox control: invalid command pins")
		}
		pins[peer] = ed25519.PublicKey(append([]byte(nil), decoded...))
		clear(decoded)
	}
	context, err := formalCoxControlContextFor(command.Plan, pins)
	if err != nil || formalFinalizerHandoffValidateBinding(
		command.Binding, pins) != nil ||
		command.Binding.Family != context.Family ||
		command.Binding.Purpose != context.Purpose ||
		command.Binding.ArtifactID != context.ArtifactID ||
		command.Binding.PlanSHA256 != context.PlanSHA256 ||
		command.Binding.PinsetSHA256 != context.PinsetSHA256 ||
		len(command.Binding.Authorities) != len(context.Authorities) ||
		!formalFinalizerHandoffAuthorityEqual(
			command.Binding.Finalizer, context.Finalizer) ||
		!formalCoxControlContextHasAuthority(context, command.LocalAuthority) {
		return zeroCommand, zeroContext,
			fmt.Errorf("formal-cox control: invalid command context")
	}
	for index := range context.Authorities {
		if !formalFinalizerHandoffAuthorityEqual(
			command.Binding.Authorities[index], context.Authorities[index]) {
			return zeroCommand, zeroContext,
				fmt.Errorf("formal-cox control: invalid command context")
		}
	}
	return command, context, nil
}

func formalCoxBlockwiseControlOpenCommandStore(
	command formalCoxBlockwiseControlCommand,
	context formalCoxBlockwiseControlContext, stateRoot string, production bool,
) (*formalCoxBlockwiseControlStore, error) {
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot ||
		production && stateRoot != formalFinalizerHandoffStateRoot {
		return nil, fmt.Errorf("formal-cox control: invalid Rock state root")
	}
	root := filepath.Join(stateRoot, command.LocalAuthority.PeerName)
	if production && root != filepath.Join(
		formalFinalizerHandoffStateRoot, command.LocalAuthority.PeerName) {
		return nil, fmt.Errorf("formal-cox control: invalid authority root")
	}
	return newFormalCoxBlockwiseControlStore(
		root, context, command.LocalAuthority, production)
}

func formalCoxControlDecodeStandard(value string, size int,
	what string,
) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != size ||
		base64.StdEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, fmt.Errorf("formal-cox control: invalid %s", what)
	}
	return decoded, nil
}

func formalCoxBlockwiseControlRunSourceAtRoot(encoded []byte,
	stateRoot string, production bool, now time.Time,
) (formalCoxBlockwiseControlSourceDescriptor, error) {
	var zero formalCoxBlockwiseControlSourceDescriptor
	command, context, err := formalCoxBlockwiseControlDecodeCommand(encoded)
	if err != nil || command.RecipientTransportPublic == "" ||
		command.RecipientTransportSignature == "" ||
		command.RecipientTransportSecret != "" ||
		command.EnvelopeBase64URL != "" || command.EnvelopeSHA256 != "" ||
		command.ReceiptSHA256 != "" {
		return zero, fmt.Errorf("formal-cox control: invalid source command")
	}
	public, err := formalCoxControlDecodeStandard(
		command.RecipientTransportPublic, 32, "recipient transport public key")
	if err != nil {
		return zero, err
	}
	defer clear(public)
	signature, err := formalCoxControlDecodeStandard(
		command.RecipientTransportSignature, ed25519.SignatureSize,
		"recipient transport signature")
	if err != nil {
		return zero, err
	}
	defer clear(signature)
	store, err := formalCoxBlockwiseControlOpenCommandStore(
		command, context, stateRoot, production)
	if err != nil {
		return zero, err
	}
	defer store.Close()
	return store.DescribeNextSource(public, signature, now)
}

func formalCoxBlockwiseControlRunImportAtRoot(encoded []byte,
	stateRoot string, production bool, now time.Time,
) (formalCoxBlockwiseControlIngressReceipt, error) {
	var zero formalCoxBlockwiseControlIngressReceipt
	command, context, err := formalCoxBlockwiseControlDecodeCommand(encoded)
	if err != nil || command.RecipientTransportPublic != "" ||
		command.RecipientTransportSignature != "" ||
		command.RecipientTransportSecret == "" ||
		command.EnvelopeBase64URL == "" || command.EnvelopeSHA256 != "" ||
		command.ReceiptSHA256 != "" || len(command.EnvelopeBase64URL) >
		((formalCoxControlMaxEnvelopeJSON+2)/3)*4 {
		return zero, fmt.Errorf("formal-cox control: invalid import command")
	}
	secret, err := formalCoxControlDecodeStandard(
		command.RecipientTransportSecret, 32, "recipient transport secret")
	if err != nil {
		return zero, err
	}
	defer clear(secret)
	envelope, err := base64.RawURLEncoding.Strict().DecodeString(
		command.EnvelopeBase64URL)
	if err != nil || len(envelope) < 64 ||
		len(envelope) > formalCoxControlMaxEnvelopeJSON ||
		base64.RawURLEncoding.EncodeToString(envelope) !=
			command.EnvelopeBase64URL {
		clear(envelope)
		return zero, fmt.Errorf("formal-cox control: invalid import envelope")
	}
	defer clear(envelope)
	store, err := formalCoxBlockwiseControlOpenCommandStore(
		command, context, stateRoot, production)
	if err != nil {
		return zero, err
	}
	defer store.Close()
	return store.ImportCanonical(envelope, secret, now)
}

func formalCoxBlockwiseControlRunDeliveryAtRoot(encoded []byte,
	stateRoot string, production bool, now time.Time,
) (formalCoxBlockwiseControlDeliveryReceipt, error) {
	var zero formalCoxBlockwiseControlDeliveryReceipt
	command, context, err := formalCoxBlockwiseControlDecodeCommand(encoded)
	if err != nil || command.RecipientTransportPublic != "" ||
		command.RecipientTransportSignature != "" ||
		command.RecipientTransportSecret != "" ||
		command.EnvelopeBase64URL != "" ||
		!formalCoxIsSHA256(command.EnvelopeSHA256) ||
		!formalCoxIsSHA256(command.ReceiptSHA256) {
		return zero, fmt.Errorf("formal-cox control: invalid delivery command")
	}
	store, err := formalCoxBlockwiseControlOpenCommandStore(
		command, context, stateRoot, production)
	if err != nil {
		return zero, err
	}
	defer store.Close()
	return store.MarkNextDelivered(
		command.EnvelopeSHA256, command.ReceiptSHA256, now)
}

func formalCoxBlockwiseControlReadCommand() ([]byte, error) {
	encoded, err := io.ReadAll(io.LimitReader(
		os.Stdin, int64(formalCoxControlCommandMax)+1))
	if err != nil || len(encoded) > formalCoxControlCommandMax {
		clear(encoded)
		return nil, fmt.Errorf("formal-cox control: invalid command input")
	}
	return encoded, nil
}

func handleFormalCoxBlockwiseControlSource() {
	encoded, err := formalCoxBlockwiseControlReadCommand()
	if err != nil {
		outputError("Formal Cox control source failed")
		return
	}
	defer clear(encoded)
	value, err := formalCoxBlockwiseControlRunSourceAtRoot(
		encoded, formalFinalizerHandoffStateRoot, true, time.Now())
	if err != nil {
		outputError("Formal Cox control source failed")
		return
	}
	output(value)
}

func handleFormalCoxBlockwiseControlImport() {
	encoded, err := formalCoxBlockwiseControlReadCommand()
	if err != nil {
		outputError("Formal Cox control import failed")
		return
	}
	defer clear(encoded)
	value, err := formalCoxBlockwiseControlRunImportAtRoot(
		encoded, formalFinalizerHandoffStateRoot, true, time.Now())
	if err != nil {
		outputError("Formal Cox control import failed")
		return
	}
	output(value)
}

func handleFormalCoxBlockwiseControlDelivery() {
	encoded, err := formalCoxBlockwiseControlReadCommand()
	if err != nil {
		outputError("Formal Cox control delivery failed")
		return
	}
	defer clear(encoded)
	value, err := formalCoxBlockwiseControlRunDeliveryAtRoot(
		encoded, formalFinalizerHandoffStateRoot, true, time.Now())
	if err != nil {
		outputError("Formal Cox control delivery failed")
		return
	}
	output(value)
}
