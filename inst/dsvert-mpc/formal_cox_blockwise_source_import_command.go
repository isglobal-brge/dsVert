package main

// Closed local command that imports one recipient-encrypted Cox source
// envelope. The receiving peer authenticates with its local identity; Go
// reopens the matching Rock-local X25519 key before deriving the source slot.
// This is an internal ingress seam, not a DSI or public Cox endpoint.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	formalCoxBlockwiseSourceImportCommandVersion = "dsvert-formal-cox-blockwise-source-import-command-v2"
	formalCoxBlockwiseSourceImportReceiptVersion = "dsvert-formal-cox-blockwise-source-import-receipt-v1"
	formalCoxBlockwiseSourceImportCommandMax     = 16 << 20
	formalCoxBlockwiseSourceImportCommandDomain  = "dsVert/formal-cox/blockwise-source-import-command/v2"
)

type formalCoxBlockwiseSourceImportCommand struct {
	Version             string                                    `json:"version"`
	Schema              json.RawMessage                           `json:"schema"`
	BlockCapacity       int                                       `json:"block_capacity"`
	RunID               string                                    `json:"run_id"`
	Pins                map[string]string                         `json:"pins"`
	RecipientTickets    []formalCoxBlockwiseSourceRecipientTicket `json:"recipient_tickets"`
	RecipientPeerName   string                                    `json:"recipient_peer_name"`
	RecipientSigningKey string                                    `json:"recipient_signing_key"`
	Delivery            formalCoxBlockwiseSourceDelivery          `json:"delivery"`
}

type formalCoxBlockwiseSourceImportReceipt struct {
	Version           string `json:"version"`
	Purpose           string `json:"purpose"`
	ReceiptSHA256     string `json:"receipt_sha256"`
	RecipientPeerName string `json:"recipient_peer_name"`
	Replayed          bool   `json:"replayed"`
}

func formalCoxBlockwiseSourceImportDecodeCommand(
	encoded []byte,
) (formalCoxBlockwiseSourceImportCommand, error) {
	var command formalCoxBlockwiseSourceImportCommand
	if len(encoded) < 2 || len(encoded) > formalCoxBlockwiseSourceImportCommandMax ||
		encoded[0] != '{' {
		return command, fmt.Errorf("formal-cox source import: invalid command")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&command); err != nil {
		return formalCoxBlockwiseSourceImportCommand{},
			fmt.Errorf("formal-cox source import: invalid command")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF ||
		command.Version != formalCoxBlockwiseSourceImportCommandVersion ||
		!formalCoxCompilerRLabel(command.RecipientPeerName) ||
		len(command.Schema) == 0 || command.BlockCapacity < 1 ||
		!formalCoxIsSHA256(command.RunID) ||
		command.RecipientSigningKey == "" {
		return formalCoxBlockwiseSourceImportCommand{},
			fmt.Errorf("formal-cox source import: non-canonical command")
	}
	return command, nil
}

func formalCoxBlockwiseSourceImportCommandKey(
	plan formalCoxBlockwisePlan, recipient string, secret []byte,
) ([32]byte, string, error) {
	var zero [32]byte
	if !formalCoxCompilerRLabel(recipient) || len(secret) != 32 {
		return zero, "", fmt.Errorf("formal-cox source import: invalid recipient key")
	}
	planSHA, err := formalCoxBlockwisePlanSHA256(plan)
	if err != nil {
		return zero, "", err
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(formalCoxBlockwiseSourceImportCommandDomain + "|"))
	_, _ = mac.Write([]byte(planSHA))
	_, _ = mac.Write([]byte("|" + recipient))
	copy(zero[:], mac.Sum(nil))
	return zero, planSHA, nil
}

func formalCoxBlockwiseSourceImportCommandRoot(
	stateRoot string, production bool, plan formalCoxBlockwisePlan,
	recipient string, secret []byte,
) (string, [32]byte, error) {
	var zero [32]byte
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot ||
		production && stateRoot != formalFinalizerHandoffStateRoot {
		return "", zero, fmt.Errorf("formal-cox source import: invalid Rock state root")
	}
	key, planSHA, err := formalCoxBlockwiseSourceImportCommandKey(
		plan, recipient, secret)
	if err != nil {
		return "", zero, err
	}
	for _, directory := range []string{
		stateRoot,
		filepath.Join(stateRoot, "formal-cox-blockwise-source-recipient-v1"),
		filepath.Join(stateRoot, "formal-cox-blockwise-source-recipient-v1", recipient),
		filepath.Join(stateRoot, "formal-cox-blockwise-source-recipient-v1", recipient, planSHA),
	} {
		if err := formalCoxBlockwiseSourceEnsurePrivateDir(directory); err != nil {
			clear(key[:])
			return "", zero, err
		}
	}
	return filepath.Join(stateRoot, "formal-cox-blockwise-source-recipient-v1",
		recipient, planSHA), key, nil
}

func formalCoxBlockwiseSourceImportOpen(
	command formalCoxBlockwiseSourceImportCommand,
	stateRoot string, production bool,
) (*formalCoxBlockwiseSourceStore, func(), error) {
	compiled, err := formalCoxCompileSignedRSchema(command.Schema)
	if err != nil {
		return nil, nil, err
	}
	plan, err := buildFormalCoxBlockwisePlan(
		compiled.Policy, command.BlockCapacity, command.RunID)
	if err != nil {
		return nil, nil, err
	}
	pins, err := formalCoxBlockwiseSourceProducerCommandDecodePins(command.Pins)
	if err != nil {
		return nil, nil, err
	}
	clearPins := func() {
		for peer := range pins {
			clear(pins[peer])
		}
	}
	context, err := newFormalCoxBlockwiseSourceContext(plan, pins)
	if err != nil {
		clearPins()
		return nil, nil, err
	}
	session, err := context.bindRecipientManifest(command.RecipientTickets)
	if err != nil {
		clearPins()
		return nil, nil, err
	}
	if _, err := formalCoxBlockwiseSourceDeliveryRecipientIndex(
		session, command.RecipientPeerName); err != nil {
		clearPins()
		return nil, nil, err
	}
	canonical, err := command.Delivery.Encode(session)
	if err != nil {
		clearPins()
		return nil, nil, err
	}
	clear(canonical)
	signer, err := formalCoxBlockwiseSourceProducerCommandDecodeKey(
		command.RecipientSigningKey)
	if err != nil {
		clearPins()
		return nil, nil, err
	}
	defer clear(signer)
	provider, err := newFormalCoxBlockwiseSourceRecipientKeyProvider(
		stateRoot, production, context, command.RecipientPeerName, signer, false)
	if err != nil {
		clearPins()
		return nil, nil, err
	}
	defer provider.Close()
	secret, err := provider.secretForSessionV1(session)
	if err != nil {
		clearPins()
		return nil, nil, err
	}
	root, key, err := formalCoxBlockwiseSourceImportCommandRoot(
		stateRoot, production, plan, command.RecipientPeerName, secret[:])
	if err != nil {
		clear(secret[:])
		clearPins()
		return nil, nil, err
	}
	store, err := newFormalCoxBlockwiseSourceStore(
		root, key, session, command.RecipientPeerName, secret[:])
	clear(key[:])
	clear(secret[:])
	if err != nil {
		clearPins()
		return nil, nil, err
	}
	return store, func() {
		_ = store.Close()
		clearPins()
	}, nil
}

func formalCoxBlockwiseSourceImportRunAtRoot(
	encoded []byte, stateRoot string, production bool,
) (formalCoxBlockwiseSourceImportReceipt, error) {
	var zero formalCoxBlockwiseSourceImportReceipt
	command, err := formalCoxBlockwiseSourceImportDecodeCommand(encoded)
	if err != nil {
		return zero, err
	}
	store, closeStore, err := formalCoxBlockwiseSourceImportOpen(
		command, stateRoot, production)
	if err != nil {
		return zero, err
	}
	defer closeStore()
	canonical, err := command.Delivery.Encode(store.session)
	if err != nil {
		return zero, err
	}
	defer clear(canonical)
	replayed, err := store.AcceptDelivery(canonical)
	if err != nil {
		return zero, err
	}
	return formalCoxBlockwiseSourceImportReceipt{
		Version:           formalCoxBlockwiseSourceImportReceiptVersion,
		Purpose:           formalCoxBlockwiseSourceDeliveryPurpose,
		ReceiptSHA256:     command.Delivery.ReceiptSHA256,
		RecipientPeerName: command.RecipientPeerName,
		Replayed:          replayed,
	}, nil
}

func formalCoxBlockwiseSourceImportReadCommand() ([]byte, error) {
	encoded, err := io.ReadAll(io.LimitReader(
		os.Stdin, int64(formalCoxBlockwiseSourceImportCommandMax)+1))
	if err != nil || len(encoded) > formalCoxBlockwiseSourceImportCommandMax {
		clear(encoded)
		return nil, fmt.Errorf("formal-cox source import: invalid command input")
	}
	return encoded, nil
}

func handleFormalCoxBlockwiseSourceImport() {
	encoded, err := formalCoxBlockwiseSourceImportReadCommand()
	if err != nil {
		mpcFatalError("formal Cox source import failed")
	}
	defer clear(encoded)
	receipt, err := formalCoxBlockwiseSourceImportRunAtRoot(
		encoded, formalFinalizerHandoffStateRoot, true)
	if err != nil {
		mpcFatalError("formal Cox source import failed")
	}
	output(receipt)
}
