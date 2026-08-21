package main

// Closed local command that returns one already-committed, recipient-encrypted
// Cox source envelope. It derives the producer's Rock slot from the signed
// schema and local source key; it neither accepts a filesystem selector nor
// decrypts a recipient share.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const (
	formalCoxBlockwiseSourceDeliveryCommandVersion = "dsvert-formal-cox-blockwise-source-delivery-command-v1"
	formalCoxBlockwiseSourceDeliveryCommandMax     = 16 << 20
)

type formalCoxBlockwiseSourceDeliveryCommand struct {
	Version           string                                    `json:"version"`
	Schema            json.RawMessage                           `json:"schema"`
	BlockCapacity     int                                       `json:"block_capacity"`
	RunID             string                                    `json:"run_id"`
	Pins              map[string]string                         `json:"pins"`
	RecipientTickets  []formalCoxBlockwiseSourceRecipientTicket `json:"recipient_tickets"`
	SourcePeerName    string                                    `json:"source_peer_name"`
	SourceSigningKey  string                                    `json:"source_signing_key"`
	BlockIndex        int                                       `json:"block_index"`
	RecipientPeerName string                                    `json:"recipient_peer_name"`
}

func formalCoxBlockwiseSourceDeliveryDecodeCommand(
	encoded []byte,
) (formalCoxBlockwiseSourceDeliveryCommand, error) {
	var command formalCoxBlockwiseSourceDeliveryCommand
	if len(encoded) < 2 || len(encoded) > formalCoxBlockwiseSourceDeliveryCommandMax ||
		encoded[0] != '{' {
		return command, fmt.Errorf("formal-cox source delivery: invalid command")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&command); err != nil {
		return formalCoxBlockwiseSourceDeliveryCommand{},
			fmt.Errorf("formal-cox source delivery: invalid command")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF ||
		command.Version != formalCoxBlockwiseSourceDeliveryCommandVersion ||
		!formalCoxCompilerRLabel(command.SourcePeerName) ||
		!formalCoxCompilerRLabel(command.RecipientPeerName) ||
		len(command.Schema) == 0 || command.BlockCapacity < 1 ||
		!formalCoxIsSHA256(command.RunID) || command.BlockIndex < 0 ||
		command.SourceSigningKey == "" {
		return formalCoxBlockwiseSourceDeliveryCommand{},
			fmt.Errorf("formal-cox source delivery: non-canonical command")
	}
	return command, nil
}

func formalCoxBlockwiseSourceDeliveryOpen(
	command formalCoxBlockwiseSourceDeliveryCommand,
	stateRoot string, production bool,
) (*formalCoxBlockwiseSourceProducer, func(), error) {
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
	key, err := formalCoxBlockwiseSourceProducerCommandDecodeKey(
		command.SourceSigningKey)
	if err != nil {
		clearPins()
		return nil, nil, err
	}
	if pin := pins[command.SourcePeerName]; len(pin) != ed25519.PublicKeySize ||
		!hmac.Equal(key.Public().(ed25519.PublicKey), pin) {
		clear(key)
		clearPins()
		return nil, nil, fmt.Errorf("formal-cox source delivery: local signer is not pinned")
	}
	root, storageKey, err := formalCoxBlockwiseSourceProducerCommandRootFromKey(
		stateRoot, production, plan, command.SourcePeerName, key)
	if err != nil {
		clear(key)
		clearPins()
		return nil, nil, err
	}
	producer, err := newFormalCoxBlockwiseSourceProducer(
		root, storageKey, session, command.SourcePeerName, key)
	clear(storageKey[:])
	clear(key)
	if err != nil {
		clearPins()
		return nil, nil, err
	}
	return producer, func() {
		_ = producer.Close()
		clearPins()
	}, nil
}

func formalCoxBlockwiseSourceDeliveryRunAtRoot(
	encoded []byte, stateRoot string, production bool,
) (formalCoxBlockwiseSourceDelivery, error) {
	var zero formalCoxBlockwiseSourceDelivery
	command, err := formalCoxBlockwiseSourceDeliveryDecodeCommand(encoded)
	if err != nil {
		return zero, err
	}
	producer, closeProducer, err := formalCoxBlockwiseSourceDeliveryOpen(
		command, stateRoot, production)
	if err != nil {
		return zero, err
	}
	defer closeProducer()
	return producer.Delivery(command.BlockIndex, command.RecipientPeerName)
}

func formalCoxBlockwiseSourceDeliveryReadCommand() ([]byte, error) {
	encoded, err := io.ReadAll(io.LimitReader(
		os.Stdin, int64(formalCoxBlockwiseSourceDeliveryCommandMax)+1))
	if err != nil || len(encoded) > formalCoxBlockwiseSourceDeliveryCommandMax {
		clear(encoded)
		return nil, fmt.Errorf("formal-cox source delivery: invalid command input")
	}
	return encoded, nil
}

func handleFormalCoxBlockwiseSourceDelivery() {
	encoded, err := formalCoxBlockwiseSourceDeliveryReadCommand()
	if err != nil {
		mpcFatalError("formal Cox source delivery failed")
	}
	defer clear(encoded)
	delivery, err := formalCoxBlockwiseSourceDeliveryRunAtRoot(
		encoded, formalFinalizerHandoffStateRoot, true)
	if err != nil {
		mpcFatalError("formal Cox source delivery failed")
	}
	output(delivery)
}
