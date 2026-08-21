package main

// Closed local command for one signed formal-Cox source block.  It accepts
// only a fully signed recipient manifest and the local source owner's private
// key; all durable paths and storage keys are derived inside Rock.  This is a
// server-internal source seam, not a DSI or public Cox endpoint.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	formalCoxBlockwiseSourceProducerCommandVersion = "dsvert-formal-cox-blockwise-source-producer-command-v1"
	formalCoxBlockwiseSourceProducerCommandMax     = 16 << 20
	formalCoxBlockwiseSourceProducerCommandDomain  = "dsVert/formal-cox/blockwise-source-producer-command/v1"
)

type formalCoxBlockwiseSourceProducerCommand struct {
	Version              string                                    `json:"version"`
	Schema               json.RawMessage                           `json:"schema"`
	BlockCapacity        int                                       `json:"block_capacity"`
	RunID                string                                    `json:"run_id"`
	Pins                 map[string]string                         `json:"pins"`
	RecipientTickets     []formalCoxBlockwiseSourceRecipientTicket `json:"recipient_tickets"`
	SourcePeerName       string                                    `json:"source_peer_name"`
	SourceSigningKey     string                                    `json:"source_signing_key"`
	BlockIndex           int                                       `json:"block_index"`
	CanonicalInputBase64 string                                    `json:"canonical_input_base64"`
}

func formalCoxBlockwiseSourceProducerCommandDecodePins(
	encoded map[string]string,
) (map[string]ed25519.PublicKey, error) {
	if len(encoded) < 2 || len(encoded) > formalCoxPhase1MaxCustodians {
		return nil, fmt.Errorf("formal-cox source producer: invalid command pins")
	}
	pins := make(map[string]ed25519.PublicKey, len(encoded))
	seen := make(map[string]bool, len(encoded))
	for peer, value := range encoded {
		if !formalCoxCompilerRLabel(peer) || seen[value] {
			return nil, fmt.Errorf("formal-cox source producer: invalid command pins")
		}
		pin, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(pin) != ed25519.PublicKeySize ||
			base64.StdEncoding.EncodeToString(pin) != value {
			clear(pin)
			return nil, fmt.Errorf("formal-cox source producer: invalid command pins")
		}
		seen[value] = true
		pins[peer] = ed25519.PublicKey(pin)
	}
	return pins, nil
}

func formalCoxBlockwiseSourceProducerCommandDecodeKey(
	encoded string,
) (ed25519.PrivateKey, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != ed25519.PrivateKeySize ||
		base64.StdEncoding.EncodeToString(key) != encoded {
		clear(key)
		return nil, fmt.Errorf("formal-cox source producer: invalid local signing key")
	}
	return ed25519.PrivateKey(key), nil
}

func formalCoxBlockwiseSourceProducerDecodeCommand(
	encoded []byte,
) (formalCoxBlockwiseSourceProducerCommand, error) {
	var command formalCoxBlockwiseSourceProducerCommand
	if len(encoded) < 2 || len(encoded) > formalCoxBlockwiseSourceProducerCommandMax ||
		encoded[0] != '{' {
		return command, fmt.Errorf("formal-cox source producer: invalid command")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&command); err != nil {
		return formalCoxBlockwiseSourceProducerCommand{},
			fmt.Errorf("formal-cox source producer: invalid command")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF ||
		command.Version != formalCoxBlockwiseSourceProducerCommandVersion {
		return formalCoxBlockwiseSourceProducerCommand{},
			fmt.Errorf("formal-cox source producer: invalid command")
	}
	if !formalCoxCompilerRLabel(command.SourcePeerName) ||
		len(command.Schema) == 0 || command.BlockCapacity < 1 ||
		!formalCoxIsSHA256(command.RunID) || command.BlockIndex < 0 ||
		command.SourceSigningKey == "" ||
		command.CanonicalInputBase64 == "" {
		return formalCoxBlockwiseSourceProducerCommand{},
			fmt.Errorf("formal-cox source producer: non-canonical command")
	}
	return command, nil
}

func formalCoxBlockwiseSourceProducerCommandKey(
	plan formalCoxBlockwisePlan, source string, signingKey ed25519.PrivateKey,
) ([32]byte, string, error) {
	var zero [32]byte
	if !formalCoxCompilerRLabel(source) || len(signingKey) != ed25519.PrivateKeySize {
		return zero, "", fmt.Errorf("formal-cox source producer: invalid source key")
	}
	planSHA, err := formalCoxBlockwisePlanSHA256(plan)
	if err != nil {
		return zero, "", err
	}
	seed := signingKey.Seed()
	defer clear(seed)
	mac := hmac.New(sha256.New, seed)
	_, _ = mac.Write([]byte(formalCoxBlockwiseSourceProducerCommandDomain + "|"))
	_, _ = mac.Write([]byte(planSHA))
	_, _ = mac.Write([]byte("|" + source))
	copy(zero[:], mac.Sum(nil))
	return zero, planSHA, nil
}

func formalCoxBlockwiseSourceProducerCommandRootFromKey(
	stateRoot string, production bool, plan formalCoxBlockwisePlan,
	source string, signingKey ed25519.PrivateKey,
) (string, [32]byte, error) {
	var zero [32]byte
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot ||
		production && stateRoot != formalFinalizerHandoffStateRoot {
		return "", zero, fmt.Errorf("formal-cox source producer: invalid Rock state root")
	}
	key, planSHA, err := formalCoxBlockwiseSourceProducerCommandKey(
		plan, source, signingKey)
	if err != nil {
		return "", zero, err
	}
	for _, directory := range []string{
		stateRoot,
		filepath.Join(stateRoot, "formal-cox-blockwise-source-producer-v1"),
		filepath.Join(stateRoot, "formal-cox-blockwise-source-producer-v1", source),
		filepath.Join(stateRoot, "formal-cox-blockwise-source-producer-v1", source, planSHA),
	} {
		if err := formalCoxBlockwiseSourceEnsurePrivateDir(directory); err != nil {
			clear(key[:])
			return "", zero, err
		}
	}
	return filepath.Join(stateRoot, "formal-cox-blockwise-source-producer-v1",
		source, planSHA), key, nil
}

// formalCoxBlockwiseSourceProducerCommandRoot is retained for exact tests and
// performs the same strict private-key decoding as the command path.
func formalCoxBlockwiseSourceProducerCommandRoot(
	stateRoot string, production bool, plan formalCoxBlockwisePlan,
	source, encodedKey string,
) (string, [32]byte, error) {
	key, err := formalCoxBlockwiseSourceProducerCommandDecodeKey(encodedKey)
	if err != nil {
		return "", [32]byte{}, err
	}
	defer clear(key)
	return formalCoxBlockwiseSourceProducerCommandRootFromKey(
		stateRoot, production, plan, source, key)
}

func formalCoxBlockwiseSourceProducerCommandInput(
	encoded string, plan formalCoxBlockwisePlan,
) ([]byte, error) {
	if len(encoded) > ((formalCoxBlockwiseSourceProducerCommandMax+2)/3)*4 {
		return nil, fmt.Errorf("formal-cox source producer: source input is too large")
	}
	input, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(input) != encoded {
		clear(input)
		return nil, fmt.Errorf("formal-cox source producer: invalid source input")
	}
	maximum := int64(plan.BlockCapacity) * int64(plan.RowWidth) *
		(formalCoxBlockwiseSourceProducerTokenMax + 1)
	if maximum < 1 || int64(len(input)) > maximum {
		clear(input)
		return nil, fmt.Errorf("formal-cox source producer: source input exceeds fixed block geometry")
	}
	return input, nil
}

func formalCoxBlockwiseSourceProducerRunAtRoot(encoded []byte,
	stateRoot string, production bool,
) (formalCoxBlockwiseSourceProductionResult, error) {
	var zero formalCoxBlockwiseSourceProductionResult
	command, err := formalCoxBlockwiseSourceProducerDecodeCommand(encoded)
	if err != nil {
		return zero, err
	}
	compiled, err := formalCoxCompileSignedRSchema(command.Schema)
	if err != nil {
		return zero, err
	}
	plan, err := buildFormalCoxBlockwisePlan(
		compiled.Policy, command.BlockCapacity, command.RunID)
	if err != nil {
		return zero, err
	}
	pins, err := formalCoxBlockwiseSourceProducerCommandDecodePins(command.Pins)
	if err != nil {
		return zero, err
	}
	defer func() {
		for peer := range pins {
			clear(pins[peer])
		}
	}()
	context, err := newFormalCoxBlockwiseSourceContext(plan, pins)
	if err != nil {
		return zero, err
	}
	session, err := context.bindRecipientManifest(command.RecipientTickets)
	if err != nil {
		return zero, err
	}
	key, err := formalCoxBlockwiseSourceProducerCommandDecodeKey(command.SourceSigningKey)
	if err != nil {
		return zero, err
	}
	defer clear(key)
	if pin := pins[command.SourcePeerName]; len(pin) != ed25519.PublicKeySize ||
		!hmac.Equal(key.Public().(ed25519.PublicKey), pin) {
		return zero, fmt.Errorf("formal-cox source producer: local signer is not pinned")
	}
	binding, err := formalCoxBlockwiseSourceProductionBindingFor(
		session, command.SourcePeerName, command.BlockIndex)
	if err != nil {
		return zero, err
	}
	input, err := formalCoxBlockwiseSourceProducerCommandInput(
		command.CanonicalInputBase64, plan)
	if err != nil {
		return zero, err
	}
	defer clear(input)
	root, storageKey, err := formalCoxBlockwiseSourceProducerCommandRootFromKey(
		stateRoot, production, plan, command.SourcePeerName, key)
	if err != nil {
		return zero, err
	}
	defer clear(storageKey[:])
	producer, err := newFormalCoxBlockwiseSourceProducer(
		root, storageKey, session, command.SourcePeerName, key)
	if err != nil {
		return zero, err
	}
	defer producer.Close()
	return producer.ProduceBlock(binding, bytes.NewReader(input))
}

func formalCoxBlockwiseSourceProducerReadCommand() ([]byte, error) {
	encoded, err := io.ReadAll(io.LimitReader(
		os.Stdin, int64(formalCoxBlockwiseSourceProducerCommandMax)+1))
	if err != nil || len(encoded) > formalCoxBlockwiseSourceProducerCommandMax {
		clear(encoded)
		return nil, fmt.Errorf("formal-cox source producer: invalid command input")
	}
	return encoded, nil
}

func handleFormalCoxBlockwiseSourceProducer() {
	encoded, err := formalCoxBlockwiseSourceProducerReadCommand()
	if err != nil {
		mpcFatalError("formal Cox source producer failed")
	}
	defer clear(encoded)
	result, err := formalCoxBlockwiseSourceProducerRunAtRoot(
		encoded, formalFinalizerHandoffStateRoot, true)
	if err != nil {
		mpcFatalError("formal Cox source producer failed")
	}
	output(result)
}
