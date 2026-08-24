package main

// Closed R-to-Go ingress for one registered formal-GLM Phase18 source block.
// It receives only canonical, server-local inputs and writes encrypted pairs
// or recipient-local pending records under Rock.  It is deliberately not a
// DataSHIELD command and never returns plaintext values, validity bits,
// consensus bytes, private keys, paths, or openings.

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
	"reflect"
)

const (
	formalGLMRegisteredPhase18SourceCommandVersionV1 = "dsvert-formal-glm-registered-phase18-source-command-v1"
	formalGLMRegisteredPhase18SourceCommandDomainV1  = "dsVert/formal-glm/registered-phase18/source-command/v1"
	formalGLMRegisteredPhase18SourceCommandMaxV1     = 32 << 20

	formalGLMRegisteredPhase18SourceCommandActionTicketV1    = "ticket"
	formalGLMRegisteredPhase18SourceCommandActionTicketSetV1 = "ticket_set"
	formalGLMRegisteredPhase18SourceCommandActionProduceV1   = "produce"
	formalGLMRegisteredPhase18SourceCommandActionImportV1    = "import"
)

type formalGLMRegisteredPhase18SourceCommandV1 struct {
	Version            string                                        `json:"version"`
	Action             string                                        `json:"action"`
	SourceContractJSON string                                        `json:"source_contract_json"`
	Pins               map[string]string                             `json:"pins"`
	LocalPeerName      string                                        `json:"local_peer_name"`
	LocalSigningKey    string                                        `json:"local_signing_key"`
	AuthorizationJSON  string                                        `json:"authorization_json,omitempty"`
	RecipientTickets   []formalGLMRegisteredPhase18RecipientTicketV1 `json:"recipient_tickets,omitempty"`
	BlockIndex         int                                           `json:"block_index,omitempty"`
	Values             []string                                      `json:"values,omitempty"`
	Validity           []bool                                        `json:"validity,omitempty"`
	PrivateConsensus   string                                        `json:"private_consensus,omitempty"`
	PairJSON           string                                        `json:"pair_json,omitempty"`
}

type formalGLMRegisteredPhase18SourceCommandResponseV1 struct {
	Version        string                                               `json:"version"`
	Ticket         *formalGLMRegisteredPhase18RecipientTicketV1         `json:"ticket,omitempty"`
	TicketReceipts []formalGLMRegisteredPhase18RecipientTicketReceiptV1 `json:"ticket_receipts,omitempty"`
	SourceReceipt  *formalGLMRegisteredPhase18SourceOutboxReceiptV3     `json:"source_receipt,omitempty"`
	PendingReceipt *formalGLMRegisteredPhase18PendingPairReceiptV1      `json:"pending_receipt,omitempty"`
	PairJSON       string                                               `json:"pair_json,omitempty"`
	Replayed       bool                                                 `json:"replayed"`
}

func formalGLMRegisteredPhase18SourceCommandDecodePinsV1(
	encoded map[string]string,
) (map[string]ed25519.PublicKey, error) {
	if len(encoded) < 2 || len(encoded) > 64 {
		return nil, fmt.Errorf("formal-glm registered Phase18 source: invalid pins")
	}
	pins := make(map[string]ed25519.PublicKey, len(encoded))
	for peer, value := range encoded {
		if !formalGLMRegistryLabelV1(peer, 128) {
			return nil, fmt.Errorf("formal-glm registered Phase18 source: invalid pins")
		}
		pin, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(pin) != ed25519.PublicKeySize ||
			base64.StdEncoding.EncodeToString(pin) != value {
			clear(pin)
			return nil, fmt.Errorf("formal-glm registered Phase18 source: invalid pins")
		}
		pins[peer] = ed25519.PublicKey(pin)
	}
	if _, err := formalGLMPhase16PinsetSHA256(pins); err != nil {
		for peer := range pins {
			clear(pins[peer])
			delete(pins, peer)
		}
		return nil, fmt.Errorf("formal-glm registered Phase18 source: invalid pins")
	}
	return pins, nil
}

func formalGLMRegisteredPhase18SourceCommandClearPinsV1(
	pins map[string]ed25519.PublicKey,
) {
	for peer := range pins {
		clear(pins[peer])
		delete(pins, peer)
	}
}

func formalGLMRegisteredPhase18SourceCommandDecodeSigningKeyV1(
	encoded, peer string, pins map[string]ed25519.PublicKey,
) (ed25519.PrivateKey, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != ed25519.PrivateKeySize ||
		base64.StdEncoding.EncodeToString(key) != encoded ||
		len(pins[peer]) != ed25519.PublicKeySize ||
		!bytes.Equal(ed25519.PrivateKey(key).Public().(ed25519.PublicKey), pins[peer]) {
		clear(key)
		return nil, fmt.Errorf("formal-glm registered Phase18 source: invalid local signer")
	}
	return ed25519.PrivateKey(key), nil
}

func formalGLMRegisteredPhase18SourceCommandDecodeV1(
	encoded []byte,
) (formalGLMRegisteredPhase18SourceCommandV1, error) {
	var command formalGLMRegisteredPhase18SourceCommandV1
	if len(encoded) < 2 || len(encoded) > formalGLMRegisteredPhase18SourceCommandMaxV1 ||
		encoded[0] != '{' {
		return command, fmt.Errorf("formal-glm registered Phase18 source: invalid command")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&command); err != nil {
		return formalGLMRegisteredPhase18SourceCommandV1{}, fmt.Errorf("formal-glm registered Phase18 source: invalid command")
	}
	var trailing any
	canonical, err := json.Marshal(command)
	if err != nil || decoder.Decode(&trailing) != io.EOF ||
		!bytes.Equal(canonical, encoded) ||
		command.Version != formalGLMRegisteredPhase18SourceCommandVersionV1 ||
		!formalGLMRegistryLabelV1(command.LocalPeerName, 128) ||
		command.SourceContractJSON == "" || command.LocalSigningKey == "" {
		clear(canonical)
		return formalGLMRegisteredPhase18SourceCommandV1{}, fmt.Errorf("formal-glm registered Phase18 source: non-canonical command")
	}
	clear(canonical)
	switch command.Action {
	case formalGLMRegisteredPhase18SourceCommandActionTicketV1:
		if command.AuthorizationJSON != "" || len(command.RecipientTickets) != 0 ||
			command.BlockIndex != 0 || len(command.Values) != 0 || len(command.Validity) != 0 ||
			command.PrivateConsensus != "" || command.PairJSON != "" {
			return formalGLMRegisteredPhase18SourceCommandV1{}, fmt.Errorf("formal-glm registered Phase18 source: invalid ticket command")
		}
	case formalGLMRegisteredPhase18SourceCommandActionTicketSetV1:
		if len(command.RecipientTickets) != 2 || command.AuthorizationJSON != "" ||
			command.BlockIndex != 0 || len(command.Values) != 0 || len(command.Validity) != 0 ||
			command.PrivateConsensus != "" || command.PairJSON != "" {
			return formalGLMRegisteredPhase18SourceCommandV1{}, fmt.Errorf("formal-glm registered Phase18 source: invalid ticket set command")
		}
	case formalGLMRegisteredPhase18SourceCommandActionProduceV1:
		if command.AuthorizationJSON == "" || len(command.RecipientTickets) != 2 ||
			command.BlockIndex < 0 || len(command.Values) == 0 || len(command.Validity) == 0 ||
			command.PrivateConsensus == "" || command.PairJSON != "" {
			return formalGLMRegisteredPhase18SourceCommandV1{}, fmt.Errorf("formal-glm registered Phase18 source: invalid produce command")
		}
	case formalGLMRegisteredPhase18SourceCommandActionImportV1:
		if len(command.RecipientTickets) != 2 || command.AuthorizationJSON != "" ||
			command.BlockIndex != 0 || len(command.Values) != 0 || len(command.Validity) != 0 ||
			command.PrivateConsensus != "" || command.PairJSON == "" {
			return formalGLMRegisteredPhase18SourceCommandV1{}, fmt.Errorf("formal-glm registered Phase18 source: invalid import command")
		}
	default:
		return formalGLMRegisteredPhase18SourceCommandV1{}, fmt.Errorf("formal-glm registered Phase18 source: unknown action")
	}
	return command, nil
}

func formalGLMRegisteredPhase18SourceCommandContextV1(
	command formalGLMRegisteredPhase18SourceCommandV1,
) (formalGLMSourceContractV1, map[string]ed25519.PublicKey, ed25519.PrivateKey, func(), error) {
	pins, err := formalGLMRegisteredPhase18SourceCommandDecodePinsV1(command.Pins)
	if err != nil {
		return formalGLMSourceContractV1{}, nil, nil, func() {}, err
	}
	contract, err := formalGLMDecodeSourceContractV1([]byte(command.SourceContractJSON), pins)
	if err != nil {
		formalGLMRegisteredPhase18SourceCommandClearPinsV1(pins)
		return formalGLMSourceContractV1{}, nil, nil, func() {}, err
	}
	key, err := formalGLMRegisteredPhase18SourceCommandDecodeSigningKeyV1(
		command.LocalSigningKey, command.LocalPeerName, pins)
	if err != nil {
		formalGLMRegisteredPhase18SourceCommandClearPinsV1(pins)
		return formalGLMSourceContractV1{}, nil, nil, func() {}, err
	}
	clearContext := func() {
		clear(key)
		formalGLMRegisteredPhase18SourceCommandClearPinsV1(pins)
		contract = formalGLMSourceContractV1{}
	}
	return contract, pins, key, clearContext, nil
}

func formalGLMRegisteredPhase18SourceCommandOutboxKeyV1(
	key ed25519.PrivateKey, contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
) ([32]byte, error) {
	var output [32]byte
	contractSHA256, err := formalGLMSourceContractSHA256V1(contract)
	if err != nil || len(key) != ed25519.PrivateKeySize ||
		authorization.SourceContractSHA256 != contractSHA256 ||
		authorization.LocalSource.SignerPeerName == "" {
		return output, fmt.Errorf("formal-glm registered Phase18 source: invalid outbox key context")
	}
	seed := key.Seed()
	defer clear(seed)
	mac := hmac.New(sha256.New, seed)
	_, _ = mac.Write([]byte(formalGLMRegisteredPhase18SourceCommandDomainV1 + "/outbox|"))
	_, _ = mac.Write([]byte(contractSHA256 + "|" + authorization.AuthorizationSHA256 + "|" + authorization.LocalSource.SignerPeerName))
	copy(output[:], mac.Sum(nil))
	if !formalGLMPhase19KeyValid(output) {
		clear(output[:])
		return output, fmt.Errorf("formal-glm registered Phase18 source: invalid outbox key")
	}
	return output, nil
}

func formalGLMRegisteredPhase18SourceCommandTicketV1(
	rockRoot string, contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey, peer string, key ed25519.PrivateKey,
) (formalGLMRegisteredPhase18SourceCommandResponseV1, error) {
	var zero formalGLMRegisteredPhase18SourceCommandResponseV1
	provider, err := newFormalGLMRegisteredPhase19PairKeyProviderV1(rockRoot, peer, contract, pins)
	if err != nil {
		return zero, err
	}
	defer provider.Close()
	transportPK, err := provider.PublicKeyV1()
	if err != nil {
		return zero, err
	}
	defer clear(transportPK)
	ticket, err := formalGLMRegisteredPhase18BuildRecipientTicketV1(contract, peer, transportPK, pins)
	if err != nil {
		return zero, err
	}
	ticket, err = formalGLMRegisteredPhase18SignRecipientTicketV1(ticket, contract, key, pins)
	if err != nil {
		return zero, err
	}
	store, err := newFormalGLMRegisteredPhase18RecipientTicketStoreV1(rockRoot, contract, pins)
	if err != nil {
		return zero, err
	}
	defer store.Close()
	_, replayed, err := store.Commit(ticket)
	if err != nil {
		return zero, err
	}
	return formalGLMRegisteredPhase18SourceCommandResponseV1{
		Version: formalGLMRegisteredPhase18SourceCommandVersionV1,
		Ticket:  &ticket, Replayed: replayed,
	}, nil
}

func formalGLMRegisteredPhase18SourceCommandTicketSetV1(
	rockRoot string, contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey, peer string, key ed25519.PrivateKey,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
) (formalGLMRegisteredPhase18SourceCommandResponseV1, error) {
	var zero formalGLMRegisteredPhase18SourceCommandResponseV1
	ordered, err := formalGLMRegisteredPhase18CanonicalTicketsV1(tickets, contract, pins)
	if err != nil {
		return zero, err
	}
	if !reflect.DeepEqual(tickets, ordered) {
		return zero, fmt.Errorf("formal-glm registered Phase18 source: non-canonical ticket set")
	}
	provider, err := newFormalGLMRegisteredPhase19PairKeyProviderV1(rockRoot, peer, contract, pins)
	if err != nil {
		return zero, err
	}
	defer provider.Close()
	transportPK, err := provider.PublicKeyV1()
	if err != nil {
		return zero, err
	}
	defer clear(transportPK)
	local := -1
	for index, candidate := range ordered {
		if candidate.RecipientName == peer {
			local = index
		}
	}
	if local < 0 || !bytes.Equal(ordered[local].TransportPK, transportPK) ||
		!bytes.Equal(key.Public().(ed25519.PublicKey), pins[peer]) {
		return zero, fmt.Errorf("formal-glm registered Phase18 source: local ticket mismatch")
	}
	store, err := newFormalGLMRegisteredPhase18RecipientTicketStoreV1(rockRoot, contract, pins)
	if err != nil {
		return zero, err
	}
	defer store.Close()
	receipts := make([]formalGLMRegisteredPhase18RecipientTicketReceiptV1, len(ordered))
	replayed := true
	for index, ticket := range ordered {
		receipt, replay, commitErr := store.Commit(ticket)
		if commitErr != nil {
			return zero, commitErr
		}
		receipts[index] = receipt
		replayed = replayed && replay
	}
	loaded, err := store.LoadSet()
	if err != nil || !reflect.DeepEqual(loaded, ordered) {
		return zero, fmt.Errorf("formal-glm registered Phase18 source: ticket set persistence failed")
	}
	return formalGLMRegisteredPhase18SourceCommandResponseV1{
		Version:        formalGLMRegisteredPhase18SourceCommandVersionV1,
		TicketReceipts: receipts, Replayed: replayed,
	}, nil
}

func formalGLMRegisteredPhase18SourceCommandAuthorizationV1(
	encoded string, contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey, peer string,
) (formalGLMRegisteredPhase18AuthorizationV1, error) {
	authorization, err := formalGLMDecodeRegisteredPhase18AuthorizationV1([]byte(encoded), contract, pins)
	if err != nil || authorization.LocalSource.SignerPeerName != peer {
		return formalGLMRegisteredPhase18AuthorizationV1{}, fmt.Errorf("formal-glm registered Phase18 source: invalid local authorization")
	}
	return authorization, nil
}

func formalGLMRegisteredPhase18SourceCommandProduceV1(
	rockRoot string, command formalGLMRegisteredPhase18SourceCommandV1,
	contract formalGLMSourceContractV1, pins map[string]ed25519.PublicKey,
	key ed25519.PrivateKey,
) (formalGLMRegisteredPhase18SourceCommandResponseV1, error) {
	var zero formalGLMRegisteredPhase18SourceCommandResponseV1
	authorization, err := formalGLMRegisteredPhase18SourceCommandAuthorizationV1(
		command.AuthorizationJSON, contract, pins, command.LocalPeerName)
	if err != nil {
		return zero, err
	}
	ordered, err := formalGLMRegisteredPhase18CanonicalTicketsV1(
		command.RecipientTickets, contract, pins)
	if err != nil || !reflect.DeepEqual(command.RecipientTickets, ordered) {
		return zero, fmt.Errorf("formal-glm registered Phase18 source: non-canonical ticket set")
	}
	consensus, err := base64.StdEncoding.Strict().DecodeString(command.PrivateConsensus)
	if err != nil || len(consensus) != sha256.Size ||
		base64.StdEncoding.EncodeToString(consensus) != command.PrivateConsensus {
		clear(consensus)
		return zero, fmt.Errorf("formal-glm registered Phase18 source: invalid private consensus")
	}
	defer clear(consensus)
	outboxKey, err := formalGLMRegisteredPhase18SourceCommandOutboxKeyV1(key, contract, authorization)
	if err != nil {
		return zero, err
	}
	defer clear(outboxKey[:])
	outbox, err := newFormalGLMRegisteredPhase18SourceOutboxV3(
		rockRoot, contract, command.LocalPeerName, key, outboxKey, pins)
	if err != nil {
		return zero, err
	}
	defer outbox.Close()
	receipt, pairJSON, replayed, err := outbox.CommitBlock(
		authorization, ordered, command.BlockIndex,
		command.Values, command.Validity, consensus)
	if err != nil {
		return zero, err
	}
	defer clear(pairJSON)
	return formalGLMRegisteredPhase18SourceCommandResponseV1{
		Version:       formalGLMRegisteredPhase18SourceCommandVersionV1,
		SourceReceipt: &receipt, PairJSON: string(pairJSON), Replayed: replayed,
	}, nil
}

func formalGLMRegisteredPhase18SourceCommandImportV1(
	rockRoot string, command formalGLMRegisteredPhase18SourceCommandV1,
	contract formalGLMSourceContractV1, pins map[string]ed25519.PublicKey,
	key ed25519.PrivateKey,
) (formalGLMRegisteredPhase18SourceCommandResponseV1, error) {
	var zero formalGLMRegisteredPhase18SourceCommandResponseV1
	if !bytes.Equal(key.Public().(ed25519.PublicKey), pins[command.LocalPeerName]) {
		return zero, fmt.Errorf("formal-glm registered Phase18 source: invalid local importer")
	}
	store, err := newFormalGLMRegisteredPhase18RecipientTicketStoreV1(rockRoot, contract, pins)
	if err != nil {
		return zero, err
	}
	defer store.Close()
	ordered, err := formalGLMRegisteredPhase18CanonicalTicketsV1(
		command.RecipientTickets, contract, pins)
	if err != nil || !reflect.DeepEqual(command.RecipientTickets, ordered) {
		return zero, fmt.Errorf("formal-glm registered Phase18 source: non-canonical ticket set")
	}
	loaded, err := store.LoadSet()
	if err != nil || !reflect.DeepEqual(loaded, ordered) {
		return zero, fmt.Errorf("formal-glm registered Phase18 source: ticket set mismatch")
	}
	pending, err := newFormalGLMRegisteredPhase18PendingPairStoreV1(
		rockRoot, command.LocalPeerName, contract, pins, store)
	if err != nil {
		return zero, err
	}
	defer pending.Close()
	receipt, replayed, err := pending.CommitPair([]byte(command.PairJSON))
	if err != nil {
		return zero, err
	}
	return formalGLMRegisteredPhase18SourceCommandResponseV1{
		Version:        formalGLMRegisteredPhase18SourceCommandVersionV1,
		PendingReceipt: &receipt, Replayed: replayed,
	}, nil
}

func formalGLMRegisteredPhase18SourceCommandRunAtRootV1(
	encoded []byte, rockRoot string,
) (formalGLMRegisteredPhase18SourceCommandResponseV1, error) {
	var zero formalGLMRegisteredPhase18SourceCommandResponseV1
	command, err := formalGLMRegisteredPhase18SourceCommandDecodeV1(encoded)
	if err != nil {
		return zero, err
	}
	contract, pins, key, clearContext, err := formalGLMRegisteredPhase18SourceCommandContextV1(command)
	if err != nil {
		return zero, err
	}
	defer clearContext()
	switch command.Action {
	case formalGLMRegisteredPhase18SourceCommandActionTicketV1:
		return formalGLMRegisteredPhase18SourceCommandTicketV1(rockRoot, contract, pins, command.LocalPeerName, key)
	case formalGLMRegisteredPhase18SourceCommandActionTicketSetV1:
		return formalGLMRegisteredPhase18SourceCommandTicketSetV1(rockRoot, contract, pins, command.LocalPeerName, key, command.RecipientTickets)
	case formalGLMRegisteredPhase18SourceCommandActionProduceV1:
		return formalGLMRegisteredPhase18SourceCommandProduceV1(rockRoot, command, contract, pins, key)
	case formalGLMRegisteredPhase18SourceCommandActionImportV1:
		return formalGLMRegisteredPhase18SourceCommandImportV1(rockRoot, command, contract, pins, key)
	default:
		return zero, fmt.Errorf("formal-glm registered Phase18 source: unknown action")
	}
}

func formalGLMRegisteredPhase18SourceCommandReadV1() ([]byte, error) {
	encoded, err := io.ReadAll(io.LimitReader(os.Stdin, formalGLMRegisteredPhase18SourceCommandMaxV1+1))
	if err != nil || len(encoded) > formalGLMRegisteredPhase18SourceCommandMaxV1 {
		clear(encoded)
		return nil, fmt.Errorf("formal-glm registered Phase18 source: invalid command input")
	}
	return encoded, nil
}

func handleFormalGLMRegisteredPhase18SourceCommandV1() {
	encoded, err := formalGLMRegisteredPhase18SourceCommandReadV1()
	if err != nil {
		mpcFatalError("formal-glm registered Phase18 source failed")
	}
	defer clear(encoded)
	response, err := formalGLMRegisteredPhase18SourceCommandRunAtRootV1(encoded, formalFinalizerHandoffStateRoot)
	if err != nil {
		mpcFatalError("formal-glm registered Phase18 source failed")
	}
	output(response)
}
