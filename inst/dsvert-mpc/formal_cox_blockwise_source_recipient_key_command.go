package main

// Closed Rock-local X25519 key issuance for a formal-Cox source recipient.
// The random private key remains in the recipient's Rock tree; only the
// signed public ticket can be handed to the source owner.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	formalCoxBlockwiseSourceRecipientKeyCommandVersion = "dsvert-formal-cox-blockwise-source-recipient-key-command-v1"
	formalCoxBlockwiseSourceRecipientKeyVersion        = "dsvert-formal-cox-blockwise-source-recipient-key-v1"
	formalCoxBlockwiseSourceRecipientKeyPurpose        = "formal-cox-rock-local-source-recipient-key-v1"
	formalCoxBlockwiseSourceRecipientKeyDomain         = "dsVert/formal-cox/blockwise-source-recipient-key/v1"
	formalCoxBlockwiseSourceRecipientKeyDir            = "formal-cox-blockwise-source-recipient-keys-v1"
	formalCoxBlockwiseSourceRecipientKeyFile           = "recipient-x25519.key"
	formalCoxBlockwiseSourceRecipientKeyBytes          = 64
	formalCoxBlockwiseSourceRecipientKeyMax            = 16 << 20
	formalCoxBlockwiseSourceRecipientKeyReadAttempts   = 32
)

type formalCoxBlockwiseSourceRecipientKeyCommand struct {
	Version             string            `json:"version"`
	Schema              json.RawMessage   `json:"schema"`
	BlockCapacity       int               `json:"block_capacity"`
	RunID               string            `json:"run_id"`
	Pins                map[string]string `json:"pins"`
	RecipientPeerName   string            `json:"recipient_peer_name"`
	RecipientSigningKey string            `json:"recipient_signing_key"`
}

type formalCoxBlockwiseSourceRecipientKeyBinding struct {
	Version           string `json:"version"`
	Purpose           string `json:"purpose"`
	PlanSHA256        string `json:"plan_sha256"`
	RunID             string `json:"run_id"`
	PinsetSHA256      string `json:"pinset_sha256"`
	RecipientPeerName string `json:"recipient_peer_name"`
	RecipientPeerID   string `json:"recipient_peer_id"`
	RecipientRole     string `json:"recipient_role"`
	SignerSHA256      string `json:"signer_sha256"`
}

type formalCoxBlockwiseSourceRecipientKeyProvider struct {
	dir       string
	path      string
	binding   [32]byte
	context   *formalCoxBlockwiseSourceContext
	recipient string
}

func formalCoxBlockwiseSourceRecipientKeyDigest(value any) ([32]byte, error) {
	var zero [32]byte
	encoded, err := json.Marshal(value)
	if err != nil {
		return zero, err
	}
	defer clear(encoded)
	digest := sha256.Sum256(append(
		[]byte(formalCoxBlockwiseSourceRecipientKeyDomain+"/binding|"), encoded...))
	if bytes.Equal(digest[:], make([]byte, len(digest))) {
		return zero, fmt.Errorf("formal-cox source recipient key: invalid binding")
	}
	return digest, nil
}

func formalCoxBlockwiseSourceRecipientKeyBindingFor(
	context *formalCoxBlockwiseSourceContext, recipient string,
	signer ed25519.PrivateKey,
) ([32]byte, error) {
	var zero [32]byte
	if context == nil || !formalCoxCompilerRLabel(recipient) ||
		len(signer) != ed25519.PrivateKeySize ||
		!formalCoxIsSHA256(context.planSHA256) ||
		!formalCoxIsSHA256(context.pinsetSHA256) ||
		!formalCoxIsSHA256(context.plan.RunID) ||
		context.peerIDs[recipient] == "" || context.roles[recipient] == "" {
		return zero, fmt.Errorf("formal-cox source recipient key: invalid binding")
	}
	pinned := context.pins[recipient]
	public := signer.Public().(ed25519.PublicKey)
	if len(pinned) != ed25519.PublicKeySize || !hmac.Equal(public, pinned) {
		return zero, fmt.Errorf("formal-cox source recipient key: signer is not pinned")
	}
	signerSHA := sha256.Sum256(public)
	return formalCoxBlockwiseSourceRecipientKeyDigest(
		formalCoxBlockwiseSourceRecipientKeyBinding{
			Version:           formalCoxBlockwiseSourceRecipientKeyVersion,
			Purpose:           formalCoxBlockwiseSourceRecipientKeyPurpose,
			PlanSHA256:        context.planSHA256,
			RunID:             context.plan.RunID,
			PinsetSHA256:      context.pinsetSHA256,
			RecipientPeerName: recipient,
			RecipientPeerID:   context.peerIDs[recipient],
			RecipientRole:     context.roles[recipient],
			SignerSHA256:      hex.EncodeToString(signerSHA[:]),
		})
}

func formalCoxBlockwiseSourceRecipientKeyPath(
	stateRoot string, production bool, context *formalCoxBlockwiseSourceContext,
	recipient string, create bool,
) (string, string, error) {
	if context == nil || !filepath.IsAbs(stateRoot) ||
		filepath.Clean(stateRoot) != stateRoot ||
		(production && stateRoot != formalFinalizerHandoffStateRoot) ||
		!formalCoxCompilerRLabel(recipient) || !formalCoxIsSHA256(context.planSHA256) {
		return "", "", fmt.Errorf("formal-cox source recipient key: invalid Rock state root")
	}
	directories := []string{
		stateRoot,
		filepath.Join(stateRoot, formalCoxBlockwiseSourceRecipientKeyDir),
		filepath.Join(stateRoot, formalCoxBlockwiseSourceRecipientKeyDir, recipient),
		filepath.Join(stateRoot, formalCoxBlockwiseSourceRecipientKeyDir, recipient,
			context.planSHA256),
	}
	for _, directory := range directories {
		if create {
			if err := formalCoxBlockwiseSourceEnsurePrivateDir(directory); err != nil {
				return "", "", err
			}
		} else {
			info, err := os.Lstat(directory)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
				info.Mode().Perm() != 0o700 ||
				!formalFinalizerHandoffPrivateOwnedDirectory(info) {
				return "", "", fmt.Errorf("formal-cox source recipient key: unavailable key directory")
			}
		}
	}
	directory := directories[len(directories)-1]
	return directory, filepath.Join(directory, formalCoxBlockwiseSourceRecipientKeyFile), nil
}

func formalCoxBlockwiseSourceRecipientKeyTag(secret, binding [32]byte) [32]byte {
	mac := hmac.New(sha256.New, secret[:])
	_, _ = mac.Write([]byte(formalCoxBlockwiseSourceRecipientKeyDomain + "/key-file|"))
	_, _ = mac.Write(binding[:])
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func newFormalCoxBlockwiseSourceRecipientKeyProvider(
	stateRoot string, production bool, context *formalCoxBlockwiseSourceContext,
	recipient string, signer ed25519.PrivateKey, create bool,
) (*formalCoxBlockwiseSourceRecipientKeyProvider, error) {
	binding, err := formalCoxBlockwiseSourceRecipientKeyBindingFor(
		context, recipient, signer)
	if err != nil {
		return nil, err
	}
	directory, path, err := formalCoxBlockwiseSourceRecipientKeyPath(
		stateRoot, production, context, recipient, create)
	if err != nil {
		clear(binding[:])
		return nil, err
	}
	provider := &formalCoxBlockwiseSourceRecipientKeyProvider{
		dir: directory, path: path, binding: binding, context: context,
		recipient: recipient,
	}
	var secret [32]byte
	if create {
		for attempt := 0; attempt < formalCoxBlockwiseSourceRecipientKeyReadAttempts; attempt++ {
			secret, err = provider.createOrReadV1()
			if err == nil {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
	} else {
		secret, err = provider.readV1()
	}
	clear(secret[:])
	if err != nil {
		provider.Close()
		return nil, fmt.Errorf("formal-cox source recipient key: durable key unavailable")
	}
	return provider, nil
}

func (provider *formalCoxBlockwiseSourceRecipientKeyProvider) readV1() ([32]byte, error) {
	var zero [32]byte
	if provider == nil || provider.path == "" ||
		bytes.Equal(provider.binding[:], make([]byte, len(provider.binding))) {
		return zero, fmt.Errorf("formal-cox source recipient key: provider is closed")
	}
	info, err := os.Lstat(provider.path)
	if err != nil {
		return zero, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 ||
		info.Size() != formalCoxBlockwiseSourceRecipientKeyBytes ||
		!exactGCPrivateOwnedRegular(info) {
		return zero, fmt.Errorf("formal-cox source recipient key: unsafe key file")
	}
	file, err := os.Open(provider.path)
	if err != nil {
		return zero, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, opened) ||
		!opened.Mode().IsRegular() || opened.Mode().Perm() != 0o600 ||
		opened.Size() != formalCoxBlockwiseSourceRecipientKeyBytes ||
		!exactGCPrivateOwnedRegular(opened) {
		_ = file.Close()
		return zero, fmt.Errorf("formal-cox source recipient key: unstable key file")
	}
	var record [formalCoxBlockwiseSourceRecipientKeyBytes]byte
	_, readErr := io.ReadFull(file, record[:])
	var extra [1]byte
	_, trailingErr := file.Read(extra[:])
	closeErr := file.Close()
	if readErr != nil || trailingErr != io.EOF || closeErr != nil {
		clear(record[:])
		return zero, fmt.Errorf("formal-cox source recipient key: invalid key file")
	}
	var secret, tag [32]byte
	copy(secret[:], record[:32])
	copy(tag[:], record[32:])
	clear(record[:])
	want := formalCoxBlockwiseSourceRecipientKeyTag(secret, provider.binding)
	if !hmac.Equal(tag[:], want[:]) {
		clear(secret[:])
		clear(tag[:])
		clear(want[:])
		return zero, fmt.Errorf("formal-cox source recipient key: key binding mismatch")
	}
	private, err := ecdh.X25519().NewPrivateKey(secret[:])
	if err != nil {
		clear(secret[:])
		return zero, fmt.Errorf("formal-cox source recipient key: invalid X25519 secret")
	}
	if _, err := formalCoxBlockwiseSourceTransportKeyID(private.PublicKey().Bytes()); err != nil {
		clear(secret[:])
		return zero, err
	}
	clear(tag[:])
	clear(want[:])
	return secret, nil
}

func (provider *formalCoxBlockwiseSourceRecipientKeyProvider) createOrReadV1() ([32]byte, error) {
	var zero [32]byte
	secret, err := provider.readV1()
	if err == nil {
		return secret, nil
	}
	if !os.IsNotExist(err) {
		return zero, err
	}
	private, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		return zero, err
	}
	copy(secret[:], private.Bytes())
	tag := formalCoxBlockwiseSourceRecipientKeyTag(secret, provider.binding)
	var record [formalCoxBlockwiseSourceRecipientKeyBytes]byte
	copy(record[:32], secret[:])
	copy(record[32:], tag[:])
	clear(tag[:])
	file, err := os.OpenFile(provider.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if os.IsExist(err) {
		clear(record[:])
		clear(secret[:])
		return provider.readV1()
	}
	if err != nil {
		clear(record[:])
		clear(secret[:])
		return zero, err
	}
	writeErr := file.Chmod(0o600)
	if writeErr == nil {
		writeErr = exactGCWriteFull(file, record[:])
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	clear(record[:])
	if writeErr != nil || closeErr != nil {
		clear(secret[:])
		if writeErr != nil {
			return zero, writeErr
		}
		return zero, closeErr
	}
	if err := exactGCSyncDir(provider.dir); err != nil {
		clear(secret[:])
		return zero, err
	}
	loaded, err := provider.readV1()
	if err != nil || !hmac.Equal(loaded[:], secret[:]) {
		clear(loaded[:])
		clear(secret[:])
		return zero, fmt.Errorf("formal-cox source recipient key: persistence failed")
	}
	clear(secret[:])
	return loaded, nil
}

func (provider *formalCoxBlockwiseSourceRecipientKeyProvider) ticketV1(
	signer ed25519.PrivateKey,
) (formalCoxBlockwiseSourceRecipientTicket, error) {
	var zero formalCoxBlockwiseSourceRecipientTicket
	secret, err := provider.readV1()
	if err != nil {
		return zero, err
	}
	defer clear(secret[:])
	private, err := ecdh.X25519().NewPrivateKey(secret[:])
	if err != nil {
		return zero, err
	}
	return provider.context.signRecipientTicket(provider.recipient,
		private.PublicKey().Bytes(), signer)
}

func (provider *formalCoxBlockwiseSourceRecipientKeyProvider) secretForSessionV1(
	session *formalCoxBlockwiseSourceSession,
) ([32]byte, error) {
	var zero [32]byte
	if provider == nil || session == nil || session.context == nil ||
		provider.context == nil ||
		session.context.planSHA256 != provider.context.planSHA256 ||
		session.context.pinsetSHA256 != provider.context.pinsetSHA256 ||
		session.context.plan.RunID != provider.context.plan.RunID {
		return zero, fmt.Errorf("formal-cox source recipient key: session mismatch")
	}
	secret, err := provider.readV1()
	if err != nil {
		return zero, err
	}
	private, err := ecdh.X25519().NewPrivateKey(secret[:])
	if err != nil {
		clear(secret[:])
		return zero, err
	}
	ticket, ok := session.tickets[provider.recipient]
	if !ok || !hmac.Equal(ticket.TransportPublicKey, private.PublicKey().Bytes()) {
		clear(secret[:])
		return zero, fmt.Errorf("formal-cox source recipient key: ticket binding mismatch")
	}
	return secret, nil
}

func (provider *formalCoxBlockwiseSourceRecipientKeyProvider) Close() {
	if provider == nil {
		return
	}
	clear(provider.binding[:])
	provider.path = ""
	provider.dir = ""
	provider.context = nil
	provider.recipient = ""
}

func formalCoxBlockwiseSourceRecipientKeyDecodeCommand(
	encoded []byte,
) (formalCoxBlockwiseSourceRecipientKeyCommand, error) {
	var command formalCoxBlockwiseSourceRecipientKeyCommand
	if len(encoded) < 2 || len(encoded) > formalCoxBlockwiseSourceRecipientKeyMax ||
		encoded[0] != '{' {
		return command, fmt.Errorf("formal-cox source recipient key: invalid command")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&command); err != nil {
		return formalCoxBlockwiseSourceRecipientKeyCommand{},
			fmt.Errorf("formal-cox source recipient key: invalid command")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF ||
		command.Version != formalCoxBlockwiseSourceRecipientKeyCommandVersion ||
		len(command.Schema) == 0 || command.BlockCapacity < 1 ||
		!formalCoxIsSHA256(command.RunID) ||
		!formalCoxCompilerRLabel(command.RecipientPeerName) ||
		command.RecipientSigningKey == "" {
		return formalCoxBlockwiseSourceRecipientKeyCommand{},
			fmt.Errorf("formal-cox source recipient key: non-canonical command")
	}
	return command, nil
}

func formalCoxBlockwiseSourceRecipientKeyCommandRunAtRoot(
	encoded []byte, stateRoot string, production bool,
) (formalCoxBlockwiseSourceRecipientTicket, error) {
	var zero formalCoxBlockwiseSourceRecipientTicket
	command, err := formalCoxBlockwiseSourceRecipientKeyDecodeCommand(encoded)
	if err != nil {
		return zero, err
	}
	compiled, err := formalCoxCompileSignedRSchema(command.Schema)
	if err != nil {
		return zero, err
	}
	plan, err := buildFormalCoxBlockwisePlan(compiled.Policy, command.BlockCapacity, command.RunID)
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
	signer, err := formalCoxBlockwiseSourceProducerCommandDecodeKey(command.RecipientSigningKey)
	if err != nil {
		return zero, err
	}
	defer clear(signer)
	provider, err := newFormalCoxBlockwiseSourceRecipientKeyProvider(
		stateRoot, production, context, command.RecipientPeerName, signer, true)
	if err != nil {
		return zero, err
	}
	defer provider.Close()
	return provider.ticketV1(signer)
}

func formalCoxBlockwiseSourceRecipientKeyReadCommand() ([]byte, error) {
	encoded, err := io.ReadAll(io.LimitReader(
		os.Stdin, int64(formalCoxBlockwiseSourceRecipientKeyMax)+1))
	if err != nil || len(encoded) > formalCoxBlockwiseSourceRecipientKeyMax {
		clear(encoded)
		return nil, fmt.Errorf("formal-cox source recipient key: command is too large")
	}
	return encoded, nil
}

func handleFormalCoxBlockwiseSourceRecipientKey() {
	encoded, err := formalCoxBlockwiseSourceRecipientKeyReadCommand()
	if err != nil {
		mpcFatalError(err.Error())
	}
	defer clear(encoded)
	ticket, err := formalCoxBlockwiseSourceRecipientKeyCommandRunAtRoot(
		encoded, formalFinalizerHandoffStateRoot, true)
	if err != nil {
		mpcFatalError(err.Error())
	}
	response, err := json.Marshal(ticket)
	if err != nil {
		mpcFatalError("formal-cox source recipient key: response failed")
	}
	defer clear(response)
	_, _ = os.Stdout.Write(append(response, '\n'))
}
