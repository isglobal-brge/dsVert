package main

// This private bootstrap reconstructs one source-bound Cox controller from
// recipient-local Rock state. It deliberately stops at the live daemon: a
// public DSI driver still has to perform the authenticated peer relay and may
// never reopen a burned exact-GC attempt.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
)

const (
	formalCoxBlockwiseWorkerBootstrapVersion = "dsvert-formal-cox-blockwise-worker-bootstrap-v1"
	formalCoxBlockwiseWorkerBootstrapDomain  = "dsVert/formal-cox/blockwise-worker-bootstrap/v1"
	formalCoxBlockwiseWorkerBootstrapDir     = "formal-cox-blockwise-worker-bootstrap-v1"
	formalCoxBlockwiseWorkerBootstrapMax     = 16 << 20
)

type formalCoxBlockwiseWorkerBootstrapCommand struct {
	Version   string                                `json:"version"`
	Source    formalCoxBlockwiseSourceImportCommand `json:"source"`
	AttemptID string                                `json:"attempt_id"`
}

type formalCoxBlockwiseWorkerBootstrap struct {
	daemon      *formalCoxBlockwiseExchangeDaemonV1
	client      *formalCoxBlockwiseExchangeDaemonClientV1
	closeSource func()
}

func formalCoxBlockwiseWorkerBootstrapDecodeCommand(
	encoded []byte,
) (formalCoxBlockwiseWorkerBootstrapCommand, error) {
	var command formalCoxBlockwiseWorkerBootstrapCommand
	if len(encoded) < 2 || len(encoded) > formalCoxBlockwiseWorkerBootstrapMax ||
		encoded[0] != '{' {
		return command, fmt.Errorf("formal-cox: invalid worker bootstrap command")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&command); err != nil {
		return formalCoxBlockwiseWorkerBootstrapCommand{},
			fmt.Errorf("formal-cox: invalid worker bootstrap command")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF ||
		command.Version != formalCoxBlockwiseWorkerBootstrapVersion ||
		!formalCoxIsSHA256(command.AttemptID) {
		return formalCoxBlockwiseWorkerBootstrapCommand{},
			fmt.Errorf("formal-cox: invalid worker bootstrap command")
	}
	canonical, err := json.Marshal(command)
	if err != nil || !bytes.Equal(canonical, encoded) {
		clear(canonical)
		return formalCoxBlockwiseWorkerBootstrapCommand{},
			fmt.Errorf("formal-cox: non-canonical worker bootstrap command")
	}
	clear(canonical)
	source, err := json.Marshal(command.Source)
	if err != nil {
		return formalCoxBlockwiseWorkerBootstrapCommand{}, err
	}
	defer clear(source)
	if _, err := formalCoxBlockwiseSourceImportDecodeCommand(source); err != nil {
		return formalCoxBlockwiseWorkerBootstrapCommand{},
			fmt.Errorf("formal-cox: invalid worker bootstrap source")
	}
	return command, nil
}

func formalCoxBlockwiseWorkerBootstrapDecodeAttempt(value string) ([32]byte, error) {
	var attempt [32]byte
	if !formalCoxIsSHA256(value) {
		return attempt, fmt.Errorf("formal-cox: invalid worker bootstrap attempt")
	}
	encoded, err := hex.DecodeString(value)
	if err != nil || len(encoded) != len(attempt) {
		clear(encoded)
		return attempt, fmt.Errorf("formal-cox: invalid worker bootstrap attempt")
	}
	copy(attempt[:], encoded)
	clear(encoded)
	return attempt, nil
}

func formalCoxBlockwiseWorkerBootstrapKey(secret []byte, purpose, planSHA, peer string,
	attempt [32]byte,
) ([32]byte, error) {
	var result [32]byte
	if len(secret) != sha256.Size || purpose == "" || !formalCoxIsSHA256(planSHA) ||
		!formalCoxCompilerRLabel(peer) {
		return result, fmt.Errorf("formal-cox: invalid worker bootstrap key context")
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(formalCoxBlockwiseWorkerBootstrapDomain + "|"))
	_, _ = mac.Write([]byte(purpose + "|" + planSHA + "|" + peer + "|"))
	_, _ = mac.Write(attempt[:])
	copy(result[:], mac.Sum(nil))
	return result, nil
}

func formalCoxBlockwiseWorkerBootstrapPaths(stateRoot string, production bool,
	planSHA, peer string,
) (string, string, error) {
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot ||
		(production && stateRoot != formalFinalizerHandoffStateRoot) ||
		!formalCoxIsSHA256(planSHA) || !formalCoxCompilerRLabel(peer) {
		return "", "", fmt.Errorf("formal-cox: invalid worker bootstrap root")
	}
	base := filepath.Join(stateRoot, formalCoxBlockwiseWorkerBootstrapDir)
	for _, directory := range []string{
		stateRoot, base, filepath.Join(base, peer), filepath.Join(base, peer, planSHA),
	} {
		if err := formalCoxBlockwiseSourceEnsurePrivateDir(directory); err != nil {
			return "", "", err
		}
	}
	base = filepath.Join(base, peer, planSHA)
	checkpoint, exchange := filepath.Join(base, "checkpoint"), filepath.Join(base, "exchange")
	for _, directory := range []string{checkpoint, exchange} {
		if err := formalCoxBlockwiseSourceEnsurePrivateDir(directory); err != nil {
			return "", "", err
		}
	}
	return checkpoint, exchange, nil
}

func openFormalCoxBlockwiseWorkerBootstrapAtRoot(encoded []byte, stateRoot string,
	production bool,
) (*formalCoxBlockwiseWorkerBootstrap, error) {
	command, err := formalCoxBlockwiseWorkerBootstrapDecodeCommand(encoded)
	if err != nil {
		return nil, err
	}
	attempt, err := formalCoxBlockwiseWorkerBootstrapDecodeAttempt(command.AttemptID)
	if err != nil {
		return nil, err
	}
	source, closeSource, err := formalCoxBlockwiseSourceImportOpen(
		command.Source, stateRoot, production)
	if err != nil {
		return nil, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			closeSource()
		}
	}()
	canonicalDelivery, err := command.Source.Delivery.Encode(source.session)
	if err != nil {
		return nil, err
	}
	defer clear(canonicalDelivery)
	if _, err := source.AcceptDelivery(canonicalDelivery); err != nil {
		return nil, err
	}
	source.mu.Lock()
	planSHA, peer := source.session.context.planSHA256, source.recipient
	secret := append([]byte(nil), source.recipientSK...)
	source.mu.Unlock()
	defer clear(secret)
	checkpointDir, exchangeDir, err := formalCoxBlockwiseWorkerBootstrapPaths(
		stateRoot, production, planSHA, peer)
	if err != nil {
		return nil, err
	}
	workerKey, err := formalCoxBlockwiseWorkerBootstrapKey(
		secret, "checkpoint", planSHA, peer, attempt)
	if err != nil {
		return nil, err
	}
	controlKey, err := formalCoxBlockwiseWorkerBootstrapKey(
		secret, "daemon-control", planSHA, peer, attempt)
	if err != nil {
		clear(workerKey[:])
		return nil, err
	}
	defer clear(workerKey[:])
	defer clear(controlKey[:])
	signer, err := formalCoxBlockwiseSourceProducerCommandDecodeKey(
		command.Source.RecipientSigningKey)
	if err != nil {
		return nil, err
	}
	defer clear(signer)
	bridge, err := newFormalCoxBlockwiseSourceBridgeFromOpenStore(
		source, checkpointDir, workerKey, signer)
	if err != nil {
		return nil, err
	}
	lease, err := openFormalCoxBlockwiseExchangeLease(exchangeDir, bridge.plan, peer, attempt)
	if err != nil {
		_ = bridge.Close()
		return nil, err
	}
	controller, err := newFormalCoxBlockwiseExchangeController(bridge, lease)
	if err != nil {
		_ = bridge.Close()
		_ = lease.Close()
		return nil, err
	}
	daemon, err := newFormalCoxBlockwiseExchangeDaemonV1(controller, controlKey[:])
	if err != nil {
		_ = controller.Close()
		return nil, err
	}
	client, err := newFormalCoxBlockwiseExchangeDaemonClientV1(
		daemon.SocketPathV1(), controlKey[:])
	if err != nil {
		_ = daemon.Close()
		return nil, err
	}
	closeOnError = false
	return &formalCoxBlockwiseWorkerBootstrap{
		daemon: daemon, client: client, closeSource: closeSource,
	}, nil
}

func (bootstrap *formalCoxBlockwiseWorkerBootstrap) Close() error {
	if bootstrap == nil {
		return nil
	}
	if bootstrap.client != nil {
		bootstrap.client.Close()
		bootstrap.client = nil
	}
	if bootstrap.daemon == nil {
		if bootstrap.closeSource != nil {
			bootstrap.closeSource()
			bootstrap.closeSource = nil
		}
		return nil
	}
	err := bootstrap.daemon.Close()
	bootstrap.daemon = nil
	if bootstrap.closeSource != nil {
		bootstrap.closeSource()
		bootstrap.closeSource = nil
	}
	return err
}
