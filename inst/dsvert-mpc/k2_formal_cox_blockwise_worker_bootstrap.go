package main

// This private bootstrap reconstructs one source-bound Cox controller from
// recipient-local Rock state. It deliberately stops at the live daemon: a
// public DSI driver still has to perform the authenticated peer relay and may
// never reopen a burned exact-GC attempt.

import (
	"bytes"
	"crypto/ed25519"
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
	formalCoxBlockwiseWorkerOpeningDir       = "formal-cox-blockwise-worker-opening-v1"
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

// formalCoxBlockwiseWorkerBootstrapAttachment reconnects to an already-live
// local worker.  It intentionally owns only the short-lived daemon client:
// it revalidates the signed recipient manifest and derives the same local
// control key without reopening the source spool owned by that worker.  It
// cannot start, replace, or recover a daemon after its exact-GC lease has
// been burned.
type formalCoxBlockwiseWorkerBootstrapAttachment struct {
	client *formalCoxBlockwiseExchangeDaemonClientV1
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

// formalCoxBlockwiseWorkerCheckpointKey remains stable across committed
// schedule steps. The exact-GC lease and daemon-control key stay bound to one
// fresh attempt; only the authenticated private checkpoint intentionally
// survives it.
func formalCoxBlockwiseWorkerCheckpointKey(secret []byte, planSHA, peer string) (
	[32]byte, error,
) {
	var result [32]byte
	if len(secret) != sha256.Size || !formalCoxIsSHA256(planSHA) ||
		!formalCoxCompilerRLabel(peer) {
		return result, fmt.Errorf("formal-cox: invalid worker checkpoint key context")
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(formalCoxBlockwiseWorkerBootstrapDomain + "|checkpoint|"))
	_, _ = mac.Write([]byte(planSHA + "|" + peer))
	copy(result[:], mac.Sum(nil))
	return result, nil
}

// formalCoxBlockwiseWorkerStickyOpeningKey is stable for one canonical plan
// and local recipient, while remaining domain-separated from the checkpoint.
// A restarted fresh worker must be able to replay the same sticky handoff.
func formalCoxBlockwiseWorkerStickyOpeningKey(secret []byte, planSHA, peer string) (
	[32]byte, error,
) {
	var result [32]byte
	if len(secret) != sha256.Size || !formalCoxIsSHA256(planSHA) ||
		!formalCoxCompilerRLabel(peer) {
		return result, fmt.Errorf("formal-cox: invalid worker sticky-opening key context")
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(formalCoxBlockwiseWorkerBootstrapDomain + "|sticky-opening|"))
	_, _ = mac.Write([]byte(planSHA + "|" + peer))
	copy(result[:], mac.Sum(nil))
	return result, nil
}

func formalCoxBlockwiseWorkerBootstrapPaths(stateRoot string, production bool,
	planSHA, peer string,
) (string, string, string, error) {
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot ||
		(production && stateRoot != formalFinalizerHandoffStateRoot) ||
		!formalCoxIsSHA256(planSHA) || !formalCoxCompilerRLabel(peer) {
		return "", "", "", fmt.Errorf("formal-cox: invalid worker bootstrap root")
	}
	base := filepath.Join(stateRoot, formalCoxBlockwiseWorkerBootstrapDir)
	for _, directory := range []string{
		stateRoot, base, filepath.Join(base, peer), filepath.Join(base, peer, planSHA),
	} {
		if err := formalCoxBlockwiseSourceEnsurePrivateDir(directory); err != nil {
			return "", "", "", err
		}
	}
	base = filepath.Join(base, peer, planSHA)
	checkpoint, exchange := filepath.Join(base, "checkpoint"), filepath.Join(base, "exchange")
	openingBase := filepath.Join(stateRoot, formalCoxBlockwiseWorkerOpeningDir)
	openingPeer := filepath.Join(openingBase, peer)
	opening := filepath.Join(openingPeer, planSHA)
	for _, directory := range []string{
		checkpoint, exchange, openingBase, openingPeer, opening,
	} {
		if err := formalCoxBlockwiseSourceEnsurePrivateDir(directory); err != nil {
			return "", "", "", err
		}
	}
	return checkpoint, exchange, opening, nil
}

// formalCoxBlockwiseWorkerBootstrapOpeningStore derives the local opening
// store solely from the recipient-local source secret already owned by the
// live worker.  The caller supplies no path, key, plan, or authority set.
func formalCoxBlockwiseWorkerBootstrapOpeningStore(
	source *formalCoxBlockwiseSourceStore, stateRoot, planSHA, peer string,
	production bool,
) (*formalCoxBlockwiseOpeningStore, error) {
	if source == nil {
		return nil, fmt.Errorf("formal-cox: opening source is unavailable")
	}
	source.mu.Lock()
	valid := !source.closed && source.session != nil &&
		source.session.context != nil && source.recipient == peer &&
		source.session.context.planSHA256 == planSHA &&
		len(source.recipientSK) == sha256.Size
	secret := append([]byte(nil), source.recipientSK...)
	plan := formalCoxBlockwisePlan{}
	pins := map[string]ed25519.PublicKey(nil)
	if valid {
		plan = source.session.context.plan
		pins = make(map[string]ed25519.PublicKey, len(source.session.context.pins))
		for name, pin := range source.session.context.pins {
			pins[name] = append(ed25519.PublicKey(nil), pin...)
		}
	}
	source.mu.Unlock()
	defer clear(secret)
	if !valid {
		formalCoxBlockwiseClearPinsV1(pins)
		return nil, fmt.Errorf("formal-cox: opening source is unavailable")
	}
	_, _, openingDir, err := formalCoxBlockwiseWorkerBootstrapPaths(
		stateRoot, production, planSHA, peer)
	if err != nil {
		formalCoxBlockwiseClearPinsV1(pins)
		return nil, err
	}
	storageRoot, err := formalCoxBlockwiseWorkerStickyOpeningKey(secret, planSHA, peer)
	if err != nil {
		formalCoxBlockwiseClearPinsV1(pins)
		return nil, err
	}
	defer clear(storageRoot[:])
	store, err := newFormalCoxBlockwiseOpeningStore(
		openingDir, storageRoot, plan, pins)
	formalCoxBlockwiseClearPinsV1(pins)
	return store, err
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
	checkpointDir, exchangeDir, _, err := formalCoxBlockwiseWorkerBootstrapPaths(
		stateRoot, production, planSHA, peer)
	if err != nil {
		return nil, err
	}
	workerKey, err := formalCoxBlockwiseWorkerCheckpointKey(
		secret, planSHA, peer)
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
	opening, err := formalCoxBlockwiseWorkerBootstrapOpeningStore(
		source, stateRoot, planSHA, peer, production)
	if err != nil {
		_ = controller.Close()
		return nil, err
	}
	if err := controller.AttachOpeningV1(opening); err != nil {
		_ = opening.Close()
		_ = controller.Close()
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

func openFormalCoxBlockwiseWorkerBootstrapAttachmentAtRoot(encoded []byte,
	stateRoot string, production bool,
) (*formalCoxBlockwiseWorkerBootstrapAttachment, error) {
	command, err := formalCoxBlockwiseWorkerBootstrapDecodeCommand(encoded)
	if err != nil {
		return nil, err
	}
	attempt, err := formalCoxBlockwiseWorkerBootstrapDecodeAttempt(command.AttemptID)
	if err != nil {
		return nil, err
	}
	compiled, err := formalCoxCompileSignedRSchema(command.Source.Schema)
	if err != nil {
		return nil, err
	}
	plan, err := buildFormalCoxBlockwisePlan(
		compiled.Policy, command.Source.BlockCapacity, command.Source.RunID)
	if err != nil {
		return nil, err
	}
	pins, err := formalCoxBlockwiseSourceProducerCommandDecodePins(command.Source.Pins)
	if err != nil {
		return nil, err
	}
	defer func() {
		for peer := range pins {
			clear(pins[peer])
		}
	}()
	context, err := newFormalCoxBlockwiseSourceContext(plan, pins)
	if err != nil {
		return nil, err
	}
	defer func() {
		for peer := range context.pins {
			clear(context.pins[peer])
		}
	}()
	session, err := context.bindRecipientManifest(command.Source.RecipientTickets)
	if err != nil {
		return nil, err
	}
	if _, err := formalCoxBlockwiseSourceDeliveryRecipientIndex(
		session, command.Source.RecipientPeerName); err != nil {
		return nil, err
	}
	canonicalDelivery, err := command.Source.Delivery.Encode(session)
	if err != nil {
		return nil, err
	}
	clear(canonicalDelivery)
	signer, err := formalCoxBlockwiseSourceProducerCommandDecodeKey(
		command.Source.RecipientSigningKey)
	if err != nil {
		return nil, err
	}
	defer clear(signer)
	provider, err := newFormalCoxBlockwiseSourceRecipientKeyProvider(
		stateRoot, production, context, command.Source.RecipientPeerName, signer, false)
	if err != nil {
		return nil, err
	}
	defer provider.Close()
	secret, err := provider.secretForSessionV1(session)
	if err != nil {
		return nil, err
	}
	defer clear(secret[:])
	planSHA, peer := context.planSHA256, command.Source.RecipientPeerName
	_, exchangeDir, _, err := formalCoxBlockwiseWorkerBootstrapPaths(
		stateRoot, production, planSHA, peer)
	if err != nil {
		return nil, err
	}
	slot, err := formalCoxBlockwiseExchangeLeaseSlot(plan, peer, attempt)
	if err != nil {
		return nil, err
	}
	controlKey, err := formalCoxBlockwiseWorkerBootstrapKey(
		secret[:], "daemon-control", planSHA, peer, attempt)
	if err != nil {
		return nil, err
	}
	defer clear(controlKey[:])
	socketRoot, socketDir, socketPath, err :=
		formalCoxBlockwiseExchangeDaemonSocketLocation(filepath.Join(exchangeDir, slot))
	if err != nil {
		return nil, err
	}
	valid := formalCoxBlockwiseExchangeLeaseValidateDir(socketRoot, socketDir) == nil &&
		formalCoxBlockwiseExchangeDaemonSocketValid(socketPath) == nil
	closeErr := socketRoot.Close()
	if !valid || closeErr != nil {
		return nil, fmt.Errorf("formal-cox: worker attachment socket is unavailable")
	}
	client, err := newFormalCoxBlockwiseExchangeDaemonClientV1(socketPath, controlKey[:])
	if err != nil {
		return nil, err
	}
	return &formalCoxBlockwiseWorkerBootstrapAttachment{client: client}, nil
}

func (attachment *formalCoxBlockwiseWorkerBootstrapAttachment) Close() error {
	if attachment == nil || attachment.client == nil {
		return nil
	}
	attachment.client.Close()
	attachment.client = nil
	return nil
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
