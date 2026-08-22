package main

// Controller for one live, source-bound Cox worker step. It owns the source
// bridge and the sole segmented spool until the sealed local receipt is
// recorded. An authenticated process/controller layer must establish the
// matching remote public root before calling Start; this private type neither
// accepts wire JSON nor restarts a burned worker attempt.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"sync"
)

const (
	formalCoxBlockwiseExchangeRootClaimVersion  = "dsvert-formal-cox-exchange-root-claim-v1"
	formalCoxBlockwiseExchangeRootClaimPurpose  = "formal_cox_blockwise_exact_gc_input_root_v1"
	formalCoxBlockwiseExchangeRootClaimDomain   = "dsVert/formal-cox/exchange-root-claim/v1"
	formalCoxBlockwiseExchangeRootClaimMax      = 4096
	formalCoxBlockwiseExchangePeerRootClaimFile = "peer-root-claim.json"
)

// formalCoxBlockwiseExchangeRootClaim is the only share-free wire value
// needed before a live controller starts a source-bound GC step. It binds the
// attempt, exact step, both designated compute identities and the public
// source commitment; it never carries a path, key, ciphertext or share.
type formalCoxBlockwiseExchangeRootClaim struct {
	Version         string                       `json:"version"`
	Purpose         string                       `json:"purpose"`
	ArtifactID      string                       `json:"artifact_id"`
	PlanSHA256      string                       `json:"plan_sha256"`
	PinsetSHA256    string                       `json:"pinset_sha256"`
	RunID           string                       `json:"run_id"`
	AttemptID       string                       `json:"attempt_id"`
	Step            formalCoxBlockwiseWorkerStep `json:"step"`
	SenderPeer      string                       `json:"sender_peer"`
	SenderPeerID    string                       `json:"sender_peer_id"`
	SenderRole      string                       `json:"sender_role"`
	RecipientPeer   string                       `json:"recipient_peer"`
	RecipientPeerID string                       `json:"recipient_peer_id"`
	RecipientRole   string                       `json:"recipient_role"`
	InputRootSHA256 string                       `json:"input_root_sha256"`
	Signature       []byte                       `json:"signature"`
}

func formalCoxBlockwiseExchangeRootClaimUnsigned(
	claim formalCoxBlockwiseExchangeRootClaim,
) ([]byte, error) {
	claim.Signature = nil
	encoded, err := json.Marshal(claim)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalCoxBlockwiseExchangeRootClaimDomain+"|"), encoded...), nil
}

func formalCoxBlockwiseExchangeMarshalRootClaim(
	claim formalCoxBlockwiseExchangeRootClaim,
) ([]byte, error) {
	if len(claim.Signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("formal-cox: invalid exchange root claim")
	}
	encoded, err := json.Marshal(claim)
	if err != nil {
		return nil, err
	}
	var decoded formalCoxBlockwiseExchangeRootClaim
	if err := formalCoxBlockwiseSourceDecodeCanonical(encoded,
		formalCoxBlockwiseExchangeRootClaimMax, "exchange root claim", &decoded); err != nil {
		clear(encoded)
		return nil, err
	}
	return encoded, nil
}

func formalCoxBlockwiseExchangeDecodeRootClaim(encoded []byte) (
	formalCoxBlockwiseExchangeRootClaim, error,
) {
	var claim formalCoxBlockwiseExchangeRootClaim
	if err := formalCoxBlockwiseSourceDecodeCanonical(encoded,
		formalCoxBlockwiseExchangeRootClaimMax, "exchange root claim", &claim); err != nil ||
		len(claim.Signature) != ed25519.SignatureSize {
		return formalCoxBlockwiseExchangeRootClaim{},
			fmt.Errorf("formal-cox: invalid exchange root claim")
	}
	return claim, nil
}

type formalCoxBlockwiseExchangeController struct {
	mu sync.Mutex

	bridge    *formalCoxBlockwiseSourceBridge
	transport *formalCoxBlockwiseExchangeTransport
	plan      formalCoxBlockwisePlan
	peer      string

	started   bool
	running   bool
	committed bool
	closed    bool
	receipt   formalCoxBlockwiseStepReceipt
	runErr    error
}

func newFormalCoxBlockwiseExchangeController(bridge *formalCoxBlockwiseSourceBridge,
	lease *formalCoxBlockwiseExchangeLease,
) (*formalCoxBlockwiseExchangeController, error) {
	if bridge == nil {
		return nil, fmt.Errorf("formal-cox: exchange controller bridge is unavailable")
	}
	bridge.mu.Lock()
	plan, peer := bridge.plan, bridge.peer
	valid := !bridge.closed && bridge.source != nil && bridge.worker != nil &&
		len(bridge.signingKey) == ed25519.PrivateKeySize
	bridge.mu.Unlock()
	if _, err := formalCoxBlockwiseValidateShape(plan); !valid || err != nil {
		return nil, fmt.Errorf("formal-cox: exchange controller bridge is invalid")
	}
	transport, err := newFormalCoxBlockwiseExchangeTransport(lease, plan, peer)
	if err != nil {
		return nil, err
	}
	return &formalCoxBlockwiseExchangeController{
		bridge: bridge, transport: transport, plan: plan, peer: peer,
	}, nil
}

func (controller *formalCoxBlockwiseExchangeController) BindPeer(peer string) error {
	if controller == nil {
		return fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed || controller.started || controller.transport == nil {
		return fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	return controller.transport.BindPeer(peer)
}

// rootClaimTemplateLocked returns the exact claim fields required for sender
// to bind this controller's public source root to recipient. The caller holds
// controller.mu; this helper takes bridge.mu only while it reads public state
// and the local signing key/pinset stay private.
func (controller *formalCoxBlockwiseExchangeController) rootClaimTemplateLocked(
	step formalCoxBlockwiseWorkerStep, attempt [32]byte, sender, recipient string,
) (formalCoxBlockwiseExchangeRootClaim, ed25519.PublicKey, error) {
	var zero formalCoxBlockwiseExchangeRootClaim
	if controller == nil || controller.closed || controller.started ||
		controller.transport == nil || !controller.transport.peerBound ||
		sender == "" || recipient == "" || sender == recipient {
		return zero, nil, fmt.Errorf("formal-cox: exchange controller is not peer-bound")
	}
	bridge := controller.bridge
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.closed || bridge.source == nil || bridge.source.session == nil ||
		bridge.source.session.context == nil || bridge.peer != controller.peer {
		return zero, nil, fmt.Errorf("formal-cox: exchange controller bridge is unavailable")
	}
	context := bridge.source.session.context
	if sender != controller.peer && recipient != controller.peer ||
		(sender != controller.peer && sender != controller.transport.remotePeer) ||
		(recipient != controller.peer && recipient != controller.transport.remotePeer) ||
		context.peerIDs[sender] == "" || context.peerIDs[recipient] == "" ||
		context.roles[sender] == "" || context.roles[recipient] == "" ||
		len(context.pins[sender]) != ed25519.PublicKeySize {
		return zero, nil, fmt.Errorf("formal-cox: invalid exchange root claim context")
	}
	localRoot, err := bridge.publicInputRootUnlocked(step)
	if err != nil {
		return zero, nil, err
	}
	if formalCoxBlockwiseWorkerStepNeedsInput(step) {
		if !formalCoxIsSHA256(localRoot) {
			return zero, nil, fmt.Errorf("formal-cox: invalid exchange source root")
		}
	} else if localRoot != "" {
		return zero, nil, fmt.Errorf("formal-cox: internal exchange step has a source root")
	}
	return formalCoxBlockwiseExchangeRootClaim{
		Version:    formalCoxBlockwiseExchangeRootClaimVersion,
		Purpose:    formalCoxBlockwiseExchangeRootClaimPurpose,
		ArtifactID: context.artifactID, PlanSHA256: context.planSHA256,
		PinsetSHA256: context.pinsetSHA256, RunID: context.plan.RunID,
		AttemptID: hex.EncodeToString(attempt[:]), Step: step,
		SenderPeer: sender, SenderPeerID: context.peerIDs[sender], SenderRole: context.roles[sender],
		RecipientPeer: recipient, RecipientPeerID: context.peerIDs[recipient], RecipientRole: context.roles[recipient],
		InputRootSHA256: localRoot,
	}, append(ed25519.PublicKey(nil), context.pins[sender]...), nil
}

// RootClaim signs the local public source-root commitment. It is available
// only while the exact-GC owner is live, peer-bound and has not begun a step.
func (controller *formalCoxBlockwiseExchangeController) RootClaim(
	step formalCoxBlockwiseWorkerStep, attempt [32]byte,
) (formalCoxBlockwiseExchangeRootClaim, error) {
	var zero formalCoxBlockwiseExchangeRootClaim
	if controller == nil {
		return zero, fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	claim, _, err := controller.rootClaimTemplateLocked(
		step, attempt, controller.peer, controller.transport.remotePeer)
	if err != nil {
		return zero, err
	}
	bridge := controller.bridge
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.closed || len(bridge.signingKey) != ed25519.PrivateKeySize ||
		!hmac.Equal(bridge.signingKey.Public().(ed25519.PublicKey),
			controller.bridge.source.session.context.pins[controller.peer]) {
		return zero, fmt.Errorf("formal-cox: exchange signing key is unavailable")
	}
	message, err := formalCoxBlockwiseExchangeRootClaimUnsigned(claim)
	if err != nil {
		return zero, err
	}
	defer clear(message)
	claim.Signature = ed25519.Sign(bridge.signingKey, message)
	return claim, nil
}

func (controller *formalCoxBlockwiseExchangeController) validatePeerRootClaimLocked(
	step formalCoxBlockwiseWorkerStep, attempt [32]byte,
	claim formalCoxBlockwiseExchangeRootClaim,
) (string, error) {
	expected, senderPin, err := controller.rootClaimTemplateLocked(
		step, attempt, controller.transport.remotePeer, controller.peer)
	if err != nil {
		return "", err
	}
	candidate := claim
	candidate.Signature = nil
	if !reflect.DeepEqual(candidate, expected) {
		return "", fmt.Errorf("formal-cox: exchange root claim binding mismatch")
	}
	message, err := formalCoxBlockwiseExchangeRootClaimUnsigned(claim)
	if err != nil {
		return "", err
	}
	defer clear(message)
	if !ed25519.Verify(senderPin, message, claim.Signature) {
		return "", fmt.Errorf("formal-cox: exchange root claim signature is invalid")
	}
	return expected.InputRootSHA256, nil
}

// ValidatePeerRootClaim checks a canonical signed peer claim before any
// checkpoint mutation. Start repeats this check under the same controller
// lock, so callers cannot replace the claim after preflight.
func (controller *formalCoxBlockwiseExchangeController) ValidatePeerRootClaim(
	step formalCoxBlockwiseWorkerStep, attempt [32]byte,
	claim formalCoxBlockwiseExchangeRootClaim,
) (string, error) {
	if controller == nil {
		return "", fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.validatePeerRootClaimLocked(step, attempt, claim)
}

func formalCoxBlockwiseExchangeReadPeerRootClaim(root *os.Root) ([]byte, error) {
	if root == nil {
		return nil, fmt.Errorf("formal-cox: exchange peer root claim is unavailable")
	}
	info, err := root.Lstat(formalCoxBlockwiseExchangePeerRootClaimFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || !exactGCPrivateOwnedRegular(info) ||
		info.Size() < 64 || info.Size() > formalCoxBlockwiseExchangeRootClaimMax {
		return nil, fmt.Errorf("formal-cox: exchange peer root claim is unsafe")
	}
	file, err := root.Open(formalCoxBlockwiseExchangePeerRootClaimFile)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, opened) ||
		opened.Mode().Perm() != 0o600 || !exactGCPrivateOwnedRegular(opened) ||
		opened.Size() != info.Size() {
		_ = file.Close()
		return nil, fmt.Errorf("formal-cox: exchange peer root claim changed while opening")
	}
	encoded := make([]byte, opened.Size())
	_, readErr := io.ReadFull(file, encoded)
	closeErr := file.Close()
	if readErr != nil {
		clear(encoded)
		return nil, readErr
	}
	if closeErr != nil {
		clear(encoded)
		return nil, closeErr
	}
	if _, err := formalCoxBlockwiseExchangeDecodeRootClaim(encoded); err != nil {
		clear(encoded)
		return nil, err
	}
	return encoded, nil
}

// persistPeerRootClaimLocked fixes the already-verified peer commitment before
// the local checkpoint advances.  The claim is itself pinned and signed, so
// this does not add a transport key or disclose a source share; it gives a
// later relay opener one durable public binding for this burned worker slot.
func (controller *formalCoxBlockwiseExchangeController) persistPeerRootClaimLocked(
	claim formalCoxBlockwiseExchangeRootClaim,
) error {
	if controller == nil || controller.closed || controller.transport == nil ||
		controller.transport.root == nil || controller.transport.closed {
		return fmt.Errorf("formal-cox: exchange peer root claim is unavailable")
	}
	encoded, err := formalCoxBlockwiseExchangeMarshalRootClaim(claim)
	if err != nil {
		return err
	}
	defer clear(encoded)
	root := controller.transport.root
	err = formalCoxBlockwiseExchangeTransportWriteInitial(root,
		formalCoxBlockwiseExchangePeerRootClaimFile, encoded)
	if os.IsExist(err) {
		existing, readErr := formalCoxBlockwiseExchangeReadPeerRootClaim(root)
		if readErr != nil {
			return readErr
		}
		defer clear(existing)
		if !bytes.Equal(existing, encoded) {
			return fmt.Errorf("formal-cox: exchange peer root claim conflicts")
		}
		return nil
	}
	if err != nil {
		return err
	}
	if err := formalCoxBlockwiseExchangeLeaseSyncRoot(root); err != nil {
		return err
	}
	existing, err := formalCoxBlockwiseExchangeReadPeerRootClaim(root)
	if err != nil {
		return err
	}
	defer clear(existing)
	if !bytes.Equal(existing, encoded) {
		return fmt.Errorf("formal-cox: exchange peer root claim readback changed")
	}
	return nil
}

// PublicInputRoot computes only the local source commitment for diagnostics
// and root-claim construction. It cannot start a worker: Start accepts only a
// signed peer root claim and recomputes the local commitment itself.
func (controller *formalCoxBlockwiseExchangeController) PublicInputRoot(
	step formalCoxBlockwiseWorkerStep,
) (string, error) {
	if controller == nil {
		return "", fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed || controller.started || controller.transport == nil ||
		!controller.transport.peerBound {
		return "", fmt.Errorf("formal-cox: exchange controller is not peer-bound")
	}
	return controller.bridge.PublicInputRoot(step)
}

func (controller *formalCoxBlockwiseExchangeController) Start(
	step formalCoxBlockwiseWorkerStep, attempt, master [32]byte,
	peerClaim formalCoxBlockwiseExchangeRootClaim,
) error {
	if controller == nil {
		return fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed || controller.started || controller.transport == nil ||
		!controller.transport.peerBound {
		return fmt.Errorf("formal-cox: exchange controller is not peer-bound")
	}
	pairedRoot, err := controller.validatePeerRootClaimLocked(step, attempt, peerClaim)
	if err != nil {
		return err
	}
	if err := controller.persistPeerRootClaimLocked(peerClaim); err != nil {
		return err
	}
	bound, err := controller.bridge.BeginAttempt(step, attempt, pairedRoot)
	if err != nil {
		return err
	}
	session, err := formalCoxBlockwiseWorkerSession(
		controller.plan, bound, attempt, master)
	if err != nil {
		return err
	}
	controller.started, controller.running = true, true
	bridge, transport := controller.bridge, controller.transport
	go func() {
		receipt, runErr := bridge.RunPendingWorkerStep(transport, session)
		controller.mu.Lock()
		defer controller.mu.Unlock()
		controller.running = false
		controller.receipt, controller.runErr = receipt, runErr
	}()
	return nil
}

func (controller *formalCoxBlockwiseExchangeController) Poll(ack int64) (
	*formalCoxBlockwiseExchangeChunk, int64, error,
) {
	if controller == nil {
		return nil, 0, fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	controller.mu.Lock()
	transport := controller.transport
	valid := !controller.closed && controller.started && transport != nil
	controller.mu.Unlock()
	if !valid {
		return nil, 0, fmt.Errorf("formal-cox: exchange controller is not running")
	}
	return transport.Poll(ack)
}

func (controller *formalCoxBlockwiseExchangeController) Relay(
	chunk formalCoxBlockwiseExchangeChunk,
) (int64, error) {
	if controller == nil {
		return 0, fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	controller.mu.Lock()
	transport := controller.transport
	valid := !controller.closed && controller.started && transport != nil
	controller.mu.Unlock()
	if !valid {
		return 0, fmt.Errorf("formal-cox: exchange controller is not running")
	}
	return transport.Relay(chunk)
}

func (controller *formalCoxBlockwiseExchangeController) Result() (
	formalCoxBlockwiseStepReceipt, bool, error,
) {
	if controller == nil {
		return formalCoxBlockwiseStepReceipt{}, false,
			fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed {
		return formalCoxBlockwiseStepReceipt{}, false,
			fmt.Errorf("formal-cox: exchange controller is closed")
	}
	if !controller.started || controller.running {
		return formalCoxBlockwiseStepReceipt{}, false, nil
	}
	if controller.runErr != nil {
		return formalCoxBlockwiseStepReceipt{}, true, controller.runErr
	}
	return controller.receipt, true, nil
}

func (controller *formalCoxBlockwiseExchangeController) Commit(
	receipts []formalCoxBlockwiseStepReceipt, pins map[string]ed25519.PublicKey,
) error {
	if controller == nil {
		return fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed || !controller.started || controller.running ||
		controller.runErr != nil || controller.committed {
		return fmt.Errorf("formal-cox: exchange controller cannot commit")
	}
	matched := false
	for _, receipt := range receipts {
		if reflect.DeepEqual(receipt, controller.receipt) {
			matched = true
		}
	}
	if !matched {
		return fmt.Errorf("formal-cox: exchange controller commit omits local receipt")
	}
	if err := controller.bridge.worker.CommitPending(receipts, pins); err != nil {
		return err
	}
	controller.committed = true
	return nil
}

func (controller *formalCoxBlockwiseExchangeController) Close() error {
	if controller == nil {
		return nil
	}
	controller.mu.Lock()
	if controller.closed {
		controller.mu.Unlock()
		return nil
	}
	controller.closed = true
	transport, bridge := controller.transport, controller.bridge
	controller.transport, controller.bridge = nil, nil
	controller.mu.Unlock()
	var transportErr error
	if transport != nil {
		transportErr = transport.Close()
	}
	if bridge != nil {
		if err := bridge.Close(); transportErr == nil {
			transportErr = err
		}
	}
	return transportErr
}
