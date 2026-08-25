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
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"sync"
)

const (
	formalCoxBlockwiseExchangeRootClaimVersion   = "dsvert-formal-cox-exchange-root-claim-v1"
	formalCoxBlockwiseExchangeRootClaimPurpose   = "formal_cox_blockwise_exact_gc_input_root_v1"
	formalCoxBlockwiseExchangeRootClaimDomain    = "dsVert/formal-cox/exchange-root-claim/v1"
	formalCoxBlockwiseExchangeRootClaimMax       = 4096
	formalCoxBlockwiseExchangeLocalRootClaimFile = "local-root-claim.json"
	formalCoxBlockwiseExchangePeerRootClaimFile  = "peer-root-claim.json"
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
	return controller.localRootClaimLocked(step, attempt)
}

func (controller *formalCoxBlockwiseExchangeController) localRootClaimLocked(
	step formalCoxBlockwiseWorkerStep, attempt [32]byte,
) (formalCoxBlockwiseExchangeRootClaim, error) {
	var zero formalCoxBlockwiseExchangeRootClaim
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

func formalCoxBlockwiseExchangeReadRootClaim(root *os.Root, name string) ([]byte, error) {
	if root == nil {
		return nil, fmt.Errorf("formal-cox: exchange root claim is unavailable")
	}
	if name != formalCoxBlockwiseExchangeLocalRootClaimFile &&
		name != formalCoxBlockwiseExchangePeerRootClaimFile {
		return nil, fmt.Errorf("formal-cox: exchange root claim name is invalid")
	}
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || !exactGCPrivateOwnedRegular(info) ||
		info.Size() < 64 || info.Size() > formalCoxBlockwiseExchangeRootClaimMax {
		return nil, fmt.Errorf("formal-cox: exchange root claim is unsafe")
	}
	file, err := root.Open(name)
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

// persistRootClaimLocked fixes one already-verified public commitment before
// the local checkpoint advances. The paired local and peer records let a
// later relay opener reject a partially initialized burned worker slot.
func (controller *formalCoxBlockwiseExchangeController) persistRootClaimLocked(
	name string, claim formalCoxBlockwiseExchangeRootClaim,
) error {
	if controller == nil || controller.closed || controller.transport == nil ||
		controller.transport.root == nil || controller.transport.closed {
		return fmt.Errorf("formal-cox: exchange root claim is unavailable")
	}
	if name != formalCoxBlockwiseExchangeLocalRootClaimFile &&
		name != formalCoxBlockwiseExchangePeerRootClaimFile {
		return fmt.Errorf("formal-cox: exchange root claim name is invalid")
	}
	encoded, err := formalCoxBlockwiseExchangeMarshalRootClaim(claim)
	if err != nil {
		return err
	}
	defer clear(encoded)
	root := controller.transport.root
	err = formalCoxBlockwiseExchangeTransportWriteInitial(root, name, encoded)
	if os.IsExist(err) {
		existing, readErr := formalCoxBlockwiseExchangeReadRootClaim(root, name)
		if readErr != nil {
			return readErr
		}
		defer clear(existing)
		if !bytes.Equal(existing, encoded) {
			return fmt.Errorf("formal-cox: exchange root claim conflicts")
		}
		return nil
	}
	if err != nil {
		return err
	}
	if err := formalCoxBlockwiseExchangeLeaseSyncRoot(root); err != nil {
		return err
	}
	existing, err := formalCoxBlockwiseExchangeReadRootClaim(root, name)
	if err != nil {
		return err
	}
	defer clear(existing)
	if !bytes.Equal(existing, encoded) {
		return fmt.Errorf("formal-cox: exchange root claim readback changed")
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
	step formalCoxBlockwiseWorkerStep, attempt [32]byte,
	peerClaim formalCoxBlockwiseExchangeRootClaim,
) error {
	if controller == nil {
		return fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.startLockedV1(step, attempt, peerClaim)
}

func (controller *formalCoxBlockwiseExchangeController) startLockedV1(
	step formalCoxBlockwiseWorkerStep, attempt [32]byte,
	peerClaim formalCoxBlockwiseExchangeRootClaim,
) error {
	if controller.closed || controller.started || controller.transport == nil ||
		!controller.transport.peerBound {
		return fmt.Errorf("formal-cox: exchange controller is not peer-bound")
	}
	pairedRoot, err := controller.validatePeerRootClaimLocked(step, attempt, peerClaim)
	if err != nil {
		return err
	}
	localClaim, err := controller.localRootClaimLocked(step, attempt)
	if err != nil {
		return err
	}
	if localClaim.InputRootSHA256 != pairedRoot {
		return fmt.Errorf("formal-cox: exchange root claim pairing mismatch")
	}
	if err := controller.persistRootClaimLocked(
		formalCoxBlockwiseExchangeLocalRootClaimFile, localClaim); err != nil {
		return err
	}
	if err := controller.persistRootClaimLocked(
		formalCoxBlockwiseExchangePeerRootClaimFile, peerClaim); err != nil {
		return err
	}
	bound, err := controller.bridge.BeginAttempt(step, attempt, pairedRoot)
	if err != nil {
		return err
	}
	master, err := controller.bridge.deriveWorkerMasterV1(bound, attempt)
	if err != nil {
		return err
	}
	session, err := formalCoxBlockwiseWorkerSession(
		controller.plan, bound, attempt, master)
	clear(master[:])
	if err != nil {
		return err
	}
	controller.committed = false
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

func formalCoxBlockwiseExchangeClaimAttemptV1(
	claim formalCoxBlockwiseExchangeRootClaim,
) ([32]byte, error) {
	var attempt [32]byte
	if !formalCoxIsSHA256(claim.AttemptID) {
		return attempt, fmt.Errorf("formal-cox: invalid exchange root claim attempt")
	}
	decoded, err := hex.DecodeString(claim.AttemptID)
	if err != nil || len(decoded) != len(attempt) {
		clear(decoded)
		return attempt, fmt.Errorf("formal-cox: invalid exchange root claim attempt")
	}
	copy(attempt[:], decoded)
	clear(decoded)
	return attempt, nil
}

// nextStepLockedV1 derives the only permissible step inside the live owner.
// A command caller may never select an index or a fresh attempt identifier.
func (controller *formalCoxBlockwiseExchangeController) nextStepLockedV1() (formalCoxBlockwiseWorkerStep, error) {
	if controller == nil || controller.closed || controller.started ||
		controller.transport == nil || !controller.transport.peerBound ||
		controller.bridge == nil {
		return formalCoxBlockwiseWorkerStep{}, fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	bridge := controller.bridge
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.closed || bridge.worker == nil {
		return formalCoxBlockwiseWorkerStep{}, fmt.Errorf("formal-cox: exchange controller bridge is unavailable")
	}
	state, err := bridge.worker.Load()
	if err != nil || state.Pending != nil || state.NextStep >= controller.plan.ScheduleSteps {
		return formalCoxBlockwiseWorkerStep{}, fmt.Errorf("formal-cox: exchange controller has no fresh step")
	}
	return formalCoxBlockwiseWorkerStepAt(controller.plan, state.NextStep)
}

func (controller *formalCoxBlockwiseExchangeController) readRootClaimLockedV1(
	name string,
) (formalCoxBlockwiseExchangeRootClaim, bool, error) {
	var zero formalCoxBlockwiseExchangeRootClaim
	if controller == nil || controller.transport == nil || controller.transport.root == nil {
		return zero, false, fmt.Errorf("formal-cox: exchange root claim is unavailable")
	}
	if _, err := controller.transport.root.Lstat(name); os.IsNotExist(err) {
		return zero, false, nil
	} else if err != nil {
		return zero, false, fmt.Errorf("formal-cox: exchange root claim is unsafe")
	}
	encoded, err := formalCoxBlockwiseExchangeReadRootClaim(controller.transport.root, name)
	if err != nil {
		return zero, false, err
	}
	defer clear(encoded)
	claim, err := formalCoxBlockwiseExchangeDecodeRootClaim(encoded)
	if err != nil {
		return zero, false, err
	}
	return claim, true, nil
}

func (controller *formalCoxBlockwiseExchangeController) validateLocalRootClaimLockedV1(
	step formalCoxBlockwiseWorkerStep, attempt [32]byte,
	claim formalCoxBlockwiseExchangeRootClaim,
) error {
	expected, pin, err := controller.rootClaimTemplateLocked(
		step, attempt, controller.peer, controller.transport.remotePeer)
	if err != nil {
		return err
	}
	candidate := claim
	candidate.Signature = nil
	if !reflect.DeepEqual(candidate, expected) {
		return fmt.Errorf("formal-cox: local exchange root claim binding mismatch")
	}
	message, err := formalCoxBlockwiseExchangeRootClaimUnsigned(claim)
	if err != nil {
		return err
	}
	defer clear(message)
	if !ed25519.Verify(pin, message, claim.Signature) {
		return fmt.Errorf("formal-cox: local exchange root claim signature is invalid")
	}
	return nil
}

// OfferV1 is the sole initiator operation.  It persists a signed local root
// claim so a retry returns byte-identical public binding material; the random
// attempt itself never leaves the owner except inside that signed frame.
func (controller *formalCoxBlockwiseExchangeController) OfferV1() (formalCoxBlockwiseExchangeRootClaim, error) {
	var zero formalCoxBlockwiseExchangeRootClaim
	if controller == nil {
		return zero, fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.peer != controller.plan.Policy.ComputePeers[0] {
		return zero, fmt.Errorf("formal-cox: only the designated initiator may offer a root claim")
	}
	step, err := controller.nextStepLockedV1()
	if err != nil {
		return zero, err
	}
	if existing, found, readErr := controller.readRootClaimLockedV1(
		formalCoxBlockwiseExchangeLocalRootClaimFile); readErr != nil {
		return zero, readErr
	} else if found {
		attempt, attemptErr := formalCoxBlockwiseExchangeClaimAttemptV1(existing)
		if attemptErr != nil || controller.validateLocalRootClaimLockedV1(step, attempt, existing) != nil {
			return zero, fmt.Errorf("formal-cox: persisted root offer is invalid")
		}
		return existing, nil
	}
	var attempt [32]byte
	if _, err := crand.Read(attempt[:]); err != nil {
		return zero, err
	}
	claim, err := controller.localRootClaimLocked(step, attempt)
	clear(attempt[:])
	if err != nil {
		return zero, err
	}
	if err := controller.persistRootClaimLocked(
		formalCoxBlockwiseExchangeLocalRootClaimFile, claim); err != nil {
		return zero, err
	}
	controller.committed = false
	return claim, nil
}

// AcceptOfferV1 validates the initiator's frame, derives the evaluator's
// matching claim from the local Rock state, and begins the evaluator step.
func (controller *formalCoxBlockwiseExchangeController) AcceptOfferV1(
	peerClaim formalCoxBlockwiseExchangeRootClaim,
) (formalCoxBlockwiseExchangeRootClaim, error) {
	var zero formalCoxBlockwiseExchangeRootClaim
	if controller == nil {
		return zero, fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.peer != controller.plan.Policy.ComputePeers[1] {
		return zero, fmt.Errorf("formal-cox: only the designated evaluator may accept a root offer")
	}
	step, err := controller.nextStepLockedV1()
	if err != nil {
		return zero, err
	}
	attempt, err := formalCoxBlockwiseExchangeClaimAttemptV1(peerClaim)
	if err != nil {
		return zero, err
	}
	if _, err := controller.validatePeerRootClaimLocked(step, attempt, peerClaim); err != nil {
		return zero, err
	}
	local, err := controller.localRootClaimLocked(step, attempt)
	if err != nil {
		return zero, err
	}
	if err := controller.startLockedV1(step, attempt, peerClaim); err != nil {
		return zero, err
	}
	return local, nil
}

// ConfirmOfferV1 admits the evaluator's signed answer only when it matches
// the already persisted initiator offer.  It never accepts a caller-selected
// step or attempt.
func (controller *formalCoxBlockwiseExchangeController) ConfirmOfferV1(
	peerClaim formalCoxBlockwiseExchangeRootClaim,
) error {
	if controller == nil {
		return fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.peer != controller.plan.Policy.ComputePeers[0] {
		return fmt.Errorf("formal-cox: only the designated initiator may confirm a root offer")
	}
	step, err := controller.nextStepLockedV1()
	if err != nil {
		return err
	}
	local, found, err := controller.readRootClaimLockedV1(
		formalCoxBlockwiseExchangeLocalRootClaimFile)
	if err != nil || !found {
		return fmt.Errorf("formal-cox: root offer is unavailable")
	}
	attempt, err := formalCoxBlockwiseExchangeClaimAttemptV1(local)
	if err != nil || controller.validateLocalRootClaimLockedV1(step, attempt, local) != nil {
		return fmt.Errorf("formal-cox: persisted root offer is invalid")
	}
	if _, err := controller.validatePeerRootClaimLocked(step, attempt, peerClaim); err != nil {
		return err
	}
	return controller.startLockedV1(step, attempt, peerClaim)
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

// CompletionV1 returns the sole durable schedule-completion marker once the
// final receipt pair has committed.  It is deliberately unavailable while a
// step is pending, so an opaque relay cannot turn a transient result or error
// into a public completion claim.
func (controller *formalCoxBlockwiseExchangeController) CompletionV1() (
	formalCoxBlockwiseCompletion, bool, error,
) {
	var zero formalCoxBlockwiseCompletion
	if controller == nil {
		return zero, false, fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed || controller.bridge == nil {
		return zero, false, fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	bridge := controller.bridge
	bridge.mu.Lock()
	if bridge.closed || bridge.worker == nil {
		bridge.mu.Unlock()
		return zero, false, fmt.Errorf("formal-cox: exchange controller bridge is unavailable")
	}
	worker := bridge.worker
	bridge.mu.Unlock()
	state, err := worker.Load()
	if err != nil {
		return zero, false, err
	}
	if state.Pending != nil || state.NextStep < controller.plan.ScheduleSteps {
		return zero, false, nil
	}
	if state.NextStep != controller.plan.ScheduleSteps {
		return zero, false, fmt.Errorf("formal-cox: exchange controller completion is invalid")
	}
	completion, _, err := worker.Completion()
	if err != nil {
		return zero, false, err
	}
	return completion, true, nil
}

func (controller *formalCoxBlockwiseExchangeController) Commit(
	receipts []formalCoxBlockwiseStepReceipt, pins map[string]ed25519.PublicKey,
) error {
	if controller == nil {
		return fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed || controller.running || controller.runErr != nil ||
		(!controller.started && !controller.committed) {
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
	if !controller.committed {
		controller.started = false
		controller.committed = true
	}
	if err := controller.clearCommittedRootClaimsLockedV1(); err != nil {
		return err
	}
	return nil
}

// clearCommittedRootClaimsLockedV1 removes only the now-obsolete root claims
// after the authenticated checkpoint has advanced.  Keeping a controller live
// for the next deterministic schedule step must not preserve a previous
// attempt's root offer, while a crash between the two unlinks remains safe:
// the durable checkpoint is already committed and a later cleanup accepts
// either missing record but rejects a conflicting one.
func (controller *formalCoxBlockwiseExchangeController) clearCommittedRootClaimsLockedV1() error {
	if controller == nil || controller.closed || !controller.committed ||
		controller.running || controller.transport == nil || controller.transport.root == nil ||
		controller.bridge == nil || controller.receipt.AttemptID == "" {
		return fmt.Errorf("formal-cox: exchange controller cannot clear committed root claims")
	}
	step := controller.receipt.Step
	attempt, err := formalCoxBlockwiseExchangeClaimAttemptV1(
		formalCoxBlockwiseExchangeRootClaim{AttemptID: controller.receipt.AttemptID})
	if err != nil {
		return err
	}
	controller.bridge.mu.Lock()
	if controller.bridge.closed || controller.bridge.worker == nil {
		controller.bridge.mu.Unlock()
		return fmt.Errorf("formal-cox: exchange controller bridge is unavailable")
	}
	state, err := controller.bridge.worker.Load()
	controller.bridge.mu.Unlock()
	if err != nil || state.Pending != nil || state.LastReceipt == nil ||
		!formalCoxBlockwiseReceiptEqual(*state.LastReceipt, controller.receipt) ||
		state.NextStep != step.ScheduleIndex+1 {
		return fmt.Errorf("formal-cox: exchange controller checkpoint did not commit the local receipt")
	}
	changed := false
	for _, record := range []struct {
		name  string
		local bool
	}{
		{name: formalCoxBlockwiseExchangeLocalRootClaimFile, local: true},
		{name: formalCoxBlockwiseExchangePeerRootClaimFile},
	} {
		claim, found, readErr := controller.readRootClaimLockedV1(record.name)
		if readErr != nil {
			return readErr
		}
		if !found {
			continue
		}
		claimStep := claim.Step
		receiptStep := step
		receiptStep.InputRoot = ""
		if claim.AttemptID != controller.receipt.AttemptID || claimStep != receiptStep ||
			claim.InputRootSHA256 != step.InputRoot {
			return fmt.Errorf("formal-cox: committed exchange root claim conflicts")
		}
		if record.local {
			err = controller.validateLocalRootClaimLockedV1(claimStep, attempt, claim)
		} else {
			_, err = controller.validatePeerRootClaimLocked(claimStep, attempt, claim)
		}
		if err != nil {
			return err
		}
		if err := controller.transport.root.Remove(record.name); err != nil && !os.IsNotExist(err) {
			return err
		}
		changed = true
	}
	if changed {
		return formalCoxBlockwiseExchangeLeaseSyncRoot(controller.transport.root)
	}
	return nil
}

// commitPinsV1 returns the pinned custodian public keys already
// authenticated by the recipient-local source session.  The outer relay must
// never accept a caller-supplied pinset: a short-lived client is permitted to
// carry signed receipts, not to select their verification authority.
func (controller *formalCoxBlockwiseExchangeController) commitPinsV1() (
	map[string]ed25519.PublicKey, error,
) {
	if controller == nil {
		return nil, fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed || controller.bridge == nil {
		return nil, fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	bridge := controller.bridge
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.closed || bridge.source == nil || bridge.source.session == nil ||
		bridge.source.session.context == nil {
		return nil, fmt.Errorf("formal-cox: exchange controller pinset is unavailable")
	}
	pins := make(map[string]ed25519.PublicKey, len(controller.plan.Policy.CustodianPeers))
	for _, peer := range controller.plan.Policy.CustodianPeers {
		pin := bridge.source.session.context.pins[peer]
		if len(pin) != ed25519.PublicKeySize {
			formalCoxBlockwiseClearPinsV1(pins)
			return nil, fmt.Errorf("formal-cox: exchange controller pinset is invalid")
		}
		pins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	return pins, nil
}

func formalCoxBlockwiseClearPinsV1(pins map[string]ed25519.PublicKey) {
	for peer := range pins {
		clear(pins[peer])
		delete(pins, peer)
	}
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
