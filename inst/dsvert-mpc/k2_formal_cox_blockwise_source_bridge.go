package main

// Rock-local bridge from one recipient-local source spool to one private
// blockwise worker checkpoint. Public pair bindings are checked before the
// local ciphertext is decrypted. A bridge never opens the other compute
// peer's spool or transport key.

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/hkdf"
)

const (
	formalCoxBlockwiseWorkerMasterVersion = "dsvert-formal-cox-blockwise-worker-master-v1"
	formalCoxBlockwiseWorkerMasterPurpose = "formal_cox_blockwise_x25519_step_master_v1"
	formalCoxBlockwiseWorkerMasterDomain  = "dsVert/formal-cox/blockwise-worker-master/v1"
)

// formalCoxBlockwiseWorkerMasterContext is public binding material only.  The
// X25519 private keys remain in the two recipient-local source stores.
type formalCoxBlockwiseWorkerMasterContext struct {
	Version               string                       `json:"version"`
	Purpose               string                       `json:"purpose"`
	ArtifactID            string                       `json:"artifact_id"`
	PlanSHA256            string                       `json:"plan_sha256"`
	PinsetSHA256          string                       `json:"pinset_sha256"`
	RunID                 string                       `json:"run_id"`
	GarblerPeer           string                       `json:"garbler_peer"`
	GarblerPeerID         string                       `json:"garbler_peer_id"`
	GarblerTicketSHA256   string                       `json:"garbler_ticket_sha256"`
	EvaluatorPeer         string                       `json:"evaluator_peer"`
	EvaluatorPeerID       string                       `json:"evaluator_peer_id"`
	EvaluatorTicketSHA256 string                       `json:"evaluator_ticket_sha256"`
	Step                  formalCoxBlockwiseWorkerStep `json:"step"`
	AttemptID             string                       `json:"attempt_id"`
}

type formalCoxBlockwiseSourceBridge struct {
	mu         sync.Mutex
	source     *formalCoxBlockwiseSourceStore
	worker     *formalCoxBlockwiseCheckpointStore
	plan       formalCoxBlockwisePlan
	peer       string
	signingKey ed25519.PrivateKey
	closed     bool
}

func newFormalCoxBlockwiseSourceBridge(sourceDir string, sourceKey [32]byte,
	session *formalCoxBlockwiseSourceSession, recipient string,
	recipientSecretKey []byte, workerDir string, workerKey [32]byte,
	signingKey ed25519.PrivateKey) (*formalCoxBlockwiseSourceBridge, error) {
	source, err := newFormalCoxBlockwiseSourceStore(
		sourceDir, sourceKey, session, recipient, recipientSecretKey)
	if err != nil {
		return nil, err
	}
	bridge, err := newFormalCoxBlockwiseSourceBridgeFromOpenStore(
		source, workerDir, workerKey, signingKey)
	if err != nil {
		_ = source.Close()
		return nil, err
	}
	return bridge, nil
}

// newFormalCoxBlockwiseSourceBridgeFromOpenStore transfers the already
// locked recipient source store to the bridge. It is used by the private
// worker bootstrap, which must not reopen the source store while taking the
// sole live exact-GC lease.
func newFormalCoxBlockwiseSourceBridgeFromOpenStore(
	source *formalCoxBlockwiseSourceStore, workerDir string, workerKey [32]byte,
	signingKey ed25519.PrivateKey,
) (*formalCoxBlockwiseSourceBridge, error) {
	if source == nil || !filepath.IsAbs(workerDir) ||
		filepath.Clean(workerDir) != workerDir ||
		len(signingKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("formal-cox: invalid source bridge policy")
	}
	source.mu.Lock()
	session, recipient := source.session, source.recipient
	valid := !source.closed && source.owner != nil && session != nil &&
		session.context != nil && hmac.Equal(
		signingKey.Public().(ed25519.PublicKey), session.context.pins[recipient])
	source.mu.Unlock()
	if !valid {
		return nil, fmt.Errorf("formal-cox: invalid source bridge policy")
	}
	// The worker constructor historically normalizes and chmods its directory.
	// Reject unsafe Rock roots first, so the bridge never follows or repairs an
	// attacker-selected path while opening its private checkpoint.
	if err := formalCoxBlockwiseSourceEnsurePrivateDir(workerDir); err != nil {
		return nil, err
	}
	worker, err := newFormalCoxBlockwiseCheckpointStore(
		workerDir, workerKey, session.context.plan, recipient)
	if err != nil {
		return nil, err
	}
	if err := worker.Bootstrap(); err != nil {
		return nil, err
	}
	return &formalCoxBlockwiseSourceBridge{
		source: source, worker: worker, plan: session.context.plan,
		peer: recipient, signingKey: append(ed25519.PrivateKey(nil), signingKey...),
	}, nil
}

// formalCoxBlockwiseSourceBridgePublicSlot validates only signed public
// metadata and ciphertext commitments. It deliberately has no decryption-key
// argument and never calls transportDecryptBytes.
func formalCoxBlockwiseSourceBridgePublicSlot(
	store *formalCoxBlockwiseSourceStore, encoded []byte) (
	formalCoxBlockwiseSourceHeader, string, error) {
	var zero formalCoxBlockwiseSourceHeader
	record, err := formalCoxBlockwiseSourceDecodeBoundSlot(
		encoded, store.session.context.slotMaximum)
	if err != nil {
		return zero, "", err
	}
	envelope, digest, err := formalCoxBlockwiseSourceValidatePublicEnvelope(
		store.session, store.recipient, record.Envelope)
	if err != nil {
		return zero, "", err
	}
	var pairedRoot string
	switch envelope.Header.StepKind {
	case formalCoxBlockwiseStepBlock:
		var manifest formalCoxBlockwiseSourcePairManifest
		if err := formalCoxBlockwiseSourceDecodeCanonical(record.Binding,
			formalCoxBlockwiseSourceBindingMax, "source pair manifest",
			&manifest); err != nil {
			return zero, "", err
		}
		pairedRoot, err = formalCoxBlockwiseSourceValidatePairManifest(
			store.session, manifest, envelope.Header, digest)
	case formalCoxBlockwiseStepUpdate:
		var barrier formalCoxBlockwiseGuardedNoiseBarrier
		if err := formalCoxBlockwiseSourceDecodeCanonical(record.Binding,
			formalCoxBlockwiseSourceBindingMax, "guarded paired noise barrier",
			&barrier); err != nil {
			return zero, "", err
		}
		pairedRoot, err = formalCoxBlockwiseSourceValidateGuardedNoiseBinding(
			store.session, barrier, envelope.Header, digest)
	default:
		err = fmt.Errorf("formal-cox: source slot has no paired binding")
	}
	if err != nil || !formalCoxIsSHA256(pairedRoot) {
		return zero, "", fmt.Errorf("formal-cox: source bridge pair binding failed")
	}
	return envelope.Header, pairedRoot, nil
}

func (bridge *formalCoxBlockwiseSourceBridge) publicInputRootUnlocked(
	step formalCoxBlockwiseWorkerStep) (string, error) {
	want, err := formalCoxBlockwiseWorkerStepAt(bridge.plan, step.ScheduleIndex)
	if err != nil || step.InputRoot != "" || step != want {
		return "", fmt.Errorf("formal-cox: invalid source bridge step")
	}
	if !formalCoxBlockwiseWorkerStepNeedsInput(step) {
		return "", nil
	}
	kind, asset, err := formalCoxBlockwiseSourceStepAsset(
		bridge.plan, step, false)
	if err != nil {
		return "", err
	}
	store := bridge.source
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed || store.owner == nil {
		return "", fmt.Errorf("formal-cox: source bridge spool is closed")
	}
	first, count := bridge.plan.TotalBlocks*
		len(bridge.plan.Policy.CustodianPeers)+asset, 1
	if kind == formalCoxBlockwiseStepBlock {
		first = asset * len(bridge.plan.Policy.CustodianPeers)
		count = len(bridge.plan.Policy.CustodianPeers)
	}
	state, err := store.readState()
	if err != nil {
		return "", err
	}
	if state.NextSlot < first+count {
		return "", fmt.Errorf("formal-cox: source bridge input is one-sided or incomplete")
	}
	pairRoots := make([]string, count)
	for local := 0; local < count; local++ {
		encoded, err := store.readSlot(first + local)
		if err != nil {
			return "", err
		}
		header, pairRoot, err := formalCoxBlockwiseSourceBridgePublicSlot(
			store, encoded)
		if err != nil || header.AssetSlot != first+local {
			return "", fmt.Errorf(
				"formal-cox: invalid, missing, or reordered source bridge slot")
		}
		pairRoots[local] = pairRoot
	}
	return formalCoxBlockwiseSourcePairedStepRoot(
		store.session, step, pairRoots)
}

// PublicInputRoot validates the local spool without decrypting a share.
func (bridge *formalCoxBlockwiseSourceBridge) PublicInputRoot(
	step formalCoxBlockwiseWorkerStep) (string, error) {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.closed {
		return "", fmt.Errorf("formal-cox: source bridge is closed")
	}
	return bridge.publicInputRootUnlocked(step)
}

// formalCoxBlockwiseMatchPublicInputRoots is the share-free two-role gate.
// Its inputs are public commitments, never source stores or plaintext shares.
func formalCoxBlockwiseMatchPublicInputRoots(plan formalCoxBlockwisePlan,
	step formalCoxBlockwiseWorkerStep, roots []string) (string, error) {
	want, err := formalCoxBlockwiseWorkerStepAt(plan, step.ScheduleIndex)
	if err != nil || step.InputRoot != "" || step != want || len(roots) != 2 {
		return "", fmt.Errorf("formal-cox: invalid source bridge root gate")
	}
	if !formalCoxBlockwiseWorkerStepNeedsInput(step) {
		if roots[0] != "" || roots[1] != "" {
			return "", fmt.Errorf("formal-cox: internal worker step received a source root")
		}
		return "", nil
	}
	if !formalCoxIsSHA256(roots[0]) || !formalCoxIsSHA256(roots[1]) ||
		!hmac.Equal([]byte(roots[0]), []byte(roots[1])) {
		return "", fmt.Errorf("formal-cox: compute roles bind different source roots")
	}
	return roots[0], nil
}

// BeginAttempt binds the already matched public root to the durable worker
// step. The local public root is recomputed so callers cannot bypass the
// two-role gate with an unrelated value.
func (bridge *formalCoxBlockwiseSourceBridge) BeginAttempt(
	step formalCoxBlockwiseWorkerStep, attempt [32]byte,
	pairedRoot string) (formalCoxBlockwiseWorkerStep, error) {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.closed {
		return formalCoxBlockwiseWorkerStep{},
			fmt.Errorf("formal-cox: source bridge is closed")
	}
	localRoot, err := bridge.publicInputRootUnlocked(step)
	if err != nil {
		return formalCoxBlockwiseWorkerStep{}, err
	}
	if formalCoxBlockwiseWorkerStepNeedsInput(step) {
		if !formalCoxIsSHA256(pairedRoot) ||
			!hmac.Equal([]byte(localRoot), []byte(pairedRoot)) {
			return formalCoxBlockwiseWorkerStep{},
				fmt.Errorf("formal-cox: source bridge root mismatch")
		}
		step.InputRoot = pairedRoot
	} else if pairedRoot != "" || localRoot != "" {
		return formalCoxBlockwiseWorkerStep{},
			fmt.Errorf("formal-cox: internal worker step received a source root")
	}
	return bridge.worker.BeginAttempt(step, attempt)
}

func formalCoxBlockwiseWorkerMasterContextSHA256(
	context formalCoxBlockwiseWorkerMasterContext,
) ([32]byte, error) {
	var zero [32]byte
	encoded, err := json.Marshal(context)
	if err != nil {
		return zero, err
	}
	defer clear(encoded)
	digest := sha256.Sum256(append(
		[]byte(formalCoxBlockwiseWorkerMasterDomain+"|"), encoded...))
	return digest, nil
}

// deriveWorkerMasterV1 derives the sole GC master for one already-bound Cox
// step from the two signed recipient X25519 tickets.  It deliberately accepts
// no caller-supplied master: changing the plan, compute pair, source root,
// step, or attempt changes the HKDF context before a circuit can start.
func (bridge *formalCoxBlockwiseSourceBridge) deriveWorkerMasterV1(
	step formalCoxBlockwiseWorkerStep, attempt [32]byte,
) ([32]byte, error) {
	var zero [32]byte
	if bridge == nil {
		return zero, fmt.Errorf("formal-cox: source bridge is unavailable")
	}
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.closed || bridge.source == nil ||
		formalCoxBlockwiseValidateWorkerStep(bridge.plan, step) != nil {
		return zero, fmt.Errorf("formal-cox: invalid worker master binding")
	}
	store := bridge.source
	store.mu.Lock()
	if store.closed || store.owner == nil || store.session == nil ||
		store.session.context == nil || store.recipient != bridge.peer ||
		len(store.recipientSK) != sha256.Size {
		store.mu.Unlock()
		return zero, fmt.Errorf("formal-cox: worker master source is unavailable")
	}
	context := store.session.context
	computePeers := context.plan.Policy.ComputePeers
	if len(computePeers) != 2 || computePeers[0] == computePeers[1] ||
		(bridge.peer != computePeers[0] && bridge.peer != computePeers[1]) {
		store.mu.Unlock()
		return zero, fmt.Errorf("formal-cox: invalid worker master compute pair")
	}
	remote := computePeers[0]
	if remote == bridge.peer {
		remote = computePeers[1]
	}
	localTicket, localOK := store.session.tickets[bridge.peer]
	remoteTicket, remoteOK := store.session.tickets[remote]
	localTicketSHA := store.session.ticketSHA256[bridge.peer]
	remoteTicketSHA := store.session.ticketSHA256[remote]
	garblerTicketSHA := store.session.ticketSHA256[computePeers[0]]
	evaluatorTicketSHA := store.session.ticketSHA256[computePeers[1]]
	secret := append([]byte(nil), store.recipientSK...)
	store.mu.Unlock()
	defer clear(secret)
	if !localOK || !remoteOK || !formalCoxIsSHA256(localTicketSHA) ||
		!formalCoxIsSHA256(remoteTicketSHA) ||
		localTicket.RecipientPeerName != bridge.peer ||
		remoteTicket.RecipientPeerName != remote ||
		localTicket.RecipientRole != context.roles[bridge.peer] ||
		remoteTicket.RecipientRole != context.roles[remote] ||
		localTicket.RecipientPeerID != context.peerIDs[bridge.peer] ||
		remoteTicket.RecipientPeerID != context.peerIDs[remote] ||
		len(localTicket.TransportPublicKey) != sha256.Size ||
		len(remoteTicket.TransportPublicKey) != sha256.Size {
		return zero, fmt.Errorf("formal-cox: invalid worker master tickets")
	}
	private, err := ecdh.X25519().NewPrivateKey(secret)
	if err != nil || !hmac.Equal(private.PublicKey().Bytes(), localTicket.TransportPublicKey) {
		return zero, fmt.Errorf("formal-cox: worker master local ticket mismatch")
	}
	masterContext := formalCoxBlockwiseWorkerMasterContext{
		Version:               formalCoxBlockwiseWorkerMasterVersion,
		Purpose:               formalCoxBlockwiseWorkerMasterPurpose,
		ArtifactID:            context.artifactID,
		PlanSHA256:            context.planSHA256,
		PinsetSHA256:          context.pinsetSHA256,
		RunID:                 context.plan.RunID,
		GarblerPeer:           computePeers[0],
		GarblerPeerID:         context.peerIDs[computePeers[0]],
		GarblerTicketSHA256:   garblerTicketSHA,
		EvaluatorPeer:         computePeers[1],
		EvaluatorPeerID:       context.peerIDs[computePeers[1]],
		EvaluatorTicketSHA256: evaluatorTicketSHA,
		Step:                  step,
		AttemptID:             hex.EncodeToString(attempt[:]),
	}
	contextDigest, err := formalCoxBlockwiseWorkerMasterContextSHA256(masterContext)
	if err != nil {
		return zero, err
	}
	peerKey, err := ecdh.X25519().NewPublicKey(remoteTicket.TransportPublicKey)
	if err != nil {
		return zero, fmt.Errorf("formal-cox: invalid worker master peer ticket")
	}
	shared, err := private.ECDH(peerKey)
	if err != nil {
		return zero, fmt.Errorf("formal-cox: worker master key agreement failed")
	}
	defer clear(shared)
	var master [32]byte
	reader := hkdf.New(sha256.New, shared, contextDigest[:],
		[]byte(formalCoxBlockwiseWorkerMasterDomain))
	if _, err := io.ReadFull(reader, master[:]); err != nil {
		clear(master[:])
		return zero, fmt.Errorf("formal-cox: worker master derivation failed")
	}
	return master, nil
}

// RunPendingWorkerStep verifies the public root again before SourceStore.Load
// decrypts the one recipient-local share. A recorded output is replayed by
// signing the same durable receipt and never re-running the circuit.
func (bridge *formalCoxBlockwiseSourceBridge) RunPendingWorkerStep(
	rw io.ReadWriter, session exactGCSession) (
	formalCoxBlockwiseStepReceipt, error) {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.closed {
		return formalCoxBlockwiseStepReceipt{},
			fmt.Errorf("formal-cox: source bridge is closed")
	}
	state, err := bridge.worker.Load()
	if err != nil {
		return formalCoxBlockwiseStepReceipt{}, err
	}
	if state.Pending == nil ||
		state.Pending.AttemptID != hex.EncodeToString(session.SessionID[:]) ||
		formalCoxBlockwiseValidateWorkerSession(
			bridge.plan, state.Pending.Step, session) != nil {
		return formalCoxBlockwiseStepReceipt{},
			fmt.Errorf("formal-cox: source bridge has no matching pending step")
	}
	if state.Pending.OutputRecorded {
		return bridge.worker.PendingReceipt(bridge.signingKey)
	}
	step := state.Pending.Step
	var input formalCoxBlockwiseSourceInput
	if formalCoxBlockwiseWorkerStepNeedsInput(step) {
		sourceStep := step
		sourceStep.InputRoot = ""
		publicRoot, err := bridge.publicInputRootUnlocked(sourceStep)
		if err != nil || !hmac.Equal(
			[]byte(publicRoot), []byte(step.InputRoot)) {
			return formalCoxBlockwiseStepReceipt{},
				fmt.Errorf("formal-cox: pending worker source root changed")
		}
		input, err = bridge.source.Load(sourceStep)
		if err != nil {
			return formalCoxBlockwiseStepReceipt{}, err
		}
		defer exactGCZeroBigInts(input.Shares)
		if input.RecipientPeer != bridge.peer || input.Step != sourceStep ||
			!hmac.Equal([]byte(input.PairedInputRootSHA256),
				[]byte(publicRoot)) {
			return formalCoxBlockwiseStepReceipt{},
				fmt.Errorf("formal-cox: decrypted source input changed its public binding")
		}
	}
	return bridge.worker.RunPendingWorkerStep(
		rw, session, input.Shares, input.ValidityShare, bridge.signingKey)
}

// SubmitStickyOpening transfers only the signed public handoff from a
// completed bridge to the owner-only finalizer.  Checkpoint state, the local
// coefficient shares and the signing key remain bridge-owned; callers cannot
// supply a different checkpoint or key at this boundary.
func (bridge *formalCoxBlockwiseSourceBridge) SubmitStickyOpening(
	opening *formalCoxBlockwiseOpeningStore,
) (formalCoxBlockwiseOpeningHandoffHeader, bool, error) {
	var zero formalCoxBlockwiseOpeningHandoffHeader
	if bridge == nil || opening == nil {
		return zero, false, fmt.Errorf("formal-cox: invalid sticky opening bridge")
	}
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.closed || bridge.worker == nil || bridge.source == nil ||
		len(bridge.signingKey) != ed25519.PrivateKeySize {
		return zero, false, fmt.Errorf("formal-cox: sticky opening bridge is closed")
	}
	return opening.SubmitLocal(bridge.worker, bridge.signingKey)
}

// SealStickyOpeningToFinalizerV1 turns an already committed local opening
// into the existing authority-only finalizer envelope.  The bridge chooses
// both the local peer and its signing key; callers can supply neither a share
// nor a replacement source or checkpoint.
func (bridge *formalCoxBlockwiseSourceBridge) SealStickyOpeningToFinalizerV1(
	opening *formalCoxBlockwiseOpeningStore,
	outbox *formalFinalizerHandoffStore,
	ticket formalFinalizerHandoffTicket,
	headers [2]formalCoxBlockwiseOpeningHandoffHeader,
) (formalFinalizerHandoffEnvelope, bool, error) {
	var zero formalFinalizerHandoffEnvelope
	if bridge == nil || opening == nil || outbox == nil {
		return zero, false, fmt.Errorf("formal-cox: invalid sticky finalizer handoff")
	}
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.closed || bridge.worker == nil || bridge.source == nil ||
		len(bridge.signingKey) != ed25519.PrivateKeySize {
		return zero, false, fmt.Errorf("formal-cox: sticky finalizer bridge is closed")
	}
	planSHA, err := formalCoxBlockwisePlanSHA256(bridge.plan)
	if err != nil || opening.planSHA256 != planSHA ||
		opening.plan.RunID != bridge.plan.RunID {
		return zero, false, fmt.Errorf("formal-cox: sticky finalizer opening binding mismatch")
	}
	peer := bridge.peer
	position := -1
	for index, candidate := range opening.plan.Policy.ComputePeers {
		if candidate == peer {
			position = index
			break
		}
	}
	local, err := opening.loadPrivateHandoff(peer)
	if err != nil || position < 0 || !formalCoxBlockwiseOpeningEqual(
		local, headers[position],
	) {
		return zero, false, fmt.Errorf("formal-cox: sticky finalizer header mismatch")
	}
	return formalCoxBlockwiseSealLocalOpening(
		opening, outbox, ticket, headers, peer, bridge.signingKey)
}

func (bridge *formalCoxBlockwiseSourceBridge) Close() error {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.closed {
		return nil
	}
	bridge.closed = true
	clear(bridge.signingKey)
	bridge.signingKey = nil
	if bridge.worker != nil {
		clear(bridge.worker.key[:])
	}
	if bridge.source == nil {
		return nil
	}
	return bridge.source.Close()
}
