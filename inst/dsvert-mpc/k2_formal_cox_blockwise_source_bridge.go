package main

// Rock-local bridge from one recipient-local source spool to one private
// blockwise worker checkpoint. Public pair bindings are checked before the
// local ciphertext is decrypted. A bridge never opens the other compute
// peer's spool or transport key.

import (
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"sync"
)

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
	if session == nil || session.context == nil ||
		!filepath.IsAbs(workerDir) || filepath.Clean(workerDir) != workerDir ||
		len(signingKey) != ed25519.PrivateKeySize ||
		!hmac.Equal(signingKey.Public().(ed25519.PublicKey),
			session.context.pins[recipient]) {
		return nil, fmt.Errorf("formal-cox: invalid source bridge policy")
	}
	// The worker constructor historically normalizes and chmods its directory.
	// Reject unsafe Rock roots first, so the bridge never follows or repairs an
	// attacker-selected path while opening its private checkpoint.
	if err := formalCoxBlockwiseSourceEnsurePrivateDir(workerDir); err != nil {
		return nil, err
	}
	source, err := newFormalCoxBlockwiseSourceStore(
		sourceDir, sourceKey, session, recipient, recipientSecretKey)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*formalCoxBlockwiseSourceBridge, error) {
		_ = source.Close()
		return nil, err
	}
	worker, err := newFormalCoxBlockwiseCheckpointStore(
		workerDir, workerKey, session.context.plan, recipient)
	if err != nil {
		return fail(err)
	}
	if err := worker.Bootstrap(); err != nil {
		return fail(err)
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

func (bridge *formalCoxBlockwiseSourceBridge) Close() error {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.closed {
		return nil
	}
	bridge.closed = true
	clear(bridge.signingKey)
	bridge.signingKey = nil
	if bridge.source == nil {
		return nil
	}
	return bridge.source.Close()
}
