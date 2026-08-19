package main

// Registered, RAM-only adapter from the Phase19 accumulator to the existing
// durable Phase15 optimizer and sealed DP bridge. Legacy aliases never cross
// this trust boundary and the raw schedule result is consumable only by the
// registered Phase20 evidence builder below.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sync"
)

const (
	formalGLMRegisteredPhase19ScheduleTailDomainV1 = "dsVert/formal-glm/registered-phase19/schedule-tail/v1"
	formalGLMRegisteredPhase19ScheduleTailDirV1    = "registered-phase19-schedule-tail-v1"
)

// All fields are private. In particular, neither the legacy plan/context nor
// the checkpoint path/key can acquire a JSON representation.
type formalGLMRegisteredPhase19ScheduleTailV1 struct {
	mu sync.Mutex

	root               *os.Root
	checkpointRelative string
	checkpointDir      string
	checkpointKey      [32]byte
	signingKey         ed25519.PrivateKey
	pins               map[string]ed25519.PublicKey
	binding            formalGLMRegisteredPhase19AttemptBindingV1
	semanticRootSHA256 string
	peer               string
	role               string
	plan               formalGLMPhase15Plan
	context            formalGLMPhase19Context
	accumulator        formalGLMPhase19AccumulatorPlan
	summary            formalGLMPhase19BlockScheduleSummary
	backendKey         [32]byte
	rootAttempt        [32]byte
	localSeal          formalGLMPhase19ExecutionSeal
	executionPair      formalGLMPhase19ExecutionReceiptPair
	store              *formalGLMPhase19StreamStore
	execution          *formalGLMRegisteredPhase19AccumulatorExecutionV1
	outputLatticeBits  int
	running            bool
	failed             bool
	finished           bool
	closeRequested     bool
	closed             bool
}

// The raw legacy result remains behind a non-serializable, single-consumer
// trust object. Its only production exit is BuildPreparedEvidenceV1.
type formalGLMRegisteredPhase19ScheduleTailResultV1 struct {
	mu sync.Mutex

	raw            formalGLMPhase19ScheduleResult
	binding        formalGLMRegisteredPhase19AttemptBindingV1
	execution      *formalGLMRegisteredPhase19AccumulatorExecutionV1
	building       bool
	closeRequested bool
	consumed       bool
	closed         bool
}

type formalGLMRegisteredPhase19ScheduleTailSlotInputV1 struct {
	SemanticRootSHA256 string `json:"semantic_root_sha256"`
	AttemptID          string `json:"attempt_id"`
	ScheduleRootSHA256 string `json:"schedule_root_sha256"`
	Peer               string `json:"peer"`
	LocalIndex         int    `json:"local_index"`
}

func formalGLMRegisteredPhase19ScheduleTailClonePinsV1(
	pins map[string]ed25519.PublicKey,
) map[string]ed25519.PublicKey {
	cloned := make(map[string]ed25519.PublicKey, len(pins))
	for peer, pin := range pins {
		cloned[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	return cloned
}

func formalGLMRegisteredPhase19ScheduleTailClearPinsV1(
	pins map[string]ed25519.PublicKey,
) {
	for peer, pin := range pins {
		clear(pin)
		delete(pins, peer)
	}
}

func formalGLMRegisteredPhase19ScheduleTailSameRootV1(
	left, right *os.Root,
) bool {
	if left == nil || right == nil {
		return false
	}
	leftInfo, leftErr := left.Stat(".")
	rightInfo, rightErr := right.Stat(".")
	return leftErr == nil && rightErr == nil && os.SameFile(leftInfo, rightInfo) &&
		leftInfo.Mode().Perm() == 0o700 && rightInfo.Mode().Perm() == 0o700 &&
		formalFinalizerHandoffPrivateOwnedDirectory(leftInfo) &&
		formalFinalizerHandoffPrivateOwnedDirectory(rightInfo)
}

func formalGLMRegisteredPhase19ScheduleTailPersistClaimV1(
	store *formalGLMRegisteredPhase19AttemptStoreV1,
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
	peer string,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
) error {
	if store == nil {
		return fmt.Errorf("formal-glm registered Phase19 schedule tail: missing attempt owner")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil || store.localIndex < 0 || store.localIndex > 1 ||
		store.contract.Core.RegisteredExecutionPlan.DesignatedComputePeers[store.localIndex] != peer ||
		!reflect.DeepEqual(store.record, record) ||
		!reflect.DeepEqual(store.contract, contract) ||
		!reflect.DeepEqual(store.pins, pins) ||
		store.validateAcceptV1(proposal, accept) != nil {
		return fmt.Errorf("formal-glm registered Phase19 schedule tail: invalid accepted claim")
	}
	if _, err := store.commitAcceptV1(proposal, accept); err != nil {
		return err
	}
	for _, file := range []string{
		formalGLMRegisteredPhase19DecisionVote0FileV1,
		formalGLMRegisteredPhase19DecisionVote1FileV1,
		formalGLMRegisteredPhase19AbandonedFileV1,
	} {
		path := store.attemptRelativePathV1(proposal.Binding.AttemptID, file)
		if _, err := store.root.Lstat(path); err == nil {
			return fmt.Errorf(
				"formal-glm registered Phase19 schedule tail: attempt is abandoning")
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	persistedProposal, foundProposal, proposalErr :=
		formalGLMRegisteredPhase19AttemptReadV1[formalGLMRegisteredPhase19ClaimProposalV1](
			store.root, store.attemptRelativePathV1(
				proposal.Binding.AttemptID,
				formalGLMRegisteredPhase19ClaimProposalFileV1))
	persistedAccept, foundAccept, acceptErr :=
		formalGLMRegisteredPhase19AttemptReadV1[formalGLMRegisteredPhase19ClaimAcceptV1](
			store.root, store.attemptRelativePathV1(
				proposal.Binding.AttemptID,
				formalGLMRegisteredPhase19ClaimAcceptFileV1))
	if proposalErr != nil || acceptErr != nil || !foundProposal || !foundAccept ||
		!reflect.DeepEqual(persistedProposal, proposal) ||
		!reflect.DeepEqual(persistedAccept, accept) {
		return fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: accepted claim is not durable")
	}
	return nil
}

func formalGLMRegisteredPhase19ScheduleTailPublicPairV1(
	pair formalGLMPhase19ExecutionReceiptPair,
	semanticRootSHA256 string,
) formalGLMRegisteredPhase19AccumulatorReceiptPairV1 {
	return formalGLMRegisteredPhase19AccumulatorReceiptPairV1{
		Version:                    formalGLMRegisteredPhase19AccumulatorPairVersionV1,
		Purpose:                    formalGLMRegisteredPhase19AccumulatorPairPurposeV1,
		SemanticRootSHA256:         semanticRootSHA256,
		AccumulatorRoot:            pair.AccumulatorRoot,
		GarblerReceiptSHA256:       pair.GarblerReceiptSHA256,
		EvaluatorReceiptSHA256:     pair.EvaluatorReceiptSHA256,
		ExecutionReceiptPairSHA256: pair.ExecutionReceiptPairSHA256,
		ExecutionValidSealed:       pair.ExecutionValidSealed,
		ExecutionValidityOpened:    pair.ExecutionValidityOpened,
		OpeningsPerformed:          pair.OpeningsPerformed,
		ProductionReady:            pair.ProductionReady,
	}
}

func formalGLMRegisteredPhase19ScheduleTailValidateEvidenceV1(
	snapshot formalGLMRegisteredPhase19AccumulatorSnapshotV1,
	localSeal *formalGLMRegisteredPhase19AccumulatorSealV1,
	pair *formalGLMRegisteredPhase19AccumulatorReceiptPairV1,
	expectedSessionID [32]byte,
) error {
	if localSeal == nil || pair == nil {
		return fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: missing accumulator trust")
	}
	if localSeal.Receipt.Receipt != localSeal.seal.Receipt ||
		localSeal.Receipt.Peer != snapshot.peer ||
		localSeal.seal.Receipt.SessionID != hex.EncodeToString(expectedSessionID[:]) {
		return fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: accumulator seal binding mismatch")
	}
	if err := formalGLMRegisteredPhase19ValidateAccumulatorReceiptV1(
		snapshot, localSeal.Receipt); err != nil {
		return fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: invalid local accumulator receipt: %w", err)
	}
	if err := formalGLMPhase19VerifyExecutionSeal(
		snapshot.context, snapshot.accumulator,
		localSeal.seal, snapshot.backendKey); err != nil {
		return fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: invalid hidden accumulator seal: %w", err)
	}
	if err := formalGLMPhase19VerifyExecutionReceiptPair(
		snapshot.context, snapshot.accumulator,
		pair.pair, snapshot.backendKey); err != nil {
		return fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: invalid private accumulator pair: %w", err)
	}
	if pair.Public() != formalGLMRegisteredPhase19ScheduleTailPublicPairV1(
		pair.pair, snapshot.semanticRootSHA256) {
		return fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: accumulator pair wrapper mismatch")
	}
	return nil
}

func formalGLMRegisteredPhase19ScheduleTailAccumulatorV1(
	execution *formalGLMRegisteredPhase19AccumulatorExecutionV1,
	localSeal *formalGLMRegisteredPhase19AccumulatorSealV1,
	pair *formalGLMRegisteredPhase19AccumulatorReceiptPairV1,
	wantAttempt [32]byte,
	claim bool,
) (formalGLMRegisteredPhase19AccumulatorSnapshotV1, error) {
	var zero formalGLMRegisteredPhase19AccumulatorSnapshotV1
	if execution == nil || localSeal == nil || pair == nil {
		return zero, fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: missing accumulator trust")
	}
	execution.mu.Lock()
	defer execution.mu.Unlock()
	if err := execution.validateLocked(); err != nil || !execution.claimed ||
		execution.running || !execution.succeeded || execution.closeRequested ||
		execution.owner == nil || execution.attempt != wantAttempt {
		return zero, fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: accumulator is not continuable")
	}
	owner := execution.owner
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := owner.validateLocked(); err != nil ||
		owner.state != formalGLMRegisteredPhase19AccumulatorStoreClaimedV1 ||
		owner.holder != execution || owner.store == nil || !owner.store.complete {
		return zero, fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: accumulator owner mismatch")
	}
	role, err := formalGLMRegisteredPhase19AccumulatorRoleV1(
		execution.context, execution.peer)
	if err != nil {
		return zero, err
	}
	snapshot := formalGLMRegisteredPhase19AccumulatorSnapshotV1{
		semanticRootSHA256:            execution.semanticRootSHA256,
		receiptSetSHA256:              execution.receiptSetSHA256,
		registeredExecutionPlanSHA256: execution.registeredExecutionPlanSHA256,
		peer:                          execution.peer, role: role,
		plan:        formalGLMRegisteredPhase19ClonePlanV1(execution.plan),
		context:     formalGLMRegisteredPhase19CloneContextV1(execution.context),
		accumulator: execution.accumulator, attempt: execution.attempt,
		backendKey: execution.backendKey, store: owner.store,
	}
	finalSession, err := formalGLMPhase19BoundedAccumulatorSession(
		snapshot.plan, snapshot.context, snapshot.accumulator, wantAttempt,
		"final", 0, 0, 1, snapshot.backendKey)
	if err != nil {
		snapshot.clear()
		return zero, err
	}
	expectedSessionID := finalSession.SessionID
	clear(finalSession.SessionID[:])
	clear(finalSession.MasterKey[:])
	if err := formalGLMRegisteredPhase19ScheduleTailValidateEvidenceV1(
		snapshot, localSeal, pair, expectedSessionID); err != nil {
		clear(expectedSessionID[:])
		snapshot.clear()
		return zero, err
	}
	clear(expectedSessionID[:])
	receiptBytes, err := json.Marshal(localSeal.Receipt.Receipt)
	if err != nil {
		snapshot.clear()
		return zero, err
	}
	receiptSHA256 := sha256.Sum256(receiptBytes)
	clear(receiptBytes)
	wantReceipt := pair.pair.EvaluatorReceiptSHA256
	if role == "garbler" {
		wantReceipt = pair.pair.GarblerReceiptSHA256
	}
	if wantReceipt != hex.EncodeToString(receiptSHA256[:]) {
		clear(receiptSHA256[:])
		snapshot.clear()
		return zero, fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: local seal is not paired")
	}
	clear(receiptSHA256[:])
	if claim {
		execution.running = true
	}
	return snapshot, nil
}

func formalGLMRegisteredPhase19ScheduleTailReleaseAccumulatorV1(
	execution *formalGLMRegisteredPhase19AccumulatorExecutionV1,
	destroy bool,
) error {
	if execution == nil {
		return nil
	}
	execution.mu.Lock()
	if execution.running {
		execution.running = false
	}
	closeRequested := execution.closeRequested
	execution.mu.Unlock()
	if destroy || closeRequested {
		return execution.Close()
	}
	return nil
}

func formalGLMRegisteredPhase19ScheduleTailCheckpointV1(
	rockRoot string,
	root *os.Root,
	provider *formalGLMRegisteredPhase20JobKeyProviderV1,
	binding formalGLMRegisteredPhase19AttemptBindingV1,
	peer string,
	localIndex int,
) (relative, absolute string, key [32]byte, err error) {
	if root == nil || provider == nil {
		return "", "", key, fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: missing job owner")
	}
	provider.mu.Lock()
	if validateErr := provider.validateLocked(); validateErr != nil ||
		provider.context.localPeer != peer || provider.context.localIndex != localIndex ||
		!formalGLMRegisteredPhase19ScheduleTailSameRootV1(root, provider.root) {
		provider.mu.Unlock()
		return "", "", key, fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: job owner mismatch")
	}
	base := provider.slotRelativeDir
	provider.mu.Unlock()
	attemptKey, err := provider.DeriveAttemptKey(binding)
	if err != nil {
		return "", "", key, err
	}
	defer clear(attemptKey[:])
	bindingBytes, err := json.Marshal(binding)
	if err != nil {
		return "", "", key, err
	}
	keyMessage := formalGLMPhase15AppendString(
		bindingBytes, peer)
	key = formalGLMPhase19MAC(attemptKey,
		formalGLMRegisteredPhase19ScheduleTailDomainV1+"/checkpoint-key",
		keyMessage)
	clear(keyMessage)
	if !formalGLMPhase19KeyValid(key) {
		clear(key[:])
		return "", "", key, fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: checkpoint key derivation failed")
	}
	slot, err := formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase19ScheduleTailDomainV1+"/checkpoint-slot",
		formalGLMRegisteredPhase19ScheduleTailSlotInputV1{
			SemanticRootSHA256: binding.SemanticRootSHA256,
			AttemptID:          binding.AttemptID, ScheduleRootSHA256: binding.ScheduleRootSHA256,
			Peer: peer, LocalIndex: localIndex,
		})
	if err != nil {
		clear(key[:])
		return "", "", key, err
	}
	relative = filepath.Join(base,
		formalGLMRegisteredPhase19ScheduleTailDirV1+"-"+slot)
	if err := formalGLMRegisteredPhase18TicketStoreEnsureDirV1(
		root, relative); err != nil {
		clear(key[:])
		return "", "", key, err
	}
	resolved, err := filepath.EvalSymlinks(rockRoot)
	if err != nil || !filepath.IsAbs(resolved) {
		clear(key[:])
		return "", "", key, fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: redirected Rock root")
	}
	absolute = filepath.Join(filepath.Clean(resolved), relative)
	relativeInfo, relativeErr := root.Lstat(relative)
	absoluteInfo, absoluteErr := os.Lstat(absolute)
	if relativeErr != nil || absoluteErr != nil ||
		!os.SameFile(relativeInfo, absoluteInfo) || !absoluteInfo.IsDir() ||
		absoluteInfo.Mode().Perm() != 0o700 ||
		!formalFinalizerHandoffPrivateOwnedDirectory(absoluteInfo) {
		clear(key[:])
		return "", "", key, fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: unsafe checkpoint slot")
	}
	return relative, absolute, key, nil
}

func newFormalGLMRegisteredPhase19ScheduleTailV1(
	rockRoot string,
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
	attemptStore *formalGLMRegisteredPhase19AttemptStoreV1,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	jobKeys *formalGLMRegisteredPhase20JobKeyProviderV1,
	execution *formalGLMRegisteredPhase19AccumulatorExecutionV1,
	localSeal *formalGLMRegisteredPhase19AccumulatorSealV1,
	pair *formalGLMRegisteredPhase19AccumulatorReceiptPairV1,
	signingKey ed25519.PrivateKey,
) (*formalGLMRegisteredPhase19ScheduleTailV1, error) {
	if runtime == nil || attemptStore == nil || jobKeys == nil || execution == nil ||
		localSeal == nil || pair == nil || proposal.Binding != accept.Binding ||
		len(signingKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: invalid preparation")
	}
	runtime.mu.Lock()
	if err := runtime.validateLocked(); err != nil {
		runtime.mu.Unlock()
		return nil, err
	}
	if err := formalGLMRegisteredPhase20ValidatePlanLockedV1(
		runtime, contract, pins); err != nil {
		runtime.mu.Unlock()
		return nil, err
	}
	if err := formalGLMRegisteredPhase20ValidateAttemptBindingLockedV1(
		runtime, record, contract, proposal.Binding, pins); err != nil {
		runtime.mu.Unlock()
		return nil, err
	}
	plan := formalGLMRegisteredPhase19ClonePlanV1(runtime.legacyPlan)
	context := formalGLMRegisteredPhase19CloneContextV1(runtime.context)
	semanticRoot := runtime.semanticRootSHA256
	receiptSet := runtime.receiptSetSHA256
	registeredPlan := runtime.registeredExecutionPlanSHA256
	backendKey := runtime.backendKey
	runtime.mu.Unlock()
	rootAttempt, err := formalGLMPhase19ScheduleDecodeHex32(
		proposal.Binding.ScheduleRootSHA256, "root")
	if err != nil {
		clear(backendKey[:])
		return nil, err
	}
	wantAccumulatorAttempt := formalGLMPhase19RuntimeAttempt(
		rootAttempt, "phase19-accumulator", 0, -1)
	snapshot, err := formalGLMRegisteredPhase19ScheduleTailAccumulatorV1(
		execution, localSeal, pair, wantAccumulatorAttempt, false)
	clear(wantAccumulatorAttempt[:])
	if err != nil {
		clear(rootAttempt[:])
		clear(backendKey[:])
		return nil, err
	}
	defer snapshot.clear()
	if snapshot.semanticRootSHA256 != semanticRoot ||
		snapshot.receiptSetSHA256 != receiptSet ||
		snapshot.registeredExecutionPlanSHA256 != registeredPlan ||
		snapshot.backendKey != backendKey ||
		!formalGLMRegisteredPhase19AccumulatorSameScheduleV1(
			plan, snapshot.plan, context, snapshot.context) {
		clear(rootAttempt[:])
		clear(backendKey[:])
		return nil, fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: runtime/accumulator mismatch")
	}
	peer := snapshot.peer
	if public, ok := signingKey.Public().(ed25519.PublicKey); !ok ||
		!bytes.Equal(public, pins[peer]) {
		clear(rootAttempt[:])
		clear(backendKey[:])
		return nil, fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: invalid checkpoint signer")
	}
	rock, err := formalGLMRegisteredPhase19OpenRockRootV1(rockRoot)
	if err != nil {
		clear(rootAttempt[:])
		clear(backendKey[:])
		return nil, err
	}
	closeRock := true
	defer func() {
		if closeRock {
			_ = rock.Close()
		}
	}()
	attemptStore.mu.Lock()
	storeRootMatches := formalGLMRegisteredPhase19ScheduleTailSameRootV1(
		rock, attemptStore.root)
	localIndex := attemptStore.localIndex
	attemptStore.mu.Unlock()
	if !storeRootMatches {
		clear(rootAttempt[:])
		clear(backendKey[:])
		return nil, fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: attempt owner Rock mismatch")
	}
	if err := formalGLMRegisteredPhase19ScheduleTailPersistClaimV1(
		attemptStore, record, contract, pins, peer, proposal, accept); err != nil {
		clear(rootAttempt[:])
		clear(backendKey[:])
		return nil, err
	}
	checkpointRelative, checkpointDir, checkpointKey, err :=
		formalGLMRegisteredPhase19ScheduleTailCheckpointV1(
			rockRoot, rock, jobKeys, proposal.Binding, peer, localIndex)
	if err != nil {
		clear(rootAttempt[:])
		clear(backendKey[:])
		return nil, err
	}
	wantAccumulatorAttempt = formalGLMPhase19RuntimeAttempt(
		rootAttempt, "phase19-accumulator", 0, -1)
	claimed, err := formalGLMRegisteredPhase19ScheduleTailAccumulatorV1(
		execution, localSeal, pair, wantAccumulatorAttempt, true)
	clear(wantAccumulatorAttempt[:])
	if err != nil {
		clear(rootAttempt[:])
		clear(backendKey[:])
		clear(checkpointKey[:])
		return nil, err
	}
	summary, err := claimed.store.Summary()
	if err != nil {
		_ = formalGLMRegisteredPhase19ScheduleTailReleaseAccumulatorV1(
			execution, false)
		claimed.clear()
		clear(rootAttempt[:])
		clear(backendKey[:])
		clear(checkpointKey[:])
		return nil, err
	}
	tail := &formalGLMRegisteredPhase19ScheduleTailV1{
		root: rock, checkpointRelative: checkpointRelative,
		checkpointDir: checkpointDir, checkpointKey: checkpointKey,
		signingKey: append(ed25519.PrivateKey(nil), signingKey...),
		pins:       formalGLMRegisteredPhase19ScheduleTailClonePinsV1(pins),
		binding:    proposal.Binding, semanticRootSHA256: semanticRoot,
		peer: peer, role: claimed.role,
		plan: claimed.plan, context: claimed.context,
		accumulator: claimed.accumulator, summary: summary,
		backendKey: backendKey, rootAttempt: rootAttempt,
		localSeal: localSeal.seal, executionPair: pair.pair,
		store: claimed.store, execution: execution,
		outputLatticeBits: contract.Core.RegisteredExecutionPlan.
			CanonicalDP.OutputLatticeBits,
	}
	claimed.plan = formalGLMPhase15Plan{}
	claimed.context = formalGLMPhase19Context{}
	claimed.store = nil
	claimed.clear()
	localSeal.Close()
	pair.Close()
	clear(checkpointKey[:])
	clear(rootAttempt[:])
	clear(backendKey[:])
	closeRock = false
	return tail, nil
}

func (tail *formalGLMRegisteredPhase19ScheduleTailV1) validateLocked() error {
	if tail == nil || tail.closed || tail.failed || tail.finished || tail.root == nil ||
		tail.execution == nil || tail.store == nil || !tail.store.complete ||
		!formalGLMPhase19KeyValid(tail.checkpointKey) ||
		!formalGLMPhase19KeyValid(tail.backendKey) ||
		!formalGLMPhase19KeyValid(tail.rootAttempt) ||
		len(tail.signingKey) != ed25519.PrivateKeySize ||
		tail.binding.SemanticRootSHA256 != tail.semanticRootSHA256 ||
		tail.binding.ScheduleRootSHA256 != hex.EncodeToString(tail.rootAttempt[:]) ||
		tail.localSeal.Receipt.Peer != tail.peer || !tail.localSeal.verified ||
		!tail.executionPair.verified {
		return fmt.Errorf("formal-glm registered Phase19 schedule tail: unavailable")
	}
	return nil
}

func (tail *formalGLMRegisteredPhase19ScheduleTailV1) validateCheckpointLocked() error {
	if err := formalGLMRegisteredPhase18TicketStoreValidateDirV1(
		tail.root, tail.checkpointRelative); err != nil {
		return err
	}
	relativeInfo, relativeErr := tail.root.Lstat(tail.checkpointRelative)
	absoluteInfo, absoluteErr := os.Lstat(tail.checkpointDir)
	if relativeErr != nil || absoluteErr != nil ||
		!os.SameFile(relativeInfo, absoluteInfo) || !absoluteInfo.IsDir() ||
		absoluteInfo.Mode().Perm() != 0o700 ||
		!formalFinalizerHandoffPrivateOwnedDirectory(absoluteInfo) {
		return fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: checkpoint slot changed")
	}
	return nil
}

func formalGLMRegisteredPhase19ScheduleTailClearRawV1(
	raw *formalGLMPhase19ScheduleResult,
) {
	if raw == nil {
		return
	}
	clear(raw.PostExecutionToken.seal[:])
	raw.PostExecutionToken.verified = false
	clear(raw.ExecutionReceiptPair.seal[:])
	raw.ExecutionReceiptPair.verified = false
	raw.DPShare = ""
	*raw = formalGLMPhase19ScheduleResult{}
}

func (tail *formalGLMRegisteredPhase19ScheduleTailV1) clearLocked() *os.Root {
	clear(tail.checkpointKey[:])
	clear(tail.backendKey[:])
	clear(tail.rootAttempt[:])
	clear(tail.signingKey)
	tail.signingKey = nil
	formalGLMRegisteredPhase19ScheduleTailClearPinsV1(tail.pins)
	clear(tail.localSeal.seal[:])
	tail.localSeal.share = 0
	tail.localSeal.verified = false
	clear(tail.executionPair.seal[:])
	tail.executionPair.verified = false
	tail.plan = formalGLMPhase15Plan{}
	tail.context = formalGLMPhase19Context{}
	tail.store = nil
	root := tail.root
	tail.root = nil
	return root
}

func (tail *formalGLMRegisteredPhase19ScheduleTailV1) failRunV1(
	runErr error,
) error {
	tail.mu.Lock()
	tail.running = false
	tail.failed = true
	closeRequested := tail.closeRequested
	execution := tail.execution
	tail.mu.Unlock()
	releaseErr := formalGLMRegisteredPhase19ScheduleTailReleaseAccumulatorV1(
		execution, false)
	if closeRequested {
		if closeErr := tail.Close(); releaseErr == nil {
			releaseErr = closeErr
		}
	}
	if releaseErr != nil {
		return fmt.Errorf("%v; schedule-tail release: %w", runErr, releaseErr)
	}
	return runErr
}

func formalGLMRegisteredPhase19RunScheduleTailPeerV1(
	rw io.ReadWriter,
	tail *formalGLMRegisteredPhase19ScheduleTailV1,
) (*formalGLMRegisteredPhase19ScheduleTailResultV1, error) {
	if rw == nil || tail == nil {
		return nil, fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: nil peer channel")
	}
	tail.mu.Lock()
	if err := tail.validateLocked(); err != nil || tail.running ||
		tail.closeRequested {
		tail.mu.Unlock()
		return nil, fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: execution unavailable")
	}
	if err := tail.validateCheckpointLocked(); err != nil {
		tail.mu.Unlock()
		return nil, err
	}
	tail.running = true
	tail.mu.Unlock()

	durable := formalGLMPhase19RuntimeDurableConfig{
		CheckpointDir: tail.checkpointDir, CheckpointKey: tail.checkpointKey,
		SigningKey:        append(ed25519.PrivateKey(nil), tail.signingKey...),
		Pins:              formalGLMRegisteredPhase19ScheduleTailClonePinsV1(tail.pins),
		OutputLatticeBits: tail.outputLatticeBits,
	}
	defer func() {
		clear(durable.CheckpointKey[:])
		clear(durable.SigningKey)
		formalGLMRegisteredPhase19ScheduleTailClearPinsV1(durable.Pins)
	}()
	checkpoint, beta, finalReceipts, runErr :=
		formalGLMPhase19RuntimeRunDurablePhase15Stream(
			rw, tail.plan, tail.context, tail.backendKey, tail.rootAttempt,
			tail.role, tail.store, durable)
	exactGCZeroBigInts(beta)
	if runErr != nil {
		return nil, tail.failRunV1(runErr)
	}
	if checkpoint == nil {
		return nil, tail.failRunV1(fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: missing durable checkpoint"))
	}
	defer clear(checkpoint.key[:])
	bridge, runErr := buildFormalGLMPhase15DPBridgePlan(
		tail.plan, finalReceipts, durable.Pins, tail.outputLatticeBits)
	if runErr != nil {
		return nil, tail.failRunV1(runErr)
	}
	localBeta, runErr := formalGLMPhase15DPBridgeLoadLocalSource(
		checkpoint, finalReceipts, durable.Pins, bridge)
	if runErr != nil {
		return nil, tail.failRunV1(runErr)
	}
	bridgeAttempt := formalGLMPhase19RuntimeAttempt(
		tail.rootAttempt, "phase15-dp-bridge", 0, -1)
	bridgeSession, runErr := formalGLMPhase15DPBridgeSession(
		tail.plan, bridge, bridgeAttempt, tail.backendKey)
	clear(bridgeAttempt[:])
	if runErr != nil {
		exactGCZeroBigInts(localBeta)
		return nil, tail.failRunV1(runErr)
	}
	var dpShares []*big.Int
	if tail.peer == bridge.GarblerPeerName {
		dpShares, runErr = formalGLMPhase15RunDPBridgeGarblerWithExecution(
			rw, tail.plan, bridge, bridgeSession, localBeta, tail.localSeal.share)
	} else if tail.peer == bridge.EvaluatorPeerName {
		dpShares, runErr = formalGLMPhase15RunDPBridgeEvaluatorWithExecution(
			rw, tail.plan, bridge, bridgeSession, localBeta, tail.localSeal.share)
	} else {
		runErr = fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: local peer has no bridge role")
	}
	exactGCZeroBigInts(localBeta)
	if runErr != nil {
		exactGCZeroBigInts(dpShares)
		return nil, tail.failRunV1(runErr)
	}
	defer exactGCZeroBigInts(dpShares)
	receiptDigest, runErr := formalGLMPhase15FinalReceiptPairDigest(finalReceipts)
	if runErr != nil {
		return nil, tail.failRunV1(runErr)
	}
	workerMessage := formalGLMPhase15AppendString(nil,
		"dsVert/formal-glm/runtime/phase15-worker-transcript/v1")
	workerMessage = formalGLMPhase15AppendString(
		workerMessage, tail.context.ContextSHA256ForPhase19())
	workerMessage = formalGLMPhase15AppendString(
		workerMessage, tail.accumulator.AccumulatorRoot)
	workerMessage = formalGLMPhase15AppendBytes(workerMessage, receiptDigest[:])
	workerDigest := sha256.Sum256(workerMessage)
	clear(workerMessage)
	evidence := formalGLMPhase19ExecutionEvidence{
		Phase15ExecutionTranscriptSHA256: finalReceipts[0].TranscriptSHA256,
		FinalCheckpointTranscriptSHA256:  finalReceipts[0].TranscriptSHA256,
		WorkerTranscriptSHA256:           hex.EncodeToString(workerDigest[:]),
		CheckpointEvidenceSHA256:         hex.EncodeToString(receiptDigest[:]),
	}
	clear(workerDigest[:])
	clear(receiptDigest[:])
	postToken, runErr := formalGLMPhase19BuildPostExecutionTokenFromSummary(
		tail.plan, tail.context, tail.summary, tail.accumulator,
		tail.executionPair, finalReceipts, durable.Pins, evidence, tail.backendKey)
	if runErr != nil {
		return nil, tail.failRunV1(runErr)
	}
	value := formalGLMPhase19RuntimeScheduleResult{
		context: tail.context, executionPair: tail.executionPair,
		finalReceipts: finalReceipts, dpBridge: bridge,
		dpShares: dpShares, postToken: postToken, backend: tail.backendKey,
	}
	decoded := formalGLMPhase19ScheduleWorkerDecoded{
		config: formalGLMPhase19ScheduleWorkerConfig{
			LocalTemplate: formalGLMPhase19RuntimeLocalInput{
				Plan: tail.plan, Recipient: tail.peer,
			},
			SemanticRootSHA256: tail.semanticRootSHA256,
			ScheduleRootSHA256: tail.binding.ScheduleRootSHA256,
			AttemptID:          tail.binding.AttemptID,
		},
		durable: formalGLMPhase19RuntimeDurableConfig{Pins: durable.Pins},
	}
	raw, runErr := formalGLMPhase19ScheduleEncodeResult(decoded, value)
	clear(value.backend[:])
	clear(value.postToken.seal[:])
	value.postToken.verified = false
	clear(postToken.seal[:])
	postToken.verified = false
	if runErr != nil {
		return nil, tail.failRunV1(runErr)
	}
	result := &formalGLMRegisteredPhase19ScheduleTailResultV1{
		raw: raw, binding: tail.binding,
	}
	tail.mu.Lock()
	if tail.closeRequested {
		tail.running = false
		tail.mu.Unlock()
		formalGLMRegisteredPhase19ScheduleTailClearRawV1(&result.raw)
		_ = tail.Close()
		return nil, fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: closed while running")
	}
	result.execution = tail.execution
	tail.execution = nil
	tail.running = false
	tail.finished = true
	root := tail.clearLocked()
	tail.mu.Unlock()
	if root != nil {
		_ = root.Close()
	}
	return result, nil
}

func (tail *formalGLMRegisteredPhase19ScheduleTailV1) Close() error {
	if tail == nil {
		return nil
	}
	tail.mu.Lock()
	if tail.closed || tail.finished {
		tail.mu.Unlock()
		return nil
	}
	if tail.running {
		tail.closeRequested = true
		execution := tail.execution
		tail.mu.Unlock()
		if execution != nil {
			return execution.Close()
		}
		return nil
	}
	tail.closed = true
	execution := tail.execution
	tail.execution = nil
	root := tail.clearLocked()
	tail.mu.Unlock()
	if root != nil {
		_ = root.Close()
	}
	return formalGLMRegisteredPhase19ScheduleTailReleaseAccumulatorV1(
		execution, true)
}

func (result *formalGLMRegisteredPhase19ScheduleTailResultV1) BuildPreparedEvidenceV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase20PreparedEvidenceV1, error) {
	var zero formalGLMRegisteredPhase20PreparedEvidenceV1
	if result == nil {
		return zero, fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: missing RAM result")
	}
	result.mu.Lock()
	if result.closed || result.consumed || result.building ||
		result.execution == nil {
		result.mu.Unlock()
		return zero, fmt.Errorf(
			"formal-glm registered Phase19 schedule tail: RAM result unavailable")
	}
	result.building = true
	raw := result.raw
	binding := result.binding
	result.mu.Unlock()
	evidence, err := formalGLMRegisteredPhase20BuildPreparedEvidenceV1(
		runtime, record, contract, binding, raw, pins)
	formalGLMRegisteredPhase19ScheduleTailClearRawV1(&raw)
	result.mu.Lock()
	result.building = false
	if err != nil {
		closeRequested := result.closeRequested
		result.mu.Unlock()
		if closeRequested {
			_ = result.Close()
		}
		return zero, err
	}
	result.consumed = true
	execution := result.execution
	result.execution = nil
	formalGLMRegisteredPhase19ScheduleTailClearRawV1(&result.raw)
	result.mu.Unlock()
	if err := formalGLMRegisteredPhase19ScheduleTailReleaseAccumulatorV1(
		execution, true); err != nil {
		return zero, err
	}
	return evidence, nil
}

func (result *formalGLMRegisteredPhase19ScheduleTailResultV1) Close() error {
	if result == nil {
		return nil
	}
	result.mu.Lock()
	if result.closed || result.consumed {
		result.mu.Unlock()
		return nil
	}
	if result.building {
		result.closeRequested = true
		result.mu.Unlock()
		return nil
	}
	result.closed = true
	execution := result.execution
	result.execution = nil
	formalGLMRegisteredPhase19ScheduleTailClearRawV1(&result.raw)
	result.mu.Unlock()
	return formalGLMRegisteredPhase19ScheduleTailReleaseAccumulatorV1(
		execution, true)
}
