package main

// Capsule-free registered wrapper around the external-memory Phase19
// execution-validity accumulator. The owner is the only object that can reach
// the ephemeral stream store; DTOs contain no store path, key, or private share.

import (
	"fmt"
	"io"
	"os"
	"sync"
)

const (
	formalGLMRegisteredPhase19AccumulatorPlanVersionV1    = "dsvert-formal-glm-registered-phase19-accumulator-plan-v1"
	formalGLMRegisteredPhase19AccumulatorPlanPurposeV1    = "formal_glm_registered_phase19_public_accumulator_plan_v1"
	formalGLMRegisteredPhase19AccumulatorReceiptVersionV1 = "dsvert-formal-glm-registered-phase19-accumulator-receipt-v1"
	formalGLMRegisteredPhase19AccumulatorReceiptPurposeV1 = "formal_glm_registered_phase19_public_accumulator_receipt_v1"
	formalGLMRegisteredPhase19AccumulatorPairVersionV1    = "dsvert-formal-glm-registered-phase19-accumulator-receipt-pair-v1"
	formalGLMRegisteredPhase19AccumulatorPairPurposeV1    = "formal_glm_registered_phase19_public_accumulator_receipt_pair_v1"
	formalGLMRegisteredPhase19AccumulatorStoreOpenV1      = "open"
	formalGLMRegisteredPhase19AccumulatorStoreCompleteV1  = "complete"
	formalGLMRegisteredPhase19AccumulatorStoreClaimedV1   = "claimed"
	formalGLMRegisteredPhase19AccumulatorStoreClosedV1    = "closed"
)

type formalGLMRegisteredPhase19AccumulatorPlanV1 struct {
	Version                       string `json:"version"`
	Purpose                       string `json:"purpose"`
	SemanticRootSHA256            string `json:"semantic_root_sha256"`
	ReceiptSetSHA256              string `json:"receipt_set_sha256"`
	RegisteredExecutionPlanSHA256 string `json:"registered_execution_plan_sha256"`
	BlockCount                    int    `json:"block_count"`
	AccumulatorRoot               string `json:"accumulator_root"`
	ExecutionValidSealed          bool   `json:"execution_valid_sealed"`
	ExecutionValidityOpened       bool   `json:"execution_validity_opened"`
	OpeningsPerformed             int    `json:"openings_performed"`
	ProductionReady               bool   `json:"production_ready"`
}

// SemanticRootSHA256 already commits the receipt set and registered execution
// plan, so the per-peer receipt and final pair do not duplicate those fields.
type formalGLMRegisteredPhase19AccumulatorReceiptV1 struct {
	Version                 string                           `json:"version"`
	Purpose                 string                           `json:"purpose"`
	SemanticRootSHA256      string                           `json:"semantic_root_sha256"`
	Peer                    string                           `json:"peer"`
	AccumulatorRoot         string                           `json:"accumulator_root"`
	Receipt                 formalGLMPhase19ExecutionReceipt `json:"receipt"`
	ExecutionValidSealed    bool                             `json:"execution_valid_sealed"`
	ExecutionValidityOpened bool                             `json:"execution_validity_opened"`
	OpeningsPerformed       int                              `json:"openings_performed"`
	ProductionReady         bool                             `json:"production_ready"`
}

// Only Receipt is exported; the hidden execution bit and seal stay private.
type formalGLMRegisteredPhase19AccumulatorSealV1 struct {
	Receipt formalGLMRegisteredPhase19AccumulatorReceiptV1 `json:"receipt"`
	seal    formalGLMPhase19ExecutionSeal
}

type formalGLMRegisteredPhase19AccumulatorReceiptPairV1 struct {
	Version                    string `json:"version"`
	Purpose                    string `json:"purpose"`
	SemanticRootSHA256         string `json:"semantic_root_sha256"`
	AccumulatorRoot            string `json:"accumulator_root"`
	GarblerReceiptSHA256       string `json:"garbler_receipt_sha256"`
	EvaluatorReceiptSHA256     string `json:"evaluator_receipt_sha256"`
	ExecutionReceiptPairSHA256 string `json:"execution_receipt_pair_sha256"`
	ExecutionValidSealed       bool   `json:"execution_valid_sealed"`
	ExecutionValidityOpened    bool   `json:"execution_validity_opened"`
	OpeningsPerformed          int    `json:"openings_performed"`
	ProductionReady            bool   `json:"production_ready"`
	pair                       formalGLMPhase19ExecutionReceiptPair
}

// The owner creates and exclusively owns the raw stream store from first
// append through the end of its single registered execution.
type formalGLMRegisteredPhase19AccumulatorStoreV1 struct {
	mu sync.Mutex

	state                         string
	semanticRootSHA256            string
	receiptSetSHA256              string
	registeredExecutionPlanSHA256 string
	peer                          string
	plan                          formalGLMPhase15Plan
	context                       formalGLMPhase19Context
	backendKey                    [32]byte
	store                         *formalGLMPhase19StreamStore
	holder                        *formalGLMRegisteredPhase19AccumulatorExecutionV1
}

// This trust object has no exported fields, hence its JSON representation is
// {}. claimed is set before any peer I/O and never reset.
type formalGLMRegisteredPhase19AccumulatorExecutionV1 struct {
	mu sync.Mutex

	semanticRootSHA256            string
	receiptSetSHA256              string
	registeredExecutionPlanSHA256 string
	peer                          string
	plan                          formalGLMPhase15Plan
	context                       formalGLMPhase19Context
	accumulator                   formalGLMPhase19AccumulatorPlan
	attempt                       [32]byte
	backendKey                    [32]byte
	owner                         *formalGLMRegisteredPhase19AccumulatorStoreV1
	claimed                       bool
	running                       bool
	succeeded                     bool
	closeRequested                bool
	closed                        bool
}

type formalGLMRegisteredPhase19AccumulatorSnapshotV1 struct {
	semanticRootSHA256            string
	receiptSetSHA256              string
	registeredExecutionPlanSHA256 string
	peer                          string
	role                          string
	plan                          formalGLMPhase15Plan
	context                       formalGLMPhase19Context
	accumulator                   formalGLMPhase19AccumulatorPlan
	attempt                       [32]byte
	backendKey                    [32]byte
	store                         *formalGLMPhase19StreamStore
}

func formalGLMRegisteredPhase19AccumulatorRoleV1(
	context formalGLMPhase19Context, peer string,
) (string, error) {
	if len(context.ComputePeers) == 2 && peer == context.ComputePeers[0] {
		return "garbler", nil
	}
	if len(context.ComputePeers) == 2 && peer == context.ComputePeers[1] {
		return "evaluator", nil
	}
	return "", fmt.Errorf(
		"formal-glm registered Phase19: invalid accumulator peer role")
}

func formalGLMRegisteredPhase19AccumulatorSameScheduleV1(
	leftPlan, rightPlan formalGLMPhase15Plan,
	leftContext, rightContext formalGLMPhase19Context,
) bool {
	leftPlanDigest, leftPlanErr := formalGLMPhase15PlanDigest(leftPlan)
	rightPlanDigest, rightPlanErr := formalGLMPhase15PlanDigest(rightPlan)
	leftContextDigest, leftContextErr := formalGLMPhase19ContextDigest(leftContext)
	rightContextDigest, rightContextErr := formalGLMPhase19ContextDigest(rightContext)
	return leftPlanErr == nil && rightPlanErr == nil &&
		leftContextErr == nil && rightContextErr == nil &&
		leftPlanDigest == rightPlanDigest && leftContextDigest == rightContextDigest
}

func (owner *formalGLMRegisteredPhase19AccumulatorStoreV1) validateLocked() error {
	if owner == nil || owner.store == nil || owner.store.file == nil ||
		!formalGLMIsSHA256(owner.semanticRootSHA256) ||
		!formalGLMIsSHA256(owner.receiptSetSHA256) ||
		!formalGLMIsSHA256(owner.registeredExecutionPlanSHA256) ||
		!formalGLMPhase19KeyValid(owner.backendKey) ||
		owner.store.peer != owner.peer || owner.store.key != owner.backendKey ||
		owner.store.next < 0 || owner.store.next > owner.plan.TotalBlocks ||
		!formalGLMRegisteredPhase19AccumulatorSameScheduleV1(
			owner.plan, owner.store.plan, owner.context, owner.store.ctx) {
		return fmt.Errorf(
			"formal-glm registered Phase19: invalid accumulator store")
	}
	if _, err := formalGLMRegisteredPhase19AccumulatorRoleV1(
		owner.context, owner.peer); err != nil {
		return err
	}
	switch owner.state {
	case formalGLMRegisteredPhase19AccumulatorStoreOpenV1:
		if owner.store.complete || owner.holder != nil {
			return fmt.Errorf("formal-glm registered Phase19: invalid open store")
		}
	case formalGLMRegisteredPhase19AccumulatorStoreCompleteV1:
		if !owner.store.complete || owner.store.next != owner.plan.TotalBlocks ||
			owner.holder != nil {
			return fmt.Errorf("formal-glm registered Phase19: incomplete store")
		}
	case formalGLMRegisteredPhase19AccumulatorStoreClaimedV1:
		if !owner.store.complete || owner.store.next != owner.plan.TotalBlocks ||
			owner.holder == nil {
			return fmt.Errorf("formal-glm registered Phase19: invalid claimed store")
		}
	default:
		return fmt.Errorf("formal-glm registered Phase19: invalid store state")
	}
	return nil
}

func formalGLMRegisteredPhase19NewAccumulatorStoreV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	peer string,
	open func(formalGLMPhase15Plan, formalGLMPhase19Context, string, [32]byte) (
		*formalGLMPhase19StreamStore, error,
	),
) (*formalGLMRegisteredPhase19AccumulatorStoreV1, error) {
	if runtime == nil {
		return nil, fmt.Errorf("formal-glm registered Phase19: missing runtime")
	}
	if open == nil {
		return nil, fmt.Errorf("formal-glm registered Phase19: missing accumulator store opener")
	}
	// Release the runtime mutex before the raw constructor touches disk.
	runtime.mu.Lock()
	if err := runtime.validateLocked(); err != nil {
		runtime.mu.Unlock()
		return nil, err
	}
	if _, err := formalGLMRegisteredPhase19AccumulatorRoleV1(
		runtime.context, peer); err != nil {
		runtime.mu.Unlock()
		return nil, err
	}
	owner := &formalGLMRegisteredPhase19AccumulatorStoreV1{
		state:                         formalGLMRegisteredPhase19AccumulatorStoreOpenV1,
		semanticRootSHA256:            runtime.semanticRootSHA256,
		receiptSetSHA256:              runtime.receiptSetSHA256,
		registeredExecutionPlanSHA256: runtime.registeredExecutionPlanSHA256,
		peer:                          peer,
		plan:                          formalGLMRegisteredPhase19ClonePlanV1(runtime.legacyPlan),
		context:                       formalGLMRegisteredPhase19CloneContextV1(runtime.context),
		backendKey:                    runtime.backendKey,
	}
	runtime.mu.Unlock()
	store, err := open(owner.plan, owner.context, peer, owner.backendKey)
	if err != nil {
		clear(owner.backendKey[:])
		return nil, err
	}
	owner.store = store
	if err := owner.validateLocked(); err != nil {
		_ = store.Destroy()
		clear(owner.backendKey[:])
		return nil, err
	}
	return owner, nil
}

func newFormalGLMRegisteredPhase19AccumulatorStoreV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	peer, directory string, maxBytes int64,
) (*formalGLMRegisteredPhase19AccumulatorStoreV1, error) {
	return formalGLMRegisteredPhase19NewAccumulatorStoreV1(
		runtime, peer,
		func(plan formalGLMPhase15Plan, context formalGLMPhase19Context,
			storePeer string, backendKey [32]byte,
		) (*formalGLMPhase19StreamStore, error) {
			return newFormalGLMPhase19StreamStore(
				directory, maxBytes, plan, context, storePeer, backendKey)
		})
}

// newFormalGLMRegisteredPhase19AccumulatorStoreRootedV1 keeps the raw block
// shares below a caller-owned Rock root. Live registered jobs must use this
// constructor so replacing a pathname cannot redirect protected blocks.
func newFormalGLMRegisteredPhase19AccumulatorStoreRootedV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	peer string, root *os.Root, directory string, maxBytes int64,
) (*formalGLMRegisteredPhase19AccumulatorStoreV1, error) {
	return formalGLMRegisteredPhase19NewAccumulatorStoreV1(
		runtime, peer,
		func(plan formalGLMPhase15Plan, context formalGLMPhase19Context,
			storePeer string, backendKey [32]byte,
		) (*formalGLMPhase19StreamStore, error) {
			return newFormalGLMPhase19StreamStoreRootedV1(
				root, directory, maxBytes, plan, context, storePeer, backendKey)
		})
}

func formalGLMRegisteredPhase19ValidateAccumulatorAppendLockedV1(
	owner *formalGLMRegisteredPhase19AccumulatorStoreV1,
	block formalGLMRegisteredPhase19MaskedBlockV1,
	pair formalGLMRegisteredPhase19MaskedReceiptPairV1,
) error {
	rows, err := formalGLMPhase19RowsInBlock(owner.plan, owner.store.next)
	if err != nil {
		return err
	}
	wantReceipt := formalGLMRegisteredPhase19MaskedReceiptV1{
		Version:                       formalGLMRegisteredPhase19MaskedReceiptVersionV1,
		Purpose:                       formalGLMRegisteredPhase19MaskedReceiptPurposeV1,
		SemanticRootSHA256:            owner.semanticRootSHA256,
		ReceiptSetSHA256:              owner.receiptSetSHA256,
		RegisteredExecutionPlanSHA256: owner.registeredExecutionPlanSHA256,
		Peer:                          owner.peer, BlockIndex: owner.store.next, RowsInBlock: rows,
		PairRoot: block.block.Receipt.PairRoot, Receipt: block.block.Receipt,
		OpeningsPerformed: 0, ProductionReady: false,
	}
	wantPair := formalGLMRegisteredPhase19MaskedReceiptPairV1{
		Version:                       formalGLMRegisteredPhase19MaskedPairVersionV1,
		Purpose:                       formalGLMRegisteredPhase19MaskedPairPurposeV1,
		SemanticRootSHA256:            owner.semanticRootSHA256,
		ReceiptSetSHA256:              owner.receiptSetSHA256,
		RegisteredExecutionPlanSHA256: owner.registeredExecutionPlanSHA256,
		BlockIndex:                    pair.pair.BlockIndex, RowsInBlock: rows,
		PairRoot:                pair.pair.PairRoot,
		GarblerReceiptSHA256:    pair.pair.GarblerReceiptSHA256,
		EvaluatorReceiptSHA256:  pair.pair.EvaluatorReceiptSHA256,
		ReceiptPairSHA256:       pair.pair.ReceiptPairSHA256,
		ExecutionValidSealed:    pair.pair.ExecutionValidSealed,
		ExecutionValidityOpened: pair.pair.ExecutionValidityOpened,
		OpeningsPerformed:       pair.pair.OpeningsPerformed,
		ProductionReady:         pair.pair.ProductionReady,
		pair:                    pair.pair,
	}
	if block.Receipt != wantReceipt || pair != wantPair ||
		pair.BlockIndex != owner.store.next || pair.PairRoot != wantReceipt.PairRoot {
		return fmt.Errorf(
			"formal-glm registered Phase19: invalid registered accumulator block")
	}
	if err := formalGLMPhase19VerifyMaskedBlockReceiptPair(
		owner.context, pair.pair, owner.backendKey); err != nil {
		return err
	}
	expected := pair.pair.EvaluatorReceiptSHA256
	if owner.peer == owner.context.ComputePeers[0] {
		expected = pair.pair.GarblerReceiptSHA256
	}
	return formalGLMPhase19VerifyMaskedBlockForAccumulator(
		owner.plan, owner.context, block.block, expected,
		owner.peer, owner.backendKey)
}

func (owner *formalGLMRegisteredPhase19AccumulatorStoreV1) AppendRegisteredV1(
	block formalGLMRegisteredPhase19MaskedBlockV1,
	pair formalGLMRegisteredPhase19MaskedReceiptPairV1,
) error {
	if owner == nil {
		return fmt.Errorf("formal-glm registered Phase19: missing accumulator store")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := owner.validateLocked(); err != nil {
		return err
	}
	if owner.state != formalGLMRegisteredPhase19AccumulatorStoreOpenV1 {
		return fmt.Errorf("formal-glm registered Phase19: store is not appendable")
	}
	if err := formalGLMRegisteredPhase19ValidateAccumulatorAppendLockedV1(
		owner, block, pair); err != nil {
		return err
	}
	return owner.store.Append(block.block, pair.pair)
}

func (owner *formalGLMRegisteredPhase19AccumulatorStoreV1) CompleteV1() error {
	if owner == nil {
		return fmt.Errorf("formal-glm registered Phase19: missing accumulator store")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := owner.validateLocked(); err != nil {
		return err
	}
	if owner.state != formalGLMRegisteredPhase19AccumulatorStoreOpenV1 {
		return fmt.Errorf("formal-glm registered Phase19: store is not completable")
	}
	if err := owner.store.Complete(); err != nil {
		return err
	}
	owner.state = formalGLMRegisteredPhase19AccumulatorStoreCompleteV1
	return owner.validateLocked()
}

func (owner *formalGLMRegisteredPhase19AccumulatorStoreV1) Destroy() error {
	if owner == nil {
		return nil
	}
	owner.mu.Lock()
	if owner.state == formalGLMRegisteredPhase19AccumulatorStoreClosedV1 {
		owner.mu.Unlock()
		return nil
	}
	if owner.state == formalGLMRegisteredPhase19AccumulatorStoreClaimedV1 {
		owner.mu.Unlock()
		return fmt.Errorf("formal-glm registered Phase19: claimed accumulator store")
	}
	if owner.state != formalGLMRegisteredPhase19AccumulatorStoreOpenV1 &&
		owner.state != formalGLMRegisteredPhase19AccumulatorStoreCompleteV1 {
		owner.mu.Unlock()
		return fmt.Errorf("formal-glm registered Phase19: invalid store state")
	}
	store := owner.store
	owner.store = nil
	owner.state = formalGLMRegisteredPhase19AccumulatorStoreClosedV1
	clear(owner.backendKey[:])
	owner.mu.Unlock()
	return store.Destroy()
}

func (execution *formalGLMRegisteredPhase19AccumulatorExecutionV1) validateLocked() error {
	if execution == nil || execution.closed ||
		!formalGLMIsSHA256(execution.semanticRootSHA256) ||
		!formalGLMIsSHA256(execution.receiptSetSHA256) ||
		!formalGLMIsSHA256(execution.registeredExecutionPlanSHA256) ||
		!formalGLMPhase19KeyValid(execution.attempt) ||
		!formalGLMPhase19KeyValid(execution.backendKey) {
		return fmt.Errorf("formal-glm registered Phase19: invalid accumulator execution")
	}
	if _, err := formalGLMRegisteredPhase19AccumulatorRoleV1(
		execution.context, execution.peer); err != nil {
		return err
	}
	if err := formalGLMPhase19ValidateContext(
		execution.plan, execution.context); err != nil {
		return err
	}
	return formalGLMPhase19VerifyAccumulatorPlan(
		execution.context, execution.accumulator, execution.backendKey)
}

func formalGLMRegisteredPhase19AccumulatorPublicPlanV1(
	execution *formalGLMRegisteredPhase19AccumulatorExecutionV1,
) formalGLMRegisteredPhase19AccumulatorPlanV1 {
	return formalGLMRegisteredPhase19AccumulatorPlanV1{
		Version:                       formalGLMRegisteredPhase19AccumulatorPlanVersionV1,
		Purpose:                       formalGLMRegisteredPhase19AccumulatorPlanPurposeV1,
		SemanticRootSHA256:            execution.semanticRootSHA256,
		ReceiptSetSHA256:              execution.receiptSetSHA256,
		RegisteredExecutionPlanSHA256: execution.registeredExecutionPlanSHA256,
		BlockCount:                    execution.accumulator.BlockCount,
		AccumulatorRoot:               execution.accumulator.AccumulatorRoot,
		ExecutionValidSealed:          execution.accumulator.ExecutionValidSealed,
		ExecutionValidityOpened:       execution.accumulator.ExecutionValidityOpened,
		OpeningsPerformed:             execution.accumulator.OpeningsPerformed,
		ProductionReady:               execution.accumulator.ProductionReady,
	}
}

func formalGLMRegisteredPhase19PrepareAccumulatorV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	owner *formalGLMRegisteredPhase19AccumulatorStoreV1,
	attempt [32]byte,
) (*formalGLMRegisteredPhase19AccumulatorExecutionV1,
	formalGLMRegisteredPhase19AccumulatorPlanV1, error) {
	var zero formalGLMRegisteredPhase19AccumulatorPlanV1
	if runtime == nil || owner == nil || !formalGLMPhase19KeyValid(attempt) {
		return nil, zero, fmt.Errorf(
			"formal-glm registered Phase19: invalid accumulator preparation")
	}
	// Validate/copy the runtime, then release it before Summary reads disk.
	runtime.mu.Lock()
	if err := runtime.validateLocked(); err != nil {
		runtime.mu.Unlock()
		return nil, zero, err
	}
	plan := formalGLMRegisteredPhase19ClonePlanV1(runtime.legacyPlan)
	context := formalGLMRegisteredPhase19CloneContextV1(runtime.context)
	semanticRoot := runtime.semanticRootSHA256
	receiptSet := runtime.receiptSetSHA256
	registeredPlan := runtime.registeredExecutionPlanSHA256
	backendKey := runtime.backendKey
	runtime.mu.Unlock()

	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := owner.validateLocked(); err != nil {
		return nil, zero, err
	}
	if owner.state != formalGLMRegisteredPhase19AccumulatorStoreCompleteV1 ||
		owner.semanticRootSHA256 != semanticRoot ||
		owner.receiptSetSHA256 != receiptSet ||
		owner.registeredExecutionPlanSHA256 != registeredPlan ||
		owner.backendKey != backendKey ||
		!formalGLMRegisteredPhase19AccumulatorSameScheduleV1(
			plan, owner.plan, context, owner.context) {
		return nil, zero, fmt.Errorf(
			"formal-glm registered Phase19: runtime/store binding mismatch")
	}
	summary, err := owner.store.Summary()
	if err != nil {
		return nil, zero, err
	}
	accumulator, err := formalGLMPhase19BuildStreamAccumulatorPlan(
		context, summary, backendKey)
	if err != nil {
		return nil, zero, err
	}
	execution := &formalGLMRegisteredPhase19AccumulatorExecutionV1{
		semanticRootSHA256: semanticRoot, receiptSetSHA256: receiptSet,
		registeredExecutionPlanSHA256: registeredPlan,
		peer:                          owner.peer, plan: plan, context: context, accumulator: accumulator,
		attempt: attempt, backendKey: backendKey, owner: owner,
	}
	if err := execution.validateLocked(); err != nil {
		execution.clearLocked()
		return nil, zero, err
	}
	owner.state = formalGLMRegisteredPhase19AccumulatorStoreClaimedV1
	owner.holder = execution
	return execution, formalGLMRegisteredPhase19AccumulatorPublicPlanV1(execution), nil
}

func (execution *formalGLMRegisteredPhase19AccumulatorExecutionV1) claim() (
	formalGLMRegisteredPhase19AccumulatorSnapshotV1, error,
) {
	var zero formalGLMRegisteredPhase19AccumulatorSnapshotV1
	if execution == nil {
		return zero, fmt.Errorf("formal-glm registered Phase19: missing execution")
	}
	execution.mu.Lock()
	defer execution.mu.Unlock()
	if err := execution.validateLocked(); err != nil {
		return zero, err
	}
	if execution.claimed || execution.running || execution.owner == nil {
		return zero, fmt.Errorf(
			"formal-glm registered Phase19: accumulator execution already claimed")
	}
	owner := execution.owner
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := owner.validateLocked(); err != nil {
		return zero, err
	}
	if owner.state != formalGLMRegisteredPhase19AccumulatorStoreClaimedV1 ||
		owner.holder != execution {
		return zero, fmt.Errorf("formal-glm registered Phase19: owner mismatch")
	}
	role, err := formalGLMRegisteredPhase19AccumulatorRoleV1(
		execution.context, execution.peer)
	if err != nil {
		return zero, err
	}
	execution.claimed, execution.running = true, true
	return formalGLMRegisteredPhase19AccumulatorSnapshotV1{
		semanticRootSHA256:            execution.semanticRootSHA256,
		receiptSetSHA256:              execution.receiptSetSHA256,
		registeredExecutionPlanSHA256: execution.registeredExecutionPlanSHA256,
		peer:                          execution.peer, role: role,
		plan:        formalGLMRegisteredPhase19ClonePlanV1(execution.plan),
		context:     formalGLMRegisteredPhase19CloneContextV1(execution.context),
		accumulator: execution.accumulator,
		attempt:     execution.attempt, backendKey: execution.backendKey,
		store: owner.store,
	}, nil
}

func (snapshot *formalGLMRegisteredPhase19AccumulatorSnapshotV1) clear() {
	if snapshot == nil {
		return
	}
	clear(snapshot.attempt[:])
	clear(snapshot.backendKey[:])
	clear(snapshot.accumulator.seal[:])
	snapshot.accumulator.verified = false
	snapshot.plan = formalGLMPhase15Plan{}
	snapshot.context = formalGLMPhase19Context{}
	snapshot.store = nil
}

func (execution *formalGLMRegisteredPhase19AccumulatorExecutionV1) finish(
	runSucceeded bool,
) error {
	execution.mu.Lock()
	if !execution.running {
		execution.mu.Unlock()
		return fmt.Errorf("formal-glm registered Phase19: execution is not running")
	}
	execution.running = false
	execution.succeeded = runSucceeded && !execution.closeRequested
	closeRequested := execution.closeRequested
	execution.mu.Unlock()
	if closeRequested {
		if err := execution.Close(); err != nil {
			return err
		}
		return fmt.Errorf(
			"formal-glm registered Phase19: execution closed while running")
	}
	return nil
}

func formalGLMRegisteredPhase19ValidateAccumulatorReceiptV1(
	snapshot formalGLMRegisteredPhase19AccumulatorSnapshotV1,
	public formalGLMRegisteredPhase19AccumulatorReceiptV1,
) error {
	want := formalGLMRegisteredPhase19AccumulatorReceiptV1{
		Version:            formalGLMRegisteredPhase19AccumulatorReceiptVersionV1,
		Purpose:            formalGLMRegisteredPhase19AccumulatorReceiptPurposeV1,
		SemanticRootSHA256: snapshot.semanticRootSHA256,
		Peer:               public.Receipt.Peer, AccumulatorRoot: public.Receipt.AccumulatorRoot,
		Receipt:                 public.Receipt,
		ExecutionValidSealed:    public.Receipt.ExecutionValidSealed,
		ExecutionValidityOpened: public.Receipt.ExecutionValidityOpened,
		OpeningsPerformed:       public.Receipt.OpeningsPerformed,
		ProductionReady:         public.Receipt.ProductionReady,
	}
	if public != want || public.AccumulatorRoot != snapshot.accumulator.AccumulatorRoot ||
		!public.ExecutionValidSealed || public.ExecutionValidityOpened ||
		public.OpeningsPerformed != 0 || public.ProductionReady {
		return fmt.Errorf(
			"formal-glm registered Phase19: invalid public accumulator receipt")
	}
	return formalGLMPhase19VerifyExecutionReceipt(
		snapshot.context, snapshot.accumulator, public.Receipt, snapshot.backendKey)
}

func formalGLMRegisteredPhase19RunAccumulatorPeerV1(
	rw io.ReadWriter,
	execution *formalGLMRegisteredPhase19AccumulatorExecutionV1,
) (result formalGLMRegisteredPhase19AccumulatorSealV1, err error) {
	if rw == nil {
		return result, fmt.Errorf("formal-glm registered Phase19: nil peer channel")
	}
	// claim releases both mutexes before the store or peer channel is touched.
	snapshot, err := execution.claim()
	if err != nil {
		return result, err
	}
	defer snapshot.clear()
	runSucceeded := false
	defer func() {
		cleanupErr := execution.finish(runSucceeded)
		if cleanupErr == nil {
			return
		}
		if err == nil {
			result.Close()
			result = formalGLMRegisteredPhase19AccumulatorSealV1{}
			err = cleanupErr
		} else {
			err = fmt.Errorf("%v; cleanup: %w", err, cleanupErr)
		}
	}()
	legacy, err := formalGLMPhase19RunBoundedAccumulatorStream(
		rw, snapshot.plan, snapshot.context, snapshot.accumulator,
		snapshot.store, snapshot.attempt, snapshot.role, snapshot.backendKey)
	if err != nil {
		return result, err
	}
	if err := formalGLMPhase19VerifyExecutionSeal(
		snapshot.context, snapshot.accumulator, legacy, snapshot.backendKey); err != nil {
		return result, err
	}
	public := formalGLMRegisteredPhase19AccumulatorReceiptV1{
		Version:            formalGLMRegisteredPhase19AccumulatorReceiptVersionV1,
		Purpose:            formalGLMRegisteredPhase19AccumulatorReceiptPurposeV1,
		SemanticRootSHA256: snapshot.semanticRootSHA256,
		Peer:               snapshot.peer, AccumulatorRoot: snapshot.accumulator.AccumulatorRoot,
		Receipt:                 legacy.Receipt,
		ExecutionValidSealed:    legacy.Receipt.ExecutionValidSealed,
		ExecutionValidityOpened: legacy.Receipt.ExecutionValidityOpened,
		OpeningsPerformed:       legacy.Receipt.OpeningsPerformed,
		ProductionReady:         legacy.Receipt.ProductionReady,
	}
	if err := formalGLMRegisteredPhase19ValidateAccumulatorReceiptV1(
		snapshot, public); err != nil {
		return result, err
	}
	runSucceeded = true
	return formalGLMRegisteredPhase19AccumulatorSealV1{
		Receipt: public, seal: legacy,
	}, nil
}

func (execution *formalGLMRegisteredPhase19AccumulatorExecutionV1) pairSnapshot() (
	formalGLMRegisteredPhase19AccumulatorSnapshotV1, error,
) {
	var zero formalGLMRegisteredPhase19AccumulatorSnapshotV1
	execution.mu.Lock()
	defer execution.mu.Unlock()
	if err := execution.validateLocked(); err != nil {
		return zero, err
	}
	if !execution.claimed || execution.running || !execution.succeeded ||
		execution.closeRequested {
		return zero, fmt.Errorf("formal-glm registered Phase19: execution is not pairable")
	}
	return formalGLMRegisteredPhase19AccumulatorSnapshotV1{
		semanticRootSHA256:            execution.semanticRootSHA256,
		receiptSetSHA256:              execution.receiptSetSHA256,
		registeredExecutionPlanSHA256: execution.registeredExecutionPlanSHA256,
		peer:                          execution.peer,
		context:                       formalGLMRegisteredPhase19CloneContextV1(execution.context),
		accumulator:                   execution.accumulator, backendKey: execution.backendKey,
	}, nil
}

func formalGLMRegisteredPhase19PairAccumulatorReceiptsV1(
	execution *formalGLMRegisteredPhase19AccumulatorExecutionV1,
	garbler, evaluator formalGLMRegisteredPhase19AccumulatorReceiptV1,
) (formalGLMRegisteredPhase19AccumulatorReceiptPairV1, error) {
	var zero formalGLMRegisteredPhase19AccumulatorReceiptPairV1
	if execution == nil {
		return zero, fmt.Errorf("formal-glm registered Phase19: missing execution")
	}
	snapshot, err := execution.pairSnapshot()
	if err != nil {
		return zero, err
	}
	defer snapshot.clear()
	if err := formalGLMRegisteredPhase19ValidateAccumulatorReceiptV1(
		snapshot, garbler); err != nil {
		return zero, err
	}
	if err := formalGLMRegisteredPhase19ValidateAccumulatorReceiptV1(
		snapshot, evaluator); err != nil {
		return zero, err
	}
	legacy, err := formalGLMPhase19PairExecutionReceipts(
		snapshot.context, snapshot.accumulator,
		garbler.Receipt, evaluator.Receipt, snapshot.backendKey)
	if err != nil {
		return zero, err
	}
	if err := formalGLMPhase19VerifyExecutionReceiptPair(
		snapshot.context, snapshot.accumulator, legacy, snapshot.backendKey); err != nil {
		return zero, err
	}
	return formalGLMRegisteredPhase19AccumulatorReceiptPairV1{
		Version:                    formalGLMRegisteredPhase19AccumulatorPairVersionV1,
		Purpose:                    formalGLMRegisteredPhase19AccumulatorPairPurposeV1,
		SemanticRootSHA256:         snapshot.semanticRootSHA256,
		AccumulatorRoot:            legacy.AccumulatorRoot,
		GarblerReceiptSHA256:       legacy.GarblerReceiptSHA256,
		EvaluatorReceiptSHA256:     legacy.EvaluatorReceiptSHA256,
		ExecutionReceiptPairSHA256: legacy.ExecutionReceiptPairSHA256,
		ExecutionValidSealed:       legacy.ExecutionValidSealed,
		ExecutionValidityOpened:    legacy.ExecutionValidityOpened,
		OpeningsPerformed:          legacy.OpeningsPerformed,
		ProductionReady:            legacy.ProductionReady, pair: legacy,
	}, nil
}

func (seal *formalGLMRegisteredPhase19AccumulatorSealV1) Close() {
	if seal != nil {
		seal.seal.share = 0
		clear(seal.seal.seal[:])
		seal.seal.verified = false
	}
}

func (pair formalGLMRegisteredPhase19AccumulatorReceiptPairV1) Public() formalGLMRegisteredPhase19AccumulatorReceiptPairV1 {
	pair.pair = formalGLMPhase19ExecutionReceiptPair{}
	return pair
}

func (pair *formalGLMRegisteredPhase19AccumulatorReceiptPairV1) Close() {
	if pair != nil {
		clear(pair.pair.seal[:])
		pair.pair.verified = false
	}
}

func (owner *formalGLMRegisteredPhase19AccumulatorStoreV1) detachClaimedLocked(
	holder *formalGLMRegisteredPhase19AccumulatorExecutionV1,
) (*formalGLMPhase19StreamStore, error) {
	if owner == nil || owner.state != formalGLMRegisteredPhase19AccumulatorStoreClaimedV1 ||
		owner.holder != holder || owner.store == nil {
		return nil, fmt.Errorf("formal-glm registered Phase19: owner release mismatch")
	}
	store := owner.store
	owner.store, owner.holder = nil, nil
	owner.state = formalGLMRegisteredPhase19AccumulatorStoreClosedV1
	clear(owner.backendKey[:])
	return store, nil
}

func (execution *formalGLMRegisteredPhase19AccumulatorExecutionV1) clearLocked() {
	clear(execution.attempt[:])
	clear(execution.backendKey[:])
	clear(execution.accumulator.seal[:])
	execution.accumulator.verified = false
	execution.plan = formalGLMPhase15Plan{}
	execution.context = formalGLMPhase19Context{}
	execution.owner = nil
	execution.succeeded = false
	execution.closed = true
}

func (execution *formalGLMRegisteredPhase19AccumulatorExecutionV1) Close() error {
	if execution == nil {
		return nil
	}
	execution.mu.Lock()
	if execution.closed {
		execution.mu.Unlock()
		return nil
	}
	if execution.running {
		execution.closeRequested = true
		execution.mu.Unlock()
		return nil
	}
	var store *formalGLMPhase19StreamStore
	var err error
	if execution.owner != nil {
		execution.owner.mu.Lock()
		store, err = execution.owner.detachClaimedLocked(execution)
		execution.owner.mu.Unlock()
	}
	if err == nil {
		execution.clearLocked()
	}
	execution.mu.Unlock()
	if err != nil {
		return err
	}
	if store != nil {
		return store.Destroy()
	}
	return nil
}
