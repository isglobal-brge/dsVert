package main

// Registered, capsule-free per-block execution seam. The two compute peers
// must receive the same server-internal backend/master root from the existing
// authenticated peer key agreement. That root never appears in any DTO here.

import (
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"sync"
)

const (
	formalGLMRegisteredPhase19FanInReceiptVersionV1   = "dsvert-formal-glm-registered-phase19-fanin-receipt-v1"
	formalGLMRegisteredPhase19FanInReceiptPurposeV1   = "formal_glm_registered_phase19_public_fanin_receipt_v1"
	formalGLMRegisteredPhase19BlockExecutionVersionV1 = "dsvert-formal-glm-registered-phase19-block-execution-v1"
	formalGLMRegisteredPhase19MaskedReceiptVersionV1  = "dsvert-formal-glm-registered-phase19-masked-receipt-v1"
	formalGLMRegisteredPhase19MaskedReceiptPurposeV1  = "formal_glm_registered_phase19_public_masked_receipt_v1"
	formalGLMRegisteredPhase19MaskedPairVersionV1     = "dsvert-formal-glm-registered-phase19-masked-receipt-pair-v1"
	formalGLMRegisteredPhase19MaskedPairPurposeV1     = "formal_glm_registered_phase19_public_masked_receipt_pair_v1"
)

// formalGLMRegisteredPhase19FanInReceiptV1 is the only fan-in object sent to
// the other compute peer. The nested receipt contains commitments and a MAC,
// never the private fan-in lanes.
type formalGLMRegisteredPhase19FanInReceiptV1 struct {
	Version                       string                       `json:"version"`
	Purpose                       string                       `json:"purpose"`
	SemanticRootSHA256            string                       `json:"semantic_root_sha256"`
	ReceiptSetSHA256              string                       `json:"receipt_set_sha256"`
	RegisteredExecutionPlanSHA256 string                       `json:"registered_execution_plan_sha256"`
	Recipient                     string                       `json:"recipient"`
	BlockIndex                    int                          `json:"block_index"`
	RowsInBlock                   int                          `json:"rows_in_block"`
	FanInRoot                     string                       `json:"fan_in_root"`
	Receipt                       formalGLMPhase19FanInReceipt `json:"receipt"`
	OpeningsPerformed             int                          `json:"openings_performed"`
	ProductionReady               bool                         `json:"production_ready"`
}

type formalGLMRegisteredPhase19BlockExecutionV1 struct {
	mu sync.Mutex

	version                       string
	semanticRootSHA256            string
	receiptSetSHA256              string
	registeredExecutionPlanSHA256 string
	peer                          string
	blockIndex                    int
	rowsInBlock                   int
	plan                          formalGLMPhase15Plan
	context                       formalGLMPhase19Context
	pair                          formalGLMPhase19PairedFanIn
	local                         formalGLMPhase19FanInResult
	session                       exactGCSession
	backendKey                    [32]byte
	verified                      bool
	claimed                       bool
}

type formalGLMRegisteredPhase19BlockExecutionSnapshotV1 struct {
	semanticRootSHA256            string
	receiptSetSHA256              string
	registeredExecutionPlanSHA256 string
	peer                          string
	blockIndex                    int
	rowsInBlock                   int
	plan                          formalGLMPhase15Plan
	context                       formalGLMPhase19Context
	pair                          formalGLMPhase19PairedFanIn
	local                         formalGLMPhase19FanInResult
	session                       exactGCSession
	backendKey                    [32]byte
}

type formalGLMRegisteredPhase19MaskedReceiptV1 struct {
	Version                       string                             `json:"version"`
	Purpose                       string                             `json:"purpose"`
	SemanticRootSHA256            string                             `json:"semantic_root_sha256"`
	ReceiptSetSHA256              string                             `json:"receipt_set_sha256"`
	RegisteredExecutionPlanSHA256 string                             `json:"registered_execution_plan_sha256"`
	Peer                          string                             `json:"peer"`
	BlockIndex                    int                                `json:"block_index"`
	RowsInBlock                   int                                `json:"rows_in_block"`
	PairRoot                      string                             `json:"pair_root"`
	Receipt                       formalGLMPhase19MaskedBlockReceipt `json:"receipt"`
	OpeningsPerformed             int                                `json:"openings_performed"`
	ProductionReady               bool                               `json:"production_ready"`
}

// formalGLMRegisteredPhase19MaskedBlockV1 serializes only its public receipt.
// The additive tuple and hidden execution-valid share remain unexported.
type formalGLMRegisteredPhase19MaskedBlockV1 struct {
	Receipt formalGLMRegisteredPhase19MaskedReceiptV1 `json:"receipt"`

	block formalGLMPhase19MaskedBlock
}

// PairRoot commits both public fan-in roots and all custodian commitments.
// The two receipt hashes additionally commit each receipt's LocalFanInRoot,
// so duplicating either full fan-in receipt here would add no binding.
type formalGLMRegisteredPhase19MaskedReceiptPairV1 struct {
	Version                       string `json:"version"`
	Purpose                       string `json:"purpose"`
	SemanticRootSHA256            string `json:"semantic_root_sha256"`
	ReceiptSetSHA256              string `json:"receipt_set_sha256"`
	RegisteredExecutionPlanSHA256 string `json:"registered_execution_plan_sha256"`
	BlockIndex                    int    `json:"block_index"`
	RowsInBlock                   int    `json:"rows_in_block"`
	PairRoot                      string `json:"pair_root"`
	GarblerReceiptSHA256          string `json:"garbler_receipt_sha256"`
	EvaluatorReceiptSHA256        string `json:"evaluator_receipt_sha256"`
	ReceiptPairSHA256             string `json:"receipt_pair_sha256"`
	ExecutionValidSealed          bool   `json:"execution_valid_sealed"`
	ExecutionValidityOpened       bool   `json:"execution_validity_opened"`
	OpeningsPerformed             int    `json:"openings_performed"`
	ProductionReady               bool   `json:"production_ready"`

	pair formalGLMPhase19MaskedBlockReceiptPair
}

func formalGLMRegisteredPhase19CloneStringsV1(values []string) []string {
	return append([]string(nil), values...)
}

func formalGLMRegisteredPhase19ClonePlanV1(
	plan formalGLMPhase15Plan,
) formalGLMPhase15Plan {
	cloned := plan
	cloned.CoordinateOwners = formalGLMRegisteredPhase19CloneStringsV1(
		plan.CoordinateOwners)
	cloned.Kernel.CustodianPeers = formalGLMRegisteredPhase19CloneStringsV1(
		plan.Kernel.CustodianPeers)
	cloned.Kernel.ComputePeers = formalGLMRegisteredPhase19CloneStringsV1(
		plan.Kernel.ComputePeers)
	cloned.Kernel.XKind = formalGLMRegisteredPhase19CloneStringsV1(plan.Kernel.XKind)
	cloned.Kernel.XLower = formalGLMRegisteredPhase19CloneStringsV1(plan.Kernel.XLower)
	cloned.Kernel.XUpper = formalGLMRegisteredPhase19CloneStringsV1(plan.Kernel.XUpper)
	cloned.Kernel.BetaStart = formalGLMRegisteredPhase19CloneStringsV1(
		plan.Kernel.BetaStart)
	cloned.Kernel.Ridge = formalGLMRegisteredPhase19CloneStringsV1(plan.Kernel.Ridge)
	cloned.Kernel.CoefficientBox = formalGLMRegisteredPhase19CloneStringsV1(
		plan.Kernel.CoefficientBox)
	cloned.Kernel.LinkKnots = formalGLMRegisteredPhase19CloneStringsV1(
		plan.Kernel.LinkKnots)
	cloned.Kernel.LinkValues = formalGLMRegisteredPhase19CloneStringsV1(
		plan.Kernel.LinkValues)
	cloned.Kernel.LinkSlopes = formalGLMRegisteredPhase19CloneStringsV1(
		plan.Kernel.LinkSlopes)
	return cloned
}

func formalGLMRegisteredPhase19CloneContextV1(
	context formalGLMPhase19Context,
) formalGLMPhase19Context {
	cloned := context
	cloned.CustodianPeers = formalGLMRegisteredPhase19CloneStringsV1(
		context.CustodianPeers)
	cloned.ComputePeers = formalGLMRegisteredPhase19CloneStringsV1(
		context.ComputePeers)
	return cloned
}

func formalGLMRegisteredPhase19CloneStringMapV1(
	values map[string]string,
) map[string]string {
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func formalGLMRegisteredPhase19CloneLegacyFanInReceiptV1(
	receipt formalGLMPhase19FanInReceipt,
) formalGLMPhase19FanInReceipt {
	cloned := receipt
	cloned.PairCommitments = formalGLMRegisteredPhase19CloneStringMapV1(
		receipt.PairCommitments)
	cloned.BlockCommitments = formalGLMRegisteredPhase19CloneStringMapV1(
		receipt.BlockCommitments)
	return cloned
}

func formalGLMRegisteredPhase19CloneLegacyFanInV1(
	result formalGLMPhase19FanInResult,
) (formalGLMPhase19FanInResult, error) {
	cloned := result
	cloned.Receipt = formalGLMRegisteredPhase19CloneLegacyFanInReceiptV1(
		result.Receipt)
	cloned.coordinateShares = make([]*big.Int, len(result.coordinateShares))
	cloned.validityShares = nil
	cloned.alignmentGateShares = nil
	cloned.consensusShares = nil
	for index, value := range result.coordinateShares {
		if value == nil {
			formalGLMPhase19RuntimeZeroFanIn(&cloned)
			return formalGLMPhase19FanInResult{}, fmt.Errorf(
				"formal-glm registered Phase19: nil private fan-in coordinate")
		}
		cloned.coordinateShares[index] = new(big.Int).Set(value)
	}
	cloned.validityShares = make([][]byte, len(result.validityShares))
	for index := range result.validityShares {
		cloned.validityShares[index] = append(
			[]byte(nil), result.validityShares[index]...)
	}
	cloned.alignmentGateShares = append(
		[]byte(nil), result.alignmentGateShares...)
	cloned.consensusShares = append(
		[][32]byte(nil), result.consensusShares...)
	return cloned, nil
}

func formalGLMRegisteredPhase19ClonePairV1(
	pair formalGLMPhase19PairedFanIn,
) formalGLMPhase19PairedFanIn {
	cloned := pair
	cloned.PairCommitments = formalGLMRegisteredPhase19CloneStringMapV1(
		pair.PairCommitments)
	return cloned
}

func formalGLMRegisteredPhase19ValidatePublicFanInReceiptLockedV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	public formalGLMRegisteredPhase19FanInReceiptV1,
) (formalGLMPhase19FanInReceipt, error) {
	legacy := formalGLMRegisteredPhase19CloneLegacyFanInReceiptV1(public.Receipt)
	rows, err := formalGLMPhase19RowsInBlock(
		runtime.legacyPlan, public.BlockIndex)
	if err != nil ||
		public.Version != formalGLMRegisteredPhase19FanInReceiptVersionV1 ||
		public.Purpose != formalGLMRegisteredPhase19FanInReceiptPurposeV1 ||
		public.SemanticRootSHA256 != runtime.semanticRootSHA256 ||
		public.ReceiptSetSHA256 != runtime.receiptSetSHA256 ||
		public.RegisteredExecutionPlanSHA256 !=
			runtime.registeredExecutionPlanSHA256 ||
		public.Recipient != legacy.Recipient ||
		public.BlockIndex != legacy.BlockIndex || public.RowsInBlock != rows ||
		public.FanInRoot != legacy.FanInRoot || public.OpeningsPerformed != 0 ||
		public.ProductionReady {
		return formalGLMPhase19FanInReceipt{}, fmt.Errorf(
			"formal-glm registered Phase19: invalid public fan-in receipt")
	}
	if err := formalGLMPhase19VerifyFanInReceipt(
		runtime.context, legacy, runtime.backendKey); err != nil {
		return formalGLMPhase19FanInReceipt{}, err
	}
	return legacy, nil
}

func formalGLMRegisteredPhase19ExportFanInReceiptV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	result formalGLMRegisteredPhase19FanInResultV1,
) (formalGLMRegisteredPhase19FanInReceiptV1, error) {
	var zero formalGLMRegisteredPhase19FanInReceiptV1
	if runtime == nil {
		return zero, fmt.Errorf(
			"formal-glm registered Phase19: runtime is unavailable")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if err := runtime.validateLocked(); err != nil {
		return zero, err
	}
	if err := formalGLMRegisteredPhase19ValidateFanInResultLockedV1(
		runtime, result); err != nil {
		return zero, err
	}
	public := formalGLMRegisteredPhase19FanInReceiptV1{
		Version:                       formalGLMRegisteredPhase19FanInReceiptVersionV1,
		Purpose:                       formalGLMRegisteredPhase19FanInReceiptPurposeV1,
		SemanticRootSHA256:            runtime.semanticRootSHA256,
		ReceiptSetSHA256:              runtime.receiptSetSHA256,
		RegisteredExecutionPlanSHA256: runtime.registeredExecutionPlanSHA256,
		Recipient:                     result.Recipient,
		BlockIndex:                    result.BlockIndex,
		RowsInBlock:                   result.RowsInBlock,
		FanInRoot:                     result.FanInRoot,
		Receipt: formalGLMRegisteredPhase19CloneLegacyFanInReceiptV1(
			result.fanIn.Receipt),
		OpeningsPerformed: 0,
		ProductionReady:   false,
	}
	if _, err := formalGLMRegisteredPhase19ValidatePublicFanInReceiptLockedV1(
		runtime, public); err != nil {
		return zero, err
	}
	return public, nil
}

func (execution *formalGLMRegisteredPhase19BlockExecutionV1) validateLocked() error {
	if execution == nil || !execution.verified ||
		execution.version != formalGLMRegisteredPhase19BlockExecutionVersionV1 ||
		!formalGLMIsSHA256(execution.semanticRootSHA256) ||
		!formalGLMIsSHA256(execution.receiptSetSHA256) ||
		!formalGLMIsSHA256(execution.registeredExecutionPlanSHA256) ||
		!formalGLMPhase19KeyValid(execution.backendKey) ||
		execution.peer != execution.local.Receipt.Recipient ||
		execution.blockIndex != execution.pair.BlockIndex ||
		execution.blockIndex != execution.local.Receipt.BlockIndex ||
		execution.rowsInBlock < 1 ||
		execution.backendKey != execution.session.MasterKey {
		return fmt.Errorf(
			"formal-glm registered Phase19: invalid block execution")
	}
	rows, err := formalGLMPhase19RowsInBlock(
		execution.plan, execution.blockIndex)
	if err != nil || rows != execution.rowsInBlock {
		return fmt.Errorf(
			"formal-glm registered Phase19: invalid block execution geometry")
	}
	if err := formalGLMPhase19VerifyLocalPair(
		execution.plan, execution.context, execution.pair,
		execution.local, execution.backendKey); err != nil {
		return err
	}
	if err := formalGLMPhase19ValidateBlockSession(
		execution.plan, execution.context, execution.pair,
		execution.session); err != nil {
		return err
	}
	return nil
}

func formalGLMRegisteredPhase19PrepareBlockExecutionV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	local formalGLMRegisteredPhase19FanInResultV1,
	peerReceipt formalGLMRegisteredPhase19FanInReceiptV1,
	attemptID [32]byte,
) (*formalGLMRegisteredPhase19BlockExecutionV1, error) {
	if runtime == nil {
		return nil, fmt.Errorf(
			"formal-glm registered Phase19: runtime is unavailable")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if err := runtime.validateLocked(); err != nil {
		return nil, err
	}
	if err := formalGLMRegisteredPhase19ValidateFanInResultLockedV1(
		runtime, local); err != nil {
		return nil, err
	}
	peer, err := formalGLMRegisteredPhase19ValidatePublicFanInReceiptLockedV1(
		runtime, peerReceipt)
	if err != nil {
		return nil, err
	}
	var pair formalGLMPhase19PairedFanIn
	if local.Recipient == runtime.context.ComputePeers[0] {
		pair, err = formalGLMPhase19PairFanIn(
			runtime.context, local.fanIn.Receipt, peer, runtime.backendKey)
	} else if local.Recipient == runtime.context.ComputePeers[1] {
		pair, err = formalGLMPhase19PairFanIn(
			runtime.context, peer, local.fanIn.Receipt, runtime.backendKey)
	} else {
		err = fmt.Errorf(
			"formal-glm registered Phase19: invalid local compute peer")
	}
	if err != nil {
		return nil, err
	}
	if err := formalGLMPhase19VerifyLocalPair(
		runtime.legacyPlan, runtime.context, pair,
		local.fanIn, runtime.backendKey); err != nil {
		return nil, err
	}
	session, err := formalGLMPhase19BlockSession(
		runtime.legacyPlan, runtime.context, pair, attemptID,
		runtime.backendKey)
	if err != nil {
		return nil, err
	}
	localCopy, err := formalGLMRegisteredPhase19CloneLegacyFanInV1(local.fanIn)
	if err != nil {
		return nil, err
	}
	execution := &formalGLMRegisteredPhase19BlockExecutionV1{
		version:                       formalGLMRegisteredPhase19BlockExecutionVersionV1,
		semanticRootSHA256:            runtime.semanticRootSHA256,
		receiptSetSHA256:              runtime.receiptSetSHA256,
		registeredExecutionPlanSHA256: runtime.registeredExecutionPlanSHA256,
		peer:                          local.Recipient,
		blockIndex:                    local.BlockIndex,
		rowsInBlock:                   local.RowsInBlock,
		plan:                          formalGLMRegisteredPhase19ClonePlanV1(runtime.legacyPlan),
		context:                       formalGLMRegisteredPhase19CloneContextV1(runtime.context),
		pair:                          formalGLMRegisteredPhase19ClonePairV1(pair),
		local:                         localCopy,
		session:                       session,
		backendKey:                    runtime.backendKey,
		verified:                      true,
	}
	if err := execution.validateLocked(); err != nil {
		execution.Close()
		return nil, err
	}
	return execution, nil
}

func (execution *formalGLMRegisteredPhase19BlockExecutionV1) claim() (
	formalGLMRegisteredPhase19BlockExecutionSnapshotV1, error,
) {
	var zero formalGLMRegisteredPhase19BlockExecutionSnapshotV1
	if execution == nil {
		return zero, fmt.Errorf(
			"formal-glm registered Phase19: block execution is unavailable")
	}
	execution.mu.Lock()
	defer execution.mu.Unlock()
	if err := execution.validateLocked(); err != nil {
		return zero, err
	}
	if execution.claimed {
		return zero, fmt.Errorf(
			"formal-glm registered Phase19: block execution session already claimed")
	}
	local, err := formalGLMRegisteredPhase19CloneLegacyFanInV1(
		execution.local)
	if err != nil {
		return zero, err
	}
	execution.claimed = true
	return formalGLMRegisteredPhase19BlockExecutionSnapshotV1{
		semanticRootSHA256:            execution.semanticRootSHA256,
		receiptSetSHA256:              execution.receiptSetSHA256,
		registeredExecutionPlanSHA256: execution.registeredExecutionPlanSHA256,
		peer:                          execution.peer,
		blockIndex:                    execution.blockIndex,
		rowsInBlock:                   execution.rowsInBlock,
		plan:                          formalGLMRegisteredPhase19ClonePlanV1(execution.plan),
		context:                       formalGLMRegisteredPhase19CloneContextV1(execution.context),
		pair:                          formalGLMRegisteredPhase19ClonePairV1(execution.pair),
		local:                         local,
		session:                       execution.session,
		backendKey:                    execution.backendKey,
	}, nil
}

func (snapshot *formalGLMRegisteredPhase19BlockExecutionSnapshotV1) clear() {
	if snapshot == nil {
		return
	}
	formalGLMPhase19RuntimeZeroFanIn(&snapshot.local)
	snapshot.local.verified = false
	clear(snapshot.pair.seal[:])
	snapshot.pair.verified = false
	snapshot.pair.PairCommitments = nil
	clear(snapshot.session.MasterKey[:])
	clear(snapshot.backendKey[:])
}

func (execution *formalGLMRegisteredPhase19BlockExecutionV1) Close() {
	if execution == nil {
		return
	}
	execution.mu.Lock()
	defer execution.mu.Unlock()
	formalGLMPhase19RuntimeZeroFanIn(&execution.local)
	execution.local.verified = false
	clear(execution.pair.seal[:])
	execution.pair.verified = false
	execution.pair.PairCommitments = nil
	clear(execution.session.MasterKey[:])
	clear(execution.backendKey[:])
	execution.verified = false
}

func formalGLMRegisteredPhase19ValidateMaskedReceiptV1(
	snapshot formalGLMRegisteredPhase19BlockExecutionSnapshotV1,
	public formalGLMRegisteredPhase19MaskedReceiptV1,
) error {
	if public.Version != formalGLMRegisteredPhase19MaskedReceiptVersionV1 ||
		public.Purpose != formalGLMRegisteredPhase19MaskedReceiptPurposeV1 ||
		public.SemanticRootSHA256 != snapshot.semanticRootSHA256 ||
		public.ReceiptSetSHA256 != snapshot.receiptSetSHA256 ||
		public.RegisteredExecutionPlanSHA256 !=
			snapshot.registeredExecutionPlanSHA256 ||
		public.Peer != public.Receipt.Peer ||
		public.BlockIndex != snapshot.blockIndex ||
		public.BlockIndex != public.Receipt.BlockIndex ||
		public.RowsInBlock != snapshot.rowsInBlock ||
		public.PairRoot != snapshot.pair.PairRoot ||
		public.PairRoot != public.Receipt.PairRoot ||
		public.Receipt.SessionID != hex.EncodeToString(
			snapshot.session.SessionID[:]) ||
		public.OpeningsPerformed != 0 || public.ProductionReady {
		return fmt.Errorf(
			"formal-glm registered Phase19: invalid public masked receipt")
	}
	return formalGLMPhase19VerifyMaskedBlockReceipt(
		snapshot.context, snapshot.pair, public.Receipt,
		snapshot.backendKey)
}

func formalGLMRegisteredPhase19RunBlockPeerV1(
	rw io.ReadWriter,
	execution *formalGLMRegisteredPhase19BlockExecutionV1,
) (formalGLMRegisteredPhase19MaskedBlockV1, error) {
	var zero formalGLMRegisteredPhase19MaskedBlockV1
	if rw == nil {
		return zero, fmt.Errorf(
			"formal-glm registered Phase19: nil peer channel")
	}
	// claim() deep-copies the one-use session and releases its local mutex
	// before protocol I/O. The registered runtime is never referenced here.
	snapshot, err := execution.claim()
	if err != nil {
		return zero, err
	}
	defer snapshot.clear()
	var block formalGLMPhase19MaskedBlock
	if snapshot.peer == snapshot.context.ComputePeers[0] {
		block, err = formalGLMPhase19RunGarbler(
			rw, snapshot.plan, snapshot.context, snapshot.pair,
			snapshot.local, snapshot.session, snapshot.backendKey)
	} else if snapshot.peer == snapshot.context.ComputePeers[1] {
		block, err = formalGLMPhase19RunEvaluator(
			rw, snapshot.plan, snapshot.context, snapshot.pair,
			snapshot.local, snapshot.session, snapshot.backendKey)
	} else {
		err = fmt.Errorf(
			"formal-glm registered Phase19: invalid block execution peer")
	}
	if err != nil {
		return zero, err
	}
	if err := formalGLMPhase19VerifyMaskedBlock(
		snapshot.plan, snapshot.context, snapshot.pair, block,
		snapshot.backendKey); err != nil {
		formalGLMRegisteredPhase19ClearMaskedBlockV1(&block)
		return zero, err
	}
	public := formalGLMRegisteredPhase19MaskedReceiptV1{
		Version:                       formalGLMRegisteredPhase19MaskedReceiptVersionV1,
		Purpose:                       formalGLMRegisteredPhase19MaskedReceiptPurposeV1,
		SemanticRootSHA256:            snapshot.semanticRootSHA256,
		ReceiptSetSHA256:              snapshot.receiptSetSHA256,
		RegisteredExecutionPlanSHA256: snapshot.registeredExecutionPlanSHA256,
		Peer:                          snapshot.peer,
		BlockIndex:                    snapshot.blockIndex,
		RowsInBlock:                   snapshot.rowsInBlock,
		PairRoot:                      snapshot.pair.PairRoot,
		Receipt:                       block.Receipt,
		OpeningsPerformed:             0,
		ProductionReady:               false,
	}
	if err := formalGLMRegisteredPhase19ValidateMaskedReceiptV1(
		snapshot, public); err != nil {
		formalGLMRegisteredPhase19ClearMaskedBlockV1(&block)
		return zero, err
	}
	return formalGLMRegisteredPhase19MaskedBlockV1{
		Receipt: public, block: block,
	}, nil
}

func formalGLMRegisteredPhase19ClearMaskedBlockV1(
	block *formalGLMPhase19MaskedBlock,
) {
	if block == nil {
		return
	}
	exactGCZeroBigInts(block.tupleShares)
	block.tupleShares = nil
	block.executionShare = 0
	clear(block.seal[:])
	block.verified = false
}

func (block *formalGLMRegisteredPhase19MaskedBlockV1) Close() {
	if block == nil {
		return
	}
	formalGLMRegisteredPhase19ClearMaskedBlockV1(&block.block)
}

func formalGLMRegisteredPhase19PairMaskedReceiptsV1(
	execution *formalGLMRegisteredPhase19BlockExecutionV1,
	garbler formalGLMRegisteredPhase19MaskedReceiptV1,
	evaluator formalGLMRegisteredPhase19MaskedReceiptV1,
) (formalGLMRegisteredPhase19MaskedReceiptPairV1, error) {
	var zero formalGLMRegisteredPhase19MaskedReceiptPairV1
	if execution == nil {
		return zero, fmt.Errorf(
			"formal-glm registered Phase19: block execution is unavailable")
	}
	execution.mu.Lock()
	defer execution.mu.Unlock()
	if err := execution.validateLocked(); err != nil {
		return zero, err
	}
	snapshot := formalGLMRegisteredPhase19BlockExecutionSnapshotV1{
		semanticRootSHA256:            execution.semanticRootSHA256,
		receiptSetSHA256:              execution.receiptSetSHA256,
		registeredExecutionPlanSHA256: execution.registeredExecutionPlanSHA256,
		peer:                          execution.peer,
		blockIndex:                    execution.blockIndex,
		rowsInBlock:                   execution.rowsInBlock,
		plan:                          execution.plan,
		context:                       execution.context,
		pair:                          execution.pair,
		session:                       execution.session,
		backendKey:                    execution.backendKey,
	}
	defer snapshot.clear()
	if err := formalGLMRegisteredPhase19ValidateMaskedReceiptV1(
		snapshot, garbler); err != nil {
		return zero, err
	}
	if err := formalGLMRegisteredPhase19ValidateMaskedReceiptV1(
		snapshot, evaluator); err != nil {
		return zero, err
	}
	legacy, err := formalGLMPhase19PairMaskedBlockReceipts(
		snapshot.context, snapshot.pair, garbler.Receipt,
		evaluator.Receipt, snapshot.backendKey)
	if err != nil {
		return zero, err
	}
	if err := formalGLMPhase19VerifyMaskedBlockReceiptPair(
		snapshot.context, legacy, snapshot.backendKey); err != nil {
		return zero, err
	}
	return formalGLMRegisteredPhase19MaskedReceiptPairV1{
		Version:                       formalGLMRegisteredPhase19MaskedPairVersionV1,
		Purpose:                       formalGLMRegisteredPhase19MaskedPairPurposeV1,
		SemanticRootSHA256:            snapshot.semanticRootSHA256,
		ReceiptSetSHA256:              snapshot.receiptSetSHA256,
		RegisteredExecutionPlanSHA256: snapshot.registeredExecutionPlanSHA256,
		BlockIndex:                    snapshot.blockIndex,
		RowsInBlock:                   snapshot.rowsInBlock,
		PairRoot:                      legacy.PairRoot,
		GarblerReceiptSHA256:          legacy.GarblerReceiptSHA256,
		EvaluatorReceiptSHA256:        legacy.EvaluatorReceiptSHA256,
		ReceiptPairSHA256:             legacy.ReceiptPairSHA256,
		ExecutionValidSealed:          legacy.ExecutionValidSealed,
		ExecutionValidityOpened:       legacy.ExecutionValidityOpened,
		OpeningsPerformed:             legacy.OpeningsPerformed,
		ProductionReady:               legacy.ProductionReady,
		pair:                          legacy,
	}, nil
}

func (pair formalGLMRegisteredPhase19MaskedReceiptPairV1) Public() formalGLMRegisteredPhase19MaskedReceiptPairV1 {
	pair.pair = formalGLMPhase19MaskedBlockReceiptPair{}
	return pair
}

func (pair *formalGLMRegisteredPhase19MaskedReceiptPairV1) Close() {
	if pair == nil {
		return
	}
	clear(pair.pair.seal[:])
	pair.pair.verified = false
}
