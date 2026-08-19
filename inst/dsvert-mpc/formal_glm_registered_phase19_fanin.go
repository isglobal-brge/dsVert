package main

// Capsule-free, server-internal adapter from the registered Phase19 loader to
// the existing exact Phase19 fan-in. Operational aliases exist only inside the
// ephemeral trust type and are deterministically derived from SemanticRoot.

import (
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"sync"
)

const (
	formalGLMRegisteredPhase19EphemeralRuntimeVersionV1 = "dsvert-formal-glm-registered-phase19-ephemeral-runtime-v1"
	formalGLMRegisteredPhase19FanInResultVersionV1      = "dsvert-formal-glm-registered-phase19-fanin-result-v1"
	formalGLMRegisteredPhase19FanInResultPurposeV1      = "formal_glm_registered_phase19_exact_source_fanin_v1"
	formalGLMRegisteredPhase19EphemeralDomainV1         = "dsVert/formal-glm/registered-phase19/ephemeral-runtime/v1"
	formalGLMRegisteredPhase19FanInDomainV1             = "dsVert/formal-glm/registered-phase19/fanin-wrapper/v1"
)

type formalGLMRegisteredPhase19RuntimeSourceV1 struct {
	source                     string
	authorizationSHA256        string
	localMaterializationSHA256 string
	commitments                []formalGLMRegisteredPhase18BlockCommitmentV1
	bindingSeals               [][32]byte
}

// formalGLMRegisteredPhase19EphemeralRuntimeV1 has no exported fields and no
// JSON representation. Its legacy aliases and backend key never leave memory.
type formalGLMRegisteredPhase19EphemeralRuntimeV1 struct {
	mu sync.Mutex

	version                       string
	semanticRootSHA256            string
	bindingRecordSHA256           string
	receiptSetSHA256              string
	globalMaterializationSHA256   string
	registeredExecutionPlanSHA256 string
	runAlias                      string
	artifactAlias                 string
	capsuleAlias                  string
	preExecutionAlias             string
	legacyPlan                    formalGLMPhase15Plan
	context                       formalGLMPhase19Context
	sources                       []formalGLMRegisteredPhase19RuntimeSourceV1
	backendKey                    [32]byte
	ledger                        *formalGLMPhase19ReplayLedger
	seal                          [32]byte
	verified                      bool
}

// formalGLMRegisteredPhase19FanInResultV1 exposes only registered, public
// routing evidence. The exact legacy fan-in and its backend seal stay private.
type formalGLMRegisteredPhase19FanInResultV1 struct {
	Version                       string `json:"version"`
	Purpose                       string `json:"purpose"`
	SemanticRootSHA256            string `json:"semantic_root_sha256"`
	ReceiptSetSHA256              string `json:"receipt_set_sha256"`
	RegisteredExecutionPlanSHA256 string `json:"registered_execution_plan_sha256"`
	Recipient                     string `json:"recipient"`
	BlockIndex                    int    `json:"block_index"`
	RowsInBlock                   int    `json:"rows_in_block"`
	FanInRoot                     string `json:"fan_in_root"`
	OpeningsPerformed             int    `json:"openings_performed"`
	ProductionReady               bool   `json:"production_ready"`

	fanIn    formalGLMPhase19FanInResult
	seal     [32]byte
	verified bool
}

func formalGLMRegisteredPhase19EphemeralAliasV1(
	semanticRootSHA256, kind string,
) (string, error) {
	if !formalGLMIsSHA256(semanticRootSHA256) {
		return "", fmt.Errorf("formal-glm registered Phase19: invalid semantic root")
	}
	switch kind {
	case "run", "artifact", "capsule", "pre-execution":
	default:
		return "", fmt.Errorf("formal-glm registered Phase19: invalid ephemeral alias kind")
	}
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase19EphemeralDomainV1+"/alias/"+kind,
		semanticRootSHA256)
}

func formalGLMRegisteredPhase19EphemeralAliasesV1(
	semanticRootSHA256 string,
) (run, artifact, capsule, preExecution string, err error) {
	values := []*string{&run, &artifact, &capsule, &preExecution}
	kinds := []string{"run", "artifact", "capsule", "pre-execution"}
	seen := make(map[string]bool, len(kinds))
	for index, kind := range kinds {
		*values[index], err = formalGLMRegisteredPhase19EphemeralAliasV1(
			semanticRootSHA256, kind)
		if err != nil || seen[*values[index]] {
			return "", "", "", "", fmt.Errorf(
				"formal-glm registered Phase19: ephemeral alias derivation failed")
		}
		seen[*values[index]] = true
	}
	return run, artifact, capsule, preExecution, nil
}

func formalGLMRegisteredPhase19LegacyRuntimePlanV1(
	plan formalGLMRegisteredExecutionPlanV1,
	semanticRootSHA256 string,
) (formalGLMPhase15Plan, string, string, string, string, error) {
	var zero formalGLMPhase15Plan
	run, artifact, capsule, preExecution, err :=
		formalGLMRegisteredPhase19EphemeralAliasesV1(semanticRootSHA256)
	if err != nil {
		return zero, "", "", "", "", err
	}
	legacy, err := formalGLMRegisteredExecutionLegacyPlanV1(plan)
	if err != nil {
		return zero, "", "", "", "", err
	}
	legacy.RunID = run
	legacy.Kernel.ArtifactSHA256 = artifact
	legacy.Kernel.CapsuleSHA256 = capsule
	if validateFormalGLMPhase15Plan(legacy) != nil ||
		formalGLMPhase19ValidateTranscriptBoundV1(
			plan.TranscriptBound, legacy, plan.CanonicalDP) != nil {
		return zero, "", "", "", "", fmt.Errorf(
			"formal-glm registered Phase19: invalid registered plan geometry")
	}
	return legacy, run, artifact, capsule, preExecution, nil
}

func formalGLMRegisteredPhase19RuntimeMessageV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
) ([]byte, error) {
	if runtime == nil {
		return nil, fmt.Errorf("formal-glm registered Phase19: runtime is unavailable")
	}
	planDigest, err := formalGLMPhase15PlanDigest(runtime.legacyPlan)
	if err != nil {
		return nil, err
	}
	contextDigest, err := formalGLMPhase19ContextDigest(runtime.context)
	if err != nil {
		return nil, err
	}
	message := formalGLMPhase15AppendString(
		nil, formalGLMRegisteredPhase19EphemeralDomainV1+"/seal")
	for _, value := range []string{
		runtime.version, runtime.semanticRootSHA256,
		runtime.bindingRecordSHA256, runtime.receiptSetSHA256,
		runtime.globalMaterializationSHA256,
		runtime.registeredExecutionPlanSHA256, runtime.runAlias,
		runtime.artifactAlias, runtime.capsuleAlias,
		runtime.preExecutionAlias, hex.EncodeToString(planDigest[:]),
		hex.EncodeToString(contextDigest[:]),
	} {
		message = formalGLMPhase15AppendString(message, value)
	}
	return message, nil
}

func formalGLMRegisteredPhase19SourceBindingMessageV1(
	semanticRootSHA256, receiptSetSHA256 string,
	source formalGLMRegisteredPhase19RuntimeSourceV1,
	commitment formalGLMRegisteredPhase18BlockCommitmentV1,
) ([]byte, error) {
	if !formalGLMIsSHA256(semanticRootSHA256) ||
		!formalGLMIsSHA256(receiptSetSHA256) || source.source == "" ||
		!formalGLMIsSHA256(source.authorizationSHA256) ||
		!formalGLMIsSHA256(source.localMaterializationSHA256) ||
		commitment.BlockIndex < 0 ||
		!formalGLMIsSHA256(commitment.PairCommitmentSHA256) ||
		!formalGLMIsSHA256(commitment.BlockCommitmentSHA256) {
		return nil, fmt.Errorf(
			"formal-glm registered Phase19: invalid source binding")
	}
	message := formalGLMPhase15AppendString(
		nil, formalGLMRegisteredPhase19EphemeralDomainV1+"/source-binding")
	for _, value := range []string{
		semanticRootSHA256, receiptSetSHA256, source.source,
		source.authorizationSHA256, source.localMaterializationSHA256,
		commitment.PairCommitmentSHA256,
		commitment.BlockCommitmentSHA256,
	} {
		message = formalGLMPhase15AppendString(message, value)
	}
	message = formalGLMPhase15AppendUint64(
		message, uint64(commitment.BlockIndex))
	return message, nil
}

func (runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1) validateLocked() error {
	if runtime == nil || !runtime.verified || runtime.ledger == nil ||
		runtime.version != formalGLMRegisteredPhase19EphemeralRuntimeVersionV1 ||
		!formalGLMIsSHA256(runtime.bindingRecordSHA256) ||
		!formalGLMPhase19KeyValid(runtime.backendKey) {
		return fmt.Errorf("formal-glm registered Phase19: invalid ephemeral runtime")
	}
	run, artifact, capsule, preExecution, err :=
		formalGLMRegisteredPhase19EphemeralAliasesV1(
			runtime.semanticRootSHA256)
	if err != nil || run != runtime.runAlias || artifact != runtime.artifactAlias ||
		capsule != runtime.capsuleAlias ||
		preExecution != runtime.preExecutionAlias ||
		runtime.legacyPlan.RunID != run ||
		runtime.legacyPlan.Kernel.ArtifactSHA256 != artifact ||
		runtime.legacyPlan.Kernel.CapsuleSHA256 != capsule ||
		runtime.context.RunID != run || runtime.context.CapsuleSHA256 != capsule ||
		runtime.context.PreExecutionTokenSHA256 != preExecution ||
		runtime.context.GlobalMaterializationRoot !=
			runtime.globalMaterializationSHA256 {
		return fmt.Errorf("formal-glm registered Phase19: ephemeral alias mismatch")
	}
	message, err := formalGLMRegisteredPhase19RuntimeMessageV1(runtime)
	if err != nil {
		return err
	}
	want := formalGLMPhase19MAC(
		runtime.backendKey, formalGLMRegisteredPhase19EphemeralDomainV1, message)
	if !hmac.Equal(want[:], runtime.seal[:]) {
		return fmt.Errorf(
			"formal-glm registered Phase19: ephemeral runtime authentication failed")
	}
	return nil
}

func newFormalGLMRegisteredPhase19EphemeralRuntimeV1(
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
	backendKey [32]byte,
) (*formalGLMRegisteredPhase19EphemeralRuntimeV1, error) {
	if !formalGLMPhase19KeyValid(backendKey) {
		return nil, fmt.Errorf(
			"formal-glm registered Phase19: missing ephemeral backend")
	}
	if err := formalGLMValidateRegisteredPhase19BindingRecordV1(
		record, contract, pins); err != nil {
		return nil, err
	}
	plan := contract.Core.RegisteredExecutionPlan
	bindingRecordSHA256, err := formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase19EphemeralDomainV1+"/validated-binding-record",
		record)
	if err != nil {
		return nil, err
	}
	legacy, run, artifact, capsule, preExecution, err :=
		formalGLMRegisteredPhase19LegacyRuntimePlanV1(
			plan, record.Binding.SemanticRootSHA256)
	if err != nil {
		return nil, err
	}
	context, err := formalGLMPhase19BuildContext(
		legacy, preExecution,
		record.Binding.GlobalMaterializationRootSHA256)
	if err != nil {
		return nil, err
	}
	sources := make([]formalGLMRegisteredPhase19RuntimeSourceV1,
		plan.CustodianCount)
	for index, source := range plan.CustodianPeers {
		receipt := record.ReceiptSet.Receipts[index]
		sources[index] = formalGLMRegisteredPhase19RuntimeSourceV1{
			source:                     source,
			authorizationSHA256:        receipt.RegisteredPhase18AuthorizationSHA256,
			localMaterializationSHA256: receipt.LocalMaterializationRootSHA256,
			commitments: append(
				[]formalGLMRegisteredPhase18BlockCommitmentV1(nil),
				receipt.BlockCommitments...),
			bindingSeals: make([][32]byte, len(receipt.BlockCommitments)),
		}
		for blockIndex, commitment := range sources[index].commitments {
			message, messageErr :=
				formalGLMRegisteredPhase19SourceBindingMessageV1(
					record.Binding.SemanticRootSHA256,
					record.Binding.ReceiptSetSHA256,
					sources[index], commitment)
			if messageErr != nil {
				return nil, messageErr
			}
			sources[index].bindingSeals[blockIndex] = formalGLMPhase19MAC(
				backendKey,
				formalGLMRegisteredPhase19EphemeralDomainV1+"/source-binding",
				message)
		}
	}
	runtime := &formalGLMRegisteredPhase19EphemeralRuntimeV1{
		version:                       formalGLMRegisteredPhase19EphemeralRuntimeVersionV1,
		semanticRootSHA256:            record.Binding.SemanticRootSHA256,
		bindingRecordSHA256:           bindingRecordSHA256,
		receiptSetSHA256:              record.Binding.ReceiptSetSHA256,
		globalMaterializationSHA256:   record.Binding.GlobalMaterializationRootSHA256,
		registeredExecutionPlanSHA256: plan.PlanSHA256,
		runAlias:                      run, artifactAlias: artifact, capsuleAlias: capsule,
		preExecutionAlias: preExecution, legacyPlan: legacy, context: context,
		sources: sources, backendKey: backendKey,
		ledger: newFormalGLMPhase19ReplayLedger(), verified: true,
	}
	message, err := formalGLMRegisteredPhase19RuntimeMessageV1(runtime)
	if err != nil {
		runtime.Close()
		return nil, err
	}
	runtime.seal = formalGLMPhase19MAC(
		backendKey, formalGLMRegisteredPhase19EphemeralDomainV1, message)
	if err := runtime.validateLocked(); err != nil {
		runtime.Close()
		return nil, err
	}
	return runtime, nil
}

func (runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1) Close() {
	if runtime == nil {
		return
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	clear(runtime.backendKey[:])
	clear(runtime.seal[:])
	for sourceIndex := range runtime.sources {
		for blockIndex := range runtime.sources[sourceIndex].bindingSeals {
			clear(runtime.sources[sourceIndex].bindingSeals[blockIndex][:])
		}
		runtime.sources[sourceIndex].bindingSeals = nil
		runtime.sources[sourceIndex].commitments = nil
	}
	runtime.verified = false
	if runtime.ledger != nil {
		runtime.ledger.mu.Lock()
		for slot := range runtime.ledger.entries {
			delete(runtime.ledger.entries, slot)
		}
		runtime.ledger.mu.Unlock()
		runtime.ledger = nil
	}
}

func formalGLMRegisteredPhase19ClearVerifiedBlocksV1(
	blocks []formalGLMPhase19VerifiedSourceBlock,
) {
	for index := range blocks {
		exactGCZeroBigInts(blocks[index].coordinateShares)
		clear(blocks[index].validityShares)
		clear(blocks[index].consensusShare[:])
		clear(blocks[index].seal[:])
		blocks[index].verified = false
	}
}

func formalGLMRegisteredPhase19ClearFanInResultV1(
	result *formalGLMRegisteredPhase19FanInResultV1,
) {
	if result == nil {
		return
	}
	formalGLMPhase19RuntimeZeroFanIn(&result.fanIn)
	clear(result.seal[:])
	result.verified = false
}

func formalGLMRegisteredPhase19ValidatePrivateBlockSetV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	blocks []formalGLMRegisteredPhase19PrivateBlockV1,
	recipient string, blockIndex int,
) error {
	plan := runtime.legacyPlan
	recipientSlot := -1
	for index, peer := range plan.Kernel.ComputePeers {
		if peer == recipient {
			recipientSlot = index
		}
	}
	if recipientSlot < 0 || blockIndex < 0 || blockIndex >= plan.TotalBlocks ||
		len(blocks) != len(runtime.sources) {
		return fmt.Errorf(
			"formal-glm registered Phase19: incomplete private block set")
	}
	rows, err := formalGLMPhase19RowsInBlock(plan, blockIndex)
	if err != nil {
		return err
	}
	role := "garbler"
	if recipientSlot == 1 {
		role = "evaluator"
	}
	modulus := exactGCModulus(plan.RingBits)
	for sourceIndex, expectedSource := range runtime.sources {
		if len(expectedSource.commitments) != plan.TotalBlocks ||
			len(expectedSource.bindingSeals) != plan.TotalBlocks {
			return fmt.Errorf(
				"formal-glm registered Phase19: incomplete runtime source binding")
		}
		commitment := expectedSource.commitments[blockIndex]
		bindingMessage, bindingErr :=
			formalGLMRegisteredPhase19SourceBindingMessageV1(
				runtime.semanticRootSHA256, runtime.receiptSetSHA256,
				expectedSource, commitment)
		wantBindingSeal := formalGLMPhase19MAC(
			runtime.backendKey,
			formalGLMRegisteredPhase19EphemeralDomainV1+"/source-binding",
			bindingMessage)
		if bindingErr != nil || !hmac.Equal(
			wantBindingSeal[:], expectedSource.bindingSeals[blockIndex][:]) {
			return fmt.Errorf(
				"formal-glm registered Phase19: invalid runtime source binding")
		}
		block := blocks[sourceIndex]
		if block.version != formalGLMRegisteredPhase19PrivateBlockVersionV1 ||
			!block.verified || block.semanticRootSHA256 != runtime.semanticRootSHA256 ||
			block.receiptSetSHA256 != runtime.receiptSetSHA256 ||
			block.registeredAuthorizationSHA256 !=
				expectedSource.authorizationSHA256 ||
			block.source != expectedSource.source || block.sourceSlot != sourceIndex ||
			block.recipient != recipient || block.recipientSlot != recipientSlot ||
			block.recipientRole != role || block.blockIndex != blockIndex ||
			block.totalBlocks != plan.TotalBlocks ||
			block.globalSlotOffset != blockIndex*plan.BlockCapacity ||
			block.slotsInBlock != plan.BlockCapacity || block.rowsInBlock != rows ||
			block.coordinateCount != runtime.context.CoordinatesPerRow ||
			block.ringBits != plan.RingBits ||
			block.recordBytes != exactGCRecordBytes(plan.RingBits) ||
			block.pairCommitmentSHA256 != commitment.PairCommitmentSHA256 ||
			block.blockCommitmentSHA256 != commitment.BlockCommitmentSHA256 ||
			len(block.coordinateShares) !=
				plan.BlockCapacity*runtime.context.CoordinatesPerRow ||
			len(block.validityShares) != plan.BlockCapacity ||
			block.alignmentGateShare > 1 || block.openingsPerformed != 0 {
			return fmt.Errorf(
				"formal-glm registered Phase19: malformed source-major private block")
		}
		for _, value := range block.coordinateShares {
			if value == nil || value.Sign() < 0 || value.Cmp(modulus) >= 0 {
				return fmt.Errorf(
					"formal-glm registered Phase19: non-canonical private coordinate")
			}
		}
		for _, share := range block.validityShares {
			if share > 1 {
				return fmt.Errorf(
					"formal-glm registered Phase19: non-bit private validity share")
			}
		}
	}
	return nil
}

func formalGLMRegisteredPhase19FanInResultMessageV1(
	result formalGLMRegisteredPhase19FanInResultV1,
) ([]byte, error) {
	if !result.verified ||
		result.Version != formalGLMRegisteredPhase19FanInResultVersionV1 ||
		result.Purpose != formalGLMRegisteredPhase19FanInResultPurposeV1 ||
		!formalGLMIsSHA256(result.SemanticRootSHA256) ||
		!formalGLMIsSHA256(result.ReceiptSetSHA256) ||
		!formalGLMIsSHA256(result.RegisteredExecutionPlanSHA256) ||
		!formalGLMIsSHA256(result.FanInRoot) || result.BlockIndex < 0 ||
		result.RowsInBlock < 1 || result.OpeningsPerformed != 0 ||
		result.ProductionReady {
		return nil, fmt.Errorf(
			"formal-glm registered Phase19: invalid fan-in wrapper")
	}
	hash, err := formalGLMRegisteredPhase19FanInResultSHA256V1(result)
	if err != nil {
		return nil, err
	}
	message := formalGLMPhase15AppendString(
		nil, formalGLMRegisteredPhase19FanInDomainV1+"/seal")
	message = formalGLMPhase15AppendString(message, hash)
	message = formalGLMPhase15AppendBytes(message, result.fanIn.seal[:])
	return message, nil
}

func formalGLMRegisteredPhase19FanInResultSHA256V1(
	result formalGLMRegisteredPhase19FanInResultV1,
) (string, error) {
	if result.Version != formalGLMRegisteredPhase19FanInResultVersionV1 ||
		result.Purpose != formalGLMRegisteredPhase19FanInResultPurposeV1 ||
		!formalGLMIsSHA256(result.SemanticRootSHA256) ||
		!formalGLMIsSHA256(result.ReceiptSetSHA256) ||
		!formalGLMIsSHA256(result.RegisteredExecutionPlanSHA256) ||
		!formalGLMIsSHA256(result.FanInRoot) || result.BlockIndex < 0 ||
		result.RowsInBlock < 1 || result.OpeningsPerformed != 0 ||
		result.ProductionReady {
		return "", fmt.Errorf(
			"formal-glm registered Phase19: invalid fan-in hash input")
	}
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase19FanInDomainV1+"/public", result)
}

func formalGLMRegisteredPhase19ValidateFanInResultLockedV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	result formalGLMRegisteredPhase19FanInResultV1,
) error {
	rows, err := formalGLMPhase19RowsInBlock(
		runtime.legacyPlan, result.BlockIndex)
	if err != nil || result.SemanticRootSHA256 != runtime.semanticRootSHA256 ||
		result.ReceiptSetSHA256 != runtime.receiptSetSHA256 ||
		result.RegisteredExecutionPlanSHA256 !=
			runtime.registeredExecutionPlanSHA256 ||
		result.Recipient != result.fanIn.Receipt.Recipient ||
		result.BlockIndex != result.fanIn.Receipt.BlockIndex ||
		result.RowsInBlock != rows || result.FanInRoot != result.fanIn.Receipt.FanInRoot ||
		formalGLMPhase19VerifyFanIn(
			runtime.legacyPlan, runtime.context, result.fanIn,
			runtime.backendKey) != nil {
		return fmt.Errorf(
			"formal-glm registered Phase19: fan-in wrapper differs from legacy result")
	}
	message, err := formalGLMRegisteredPhase19FanInResultMessageV1(result)
	if err != nil {
		return err
	}
	want := formalGLMPhase19MAC(
		runtime.backendKey, formalGLMRegisteredPhase19FanInDomainV1, message)
	if !hmac.Equal(want[:], result.seal[:]) {
		return fmt.Errorf(
			"formal-glm registered Phase19: fan-in wrapper authentication failed")
	}
	return nil
}

func formalGLMRegisteredPhase19ValidateFanInResultV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	result formalGLMRegisteredPhase19FanInResultV1,
) error {
	if runtime == nil {
		return fmt.Errorf("formal-glm registered Phase19: runtime is unavailable")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if err := runtime.validateLocked(); err != nil {
		return err
	}
	return formalGLMRegisteredPhase19ValidateFanInResultLockedV1(
		runtime, result)
}

func formalGLMRegisteredPhase19FanInPrivateBlockSetLockedV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	blocks []formalGLMRegisteredPhase19PrivateBlockV1,
	recipient string,
	blockIndex int,
) (formalGLMRegisteredPhase19FanInResultV1, error) {
	var zero formalGLMRegisteredPhase19FanInResultV1
	if err := formalGLMRegisteredPhase19ValidatePrivateBlockSetV1(
		runtime, blocks, recipient, blockIndex); err != nil {
		return zero, err
	}
	verified := make([]formalGLMPhase19VerifiedSourceBlock, 0,
		len(runtime.sources))
	defer formalGLMRegisteredPhase19ClearVerifiedBlocksV1(verified)
	for sourceIndex := range runtime.sources {
		block := blocks[sourceIndex]
		sealed, err := formalGLMPhase19SealSourceBlock(
			runtime.legacyPlan, runtime.context, block.source, recipient,
			blockIndex, block.coordinateShares, block.validityShares,
			block.alignmentGateShare, block.alignmentConsensusShare,
			block.pairCommitmentSHA256, block.blockCommitmentSHA256,
			runtime.backendKey)
		if err != nil {
			return zero, err
		}
		verified = append(verified, sealed)
	}
	legacy, err := formalGLMPhase19FanIn(
		runtime.legacyPlan, runtime.context, recipient, blockIndex, verified,
		runtime.ledger, runtime.backendKey)
	if err != nil {
		return zero, err
	}
	rows, _ := formalGLMPhase19RowsInBlock(runtime.legacyPlan, blockIndex)
	result := formalGLMRegisteredPhase19FanInResultV1{
		Version:                       formalGLMRegisteredPhase19FanInResultVersionV1,
		Purpose:                       formalGLMRegisteredPhase19FanInResultPurposeV1,
		SemanticRootSHA256:            runtime.semanticRootSHA256,
		ReceiptSetSHA256:              runtime.receiptSetSHA256,
		RegisteredExecutionPlanSHA256: runtime.registeredExecutionPlanSHA256,
		Recipient:                     recipient, BlockIndex: blockIndex, RowsInBlock: rows,
		FanInRoot:         legacy.Receipt.FanInRoot,
		OpeningsPerformed: 0, ProductionReady: false,
		fanIn: legacy, verified: true,
	}
	message, err := formalGLMRegisteredPhase19FanInResultMessageV1(result)
	if err != nil {
		formalGLMRegisteredPhase19ClearFanInResultV1(&result)
		return zero, err
	}
	result.seal = formalGLMPhase19MAC(
		runtime.backendKey, formalGLMRegisteredPhase19FanInDomainV1, message)
	if err := formalGLMRegisteredPhase19ValidateFanInResultLockedV1(
		runtime, result); err != nil {
		formalGLMRegisteredPhase19ClearFanInResultV1(&result)
		return zero, err
	}
	return result, nil
}

// formalGLMRegisteredPhase19FanInPrivateBlockSetV1 consumes exactly one
// source-complete private block set. It is the bounded-memory counterpart of
// the legacy source-major adapter and never retains another block.
func formalGLMRegisteredPhase19FanInPrivateBlockSetV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	blocks []formalGLMRegisteredPhase19PrivateBlockV1,
	recipient string,
	blockIndex int,
) (formalGLMRegisteredPhase19FanInResultV1, error) {
	var zero formalGLMRegisteredPhase19FanInResultV1
	if runtime == nil {
		return zero, fmt.Errorf(
			"formal-glm registered Phase19: runtime is unavailable")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if err := runtime.validateLocked(); err != nil {
		return zero, err
	}
	return formalGLMRegisteredPhase19FanInPrivateBlockSetLockedV1(
		runtime, blocks, recipient, blockIndex)
}

// formalGLMRegisteredPhase19FanInBlockV1 preserves the historical
// source-major private-block API. New callers should use the block-set seam.
func formalGLMRegisteredPhase19FanInBlockV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	blocks []formalGLMRegisteredPhase19PrivateBlockV1,
	recipient string,
	blockIndex int,
) (formalGLMRegisteredPhase19FanInResultV1, error) {
	var zero formalGLMRegisteredPhase19FanInResultV1
	if runtime == nil {
		return zero, fmt.Errorf(
			"formal-glm registered Phase19: runtime is unavailable")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if err := runtime.validateLocked(); err != nil {
		return zero, err
	}
	if blockIndex < 0 || blockIndex >= runtime.legacyPlan.TotalBlocks ||
		len(blocks) != len(runtime.sources)*runtime.legacyPlan.TotalBlocks {
		return zero, fmt.Errorf(
			"formal-glm registered Phase19: incomplete source-major private blocks")
	}
	blockSet := make([]formalGLMRegisteredPhase19PrivateBlockV1,
		len(runtime.sources))
	for sourceIndex := range blockSet {
		blockSet[sourceIndex] =
			blocks[sourceIndex*runtime.legacyPlan.TotalBlocks+blockIndex]
	}
	return formalGLMRegisteredPhase19FanInPrivateBlockSetLockedV1(
		runtime, blockSet, recipient, blockIndex)
}
