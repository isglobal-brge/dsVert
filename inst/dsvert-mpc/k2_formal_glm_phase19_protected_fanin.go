package main

// Phase 1.9 is the internal, sealed K-to-two materialisation fan-in for the
// formal GLM.  It consumes only blocks which the internal durable Phase-1.8
// finaliser has authenticated and decrypted locally.  The relay never receives a plaintext
// coordinate, validity bit, alignment status, consensus digest, or output
// share.  This file intentionally registers no command handler.
//
// The exact GC reconstructs every custodian validity lane with XOR, applies an
// exact all-K AND, reconstructs XOR-shared consensus digests only inside GC,
// compares them across all K custodians, validates the complete scientific tuple, and masks
// all p+3 coordinates when any row condition fails.  A second exact circuit
// accumulates a hidden "at least one positive-weight row" bit.  Neither bit is
// opened here.  The threat model remains pinned, semi-honest and non-colluding
// compute peers; a malicious custodian can still lie about its own source row.

import (
	"bytes"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/p2p"
)

const (
	formalGLMPhase19ContextVersion    = "dsvert-formal-glm-phase19-context-v2"
	formalGLMPhase19BlockVersion      = "dsvert-formal-glm-phase19-verified-source-block-v2"
	formalGLMPhase19FanInVersion      = "dsvert-formal-glm-phase19-fanin-receipt-v2"
	formalGLMPhase19PairVersion       = "dsvert-formal-glm-phase19-paired-fanin-v2"
	formalGLMPhase19OutputVersion     = "dsvert-formal-glm-phase19-masked-block-v2"
	formalGLMPhase19ExecVersion       = "dsvert-formal-glm-phase19-execution-seal-v2"
	formalGLMPhase19StreamExecVersion = "dsvert-formal-glm-phase19-stream-execution-seal-v1"

	formalGLMPhase19ContextDomain = "dsVert/formal-glm/phase19/context/v2"
	formalGLMPhase19BlockDomain   = "dsVert/formal-glm/phase19/verified-source-block/v2"
	formalGLMPhase19FanInDomain   = "dsVert/formal-glm/phase19/fanin/v2"
	formalGLMPhase19PairDomain    = "dsVert/formal-glm/phase19/paired-fanin/v2"
	formalGLMPhase19OutputDomain  = "dsVert/formal-glm/phase19/masked-output/v2"
	formalGLMPhase19ExecDomain    = "dsVert/formal-glm/phase19/execution-accumulator/v2"
)

type formalGLMPhase19Context struct {
	Version                   string   `json:"version"`
	CapsuleSHA256             string   `json:"capsule_sha256"`
	Phase15PlanSHA256         string   `json:"phase15_plan_sha256"`
	PreExecutionTokenSHA256   string   `json:"pre_execution_token_sha256"`
	RunID                     string   `json:"run_id"`
	PinsetSHA256              string   `json:"pinset_sha256"`
	GlobalMaterializationRoot string   `json:"global_materialization_root"`
	CustodianPeers            []string `json:"custodian_peers"`
	ComputePeers              []string `json:"compute_peers"`
	TotalCapacity             int      `json:"total_capacity"`
	BlockCapacity             int      `json:"block_capacity"`
	TotalBlocks               int      `json:"total_blocks"`
	CoordinatesPerRow         int      `json:"coordinates_per_row"`
	RingBits                  int      `json:"ring_bits"`
	InputContract             string   `json:"input_contract"`
	ValidityContract          string   `json:"validity_contract"`
	ConsensusContract         string   `json:"consensus_contract"`
	OutputContract            string   `json:"output_contract"`
	ProductionReady           bool     `json:"production_ready"`
}

func formalGLMPhase19BuildContext(plan formalGLMPhase15Plan,
	preExecutionTokenSHA256, globalMaterializationRoot string) (
	formalGLMPhase19Context, error) {

	if err := validateFormalGLMPhase15Plan(plan); err != nil {
		return formalGLMPhase19Context{}, err
	}
	if !formalGLMIsSHA256(preExecutionTokenSHA256) ||
		!formalGLMIsSHA256(globalMaterializationRoot) {
		return formalGLMPhase19Context{},
			fmt.Errorf("formal-glm: invalid Phase-1.9 pre-execution binding")
	}
	planDigest, err := formalGLMPhase15PlanDigest(plan)
	if err != nil {
		return formalGLMPhase19Context{}, err
	}
	ctx := formalGLMPhase19Context{
		Version:                   formalGLMPhase19ContextVersion,
		CapsuleSHA256:             plan.Kernel.CapsuleSHA256,
		Phase15PlanSHA256:         hex.EncodeToString(planDigest[:]),
		PreExecutionTokenSHA256:   preExecutionTokenSHA256,
		RunID:                     plan.RunID,
		PinsetSHA256:              plan.Kernel.PinsetSHA256,
		GlobalMaterializationRoot: globalMaterializationRoot,
		CustodianPeers:            append([]string(nil), plan.Kernel.CustodianPeers...),
		ComputePeers:              append([]string(nil), plan.Kernel.ComputePeers...),
		TotalCapacity:             plan.TotalCapacity,
		BlockCapacity:             plan.BlockCapacity,
		TotalBlocks:               plan.TotalBlocks,
		CoordinatesPerRow:         plan.Kernel.CoefficientCount + 3,
		RingBits:                  plan.RingBits,
		InputContract:             "phase18_authenticated_decrypted_fixed_shape_blocks_only_v1",
		ValidityContract:          "xor_two_recipient_then_exact_all_k_and_inside_gc_v1",
		ConsensusContract:         "xor_shared_sha256_reconstructed_and_equal_all_k_inside_gc_v2",
		OutputContract:            "sealed_full_tuple_additive_shares_plus_hidden_execution_bit_v1",
		ProductionReady:           false,
	}
	if err := formalGLMPhase19ValidateContext(plan, ctx); err != nil {
		return formalGLMPhase19Context{}, err
	}
	return ctx, nil
}

func formalGLMPhase19ValidateContext(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context) error {

	if err := validateFormalGLMPhase15Plan(plan); err != nil {
		return err
	}
	planDigest, err := formalGLMPhase15PlanDigest(plan)
	if err != nil {
		return err
	}
	if ctx.Version != formalGLMPhase19ContextVersion ||
		ctx.CapsuleSHA256 != plan.Kernel.CapsuleSHA256 ||
		ctx.Phase15PlanSHA256 != hex.EncodeToString(planDigest[:]) ||
		ctx.RunID != plan.RunID || ctx.PinsetSHA256 != plan.Kernel.PinsetSHA256 ||
		!formalGLMIsSHA256(ctx.PreExecutionTokenSHA256) ||
		!formalGLMIsSHA256(ctx.GlobalMaterializationRoot) ||
		!formalGLMPhase19SameStrings(ctx.CustodianPeers, plan.Kernel.CustodianPeers) ||
		!formalGLMPhase19SameStrings(ctx.ComputePeers, plan.Kernel.ComputePeers) ||
		ctx.TotalCapacity != plan.TotalCapacity ||
		ctx.BlockCapacity != plan.BlockCapacity || ctx.TotalBlocks != plan.TotalBlocks ||
		ctx.CoordinatesPerRow != plan.Kernel.CoefficientCount+3 ||
		ctx.RingBits != plan.RingBits ||
		ctx.InputContract != "phase18_authenticated_decrypted_fixed_shape_blocks_only_v1" ||
		ctx.ValidityContract != "xor_two_recipient_then_exact_all_k_and_inside_gc_v1" ||
		ctx.ConsensusContract != "xor_shared_sha256_reconstructed_and_equal_all_k_inside_gc_v2" ||
		ctx.OutputContract != "sealed_full_tuple_additive_shares_plus_hidden_execution_bit_v1" ||
		ctx.ProductionReady {
		return fmt.Errorf("formal-glm: invalid or type-confused Phase-1.9 context")
	}
	return nil
}

func formalGLMPhase19SameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func formalGLMPhase19Contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func formalGLMPhase19ContextDigest(ctx formalGLMPhase19Context) ([32]byte, error) {
	encoded, err := json.Marshal(ctx)
	if err != nil {
		return [32]byte{}, err
	}
	message := formalGLMPhase15AppendString(nil, formalGLMPhase19ContextDomain)
	message = formalGLMPhase15AppendBytes(message, encoded)
	return sha256.Sum256(message), nil
}

func formalGLMPhase19RowsInBlock(plan formalGLMPhase15Plan, block int) (int, error) {
	if block < 0 || block >= plan.TotalBlocks {
		return 0, fmt.Errorf("formal-glm: invalid Phase-1.9 block index")
	}
	rows := plan.BlockCapacity
	if remaining := plan.TotalCapacity - block*plan.BlockCapacity; remaining < rows {
		rows = remaining
	}
	return rows, nil
}

func formalGLMPhase19KeyValid(key [32]byte) bool {
	return !bytes.Equal(key[:], make([]byte, len(key)))
}

func formalGLMPhase19MAC(key [32]byte, domain string, message []byte) [32]byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(message)
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}

// formalGLMPhase19VerifiedSourceBlock is an internal trust-boundary type.  Its
// private fields are intentionally absent from JSON.  The seal prevents an
// in-process adapter from changing a verified block after authentication.
type formalGLMPhase19VerifiedSourceBlock struct {
	Version            string `json:"version"`
	ContextSHA256      string `json:"context_sha256"`
	Source             string `json:"source"`
	Recipient          string `json:"recipient"`
	BlockIndex         int    `json:"block_index"`
	RowsInBlock        int    `json:"rows_in_block"`
	PairCommitment     string `json:"pair_commitment"`
	BlockCommitment    string `json:"block_commitment"`
	coordinateShares   []*big.Int
	validityShares     []byte
	alignmentGateShare byte
	consensusShare     [32]byte
	seal               [32]byte
	verified           bool
}

func formalGLMPhase19SourceBlockMessage(plan formalGLMPhase15Plan,
	block formalGLMPhase19VerifiedSourceBlock) ([]byte, error) {

	encoded, err := formalGLMPhase15EncodeRecords(block.coordinateShares, plan.RingBits)
	if err != nil {
		return nil, err
	}
	message := formalGLMPhase15AppendString(nil, block.Version)
	for _, value := range []string{block.ContextSHA256, block.Source, block.Recipient,
		block.PairCommitment, block.BlockCommitment} {
		message = formalGLMPhase15AppendString(message, value)
	}
	message = formalGLMPhase15AppendUint64(message, uint64(block.BlockIndex))
	message = formalGLMPhase15AppendUint64(message, uint64(block.RowsInBlock))
	message = formalGLMPhase15AppendBytes(message, encoded)
	message = formalGLMPhase15AppendBytes(message, block.validityShares)
	message = append(message, block.alignmentGateShare)
	message = append(message, block.consensusShare[:]...)
	return message, nil
}

func formalGLMPhase19SealSourceBlock(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, source, recipient string, blockIndex int,
	coordinateShares []*big.Int, validityShares []byte, alignmentGateShare byte,
	consensusShare [32]byte, pairCommitment, blockCommitment string,
	backendKey [32]byte) (formalGLMPhase19VerifiedSourceBlock, error) {

	var zero formalGLMPhase19VerifiedSourceBlock
	if err := formalGLMPhase19ValidateContext(plan, ctx); err != nil {
		return zero, err
	}
	if !formalGLMPhase19KeyValid(backendKey) {
		return zero, fmt.Errorf("formal-glm: missing Phase-1.9 backend key")
	}
	if !formalGLMPhase19Contains(ctx.CustodianPeers, source) ||
		!formalGLMPhase19Contains(ctx.ComputePeers, recipient) ||
		!formalGLMIsSHA256(pairCommitment) || !formalGLMIsSHA256(blockCommitment) {
		return zero, fmt.Errorf("formal-glm: invalid Phase-1.9 source route or commitment")
	}
	rows, err := formalGLMPhase19RowsInBlock(plan, blockIndex)
	if err != nil {
		return zero, err
	}
	coordinateCount := plan.BlockCapacity * ctx.CoordinatesPerRow
	if len(coordinateShares) != coordinateCount || len(validityShares) != plan.BlockCapacity {
		return zero, fmt.Errorf("formal-glm: invalid fixed Phase-1.9 source shape")
	}
	copyCoordinates := make([]*big.Int, coordinateCount)
	modulus := exactGCModulus(plan.RingBits)
	for i, value := range coordinateShares {
		if value == nil || value.Sign() < 0 || value.Cmp(modulus) >= 0 {
			return zero, fmt.Errorf("formal-glm: non-canonical Phase-1.9 coordinate share")
		}
		copyCoordinates[i] = new(big.Int).Set(value)
	}
	ctxDigest, _ := formalGLMPhase19ContextDigest(ctx)
	result := formalGLMPhase19VerifiedSourceBlock{
		Version:            formalGLMPhase19BlockVersion,
		ContextSHA256:      hex.EncodeToString(ctxDigest[:]),
		Source:             source,
		Recipient:          recipient,
		BlockIndex:         blockIndex,
		RowsInBlock:        rows,
		PairCommitment:     pairCommitment,
		BlockCommitment:    blockCommitment,
		coordinateShares:   copyCoordinates,
		validityShares:     append([]byte(nil), validityShares...),
		alignmentGateShare: alignmentGateShare,
		consensusShare:     consensusShare,
		verified:           true,
	}
	message, err := formalGLMPhase19SourceBlockMessage(plan, result)
	if err != nil {
		return zero, err
	}
	result.seal = formalGLMPhase19MAC(backendKey, formalGLMPhase19BlockDomain, message)
	return result, nil
}

func formalGLMPhase19VerifySourceBlock(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, block formalGLMPhase19VerifiedSourceBlock,
	backendKey [32]byte) error {

	if !block.verified || block.Version != formalGLMPhase19BlockVersion ||
		!formalGLMPhase19KeyValid(backendKey) {
		return fmt.Errorf("formal-glm: unverified Phase-1.9 source block")
	}
	ctxDigest, err := formalGLMPhase19ContextDigest(ctx)
	if err != nil || block.ContextSHA256 != hex.EncodeToString(ctxDigest[:]) {
		return fmt.Errorf("formal-glm: Phase-1.9 source/context mismatch")
	}
	rows, err := formalGLMPhase19RowsInBlock(plan, block.BlockIndex)
	if err != nil || rows != block.RowsInBlock ||
		len(block.coordinateShares) != plan.BlockCapacity*ctx.CoordinatesPerRow ||
		len(block.validityShares) != plan.BlockCapacity ||
		!formalGLMPhase19Contains(ctx.CustodianPeers, block.Source) ||
		!formalGLMPhase19Contains(ctx.ComputePeers, block.Recipient) ||
		!formalGLMIsSHA256(block.PairCommitment) ||
		!formalGLMIsSHA256(block.BlockCommitment) {
		return fmt.Errorf("formal-glm: malformed Phase-1.9 source block")
	}
	message, err := formalGLMPhase19SourceBlockMessage(plan, block)
	if err != nil {
		return err
	}
	want := formalGLMPhase19MAC(backendKey, formalGLMPhase19BlockDomain, message)
	if !hmac.Equal(want[:], block.seal[:]) {
		return fmt.Errorf("formal-glm: Phase-1.9 source-block authentication failed")
	}
	return nil
}

type formalGLMPhase19ReplayLedger struct {
	mu      sync.Mutex
	entries map[string][32]byte
}

func newFormalGLMPhase19ReplayLedger() *formalGLMPhase19ReplayLedger {
	return &formalGLMPhase19ReplayLedger{entries: make(map[string][32]byte)}
}

func (ledger *formalGLMPhase19ReplayLedger) accept(slot string, digest [32]byte) error {
	if ledger == nil {
		return fmt.Errorf("formal-glm: Phase-1.9 replay ledger is required")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if previous, ok := ledger.entries[slot]; ok {
		if previous != digest {
			return fmt.Errorf("formal-glm: conflicting Phase-1.9 source replay")
		}
		return nil
	}
	ledger.entries[slot] = digest
	return nil
}

type formalGLMPhase19FanInReceipt struct {
	Version            string            `json:"version"`
	ContextSHA256      string            `json:"context_sha256"`
	Recipient          string            `json:"recipient"`
	BlockIndex         int               `json:"block_index"`
	PairCommitmentRoot string            `json:"pair_commitment_root"`
	FanInRoot          string            `json:"fan_in_root"`
	PairCommitments    map[string]string `json:"pair_commitments"`
	BlockCommitments   map[string]string `json:"block_commitments"`
	ReceiptMAC         string            `json:"receipt_mac"`
	ProductionReady    bool              `json:"production_ready"`
}

type formalGLMPhase19FanInResult struct {
	Receipt             formalGLMPhase19FanInReceipt
	coordinateShares    []*big.Int
	validityShares      [][]byte
	alignmentGateShares []byte
	consensusShares     [][32]byte
	seal                [32]byte
	verified            bool
}

func formalGLMPhase19CommitmentRoot(domain, contextSHA, recipient string,
	blockIndex int, commitments map[string]string, sources []string) (string, error) {

	if !formalGLMIsSHA256(contextSHA) || blockIndex < 0 || len(commitments) != len(sources) {
		return "", fmt.Errorf("formal-glm: invalid Phase-1.9 commitment root input")
	}
	message := formalGLMPhase15AppendString(nil, domain)
	message = formalGLMPhase15AppendString(message, contextSHA)
	message = formalGLMPhase15AppendString(message, recipient)
	message = formalGLMPhase15AppendUint64(message, uint64(blockIndex))
	for _, source := range sources {
		value := commitments[source]
		if !formalGLMIsSHA256(value) {
			return "", fmt.Errorf("formal-glm: incomplete Phase-1.9 commitment set")
		}
		message = formalGLMPhase15AppendString(message, source)
		message = formalGLMPhase15AppendString(message, value)
	}
	digest := sha256.Sum256(message)
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMPhase19FanInRoot(receipt formalGLMPhase19FanInReceipt,
	sources []string) (string, error) {

	message := formalGLMPhase15AppendString(nil, formalGLMPhase19FanInDomain)
	for _, value := range []string{receipt.ContextSHA256, receipt.Recipient,
		receipt.PairCommitmentRoot} {
		message = formalGLMPhase15AppendString(message, value)
	}
	message = formalGLMPhase15AppendUint64(message, uint64(receipt.BlockIndex))
	for _, source := range sources {
		pair, block := receipt.PairCommitments[source], receipt.BlockCommitments[source]
		if !formalGLMIsSHA256(pair) || !formalGLMIsSHA256(block) {
			return "", fmt.Errorf("formal-glm: incomplete Phase-1.9 fan-in commitment")
		}
		message = formalGLMPhase15AppendString(message, source)
		message = formalGLMPhase15AppendString(message, pair)
		message = formalGLMPhase15AppendString(message, block)
	}
	digest := sha256.Sum256(message)
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMPhase19FanInReceiptMessage(receipt formalGLMPhase19FanInReceipt,
	sources []string) ([]byte, error) {

	if receipt.Version != formalGLMPhase19FanInVersion || receipt.ProductionReady {
		return nil, fmt.Errorf("formal-glm: invalid Phase-1.9 fan-in receipt")
	}
	message := formalGLMPhase15AppendString(nil, receipt.Version)
	for _, value := range []string{receipt.ContextSHA256, receipt.Recipient,
		receipt.PairCommitmentRoot, receipt.FanInRoot} {
		message = formalGLMPhase15AppendString(message, value)
	}
	message = formalGLMPhase15AppendUint64(message, uint64(receipt.BlockIndex))
	for _, source := range sources {
		message = formalGLMPhase15AppendString(message, source)
		message = formalGLMPhase15AppendString(message, receipt.PairCommitments[source])
		message = formalGLMPhase15AppendString(message, receipt.BlockCommitments[source])
	}
	return message, nil
}

func formalGLMPhase19PrivateFanInMessage(plan formalGLMPhase15Plan,
	result formalGLMPhase19FanInResult) ([]byte, error) {

	message, err := formalGLMPhase19FanInReceiptMessage(
		result.Receipt, plan.Kernel.CustodianPeers)
	if err != nil {
		return nil, err
	}
	encoded, err := formalGLMPhase15EncodeRecords(result.coordinateShares, plan.RingBits)
	if err != nil {
		return nil, err
	}
	message = formalGLMPhase15AppendBytes(message, encoded)
	for i := range result.validityShares {
		message = formalGLMPhase15AppendBytes(message, result.validityShares[i])
		message = append(message, result.alignmentGateShares[i])
		message = append(message, result.consensusShares[i][:]...)
	}
	return message, nil
}

func formalGLMPhase19FanIn(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, recipient string, blockIndex int,
	blocks []formalGLMPhase19VerifiedSourceBlock,
	ledger *formalGLMPhase19ReplayLedger, backendKey [32]byte) (
	formalGLMPhase19FanInResult, error) {

	var zero formalGLMPhase19FanInResult
	if err := formalGLMPhase19ValidateContext(plan, ctx); err != nil {
		return zero, err
	}
	if !formalGLMPhase19KeyValid(backendKey) ||
		!formalGLMPhase19Contains(ctx.ComputePeers, recipient) ||
		len(blocks) != len(ctx.CustodianPeers) {
		return zero, fmt.Errorf("formal-glm: incomplete or invalid Phase-1.9 fan-in")
	}
	if _, err := formalGLMPhase19RowsInBlock(plan, blockIndex); err != nil {
		return zero, err
	}
	ctxDigest, _ := formalGLMPhase19ContextDigest(ctx)
	ctxHash := hex.EncodeToString(ctxDigest[:])
	coordinateCount := plan.BlockCapacity * ctx.CoordinatesPerRow
	result := formalGLMPhase19FanInResult{
		Receipt: formalGLMPhase19FanInReceipt{
			Version: formalGLMPhase19FanInVersion, ContextSHA256: ctxHash,
			Recipient: recipient, BlockIndex: blockIndex,
			PairCommitments:  make(map[string]string, len(ctx.CustodianPeers)),
			BlockCommitments: make(map[string]string, len(ctx.CustodianPeers)),
			ProductionReady:  false,
		},
		coordinateShares:    make([]*big.Int, coordinateCount),
		validityShares:      make([][]byte, len(ctx.CustodianPeers)),
		alignmentGateShares: make([]byte, len(ctx.CustodianPeers)),
		consensusShares:     make([][32]byte, len(ctx.CustodianPeers)),
	}
	for i := range result.coordinateShares {
		result.coordinateShares[i] = new(big.Int)
	}
	seen := make(map[string]formalGLMPhase19VerifiedSourceBlock, len(blocks))
	for _, block := range blocks {
		if err := formalGLMPhase19VerifySourceBlock(plan, ctx, block, backendKey); err != nil {
			return zero, err
		}
		if block.Recipient != recipient || block.BlockIndex != blockIndex ||
			seen[block.Source].verified {
			return zero, fmt.Errorf("formal-glm: duplicate or misrouted Phase-1.9 source block")
		}
		seen[block.Source] = block
	}
	modulus := exactGCModulus(plan.RingBits)
	for sourceIndex, source := range ctx.CustodianPeers {
		block, ok := seen[source]
		if !ok {
			return zero, fmt.Errorf("formal-glm: missing Phase-1.9 custodian lane")
		}
		slot := fmt.Sprintf("%s|%s|%d|%s|%s", ctxHash, recipient,
			blockIndex, source, formalGLMPhase19BlockVersion)
		if err := ledger.accept(slot, block.seal); err != nil {
			return zero, err
		}
		for i, share := range block.coordinateShares {
			result.coordinateShares[i].Add(result.coordinateShares[i], share)
			result.coordinateShares[i].Mod(result.coordinateShares[i], modulus)
		}
		result.validityShares[sourceIndex] = append([]byte(nil), block.validityShares...)
		result.alignmentGateShares[sourceIndex] = block.alignmentGateShare
		result.consensusShares[sourceIndex] = block.consensusShare
		result.Receipt.PairCommitments[source] = block.PairCommitment
		result.Receipt.BlockCommitments[source] = block.BlockCommitment
	}
	var err error
	result.Receipt.PairCommitmentRoot, err = formalGLMPhase19CommitmentRoot(
		formalGLMPhase19PairDomain+"/commitments", ctxHash, "", blockIndex,
		result.Receipt.PairCommitments, ctx.CustodianPeers)
	if err != nil {
		return zero, err
	}
	result.Receipt.FanInRoot, err = formalGLMPhase19FanInRoot(
		result.Receipt, ctx.CustodianPeers)
	if err != nil {
		return zero, err
	}
	receiptMessage, err := formalGLMPhase19FanInReceiptMessage(
		result.Receipt, ctx.CustodianPeers)
	if err != nil {
		return zero, err
	}
	receiptMAC := formalGLMPhase19MAC(backendKey,
		formalGLMPhase19FanInDomain+"/receipt", receiptMessage)
	result.Receipt.ReceiptMAC = hex.EncodeToString(receiptMAC[:])
	privateMessage, err := formalGLMPhase19PrivateFanInMessage(plan, result)
	if err != nil {
		return zero, err
	}
	result.seal = formalGLMPhase19MAC(backendKey,
		formalGLMPhase19FanInDomain+"/private", privateMessage)
	result.verified = true
	return result, nil
}

func formalGLMPhase19VerifyFanInReceipt(ctx formalGLMPhase19Context,
	receipt formalGLMPhase19FanInReceipt, backendKey [32]byte) error {

	ctxDigest, err := formalGLMPhase19ContextDigest(ctx)
	if err != nil || receipt.ContextSHA256 != hex.EncodeToString(ctxDigest[:]) ||
		receipt.Version != formalGLMPhase19FanInVersion ||
		!formalGLMPhase19Contains(ctx.ComputePeers, receipt.Recipient) ||
		receipt.BlockIndex < 0 || receipt.BlockIndex >= ctx.TotalBlocks ||
		len(receipt.PairCommitments) != len(ctx.CustodianPeers) ||
		len(receipt.BlockCommitments) != len(ctx.CustodianPeers) ||
		receipt.ProductionReady || !formalGLMPhase19KeyValid(backendKey) {
		return fmt.Errorf("formal-glm: invalid Phase-1.9 fan-in receipt")
	}
	wantPairRoot, err := formalGLMPhase19CommitmentRoot(
		formalGLMPhase19PairDomain+"/commitments", receipt.ContextSHA256, "",
		receipt.BlockIndex, receipt.PairCommitments, ctx.CustodianPeers)
	if err != nil || receipt.PairCommitmentRoot != wantPairRoot {
		return fmt.Errorf("formal-glm: invalid Phase-1.9 pair-commitment root")
	}
	wantRoot, err := formalGLMPhase19FanInRoot(receipt, ctx.CustodianPeers)
	if err != nil || receipt.FanInRoot != wantRoot {
		return fmt.Errorf("formal-glm: invalid Phase-1.9 fan-in root")
	}
	message, err := formalGLMPhase19FanInReceiptMessage(receipt, ctx.CustodianPeers)
	if err != nil {
		return err
	}
	wantMAC := formalGLMPhase19MAC(backendKey,
		formalGLMPhase19FanInDomain+"/receipt", message)
	gotMAC, decodeErr := hex.DecodeString(receipt.ReceiptMAC)
	if decodeErr != nil || !hmac.Equal(wantMAC[:], gotMAC) {
		return fmt.Errorf("formal-glm: Phase-1.9 fan-in receipt authentication failed")
	}
	return nil
}

func formalGLMPhase19VerifyFanIn(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, result formalGLMPhase19FanInResult,
	backendKey [32]byte) error {

	if !result.verified || len(result.coordinateShares) !=
		plan.BlockCapacity*ctx.CoordinatesPerRow ||
		len(result.validityShares) != len(ctx.CustodianPeers) ||
		len(result.alignmentGateShares) != len(ctx.CustodianPeers) ||
		len(result.consensusShares) != len(ctx.CustodianPeers) {
		return fmt.Errorf("formal-glm: unverified Phase-1.9 fan-in")
	}
	if err := formalGLMPhase19VerifyFanInReceipt(ctx, result.Receipt, backendKey); err != nil {
		return err
	}
	for _, lane := range result.validityShares {
		if len(lane) != plan.BlockCapacity {
			return fmt.Errorf("formal-glm: invalid Phase-1.9 validity lane shape")
		}
	}
	message, err := formalGLMPhase19PrivateFanInMessage(plan, result)
	if err != nil {
		return err
	}
	want := formalGLMPhase19MAC(backendKey,
		formalGLMPhase19FanInDomain+"/private", message)
	if !hmac.Equal(want[:], result.seal[:]) {
		return fmt.Errorf("formal-glm: Phase-1.9 private fan-in authentication failed")
	}
	return nil
}

type formalGLMPhase19PairedFanIn struct {
	Version            string            `json:"version"`
	ContextSHA256      string            `json:"context_sha256"`
	BlockIndex         int               `json:"block_index"`
	GarblerFanInRoot   string            `json:"garbler_fan_in_root"`
	EvaluatorFanInRoot string            `json:"evaluator_fan_in_root"`
	PairCommitmentRoot string            `json:"pair_commitment_root"`
	PairCommitments    map[string]string `json:"pair_commitments"`
	PairRoot           string            `json:"pair_root"`
	ProductionReady    bool              `json:"production_ready"`
	seal               [32]byte
	verified           bool
}

func formalGLMPhase19PairMessage(pair formalGLMPhase19PairedFanIn,
	sources []string) ([]byte, error) {
	if pair.Version != formalGLMPhase19PairVersion || pair.ProductionReady ||
		!formalGLMIsSHA256(pair.ContextSHA256) ||
		!formalGLMIsSHA256(pair.GarblerFanInRoot) ||
		!formalGLMIsSHA256(pair.EvaluatorFanInRoot) ||
		!formalGLMIsSHA256(pair.PairCommitmentRoot) {
		return nil, fmt.Errorf("formal-glm: invalid paired Phase-1.9 fan-in")
	}
	message := formalGLMPhase15AppendString(nil, pair.Version)
	for _, value := range []string{pair.ContextSHA256, pair.GarblerFanInRoot,
		pair.EvaluatorFanInRoot, pair.PairCommitmentRoot} {
		message = formalGLMPhase15AppendString(message, value)
	}
	message = formalGLMPhase15AppendUint64(message, uint64(pair.BlockIndex))
	for _, source := range sources {
		commitment := pair.PairCommitments[source]
		if !formalGLMIsSHA256(commitment) {
			return nil, fmt.Errorf("formal-glm: incomplete paired Phase-1.9 fan-in")
		}
		message = formalGLMPhase15AppendString(message, source)
		message = formalGLMPhase15AppendString(message, commitment)
	}
	return message, nil
}

func formalGLMPhase19PairFanIn(ctx formalGLMPhase19Context,
	left, right formalGLMPhase19FanInReceipt, backendKey [32]byte) (
	formalGLMPhase19PairedFanIn, error) {

	var zero formalGLMPhase19PairedFanIn
	if err := formalGLMPhase19VerifyFanInReceipt(ctx, left, backendKey); err != nil {
		return zero, err
	}
	if err := formalGLMPhase19VerifyFanInReceipt(ctx, right, backendKey); err != nil {
		return zero, err
	}
	if left.Recipient != ctx.ComputePeers[0] || right.Recipient != ctx.ComputePeers[1] ||
		left.BlockIndex != right.BlockIndex ||
		left.ContextSHA256 != right.ContextSHA256 ||
		left.PairCommitmentRoot != right.PairCommitmentRoot {
		return zero, fmt.Errorf("formal-glm: swapped or mismatched Phase-1.9 fan-in pair")
	}
	commitments := make(map[string]string, len(ctx.CustodianPeers))
	for _, source := range ctx.CustodianPeers {
		if left.PairCommitments[source] == "" ||
			left.PairCommitments[source] != right.PairCommitments[source] {
			return zero, fmt.Errorf("formal-glm: Phase-1.9 custodian pair equivocation")
		}
		commitments[source] = left.PairCommitments[source]
	}
	result := formalGLMPhase19PairedFanIn{
		Version:            formalGLMPhase19PairVersion,
		ContextSHA256:      left.ContextSHA256,
		BlockIndex:         left.BlockIndex,
		GarblerFanInRoot:   left.FanInRoot,
		EvaluatorFanInRoot: right.FanInRoot,
		PairCommitmentRoot: left.PairCommitmentRoot,
		PairCommitments:    commitments,
		ProductionReady:    false,
	}
	message, err := formalGLMPhase19PairMessage(result, ctx.CustodianPeers)
	if err != nil {
		return zero, err
	}
	digest := sha256.Sum256(append([]byte(formalGLMPhase19PairDomain+"|"), message...))
	result.PairRoot = hex.EncodeToString(digest[:])
	result.seal = formalGLMPhase19MAC(backendKey,
		formalGLMPhase19PairDomain+"/seal", append(message, digest[:]...))
	result.verified = true
	return result, nil
}

func formalGLMPhase19VerifyPair(ctx formalGLMPhase19Context,
	pair formalGLMPhase19PairedFanIn, backendKey [32]byte) error {

	ctxDigest, err := formalGLMPhase19ContextDigest(ctx)
	if err != nil || !pair.verified || pair.ContextSHA256 != hex.EncodeToString(ctxDigest[:]) ||
		pair.BlockIndex < 0 || pair.BlockIndex >= ctx.TotalBlocks ||
		len(pair.PairCommitments) != len(ctx.CustodianPeers) ||
		!formalGLMIsSHA256(pair.PairRoot) || !formalGLMPhase19KeyValid(backendKey) {
		return fmt.Errorf("formal-glm: unverified paired Phase-1.9 fan-in")
	}
	message, err := formalGLMPhase19PairMessage(pair, ctx.CustodianPeers)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(append([]byte(formalGLMPhase19PairDomain+"|"), message...))
	wantSeal := formalGLMPhase19MAC(backendKey,
		formalGLMPhase19PairDomain+"/seal", append(message, digest[:]...))
	if pair.PairRoot != hex.EncodeToString(digest[:]) ||
		!hmac.Equal(wantSeal[:], pair.seal[:]) {
		return fmt.Errorf("formal-glm: paired Phase-1.9 fan-in authentication failed")
	}
	return nil
}

func formalGLMPhase19VerifyLocalPair(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, pair formalGLMPhase19PairedFanIn,
	local formalGLMPhase19FanInResult, backendKey [32]byte) error {

	if err := formalGLMPhase19VerifyPair(ctx, pair, backendKey); err != nil {
		return err
	}
	if err := formalGLMPhase19VerifyFanIn(plan, ctx, local, backendKey); err != nil {
		return err
	}
	want := pair.EvaluatorFanInRoot
	if local.Receipt.Recipient == ctx.ComputePeers[0] {
		want = pair.GarblerFanInRoot
	}
	if local.Receipt.BlockIndex != pair.BlockIndex || local.Receipt.FanInRoot != want ||
		local.Receipt.PairCommitmentRoot != pair.PairCommitmentRoot {
		return fmt.Errorf("formal-glm: local Phase-1.9 fan-in is not in the paired receipt")
	}
	return nil
}

type formalGLMPhase19InputLayout struct {
	CoordinateCount int
	ValidityStart   int
	GateStart       int
	ConsensusStart  int
	LocalCount      int
	MaskStart       int
	GarblerCount    int
	EvaluatorCount  int
	OutputCount     int
}

func formalGLMPhase19Layout(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context) (formalGLMPhase19InputLayout, error) {

	if err := formalGLMPhase19ValidateContext(plan, ctx); err != nil {
		return formalGLMPhase19InputLayout{}, err
	}
	k := len(ctx.CustodianPeers)
	n := plan.BlockCapacity * ctx.CoordinatesPerRow
	validityStart := n
	gateStart := validityStart + k*plan.BlockCapacity
	consensusStart := gateStart + k
	local := consensusStart + 4*k
	return formalGLMPhase19InputLayout{
		CoordinateCount: n,
		ValidityStart:   validityStart,
		GateStart:       gateStart,
		ConsensusStart:  consensusStart,
		LocalCount:      local,
		MaskStart:       local,
		GarblerCount:    local + n + 1,
		EvaluatorCount:  local,
		OutputCount:     n + 1,
	}, nil
}

func formalGLMPhase19ConsensusLimbs(digest [32]byte) []*big.Int {
	result := make([]*big.Int, 4)
	for i := range result {
		result[i] = new(big.Int).SetUint64(binary.BigEndian.Uint64(digest[8*i : 8*(i+1)]))
	}
	return result
}

func formalGLMPhase19LocalInputValues(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, pair formalGLMPhase19PairedFanIn,
	local formalGLMPhase19FanInResult, backendKey [32]byte) ([]*big.Int, error) {

	if err := formalGLMPhase19VerifyLocalPair(plan, ctx, pair, local, backendKey); err != nil {
		return nil, err
	}
	layout, _ := formalGLMPhase19Layout(plan, ctx)
	values := make([]*big.Int, 0, layout.LocalCount)
	for _, value := range local.coordinateShares {
		values = append(values, new(big.Int).Set(value))
	}
	for source := range ctx.CustodianPeers {
		for _, value := range local.validityShares[source] {
			values = append(values, new(big.Int).SetUint64(uint64(value)))
		}
	}
	for _, value := range local.alignmentGateShares {
		values = append(values, new(big.Int).SetUint64(uint64(value)))
	}
	for _, digest := range local.consensusShares {
		values = append(values, formalGLMPhase19ConsensusLimbs(digest)...)
	}
	if len(values) != layout.LocalCount {
		return nil, fmt.Errorf("formal-glm: internal Phase-1.9 input-layout mismatch")
	}
	return values, nil
}

func formalGLMPhase19GarblerInputValues(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, pair formalGLMPhase19PairedFanIn,
	local formalGLMPhase19FanInResult, tupleMasks []*big.Int,
	executionMask byte, backendKey [32]byte) ([]*big.Int, error) {

	base, err := formalGLMPhase19LocalInputValues(plan, ctx, pair, local, backendKey)
	if err != nil {
		return nil, err
	}
	layout, _ := formalGLMPhase19Layout(plan, ctx)
	if local.Receipt.Recipient != ctx.ComputePeers[0] ||
		len(tupleMasks) != layout.CoordinateCount || executionMask > 1 {
		return nil, fmt.Errorf("formal-glm: invalid Phase-1.9 garbler masks")
	}
	modulus := exactGCModulus(plan.RingBits)
	values := append([]*big.Int(nil), base...)
	for _, mask := range tupleMasks {
		if mask == nil || mask.Sign() < 0 || mask.Cmp(modulus) >= 0 {
			return nil, fmt.Errorf("formal-glm: invalid Phase-1.9 tuple mask")
		}
		values = append(values, new(big.Int).Set(mask))
	}
	values = append(values, new(big.Int).SetUint64(uint64(executionMask)))
	if len(values) != layout.GarblerCount {
		return nil, fmt.Errorf("formal-glm: internal Phase-1.9 garbler-layout mismatch")
	}
	return values, nil
}

func formalGLMPhase19CircuitSource(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context) (string, error) {

	parsed, err := formalGLMPhase15ValidateShape(plan)
	if err != nil {
		return "", err
	}
	if err := formalGLMPhase19ValidateContext(plan, ctx); err != nil {
		return "", err
	}
	layout, _ := formalGLMPhase19Layout(plan, ctx)
	rowsInBlock, err := formalGLMPhase19RowsInBlock(plan, 0)
	if err != nil {
		return "", err
	}
	// Every block except possibly the final block has the same public shape.
	// The final block's public padding is handled by a block-specific constant
	// below, so the caller substitutes the actual block before compilation.
	_ = rowsInBlock
	preamble, uintType, mask, constant := formalGLMPhase15CircuitPreamble(
		parsed, plan.RingBits)
	fracMask := new(big.Int).Sub(new(big.Int).Set(parsed.scale), big.NewInt(1)).Text(16)
	k, block, p := len(ctx.CustodianPeers), plan.BlockCapacity,
		plan.Kernel.CoefficientCount
	var source strings.Builder
	source.WriteString(preamble)
	fmt.Fprintf(&source, "func main(g [%d]%s, e [%d]%s) [%d]%s {\n",
		layout.GarblerCount, uintType, layout.EvaluatorCount, uintType,
		layout.OutputCount, uintType)
	source.WriteString("\tglobalValid := true\n")
	for custodian := 0; custodian < k; custodian++ {
		index := layout.GateStart + custodian
		fmt.Fprintf(&source, "\tgg%d := g[%d]\n\teg%d := e[%d]\n",
			custodian, index, custodian, index)
		fmt.Fprintf(&source,
			"\tgateSharesValid%d := (gg%d == %s(0) || gg%d == %s(1)) && (eg%d == %s(0) || eg%d == %s(1))\n",
			custodian, custodian, uintType, custodian, uintType,
			custodian, uintType, custodian, uintType)
		fmt.Fprintf(&source, "\tgateAccepted%d := gg%d != eg%d\n",
			custodian, custodian, custodian)
		fmt.Fprintf(&source,
			"\tglobalValid = globalValid && gateSharesValid%d && gateAccepted%d\n",
			custodian, custodian)
	}
	source.WriteString("\tconsensusNonZero := false\n")
	for custodian := 0; custodian < k; custodian++ {
		for limb := 0; limb < 4; limb++ {
			index := layout.ConsensusStart + 4*custodian + limb
			fmt.Fprintf(&source, "\tcg%d_%d := g[%d]\n\tce%d_%d := e[%d]\n",
				custodian, limb, index, custodian, limb, index)
			fmt.Fprintf(&source, "\tc%d_%d := cg%d_%d ^ ce%d_%d\n",
				custodian, limb, custodian, limb, custodian, limb)
			if custodian > 0 {
				fmt.Fprintf(&source,
					"\tglobalValid = globalValid && c%d_%d == c0_%d\n",
					custodian, limb, limb)
			}
			fmt.Fprintf(&source,
				"\tconsensusNonZero = consensusNonZero || c%d_%d != %s(0)\n",
				custodian, limb, uintType)
		}
	}
	source.WriteString("\tglobalValid = globalValid && consensusNonZero\n")
	source.WriteString("\tanyActive := false\n")
	for row := 0; row < block; row++ {
		base := row * (p + 3)
		for coordinate := 0; coordinate < p+3; coordinate++ {
			index := base + coordinate
			fmt.Fprintf(&source,
				"\tv%d_%d := (g[%d] + e[%d]) & %s(0x%s)\n",
				row, coordinate, index, index, uintType, mask)
		}
		fmt.Fprintf(&source, "\trowValid%d := globalValid\n", row)
		for custodian := 0; custodian < k; custodian++ {
			index := layout.ValidityStart + custodian*block + row
			fmt.Fprintf(&source, "\tvg%d_%d := g[%d]\n\tve%d_%d := e[%d]\n",
				row, custodian, index, row, custodian, index)
			fmt.Fprintf(&source,
				"\tvaliditySharesValid%d_%d := (vg%d_%d == %s(0) || vg%d_%d == %s(1)) && (ve%d_%d == %s(0) || ve%d_%d == %s(1))\n",
				row, custodian, row, custodian, uintType, row, custodian, uintType,
				row, custodian, uintType, row, custodian, uintType)
			fmt.Fprintf(&source, "\tvalidityLane%d_%d := vg%d_%d != ve%d_%d\n",
				row, custodian, row, custodian, row, custodian)
			fmt.Fprintf(&source,
				"\trowValid%d = rowValid%d && validitySharesValid%d_%d && validityLane%d_%d\n",
				row, row, row, custodian, row, custodian)
		}
		fmt.Fprintf(&source,
			"\trowValid%d = rowValid%d && !signedLess(v%d_0, %s(0)) && !signedLess(%s, v%d_0)\n",
			row, row, row, uintType, constant(parsed.weightUpper), row)
		for coefficient := 0; coefficient < p; coefficient++ {
			coordinate := 1 + coefficient
			if formalGLMIndicatorKind(plan.Kernel.XKind[coefficient]) {
				fmt.Fprintf(&source,
					"\trowValid%d = rowValid%d && (v%d_%d == %s(0) || v%d_%d == %s)\n",
					row, row, row, coordinate, uintType, row, coordinate,
					constant(parsed.scale))
			} else {
				fmt.Fprintf(&source,
					"\trowValid%d = rowValid%d && !signedLess(v%d_%d, %s) && !signedLess(%s, v%d_%d)\n",
					row, row, row, coordinate, constant(parsed.xLower[coefficient]),
					constant(parsed.xUpper[coefficient]), row, coordinate)
			}
		}
		yCoordinate, offsetCoordinate := p+1, p+2
		if plan.Kernel.Family == "binomial" {
			fmt.Fprintf(&source,
				"\trowValid%d = rowValid%d && (v%d_%d == %s(0) || v%d_%d == %s)\n",
				row, row, row, yCoordinate, uintType, row, yCoordinate,
				constant(parsed.scale))
		} else {
			fmt.Fprintf(&source,
				"\trowValid%d = rowValid%d && !signedLess(v%d_%d, %s(0)) && !signedLess(%s, v%d_%d) && (v%d_%d & %s(0x%s)) == %s(0)\n",
				row, row, row, yCoordinate, uintType, constant(parsed.outcomeUpper),
				row, yCoordinate, row, yCoordinate, uintType, fracMask, uintType)
		}
		fmt.Fprintf(&source,
			"\trowValid%d = rowValid%d && !signedLess(v%d_%d, %s) && !signedLess(%s, v%d_%d)\n",
			row, row, row, offsetCoordinate, constant(parsed.offsetLower),
			constant(parsed.offsetUpper), row, offsetCoordinate)
		// A block-specific public padding guard is injected by the specialised
		// source builder below.  This marker is replaced before compilation.
		fmt.Fprintf(&source, "\t/*PHASE19_PADDING_ROW_%d*/\n", row)
		fmt.Fprintf(&source, "\tif rowValid%d && v%d_0 != %s(0) { anyActive = true }\n",
			row, row, uintType)
		fmt.Fprintf(&source, "\tif !rowValid%d {\n", row)
		for coordinate := 0; coordinate < p+3; coordinate++ {
			fmt.Fprintf(&source, "\t\tv%d_%d = %s(0)\n", row, coordinate, uintType)
		}
		source.WriteString("\t}\n")
	}
	for row := 0; row < block; row++ {
		base := row * (p + 3)
		for coordinate := 0; coordinate < p+3; coordinate++ {
			index := base + coordinate
			fmt.Fprintf(&source,
				"\tout%d := (v%d_%d - g[%d]) & %s(0x%s)\n",
				index, row, coordinate, layout.MaskStart+index, uintType, mask)
		}
	}
	fmt.Fprintf(&source, "\texecutionMask := g[%d]\n", layout.MaskStart+layout.CoordinateCount)
	fmt.Fprintf(&source,
		"\texecutionMaskValid := executionMask == %s(0) || executionMask == %s(1)\n",
		uintType, uintType)
	source.WriteString("\texecutionValid := globalValid && anyActive\n")
	fmt.Fprintf(&source, "\texecutionShare := %s(0)\n", uintType)
	source.WriteString("\tif executionMaskValid {\n")
	source.WriteString("\t\texecutionShare = executionMask\n")
	fmt.Fprintf(&source, "\t\tif executionValid { executionShare = %s(1) - executionMask }\n",
		uintType)
	source.WriteString("\t}\n")
	fmt.Fprintf(&source, "\tvar out [%d]%s\n", layout.OutputCount, uintType)
	for i := 0; i < layout.CoordinateCount; i++ {
		fmt.Fprintf(&source, "\tout[%d] = out%d\n", i, i)
	}
	fmt.Fprintf(&source, "\tout[%d] = executionShare\n", layout.CoordinateCount)
	source.WriteString("\treturn out\n}\n")
	return source.String(), nil
}

func formalGLMPhase19BlockCircuitSource(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, blockIndex int) (string, error) {

	source, err := formalGLMPhase19CircuitSource(plan, ctx)
	if err != nil {
		return "", err
	}
	rows, err := formalGLMPhase19RowsInBlock(plan, blockIndex)
	if err != nil {
		return "", err
	}
	for row := 0; row < plan.BlockCapacity; row++ {
		marker := fmt.Sprintf("/*PHASE19_PADDING_ROW_%d*/", row)
		replacement := ""
		if row >= rows {
			replacement = fmt.Sprintf("rowValid%d = false", row)
		}
		if strings.Count(source, marker) != 1 {
			return "", fmt.Errorf("formal-glm: invalid Phase-1.9 padding marker")
		}
		source = strings.Replace(source, marker, replacement, 1)
	}
	return source, nil
}

func compileFormalGLMPhase19Block(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, blockIndex int) (*circuit.Circuit, error) {

	source, err := formalGLMPhase19BlockCircuitSource(plan, ctx, blockIndex)
	if err != nil {
		return nil, err
	}
	circ, err := compileFormalGLMPhase15Source(source, "Phase-1.9 protected fan-in")
	if err != nil {
		return nil, err
	}
	layout, _ := formalGLMPhase19Layout(plan, ctx)
	typeBits := exactGCTypeBits(plan.RingBits)
	if len(circ.Inputs) != 2 || len(circ.Outputs) != 1 ||
		int(circ.Inputs[0].Type.Bits) != layout.GarblerCount*typeBits ||
		int(circ.Inputs[1].Type.Bits) != layout.EvaluatorCount*typeBits ||
		circ.Outputs.Size() != layout.OutputCount*typeBits {
		return nil, fmt.Errorf("formal-glm: compiler produced invalid Phase-1.9 arity")
	}
	return circ, nil
}

func formalGLMPhase19BlockPurpose(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, pair formalGLMPhase19PairedFanIn,
	attemptID [32]byte) (string, error) {

	if err := formalGLMPhase19ValidateContext(plan, ctx); err != nil {
		return "", err
	}
	if !pair.verified || !formalGLMIsSHA256(pair.PairRoot) {
		return "", fmt.Errorf("formal-glm: unverified Phase-1.9 pair purpose")
	}
	source, err := formalGLMPhase19BlockCircuitSource(plan, ctx, pair.BlockIndex)
	if err != nil {
		return "", err
	}
	circuitDigest := sha256.Sum256([]byte(source))
	ctxDigest, _ := formalGLMPhase19ContextDigest(ctx)
	return fmt.Sprintf("formal-glm/phase19-v2/%s/block/%d/pair/%s/circuit/%s/attempt/%s",
		hex.EncodeToString(ctxDigest[:]), pair.BlockIndex, pair.PairRoot,
		hex.EncodeToString(circuitDigest[:]), hex.EncodeToString(attemptID[:])), nil
}

func formalGLMPhase19BlockSession(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, pair formalGLMPhase19PairedFanIn,
	attemptID, masterKey [32]byte) (exactGCSession, error) {

	if err := formalGLMPhase19VerifyPair(ctx, pair, masterKey); err != nil {
		return exactGCSession{}, err
	}
	layout, err := formalGLMPhase19Layout(plan, ctx)
	if err != nil {
		return exactGCSession{}, err
	}
	purpose, err := formalGLMPhase19BlockPurpose(plan, ctx, pair, attemptID)
	if err != nil {
		return exactGCSession{}, err
	}
	session := exactGCSession{
		SessionID: attemptID, MasterKey: masterKey,
		GarblerID: ctx.ComputePeers[0], EvaluatorID: ctx.ComputePeers[1],
		Purpose: purpose,
		Spec: exactGCCircuitSpec{
			Operation: exactGCFormalGLMOneIteration,
			RingBits:  plan.RingBits,
			FracBits:  plan.Kernel.FracBits,
			VectorLen: layout.LocalCount + layout.CoordinateCount + 1,
		},
	}
	if err := session.validate(); err != nil {
		return exactGCSession{}, err
	}
	return session, nil
}

func formalGLMPhase19ValidateBlockSession(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, pair formalGLMPhase19PairedFanIn,
	session exactGCSession) error {

	want, err := formalGLMPhase19BlockSession(
		plan, ctx, pair, session.SessionID, session.MasterKey)
	if err != nil {
		return err
	}
	if session.GarblerID != want.GarblerID ||
		session.EvaluatorID != want.EvaluatorID || session.Purpose != want.Purpose ||
		session.Spec.Operation != want.Spec.Operation ||
		session.Spec.RingBits != want.Spec.RingBits ||
		session.Spec.FracBits != want.Spec.FracBits ||
		session.Spec.VectorLen != want.Spec.VectorLen {
		return fmt.Errorf("formal-glm: Phase-1.9 block/session binding mismatch")
	}
	return nil
}

func formalGLMPhase19RandomExecutionMask() (byte, error) {
	var value [1]byte
	if _, err := io.ReadFull(crand.Reader, value[:]); err != nil {
		return 0, fmt.Errorf("formal-glm: generate Phase-1.9 execution mask: %w", err)
	}
	return value[0] & 1, nil
}

func formalGLMPhase19DecodeCircuitOutput(packed *big.Int,
	coordinateCount, ringBits int) ([]*big.Int, byte, error) {

	if packed == nil || packed.Sign() < 0 || coordinateCount < 1 {
		return nil, 0, fmt.Errorf("formal-glm: invalid Phase-1.9 circuit output")
	}
	stride := exactGCTypeBits(ringBits)
	mask := exactGCMask(ringBits)
	shares := make([]*big.Int, coordinateCount)
	for i := range shares {
		shares[i] = new(big.Int).Rsh(new(big.Int).Set(packed), uint(i*stride))
		shares[i].And(shares[i], mask)
	}
	execution := new(big.Int).Rsh(new(big.Int).Set(packed),
		uint(coordinateCount*stride))
	execution.And(execution, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(stride)), big.NewInt(1)))
	if execution.Sign() < 0 || execution.Cmp(big.NewInt(1)) > 0 {
		return nil, 0, fmt.Errorf("formal-glm: circuit emitted invalid hidden execution share")
	}
	return shares, byte(execution.Uint64()), nil
}

type formalGLMPhase19MaskedBlockReceipt struct {
	Version              string `json:"version"`
	ContextSHA256        string `json:"context_sha256"`
	Peer                 string `json:"peer"`
	BlockIndex           int    `json:"block_index"`
	SessionID            string `json:"session_id"`
	PairRoot             string `json:"pair_root"`
	LocalFanInRoot       string `json:"local_fan_in_root"`
	CircuitSHA256        string `json:"circuit_sha256"`
	OutputShareSeal      string `json:"output_share_seal"`
	TranscriptSHA256     string `json:"transcript_sha256"`
	ReceiptMAC           string `json:"receipt_mac"`
	ExecutionValidSealed bool   `json:"execution_valid_sealed"`
	OpeningsPerformed    int    `json:"openings_performed"`
	ProductionReady      bool   `json:"production_ready"`
}

type formalGLMPhase19MaskedBlock struct {
	Receipt        formalGLMPhase19MaskedBlockReceipt
	tupleShares    []*big.Int
	executionShare byte
	seal           [32]byte
	verified       bool
}

func formalGLMPhase19OutputReceiptMessage(
	receipt formalGLMPhase19MaskedBlockReceipt) ([]byte, error) {

	if receipt.Version != formalGLMPhase19OutputVersion ||
		!formalGLMIsSHA256(receipt.ContextSHA256) ||
		!formalGLMIsSHA256(receipt.SessionID) || !formalGLMIsSHA256(receipt.PairRoot) ||
		!formalGLMIsSHA256(receipt.LocalFanInRoot) ||
		!formalGLMIsSHA256(receipt.CircuitSHA256) ||
		!formalGLMIsSHA256(receipt.OutputShareSeal) ||
		!receipt.ExecutionValidSealed || receipt.OpeningsPerformed != 0 ||
		receipt.ProductionReady {
		return nil, fmt.Errorf("formal-glm: invalid Phase-1.9 masked-block receipt")
	}
	message := formalGLMPhase15AppendString(nil, receipt.Version)
	for _, value := range []string{receipt.ContextSHA256, receipt.Peer,
		receipt.SessionID, receipt.PairRoot, receipt.LocalFanInRoot,
		receipt.CircuitSHA256, receipt.OutputShareSeal} {
		message = formalGLMPhase15AppendString(message, value)
	}
	message = formalGLMPhase15AppendUint64(message, uint64(receipt.BlockIndex))
	return message, nil
}

func formalGLMPhase19BuildMaskedBlock(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, pair formalGLMPhase19PairedFanIn,
	session exactGCSession, peer string, tupleShares []*big.Int,
	executionShare byte, backendKey [32]byte) (formalGLMPhase19MaskedBlock, error) {

	var zero formalGLMPhase19MaskedBlock
	if err := formalGLMPhase19ValidateBlockSession(plan, ctx, pair, session); err != nil {
		return zero, err
	}
	layout, _ := formalGLMPhase19Layout(plan, ctx)
	if (peer != ctx.ComputePeers[0] && peer != ctx.ComputePeers[1]) ||
		len(tupleShares) != layout.CoordinateCount || executionShare > 1 ||
		!formalGLMPhase19KeyValid(backendKey) {
		return zero, fmt.Errorf("formal-glm: invalid Phase-1.9 masked output")
	}
	encoded, err := formalGLMPhase15EncodeRecords(tupleShares, plan.RingBits)
	if err != nil {
		return zero, err
	}
	privateMessage := formalGLMPhase15AppendString(nil, peer)
	privateMessage = formalGLMPhase15AppendBytes(privateMessage, encoded)
	privateMessage = append(privateMessage, executionShare)
	privateMessage = append(privateMessage, session.SessionID[:]...)
	shareSeal := formalGLMPhase19MAC(backendKey,
		formalGLMPhase19OutputDomain+"/share", privateMessage)
	ctxDigest, _ := formalGLMPhase19ContextDigest(ctx)
	source, _ := formalGLMPhase19BlockCircuitSource(plan, ctx, pair.BlockIndex)
	circuitDigest := sha256.Sum256([]byte(source))
	localRoot := pair.EvaluatorFanInRoot
	if peer == ctx.ComputePeers[0] {
		localRoot = pair.GarblerFanInRoot
	}
	receipt := formalGLMPhase19MaskedBlockReceipt{
		Version:              formalGLMPhase19OutputVersion,
		ContextSHA256:        hex.EncodeToString(ctxDigest[:]),
		Peer:                 peer,
		BlockIndex:           pair.BlockIndex,
		SessionID:            hex.EncodeToString(session.SessionID[:]),
		PairRoot:             pair.PairRoot,
		LocalFanInRoot:       localRoot,
		CircuitSHA256:        hex.EncodeToString(circuitDigest[:]),
		OutputShareSeal:      hex.EncodeToString(shareSeal[:]),
		ExecutionValidSealed: true,
		OpeningsPerformed:    0,
		ProductionReady:      false,
	}
	receiptMessage, err := formalGLMPhase19OutputReceiptMessage(receipt)
	if err != nil {
		return zero, err
	}
	transcript := sha256.Sum256(append(
		[]byte(formalGLMPhase19OutputDomain+"/transcript|"), receiptMessage...))
	receipt.TranscriptSHA256 = hex.EncodeToString(transcript[:])
	// TranscriptSHA256 is deliberately excluded from its own preimage but is
	// authenticated by the following receipt MAC.
	receiptMACMessage := formalGLMPhase15AppendBytes(receiptMessage, transcript[:])
	receiptMAC := formalGLMPhase19MAC(backendKey,
		formalGLMPhase19OutputDomain+"/receipt", receiptMACMessage)
	receipt.ReceiptMAC = hex.EncodeToString(receiptMAC[:])
	copyShares := make([]*big.Int, len(tupleShares))
	for i, value := range tupleShares {
		copyShares[i] = new(big.Int).Set(value)
	}
	return formalGLMPhase19MaskedBlock{
		Receipt: receipt, tupleShares: copyShares, executionShare: executionShare,
		seal: shareSeal, verified: true,
	}, nil
}

func formalGLMPhase19VerifyMaskedBlock(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, pair formalGLMPhase19PairedFanIn,
	block formalGLMPhase19MaskedBlock, backendKey [32]byte) error {

	if !block.verified || block.executionShare > 1 ||
		len(block.tupleShares) != plan.BlockCapacity*ctx.CoordinatesPerRow {
		return fmt.Errorf("formal-glm: unverified Phase-1.9 masked block")
	}
	if err := formalGLMPhase19ValidateContext(plan, ctx); err != nil {
		return err
	}
	if err := formalGLMPhase19VerifyPair(ctx, pair, backendKey); err != nil {
		return err
	}
	encoded, err := formalGLMPhase15EncodeRecords(block.tupleShares, plan.RingBits)
	if err != nil {
		return err
	}
	sessionBytes, err := hex.DecodeString(block.Receipt.SessionID)
	if err != nil || len(sessionBytes) != 32 {
		return fmt.Errorf("formal-glm: invalid Phase-1.9 output session")
	}
	privateMessage := formalGLMPhase15AppendString(nil, block.Receipt.Peer)
	privateMessage = formalGLMPhase15AppendBytes(privateMessage, encoded)
	privateMessage = append(privateMessage, block.executionShare)
	privateMessage = append(privateMessage, sessionBytes...)
	wantShareSeal := formalGLMPhase19MAC(backendKey,
		formalGLMPhase19OutputDomain+"/share", privateMessage)
	if !hmac.Equal(wantShareSeal[:], block.seal[:]) ||
		block.Receipt.OutputShareSeal != hex.EncodeToString(wantShareSeal[:]) {
		return fmt.Errorf("formal-glm: Phase-1.9 masked share authentication failed")
	}
	return formalGLMPhase19VerifyMaskedBlockReceipt(ctx, pair, block.Receipt, backendKey)
}

func formalGLMPhase19VerifyMaskedBlockReceipt(ctx formalGLMPhase19Context,
	pair formalGLMPhase19PairedFanIn, receipt formalGLMPhase19MaskedBlockReceipt,
	backendKey [32]byte) error {

	ctxDigest, err := formalGLMPhase19ContextDigest(ctx)
	if err != nil || receipt.ContextSHA256 != hex.EncodeToString(ctxDigest[:]) ||
		receipt.BlockIndex != pair.BlockIndex || receipt.PairRoot != pair.PairRoot ||
		(receipt.Peer != ctx.ComputePeers[0] && receipt.Peer != ctx.ComputePeers[1]) {
		return fmt.Errorf("formal-glm: mismatched Phase-1.9 masked-block receipt")
	}
	wantLocalRoot := pair.EvaluatorFanInRoot
	if receipt.Peer == ctx.ComputePeers[0] {
		wantLocalRoot = pair.GarblerFanInRoot
	}
	if receipt.LocalFanInRoot != wantLocalRoot {
		return fmt.Errorf("formal-glm: masked block is bound to a different fan-in")
	}
	message, err := formalGLMPhase19OutputReceiptMessage(receipt)
	if err != nil {
		return err
	}
	transcript := sha256.Sum256(append(
		[]byte(formalGLMPhase19OutputDomain+"/transcript|"), message...))
	if receipt.TranscriptSHA256 != hex.EncodeToString(transcript[:]) {
		return fmt.Errorf("formal-glm: invalid Phase-1.9 masked-block transcript")
	}
	wantMAC := formalGLMPhase19MAC(backendKey,
		formalGLMPhase19OutputDomain+"/receipt",
		formalGLMPhase15AppendBytes(message, transcript[:]))
	gotMAC, decodeErr := hex.DecodeString(receipt.ReceiptMAC)
	if decodeErr != nil || !hmac.Equal(wantMAC[:], gotMAC) {
		return fmt.Errorf("formal-glm: Phase-1.9 masked-block receipt authentication failed")
	}
	return nil
}

func formalGLMPhase19RunGarbler(rw io.ReadWriter, plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, pair formalGLMPhase19PairedFanIn,
	local formalGLMPhase19FanInResult, session exactGCSession,
	backendKey [32]byte) (formalGLMPhase19MaskedBlock, error) {

	var zero formalGLMPhase19MaskedBlock
	if rw == nil {
		return zero, fmt.Errorf("formal-glm: nil Phase-1.9 peer channel")
	}
	if local.Receipt.Recipient != ctx.ComputePeers[0] ||
		session.GarblerID != ctx.ComputePeers[0] {
		return zero, fmt.Errorf("formal-glm: invalid Phase-1.9 garbler role")
	}
	if err := formalGLMPhase19ValidateBlockSession(plan, ctx, pair, session); err != nil {
		return zero, err
	}
	layout, _ := formalGLMPhase19Layout(plan, ctx)
	masks, err := formalGLMRandomMasks(layout.CoordinateCount, plan.RingBits)
	if err != nil {
		return zero, err
	}
	executionMask, err := formalGLMPhase19RandomExecutionMask()
	if err != nil {
		return zero, err
	}
	values, err := formalGLMPhase19GarblerInputValues(
		plan, ctx, pair, local, masks, executionMask, backendKey)
	if err != nil {
		return zero, err
	}
	circ, err := compileFormalGLMPhase19Block(plan, ctx, pair.BlockIndex)
	if err != nil {
		return zero, err
	}
	input := exactGCPackChunks(values, exactGCTypeBits(plan.RingBits))
	secure, err := newExactGCSecureRecordRW(rw, session, exactGCRoleGarbler)
	if err != nil {
		return zero, err
	}
	conn := p2p.NewConn(secure)
	protocolErr := exactGCGarblerProtocol(conn, circ, input, session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return zero, err
	}
	return formalGLMPhase19BuildMaskedBlock(
		plan, ctx, pair, session, ctx.ComputePeers[0], masks,
		executionMask, backendKey)
}

func formalGLMPhase19RunEvaluator(rw io.ReadWriter, plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, pair formalGLMPhase19PairedFanIn,
	local formalGLMPhase19FanInResult, session exactGCSession,
	backendKey [32]byte) (formalGLMPhase19MaskedBlock, error) {

	var zero formalGLMPhase19MaskedBlock
	if rw == nil {
		return zero, fmt.Errorf("formal-glm: nil Phase-1.9 peer channel")
	}
	if local.Receipt.Recipient != ctx.ComputePeers[1] ||
		session.EvaluatorID != ctx.ComputePeers[1] {
		return zero, fmt.Errorf("formal-glm: invalid Phase-1.9 evaluator role")
	}
	if err := formalGLMPhase19ValidateBlockSession(plan, ctx, pair, session); err != nil {
		return zero, err
	}
	values, err := formalGLMPhase19LocalInputValues(
		plan, ctx, pair, local, backendKey)
	if err != nil {
		return zero, err
	}
	circ, err := compileFormalGLMPhase19Block(plan, ctx, pair.BlockIndex)
	if err != nil {
		return zero, err
	}
	input := exactGCPackChunks(values, exactGCTypeBits(plan.RingBits))
	secure, err := newExactGCSecureRecordRW(rw, session, exactGCRoleEvaluator)
	if err != nil {
		return zero, err
	}
	conn := p2p.NewConn(secure)
	packed, protocolErr := exactGCEvaluatorProtocol(conn, circ, input, session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return zero, err
	}
	layout, _ := formalGLMPhase19Layout(plan, ctx)
	shares, executionShare, err := formalGLMPhase19DecodeCircuitOutput(
		packed, layout.CoordinateCount, plan.RingBits)
	if err != nil {
		return zero, err
	}
	return formalGLMPhase19BuildMaskedBlock(
		plan, ctx, pair, session, ctx.ComputePeers[1], shares,
		executionShare, backendKey)
}

type formalGLMPhase19MaskedBlockReceiptPair struct {
	Version                 string `json:"version"`
	ContextSHA256           string `json:"context_sha256"`
	BlockIndex              int    `json:"block_index"`
	PairRoot                string `json:"pair_root"`
	GarblerReceiptSHA256    string `json:"garbler_receipt_sha256"`
	EvaluatorReceiptSHA256  string `json:"evaluator_receipt_sha256"`
	ReceiptPairSHA256       string `json:"receipt_pair_sha256"`
	ExecutionValidSealed    bool   `json:"execution_valid_sealed"`
	ExecutionValidityOpened bool   `json:"execution_validity_opened"`
	OpeningsPerformed       int    `json:"openings_performed"`
	ProductionReady         bool   `json:"production_ready"`
	seal                    [32]byte
	verified                bool
}

func formalGLMPhase19MaskedBlockPairMessage(
	pair formalGLMPhase19MaskedBlockReceiptPair) ([]byte, error) {

	if pair.Version != formalGLMPhase19OutputVersion+"-pair" ||
		!formalGLMIsSHA256(pair.ContextSHA256) || !formalGLMIsSHA256(pair.PairRoot) ||
		!formalGLMIsSHA256(pair.GarblerReceiptSHA256) ||
		!formalGLMIsSHA256(pair.EvaluatorReceiptSHA256) ||
		!formalGLMIsSHA256(pair.ReceiptPairSHA256) ||
		!pair.ExecutionValidSealed || pair.ExecutionValidityOpened ||
		pair.OpeningsPerformed != 0 || pair.ProductionReady {
		return nil, fmt.Errorf("formal-glm: invalid Phase-1.9 masked-block receipt pair")
	}
	public := pair
	public.seal = [32]byte{}
	public.verified = false
	return json.Marshal(public)
}

func formalGLMPhase19PairMaskedBlockReceipts(ctx formalGLMPhase19Context,
	pair formalGLMPhase19PairedFanIn, left, right formalGLMPhase19MaskedBlockReceipt,
	backendKey [32]byte) (formalGLMPhase19MaskedBlockReceiptPair, error) {

	var zero formalGLMPhase19MaskedBlockReceiptPair
	if err := formalGLMPhase19VerifyMaskedBlockReceipt(ctx, pair, left, backendKey); err != nil {
		return zero, err
	}
	if err := formalGLMPhase19VerifyMaskedBlockReceipt(ctx, pair, right, backendKey); err != nil {
		return zero, err
	}
	if left.Peer != ctx.ComputePeers[0] || right.Peer != ctx.ComputePeers[1] ||
		left.SessionID != right.SessionID || left.CircuitSHA256 != right.CircuitSHA256 ||
		left.TranscriptSHA256 == right.TranscriptSHA256 {
		return zero, fmt.Errorf("formal-glm: swapped, replayed, or mismatched masked-block receipts")
	}
	leftBytes, _ := json.Marshal(left)
	rightBytes, _ := json.Marshal(right)
	leftDigest, rightDigest := sha256.Sum256(leftBytes), sha256.Sum256(rightBytes)
	message := formalGLMPhase15AppendString(nil, formalGLMPhase19OutputDomain+"/pair")
	message = append(message, leftDigest[:]...)
	message = append(message, rightDigest[:]...)
	pairDigest := sha256.Sum256(message)
	ctxDigest, _ := formalGLMPhase19ContextDigest(ctx)
	result := formalGLMPhase19MaskedBlockReceiptPair{
		Version:                 formalGLMPhase19OutputVersion + "-pair",
		ContextSHA256:           hex.EncodeToString(ctxDigest[:]),
		BlockIndex:              pair.BlockIndex,
		PairRoot:                pair.PairRoot,
		GarblerReceiptSHA256:    hex.EncodeToString(leftDigest[:]),
		EvaluatorReceiptSHA256:  hex.EncodeToString(rightDigest[:]),
		ReceiptPairSHA256:       hex.EncodeToString(pairDigest[:]),
		ExecutionValidSealed:    true,
		ExecutionValidityOpened: false,
		OpeningsPerformed:       0,
		ProductionReady:         false,
		verified:                true,
	}
	encoded, err := formalGLMPhase19MaskedBlockPairMessage(result)
	if err != nil {
		return zero, err
	}
	result.seal = formalGLMPhase19MAC(backendKey,
		formalGLMPhase19OutputDomain+"/receipt-pair", encoded)
	return result, nil
}

func formalGLMPhase19VerifyMaskedBlockReceiptPair(ctx formalGLMPhase19Context,
	pair formalGLMPhase19MaskedBlockReceiptPair, backendKey [32]byte) error {

	ctxDigest, err := formalGLMPhase19ContextDigest(ctx)
	if err != nil || !pair.verified ||
		pair.ContextSHA256 != hex.EncodeToString(ctxDigest[:]) ||
		pair.BlockIndex < 0 || pair.BlockIndex >= ctx.TotalBlocks ||
		!formalGLMPhase19KeyValid(backendKey) {
		return fmt.Errorf("formal-glm: unverified Phase-1.9 masked-block receipt pair")
	}
	encoded, err := formalGLMPhase19MaskedBlockPairMessage(pair)
	if err != nil {
		return err
	}
	want := formalGLMPhase19MAC(backendKey,
		formalGLMPhase19OutputDomain+"/receipt-pair", encoded)
	if !hmac.Equal(want[:], pair.seal[:]) {
		return fmt.Errorf("formal-glm: masked-block receipt-pair authentication failed")
	}
	return nil
}

type formalGLMPhase19AccumulatorPlan struct {
	Version                 string   `json:"version"`
	ContextSHA256           string   `json:"context_sha256"`
	BlockReceiptPairSHA256  []string `json:"block_receipt_pair_sha256,omitempty"`
	BlockCount              int      `json:"block_count,omitempty"`
	AccumulatorRoot         string   `json:"accumulator_root"`
	ExecutionValidSealed    bool     `json:"execution_valid_sealed"`
	ExecutionValidityOpened bool     `json:"execution_validity_opened"`
	OpeningsPerformed       int      `json:"openings_performed"`
	ProductionReady         bool     `json:"production_ready"`
	seal                    [32]byte
	verified                bool
}

func formalGLMPhase19AccumulatorPlanMessage(
	plan formalGLMPhase19AccumulatorPlan) ([]byte, error) {

	legacy := plan.Version == formalGLMPhase19ExecVersion &&
		plan.BlockCount == 0 && len(plan.BlockReceiptPairSHA256) > 0
	streamed := plan.Version == formalGLMPhase19StreamExecVersion &&
		plan.BlockCount > 0 && len(plan.BlockReceiptPairSHA256) == 0
	if (!legacy && !streamed) ||
		!formalGLMIsSHA256(plan.ContextSHA256) ||
		!formalGLMIsSHA256(plan.AccumulatorRoot) ||
		!plan.ExecutionValidSealed || plan.ExecutionValidityOpened ||
		plan.OpeningsPerformed != 0 || plan.ProductionReady {
		return nil, fmt.Errorf("formal-glm: invalid Phase-1.9 accumulator plan")
	}
	for _, value := range plan.BlockReceiptPairSHA256 {
		if !formalGLMIsSHA256(value) {
			return nil, fmt.Errorf("formal-glm: invalid Phase-1.9 block receipt root")
		}
	}
	public := plan
	public.seal = [32]byte{}
	public.verified = false
	return json.Marshal(public)
}

func formalGLMPhase19BuildAccumulatorPlan(ctx formalGLMPhase19Context,
	blocks []formalGLMPhase19MaskedBlockReceiptPair,
	backendKey [32]byte) (formalGLMPhase19AccumulatorPlan, error) {

	var zero formalGLMPhase19AccumulatorPlan
	if len(blocks) != ctx.TotalBlocks || !formalGLMPhase19KeyValid(backendKey) {
		return zero, fmt.Errorf("formal-glm: incomplete Phase-1.9 block schedule")
	}
	ctxDigest, err := formalGLMPhase19ContextDigest(ctx)
	if err != nil {
		return zero, err
	}
	receipts := make([]string, ctx.TotalBlocks)
	seen := make([]bool, ctx.TotalBlocks)
	for _, block := range blocks {
		if err := formalGLMPhase19VerifyMaskedBlockReceiptPair(
			ctx, block, backendKey); err != nil {
			return zero, err
		}
		if seen[block.BlockIndex] {
			return zero, fmt.Errorf("formal-glm: duplicate Phase-1.9 block receipt")
		}
		seen[block.BlockIndex] = true
		receipts[block.BlockIndex] = block.ReceiptPairSHA256
	}
	message := formalGLMPhase15AppendString(nil, formalGLMPhase19ExecDomain+"/plan")
	message = append(message, ctxDigest[:]...)
	for _, receipt := range receipts {
		message = formalGLMPhase15AppendString(message, receipt)
	}
	root := sha256.Sum256(message)
	result := formalGLMPhase19AccumulatorPlan{
		Version:                 formalGLMPhase19ExecVersion,
		ContextSHA256:           hex.EncodeToString(ctxDigest[:]),
		BlockReceiptPairSHA256:  receipts,
		AccumulatorRoot:         hex.EncodeToString(root[:]),
		ExecutionValidSealed:    true,
		ExecutionValidityOpened: false,
		OpeningsPerformed:       0,
		ProductionReady:         false,
		verified:                true,
	}
	encoded, err := formalGLMPhase19AccumulatorPlanMessage(result)
	if err != nil {
		return zero, err
	}
	result.seal = formalGLMPhase19MAC(backendKey,
		formalGLMPhase19ExecDomain+"/plan-seal", encoded)
	return result, nil
}

func formalGLMPhase19BuildStreamAccumulatorPlan(ctx formalGLMPhase19Context,
	summary formalGLMPhase19BlockScheduleSummary,
	backendKey [32]byte) (formalGLMPhase19AccumulatorPlan, error) {

	var zero formalGLMPhase19AccumulatorPlan
	ctxDigest, err := formalGLMPhase19ContextDigest(ctx)
	if err != nil || summary.TotalBlocks != ctx.TotalBlocks ||
		!formalGLMIsSHA256(summary.AccumulatorRoot) ||
		!formalGLMPhase19KeyValid(backendKey) {
		return zero, fmt.Errorf("formal-glm: invalid streamed accumulator summary")
	}
	result := formalGLMPhase19AccumulatorPlan{
		Version:                 formalGLMPhase19StreamExecVersion,
		ContextSHA256:           hex.EncodeToString(ctxDigest[:]),
		BlockCount:              summary.TotalBlocks,
		AccumulatorRoot:         summary.AccumulatorRoot,
		ExecutionValidSealed:    true,
		ExecutionValidityOpened: false,
		OpeningsPerformed:       0,
		ProductionReady:         false,
		verified:                true,
	}
	encoded, err := formalGLMPhase19AccumulatorPlanMessage(result)
	if err != nil {
		return zero, err
	}
	result.seal = formalGLMPhase19MAC(backendKey,
		formalGLMPhase19ExecDomain+"/plan-seal", encoded)
	return result, nil
}

func formalGLMPhase19VerifyAccumulatorPlan(ctx formalGLMPhase19Context,
	plan formalGLMPhase19AccumulatorPlan, backendKey [32]byte) error {

	ctxDigest, err := formalGLMPhase19ContextDigest(ctx)
	legacy := plan.Version == formalGLMPhase19ExecVersion &&
		plan.BlockCount == 0 && len(plan.BlockReceiptPairSHA256) == ctx.TotalBlocks
	streamed := plan.Version == formalGLMPhase19StreamExecVersion &&
		plan.BlockCount == ctx.TotalBlocks && len(plan.BlockReceiptPairSHA256) == 0
	if err != nil || !plan.verified || (!legacy && !streamed) ||
		plan.ContextSHA256 != hex.EncodeToString(ctxDigest[:]) ||
		!formalGLMPhase19KeyValid(backendKey) {
		return fmt.Errorf("formal-glm: unverified Phase-1.9 accumulator plan")
	}
	if legacy {
		message := formalGLMPhase15AppendString(nil,
			formalGLMPhase19ExecDomain+"/plan")
		message = append(message, ctxDigest[:]...)
		for _, receipt := range plan.BlockReceiptPairSHA256 {
			message = formalGLMPhase15AppendString(message, receipt)
		}
		root := sha256.Sum256(message)
		if plan.AccumulatorRoot != hex.EncodeToString(root[:]) {
			return fmt.Errorf("formal-glm: invalid Phase-1.9 accumulator root")
		}
	} else if !formalGLMIsSHA256(plan.AccumulatorRoot) {
		return fmt.Errorf("formal-glm: invalid streamed accumulator root")
	}
	encoded, err := formalGLMPhase19AccumulatorPlanMessage(plan)
	if err != nil {
		return err
	}
	want := formalGLMPhase19MAC(backendKey,
		formalGLMPhase19ExecDomain+"/plan-seal", encoded)
	if !hmac.Equal(want[:], plan.seal[:]) {
		return fmt.Errorf("formal-glm: accumulator-plan authentication failed")
	}
	return nil
}

func formalGLMPhase19AccumulatorCircuitSource(blocks int) (string, error) {
	if blocks < 1 || blocks > formalGLMPhase15MaxTotal {
		return "", fmt.Errorf("formal-glm: invalid Phase-1.9 accumulator shape")
	}
	var source strings.Builder
	fmt.Fprintf(&source, "package main\nfunc main(g [%d]uint8, e [%d]uint8) [1]uint8 {\n",
		blocks+1, blocks)
	source.WriteString("\tallSharesValid := true\n\tanyActive := false\n")
	for block := 0; block < blocks; block++ {
		fmt.Fprintf(&source,
			"\tgValid%d := g[%d] == uint8(0) || g[%d] == uint8(1)\n",
			block, block, block)
		fmt.Fprintf(&source,
			"\teValid%d := e[%d] == uint8(0) || e[%d] == uint8(1)\n",
			block, block, block)
		fmt.Fprintf(&source,
			"\tallSharesValid = allSharesValid && gValid%d && eValid%d\n",
			block, block)
		fmt.Fprintf(&source,
			"\tanyActive = anyActive || (g[%d] != e[%d] && gValid%d && eValid%d)\n",
			block, block, block, block)
	}
	fmt.Fprintf(&source, "\tmask := g[%d]\n", blocks)
	source.WriteString("\tmaskValid := mask == uint8(0) || mask == uint8(1)\n")
	source.WriteString("\texecutionValid := allSharesValid && anyActive\n")
	source.WriteString("\toutShare := uint8(0)\n")
	source.WriteString("\tif maskValid {\n\t\toutShare = mask\n")
	source.WriteString("\t\tif executionValid { outShare = uint8(1) - mask }\n\t}\n")
	source.WriteString("\tvar out [1]uint8\n\tout[0] = outShare\n\treturn out\n}\n")
	return source.String(), nil
}

func compileFormalGLMPhase19Accumulator(blocks int) (*circuit.Circuit, error) {
	source, err := formalGLMPhase19AccumulatorCircuitSource(blocks)
	if err != nil {
		return nil, err
	}
	circ, err := compileFormalGLMPhase15Source(source, "Phase-1.9 execution accumulator")
	if err != nil {
		return nil, err
	}
	if len(circ.Inputs) != 2 || len(circ.Outputs) != 1 ||
		int(circ.Inputs[0].Type.Bits) != (blocks+1)*8 ||
		int(circ.Inputs[1].Type.Bits) != blocks*8 || circ.Outputs.Size() != 8 {
		return nil, fmt.Errorf("formal-glm: compiler produced invalid accumulator arity")
	}
	return circ, nil
}

func formalGLMPhase19AccumulatorPurpose(ctx formalGLMPhase19Context,
	plan formalGLMPhase19AccumulatorPlan, attempt [32]byte) (string, error) {
	if !plan.verified || !formalGLMIsSHA256(plan.AccumulatorRoot) {
		return "", fmt.Errorf("formal-glm: invalid accumulator purpose")
	}
	return fmt.Sprintf("formal-glm/phase19-v2/execution/%s/root/%s/attempt/%s",
		plan.ContextSHA256, plan.AccumulatorRoot, hex.EncodeToString(attempt[:])), nil
}

func formalGLMPhase19AccumulatorSession(glmPlan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, accumulator formalGLMPhase19AccumulatorPlan,
	attempt, masterKey [32]byte) (exactGCSession, error) {

	if err := formalGLMPhase19VerifyAccumulatorPlan(ctx, accumulator, masterKey); err != nil {
		return exactGCSession{}, err
	}
	purpose, err := formalGLMPhase19AccumulatorPurpose(ctx, accumulator, attempt)
	if err != nil {
		return exactGCSession{}, err
	}
	blockCount := len(accumulator.BlockReceiptPairSHA256)
	if accumulator.BlockCount > 0 {
		blockCount = accumulator.BlockCount
	}
	session := exactGCSession{
		SessionID: attempt, MasterKey: masterKey,
		GarblerID: ctx.ComputePeers[0], EvaluatorID: ctx.ComputePeers[1],
		Purpose: purpose,
		Spec: exactGCCircuitSpec{
			Operation: exactGCFormalGLMOneIteration,
			RingBits:  glmPlan.RingBits,
			FracBits:  glmPlan.Kernel.FracBits,
			VectorLen: blockCount + 1,
		},
	}
	if err := session.validate(); err != nil {
		return exactGCSession{}, err
	}
	return session, nil
}

func formalGLMPhase19ValidateAccumulatorSession(glmPlan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, accumulator formalGLMPhase19AccumulatorPlan,
	session exactGCSession) error {

	want, err := formalGLMPhase19AccumulatorSession(
		glmPlan, ctx, accumulator, session.SessionID, session.MasterKey)
	if err != nil {
		return err
	}
	if session.GarblerID != want.GarblerID || session.EvaluatorID != want.EvaluatorID ||
		session.Purpose != want.Purpose || session.Spec.Operation != want.Spec.Operation ||
		session.Spec.RingBits != want.Spec.RingBits ||
		session.Spec.FracBits != want.Spec.FracBits ||
		session.Spec.VectorLen != want.Spec.VectorLen {
		return fmt.Errorf("formal-glm: Phase-1.9 accumulator/session binding mismatch")
	}
	return nil
}

func formalGLMPhase19VerifyMaskedBlockForAccumulator(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, block formalGLMPhase19MaskedBlock,
	expectedReceiptSHA256, peer string, backendKey [32]byte) error {

	if !block.verified || block.Receipt.Peer != peer || block.executionShare > 1 ||
		len(block.tupleShares) != plan.BlockCapacity*ctx.CoordinatesPerRow ||
		!formalGLMIsSHA256(expectedReceiptSHA256) {
		return fmt.Errorf("formal-glm: invalid local block for execution accumulator")
	}
	receiptBytes, err := json.Marshal(block.Receipt)
	if err != nil {
		return err
	}
	receiptDigest := sha256.Sum256(receiptBytes)
	if expectedReceiptSHA256 != hex.EncodeToString(receiptDigest[:]) {
		return fmt.Errorf("formal-glm: accumulator received a swapped block receipt")
	}
	encoded, err := formalGLMPhase15EncodeRecords(block.tupleShares, plan.RingBits)
	if err != nil {
		return err
	}
	sessionBytes, err := hex.DecodeString(block.Receipt.SessionID)
	if err != nil || len(sessionBytes) != 32 {
		return fmt.Errorf("formal-glm: invalid accumulator source session")
	}
	privateMessage := formalGLMPhase15AppendString(nil, peer)
	privateMessage = formalGLMPhase15AppendBytes(privateMessage, encoded)
	privateMessage = append(privateMessage, block.executionShare)
	privateMessage = append(privateMessage, sessionBytes...)
	wantShareSeal := formalGLMPhase19MAC(backendKey,
		formalGLMPhase19OutputDomain+"/share", privateMessage)
	if !hmac.Equal(wantShareSeal[:], block.seal[:]) ||
		block.Receipt.OutputShareSeal != hex.EncodeToString(wantShareSeal[:]) {
		return fmt.Errorf("formal-glm: accumulator source-share authentication failed")
	}
	message, err := formalGLMPhase19OutputReceiptMessage(block.Receipt)
	if err != nil {
		return err
	}
	transcript := sha256.Sum256(append(
		[]byte(formalGLMPhase19OutputDomain+"/transcript|"), message...))
	wantMAC := formalGLMPhase19MAC(backendKey,
		formalGLMPhase19OutputDomain+"/receipt",
		formalGLMPhase15AppendBytes(message, transcript[:]))
	gotMAC, decodeErr := hex.DecodeString(block.Receipt.ReceiptMAC)
	if block.Receipt.ContextSHA256 != ctx.ContextSHA256ForPhase19() ||
		block.Receipt.TranscriptSHA256 != hex.EncodeToString(transcript[:]) ||
		decodeErr != nil || !hmac.Equal(wantMAC[:], gotMAC) {
		return fmt.Errorf("formal-glm: accumulator source receipt authentication failed")
	}
	return nil
}

func (ctx formalGLMPhase19Context) ContextSHA256ForPhase19() string {
	digest, err := formalGLMPhase19ContextDigest(ctx)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(digest[:])
}

func formalGLMPhase19AccumulatorLocalShares(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, accumulator formalGLMPhase19AccumulatorPlan,
	pairs []formalGLMPhase19MaskedBlockReceiptPair,
	blocks []formalGLMPhase19MaskedBlock, peer string,
	backendKey [32]byte) ([]byte, error) {

	if err := formalGLMPhase19VerifyAccumulatorPlan(ctx, accumulator, backendKey); err != nil {
		return nil, err
	}
	if len(pairs) != ctx.TotalBlocks || len(blocks) != ctx.TotalBlocks ||
		(peer != ctx.ComputePeers[0] && peer != ctx.ComputePeers[1]) {
		return nil, fmt.Errorf("formal-glm: incomplete Phase-1.9 accumulator input")
	}
	rebuilt, err := formalGLMPhase19BuildAccumulatorPlan(ctx, pairs, backendKey)
	if err != nil || rebuilt.AccumulatorRoot != accumulator.AccumulatorRoot {
		return nil, fmt.Errorf("formal-glm: accumulator receipt schedule mismatch")
	}
	pairByBlock := make(map[int]formalGLMPhase19MaskedBlockReceiptPair, len(pairs))
	for _, pair := range pairs {
		pairByBlock[pair.BlockIndex] = pair
	}
	blockByIndex := make(map[int]formalGLMPhase19MaskedBlock, len(blocks))
	for _, block := range blocks {
		if _, duplicate := blockByIndex[block.Receipt.BlockIndex]; duplicate {
			return nil, fmt.Errorf("formal-glm: duplicate local accumulator block")
		}
		blockByIndex[block.Receipt.BlockIndex] = block
	}
	result := make([]byte, ctx.TotalBlocks)
	for index := 0; index < ctx.TotalBlocks; index++ {
		pair, pairOK := pairByBlock[index]
		block, blockOK := blockByIndex[index]
		if !pairOK || !blockOK {
			return nil, fmt.Errorf("formal-glm: missing local accumulator block")
		}
		expected := pair.EvaluatorReceiptSHA256
		if peer == ctx.ComputePeers[0] {
			expected = pair.GarblerReceiptSHA256
		}
		if err := formalGLMPhase19VerifyMaskedBlockForAccumulator(
			plan, ctx, block, expected, peer, backendKey); err != nil {
			return nil, err
		}
		result[index] = block.executionShare
	}
	return result, nil
}

type formalGLMPhase19ExecutionReceipt struct {
	Version                 string `json:"version"`
	ContextSHA256           string `json:"context_sha256"`
	Peer                    string `json:"peer"`
	SessionID               string `json:"session_id"`
	AccumulatorRoot         string `json:"accumulator_root"`
	ExecutionShareSeal      string `json:"execution_share_seal"`
	TranscriptSHA256        string `json:"transcript_sha256"`
	ReceiptMAC              string `json:"receipt_mac"`
	ExecutionValidSealed    bool   `json:"execution_valid_sealed"`
	ExecutionValidityOpened bool   `json:"execution_validity_opened"`
	OpeningsPerformed       int    `json:"openings_performed"`
	ProductionReady         bool   `json:"production_ready"`
}

type formalGLMPhase19ExecutionSeal struct {
	Receipt  formalGLMPhase19ExecutionReceipt
	share    byte
	seal     [32]byte
	verified bool
}

func formalGLMPhase19ExecutionReceiptMessage(
	receipt formalGLMPhase19ExecutionReceipt) ([]byte, error) {
	if receipt.Version != formalGLMPhase19ExecVersion+"-receipt" ||
		!formalGLMIsSHA256(receipt.ContextSHA256) ||
		!formalGLMIsSHA256(receipt.SessionID) ||
		!formalGLMIsSHA256(receipt.AccumulatorRoot) ||
		!formalGLMIsSHA256(receipt.ExecutionShareSeal) ||
		!receipt.ExecutionValidSealed || receipt.ExecutionValidityOpened ||
		receipt.OpeningsPerformed != 0 || receipt.ProductionReady {
		return nil, fmt.Errorf("formal-glm: invalid Phase-1.9 execution receipt")
	}
	message := formalGLMPhase15AppendString(nil, receipt.Version)
	for _, value := range []string{receipt.ContextSHA256, receipt.Peer,
		receipt.SessionID, receipt.AccumulatorRoot, receipt.ExecutionShareSeal} {
		message = formalGLMPhase15AppendString(message, value)
	}
	return message, nil
}

func formalGLMPhase19BuildExecutionSeal(ctx formalGLMPhase19Context,
	accumulator formalGLMPhase19AccumulatorPlan, session exactGCSession,
	peer string, share byte, backendKey [32]byte) (
	formalGLMPhase19ExecutionSeal, error) {

	var zero formalGLMPhase19ExecutionSeal
	if share > 1 || (peer != ctx.ComputePeers[0] && peer != ctx.ComputePeers[1]) ||
		!formalGLMPhase19KeyValid(backendKey) {
		return zero, fmt.Errorf("formal-glm: invalid hidden execution share")
	}
	privateMessage := formalGLMPhase15AppendString(nil, peer)
	privateMessage = append(privateMessage, share)
	privateMessage = append(privateMessage, session.SessionID[:]...)
	privateMessage = formalGLMPhase15AppendString(privateMessage,
		accumulator.AccumulatorRoot)
	shareSeal := formalGLMPhase19MAC(backendKey,
		formalGLMPhase19ExecDomain+"/share", privateMessage)
	receipt := formalGLMPhase19ExecutionReceipt{
		Version:                 formalGLMPhase19ExecVersion + "-receipt",
		ContextSHA256:           ctx.ContextSHA256ForPhase19(),
		Peer:                    peer,
		SessionID:               hex.EncodeToString(session.SessionID[:]),
		AccumulatorRoot:         accumulator.AccumulatorRoot,
		ExecutionShareSeal:      hex.EncodeToString(shareSeal[:]),
		ExecutionValidSealed:    true,
		ExecutionValidityOpened: false,
		OpeningsPerformed:       0,
		ProductionReady:         false,
	}
	message, err := formalGLMPhase19ExecutionReceiptMessage(receipt)
	if err != nil {
		return zero, err
	}
	transcript := sha256.Sum256(append(
		[]byte(formalGLMPhase19ExecDomain+"/transcript|"), message...))
	receipt.TranscriptSHA256 = hex.EncodeToString(transcript[:])
	receiptMAC := formalGLMPhase19MAC(backendKey,
		formalGLMPhase19ExecDomain+"/receipt",
		formalGLMPhase15AppendBytes(message, transcript[:]))
	receipt.ReceiptMAC = hex.EncodeToString(receiptMAC[:])
	return formalGLMPhase19ExecutionSeal{
		Receipt: receipt, share: share, seal: shareSeal, verified: true,
	}, nil
}

func formalGLMPhase19VerifyExecutionReceipt(ctx formalGLMPhase19Context,
	accumulator formalGLMPhase19AccumulatorPlan,
	receipt formalGLMPhase19ExecutionReceipt, backendKey [32]byte) error {
	if receipt.ContextSHA256 != ctx.ContextSHA256ForPhase19() ||
		receipt.AccumulatorRoot != accumulator.AccumulatorRoot ||
		(receipt.Peer != ctx.ComputePeers[0] && receipt.Peer != ctx.ComputePeers[1]) {
		return fmt.Errorf("formal-glm: mismatched Phase-1.9 execution receipt")
	}
	message, err := formalGLMPhase19ExecutionReceiptMessage(receipt)
	if err != nil {
		return err
	}
	transcript := sha256.Sum256(append(
		[]byte(formalGLMPhase19ExecDomain+"/transcript|"), message...))
	wantMAC := formalGLMPhase19MAC(backendKey,
		formalGLMPhase19ExecDomain+"/receipt",
		formalGLMPhase15AppendBytes(message, transcript[:]))
	gotMAC, decodeErr := hex.DecodeString(receipt.ReceiptMAC)
	if receipt.TranscriptSHA256 != hex.EncodeToString(transcript[:]) ||
		decodeErr != nil || !hmac.Equal(wantMAC[:], gotMAC) {
		return fmt.Errorf("formal-glm: execution receipt authentication failed")
	}
	return nil
}

func formalGLMPhase19VerifyExecutionSeal(ctx formalGLMPhase19Context,
	accumulator formalGLMPhase19AccumulatorPlan,
	seal formalGLMPhase19ExecutionSeal, backendKey [32]byte) error {
	if !seal.verified || seal.share > 1 {
		return fmt.Errorf("formal-glm: unverified hidden execution share")
	}
	if err := formalGLMPhase19VerifyExecutionReceipt(
		ctx, accumulator, seal.Receipt, backendKey); err != nil {
		return err
	}
	sessionBytes, err := hex.DecodeString(seal.Receipt.SessionID)
	if err != nil || len(sessionBytes) != 32 {
		return fmt.Errorf("formal-glm: invalid execution receipt session")
	}
	privateMessage := formalGLMPhase15AppendString(nil, seal.Receipt.Peer)
	privateMessage = append(privateMessage, seal.share)
	privateMessage = append(privateMessage, sessionBytes...)
	privateMessage = formalGLMPhase15AppendString(privateMessage,
		accumulator.AccumulatorRoot)
	want := formalGLMPhase19MAC(backendKey,
		formalGLMPhase19ExecDomain+"/share", privateMessage)
	if !hmac.Equal(want[:], seal.seal[:]) ||
		seal.Receipt.ExecutionShareSeal != hex.EncodeToString(want[:]) {
		return fmt.Errorf("formal-glm: hidden execution-share authentication failed")
	}
	return nil
}

func formalGLMPhase19RunAccumulatorGarbler(rw io.ReadWriter,
	glmPlan formalGLMPhase15Plan, ctx formalGLMPhase19Context,
	accumulator formalGLMPhase19AccumulatorPlan,
	pairs []formalGLMPhase19MaskedBlockReceiptPair,
	blocks []formalGLMPhase19MaskedBlock, session exactGCSession,
	backendKey [32]byte) (formalGLMPhase19ExecutionSeal, error) {

	var zero formalGLMPhase19ExecutionSeal
	if rw == nil {
		return zero, fmt.Errorf("formal-glm: nil execution-accumulator channel")
	}
	if err := formalGLMPhase19ValidateAccumulatorSession(
		glmPlan, ctx, accumulator, session); err != nil {
		return zero, err
	}
	shares, err := formalGLMPhase19AccumulatorLocalShares(
		glmPlan, ctx, accumulator, pairs, blocks, ctx.ComputePeers[0], backendKey)
	if err != nil {
		return zero, err
	}
	mask, err := formalGLMPhase19RandomExecutionMask()
	if err != nil {
		return zero, err
	}
	values := make([]*big.Int, 0, len(shares)+1)
	for _, share := range shares {
		values = append(values, new(big.Int).SetUint64(uint64(share)))
	}
	values = append(values, new(big.Int).SetUint64(uint64(mask)))
	circ, err := compileFormalGLMPhase19Accumulator(len(shares))
	if err != nil {
		return zero, err
	}
	secure, err := newExactGCSecureRecordRW(rw, session, exactGCRoleGarbler)
	if err != nil {
		return zero, err
	}
	conn := p2p.NewConn(secure)
	protocolErr := exactGCGarblerProtocol(conn, circ, exactGCPackChunks(values, 8), session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return zero, err
	}
	return formalGLMPhase19BuildExecutionSeal(
		ctx, accumulator, session, ctx.ComputePeers[0], mask, backendKey)
}

func formalGLMPhase19RunAccumulatorEvaluator(rw io.ReadWriter,
	glmPlan formalGLMPhase15Plan, ctx formalGLMPhase19Context,
	accumulator formalGLMPhase19AccumulatorPlan,
	pairs []formalGLMPhase19MaskedBlockReceiptPair,
	blocks []formalGLMPhase19MaskedBlock, session exactGCSession,
	backendKey [32]byte) (formalGLMPhase19ExecutionSeal, error) {

	var zero formalGLMPhase19ExecutionSeal
	if rw == nil {
		return zero, fmt.Errorf("formal-glm: nil execution-accumulator channel")
	}
	if err := formalGLMPhase19ValidateAccumulatorSession(
		glmPlan, ctx, accumulator, session); err != nil {
		return zero, err
	}
	shares, err := formalGLMPhase19AccumulatorLocalShares(
		glmPlan, ctx, accumulator, pairs, blocks, ctx.ComputePeers[1], backendKey)
	if err != nil {
		return zero, err
	}
	values := make([]*big.Int, len(shares))
	for i, share := range shares {
		values[i] = new(big.Int).SetUint64(uint64(share))
	}
	circ, err := compileFormalGLMPhase19Accumulator(len(shares))
	if err != nil {
		return zero, err
	}
	secure, err := newExactGCSecureRecordRW(rw, session, exactGCRoleEvaluator)
	if err != nil {
		return zero, err
	}
	conn := p2p.NewConn(secure)
	packed, protocolErr := exactGCEvaluatorProtocol(
		conn, circ, exactGCPackChunks(values, 8), session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return zero, err
	}
	if packed == nil || packed.Sign() < 0 || packed.Cmp(big.NewInt(1)) > 0 {
		return zero, fmt.Errorf("formal-glm: accumulator emitted invalid execution share")
	}
	return formalGLMPhase19BuildExecutionSeal(
		ctx, accumulator, session, ctx.ComputePeers[1], byte(packed.Uint64()), backendKey)
}

type formalGLMPhase19ExecutionReceiptPair struct {
	Version                    string `json:"version"`
	ContextSHA256              string `json:"context_sha256"`
	AccumulatorRoot            string `json:"accumulator_root"`
	GarblerReceiptSHA256       string `json:"garbler_receipt_sha256"`
	EvaluatorReceiptSHA256     string `json:"evaluator_receipt_sha256"`
	ExecutionReceiptPairSHA256 string `json:"execution_receipt_pair_sha256"`
	ExecutionValidSealed       bool   `json:"execution_valid_sealed"`
	ExecutionValidityOpened    bool   `json:"execution_validity_opened"`
	OpeningsPerformed          int    `json:"openings_performed"`
	ProductionReady            bool   `json:"production_ready"`
	seal                       [32]byte
	verified                   bool
}

func formalGLMPhase19PairExecutionReceipts(ctx formalGLMPhase19Context,
	accumulator formalGLMPhase19AccumulatorPlan,
	left, right formalGLMPhase19ExecutionReceipt, backendKey [32]byte) (
	formalGLMPhase19ExecutionReceiptPair, error) {
	var zero formalGLMPhase19ExecutionReceiptPair
	if err := formalGLMPhase19VerifyExecutionReceipt(
		ctx, accumulator, left, backendKey); err != nil {
		return zero, err
	}
	if err := formalGLMPhase19VerifyExecutionReceipt(
		ctx, accumulator, right, backendKey); err != nil {
		return zero, err
	}
	if left.Peer != ctx.ComputePeers[0] || right.Peer != ctx.ComputePeers[1] ||
		left.SessionID != right.SessionID || left.TranscriptSHA256 == right.TranscriptSHA256 {
		return zero, fmt.Errorf("formal-glm: swapped or mismatched execution receipts")
	}
	leftBytes, _ := json.Marshal(left)
	rightBytes, _ := json.Marshal(right)
	leftDigest, rightDigest := sha256.Sum256(leftBytes), sha256.Sum256(rightBytes)
	message := formalGLMPhase15AppendString(nil, formalGLMPhase19ExecDomain+"/pair")
	message = append(message, leftDigest[:]...)
	message = append(message, rightDigest[:]...)
	pairDigest := sha256.Sum256(message)
	result := formalGLMPhase19ExecutionReceiptPair{
		Version:                    formalGLMPhase19ExecVersion + "-receipt-pair",
		ContextSHA256:              ctx.ContextSHA256ForPhase19(),
		AccumulatorRoot:            accumulator.AccumulatorRoot,
		GarblerReceiptSHA256:       hex.EncodeToString(leftDigest[:]),
		EvaluatorReceiptSHA256:     hex.EncodeToString(rightDigest[:]),
		ExecutionReceiptPairSHA256: hex.EncodeToString(pairDigest[:]),
		ExecutionValidSealed:       true,
		ExecutionValidityOpened:    false,
		OpeningsPerformed:          0,
		ProductionReady:            false,
		verified:                   true,
	}
	encoded, _ := json.Marshal(result)
	result.seal = formalGLMPhase19MAC(backendKey,
		formalGLMPhase19ExecDomain+"/receipt-pair-seal", encoded)
	return result, nil
}
