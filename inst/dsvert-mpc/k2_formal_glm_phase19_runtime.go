package main

// Server-local runtime bridge from authenticated Phase-1.8 ciphertext frames
// to the specialised Phase-1.9 exact-GC fan-in.  This bridge is deliberately
// absent from runtime-capabilities: it is an internal worker boundary, not a
// command that accepts analyst-provided statistics or opens an MPC share.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

const (
	formalGLMPhase19RuntimePrepareVersion = "dsvert-formal-glm-phase19-runtime-prepare-v1"
	formalGLMPhase19RuntimeWorkerVersion  = "dsvert-formal-glm-phase19-runtime-worker-v1"
	formalGLMPhase19RuntimeResultVersion  = "dsvert-formal-glm-phase19-runtime-result-v1"
	formalGLMPhase19RuntimeMaxConfigBytes = 64 << 20
)

// formalGLMPhase19RuntimeLocalInput contains only server-local key handles,
// public cross-signed plan material and paths to authenticated encrypted
// Phase-1.8 frames.  No plaintext row or unsealed additive share has a JSON
// representation at this boundary.
type formalGLMPhase19RuntimeLocalInput struct {
	Version                     string               `json:"version"`
	Plan                        formalGLMPhase15Plan `json:"plan"`
	PreExecutionTokenSHA256     string               `json:"pre_execution_token_sha256"`
	GlobalMaterializationRoot   string               `json:"global_materialization_root"`
	Recipient                   string               `json:"recipient"`
	FinalizerDir                string               `json:"finalizer_dir"`
	IngressPaths                []string             `json:"ingress_paths"`
	LocalIngressKey             string               `json:"local_ingress_key"`
	RecipientTransportSecretKey string               `json:"recipient_transport_secret_key"`
	BackendKey                  string               `json:"backend_key"`
	BlockIndex                  int                  `json:"block_index"`
}

type formalGLMPhase19RuntimePrepareOutput struct {
	Version           string                       `json:"version"`
	Context           formalGLMPhase19Context      `json:"context"`
	Receipt           formalGLMPhase19FanInReceipt `json:"receipt"`
	BlockIndex        int                          `json:"block_index"`
	OpeningsPerformed int                          `json:"openings_performed"`
	ProductionReady   bool                         `json:"production_ready"`
}

type formalGLMPhase19RuntimeWorkerConfig struct {
	Version       string                            `json:"version"`
	Role          string                            `json:"role"`
	Local         formalGLMPhase19RuntimeLocalInput `json:"local"`
	PeerReceipt   formalGLMPhase19FanInReceipt      `json:"peer_receipt"`
	AttemptID     string                            `json:"attempt_id"`
	SpoolDir      string                            `json:"spool_dir"`
	MaxSpoolBytes int64                             `json:"max_spool_bytes"`
	TTLSeconds    int                               `json:"ttl_seconds"`
	HeartbeatKey  string                            `json:"heartbeat_key"`
}

type formalGLMPhase19RuntimeResult struct {
	Version           string                             `json:"version"`
	Kind              string                             `json:"kind"`
	ContextSHA256     string                             `json:"context_sha256"`
	BlockIndex        int                                `json:"block_index"`
	Peer              string                             `json:"peer"`
	AttemptID         string                             `json:"attempt_id"`
	TupleShare        string                             `json:"tuple_share"`
	ExecutionShare    int                                `json:"execution_share"`
	Receipt           formalGLMPhase19MaskedBlockReceipt `json:"receipt"`
	OpeningsPerformed int                                `json:"openings_performed"`
	ProductionReady   bool                               `json:"production_ready"`
}

type formalGLMPhase19RuntimeLocal struct {
	context formalGLMPhase19Context
	result  formalGLMPhase19FanInResult
	backend [32]byte
}

type formalGLMPhase19RuntimeScheduleResult struct {
	context       formalGLMPhase19Context
	blockReceipts []formalGLMPhase19MaskedBlockReceiptPair
	executionSeal formalGLMPhase19ExecutionSeal
	executionPair formalGLMPhase19ExecutionReceiptPair
	betaShares    []*big.Int
	finalReceipts []formalGLMPhase15StepReceipt
	dpBridge      formalGLMPhase15DPBridgePlan
	dpShares      []*big.Int
	postToken     formalGLMPhase19PostExecutionToken
	backend       [32]byte
}

type formalGLMPhase19RuntimeDurableConfig struct {
	CheckpointDir     string
	CheckpointKey     [32]byte
	SigningKey        ed25519.PrivateKey
	Pins              map[string]ed25519.PublicKey
	OutputLatticeBits int
}

type formalGLMPhase19RuntimeCheckpointStatus struct {
	PlanSHA256       string                       `json:"plan_sha256"`
	Peer             string                       `json:"peer"`
	NextStep         int                          `json:"next_step"`
	TranscriptSHA256 string                       `json:"transcript_sha256"`
	Pending          *formalGLMPhase15StepReceipt `json:"pending,omitempty"`
	Last             *formalGLMPhase15StepReceipt `json:"last,omitempty"`
}

func formalGLMPhase19RuntimeDecodeKey(value, name string) ([32]byte, error) {
	var result [32]byte
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != len(result) ||
		base64.StdEncoding.EncodeToString(decoded) != value {
		return result, fmt.Errorf("formal-glm: invalid Phase-1.9 %s", name)
	}
	copy(result[:], decoded)
	clear(decoded)
	if !formalGLMPhase19KeyValid(result) {
		clear(result[:])
		return result, fmt.Errorf("formal-glm: missing Phase-1.9 %s", name)
	}
	return result, nil
}

func formalGLMPhase19RuntimeValidatePath(path, name string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return fmt.Errorf("formal-glm: invalid Phase-1.9 %s path", name)
	}
	return nil
}

func formalGLMPhase19RuntimeReadIngress(path string) ([]byte, error) {
	if err := formalGLMPhase19RuntimeValidatePath(path, "ingress"); err != nil {
		return nil, err
	}
	return formalGLMPhase18ReadRecord(path)
}

func formalGLMPhase19RuntimeZeroFanIn(result *formalGLMPhase19FanInResult) {
	if result == nil {
		return
	}
	exactGCZeroBigInts(result.coordinateShares)
	for i := range result.validityShares {
		clear(result.validityShares[i])
	}
	clear(result.alignmentGateShares)
	for i := range result.consensusShares {
		clear(result.consensusShares[i][:])
	}
	clear(result.seal[:])
}

func formalGLMPhase19RuntimeLoadLocal(input formalGLMPhase19RuntimeLocalInput) (
	formalGLMPhase19RuntimeLocal, error) {

	var zero formalGLMPhase19RuntimeLocal
	if input.Version != formalGLMPhase19RuntimePrepareVersion ||
		exactGCValidateLabel("Phase-1.9 runtime recipient", input.Recipient, 128) != nil ||
		input.BlockIndex < 0 || input.BlockIndex >= input.Plan.TotalBlocks ||
		(len(input.IngressPaths) != 0 &&
			len(input.IngressPaths) != len(input.Plan.Kernel.CustodianPeers)) {
		return zero, fmt.Errorf("formal-glm: invalid Phase-1.9 runtime request")
	}
	if err := formalGLMPhase19RuntimeValidatePath(input.FinalizerDir, "finalizer"); err != nil {
		return zero, err
	}
	ctx, err := formalGLMPhase19BuildContext(
		input.Plan, input.PreExecutionTokenSHA256, input.GlobalMaterializationRoot)
	if err != nil {
		return zero, err
	}
	if !formalGLMPhase19Contains(ctx.ComputePeers, input.Recipient) {
		return zero, fmt.Errorf("formal-glm: Phase-1.9 recipient is not a designated compute peer")
	}
	ingressKey, err := formalGLMPhase19RuntimeDecodeKey(
		input.LocalIngressKey, "local ingress key")
	if err != nil {
		return zero, err
	}
	defer clear(ingressKey[:])
	backend, err := formalGLMPhase19RuntimeDecodeKey(input.BackendKey, "backend key")
	if err != nil {
		return zero, err
	}
	recipientSecret, err := base64.StdEncoding.Strict().DecodeString(
		input.RecipientTransportSecretKey)
	if err != nil || len(recipientSecret) != 32 ||
		base64.StdEncoding.EncodeToString(recipientSecret) !=
			input.RecipientTransportSecretKey {
		clear(backend[:])
		clear(recipientSecret)
		return zero, fmt.Errorf("formal-glm: invalid Phase-1.9 recipient transport key")
	}
	defer clear(recipientSecret)
	store, err := newFormalGLMPhase18DurableFinalizer(
		input.FinalizerDir, input.Recipient, ingressKey)
	if err != nil {
		clear(backend[:])
		return zero, err
	}
	seen := make(map[string]bool, len(input.IngressPaths))
	for _, path := range input.IngressPaths {
		if seen[path] {
			clear(backend[:])
			return zero, fmt.Errorf("formal-glm: duplicate Phase-1.8 ingress path")
		}
		seen[path] = true
		encoded, readErr := formalGLMPhase19RuntimeReadIngress(path)
		if readErr != nil {
			clear(backend[:])
			return zero, readErr
		}
		_, ingestErr := store.IngestAndFinalizeWithBackend(
			input.Plan, ctx, encoded, recipientSecret, backend)
		clear(encoded)
		if ingestErr != nil {
			clear(backend[:])
			return zero, ingestErr
		}
	}
	blocks, err := store.LoadCompleteBlockWithBackend(
		input.Plan, ctx, input.BlockIndex, recipientSecret, backend)
	if err != nil {
		clear(backend[:])
		return zero, err
	}
	ledger := newFormalGLMPhase19ReplayLedger()
	local, err := formalGLMPhase19FanIn(
		input.Plan, ctx, input.Recipient, input.BlockIndex, blocks, ledger, backend)
	for i := range blocks {
		exactGCZeroBigInts(blocks[i].coordinateShares)
		clear(blocks[i].validityShares)
		clear(blocks[i].consensusShare[:])
		clear(blocks[i].seal[:])
	}
	if err != nil {
		clear(backend[:])
		return zero, err
	}
	return formalGLMPhase19RuntimeLocal{
		context: ctx, result: local, backend: backend,
	}, nil
}

func formalGLMPhase19RuntimePrepare(input formalGLMPhase19RuntimeLocalInput) (
	formalGLMPhase19RuntimePrepareOutput, error) {

	local, err := formalGLMPhase19RuntimeLoadLocal(input)
	if err != nil {
		return formalGLMPhase19RuntimePrepareOutput{}, err
	}
	defer formalGLMPhase19RuntimeZeroFanIn(&local.result)
	defer clear(local.backend[:])
	return formalGLMPhase19RuntimePrepareOutput{
		Version: formalGLMPhase19RuntimePrepareVersion,
		Context: local.context, Receipt: local.result.Receipt,
		BlockIndex: input.BlockIndex, OpeningsPerformed: 0,
		ProductionReady: false,
	}, nil
}

func formalGLMPhase19RuntimePair(ctx formalGLMPhase19Context,
	local, peer formalGLMPhase19FanInReceipt, backend [32]byte) (
	formalGLMPhase19PairedFanIn, error) {

	if local.Recipient == ctx.ComputePeers[0] {
		return formalGLMPhase19PairFanIn(ctx, local, peer, backend)
	}
	if local.Recipient == ctx.ComputePeers[1] {
		return formalGLMPhase19PairFanIn(ctx, peer, local, backend)
	}
	return formalGLMPhase19PairedFanIn{},
		fmt.Errorf("formal-glm: invalid Phase-1.9 local receipt role")
}

func formalGLMPhase19RuntimeRunPeer(rw io.ReadWriter,
	input formalGLMPhase19RuntimeLocalInput,
	peerReceipt formalGLMPhase19FanInReceipt, attemptID [32]byte) (
	formalGLMPhase19MaskedBlock, error) {

	var zero formalGLMPhase19MaskedBlock
	local, err := formalGLMPhase19RuntimeLoadLocal(input)
	if err != nil {
		return zero, err
	}
	defer formalGLMPhase19RuntimeZeroFanIn(&local.result)
	defer clear(local.backend[:])
	pair, err := formalGLMPhase19RuntimePair(
		local.context, local.result.Receipt, peerReceipt, local.backend)
	if err != nil {
		return zero, err
	}
	if err := formalGLMPhase19VerifyLocalPair(
		input.Plan, local.context, pair, local.result, local.backend); err != nil {
		return zero, err
	}
	session, err := formalGLMPhase19BlockSession(
		input.Plan, local.context, pair, attemptID, local.backend)
	if err != nil {
		return zero, err
	}
	if input.Recipient == local.context.ComputePeers[0] {
		return formalGLMPhase19RunGarbler(
			rw, input.Plan, local.context, pair, local.result, session, local.backend)
	}
	return formalGLMPhase19RunEvaluator(
		rw, input.Plan, local.context, pair, local.result, session, local.backend)
}

func formalGLMPhase19RuntimeEncodeResult(input formalGLMPhase19RuntimeLocalInput,
	block formalGLMPhase19MaskedBlock, attemptID [32]byte) (
	formalGLMPhase19RuntimeResult, error) {

	if !block.verified || block.Receipt.Peer != input.Recipient ||
		block.Receipt.BlockIndex != input.BlockIndex || block.executionShare > 1 {
		return formalGLMPhase19RuntimeResult{},
			fmt.Errorf("formal-glm: invalid Phase-1.9 runtime output")
	}
	encoded, err := formalGLMPhase15EncodeRecords(
		block.tupleShares, input.Plan.RingBits)
	if err != nil {
		return formalGLMPhase19RuntimeResult{}, err
	}
	return formalGLMPhase19RuntimeResult{
		Version:       formalGLMPhase19RuntimeResultVersion,
		Kind:          "sealed_phase19_full_tuple_additive_share_v1",
		ContextSHA256: block.Receipt.ContextSHA256,
		BlockIndex:    input.BlockIndex, Peer: input.Recipient,
		AttemptID:      hex.EncodeToString(attemptID[:]),
		TupleShare:     base64.StdEncoding.EncodeToString(encoded),
		ExecutionShare: int(block.executionShare), Receipt: block.Receipt,
		OpeningsPerformed: 0, ProductionReady: false,
	}, nil
}

func formalGLMPhase19RuntimeAttempt(root [32]byte, label string,
	iteration, block int) [32]byte {
	message := formalGLMPhase15AppendString(nil,
		"dsVert/formal-glm/runtime/attempt/v1")
	message = append(message, root[:]...)
	message = formalGLMPhase15AppendString(message, label)
	message = formalGLMPhase15AppendUint64(message, uint64(iteration+1))
	message = formalGLMPhase15AppendUint64(message, uint64(block+1))
	return sha256.Sum256(message)
}

func formalGLMPhase19RuntimeControlSession(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, backend, root [32]byte, label string,
	index int) (exactGCSession, error) {

	attempt := formalGLMPhase19RuntimeAttempt(root, "control/"+label, 0, index)
	purpose := fmt.Sprintf(
		"formal-glm/runtime/control/v1/%s/%s/%d/%s",
		ctx.ContextSHA256ForPhase19(), label, index,
		hex.EncodeToString(root[:]))
	session := exactGCSession{
		SessionID: attempt, MasterKey: backend,
		GarblerID: ctx.ComputePeers[0], EvaluatorID: ctx.ComputePeers[1],
		Purpose: purpose,
		Spec: exactGCCircuitSpec{
			Operation: exactGCFormalGLMOneIteration,
			RingBits:  plan.RingBits, FracBits: plan.Kernel.FracBits,
			VectorLen: 1,
		},
	}
	if err := session.validate(); err != nil {
		return exactGCSession{}, err
	}
	return session, nil
}

func formalGLMPhase19RuntimeControlExchange(rw io.ReadWriter,
	session exactGCSession, role string, local []byte, maximum int) ([]byte, error) {

	if rw == nil || len(local) < 2 || len(local) > maximum || maximum > 8<<20 {
		return nil, fmt.Errorf("formal-glm: invalid bounded runtime control record")
	}
	gcRole := exactGCRoleGarbler
	if role == "evaluator" {
		gcRole = exactGCRoleEvaluator
	} else if role != "garbler" {
		return nil, fmt.Errorf("formal-glm: invalid runtime control role")
	}
	secure, err := newExactGCSecureRecordRW(rw, session, gcRole)
	if err != nil {
		return nil, err
	}
	write := func() error {
		record := make([]byte, 4+len(local))
		binary.BigEndian.PutUint32(record[:4], uint32(len(local)))
		copy(record[4:], local)
		_, err := secure.Write(record)
		return err
	}
	read := func() ([]byte, error) {
		header := make([]byte, 4)
		if _, err := io.ReadFull(secure, header); err != nil {
			return nil, err
		}
		size := int(binary.BigEndian.Uint32(header))
		if size < 2 || size > maximum {
			return nil, fmt.Errorf("formal-glm: peer control record exceeds its bound")
		}
		value := make([]byte, size)
		if _, err := io.ReadFull(secure, value); err != nil {
			return nil, err
		}
		return value, nil
	}
	var peer []byte
	if role == "garbler" {
		if err := write(); err != nil {
			return nil, err
		}
		peer, err = read()
	} else {
		peer, err = read()
		if err == nil {
			err = write()
		}
	}
	if err != nil {
		return nil, err
	}
	if flusher, ok := rw.(interface{ Flush() error }); ok {
		if err := flusher.Flush(); err != nil {
			return nil, err
		}
	}
	return peer, nil
}

func formalGLMPhase19RuntimeExchangeJSON(rw io.ReadWriter,
	plan formalGLMPhase15Plan, ctx formalGLMPhase19Context,
	backend, root [32]byte, role, label string, index int,
	local, peer interface{}) error {

	encoded, err := json.Marshal(local)
	if err != nil {
		return err
	}
	session, err := formalGLMPhase19RuntimeControlSession(
		plan, ctx, backend, root, label, index)
	if err != nil {
		return err
	}
	received, err := formalGLMPhase19RuntimeControlExchange(
		rw, session, role, encoded, 2<<20)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(received))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(peer); err != nil {
		return fmt.Errorf("formal-glm: invalid authenticated peer control record")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("formal-glm: trailing authenticated peer control record")
	}
	return nil
}

func formalGLMPhase19RuntimeInitialBeta(plan formalGLMPhase15Plan,
	role string) ([]*big.Int, error) {
	parsed, err := formalGLMPhase15ValidateShape(plan)
	if err != nil {
		return nil, err
	}
	result := make([]*big.Int, plan.Kernel.CoefficientCount)
	modulus := exactGCModulus(plan.RingBits)
	for index := range result {
		result[index] = new(big.Int)
		if role == "garbler" {
			result[index].Mod(new(big.Int).Set(parsed.betaStart[index]), modulus)
		}
	}
	return result, nil
}

func formalGLMPhase19RuntimeBuildCheckpointStatus(
	store *formalGLMPhase15CheckpointStore,
	signingKey ed25519.PrivateKey) (formalGLMPhase19RuntimeCheckpointStatus, error) {
	state, err := store.Load()
	if err != nil {
		return formalGLMPhase19RuntimeCheckpointStatus{}, err
	}
	status := formalGLMPhase19RuntimeCheckpointStatus{
		PlanSHA256: state.PlanSHA256, Peer: state.Peer,
		NextStep: state.NextStep, TranscriptSHA256: state.TranscriptSHA256,
	}
	if state.LastReceipt != nil {
		value := *state.LastReceipt
		value.Signature = append([]byte(nil), state.LastReceipt.Signature...)
		status.Last = &value
	}
	if state.Pending != nil && state.Pending.OutputRecorded {
		value, err := store.PendingReceipt(signingKey)
		if err != nil {
			return formalGLMPhase19RuntimeCheckpointStatus{}, err
		}
		status.Pending = &value
	}
	return status, nil
}

func formalGLMPhase19RuntimeReceiptPair(local, peer formalGLMPhase15StepReceipt,
	plan formalGLMPhase15Plan, pins map[string]ed25519.PublicKey) (
	[]formalGLMPhase15StepReceipt, error) {
	receipts := []formalGLMPhase15StepReceipt{local, peer}
	if err := formalGLMPhase15VerifyReceiptPair(plan, receipts, pins); err != nil {
		return nil, err
	}
	return receipts, nil
}

// formalGLMPhase19RuntimeReconcileCheckpoint closes the only recoverable
// split-commit state: one peer durably committed a barrier for which the other
// still has the signed pending output. No private state crosses the channel.
func formalGLMPhase19RuntimeReconcileCheckpoint(rw io.ReadWriter,
	plan formalGLMPhase15Plan, ctx formalGLMPhase19Context,
	backend, root [32]byte, role string,
	store *formalGLMPhase15CheckpointStore,
	config formalGLMPhase19RuntimeDurableConfig) (
	[]formalGLMPhase15StepReceipt, error) {

	for round := 0; round < 3; round++ {
		local, err := formalGLMPhase19RuntimeBuildCheckpointStatus(
			store, config.SigningKey)
		if err != nil {
			return nil, err
		}
		var peer formalGLMPhase19RuntimeCheckpointStatus
		if err := formalGLMPhase19RuntimeExchangeJSON(
			rw, plan, ctx, backend, root, role,
			"phase15-checkpoint-reconcile", round, local, &peer); err != nil {
			return nil, err
		}
		if peer.Peer == local.Peer ||
			!formalGLMPhase19Contains(plan.Kernel.ComputePeers, peer.Peer) ||
			peer.PlanSHA256 != local.PlanSHA256 ||
			peer.NextStep < 0 || peer.NextStep > plan.ScheduleSteps ||
			!formalGLMIsSHA256(peer.TranscriptSHA256) {
			return nil, fmt.Errorf("formal-glm: invalid peer checkpoint status")
		}
		if local.NextStep == peer.NextStep {
			if local.TranscriptSHA256 != peer.TranscriptSHA256 {
				return nil, fmt.Errorf("formal-glm: checkpoint transcripts diverged")
			}
			if local.NextStep != plan.ScheduleSteps {
				return nil, nil
			}
			if local.Last == nil || peer.Last == nil {
				return nil, fmt.Errorf("formal-glm: final checkpoint receipts are missing")
			}
			return formalGLMPhase19RuntimeReceiptPair(
				*local.Last, *peer.Last, plan, config.Pins)
		}
		if local.NextStep+1 == peer.NextStep {
			if local.Pending == nil || peer.Last == nil {
				return nil, fmt.Errorf("formal-glm: unrecoverable split checkpoint commit")
			}
			receipts, err := formalGLMPhase19RuntimeReceiptPair(
				*local.Pending, *peer.Last, plan, config.Pins)
			if err != nil {
				return nil, err
			}
			if err := store.CommitPending(receipts, config.Pins); err != nil {
				return nil, err
			}
			continue
		}
		if peer.NextStep+1 == local.NextStep {
			if peer.Pending == nil || local.Last == nil {
				return nil, fmt.Errorf("formal-glm: unrecoverable split checkpoint commit")
			}
			if _, err := formalGLMPhase19RuntimeReceiptPair(
				*local.Last, *peer.Pending, plan, config.Pins); err != nil {
				return nil, err
			}
			continue
		}
		return nil, fmt.Errorf("formal-glm: checkpoint schedules diverged")
	}
	return nil, fmt.Errorf("formal-glm: checkpoint reconciliation did not converge")
}

func formalGLMPhase19RuntimeRunDurablePhase15(rw io.ReadWriter,
	plan formalGLMPhase15Plan, ctx formalGLMPhase19Context,
	backend, root [32]byte, role string,
	blocks []formalGLMPhase19MaskedBlock,
	receiptPairs []formalGLMPhase19MaskedBlockReceiptPair,
	config formalGLMPhase19RuntimeDurableConfig) (
	*formalGLMPhase15CheckpointStore, []*big.Int,
	[]formalGLMPhase15StepReceipt, error) {

	if formalGLMPhase19RuntimeValidatePath(config.CheckpointDir, "checkpoint") != nil ||
		!formalGLMPhase19KeyValid(config.CheckpointKey) ||
		len(config.SigningKey) != ed25519.PrivateKeySize ||
		config.OutputLatticeBits < 1 ||
		config.OutputLatticeBits > plan.Kernel.FracBits {
		return nil, nil, nil, fmt.Errorf("formal-glm: invalid durable Phase-1.5 configuration")
	}
	peer := ctx.ComputePeers[0]
	if role == "evaluator" {
		peer = ctx.ComputePeers[1]
	}
	publicKey, ok := config.SigningKey.Public().(ed25519.PublicKey)
	if !ok || !hmac.Equal(publicKey, config.Pins[peer]) {
		return nil, nil, nil, fmt.Errorf("formal-glm: checkpoint signer is not the pinned local peer")
	}
	if roles, err := formalGLMPhase16PinnedRoles(plan, config.Pins); err != nil ||
		roles.PinsetSHA256 != plan.Kernel.PinsetSHA256 {
		return nil, nil, nil, fmt.Errorf("formal-glm: durable checkpoint pinset mismatch")
	}
	store, err := newFormalGLMPhase15CheckpointStore(
		config.CheckpointDir, config.CheckpointKey, plan, peer)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := store.Bootstrap(); err != nil {
		return nil, nil, nil, err
	}
	finalReceipts, err := formalGLMPhase19RuntimeReconcileCheckpoint(
		rw, plan, ctx, backend, root, role, store, config)
	if err != nil {
		return nil, nil, nil, err
	}
	planDigest, err := formalGLMPhase15PlanDigest(plan)
	if err != nil {
		return nil, nil, nil, err
	}
	planSHA256 := hex.EncodeToString(planDigest[:])
	for {
		state, err := store.Load()
		if err != nil {
			return nil, nil, nil, err
		}
		if state.NextStep == plan.ScheduleSteps {
			break
		}
		stepIndex := state.NextStep
		iteration := stepIndex / (plan.TotalBlocks + 1)
		within := stepIndex % (plan.TotalBlocks + 1)
		blockIndex := within
		if within == plan.TotalBlocks {
			blockIndex = -1
		}
		attempt := formalGLMPhase19RuntimeAttempt(
			root, "phase15-checkpoint", iteration, blockIndex)
		step, err := store.BeginAttempt(attempt)
		if err != nil {
			return nil, nil, nil, err
		}
		var fanIn *formalGLMPhase15FanInResult
		if blockIndex >= 0 {
			fanIn = &formalGLMPhase15FanInResult{
				PlanSHA256: planSHA256, Recipient: peer,
				BlockIndex: blockIndex, Shares: blocks[blockIndex].tupleShares,
				FanInRoot: receiptPairs[blockIndex].ReceiptPairSHA256,
				verified:  true,
			}
			step.SourceRoot = fanIn.FanInRoot
		}
		session, err := formalGLMPhase15StepSession(plan, step, attempt, backend)
		if err != nil {
			return nil, nil, nil, err
		}
		localReceipt, err := store.RunPendingWorkerStep(
			rw, session, fanIn, config.SigningKey)
		if err != nil {
			return nil, nil, nil, err
		}
		var peerReceipt formalGLMPhase15StepReceipt
		if err := formalGLMPhase19RuntimeExchangeJSON(
			rw, plan, ctx, backend, root, role,
			"phase15-step-receipt", stepIndex, localReceipt,
			&peerReceipt); err != nil {
			return nil, nil, nil, err
		}
		receipts, err := formalGLMPhase19RuntimeReceiptPair(
			localReceipt, peerReceipt, plan, config.Pins)
		if err != nil {
			return nil, nil, nil, err
		}
		if err := store.CommitPending(receipts, config.Pins); err != nil {
			return nil, nil, nil, err
		}
		if stepIndex == plan.ScheduleSteps-1 {
			finalReceipts = receipts
		}
	}
	if len(finalReceipts) != 2 {
		localReceipt, err := store.CommittedFinalReceipt()
		if err != nil {
			return nil, nil, nil, err
		}
		var peerReceipt formalGLMPhase15StepReceipt
		if err := formalGLMPhase19RuntimeExchangeJSON(
			rw, plan, ctx, backend, root, role,
			"phase15-final-receipt", 0, localReceipt, &peerReceipt); err != nil {
			return nil, nil, nil, err
		}
		finalReceipts, err = formalGLMPhase19RuntimeReceiptPair(
			localReceipt, peerReceipt, plan, config.Pins)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	state, err := store.Load()
	if err != nil {
		return nil, nil, nil, err
	}
	beta, err := formalGLMPhase15DecodeStateValues(
		state.Beta, plan.Kernel.CoefficientCount, plan.RingBits)
	if err != nil {
		return nil, nil, nil, err
	}
	return store, beta, finalReceipts, nil
}

func formalGLMPhase19RuntimeRunDurablePhase15Stream(rw io.ReadWriter,
	plan formalGLMPhase15Plan, ctx formalGLMPhase19Context,
	backend, root [32]byte, role string,
	blocks *formalGLMPhase19StreamStore,
	config formalGLMPhase19RuntimeDurableConfig) (
	*formalGLMPhase15CheckpointStore, []*big.Int,
	[]formalGLMPhase15StepReceipt, error) {

	if blocks == nil || !blocks.complete ||
		formalGLMPhase19RuntimeValidatePath(config.CheckpointDir, "checkpoint") != nil ||
		!formalGLMPhase19KeyValid(config.CheckpointKey) ||
		len(config.SigningKey) != ed25519.PrivateKeySize ||
		config.OutputLatticeBits < 1 ||
		config.OutputLatticeBits > plan.Kernel.FracBits {
		return nil, nil, nil,
			fmt.Errorf("formal-glm: invalid streamed durable Phase-1.5 configuration")
	}
	peer := ctx.ComputePeers[0]
	if role == "evaluator" {
		peer = ctx.ComputePeers[1]
	}
	if blocks.peer != peer ||
		blocks.ctx.ContextSHA256ForPhase19() != ctx.ContextSHA256ForPhase19() {
		return nil, nil, nil, fmt.Errorf("formal-glm: private block-store peer mismatch")
	}
	publicKey, ok := config.SigningKey.Public().(ed25519.PublicKey)
	if !ok || !hmac.Equal(publicKey, config.Pins[peer]) {
		return nil, nil, nil,
			fmt.Errorf("formal-glm: checkpoint signer is not the pinned local peer")
	}
	if roles, err := formalGLMPhase16PinnedRoles(plan, config.Pins); err != nil ||
		roles.PinsetSHA256 != plan.Kernel.PinsetSHA256 {
		return nil, nil, nil,
			fmt.Errorf("formal-glm: durable checkpoint pinset mismatch")
	}
	checkpoint, err := newFormalGLMPhase15CheckpointStore(
		config.CheckpointDir, config.CheckpointKey, plan, peer)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := checkpoint.Bootstrap(); err != nil {
		return nil, nil, nil, err
	}
	finalReceipts, err := formalGLMPhase19RuntimeReconcileCheckpoint(
		rw, plan, ctx, backend, root, role, checkpoint, config)
	if err != nil {
		return nil, nil, nil, err
	}
	planDigest, err := formalGLMPhase15PlanDigest(plan)
	if err != nil {
		return nil, nil, nil, err
	}
	planSHA256 := hex.EncodeToString(planDigest[:])
	for {
		state, err := checkpoint.Load()
		if err != nil {
			return nil, nil, nil, err
		}
		if state.NextStep == plan.ScheduleSteps {
			break
		}
		stepIndex := state.NextStep
		iteration := stepIndex / (plan.TotalBlocks + 1)
		within := stepIndex % (plan.TotalBlocks + 1)
		blockIndex := within
		if within == plan.TotalBlocks {
			blockIndex = -1
		}
		attempt := formalGLMPhase19RuntimeAttempt(
			root, "phase15-checkpoint", iteration, blockIndex)
		step, err := checkpoint.BeginAttempt(attempt)
		if err != nil {
			return nil, nil, nil, err
		}
		var fanIn *formalGLMPhase15FanInResult
		var stored formalGLMPhase19StoredBlock
		if blockIndex >= 0 {
			stored, err = blocks.ReadBlock(blockIndex)
			if err != nil {
				return nil, nil, nil, err
			}
			fanIn = &formalGLMPhase15FanInResult{
				PlanSHA256: planSHA256, Recipient: peer,
				BlockIndex: blockIndex, Shares: stored.TupleShares,
				FanInRoot: stored.ReceiptPairSHA256, verified: true,
			}
			step.SourceRoot = fanIn.FanInRoot
		}
		session, err := formalGLMPhase15StepSession(plan, step, attempt, backend)
		if err != nil {
			exactGCZeroBigInts(stored.TupleShares)
			return nil, nil, nil, err
		}
		localReceipt, err := checkpoint.RunPendingWorkerStep(
			rw, session, fanIn, config.SigningKey)
		exactGCZeroBigInts(stored.TupleShares)
		if err != nil {
			return nil, nil, nil, err
		}
		var peerReceipt formalGLMPhase15StepReceipt
		if err := formalGLMPhase19RuntimeExchangeJSON(
			rw, plan, ctx, backend, root, role,
			"phase15-step-receipt", stepIndex, localReceipt,
			&peerReceipt); err != nil {
			return nil, nil, nil, err
		}
		receipts, err := formalGLMPhase19RuntimeReceiptPair(
			localReceipt, peerReceipt, plan, config.Pins)
		if err != nil {
			return nil, nil, nil, err
		}
		if err := checkpoint.CommitPending(receipts, config.Pins); err != nil {
			return nil, nil, nil, err
		}
		if stepIndex == plan.ScheduleSteps-1 {
			finalReceipts = receipts
		}
	}
	if len(finalReceipts) != 2 {
		localReceipt, err := checkpoint.CommittedFinalReceipt()
		if err != nil {
			return nil, nil, nil, err
		}
		var peerReceipt formalGLMPhase15StepReceipt
		if err := formalGLMPhase19RuntimeExchangeJSON(
			rw, plan, ctx, backend, root, role,
			"phase15-final-receipt", 0, localReceipt, &peerReceipt); err != nil {
			return nil, nil, nil, err
		}
		finalReceipts, err = formalGLMPhase19RuntimeReceiptPair(
			localReceipt, peerReceipt, plan, config.Pins)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	state, err := checkpoint.Load()
	if err != nil {
		return nil, nil, nil, err
	}
	beta, err := formalGLMPhase15DecodeStateValues(
		state.Beta, plan.Kernel.CoefficientCount, plan.RingBits)
	if err != nil {
		return nil, nil, nil, err
	}
	return checkpoint, beta, finalReceipts, nil
}

// formalGLMPhase19RuntimeRunSchedule executes, on one compute peer, the full
// protected Phase-1.9 block fan-in, hidden-validity accumulator and fixed
// Phase-1.5 optimizer. The two callers use the same rw transport concurrently;
// no function in this schedule reconstructs a tuple, validity bit or beta.
// The returned beta remains a server-local additive share.
func formalGLMPhase19RuntimeRunSchedule(rw io.ReadWriter,
	inputs []formalGLMPhase19RuntimeLocalInput,
	peerFanIn []formalGLMPhase19FanInReceipt, root [32]byte) (
	formalGLMPhase19RuntimeScheduleResult, error) {
	return formalGLMPhase19RuntimeRunScheduleCore(
		rw, inputs, peerFanIn, root, nil)
}

func formalGLMPhase19RuntimeRunDurableSchedule(rw io.ReadWriter,
	inputs []formalGLMPhase19RuntimeLocalInput,
	peerFanIn []formalGLMPhase19FanInReceipt, root [32]byte,
	config formalGLMPhase19RuntimeDurableConfig) (
	formalGLMPhase19RuntimeScheduleResult, error) {
	return formalGLMPhase19RuntimeRunScheduleCore(
		rw, inputs, peerFanIn, root, &config)
}

func formalGLMPhase19RuntimeRunScheduleCore(rw io.ReadWriter,
	inputs []formalGLMPhase19RuntimeLocalInput,
	peerFanIn []formalGLMPhase19FanInReceipt, root [32]byte,
	durable *formalGLMPhase19RuntimeDurableConfig) (
	formalGLMPhase19RuntimeScheduleResult, error) {

	var zero formalGLMPhase19RuntimeScheduleResult
	if len(inputs) == 0 ||
		(len(peerFanIn) != 0 && len(inputs) != len(peerFanIn)) {
		return zero, fmt.Errorf("formal-glm: incomplete runtime schedule")
	}
	plan := inputs[0].Plan
	if len(inputs) != plan.TotalBlocks {
		return zero, fmt.Errorf("formal-glm: runtime schedule does not cover all blocks")
	}
	role := "evaluator"
	if inputs[0].Recipient == plan.Kernel.ComputePeers[0] {
		role = "garbler"
	} else if inputs[0].Recipient != plan.Kernel.ComputePeers[1] {
		return zero, fmt.Errorf("formal-glm: invalid runtime schedule peer")
	}
	blocks := make([]formalGLMPhase19MaskedBlock, plan.TotalBlocks)
	receiptPairs := make([]formalGLMPhase19MaskedBlockReceiptPair, plan.TotalBlocks)
	seen := make([]bool, plan.TotalBlocks)
	var ctx formalGLMPhase19Context
	var backend [32]byte
	backendSet := false
	for position := range inputs {
		input := inputs[position]
		if input.Recipient != inputs[0].Recipient ||
			!reflect.DeepEqual(input.Plan, plan) || input.BlockIndex < 0 ||
			input.BlockIndex >= plan.TotalBlocks || seen[input.BlockIndex] {
			return zero, fmt.Errorf("formal-glm: conflicting runtime block schedule")
		}
		seen[input.BlockIndex] = true
		local, err := formalGLMPhase19RuntimeLoadLocal(input)
		if err != nil {
			return zero, err
		}
		if !backendSet {
			ctx, backend, backendSet = local.context, local.backend, true
		} else if !reflect.DeepEqual(ctx, local.context) ||
			!hmac.Equal(backend[:], local.backend[:]) {
			formalGLMPhase19RuntimeZeroFanIn(&local.result)
			clear(local.backend[:])
			return zero, fmt.Errorf("formal-glm: runtime blocks changed context or backend")
		} else {
			clear(local.backend[:])
		}
		peerFanInReceipt := formalGLMPhase19FanInReceipt{}
		if len(peerFanIn) == 0 {
			err = formalGLMPhase19RuntimeExchangeJSON(
				rw, plan, ctx, backend, root, role, "fanin-receipt",
				input.BlockIndex, local.result.Receipt, &peerFanInReceipt)
		} else {
			peerFanInReceipt = peerFanIn[position]
		}
		if err != nil {
			formalGLMPhase19RuntimeZeroFanIn(&local.result)
			clear(backend[:])
			return zero, err
		}
		pair, err := formalGLMPhase19RuntimePair(
			ctx, local.result.Receipt, peerFanInReceipt, backend)
		if err == nil {
			err = formalGLMPhase19VerifyLocalPair(
				plan, ctx, pair, local.result, backend)
		}
		if err != nil {
			formalGLMPhase19RuntimeZeroFanIn(&local.result)
			clear(backend[:])
			return zero, err
		}
		attempt := formalGLMPhase19RuntimeAttempt(
			root, "phase19-block", 0, input.BlockIndex)
		session, err := formalGLMPhase19BlockSession(
			plan, ctx, pair, attempt, backend)
		if err == nil && role == "garbler" {
			blocks[input.BlockIndex], err = formalGLMPhase19RunGarbler(
				rw, plan, ctx, pair, local.result, session, backend)
		} else if err == nil {
			blocks[input.BlockIndex], err = formalGLMPhase19RunEvaluator(
				rw, plan, ctx, pair, local.result, session, backend)
		}
		formalGLMPhase19RuntimeZeroFanIn(&local.result)
		if err != nil {
			clear(backend[:])
			return zero, err
		}
		var peerReceipt formalGLMPhase19MaskedBlockReceipt
		if err := formalGLMPhase19RuntimeExchangeJSON(
			rw, plan, ctx, backend, root, role, "masked-block-receipt",
			input.BlockIndex, blocks[input.BlockIndex].Receipt,
			&peerReceipt); err != nil {
			clear(backend[:])
			return zero, err
		}
		if role == "garbler" {
			receiptPairs[input.BlockIndex], err =
				formalGLMPhase19PairMaskedBlockReceipts(
					ctx, pair, blocks[input.BlockIndex].Receipt,
					peerReceipt, backend)
		} else {
			receiptPairs[input.BlockIndex], err =
				formalGLMPhase19PairMaskedBlockReceipts(
					ctx, pair, peerReceipt,
					blocks[input.BlockIndex].Receipt, backend)
		}
		if err != nil {
			clear(backend[:])
			return zero, err
		}
	}

	accumulator, err := formalGLMPhase19BuildAccumulatorPlan(
		ctx, receiptPairs, backend)
	if err != nil {
		clear(backend[:])
		return zero, err
	}
	accAttempt := formalGLMPhase19RuntimeAttempt(root, "phase19-accumulator", 0, -1)
	var execution formalGLMPhase19ExecutionSeal
	if role == "garbler" {
		execution, err = formalGLMPhase19RunBoundedAccumulatorGarbler(
			rw, plan, ctx, accumulator, receiptPairs, blocks,
			accAttempt, backend)
	} else {
		execution, err = formalGLMPhase19RunBoundedAccumulatorEvaluator(
			rw, plan, ctx, accumulator, receiptPairs, blocks,
			accAttempt, backend)
	}
	if err != nil {
		clear(backend[:])
		return zero, err
	}
	var peerExecution formalGLMPhase19ExecutionReceipt
	if err := formalGLMPhase19RuntimeExchangeJSON(
		rw, plan, ctx, backend, root, role, "execution-receipt", 0,
		execution.Receipt, &peerExecution); err != nil {
		clear(backend[:])
		return zero, err
	}
	var executionPair formalGLMPhase19ExecutionReceiptPair
	if role == "garbler" {
		executionPair, err = formalGLMPhase19PairExecutionReceipts(
			ctx, accumulator, execution.Receipt, peerExecution, backend)
	} else {
		executionPair, err = formalGLMPhase19PairExecutionReceipts(
			ctx, accumulator, peerExecution, execution.Receipt, backend)
	}
	if err != nil {
		clear(backend[:])
		return zero, err
	}

	var beta []*big.Int
	var finalReceipts []formalGLMPhase15StepReceipt
	var dpBridge formalGLMPhase15DPBridgePlan
	var dpShares []*big.Int
	var postToken formalGLMPhase19PostExecutionToken
	if durable != nil {
		store, durableBeta, receipts, durableErr :=
			formalGLMPhase19RuntimeRunDurablePhase15(
				rw, plan, ctx, backend, root, role, blocks,
				receiptPairs, *durable)
		if durableErr != nil {
			clear(backend[:])
			return zero, durableErr
		}
		beta, finalReceipts = durableBeta, receipts
		dpBridge, err = buildFormalGLMPhase15DPBridgePlan(
			plan, finalReceipts, durable.Pins, durable.OutputLatticeBits)
		if err != nil {
			clear(backend[:])
			return zero, err
		}
		localBeta, err := formalGLMPhase15DPBridgeLoadLocalSource(
			store, finalReceipts, durable.Pins, dpBridge)
		if err != nil {
			clear(backend[:])
			return zero, err
		}
		bridgeAttempt := formalGLMPhase19RuntimeAttempt(
			root, "phase15-dp-bridge", 0, -1)
		bridgeSession, err := formalGLMPhase15DPBridgeSession(
			plan, dpBridge, bridgeAttempt, backend)
		if err != nil {
			clear(backend[:])
			return zero, err
		}
		if inputs[0].Recipient == dpBridge.GarblerPeerName {
			dpShares, err = formalGLMPhase15RunDPBridgeGarblerWithExecution(
				rw, plan, dpBridge, bridgeSession, localBeta,
				execution.share)
		} else if inputs[0].Recipient == dpBridge.EvaluatorPeerName {
			dpShares, err = formalGLMPhase15RunDPBridgeEvaluatorWithExecution(
				rw, plan, dpBridge, bridgeSession, localBeta,
				execution.share)
		} else {
			err = fmt.Errorf("formal-glm: local peer has no DP bridge role")
		}
		exactGCZeroBigInts(localBeta)
		if err != nil {
			clear(backend[:])
			return zero, err
		}
		receiptDigest, err := formalGLMPhase15FinalReceiptPairDigest(
			finalReceipts)
		if err != nil {
			clear(backend[:])
			return zero, err
		}
		workerMessage := formalGLMPhase15AppendString(nil,
			"dsVert/formal-glm/runtime/phase15-worker-transcript/v1")
		workerMessage = formalGLMPhase15AppendString(
			workerMessage, ctx.ContextSHA256ForPhase19())
		workerMessage = formalGLMPhase15AppendString(
			workerMessage, accumulator.AccumulatorRoot)
		workerMessage = formalGLMPhase15AppendBytes(
			workerMessage, receiptDigest[:])
		workerDigest := sha256.Sum256(workerMessage)
		evidence := formalGLMPhase19ExecutionEvidence{
			Phase15ExecutionTranscriptSHA256: finalReceipts[0].TranscriptSHA256,
			FinalCheckpointTranscriptSHA256:  finalReceipts[0].TranscriptSHA256,
			WorkerTranscriptSHA256:           hex.EncodeToString(workerDigest[:]),
			CheckpointEvidenceSHA256:         hex.EncodeToString(receiptDigest[:]),
		}
		postToken, err = formalGLMPhase19BuildPostExecutionToken(
			plan, ctx, receiptPairs, accumulator, executionPair,
			finalReceipts, durable.Pins, evidence, backend)
		if err != nil {
			clear(backend[:])
			return zero, err
		}
	} else {
		beta, err = formalGLMPhase19RuntimeInitialBeta(plan, role)
		if err != nil {
			clear(backend[:])
			return zero, err
		}
		p := plan.Kernel.CoefficientCount
		for iteration := 0; iteration < plan.Iterations; iteration++ {
			gradient := make([]*big.Int, p)
			for index := range gradient {
				gradient[index] = new(big.Int)
			}
			for blockIndex := 0; blockIndex < plan.TotalBlocks; blockIndex++ {
				step := formalGLMPhase15Step{
					Iteration: iteration, BlockIndex: blockIndex,
					SourceRoot: receiptPairs[blockIndex].ReceiptPairSHA256,
				}
				attempt := formalGLMPhase19RuntimeAttempt(
					root, "phase15-block", iteration, blockIndex)
				session, err := formalGLMPhase15StepSession(
					plan, step, attempt, backend)
				if err != nil {
					clear(backend[:])
					return zero, err
				}
				localInput := append([]*big.Int{}, blocks[blockIndex].tupleShares...)
				localInput = append(localInput, beta...)
				localInput = append(localInput, gradient...)
				var output []*big.Int
				if role == "garbler" {
					output, err = formalGLMPhase15RunGarbler(
						rw, plan, step, session, localInput)
				} else {
					output, err = formalGLMPhase15RunEvaluator(
						rw, plan, step, session, localInput)
				}
				if err != nil {
					clear(backend[:])
					return zero, err
				}
				beta, gradient = output[:p], output[p:]
			}
			step := formalGLMPhase15Step{Iteration: iteration, BlockIndex: -1}
			attempt := formalGLMPhase19RuntimeAttempt(
				root, "phase15-finalize", iteration, -1)
			session, err := formalGLMPhase15StepSession(plan, step, attempt, backend)
			if err != nil {
				clear(backend[:])
				return zero, err
			}
			localInput := append(append([]*big.Int{}, beta...), gradient...)
			if role == "garbler" {
				beta, err = formalGLMPhase15RunGarbler(
					rw, plan, step, session, localInput)
			} else {
				beta, err = formalGLMPhase15RunEvaluator(
					rw, plan, step, session, localInput)
			}
			if err != nil {
				clear(backend[:])
				return zero, err
			}
		}
	}
	for index := range blocks {
		exactGCZeroBigInts(blocks[index].tupleShares)
		clear(blocks[index].seal[:])
	}
	return formalGLMPhase19RuntimeScheduleResult{
		context: ctx, blockReceipts: receiptPairs,
		executionSeal: execution, executionPair: executionPair,
		betaShares: beta, finalReceipts: finalReceipts,
		dpBridge: dpBridge, dpShares: dpShares, postToken: postToken,
		backend: backend,
	}, nil
}

func formalGLMPhase19RuntimeStrictDecode(reader io.Reader, target interface{},
	maximum int64) error {
	limited := io.LimitReader(reader, maximum+1)
	data, err := io.ReadAll(limited)
	if err != nil || len(data) == 0 || int64(len(data)) > maximum {
		return fmt.Errorf("formal-glm: invalid bounded runtime input")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("formal-glm: invalid runtime JSON")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("formal-glm: trailing runtime JSON")
	}
	return nil
}

func handleFormalGLMPhase19RuntimePrepare() {
	var input formalGLMPhase19RuntimeLocalInput
	if err := formalGLMPhase19RuntimeStrictDecode(
		os.Stdin, &input, formalGLMPhase19RuntimeMaxConfigBytes); err != nil {
		mpcFatalError("formal-glm Phase-1.9 prepare rejected")
	}
	result, err := formalGLMPhase19RuntimePrepare(input)
	input.LocalIngressKey = ""
	input.RecipientTransportSecretKey = ""
	input.BackendKey = ""
	if err != nil {
		mpcFatalError("formal-glm Phase-1.9 prepare failed")
	}
	mpcWriteOutput(result)
}

func formalGLMPhase19RuntimeReadWorkerConfig(path string) (
	formalGLMPhase19RuntimeWorkerConfig, error) {

	var config formalGLMPhase19RuntimeWorkerConfig
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return config, fmt.Errorf("formal-glm: invalid Phase-1.9 worker config path")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 || !exactGCPrivateOwnedRegular(info) ||
		info.Size() < 2 || info.Size() > formalGLMPhase19RuntimeMaxConfigBytes {
		return config, fmt.Errorf("formal-glm: unsafe Phase-1.9 worker config")
	}
	file, err := os.Open(path)
	if err != nil {
		return config, err
	}
	defer file.Close()
	if err := formalGLMPhase19RuntimeStrictDecode(
		file, &config, formalGLMPhase19RuntimeMaxConfigBytes); err != nil {
		return config, err
	}
	if config.Version != formalGLMPhase19RuntimeWorkerVersion ||
		(config.Role != "garbler" && config.Role != "evaluator") ||
		config.MaxSpoolBytes < 1<<20 || config.MaxSpoolBytes > 64<<30 ||
		config.TTLSeconds < 10 || config.TTLSeconds > 86400 ||
		formalGLMPhase19RuntimeValidatePath(config.SpoolDir, "spool") != nil ||
		filepath.Dir(path) != config.SpoolDir {
		return config, fmt.Errorf("formal-glm: invalid Phase-1.9 worker policy")
	}
	return config, nil
}

func handleFormalGLMPhase19RuntimeWorker(configPath string) (returnErr error) {
	config, err := formalGLMPhase19RuntimeReadWorkerConfig(configPath)
	if err != nil {
		return err
	}
	if err := exactGCRemoveSensitiveConfig(configPath); err != nil {
		return err
	}
	defer func() {
		config.Local.LocalIngressKey = ""
		config.Local.RecipientTransportSecretKey = ""
		config.Local.BackendKey = ""
	}()
	if err := exactGCPrepareWorkerSpool(config.SpoolDir); err != nil {
		return err
	}
	heartbeat, err := exactGCStrictBase64(config.HeartbeatKey, 32)
	if err != nil {
		return fmt.Errorf("formal-glm: invalid Phase-1.9 heartbeat key")
	}
	clear(heartbeat)
	stopHeartbeat, err := exactGCStartWorkerHeartbeat(
		config.SpoolDir, config.AttemptID, config.HeartbeatKey,
		time.Duration(config.TTLSeconds)*time.Second)
	config.HeartbeatKey = ""
	if err != nil {
		return err
	}
	heartbeatStopped := false
	defer func() {
		if !heartbeatStopped {
			if stopErr := stopHeartbeat(); returnErr == nil && stopErr != nil {
				returnErr = stopErr
			}
		}
	}()
	attemptBytes, err := hex.DecodeString(config.AttemptID)
	if err != nil || len(attemptBytes) != 32 ||
		hex.EncodeToString(attemptBytes) != config.AttemptID {
		return fmt.Errorf("formal-glm: invalid Phase-1.9 attempt")
	}
	var attempt [32]byte
	copy(attempt[:], attemptBytes)
	clear(attemptBytes)
	if err := exactGCPrivateMarker(config.SpoolDir, "ready", []byte("1")); err != nil {
		return err
	}
	spool, err := newExactGCSpoolRW(
		config.SpoolDir, config.MaxSpoolBytes,
		time.Duration(config.TTLSeconds)*time.Second)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			if closeErr := spool.Close(); returnErr == nil && closeErr != nil {
				returnErr = closeErr
			}
		}
	}()
	block, err := formalGLMPhase19RuntimeRunPeer(
		spool, config.Local, config.PeerReceipt, attempt)
	if err != nil {
		return err
	}
	defer func() {
		exactGCZeroBigInts(block.tupleShares)
		clear(block.seal[:])
	}()
	if err := spool.Close(); err != nil {
		return err
	}
	closed = true
	result, err := formalGLMPhase19RuntimeEncodeResult(config.Local, block, attempt)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if err := stopHeartbeat(); err != nil {
		return err
	}
	heartbeatStopped = true
	if err := exactGCPrivateMarker(config.SpoolDir, "result.json", encoded); err != nil {
		return err
	}
	if err := exactGCPrivateMarker(config.SpoolDir, "done", []byte("1")); err != nil {
		return err
	}
	return nil
}

func formalGLMPhase19RuntimeReceiptsEqual(left, right formalGLMPhase19FanInReceipt) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && hmac.Equal(leftJSON, rightJSON)
}
