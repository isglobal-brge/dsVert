package main

// Fixed-memory durable Phase-1.9 -> Phase-1.5 runtime. The private manifest,
// protected block store and bounded accumulator keep process RAM independent
// of TotalBlocks while preserving the reviewed exact-GC sessions and roots.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
)

func formalGLMPhase19RuntimeRunDurableScheduleManifest(
	rw io.ReadWriter, template formalGLMPhase19RuntimeLocalInput,
	manifest *formalGLMPhase19ScheduleManifestReader, root [32]byte,
	durable formalGLMPhase19RuntimeDurableConfig,
	workDir string, maxStoreBytes int64) (
	formalGLMPhase19RuntimeScheduleResult, error) {

	var zero formalGLMPhase19RuntimeScheduleResult
	plan := template.Plan
	if rw == nil || manifest == nil || template.BlockIndex != -1 ||
		len(template.IngressPaths) != 0 ||
		template.Version != formalGLMPhase19RuntimePrepareVersion ||
		manifest.plan.RunID != plan.RunID || !formalGLMPhase19KeyValid(root) {
		return zero, fmt.Errorf("formal-glm: invalid streamed runtime schedule")
	}
	role := "evaluator"
	if template.Recipient == plan.Kernel.ComputePeers[0] {
		role = "garbler"
	} else if template.Recipient != plan.Kernel.ComputePeers[1] {
		return zero, fmt.Errorf("formal-glm: invalid streamed runtime peer")
	}
	var ctx formalGLMPhase19Context
	var backend [32]byte
	backendSet := false
	keepBackend := false
	defer func() {
		if !keepBackend {
			clear(backend[:])
		}
	}()
	var store *formalGLMPhase19StreamStore
	defer func() {
		if store != nil {
			_ = store.Destroy()
		}
	}()

	for blockIndex := 0; blockIndex < plan.TotalBlocks; blockIndex++ {
		entry, err := manifest.Next()
		if err != nil {
			return zero, err
		}
		input := template
		input.BlockIndex = entry.BlockIndex
		input.IngressPaths = append([]string(nil), entry.IngressPaths...)
		local, err := formalGLMPhase19RuntimeLoadLocal(input)
		input.IngressPaths = nil
		if err != nil {
			return zero, err
		}
		if !backendSet {
			ctx, backend, backendSet = local.context, local.backend, true
			store, err = newFormalGLMPhase19StreamStore(
				workDir, maxStoreBytes, plan, ctx, template.Recipient, backend)
			if err != nil {
				formalGLMPhase19RuntimeZeroFanIn(&local.result)
				clear(local.backend[:])
				return zero, err
			}
		} else if local.context.ContextSHA256ForPhase19() !=
			ctx.ContextSHA256ForPhase19() ||
			!hmac.Equal(backend[:], local.backend[:]) {
			formalGLMPhase19RuntimeZeroFanIn(&local.result)
			clear(local.backend[:])
			return zero,
				fmt.Errorf("formal-glm: streamed blocks changed context or backend")
		} else {
			clear(local.backend[:])
		}
		var peerFanIn formalGLMPhase19FanInReceipt
		if err := formalGLMPhase19RuntimeExchangeJSON(
			rw, plan, ctx, backend, root, role, "fanin-receipt",
			blockIndex, local.result.Receipt, &peerFanIn); err != nil {
			formalGLMPhase19RuntimeZeroFanIn(&local.result)
			return zero, err
		}
		pair, err := formalGLMPhase19RuntimePair(
			ctx, local.result.Receipt, peerFanIn, backend)
		if err == nil {
			err = formalGLMPhase19VerifyLocalPair(
				plan, ctx, pair, local.result, backend)
		}
		if err != nil {
			formalGLMPhase19RuntimeZeroFanIn(&local.result)
			return zero, err
		}
		attempt := formalGLMPhase19RuntimeAttempt(
			root, "phase19-block", 0, blockIndex)
		session, err := formalGLMPhase19BlockSession(
			plan, ctx, pair, attempt, backend)
		var block formalGLMPhase19MaskedBlock
		if err == nil && role == "garbler" {
			block, err = formalGLMPhase19RunGarbler(
				rw, plan, ctx, pair, local.result, session, backend)
		} else if err == nil {
			block, err = formalGLMPhase19RunEvaluator(
				rw, plan, ctx, pair, local.result, session, backend)
		}
		formalGLMPhase19RuntimeZeroFanIn(&local.result)
		if err != nil {
			return zero, err
		}
		var peerReceipt formalGLMPhase19MaskedBlockReceipt
		if err := formalGLMPhase19RuntimeExchangeJSON(
			rw, plan, ctx, backend, root, role, "masked-block-receipt",
			blockIndex, block.Receipt, &peerReceipt); err != nil {
			exactGCZeroBigInts(block.tupleShares)
			clear(block.seal[:])
			return zero, err
		}
		var receiptPair formalGLMPhase19MaskedBlockReceiptPair
		if role == "garbler" {
			receiptPair, err = formalGLMPhase19PairMaskedBlockReceipts(
				ctx, pair, block.Receipt, peerReceipt, backend)
		} else {
			receiptPair, err = formalGLMPhase19PairMaskedBlockReceipts(
				ctx, pair, peerReceipt, block.Receipt, backend)
		}
		if err == nil {
			err = store.Append(block, receiptPair)
		}
		exactGCZeroBigInts(block.tupleShares)
		clear(block.seal[:])
		if err != nil {
			return zero, err
		}
	}
	if err := manifest.Finish(); err != nil {
		return zero, err
	}
	if store == nil || !backendSet {
		return zero, fmt.Errorf("formal-glm: empty streamed runtime schedule")
	}
	if err := store.Complete(); err != nil {
		return zero, err
	}
	summary, err := store.Summary()
	if err != nil {
		return zero, err
	}
	accumulator, err := formalGLMPhase19BuildStreamAccumulatorPlan(
		ctx, summary, backend)
	if err != nil {
		return zero, err
	}
	accAttempt := formalGLMPhase19RuntimeAttempt(
		root, "phase19-accumulator", 0, -1)
	execution, err := formalGLMPhase19RunBoundedAccumulatorStream(
		rw, plan, ctx, accumulator, store, accAttempt, role, backend)
	if err != nil {
		return zero, err
	}
	var peerExecution formalGLMPhase19ExecutionReceipt
	if err := formalGLMPhase19RuntimeExchangeJSON(
		rw, plan, ctx, backend, root, role, "execution-receipt", 0,
		execution.Receipt, &peerExecution); err != nil {
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
		return zero, err
	}

	checkpoint, beta, finalReceipts, err :=
		formalGLMPhase19RuntimeRunDurablePhase15Stream(
			rw, plan, ctx, backend, root, role, store, durable)
	if err != nil {
		return zero, err
	}
	var dpShares []*big.Int
	committed := false
	defer func() {
		if !committed {
			exactGCZeroBigInts(beta)
			exactGCZeroBigInts(dpShares)
		}
	}()
	dpBridge, err := buildFormalGLMPhase15DPBridgePlan(
		plan, finalReceipts, durable.Pins, durable.OutputLatticeBits)
	if err != nil {
		return zero, err
	}
	localBeta, err := formalGLMPhase15DPBridgeLoadLocalSource(
		checkpoint, finalReceipts, durable.Pins, dpBridge)
	if err != nil {
		return zero, err
	}
	bridgeAttempt := formalGLMPhase19RuntimeAttempt(
		root, "phase15-dp-bridge", 0, -1)
	bridgeSession, err := formalGLMPhase15DPBridgeSession(
		plan, dpBridge, bridgeAttempt, backend)
	if err != nil {
		exactGCZeroBigInts(localBeta)
		return zero, err
	}
	if template.Recipient == dpBridge.GarblerPeerName {
		dpShares, err = formalGLMPhase15RunDPBridgeGarblerWithExecution(
			rw, plan, dpBridge, bridgeSession, localBeta, execution.share)
	} else if template.Recipient == dpBridge.EvaluatorPeerName {
		dpShares, err = formalGLMPhase15RunDPBridgeEvaluatorWithExecution(
			rw, plan, dpBridge, bridgeSession, localBeta, execution.share)
	} else {
		err = fmt.Errorf("formal-glm: local peer has no DP bridge role")
	}
	exactGCZeroBigInts(localBeta)
	if err != nil {
		return zero, err
	}
	receiptDigest, err := formalGLMPhase15FinalReceiptPairDigest(finalReceipts)
	if err != nil {
		return zero, err
	}
	workerMessage := formalGLMPhase15AppendString(nil,
		"dsVert/formal-glm/runtime/phase15-worker-transcript/v1")
	workerMessage = formalGLMPhase15AppendString(
		workerMessage, ctx.ContextSHA256ForPhase19())
	workerMessage = formalGLMPhase15AppendString(
		workerMessage, accumulator.AccumulatorRoot)
	workerMessage = formalGLMPhase15AppendBytes(workerMessage, receiptDigest[:])
	workerDigest := sha256.Sum256(workerMessage)
	evidence := formalGLMPhase19ExecutionEvidence{
		Phase15ExecutionTranscriptSHA256: finalReceipts[0].TranscriptSHA256,
		FinalCheckpointTranscriptSHA256:  finalReceipts[0].TranscriptSHA256,
		WorkerTranscriptSHA256:           hex.EncodeToString(workerDigest[:]),
		CheckpointEvidenceSHA256:         hex.EncodeToString(receiptDigest[:]),
	}
	postToken, err := formalGLMPhase19BuildPostExecutionTokenFromSummary(
		plan, ctx, summary, accumulator, executionPair,
		finalReceipts, durable.Pins, evidence, backend)
	if err != nil {
		return zero, err
	}
	if err := store.Destroy(); err != nil {
		return zero, err
	}
	store = nil
	keepBackend = true
	committed = true
	return formalGLMPhase19RuntimeScheduleResult{
		context: ctx, executionSeal: execution, executionPair: executionPair,
		betaShares: beta, finalReceipts: finalReceipts,
		dpBridge: dpBridge, dpShares: dpShares, postToken: postToken,
		backend: backend,
	}, nil
}
