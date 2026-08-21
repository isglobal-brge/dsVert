package main

// Private one-shot continuation from the registered block stream to the
// Phase20 terminal draft. It retains the accumulator hand-off, legacy schedule
// result, and canonical DP share entirely inside this package.

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"reflect"
	"sync"
)

type formalGLMRegisteredPhase19ComputePipelineV1 struct {
	mu sync.Mutex

	rockRoot string
	stream   *formalGLMRegisteredPhase19BlockStreamV1
	runtime  *formalGLMRegisteredPhase19EphemeralRuntimeV1
	record   formalGLMRegisteredPhase19BindingRecordV1
	contract formalGLMSourceContractV1
	pins     map[string]ed25519.PublicKey
	attempts *formalGLMRegisteredPhase19AttemptStoreV1
	proposal formalGLMRegisteredPhase19ClaimProposalV1
	accept   formalGLMRegisteredPhase19ClaimAcceptV1
	jobKeys  *formalGLMRegisteredPhase20JobKeyProviderV1
	signing  ed25519.PrivateKey
	peer     string
	role     string
	root     [32]byte

	claimed        bool
	running        bool
	finished       bool
	closeRequested bool
	closed         bool
}

func newFormalGLMRegisteredPhase19ComputePipelineV1(
	rockRoot string,
	stream *formalGLMRegisteredPhase19BlockStreamV1,
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
	attempts *formalGLMRegisteredPhase19AttemptStoreV1,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	jobKeys *formalGLMRegisteredPhase20JobKeyProviderV1,
	signing ed25519.PrivateKey,
) (*formalGLMRegisteredPhase19ComputePipelineV1, error) {
	if stream == nil || runtime == nil || attempts == nil || jobKeys == nil ||
		proposal.Binding != accept.Binding || len(signing) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("formal-glm registered Phase19 compute pipeline: invalid preparation")
	}
	root, err := formalGLMPhase19ScheduleDecodeHex32(
		proposal.Binding.ScheduleRootSHA256, "root")
	if err != nil {
		return nil, err
	}
	defer clear(root[:])
	runtime.mu.Lock()
	runtimeErr := runtime.validateLocked()
	if runtimeErr == nil {
		runtimeErr = formalGLMRegisteredPhase20ValidatePlanLockedV1(
			runtime, contract, pins)
	}
	context := formalGLMRegisteredPhase19CloneContextV1(runtime.context)
	runtime.mu.Unlock()
	if runtimeErr != nil {
		return nil, runtimeErr
	}
	stream.mu.Lock()
	streamOK := !stream.claimed && !stream.running && !stream.succeeded &&
		!stream.closed && stream.runtime == runtime &&
		reflect.DeepEqual(stream.record, record) && stream.accumulator != nil &&
		stream.rootAttempt == root
	peer := stream.peer
	streamRole := stream.role
	stream.mu.Unlock()
	if !streamOK {
		return nil, fmt.Errorf("formal-glm registered Phase19 compute pipeline: invalid block stream")
	}
	role, err := formalGLMRegisteredPhase19AccumulatorRoleV1(context, peer)
	if err != nil || role != streamRole {
		return nil, fmt.Errorf("formal-glm registered Phase19 compute pipeline: block stream role mismatch")
	}
	attempts.mu.Lock()
	attemptOK := attempts.root != nil && attempts.localIndex >= 0 &&
		attempts.localIndex < len(context.ComputePeers) &&
		context.ComputePeers[attempts.localIndex] == peer &&
		reflect.DeepEqual(attempts.record, record) &&
		reflect.DeepEqual(attempts.contract, contract) &&
		reflect.DeepEqual(attempts.pins, pins) &&
		attempts.validateAcceptV1(proposal, accept) == nil
	attemptRoot := attempts.root
	attempts.mu.Unlock()
	if !attemptOK {
		return nil, fmt.Errorf("formal-glm registered Phase19 compute pipeline: invalid accepted attempt")
	}
	if public, ok := signing.Public().(ed25519.PublicKey); !ok ||
		!bytes.Equal(public, pins[peer]) {
		return nil, fmt.Errorf("formal-glm registered Phase19 compute pipeline: invalid signer")
	}
	rock, err := formalGLMRegisteredPhase19OpenRockRootV1(rockRoot)
	if err != nil {
		return nil, err
	}
	rootMatches := formalGLMRegisteredPhase19ScheduleTailSameRootV1(rock, attemptRoot)
	_ = rock.Close()
	if !rootMatches {
		return nil, fmt.Errorf("formal-glm registered Phase19 compute pipeline: Rock root mismatch")
	}
	clonedRecord, recordErr := formalGLMRegisteredPhase20TerminalCloneV1(record)
	clonedContract, contractErr := formalGLMRegisteredPhase20TerminalCloneV1(contract)
	clonedProposal, proposalErr := formalGLMRegisteredPhase20TerminalCloneV1(proposal)
	clonedAccept, acceptErr := formalGLMRegisteredPhase20TerminalCloneV1(accept)
	if recordErr != nil || contractErr != nil || proposalErr != nil || acceptErr != nil {
		return nil, fmt.Errorf("formal-glm registered Phase19 compute pipeline: invalid private state")
	}
	pipeline := &formalGLMRegisteredPhase19ComputePipelineV1{
		rockRoot: rockRoot, stream: stream, runtime: runtime, record: clonedRecord,
		contract: clonedContract,
		pins:     formalGLMRegisteredPhase19ScheduleTailClonePinsV1(pins),
		attempts: attempts, proposal: clonedProposal, accept: clonedAccept,
		jobKeys: jobKeys, signing: append(ed25519.PrivateKey(nil), signing...),
		peer: peer, role: role, root: root,
	}
	return pipeline, nil
}

func (pipeline *formalGLMRegisteredPhase19ComputePipelineV1) clearLocked() {
	clear(pipeline.root[:])
	clear(pipeline.signing)
	pipeline.signing = nil
	formalGLMRegisteredPhase19ScheduleTailClearPinsV1(pipeline.pins)
	pipeline.pins = nil
	pipeline.record = formalGLMRegisteredPhase19BindingRecordV1{}
	pipeline.contract = formalGLMSourceContractV1{}
	pipeline.proposal = formalGLMRegisteredPhase19ClaimProposalV1{}
	pipeline.accept = formalGLMRegisteredPhase19ClaimAcceptV1{}
	pipeline.rockRoot = ""
	pipeline.stream, pipeline.runtime, pipeline.attempts, pipeline.jobKeys = nil, nil, nil, nil
}

func (pipeline *formalGLMRegisteredPhase19ComputePipelineV1) claimV1() error {
	if pipeline == nil {
		return fmt.Errorf("formal-glm registered Phase19 compute pipeline: unavailable")
	}
	pipeline.mu.Lock()
	defer pipeline.mu.Unlock()
	if pipeline.closed || pipeline.claimed || pipeline.running || pipeline.finished ||
		pipeline.stream == nil || pipeline.runtime == nil || pipeline.attempts == nil ||
		pipeline.jobKeys == nil || !formalGLMPhase19KeyValid(pipeline.root) {
		return fmt.Errorf("formal-glm registered Phase19 compute pipeline: unavailable")
	}
	pipeline.claimed = true
	pipeline.running = true
	return nil
}

func (pipeline *formalGLMRegisteredPhase19ComputePipelineV1) checkRunningV1() error {
	pipeline.mu.Lock()
	defer pipeline.mu.Unlock()
	if pipeline.closed || pipeline.closeRequested || !pipeline.running {
		return fmt.Errorf("formal-glm registered Phase19 compute pipeline: closed while running")
	}
	return nil
}

func (pipeline *formalGLMRegisteredPhase19ComputePipelineV1) finishV1(
	succeeded bool,
) {
	pipeline.mu.Lock()
	pipeline.running = false
	pipeline.finished = succeeded && !pipeline.closeRequested
	if !pipeline.finished {
		pipeline.closed = true
		pipeline.clearLocked()
	}
	pipeline.mu.Unlock()
}

func formalGLMRegisteredPhase19ComputePipelineDetachAccumulatorV1(
	stream *formalGLMRegisteredPhase19BlockStreamV1,
	requireSuccess bool,
) (*formalGLMRegisteredPhase19AccumulatorStoreV1, error) {
	if stream == nil {
		return nil, fmt.Errorf("formal-glm registered Phase19 compute pipeline: missing block stream")
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.running || stream.accumulator == nil || (requireSuccess && !stream.succeeded) {
		return nil, fmt.Errorf("formal-glm registered Phase19 compute pipeline: block stream is not transferable")
	}
	accumulator := stream.accumulator
	stream.accumulator = nil
	clear(stream.privateKey[:])
	clear(stream.rootAttempt[:])
	stream.runtime = nil
	stream.ingress = nil
	stream.record = formalGLMRegisteredPhase19BindingRecordV1{}
	stream.closed = true
	return accumulator, nil
}

func formalGLMRegisteredPhase19ComputePipelineExchangeV1[T any](
	rw io.ReadWriter,
	pipeline *formalGLMRegisteredPhase19ComputePipelineV1,
	label string,
	local T,
) (T, error) {
	var peer T
	pipeline.runtime.mu.Lock()
	err := pipeline.runtime.validateLocked()
	plan := formalGLMRegisteredPhase19ClonePlanV1(pipeline.runtime.legacyPlan)
	context := formalGLMRegisteredPhase19CloneContextV1(pipeline.runtime.context)
	backend := pipeline.runtime.backendKey
	pipeline.runtime.mu.Unlock()
	defer clear(backend[:])
	if err != nil {
		return peer, err
	}
	if err := formalGLMPhase19RuntimeExchangeJSON(
		rw, plan, context, backend, pipeline.root, pipeline.role, label, 0,
		local, &peer); err != nil {
		return peer, err
	}
	return peer, nil
}

func (pipeline *formalGLMRegisteredPhase19ComputePipelineV1) RunV1(
	rw io.ReadWriter,
) (terminal *formalGLMRegisteredPhase20TerminalOwnerV1, err error) {
	if rw == nil {
		return nil, fmt.Errorf("formal-glm registered Phase19 compute pipeline: nil peer channel")
	}
	if err := pipeline.claimV1(); err != nil {
		return nil, err
	}
	var accumulator *formalGLMRegisteredPhase19AccumulatorStoreV1
	var execution *formalGLMRegisteredPhase19AccumulatorExecutionV1
	var tail *formalGLMRegisteredPhase19ScheduleTailV1
	var result *formalGLMRegisteredPhase19ScheduleTailResultV1
	succeeded := false
	defer func() {
		if !succeeded {
			if result != nil {
				_ = result.Close()
			} else if tail != nil {
				_ = tail.Close()
			} else if execution != nil {
				_ = execution.Close()
			} else if accumulator != nil {
				_ = accumulator.Destroy()
			} else if pipeline.stream != nil {
				if owned, detachErr := formalGLMRegisteredPhase19ComputePipelineDetachAccumulatorV1(
					pipeline.stream, false); detachErr == nil {
					_ = owned.Destroy()
				}
				pipeline.stream.Close()
			}
			if terminal != nil {
				_ = terminal.Close()
				terminal = nil
			}
		}
		pipeline.finishV1(succeeded)
	}()
	if err = pipeline.stream.RunV1(rw); err != nil {
		return nil, err
	}
	if err = pipeline.checkRunningV1(); err != nil {
		return nil, err
	}
	accumulator, err = formalGLMRegisteredPhase19ComputePipelineDetachAccumulatorV1(
		pipeline.stream, true)
	if err != nil {
		return nil, err
	}
	accumulatorAttempt := formalGLMPhase19RuntimeAttempt(
		pipeline.root, "phase19-accumulator", 0, -1)
	execution, _, err = formalGLMRegisteredPhase19PrepareAccumulatorV1(
		pipeline.runtime, accumulator, accumulatorAttempt)
	clear(accumulatorAttempt[:])
	if err != nil {
		return nil, err
	}
	localSeal, err := formalGLMRegisteredPhase19RunAccumulatorPeerV1(rw, execution)
	if err != nil {
		return nil, err
	}
	defer localSeal.Close()
	remoteReceipt, err := formalGLMRegisteredPhase19ComputePipelineExchangeV1(
		rw, pipeline, "registered-phase19/accumulator", localSeal.Receipt)
	if err != nil {
		return nil, err
	}
	garblerReceipt, evaluatorReceipt := localSeal.Receipt, remoteReceipt
	if pipeline.role == "evaluator" {
		garblerReceipt, evaluatorReceipt = remoteReceipt, localSeal.Receipt
	}
	pair, err := formalGLMRegisteredPhase19PairAccumulatorReceiptsV1(
		execution, garblerReceipt, evaluatorReceipt)
	if err != nil {
		return nil, err
	}
	defer pair.Close()
	if err = pipeline.checkRunningV1(); err != nil {
		return nil, err
	}
	tail, err = newFormalGLMRegisteredPhase19ScheduleTailV1(
		pipeline.rockRoot, pipeline.runtime, pipeline.record, pipeline.contract,
		pipeline.pins, pipeline.attempts, pipeline.proposal, pipeline.accept,
		pipeline.jobKeys, execution, &localSeal, &pair, pipeline.signing)
	if err != nil {
		return nil, err
	}
	execution, accumulator = nil, nil
	result, err = formalGLMRegisteredPhase19RunScheduleTailPeerV1(rw, tail)
	if err != nil {
		return nil, err
	}
	tail = nil
	evidence, err := result.BuildPreparedEvidenceV1(
		pipeline.runtime, pipeline.record, pipeline.contract, pipeline.pins)
	result = nil
	if err != nil {
		return nil, err
	}
	if err = formalGLMRegisteredPhase20ExchangeComputeReadyV1(
		rw, pipeline.runtime, pipeline.record, pipeline.contract, pipeline.pins,
		pipeline.accept, evidence); err != nil {
		return nil, err
	}
	if err = pipeline.checkRunningV1(); err != nil {
		return nil, err
	}
	defer func() {
		evidence.CanonicalDPShare = ""
		for index := range evidence.FinalReceipts {
			clear(evidence.FinalReceipts[index].Signature)
		}
	}()
	terminal, err = newFormalGLMRegisteredPhase20TerminalOwnerV1(
		pipeline.attempts, pipeline.jobKeys, pipeline.runtime,
		pipeline.proposal, pipeline.accept)
	if err != nil {
		return nil, err
	}
	pipeline.attempts, pipeline.jobKeys = nil, nil
	if _, err = terminal.SealLocalEvidenceV1(evidence); err != nil {
		return nil, err
	}
	if err = pipeline.checkRunningV1(); err != nil {
		return nil, err
	}
	succeeded = true
	pipeline.mu.Lock()
	pipeline.clearLocked()
	pipeline.mu.Unlock()
	return terminal, nil
}

func (pipeline *formalGLMRegisteredPhase19ComputePipelineV1) Close() error {
	if pipeline == nil {
		return nil
	}
	pipeline.mu.Lock()
	if pipeline.closed || pipeline.finished {
		pipeline.mu.Unlock()
		return nil
	}
	if pipeline.running {
		pipeline.closeRequested = true
		stream := pipeline.stream
		pipeline.mu.Unlock()
		if stream != nil {
			stream.Close()
		}
		return nil
	}
	stream := pipeline.stream
	pipeline.closed = true
	pipeline.clearLocked()
	pipeline.mu.Unlock()
	if stream != nil {
		if accumulator, err := formalGLMRegisteredPhase19ComputePipelineDetachAccumulatorV1(
			stream, false); err == nil {
			return accumulator.Destroy()
		}
		stream.Close()
	}
	return nil
}
