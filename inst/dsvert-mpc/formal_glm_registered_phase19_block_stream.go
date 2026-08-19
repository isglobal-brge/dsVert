package main

// One-block-at-a-time registered Phase19 compute path. It intentionally ends
// at the completed external-memory accumulator; the schedule tail owns the
// distinct optimizer, DP bridge, and terminal transitions.

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"reflect"
	"sync"
)

type formalGLMRegisteredPhase19BlockStreamV1 struct {
	mu sync.Mutex

	runtime     *formalGLMRegisteredPhase19EphemeralRuntimeV1
	record      formalGLMRegisteredPhase19BindingRecordV1
	ingress     *formalGLMRegisteredPhase18IngressStoreV3
	accumulator *formalGLMRegisteredPhase19AccumulatorStoreV1
	peer        string
	role        string
	rootAttempt [32]byte
	privateKey  [32]byte

	claimed        bool
	running        bool
	succeeded      bool
	closeRequested bool
	closed         bool
}

type formalGLMRegisteredPhase19BlockStreamSnapshotV1 struct {
	runtime     *formalGLMRegisteredPhase19EphemeralRuntimeV1
	record      formalGLMRegisteredPhase19BindingRecordV1
	ingress     *formalGLMRegisteredPhase18IngressStoreV3
	accumulator *formalGLMRegisteredPhase19AccumulatorStoreV1
	peer        string
	role        string
	rootAttempt [32]byte
	privateKey  [32]byte
}

func newFormalGLMRegisteredPhase19BlockStreamV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	ingress *formalGLMRegisteredPhase18IngressStoreV3,
	recipientPrivateKey []byte,
	accumulator *formalGLMRegisteredPhase19AccumulatorStoreV1,
) (*formalGLMRegisteredPhase19BlockStreamV1, error) {
	if runtime == nil || ingress == nil || accumulator == nil ||
		len(recipientPrivateKey) != 32 || proposal.Binding != accept.Binding {
		return nil, fmt.Errorf("formal-glm registered Phase19 block stream: invalid preparation")
	}
	runtime.mu.Lock()
	if err := runtime.validateLocked(); err != nil ||
		formalGLMRegisteredPhase20ValidatePlanLockedV1(runtime, contract, pins) != nil ||
		formalGLMRegisteredPhase20ValidateAttemptBindingLockedV1(
			runtime, record, contract, proposal.Binding, pins) != nil {
		runtime.mu.Unlock()
		return nil, fmt.Errorf("formal-glm registered Phase19 block stream: invalid execution binding")
	}
	semanticRoot := runtime.semanticRootSHA256
	receiptSet := runtime.receiptSetSHA256
	registeredPlan := runtime.registeredExecutionPlanSHA256
	context := formalGLMRegisteredPhase19CloneContextV1(runtime.context)
	runtime.mu.Unlock()

	accumulator.mu.Lock()
	accumulatorErr := accumulator.validateLocked()
	peer := accumulator.peer
	validAccumulator := accumulatorErr == nil &&
		accumulator.state == formalGLMRegisteredPhase19AccumulatorStoreOpenV1 &&
		accumulator.semanticRootSHA256 == semanticRoot &&
		accumulator.receiptSetSHA256 == receiptSet &&
		accumulator.registeredExecutionPlanSHA256 == registeredPlan
	accumulator.mu.Unlock()
	if !validAccumulator {
		return nil, fmt.Errorf("formal-glm registered Phase19 block stream: accumulator binding mismatch")
	}
	ingress.mu.Lock()
	validIngress := ingress.root != nil && ingress.recipient == peer &&
		ingress.expectedGlobalMaterializationRoot ==
			record.Binding.GlobalMaterializationRootSHA256 &&
		ingress.context != nil && ingress.context.valid() &&
		reflect.DeepEqual(ingress.contract, contract) &&
		reflect.DeepEqual(ingress.pins, pins)
	ingress.mu.Unlock()
	if !validIngress {
		return nil, fmt.Errorf("formal-glm registered Phase19 block stream: ingress binding mismatch")
	}
	role, err := formalGLMRegisteredPhase19AccumulatorRoleV1(context, peer)
	if err != nil {
		return nil, err
	}
	rootAttempt, err := formalGLMPhase19ScheduleDecodeHex32(
		proposal.Binding.ScheduleRootSHA256, "root")
	if err != nil {
		return nil, err
	}
	stream := &formalGLMRegisteredPhase19BlockStreamV1{
		runtime: runtime, record: record, ingress: ingress, accumulator: accumulator,
		peer: peer, role: role, rootAttempt: rootAttempt,
	}
	copy(stream.privateKey[:], recipientPrivateKey)
	if !formalGLMPhase19KeyValid(stream.privateKey) {
		stream.Close()
		return nil, fmt.Errorf("formal-glm registered Phase19 block stream: invalid recipient key")
	}
	return stream, nil
}

func (stream *formalGLMRegisteredPhase19BlockStreamV1) claimV1() (
	formalGLMRegisteredPhase19BlockStreamSnapshotV1, error,
) {
	var zero formalGLMRegisteredPhase19BlockStreamSnapshotV1
	if stream == nil {
		return zero, fmt.Errorf("formal-glm registered Phase19 block stream: unavailable")
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.closed || stream.claimed || stream.running || stream.succeeded ||
		stream.runtime == nil || stream.ingress == nil || stream.accumulator == nil ||
		!formalGLMPhase19KeyValid(stream.rootAttempt) ||
		!formalGLMPhase19KeyValid(stream.privateKey) {
		return zero, fmt.Errorf("formal-glm registered Phase19 block stream: unavailable")
	}
	stream.claimed = true
	stream.running = true
	return formalGLMRegisteredPhase19BlockStreamSnapshotV1{
		runtime: stream.runtime, record: stream.record, ingress: stream.ingress,
		accumulator: stream.accumulator, peer: stream.peer, role: stream.role,
		rootAttempt: stream.rootAttempt, privateKey: stream.privateKey,
	}, nil
}

func (snapshot *formalGLMRegisteredPhase19BlockStreamSnapshotV1) clearV1() {
	if snapshot == nil {
		return
	}
	clear(snapshot.privateKey[:])
	clear(snapshot.rootAttempt[:])
	snapshot.runtime = nil
	snapshot.ingress = nil
	snapshot.accumulator = nil
}

func (stream *formalGLMRegisteredPhase19BlockStreamV1) checkRunningV1() error {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.closed || stream.closeRequested || !stream.running {
		return fmt.Errorf("formal-glm registered Phase19 block stream: closed while running")
	}
	return nil
}

func (stream *formalGLMRegisteredPhase19BlockStreamV1) finishV1(
	succeeded bool,
) error {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if !stream.running {
		return fmt.Errorf("formal-glm registered Phase19 block stream: invalid completion")
	}
	stream.running = false
	stream.succeeded = succeeded && !stream.closeRequested
	if stream.succeeded || stream.closeRequested {
		clear(stream.privateKey[:])
		clear(stream.rootAttempt[:])
		if stream.closeRequested {
			stream.closed = true
		}
	}
	if !stream.succeeded {
		return fmt.Errorf("formal-glm registered Phase19 block stream: incomplete execution")
	}
	return nil
}

func formalGLMRegisteredPhase19BlockStreamExchangeV1[T any](
	rw io.ReadWriter,
	snapshot formalGLMRegisteredPhase19BlockStreamSnapshotV1,
	label string,
	blockIndex int,
	local T,
) (T, error) {
	var peer T
	snapshot.runtime.mu.Lock()
	if err := snapshot.runtime.validateLocked(); err != nil {
		snapshot.runtime.mu.Unlock()
		return peer, err
	}
	plan := formalGLMRegisteredPhase19ClonePlanV1(snapshot.runtime.legacyPlan)
	context := formalGLMRegisteredPhase19CloneContextV1(snapshot.runtime.context)
	backend := snapshot.runtime.backendKey
	snapshot.runtime.mu.Unlock()
	defer clear(backend[:])
	if err := formalGLMPhase19RuntimeExchangeJSON(
		rw, plan, context, backend, snapshot.rootAttempt, snapshot.role,
		label, blockIndex, local, &peer); err != nil {
		return peer, err
	}
	return peer, nil
}

func (stream *formalGLMRegisteredPhase19BlockStreamV1) RunV1(
	rw io.ReadWriter,
) (err error) {
	if rw == nil {
		return fmt.Errorf("formal-glm registered Phase19 block stream: nil peer channel")
	}
	snapshot, err := stream.claimV1()
	if err != nil {
		return err
	}
	defer snapshot.clearV1()
	succeeded := false
	defer func() {
		finishErr := stream.finishV1(succeeded)
		if err == nil && finishErr != nil {
			err = finishErr
		}
	}()

	snapshot.runtime.mu.Lock()
	if runtimeErr := snapshot.runtime.validateLocked(); runtimeErr != nil {
		snapshot.runtime.mu.Unlock()
		return runtimeErr
	}
	plan := formalGLMRegisteredPhase19ClonePlanV1(snapshot.runtime.legacyPlan)
	context := formalGLMRegisteredPhase19CloneContextV1(snapshot.runtime.context)
	snapshot.runtime.mu.Unlock()
	if len(context.ComputePeers) != 2 || snapshot.peer != context.ComputePeers[0] &&
		snapshot.peer != context.ComputePeers[1] {
		return fmt.Errorf("formal-glm registered Phase19 block stream: invalid compute peer")
	}
	for blockIndex := 0; blockIndex < plan.TotalBlocks; blockIndex++ {
		if err := stream.checkRunningV1(); err != nil {
			return err
		}
		privateBlocks, loadErr := formalGLMLoadRegisteredPhase19PrivateBlockSetV1(
			snapshot.record, snapshot.ingress, snapshot.privateKey[:], blockIndex)
		if loadErr != nil {
			return loadErr
		}
		fanIn, fanInErr := formalGLMRegisteredPhase19FanInPrivateBlockSetV1(
			snapshot.runtime, privateBlocks, snapshot.peer, blockIndex)
		formalGLMRegisteredPhase19ClearPrivateBlocksV1(privateBlocks)
		if fanInErr != nil {
			return fanInErr
		}
		peerFanIn, exportErr := formalGLMRegisteredPhase19ExportFanInReceiptV1(
			snapshot.runtime, fanIn)
		if exportErr != nil {
			formalGLMRegisteredPhase19ClearFanInResultV1(&fanIn)
			return exportErr
		}
		remoteFanIn, exchangeErr := formalGLMRegisteredPhase19BlockStreamExchangeV1(
			rw, snapshot, "registered-phase19/fan-in", blockIndex, peerFanIn)
		if exchangeErr != nil {
			formalGLMRegisteredPhase19ClearFanInResultV1(&fanIn)
			return exchangeErr
		}
		blockAttempt := formalGLMPhase19RuntimeAttempt(
			snapshot.rootAttempt, "phase19-block", 0, blockIndex)
		execution, prepareErr := formalGLMRegisteredPhase19PrepareBlockExecutionV1(
			snapshot.runtime, fanIn, remoteFanIn, blockAttempt)
		clear(blockAttempt[:])
		formalGLMRegisteredPhase19ClearFanInResultV1(&fanIn)
		if prepareErr != nil {
			return prepareErr
		}
		masked, runErr := formalGLMRegisteredPhase19RunBlockPeerV1(rw, execution)
		if runErr != nil {
			execution.Close()
			return runErr
		}
		remoteMasked, exchangeErr := formalGLMRegisteredPhase19BlockStreamExchangeV1(
			rw, snapshot, "registered-phase19/masked", blockIndex, masked.Receipt)
		if exchangeErr != nil {
			masked.Close()
			execution.Close()
			return exchangeErr
		}
		garblerMasked, evaluatorMasked := masked.Receipt, remoteMasked
		if snapshot.role == "evaluator" {
			garblerMasked, evaluatorMasked = remoteMasked, masked.Receipt
		}
		pair, pairErr := formalGLMRegisteredPhase19PairMaskedReceiptsV1(
			execution, garblerMasked, evaluatorMasked)
		if pairErr == nil {
			pairErr = snapshot.accumulator.AppendRegisteredV1(masked, pair)
		}
		pair.Close()
		masked.Close()
		execution.Close()
		if pairErr != nil {
			return pairErr
		}
	}
	if err := snapshot.accumulator.CompleteV1(); err != nil {
		return err
	}
	succeeded = true
	return nil
}

func (stream *formalGLMRegisteredPhase19BlockStreamV1) Close() {
	if stream == nil {
		return
	}
	stream.mu.Lock()
	if stream.closed {
		stream.mu.Unlock()
		return
	}
	if stream.running {
		stream.closeRequested = true
		stream.mu.Unlock()
		return
	}
	clear(stream.privateKey[:])
	clear(stream.rootAttempt[:])
	stream.runtime = nil
	stream.ingress = nil
	stream.accumulator = nil
	stream.record = formalGLMRegisteredPhase19BindingRecordV1{}
	stream.closed = true
	stream.mu.Unlock()
}
