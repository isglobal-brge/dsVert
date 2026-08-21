package main

// Private one-shot execution from a live registered job worker to its sealed
// Phase20 terminal owner. The caller supplies only Rock-local capabilities;
// no path, key, runtime, raw output, or transport leaves this package seam.

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"reflect"
	"time"
)

type formalGLMRegisteredPhase20JobComputeSnapshotV1 struct {
	controller *formalGLMRegisteredPhase20JobWorkerControllerV1
	transport  *formalGLMRegisteredPhase20JobTransportV1
	scratch    *os.Root
	record     formalGLMRegisteredPhase19BindingRecordV1
	contract   formalGLMSourceContractV1
	pins       map[string]ed25519.PublicKey
	attempts   *formalGLMRegisteredPhase19AttemptStoreV1
	jobKeys    *formalGLMRegisteredPhase20JobKeyProviderV1
	proposal   formalGLMRegisteredPhase19ClaimProposalV1
	accept     formalGLMRegisteredPhase19ClaimAcceptV1
	peer       string
	signing    ed25519.PrivateKey
	rockRoot   string
}

func (snapshot *formalGLMRegisteredPhase20JobComputeSnapshotV1) clearV1() {
	if snapshot == nil {
		return
	}
	clear(snapshot.signing)
	snapshot.signing = nil
	formalGLMRegisteredPhase19ScheduleTailClearPinsV1(snapshot.pins)
	snapshot.pins = nil
	snapshot.record = formalGLMRegisteredPhase19BindingRecordV1{}
	snapshot.contract = formalGLMSourceContractV1{}
	snapshot.proposal = formalGLMRegisteredPhase19ClaimProposalV1{}
	snapshot.accept = formalGLMRegisteredPhase19ClaimAcceptV1{}
	snapshot.controller, snapshot.transport, snapshot.scratch = nil, nil, nil
	snapshot.attempts, snapshot.jobKeys = nil, nil
	snapshot.peer, snapshot.rockRoot = "", ""
}

func formalGLMRegisteredPhase20JobComputePeerBoundV1(
	controller *formalGLMRegisteredPhase20JobWorkerControllerV1,
) (*formalGLMRegisteredPhase20JobTransportV1, error) {
	if controller == nil {
		return nil, fmt.Errorf("formal-glm registered Phase20 job compute: worker unavailable")
	}
	controller.mu.Lock()
	if controller.closed || controller.metadata == nil || controller.transport == nil {
		controller.mu.Unlock()
		return nil, fmt.Errorf("formal-glm registered Phase20 job compute: worker unavailable")
	}
	metadata, transport := controller.metadata, controller.transport
	controller.mu.Unlock()
	lock, err := metadata.acquireRelayLockV1()
	if err != nil {
		return nil, err
	}
	boundErr := metadata.peerBoundLockedV1()
	metadata.releaseRelayLockV1(lock)
	if boundErr != nil {
		return nil, boundErr
	}
	transport.mu.Lock()
	ready := !transport.closed && transport.peerEpochBound &&
		transport.state == formalGLMRegisteredPhase20JobRunningV1 &&
		transport.scratch != nil
	transport.mu.Unlock()
	if !ready {
		return nil, fmt.Errorf("formal-glm registered Phase20 job compute: peer epoch unavailable")
	}
	return transport, nil
}

func (owner *formalGLMRegisteredPhase20JobOwnerV1) computeSnapshotV1() (
	formalGLMRegisteredPhase20JobComputeSnapshotV1, error,
) {
	var zero formalGLMRegisteredPhase20JobComputeSnapshotV1
	if err := owner.closedV1(); err != nil || owner.computeStarted {
		if err != nil {
			return zero, err
		}
		return zero, fmt.Errorf("formal-glm registered Phase20 job compute: already claimed")
	}
	accepted, err := owner.activeV1()
	if err != nil {
		return zero, err
	}
	fence, err := owner.fenceV1(accepted.proposal.Binding.AttemptID)
	if err != nil {
		return zero, err
	}
	defer fence.Close()
	accepted, err = owner.activeV1()
	if err != nil {
		return zero, err
	}
	if owner.controller == nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 job compute: worker unavailable")
	}
	owner.controller.mu.Lock()
	controllerErr := formalGLMRegisteredPhase20JobControlControllerLockedV1(
		owner.controller, accepted)
	owner.controller.mu.Unlock()
	if controllerErr != nil || owner.controller.HeartbeatV1() != nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 job compute: worker unavailable")
	}
	transport, err := formalGLMRegisteredPhase20JobComputePeerBoundV1(owner.controller)
	if err != nil {
		return zero, err
	}
	transport.mu.Lock()
	scratch := transport.scratch
	transport.mu.Unlock()
	if scratch == nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 job compute: worker unavailable")
	}
	owner.attempts.mu.Lock()
	valid := owner.attempts.root != nil && owner.attempts.localIndex >= 0 &&
		owner.attempts.localIndex < len(owner.attempts.contract.Core.RegisteredExecutionPlan.DesignatedComputePeers) &&
		owner.attempts.validateAcceptV1(accepted.proposal, accepted.accept) == nil
	peer := ""
	if valid {
		peer = owner.attempts.contract.Core.RegisteredExecutionPlan.DesignatedComputePeers[owner.attempts.localIndex]
	}
	record, contract := owner.attempts.record, owner.attempts.contract
	pins := formalGLMRegisteredPhase19ScheduleTailClonePinsV1(owner.attempts.pins)
	signing := append(ed25519.PrivateKey(nil), owner.attempts.signingKey...)
	rockRoot := ""
	if owner.attempts.root != nil {
		rockRoot = owner.attempts.root.Name()
	}
	owner.attempts.mu.Unlock()
	if !valid || rockRoot == "" || len(signing) != ed25519.PrivateKeySize {
		clear(signing)
		formalGLMRegisteredPhase19ScheduleTailClearPinsV1(pins)
		return zero, fmt.Errorf("formal-glm registered Phase20 job compute: invalid accepted owner")
	}
	owner.computeStarted = true
	owner.computeRunning = true
	owner.computeDone = make(chan struct{})
	return formalGLMRegisteredPhase20JobComputeSnapshotV1{
		controller: owner.controller, transport: transport, scratch: scratch, record: record,
		contract: contract, pins: pins, attempts: owner.attempts, jobKeys: owner.jobKeys,
		proposal: accepted.proposal, accept: accepted.accept, peer: peer,
		signing: signing, rockRoot: rockRoot,
	}, nil
}

func formalGLMRegisteredPhase20JobComputePairSecretsV1(
	provider *formalGLMRegisteredPhase19PairKeyProviderV1,
	snapshot formalGLMRegisteredPhase20JobComputeSnapshotV1,
) (backend, private [32]byte, err error) {
	if provider == nil {
		return backend, private, fmt.Errorf("formal-glm registered Phase20 job compute: pair key unavailable")
	}
	snapshot.attempts.mu.Lock()
	attemptRoot, localIndex := snapshot.attempts.root, snapshot.attempts.localIndex
	snapshot.attempts.mu.Unlock()
	provider.mu.Lock()
	valid := provider.root != nil && provider.localPeer == snapshot.peer &&
		provider.localIndex == localIndex &&
		formalGLMRegisteredPhase19ScheduleTailSameRootV1(attemptRoot, provider.root) &&
		reflect.DeepEqual(provider.context.contract, snapshot.contract) &&
		reflect.DeepEqual(provider.context.pins, snapshot.pins)
	if valid {
		backend, err = provider.deriveBackendLockedV1(
			snapshot.record.RecipientTickets,
			snapshot.record.Binding.SemanticRootSHA256)
	}
	if err == nil && valid {
		private, err = provider.readKeyLockedV1()
	}
	provider.mu.Unlock()
	if !valid || err != nil || !formalGLMPhase19KeyValid(backend) ||
		!formalGLMPhase19KeyValid(private) {
		clear(backend[:])
		clear(private[:])
		return backend, private, fmt.Errorf("formal-glm registered Phase20 job compute: pair key binding mismatch")
	}
	return backend, private, nil
}

func formalGLMRegisteredPhase20JobComputeHeartbeatV1(
	controller *formalGLMRegisteredPhase20JobWorkerControllerV1,
	stop <-chan struct{}, done chan<- struct{}, failure chan<- error,
) {
	defer close(done)
	ticker := time.NewTicker(formalGLMRegisteredPhase20JobHeartbeatTTLV1 / 4)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if err := controller.HeartbeatV1(); err != nil {
				failure <- err
				_ = controller.Close()
				return
			}
		}
	}
}

// RunComputeV1 consumes one prepared ingress owner with the live job worker.
// It leaves only a sealed terminal owner inside the JobOwner; no raw schedule
// result, DP share, stream store, key, or worker path is returned.
func (owner *formalGLMRegisteredPhase20JobOwnerV1) RunComputeV1(
	provider *formalGLMRegisteredPhase19PairKeyProviderV1,
	ingress *formalGLMRegisteredPhase18IngressStoreV3,
) (err error) {
	if owner == nil || ingress == nil {
		return fmt.Errorf("formal-glm registered Phase20 job compute: invalid input")
	}
	owner.mu.Lock()
	snapshot, err := owner.computeSnapshotV1()
	owner.mu.Unlock()
	if err != nil {
		return err
	}
	defer snapshot.clearV1()
	defer func() {
		owner.mu.Lock()
		owner.computeRunning = false
		if owner.computeDone != nil {
			close(owner.computeDone)
			owner.computeDone = nil
		}
		owner.mu.Unlock()
	}()
	backend, private, err := formalGLMRegisteredPhase20JobComputePairSecretsV1(
		provider, snapshot)
	if err != nil {
		return err
	}
	defer clear(backend[:])
	defer clear(private[:])
	runtime, err := newFormalGLMRegisteredPhase19EphemeralRuntimeV1(
		snapshot.record, snapshot.contract, snapshot.pins, backend)
	if err != nil {
		return err
	}
	runtimeTransferred := false
	defer func() {
		if !runtimeTransferred {
			runtime.Close()
		}
	}()
	runtime.mu.Lock()
	legacy := formalGLMRegisteredPhase19ClonePlanV1(runtime.legacyPlan)
	runtime.mu.Unlock()
	_, required, err := formalGLMPhase19StreamStoreRequiredBytes(legacy)
	if err != nil {
		return err
	}
	accumulator, err := newFormalGLMRegisteredPhase19AccumulatorStoreRootedV1(
		runtime, snapshot.peer, snapshot.scratch, "phase19-blocks", required)
	if err != nil {
		return err
	}
	stream, err := newFormalGLMRegisteredPhase19BlockStreamV1(
		runtime, snapshot.record, snapshot.contract, snapshot.pins, snapshot.attempts,
		snapshot.proposal, snapshot.accept, ingress, private[:], accumulator)
	if err != nil {
		_ = accumulator.Destroy()
		return err
	}
	pipeline, err := newFormalGLMRegisteredPhase19ComputePipelineV1(
		snapshot.rockRoot, stream, runtime, snapshot.record, snapshot.contract,
		snapshot.pins, snapshot.attempts, snapshot.proposal, snapshot.accept,
		snapshot.jobKeys, snapshot.signing)
	if err != nil {
		stream.Close()
		_ = accumulator.Destroy()
		return err
	}
	defer pipeline.Close()
	heartbeatStop := make(chan struct{})
	heartbeatDone := make(chan struct{})
	heartbeatFailure := make(chan error, 1)
	go formalGLMRegisteredPhase20JobComputeHeartbeatV1(
		snapshot.controller, heartbeatStop, heartbeatDone, heartbeatFailure)
	terminal, runErr := pipeline.RunV1(snapshot.transport)
	close(heartbeatStop)
	<-heartbeatDone
	select {
	case heartbeatErr := <-heartbeatFailure:
		if runErr != nil {
			runErr = fmt.Errorf("%w; formal-glm registered Phase20 job compute: heartbeat failed: %v", runErr, heartbeatErr)
		} else {
			runErr = fmt.Errorf("formal-glm registered Phase20 job compute: heartbeat failed: %w", heartbeatErr)
		}
	default:
	}
	ingress.Close()
	if runErr != nil {
		if terminal != nil {
			_ = terminal.Close()
		}
		return runErr
	}
	owner.mu.Lock()
	if owner.closed || owner.attempts != snapshot.attempts ||
		owner.jobKeys != snapshot.jobKeys {
		owner.mu.Unlock()
		_ = terminal.Close()
		return fmt.Errorf("formal-glm registered Phase20 job compute: owner closed")
	}
	owner.terminal = terminal
	owner.attempts, owner.jobKeys, owner.control = nil, nil, nil
	runtimeTransferred = true
	owner.mu.Unlock()
	return nil
}
