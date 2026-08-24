package main

// Private one-shot execution from a live registered job worker to its sealed
// Phase20 terminal owner. The caller supplies only Rock-local capabilities;
// no path, key, runtime, raw output, or transport leaves this package seam.

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"time"
)

const (
	formalGLMRegisteredPhase20JobIngressKeyVersionV1 = "dsvert-formal-glm-registered-phase20-ingress-key-v1"
	formalGLMRegisteredPhase20JobIngressKeyPurposeV1 = "formal_glm_registered_phase20_recipient_ingress_mac_v1"
	formalGLMRegisteredPhase20JobIngressKeyDomainV1  = "dsVert/formal-glm/registered-phase20/ingress-key/v1"
)

// The outer ingress MAC is recipient-bound and derives from the already
// authenticated compute-pair backend. It therefore needs no caller-provided
// secret or second durable key slot.
type formalGLMRegisteredPhase20JobIngressKeyInputV1 struct {
	Version                       string `json:"version"`
	Purpose                       string `json:"purpose"`
	ArtifactID                    string `json:"artifact_id"`
	SourceContractCoreSHA256      string `json:"source_contract_core_sha256"`
	SourceContractSHA256          string `json:"source_contract_sha256"`
	RegisteredExecutionPlanSHA256 string `json:"registered_execution_plan_sha256"`
	PinsetSHA256                  string `json:"pinset_sha256"`
	SemanticRootSHA256            string `json:"semantic_root_sha256"`
	GlobalMaterializationRoot     string `json:"global_materialization_root_sha256"`
	Recipient                     string `json:"recipient"`
	RecipientTicketSHA256         string `json:"recipient_ticket_sha256"`
}

func formalGLMRegisteredPhase20JobIngressKeyV1(
	backend [32]byte,
	record formalGLMRegisteredPhase19BindingRecordV1,
	recipient string,
) ([32]byte, error) {
	var zero [32]byte
	binding := record.Binding
	if !formalGLMPhase19KeyValid(backend) ||
		record.Version != formalGLMRegisteredPhase19BindingRecordVersion ||
		record.Purpose != formalGLMRegisteredPhase19BindingRecordPurpose ||
		!formalGLMIsSHA256(binding.ArtifactID) ||
		!formalGLMIsSHA256(binding.SourceContractCoreSHA256) ||
		!formalGLMIsSHA256(binding.SourceContractSHA256) ||
		!formalGLMIsSHA256(binding.RegisteredExecutionPlanSHA256) ||
		!formalGLMIsSHA256(binding.PinsetSHA256) ||
		!formalGLMIsSHA256(binding.SemanticRootSHA256) ||
		!formalGLMIsSHA256(binding.GlobalMaterializationRootSHA256) ||
		binding.ReceiptSetSHA256 != record.ReceiptSet.ReceiptSetSHA256 ||
		binding.GlobalMaterializationRootSHA256 != record.ReceiptSet.GlobalMaterializationRootSHA256 ||
		len(binding.DesignatedComputePeers) != 2 ||
		len(binding.RecipientBindings) != 2 {
		return zero, fmt.Errorf("formal-glm registered Phase20 job compute: invalid ingress key binding")
	}
	recipientIndex := -1
	for index, peer := range binding.DesignatedComputePeers {
		if peer == recipient {
			recipientIndex = index
		}
	}
	if recipientIndex < 0 || recipientIndex >= len(record.RecipientTickets) ||
		record.RecipientTickets[recipientIndex].RecipientName != recipient {
		return zero, fmt.Errorf("formal-glm registered Phase20 job compute: invalid ingress recipient")
	}
	ticketSHA256, err := formalGLMRegisteredPhase18RecipientTicketSHA256V1(
		record.RecipientTickets[recipientIndex])
	if err != nil ||
		binding.RecipientBindings[recipientIndex].RecipientName != recipient ||
		binding.RecipientBindings[recipientIndex].RecipientTicketSHA256 != ticketSHA256 {
		return zero, fmt.Errorf("formal-glm registered Phase20 job compute: invalid ingress ticket")
	}
	encoded, err := json.Marshal(formalGLMRegisteredPhase20JobIngressKeyInputV1{
		Version:                       formalGLMRegisteredPhase20JobIngressKeyVersionV1,
		Purpose:                       formalGLMRegisteredPhase20JobIngressKeyPurposeV1,
		ArtifactID:                    binding.ArtifactID,
		SourceContractCoreSHA256:      binding.SourceContractCoreSHA256,
		SourceContractSHA256:          binding.SourceContractSHA256,
		RegisteredExecutionPlanSHA256: binding.RegisteredExecutionPlanSHA256,
		PinsetSHA256:                  binding.PinsetSHA256,
		SemanticRootSHA256:            binding.SemanticRootSHA256,
		GlobalMaterializationRoot:     binding.GlobalMaterializationRootSHA256,
		Recipient:                     recipient,
		RecipientTicketSHA256:         ticketSHA256,
	})
	if err != nil {
		return zero, err
	}
	defer clear(encoded)
	key := formalGLMPhase19MAC(
		backend, formalGLMRegisteredPhase20JobIngressKeyDomainV1, encoded)
	if !formalGLMPhase19KeyValid(key) {
		clear(key[:])
		return zero, fmt.Errorf("formal-glm registered Phase20 job compute: invalid ingress key")
	}
	return key, nil
}

func formalGLMRegisteredPhase20JobComputeValidateIngressV1(
	ingress *formalGLMRegisteredPhase18IngressStoreV3,
	snapshot formalGLMRegisteredPhase20JobComputeSnapshotV1,
	key [32]byte,
) error {
	if ingress == nil || snapshot.attempts == nil {
		return fmt.Errorf("formal-glm registered Phase20 job compute: ingress unavailable")
	}
	snapshot.attempts.mu.Lock()
	attemptRoot := snapshot.attempts.root
	snapshot.attempts.mu.Unlock()
	ingress.mu.Lock()
	valid := ingress.root != nil &&
		formalGLMRegisteredPhase19ScheduleTailSameRootV1(attemptRoot, ingress.root) &&
		ingress.recipient == snapshot.peer &&
		ingress.localKey == key &&
		ingress.expectedGlobalMaterializationRoot ==
			snapshot.record.ReceiptSet.GlobalMaterializationRootSHA256 &&
		reflect.DeepEqual(ingress.contract, snapshot.contract) &&
		reflect.DeepEqual(ingress.pins, snapshot.pins)
	ingress.mu.Unlock()
	if !valid {
		return fmt.Errorf("formal-glm registered Phase20 job compute: ingress binding mismatch")
	}
	return nil
}

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
	ingressKey, err := formalGLMRegisteredPhase20JobIngressKeyV1(
		backend, snapshot.record, snapshot.peer)
	if err != nil {
		return err
	}
	defer clear(ingressKey[:])
	if err := formalGLMRegisteredPhase20JobComputeValidateIngressV1(
		ingress, snapshot, ingressKey); err != nil {
		return err
	}
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
