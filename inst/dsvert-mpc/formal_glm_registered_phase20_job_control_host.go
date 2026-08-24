package main

// A live registered job must keep exactly one controller and one exact-GC
// transport owner.  This small host is the process-local boundary used by a
// later Rock-backed command adapter: it reconstructs that owner only from a
// signed binding and exposes opaque control/relay operations, never stores,
// paths, keys, or a raw statistical result.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
)

const formalGLMRegisteredPhase20JobControlHostVersionV1 = "dsvert-formal-glm-registered-phase20-job-control-host-v1"

// The bootstrap is server-local sensitive input.  It is intentionally not a
// public command DTO: a future Rock reader must strictly decode it from an
// owner-only file before starting a host process.
type formalGLMRegisteredPhase20JobControlHostConfigV1 struct {
	Version  string                                    `json:"version"`
	Contract formalGLMSourceContractV1                 `json:"contract"`
	Record   formalGLMRegisteredPhase19BindingRecordV1 `json:"record"`
	Pins     map[string]ed25519.PublicKey              `json:"pins"`
	Peer     string                                    `json:"peer"`
	Signing  ed25519.PrivateKey                        `json:"signing"`
	Start    formalGLMRegisteredPhase20JobStartV1      `json:"start"`
}

// All fields stay private so this handle marshals to `{}`.  The owner itself
// remains private too: callers receive only the same opaque frames that can
// cross the authenticated peer relay.
type formalGLMRegisteredPhase20JobControlHostV1 struct {
	mu        sync.Mutex
	ops       sync.WaitGroup
	owner     *formalGLMRegisteredPhase20JobOwnerV1
	closed    bool
	closeDone chan struct{}
}

func formalGLMRegisteredPhase20JobControlHostCloneV1(
	config formalGLMRegisteredPhase20JobControlHostConfigV1,
) (formalGLMRegisteredPhase20JobControlHostConfigV1, error) {
	var cloned formalGLMRegisteredPhase20JobControlHostConfigV1
	encoded, err := json.Marshal(config)
	if err != nil {
		return cloned, err
	}
	defer clear(encoded)
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		return formalGLMRegisteredPhase20JobControlHostConfigV1{}, err
	}
	return cloned, nil
}

func formalGLMRegisteredPhase20JobControlHostClearConfigV1(
	config *formalGLMRegisteredPhase20JobControlHostConfigV1,
) {
	if config == nil {
		return
	}
	clear(config.Signing)
	config.Signing = nil
	for peer, pin := range config.Pins {
		clear(pin)
		delete(config.Pins, peer)
	}
	config.Pins = nil
	config.Contract = formalGLMSourceContractV1{}
	config.Record = formalGLMRegisteredPhase19BindingRecordV1{}
	config.Peer = ""
	config.Start = formalGLMRegisteredPhase20JobStartV1{}
	config.Version = ""
}

func formalGLMRegisteredPhase20JobControlHostValidateV1(
	config formalGLMRegisteredPhase20JobControlHostConfigV1,
) error {
	if config.Version != formalGLMRegisteredPhase20JobControlHostVersionV1 ||
		len(config.Pins) == 0 || len(config.Signing) != ed25519.PrivateKeySize ||
		formalGLMValidateSourceContractV1(config.Contract, config.Pins) != nil ||
		formalGLMValidateRegisteredPhase19BindingRecordV1(
			config.Record, config.Contract, config.Pins) != nil ||
		config.Start.ArtifactID != config.Record.Binding.ArtifactID ||
		config.Start.ReceiptSetSHA256 != config.Record.Binding.ReceiptSetSHA256 {
		return fmt.Errorf("formal-glm registered Phase20 job host: invalid bootstrap")
	}
	plan := config.Contract.Core.RegisteredExecutionPlan
	local := -1
	for index, peer := range plan.DesignatedComputePeers {
		if peer == config.Peer {
			local = index
		}
	}
	if local < 0 || local >= len(plan.NoiseAuthorities) ||
		len(plan.DesignatedComputePeers) != 2 || len(plan.NoiseAuthorities) != 2 ||
		plan.NoiseAuthorities[local].PeerName != config.Peer ||
		len(config.Pins[config.Peer]) != ed25519.PublicKeySize ||
		!bytes.Equal(config.Signing.Public().(ed25519.PublicKey), config.Pins[config.Peer]) {
		return fmt.Errorf("formal-glm registered Phase20 job host: invalid local authority")
	}
	return nil
}

func newFormalGLMRegisteredPhase20JobControlHostV1(
	rockRoot string,
	config formalGLMRegisteredPhase20JobControlHostConfigV1,
) (*formalGLMRegisteredPhase20JobControlHostV1, error) {
	cloned, err := formalGLMRegisteredPhase20JobControlHostCloneV1(config)
	if err != nil {
		return nil, err
	}
	defer formalGLMRegisteredPhase20JobControlHostClearConfigV1(&cloned)
	if err := formalGLMRegisteredPhase20JobControlHostValidateV1(cloned); err != nil {
		return nil, err
	}
	attempts, err := newFormalGLMRegisteredPhase19AttemptStoreV1(
		rockRoot, cloned.Record, cloned.Contract, cloned.Pins, cloned.Peer, cloned.Signing)
	if err != nil {
		return nil, err
	}
	keys, err := newFormalGLMRegisteredPhase20JobKeyProviderV1(
		rockRoot, cloned.Contract, cloned.Pins, cloned.Record, cloned.Peer)
	if err != nil {
		attempts.Close()
		return nil, err
	}
	owner, err := newFormalGLMRegisteredPhase20JobOwnerV1(attempts, keys, cloned.Start)
	if err != nil {
		_ = keys.Close()
		attempts.Close()
		return nil, err
	}
	return &formalGLMRegisteredPhase20JobControlHostV1{owner: owner}, nil
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) beginOpV1() (
	*formalGLMRegisteredPhase20JobOwnerV1, func(), error,
) {
	if host == nil {
		return nil, nil, fmt.Errorf("formal-glm registered Phase20 job host: unavailable")
	}
	host.mu.Lock()
	owner := host.owner
	closed := host.closed
	if !closed && owner != nil {
		host.ops.Add(1)
	}
	host.mu.Unlock()
	if closed || owner == nil {
		return nil, nil, fmt.Errorf("formal-glm registered Phase20 job host: closed")
	}
	return owner, host.ops.Done, nil
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) NegotiateV1(
	inbound []byte,
) (formalGLMRegisteredPhase20JobOwnerResultV1, error) {
	owner, done, err := host.beginOpV1()
	if err != nil {
		return formalGLMRegisteredPhase20JobOwnerResultV1{}, err
	}
	defer done()
	return owner.NegotiateV1(inbound)
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) StartOrInspectV1() (
	formalGLMRegisteredPhase20JobOwnerResultV1, error,
) {
	owner, done, err := host.beginOpV1()
	if err != nil {
		return formalGLMRegisteredPhase20JobOwnerResultV1{}, err
	}
	defer done()
	return owner.StartOrInspectV1()
}

func formalGLMRegisteredPhase20JobControlHostIngressBridgeV1(
	owner *formalGLMRegisteredPhase20JobOwnerV1,
) (*formalGLMRegisteredPhase20JobIngressBridgeV1, error) {
	if owner == nil {
		return nil, fmt.Errorf("formal-glm registered Phase20 job host: owner unavailable")
	}
	owner.mu.Lock()
	attempts := owner.attempts
	owner.mu.Unlock()
	if attempts == nil {
		return nil, fmt.Errorf("formal-glm registered Phase20 job host: compute is unavailable")
	}
	attempts.mu.Lock()
	if attempts.root == nil || attempts.localIndex < 0 ||
		attempts.localIndex >= len(attempts.contract.Core.RegisteredExecutionPlan.DesignatedComputePeers) {
		attempts.mu.Unlock()
		return nil, fmt.Errorf("formal-glm registered Phase20 job host: invalid attempt owner")
	}
	rockRoot := attempts.root.Name()
	peer := attempts.contract.Core.RegisteredExecutionPlan.DesignatedComputePeers[attempts.localIndex]
	record, contract := attempts.record, attempts.contract
	pins := formalGLMRegisteredPhase19ScheduleTailClonePinsV1(attempts.pins)
	attempts.mu.Unlock()
	bridge, err := newFormalGLMRegisteredPhase20JobIngressBridgeV1(
		rockRoot, peer, record, contract, pins)
	formalGLMRegisteredPhase19ScheduleTailClearPinsV1(pins)
	if err != nil {
		return nil, err
	}
	return bridge, nil
}

// RunComputeV1 finalizes only the existing signed pending pairs and then
// executes the registered job. It returns no schedule result, DP share,
// store, path, or key.
func (host *formalGLMRegisteredPhase20JobControlHostV1) RunComputeV1() error {
	owner, done, err := host.beginOpV1()
	if err != nil {
		return err
	}
	defer done()
	bridge, err := formalGLMRegisteredPhase20JobControlHostIngressBridgeV1(owner)
	if err != nil {
		return err
	}
	defer bridge.Close()
	if _, _, err := bridge.FinalizeV1(); err != nil {
		return err
	}
	provider, ingress, err := bridge.ComputeInputsV1()
	if err != nil {
		return err
	}
	return owner.RunComputeV1(provider, ingress)
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) JobRefV1() (
	formalGLMRegisteredPhase20JobRefV1, []byte, error,
) {
	owner, done, err := host.beginOpV1()
	if err != nil {
		return formalGLMRegisteredPhase20JobRefV1{}, nil, err
	}
	defer done()
	return owner.JobRefV1()
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) BindPeerJobRefV1(
	encoded []byte,
) error {
	owner, done, err := host.beginOpV1()
	if err != nil {
		return err
	}
	defer done()
	return owner.BindPeerJobRefV1(encoded)
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) HeartbeatV1() error {
	owner, done, err := host.beginOpV1()
	if err != nil {
		return err
	}
	defer done()
	return owner.HeartbeatV1()
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) transportV1(
	ref formalGLMRegisteredPhase20JobRefV1,
) (*formalGLMRegisteredPhase20JobTransportV1, func(), error) {
	owner, done, err := host.beginOpV1()
	if err != nil {
		return nil, nil, err
	}
	owner.mu.Lock()
	controller := owner.controller
	owner.mu.Unlock()
	if controller == nil {
		done()
		return nil, nil, fmt.Errorf("formal-glm registered Phase20 job host: controller unavailable")
	}
	controller.mu.Lock()
	transport := controller.transport
	controller.mu.Unlock()
	if transport == nil {
		done()
		return nil, nil, fmt.Errorf("formal-glm registered Phase20 job host: transport unavailable")
	}
	transport.mu.Lock()
	valid := !transport.closed && !ref.ProductionReady &&
		reflect.DeepEqual(ref, transport.ref)
	transport.mu.Unlock()
	if !valid {
		done()
		return nil, nil, fmt.Errorf("formal-glm registered Phase20 job host: JobRef mismatch")
	}
	return transport, done, nil
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) PollV1(
	ref formalGLMRegisteredPhase20JobRefV1, acknowledged int64,
) (formalGLMRegisteredPhase20JobPollResultV1, error) {
	transport, done, err := host.transportV1(ref)
	if err != nil {
		return formalGLMRegisteredPhase20JobPollResultV1{}, err
	}
	defer done()
	return transport.Poll(acknowledged)
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) RelayV1(
	ref formalGLMRegisteredPhase20JobRefV1,
	chunk formalGLMRegisteredPhase20RelayChunkV1,
) (int64, error) {
	transport, done, err := host.transportV1(ref)
	if err != nil {
		return 0, err
	}
	defer done()
	return transport.Relay(chunk)
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) Close() error {
	if host == nil {
		return nil
	}
	host.mu.Lock()
	if host.closed {
		done := host.closeDone
		host.mu.Unlock()
		if done != nil {
			<-done
		}
		return nil
	}
	host.closed = true
	owner := host.owner
	host.owner = nil
	host.closeDone = make(chan struct{})
	done := host.closeDone
	host.mu.Unlock()
	host.ops.Wait()
	defer close(done)
	if owner == nil {
		return nil
	}
	return owner.Close()
}
