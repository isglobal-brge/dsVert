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
	"path/filepath"
	"reflect"
	"sync"
)

const formalGLMRegisteredPhase20JobControlHostVersionV1 = "dsvert-formal-glm-registered-phase20-job-control-host-v1"

// The bootstrap is server-local sensitive input.  It is intentionally not a
// public command DTO: a future Rock reader must strictly decode it from an
// owner-only file before starting a host process.
type formalGLMRegisteredPhase20JobControlHostConfigV1 struct {
	Version              string                                                 `json:"version"`
	Contract             formalGLMSourceContractV1                              `json:"contract"`
	Record               formalGLMRegisteredPhase19BindingRecordV1              `json:"record"`
	Pins                 map[string]ed25519.PublicKey                           `json:"pins"`
	Peer                 string                                                 `json:"peer"`
	Signing              ed25519.PrivateKey                                     `json:"signing"`
	SamplerAuthorityRoot [32]byte                                               `json:"sampler_authority_root"`
	Start                formalGLMRegisteredPhase20JobStartV1                   `json:"start"`
	Publication          *formalGLMRegisteredPhase21PublicationContextV1        `json:"publication,omitempty"`
	Phase16Policy        *formalGLMRegisteredPhase21PostSelectedPhase16PolicyV1 `json:"phase16_policy,omitempty"`
}

// All fields stay private so this handle marshals to `{}`.  The owner itself
// remains private too: callers receive only the same opaque frames that can
// cross the authenticated peer relay.
type formalGLMRegisteredPhase20JobControlHostV1 struct {
	mu                   sync.Mutex
	ops                  sync.WaitGroup
	owner                *formalGLMRegisteredPhase20JobOwnerV1
	publication          *formalGLMRegisteredPhase21PublicationContextV1
	phase16Policy        *formalGLMRegisteredPhase21PostSelectedPhase16PolicyV1
	samplerAuthorityRoot [32]byte
	stage                *formalGLMRegisteredPhase21StageTaskV1
	closed               bool
	closeDone            chan struct{}
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
	clear(config.SamplerAuthorityRoot[:])
	config.Start = formalGLMRegisteredPhase20JobStartV1{}
	formalGLMRegisteredPhase21PublicationContextClearV1(config.Publication)
	config.Publication = nil
	formalGLMRegisteredPhase21PostSelectedPhase16PolicyClearV1(config.Phase16Policy)
	config.Phase16Policy = nil
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
	if config.Publication != nil &&
		formalGLMRegisteredPhase21PublicationContextValidateV1(
			*config.Publication, config.Contract, config.Pins) != nil {
		return fmt.Errorf("formal-glm registered Phase20 job host: invalid publication context")
	}
	if config.Phase16Policy != nil &&
		(config.Publication == nil ||
			formalGLMRegisteredPhase21ValidatePostSelectedPhase16PolicyV1(
				*config.Phase16Policy, config.Contract, config.Pins) != nil) {
		return fmt.Errorf("formal-glm registered Phase20 job host: invalid Phase16 policy")
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
	var zeroRoot [32]byte
	if config.Publication == nil {
		if config.SamplerAuthorityRoot != zeroRoot {
			return fmt.Errorf("formal-glm registered Phase20 job host: unexpected sampler authority root")
		}
		return nil
	}
	stageReady, err := formalGLMRegisteredPhase21PublicationStageInputsV1(
		*config.Publication)
	if err != nil {
		return fmt.Errorf("formal-glm registered Phase20 job host: invalid publication context")
	}
	if !stageReady && config.Phase16Policy == nil {
		if config.SamplerAuthorityRoot != zeroRoot {
			return fmt.Errorf("formal-glm registered Phase20 job host: unexpected sampler authority root")
		}
		return nil
	}
	authority, err := formalGLMPhase21RockAuthority(
		config.Publication.SamplerContract.Artifact, config.Peer)
	if err != nil || authority.PeerName != config.Peer ||
		config.SamplerAuthorityRoot == zeroRoot {
		return fmt.Errorf("formal-glm registered Phase20 job host: invalid sampler authority root")
	}
	_, commitment, err := formalGLMPhase21SamplerV2Derive(
		config.SamplerAuthorityRoot, config.Publication.SamplerContract.ArtifactID,
		config.Publication.SamplerContract.SamplerMode, authority.Role,
		authority.PeerName, authority.PeerID)
	if err != nil || authority.Role != config.Publication.SamplerContract.Artifact.NoiseAuthorities[local].Role ||
		!reflect.DeepEqual(commitment, config.Publication.SamplerContract.NoiseCommitments[local]) {
		return fmt.Errorf("formal-glm registered Phase20 job host: invalid sampler authority root")
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
	var publication *formalGLMRegisteredPhase21PublicationContextV1
	if cloned.Publication != nil {
		copied, copyErr := formalGLMRegisteredPhase21PublicationContextCloneV1(
			*cloned.Publication, cloned.Contract, cloned.Pins)
		if copyErr != nil {
			return nil, copyErr
		}
		publication = &copied
	}
	var phase16Policy *formalGLMRegisteredPhase21PostSelectedPhase16PolicyV1
	if cloned.Phase16Policy != nil {
		copied := *cloned.Phase16Policy
		copied.ReceiptReferences = append(
			[]jointDPBiomedicalGaussianReceiptReference(nil), copied.ReceiptReferences...)
		copied.CustodianSignatures = make(
			[]jointDPBiomedicalGaussianSignature, len(cloned.Phase16Policy.CustodianSignatures))
		for index, signature := range cloned.Phase16Policy.CustodianSignatures {
			copied.CustodianSignatures[index] = jointDPBiomedicalGaussianSignature{
				Signer: signature.Signer, Signature: append([]byte(nil), signature.Signature...),
			}
		}
		phase16Policy = &copied
	}
	clearPublication := func() {
		formalGLMRegisteredPhase21PublicationContextClearV1(publication)
		publication = nil
		formalGLMRegisteredPhase21PostSelectedPhase16PolicyClearV1(phase16Policy)
		phase16Policy = nil
	}
	attempts, err := newFormalGLMRegisteredPhase19AttemptStoreV1(
		rockRoot, cloned.Record, cloned.Contract, cloned.Pins, cloned.Peer, cloned.Signing)
	if err != nil {
		clearPublication()
		return nil, err
	}
	keys, err := newFormalGLMRegisteredPhase20JobKeyProviderV1(
		rockRoot, cloned.Contract, cloned.Pins, cloned.Record, cloned.Peer)
	if err != nil {
		attempts.Close()
		clearPublication()
		return nil, err
	}
	owner, err := newFormalGLMRegisteredPhase20JobOwnerV1(attempts, keys, cloned.Start)
	if err != nil {
		_ = keys.Close()
		attempts.Close()
		clearPublication()
		return nil, err
	}
	return &formalGLMRegisteredPhase20JobControlHostV1{
		owner: owner, publication: publication, phase16Policy: phase16Policy,
		samplerAuthorityRoot: cloned.SamplerAuthorityRoot,
	}, nil
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

// HealthV1 proves only that this private host is still open.  It deliberately
// does not advance the worker, transport, heartbeat or attempt state.
func (host *formalGLMRegisteredPhase20JobControlHostV1) HealthV1() error {
	_, done, err := host.beginOpV1()
	if err != nil {
		return err
	}
	done()
	return nil
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

// RunTerminalV1 completes the authenticated two-party selection after compute.
// Its only output is the encrypted handoff commitment; the selected source,
// DP share, paths and keys remain Rock-local.
func (host *formalGLMRegisteredPhase20JobControlHostV1) RunTerminalV1() (
	formalGLMPhase20HandoffCommit, error,
) {
	var zero formalGLMPhase20HandoffCommit
	owner, done, err := host.beginOpV1()
	if err != nil {
		return zero, err
	}
	defer done()
	commit, err := owner.RunTerminalV1()
	if err != nil {
		return zero, err
	}
	if err := host.persistSelectedPublicationAssetsV1(owner); err != nil {
		return zero, err
	}
	return commit, nil
}

// persistSelectedPublicationAssetsV1 makes the signed Phase21 inputs
// restartable only after the Phase20 terminal selected the encrypted handoff.
// It writes no DP share, private key, backend key, or scheduler result.
func (host *formalGLMRegisteredPhase20JobControlHostV1) persistSelectedPublicationAssetsV1(
	owner *formalGLMRegisteredPhase20JobOwnerV1,
) error {
	if host == nil || owner == nil {
		return fmt.Errorf("formal-glm registered Phase20 job host: publication unavailable")
	}
	host.mu.Lock()
	publication := host.publication
	host.mu.Unlock()
	if publication == nil {
		return nil
	}
	owner.mu.Lock()
	terminal := owner.terminal
	owner.mu.Unlock()
	if terminal == nil {
		return fmt.Errorf("formal-glm registered Phase20 job host: terminal unavailable")
	}
	terminal.mu.Lock()
	if terminal.closed || terminal.attempts == nil || terminal.attempts.root == nil {
		terminal.mu.Unlock()
		return fmt.Errorf("formal-glm registered Phase20 job host: terminal unavailable")
	}
	rockRoot, peer := terminal.attempts.root.Name(), terminal.peer
	contract := terminal.contract
	pins := formalGLMRegisteredPhase20TerminalClonePinsV1(terminal.pins)
	terminal.mu.Unlock()
	defer formalGLMRegisteredPhase20TerminalClearPinsV1(pins)
	context, err := formalGLMRegisteredPhase21PublicationContextCloneV1(
		*publication, contract, pins)
	if err != nil {
		return err
	}
	defer formalGLMRegisteredPhase21PublicationContextClearV1(&context)
	return formalGLMRegisteredPhase21PersistSelectedPublicationContextV1(
		terminal, filepath.Join(rockRoot, peer), context, contract, pins)
}

// formalGLMRegisteredPhase21PersistSelectedPublicationContextV1 validates a
// private Phase21 context against Selected before it reaches the durable
// lifecycle assets. The caller owns context and keeps it out of the command
// surface.
func formalGLMRegisteredPhase21PersistSelectedPublicationContextV1(
	terminal *formalGLMRegisteredPhase20TerminalOwnerV1,
	authorityRoot string,
	context formalGLMRegisteredPhase21PublicationContextV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) error {
	if terminal == nil || authorityRoot == "" {
		return fmt.Errorf("formal-glm registered Phase21 assets: terminal unavailable")
	}
	stageReady, err := formalGLMRegisteredPhase21PublicationStageInputsV1(context)
	if err != nil {
		return err
	}
	if stageReady {
		if err := formalGLMRegisteredPhase21ValidateSelectedStageInputsV1(terminal, context); err != nil {
			return err
		}
	}
	_, _, err = formalGLMRegisteredPhase21PersistPublicationAssetsV1(
		authorityRoot, context, contract, pins)
	return err
}

// formalGLMRegisteredPhase21ValidateSelectedStageInputsV1 admits the signed
// Phase16 inputs against the encrypted Selected handoff before they become
// restartable Phase21 assets. It executes no sampler draw and releases the
// rehydrated source immediately.
func formalGLMRegisteredPhase21ValidateSelectedStageInputsV1(
	terminal *formalGLMRegisteredPhase20TerminalOwnerV1,
	publication formalGLMRegisteredPhase21PublicationContextV1,
) error {
	if terminal == nil {
		return fmt.Errorf("formal-glm registered Phase21 assets: terminal unavailable")
	}
	terminal.mu.Lock()
	if terminal.closed || terminal.attempts == nil || terminal.jobKeys == nil || terminal.runtime == nil {
		terminal.mu.Unlock()
		return fmt.Errorf("formal-glm registered Phase21 assets: terminal unavailable")
	}
	attempts, keys, runtime := terminal.attempts, terminal.jobKeys, terminal.runtime
	semanticRoot, peer := terminal.record.Binding.SemanticRootSHA256, terminal.peer
	pins := formalGLMRegisteredPhase20TerminalClonePinsV1(terminal.pins)
	terminal.mu.Unlock()
	defer formalGLMRegisteredPhase20TerminalClearPinsV1(pins)
	if !formalGLMIsSHA256(semanticRoot) {
		return fmt.Errorf("formal-glm registered Phase21 assets: invalid selected handoff")
	}
	attempts.mu.Lock()
	rockRoot := ""
	if attempts.root != nil {
		rockRoot = attempts.root.Name()
	}
	attempts.mu.Unlock()
	keys.mu.Lock()
	storageRoot := keys.storageRoot
	keysValid := keys.validateLocked() == nil
	keys.mu.Unlock()
	runtime.mu.Lock()
	backend := runtime.backendKey
	runtime.mu.Unlock()
	defer clear(storageRoot[:])
	defer clear(backend[:])
	if rockRoot == "" || !keysValid {
		return fmt.Errorf("formal-glm registered Phase21 assets: selected handoff unavailable")
	}
	store, err := newFormalGLMPhase20HandoffStore(
		filepath.Join(rockRoot, peer, "formal-glm-phase20-handoff"), semanticRoot, peer,
		storageRoot, backend, pins)
	if err != nil {
		return err
	}
	defer store.close()
	runtimeState, _, err := formalGLMPhase21LoadAndAdmit(
		store, publication.Capsule, publication.Request,
		publication.BackendSignatures, publication.WorkerSignatures)
	if err != nil {
		return fmt.Errorf("formal-glm registered Phase21 assets: invalid Stage inputs")
	}
	runtimeState.clear()
	return nil
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
	publication := host.publication
	phase16Policy := host.phase16Policy
	stage := host.stage
	host.owner = nil
	host.publication = nil
	host.phase16Policy = nil
	host.stage = nil
	clear(host.samplerAuthorityRoot[:])
	host.closeDone = make(chan struct{})
	done := host.closeDone
	host.mu.Unlock()
	if stage != nil {
		_ = stage.abortV1()
	}
	host.ops.Wait()
	defer close(done)
	if owner == nil {
		formalGLMRegisteredPhase21PublicationContextClearV1(publication)
		formalGLMRegisteredPhase21PostSelectedPhase16PolicyClearV1(phase16Policy)
		return nil
	}
	err := owner.Close()
	formalGLMRegisteredPhase21PublicationContextClearV1(publication)
	formalGLMRegisteredPhase21PostSelectedPhase16PolicyClearV1(phase16Policy)
	return err
}
