package main

// The registered host owns the only Phase21 sampler worker for its selected
// attempt.  This controller starts that existing Rock lifecycle action once
// and exposes only the encrypted exact-GC ranges through the already signed
// relay.  It never returns a DP share, a sampler root, a storage path, or a
// lifecycle secret.

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const (
	formalGLMRegisteredPhase21StageRootDomainV1 = "dsVert/formal-glm/registered-phase21/stage-root/v1"
	formalGLMRegisteredPhase21StageSecretFileV1 = "registered-phase21-stage-secret.json"
	formalGLMRegisteredPhase21StageMaxSpoolV1   = 64 << 20
	formalGLMRegisteredPhase21StageTTLV1        = 30

	formalGLMRegisteredPhase21StageRunningV1  = "running"
	formalGLMRegisteredPhase21StageCompleteV1 = "complete"
	formalGLMRegisteredPhase21StageFailedV1   = "failed"
)

// The status contains only a signed public lifecycle receipt.  Its producer
// stays private and JSON-marshals to {}.
type formalGLMRegisteredPhase21StageStatusV1 struct {
	State           string                           `json:"state"`
	Stage           *formalGLMPhase21RockStageRecord `json:"stage,omitempty"`
	ProductionReady bool                             `json:"production_ready"`
}

type formalGLMRegisteredPhase21StageHostStateV1 struct {
	stickyRoot         [32]byte
	phase20StorageRoot [32]byte
	backendKey         [32]byte
	authorityRoot      [32]byte
	authoritySeed      [32]byte
	transportRoot      [32]byte
	semanticRoot       string
	rockRoot           string
	spoolDir           string
	secretPath         string
	operation          formalGLMPhase21RockStageOperation
	peer               string
	remotePeer         string
	artifactID         string
	pins               map[string]ed25519.PublicKey
	signing            ed25519.PrivateKey
}

func formalGLMRegisteredPhase21StageValidateSpoolV1(
	root *os.Root, absolute string, segmentRoots [2]*os.Root,
) error {
	if err := formalGLMRegisteredPhase20JobTransportValidateRootV1(root, absolute); err != nil {
		return err
	}
	for _, name := range []string{
		"inbound.bin", "outbound.bin", "exchange.hb", "worker.hb",
		"inbound.state", "inbound.ack", "outbound.head", "outbound.ack",
	} {
		info, err := root.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm() != 0o600 || !exactGCPrivateOwnedRegular(info) {
			return fmt.Errorf("formal-glm registered Phase21 stage: unsafe local spool")
		}
	}
	for index, name := range []string{"inbound.segments", "outbound.segments"} {
		info, err := root.Lstat(name)
		pinned, pinErr := segmentRoots[index].Stat(".")
		if err != nil || pinErr != nil || !info.IsDir() ||
			info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 ||
			!formalFinalizerHandoffPrivateOwnedDirectory(info) || !os.SameFile(info, pinned) {
			return fmt.Errorf("formal-glm registered Phase21 stage: unsafe local spool")
		}
	}
	return exactGCPrepareWorkerSpool(absolute)
}

// formalGLMRegisteredPhase21StagePrepareSpoolV1 initializes the one clean
// exact-GC spool consumed by the existing Phase21 Stage action.  A partially
// created or already used spool is deliberately not repaired: it cannot be
// distinguished from an interrupted transcript and must fail closed.
func formalGLMRegisteredPhase21StagePrepareSpoolV1(
	authorityRoot, artifactID string,
) (string, error) {
	if !filepath.IsAbs(authorityRoot) || filepath.Clean(authorityRoot) != authorityRoot ||
		!formalGLMIsSHA256(artifactID) ||
		formalFinalizerHandoffEnsurePrivateDir(authorityRoot) != nil {
		return "", fmt.Errorf("formal-glm registered Phase21 stage: unsafe local spool")
	}
	root, err := os.OpenRoot(authorityRoot)
	if err != nil {
		return "", err
	}
	defer root.Close()
	const parent = "formal-glm-exact-gc-v2"
	if err := formalGLMPhase21EnsureRootPrivateDir(root, parent); err != nil {
		return "", err
	}
	relative := filepath.Join(parent, artifactID)
	created := false
	if err := root.Mkdir(relative, 0o700); err == nil {
		created = true
		if err := root.Chmod(relative, 0o700); err != nil {
			return "", err
		}
		if err := formalGLMPhase21RootSyncDir(root, relative); err != nil {
			return "", err
		}
	} else if !os.IsExist(err) {
		return "", err
	}
	spoolRoot, err := root.OpenRoot(relative)
	if err != nil {
		return "", err
	}
	defer spoolRoot.Close()
	spoolDir := filepath.Join(authorityRoot, relative)
	if err := formalGLMRegisteredPhase20JobTransportValidateRootV1(spoolRoot, spoolDir); err != nil {
		return "", err
	}
	if !created {
		var segmentRoots [2]*os.Root
		for index, directory := range []string{"inbound.segments", "outbound.segments"} {
			segmentRoots[index], err = spoolRoot.OpenRoot(directory)
			if err != nil {
				return "", err
			}
			defer segmentRoots[index].Close()
		}
		if err := formalGLMRegisteredPhase21StageValidateSpoolV1(
			spoolRoot, spoolDir, segmentRoots); err != nil {
			return "", fmt.Errorf("formal-glm registered Phase21 stage: existing spool: %w", err)
		}
		return spoolDir, nil
	}
	files := []struct {
		name string
		data []byte
	}{
		{"inbound.bin", nil}, {"outbound.bin", nil},
		{"exchange.hb", []byte(".")}, {"worker.hb", []byte(".")},
		{"inbound.state", []byte(exactGCInboundStateInitial)},
		{"inbound.ack", []byte("0")}, {"outbound.head", []byte("0")},
		{"outbound.ack", []byte("0")},
	}
	for _, file := range files {
		if err := formalGLMRegisteredPhase20JobTransportWriteInitialV1(
			spoolRoot, file.name, file.data); err != nil {
			return "", err
		}
	}
	var segmentRoots [2]*os.Root
	for index, directory := range []string{"inbound.segments", "outbound.segments"} {
		if err := spoolRoot.Mkdir(directory, 0o700); err != nil {
			return "", err
		}
		if err := spoolRoot.Chmod(directory, 0o700); err != nil {
			return "", err
		}
		segmentRoots[index], err = spoolRoot.OpenRoot(directory)
		if err != nil {
			return "", err
		}
		defer segmentRoots[index].Close()
	}
	if err := formalGLMPhase21RootSyncDir(spoolRoot, "state"); err != nil {
		return "", err
	}
	if err := formalGLMRegisteredPhase21StageValidateSpoolV1(
		spoolRoot, spoolDir, segmentRoots); err != nil {
		return "", fmt.Errorf("formal-glm registered Phase21 stage: initial spool: %w", err)
	}
	return spoolDir, nil
}

func (state *formalGLMRegisteredPhase21StageHostStateV1) clearV1() {
	if state == nil {
		return
	}
	clear(state.stickyRoot[:])
	clear(state.phase20StorageRoot[:])
	clear(state.backendKey[:])
	clear(state.authorityRoot[:])
	clear(state.authoritySeed[:])
	clear(state.transportRoot[:])
	clear(state.signing)
	state.signing = nil
	formalGLMRegisteredPhase20TerminalClearPinsV1(state.pins)
	*state = formalGLMRegisteredPhase21StageHostStateV1{}
}

// Derive independent local keys for the sticky store and handoff transport.
// The job-storage root stays Rock-local and is never used as a peer key.
func formalGLMRegisteredPhase21StageRootV1(
	storageRoot [32]byte, artifactID, peer, purpose string,
) [32]byte {
	mac := hmac.New(sha256.New, storageRoot[:])
	_, _ = mac.Write([]byte(formalGLMRegisteredPhase21StageRootDomainV1))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(purpose))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(artifactID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(peer))
	var root [32]byte
	copy(root[:], mac.Sum(nil))
	return root
}

func formalGLMRegisteredPhase21StageCloneRecordV1(
	record formalGLMPhase21RockStageRecord,
) (*formalGLMPhase21RockStageRecord, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	var cloned formalGLMPhase21RockStageRecord
	if err := formalGLMPhase21RockStrictDecode(encoded, &cloned); err != nil {
		return nil, err
	}
	return &cloned, nil
}

type formalGLMRegisteredPhase21StageTaskV1 struct {
	mu sync.Mutex

	running  bool
	complete bool
	failed   bool
	failure  error
	record   *formalGLMPhase21RockStageRecord
	relay    *formalGLMRegisteredPhase21StageRelayV1
	done     chan struct{}

	authorityRoot string
	spoolDir      string
	artifactID    string
	peer          string
	remotePeer    string
	pins          map[string]ed25519.PublicKey
	signing       ed25519.PrivateKey
}

func (task *formalGLMRegisteredPhase21StageTaskV1) clearLockedV1() {
	if task.relay != nil {
		task.relay.Close()
		task.relay = nil
	}
	clear(task.signing)
	task.signing = nil
	formalGLMRegisteredPhase20TerminalClearPinsV1(task.pins)
	task.pins = nil
	task.authorityRoot, task.spoolDir, task.artifactID = "", "", ""
	task.peer, task.remotePeer = "", ""
}

func (task *formalGLMRegisteredPhase21StageTaskV1) statusV1() (
	formalGLMRegisteredPhase21StageStatusV1, error,
) {
	if task == nil {
		return formalGLMRegisteredPhase21StageStatusV1{},
			fmt.Errorf("formal-glm registered Phase21 stage: unavailable")
	}
	task.mu.Lock()
	defer task.mu.Unlock()
	status := formalGLMRegisteredPhase21StageStatusV1{ProductionReady: false}
	switch {
	case task.running:
		status.State = formalGLMRegisteredPhase21StageRunningV1
	case task.complete:
		status.State = formalGLMRegisteredPhase21StageCompleteV1
	case task.failed:
		status.State = formalGLMRegisteredPhase21StageFailedV1
	default:
		return formalGLMRegisteredPhase21StageStatusV1{},
			fmt.Errorf("formal-glm registered Phase21 stage: unavailable")
	}
	if task.record != nil {
		cloned, err := formalGLMRegisteredPhase21StageCloneRecordV1(*task.record)
		if err != nil {
			return formalGLMRegisteredPhase21StageStatusV1{}, err
		}
		status.Stage = cloned
	}
	return status, nil
}

func (task *formalGLMRegisteredPhase21StageTaskV1) relayV1() (
	*formalGLMRegisteredPhase21StageRelayV1, bool, error,
) {
	if task == nil {
		return nil, false, fmt.Errorf("formal-glm registered Phase21 stage: unavailable")
	}
	task.mu.Lock()
	defer task.mu.Unlock()
	if task.relay != nil {
		return task.relay, true, nil
	}
	if !task.running {
		return nil, false, nil
	}
	if _, err := os.Lstat(task.spoolDir); os.IsNotExist(err) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, fmt.Errorf("formal-glm registered Phase21 stage: unavailable")
	}
	relay, err := newFormalGLMRegisteredPhase21StageRelayV1(
		formalGLMRegisteredPhase21StageRelayConfigV1{
			ArtifactID: task.artifactID, LocalPeer: task.peer,
			Peer: task.remotePeer, SpoolDir: task.spoolDir,
			Signing: task.signing, Pins: task.pins,
		})
	if err != nil {
		return nil, false, err
	}
	task.relay = relay
	return relay, true, nil
}

func (task *formalGLMRegisteredPhase21StageTaskV1) abortV1() error {
	if task == nil {
		return nil
	}
	task.mu.Lock()
	spool := task.spoolDir
	running := task.running
	task.mu.Unlock()
	if !running || spool == "" {
		return nil
	}
	info, err := os.Lstat(spool)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o700 || !formalFinalizerHandoffPrivateOwnedDirectory(info) {
		return fmt.Errorf("formal-glm registered Phase21 stage: unsafe local spool")
	}
	root, err := os.OpenRoot(spool)
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := root.OpenFile("abort", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if os.IsExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := file.Write([]byte("1")); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func (task *formalGLMRegisteredPhase21StageTaskV1) closeV1() {
	if task == nil {
		return
	}
	_ = task.abortV1()
	task.mu.Lock()
	if !task.running {
		task.clearLockedV1()
	}
	task.mu.Unlock()
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) phase21StageStateV1(
	owner *formalGLMRegisteredPhase20JobOwnerV1,
) (formalGLMRegisteredPhase21StageHostStateV1, error) {
	var zero formalGLMRegisteredPhase21StageHostStateV1
	preflight, err := host.phase21PreflightStateV1(owner)
	if err != nil {
		return zero, err
	}
	defer preflight.clearV1()
	stageReady, err := formalGLMRegisteredPhase21PublicationStageInputsV1(preflight.publication)
	if err != nil || !stageReady {
		return zero, fmt.Errorf("formal-glm registered Phase21 stage: inputs unavailable")
	}
	postSelected, err := host.postSelectedInputsV1(owner)
	if err != nil {
		return zero, err
	}
	defer postSelected.clearV1()
	selected, trusted, err := postSelected.terminal.LoadSelectedSourceV1()
	if err != nil {
		return zero, err
	}
	defer trusted.clear()
	policySHA256, err := formalGLMRegisteredPhase21PostSelectedPhase16PolicySHA256V1(
		postSelected.policy)
	if err != nil {
		return zero, err
	}
	terminal := postSelected.terminal
	if terminal == nil {
		return zero, fmt.Errorf("formal-glm registered Phase21 stage: terminal unavailable")
	}
	terminal.mu.Lock()
	if terminal.closed || terminal.runtime == nil || terminal.attempts == nil {
		terminal.mu.Unlock()
		return zero, fmt.Errorf("formal-glm registered Phase21 stage: terminal unavailable")
	}
	semanticRoot := terminal.record.Binding.SemanticRootSHA256
	runtime := terminal.runtime
	terminal.mu.Unlock()
	runtime.mu.Lock()
	backendKey := runtime.backendKey
	runtime.mu.Unlock()
	if !formalGLMIsSHA256(semanticRoot) || !formalGLMPhase19KeyValid(backendKey) {
		clear(backendKey[:])
		return zero, fmt.Errorf("formal-glm registered Phase21 stage: terminal unavailable")
	}
	artifact := preflight.publication.SamplerContract.Artifact
	artifactID := preflight.publication.SamplerContract.ArtifactID
	local, err := formalGLMPhase21RockAuthority(artifact, preflight.peer)
	if err != nil {
		clear(backendKey[:])
		return zero, err
	}
	remote := ""
	paths := [2]string{}
	for index, authority := range artifact.NoiseAuthorities {
		if authority.PeerName == preflight.peer {
			paths[index], err = formalGLMPhase21RockPreflightRecordPath(
				preflight.authorityRoot, artifactID,
				formalGLMPhase21RockStateAbsent, "")
		} else {
			remote = authority.PeerName
			paths[index], err = formalGLMRegisteredPhase21PreflightInboxPathV1(
				preflight.authorityRoot, artifactID, authority.Role)
		}
		if err != nil {
			clear(backendKey[:])
			return zero, err
		}
	}
	if remote == "" || local.PeerName != preflight.peer {
		clear(backendKey[:])
		return zero, fmt.Errorf("formal-glm registered Phase21 stage: invalid authorities")
	}
	computeAuthority, err := formalGLMRegisteredPhase21PostSelectedComputeAuthorityV1(
		postSelected.contract.Core.RegisteredExecutionPlan, postSelected.peer)
	if err != nil || computeAuthority.Role != local.Role ||
		computeAuthority.PeerName != local.PeerName || computeAuthority.PeerID != local.PeerID {
		clear(backendKey[:])
		return zero, fmt.Errorf("formal-glm registered Phase21 stage: invalid authorities")
	}
	authoritySeed, err := formalGLMRegisteredPhase21DerivePostSelectedAuthoritySeedV1(
		postSelected.authorityRoot, selected.SelectedSHA256, policySHA256,
		preflight.publication.Capsule.ReleaseContractSHA256, computeAuthority)
	if err != nil {
		clear(backendKey[:])
		return zero, err
	}
	assets, err := formalGLMRegisteredPhase21PublicationAssetsPathsV1(
		preflight.authorityRoot, artifactID)
	if err != nil {
		clear(backendKey[:])
		clear(authoritySeed[:])
		return zero, err
	}
	stickyRoot := formalGLMRegisteredPhase21PreflightStickyRootV1(
		preflight.storageRoot, artifactID, preflight.peer)
	transportRoot := formalGLMRegisteredPhase21StageRootV1(
		preflight.storageRoot, artifactID, preflight.peer, "transport")
	spoolDir := filepath.Join(preflight.authorityRoot, "formal-glm-exact-gc-v2", artifactID)
	secretPath := filepath.Join(preflight.authorityRoot, "commands-v1",
		formalGLMRegisteredPhase21StageSecretFileV1)
	operation := formalGLMPhase21RockStageOperation{
		ArtifactContractPath: assets.contractPath, PinsetPath: assets.pinsetPath,
		RegistryResolutionPath: assets.resolutionPath, PreflightRecordPaths: paths,
		PeerName: preflight.peer, Phase20SemanticRootSHA256: semanticRoot,
		CapsulePath: assets.capsulePath, RequestPath: assets.requestPath,
		BackendSignaturesPath:     assets.backendSignaturesPath,
		WorkerSignaturesPath:      assets.workerSignaturesPath,
		SamplerAuthorizationsPath: assets.samplerAuthorizationsPath,
		SpoolDir:                  spoolDir, MaxSpoolBytes: formalGLMRegisteredPhase21StageMaxSpoolV1,
		TTLSeconds: formalGLMRegisteredPhase21StageTTLV1, SecretBundlePath: secretPath,
	}
	relayPins := make(map[string]ed25519.PublicKey, 2)
	for _, peer := range []string{preflight.peer, remote} {
		pin := preflight.pins[peer]
		if len(pin) != ed25519.PublicKeySize {
			clear(backendKey[:])
			clear(authoritySeed[:])
			formalGLMRegisteredPhase20TerminalClearPinsV1(relayPins)
			return zero, fmt.Errorf("formal-glm registered Phase21 stage: invalid authority pins")
		}
		relayPins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	state := formalGLMRegisteredPhase21StageHostStateV1{
		stickyRoot: stickyRoot, phase20StorageRoot: preflight.storageRoot,
		backendKey: backendKey, authorityRoot: postSelected.authorityRoot,
		authoritySeed: authoritySeed, transportRoot: transportRoot,
		semanticRoot: semanticRoot, rockRoot: preflight.authorityRoot,
		spoolDir: spoolDir, secretPath: secretPath, operation: operation,
		peer: preflight.peer, remotePeer: remote, artifactID: artifactID,
		pins: relayPins, signing: preflight.signing,
	}
	preflight.signing = nil
	return state, nil
}

func formalGLMRegisteredPhase21StageWriteSecretV1(
	state formalGLMRegisteredPhase21StageHostStateV1,
) error {
	if state.rockRoot == "" || state.secretPath == "" ||
		state.operation.SecretBundlePath != state.secretPath ||
		!formalGLMPhase19KeyValid(state.stickyRoot) ||
		!formalGLMPhase19KeyValid(state.phase20StorageRoot) ||
		!formalGLMPhase19KeyValid(state.backendKey) ||
		!formalGLMPhase19KeyValid(state.authorityRoot) ||
		!formalGLMPhase19KeyValid(state.authoritySeed) ||
		!formalGLMPhase19KeyValid(state.transportRoot) ||
		len(state.signing) != ed25519.PrivateKeySize {
		return fmt.Errorf("formal-glm registered Phase21 stage: invalid secret state")
	}
	_, _, err := formalGLMPhase21RockWriteJSON(state.rockRoot,
		state.secretPath, formalGLMPhase21RockStageSecret{
			Version:              formalGLMPhase21RockSecretVersion,
			Family:               formalFinalizerHandoffFamilyGLM,
			Purpose:              formalGLMPhase21RockPurpose,
			Action:               formalGLMPhase21RockActionStage,
			StickyStorageRoot:    base64.StdEncoding.EncodeToString(state.stickyRoot[:]),
			Phase20StorageRoot:   base64.StdEncoding.EncodeToString(state.phase20StorageRoot[:]),
			BackendKey:           base64.StdEncoding.EncodeToString(state.backendKey[:]),
			AuthorityRoot:        base64.StdEncoding.EncodeToString(state.authorityRoot[:]),
			AuthoritySeed:        base64.StdEncoding.EncodeToString(state.authoritySeed[:]),
			TransportStorageRoot: base64.StdEncoding.EncodeToString(state.transportRoot[:]),
			SigningPrivateKey:    base64.StdEncoding.EncodeToString(state.signing),
		})
	return err
}

func newFormalGLMRegisteredPhase21StageTaskV1(
	state formalGLMRegisteredPhase21StageHostStateV1,
	done func(),
) (*formalGLMRegisteredPhase21StageTaskV1, error) {
	if done == nil || state.rockRoot == "" || state.spoolDir == "" ||
		state.artifactID == "" || state.peer == "" || state.remotePeer == "" ||
		len(state.signing) != ed25519.PrivateKeySize || len(state.pins) != 2 {
		return nil, fmt.Errorf("formal-glm registered Phase21 stage: invalid task")
	}
	if err := formalGLMRegisteredPhase21StageWriteSecretV1(state); err != nil {
		return nil, err
	}
	pins := formalGLMRegisteredPhase20TerminalClonePinsV1(state.pins)
	signing := append(ed25519.PrivateKey(nil), state.signing...)
	if len(pins) != 2 || len(signing) != ed25519.PrivateKeySize {
		formalGLMRegisteredPhase20TerminalClearPinsV1(pins)
		clear(signing)
		return nil, fmt.Errorf("formal-glm registered Phase21 stage: invalid task")
	}
	operation, err := json.Marshal(state.operation)
	if err != nil {
		formalGLMRegisteredPhase20TerminalClearPinsV1(pins)
		clear(signing)
		return nil, err
	}
	task := &formalGLMRegisteredPhase21StageTaskV1{
		running: true, done: make(chan struct{}), authorityRoot: state.rockRoot,
		spoolDir: state.spoolDir, artifactID: state.artifactID,
		peer: state.peer, remotePeer: state.remotePeer,
		pins: pins, signing: signing,
	}
	go func() {
		defer done()
		defer clear(operation)
		response, runErr := formalGLMPhase21RockRun(
			task.authorityRoot, false, formalGLMPhase21RockActionStage, operation)
		task.mu.Lock()
		task.running = false
		task.failure = runErr
		task.complete = runErr == nil && response.Stage != nil &&
			response.State == formalGLMPhase21RockStateStaged && !response.ProductionReady
		task.failed = !task.complete
		if task.complete {
			record, cloneErr := formalGLMRegisteredPhase21StageCloneRecordV1(*response.Stage)
			if cloneErr == nil {
				task.record = record
			} else {
				task.complete, task.failed = false, true
			}
		}
		if task.relay != nil {
			task.relay.Close()
			task.relay = nil
		}
		task.clearLockedV1()
		close(task.done)
		task.mu.Unlock()
	}()
	return task, nil
}

func (task *formalGLMRegisteredPhase21StageTaskV1) pollV1(
	acknowledgement *formalGLMRegisteredPhase21StageRelayAckV1,
) (*formalGLMRegisteredPhase21StageRelayChunkV1, error) {
	relay, ready, err := task.relayV1()
	if err != nil || !ready {
		return nil, err
	}
	return relay.PollV1(acknowledgement)
}

func (task *formalGLMRegisteredPhase21StageTaskV1) relayChunkV1(
	chunk formalGLMRegisteredPhase21StageRelayChunkV1,
) (formalGLMRegisteredPhase21StageRelayAckV1, error) {
	relay, ready, err := task.relayV1()
	if err != nil {
		return formalGLMRegisteredPhase21StageRelayAckV1{}, err
	}
	if !ready {
		return formalGLMRegisteredPhase21StageRelayAckV1{},
			fmt.Errorf("formal-glm registered Phase21 stage: relay unavailable")
	}
	return relay.RelayV1(chunk)
}

// StartPhase21StageV1 is one-shot for this host lifetime.  A new host can
// safely invoke it again after restart; the underlying Rock lifecycle treats
// the exact same durable Stage record as a replay.
func (host *formalGLMRegisteredPhase20JobControlHostV1) StartPhase21StageV1() (
	formalGLMRegisteredPhase21StageStatusV1, error,
) {
	var zero formalGLMRegisteredPhase21StageStatusV1
	owner, done, err := host.beginOpV1()
	if err != nil {
		return zero, err
	}
	host.mu.Lock()
	existing := host.stage
	host.mu.Unlock()
	if existing != nil {
		done()
		return existing.statusV1()
	}
	if err := host.persistSelectedPublicationAssetsV1(owner); err != nil {
		done()
		return zero, err
	}
	state, err := host.phase21StageStateV1(owner)
	if err != nil {
		done()
		return zero, err
	}
	spoolDir, err := formalGLMRegisteredPhase21StagePrepareSpoolV1(
		state.rockRoot, state.artifactID)
	if err != nil || spoolDir != state.spoolDir {
		state.clearV1()
		done()
		return zero, fmt.Errorf("formal-glm registered Phase21 stage: unavailable")
	}
	task, err := newFormalGLMRegisteredPhase21StageTaskV1(state, done)
	state.clearV1()
	if err != nil {
		done()
		return zero, err
	}
	host.mu.Lock()
	if host.closed {
		host.mu.Unlock()
		_ = task.abortV1()
		<-task.done
		return zero, fmt.Errorf("formal-glm registered Phase21 stage: host closed")
	}
	if host.stage != nil {
		existing = host.stage
		host.mu.Unlock()
		_ = task.abortV1()
		<-task.done
		return existing.statusV1()
	}
	host.stage = task
	host.mu.Unlock()
	return task.statusV1()
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) Phase21StageStatusV1() (
	formalGLMRegisteredPhase21StageStatusV1, error,
) {
	if host == nil {
		return formalGLMRegisteredPhase21StageStatusV1{},
			fmt.Errorf("formal-glm registered Phase21 stage: host unavailable")
	}
	host.mu.Lock()
	task, closed := host.stage, host.closed
	host.mu.Unlock()
	if closed || task == nil {
		return formalGLMRegisteredPhase21StageStatusV1{},
			fmt.Errorf("formal-glm registered Phase21 stage: unavailable")
	}
	return task.statusV1()
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) PollPhase21StageV1(
	acknowledgement *formalGLMRegisteredPhase21StageRelayAckV1,
) (*formalGLMRegisteredPhase21StageRelayChunkV1, error) {
	if host == nil {
		return nil, fmt.Errorf("formal-glm registered Phase21 stage: host unavailable")
	}
	host.mu.Lock()
	task, closed := host.stage, host.closed
	host.mu.Unlock()
	if closed || task == nil {
		return nil, fmt.Errorf("formal-glm registered Phase21 stage: unavailable")
	}
	return task.pollV1(acknowledgement)
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) RelayPhase21StageV1(
	chunk formalGLMRegisteredPhase21StageRelayChunkV1,
) (formalGLMRegisteredPhase21StageRelayAckV1, error) {
	if host == nil {
		return formalGLMRegisteredPhase21StageRelayAckV1{},
			fmt.Errorf("formal-glm registered Phase21 stage: host unavailable")
	}
	host.mu.Lock()
	task, closed := host.stage, host.closed
	host.mu.Unlock()
	if closed || task == nil {
		return formalGLMRegisteredPhase21StageRelayAckV1{},
			fmt.Errorf("formal-glm registered Phase21 stage: unavailable")
	}
	return task.relayChunkV1(chunk)
}
