package main

// Private host bridge into the existing Phase21 preflight action.  Preflight
// contains only signed lifecycle state (absent or an existing public
// certificate); it never carries a local output share or a model result.

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
)

const (
	formalGLMRegisteredPhase21PreflightSecretFileV1 = "registered-phase21-preflight-secret.json"
	formalGLMRegisteredPhase21PreflightDomainV1     = "dsVert/formal-glm/registered-phase21/preflight-sticky/v1"
)

type formalGLMRegisteredPhase21PreflightHostStateV1 struct {
	authorityRoot string
	peer          string
	contract      formalGLMSourceContractV1
	pins          map[string]ed25519.PublicKey
	publication   formalGLMRegisteredPhase21PublicationContextV1
	storageRoot   [32]byte
	signing       ed25519.PrivateKey
}

func (state *formalGLMRegisteredPhase21PreflightHostStateV1) clearV1() {
	if state == nil {
		return
	}
	clear(state.storageRoot[:])
	clear(state.signing)
	state.signing = nil
	formalGLMRegisteredPhase20TerminalClearPinsV1(state.pins)
	formalGLMRegisteredPhase21PublicationContextClearV1(&state.publication)
	*state = formalGLMRegisteredPhase21PreflightHostStateV1{}
}

func formalGLMRegisteredPhase21PreflightStickyRootV1(
	storageRoot [32]byte, artifactID, peer string,
) [32]byte {
	mac := hmac.New(sha256.New, storageRoot[:])
	_, _ = mac.Write([]byte(formalGLMRegisteredPhase21PreflightDomainV1))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(artifactID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(peer))
	var root [32]byte
	copy(root[:], mac.Sum(nil))
	return root
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) phase21PreflightStateV1(
	owner *formalGLMRegisteredPhase20JobOwnerV1,
) (formalGLMRegisteredPhase21PreflightHostStateV1, error) {
	var zero formalGLMRegisteredPhase21PreflightHostStateV1
	if host == nil || owner == nil {
		return zero, fmt.Errorf("formal-glm registered Phase21 preflight: host unavailable")
	}
	host.mu.Lock()
	publication := host.publication
	host.mu.Unlock()
	if publication == nil {
		return zero, fmt.Errorf("formal-glm registered Phase21 preflight: publication unavailable")
	}
	owner.mu.Lock()
	terminal := owner.terminal
	owner.mu.Unlock()
	if terminal == nil {
		return zero, fmt.Errorf("formal-glm registered Phase21 preflight: terminal unavailable")
	}
	_, selectedSource, err := terminal.LoadSelectedSourceV1()
	if err != nil {
		return zero, err
	}
	selectedSource.clear()
	terminal.mu.Lock()
	attempts, keys := terminal.attempts, terminal.jobKeys
	peer, contract := terminal.peer, terminal.contract
	pins := formalGLMRegisteredPhase20TerminalClonePinsV1(terminal.pins)
	terminal.mu.Unlock()
	if attempts == nil || keys == nil {
		formalGLMRegisteredPhase20TerminalClearPinsV1(pins)
		return zero, fmt.Errorf("formal-glm registered Phase21 preflight: terminal unavailable")
	}
	attempts.mu.Lock()
	rockRoot := ""
	if attempts.root != nil {
		rockRoot = attempts.root.Name()
	}
	signing := append(ed25519.PrivateKey(nil), attempts.signingKey...)
	attempts.mu.Unlock()
	keys.mu.Lock()
	storageRoot := keys.storageRoot
	keys.mu.Unlock()
	if rockRoot == "" || len(signing) != ed25519.PrivateKeySize {
		clear(storageRoot[:])
		clear(signing)
		formalGLMRegisteredPhase20TerminalClearPinsV1(pins)
		return zero, fmt.Errorf("formal-glm registered Phase21 preflight: terminal unavailable")
	}
	context, err := formalGLMRegisteredPhase21PublicationContextCloneV1(
		*publication, contract, pins)
	if err != nil {
		clear(storageRoot[:])
		clear(signing)
		formalGLMRegisteredPhase20TerminalClearPinsV1(pins)
		return zero, err
	}
	return formalGLMRegisteredPhase21PreflightHostStateV1{
		authorityRoot: filepath.Join(rockRoot, peer), peer: peer,
		contract: contract, pins: pins, publication: context,
		storageRoot: storageRoot, signing: signing,
	}, nil
}

func formalGLMRegisteredPhase21PreflightSecretPathV1(root string) string {
	return filepath.Join(root, "commands-v1",
		formalGLMRegisteredPhase21PreflightSecretFileV1)
}

func formalGLMRegisteredPhase21PreflightInboxPathV1(
	root, artifactID, role string,
) (string, error) {
	if !formalGLMIsSHA256(artifactID) || role != "garbler" && role != "evaluator" {
		return "", fmt.Errorf("formal-glm registered Phase21 preflight: invalid peer record")
	}
	return filepath.Join(root, formalGLMRegisteredPhase21PublicationAssetsDirV1,
		artifactID, "inbox-preflight-"+role+".json"), nil
}

// RunPhase21PreflightV1 signs the local preflight record after Selected and
// its durable Phase21 assets both exist. The secret bundle is local and is
// removed by the generic lifecycle action after the record commit.
func (host *formalGLMRegisteredPhase20JobControlHostV1) RunPhase21PreflightV1() (
	formalGLMPhase21RockPreflightRecord, error,
) {
	var zero formalGLMPhase21RockPreflightRecord
	owner, done, err := host.beginOpV1()
	if err != nil {
		return zero, err
	}
	defer done()
	state, err := host.phase21PreflightStateV1(owner)
	if err != nil {
		return zero, err
	}
	defer state.clearV1()
	assets, err := formalGLMRegisteredPhase21PublicationAssetsPathsV1(
		state.authorityRoot, state.publication.SamplerContract.ArtifactID)
	if err != nil {
		return zero, err
	}
	stickyRoot := formalGLMRegisteredPhase21PreflightStickyRootV1(
		state.storageRoot, state.publication.SamplerContract.ArtifactID, state.peer)
	defer clear(stickyRoot[:])
	secretPath := formalGLMRegisteredPhase21PreflightSecretPathV1(state.authorityRoot)
	_, _, err = formalGLMPhase21RockWriteJSON(state.authorityRoot, secretPath,
		formalGLMPhase21RockPreflightSecret{
			Version:           formalGLMPhase21RockSecretVersion,
			Family:            formalFinalizerHandoffFamilyGLM,
			Purpose:           formalGLMPhase21RockPurpose,
			Action:            formalGLMPhase21RockActionPreflight,
			StickyStorageRoot: base64.StdEncoding.EncodeToString(stickyRoot[:]),
			SigningPrivateKey: base64.StdEncoding.EncodeToString(state.signing),
		})
	if err != nil {
		return zero, err
	}
	operation, err := json.Marshal(formalGLMPhase21RockPreflightOperation{
		ArtifactContractPath:   assets.contractPath,
		PinsetPath:             assets.pinsetPath,
		RegistryResolutionPath: assets.resolutionPath,
		PeerName:               state.peer,
		SecretBundlePath:       secretPath,
	})
	if err != nil {
		return zero, err
	}
	defer clear(operation)
	response, err := formalGLMPhase21RockRun(
		state.authorityRoot, false, formalGLMPhase21RockActionPreflight, operation)
	if err != nil || response.Preflight == nil || response.ProductionReady {
		return zero, fmt.Errorf("formal-glm registered Phase21 preflight: lifecycle failed")
	}
	return *response.Preflight, nil
}

// ImportPhase21PeerPreflightV1 accepts only the opposite designated
// authority's signed record. It is saved separately from the local preflight
// slot so a remote replay can never overwrite local state.
func (host *formalGLMRegisteredPhase20JobControlHostV1) ImportPhase21PeerPreflightV1(
	record formalGLMPhase21RockPreflightRecord,
) error {
	if _, err := host.RunPhase21PreflightV1(); err != nil {
		return err
	}
	owner, done, err := host.beginOpV1()
	if err != nil {
		return err
	}
	defer done()
	state, err := host.phase21PreflightStateV1(owner)
	if err != nil {
		return err
	}
	defer state.clearV1()
	if formalGLMPhase21RockValidatePreflightRecord(
		record, state.publication.SamplerContract, state.pins) != nil ||
		record.Receipt.PeerName == state.peer {
		return fmt.Errorf("formal-glm registered Phase21 preflight: invalid peer record")
	}
	local, err := formalGLMPhase21RockAuthority(
		state.publication.SamplerContract.Artifact, state.peer)
	if err != nil || record.Receipt.Role == local.Role {
		return fmt.Errorf("formal-glm registered Phase21 preflight: invalid peer record")
	}
	path, err := formalGLMRegisteredPhase21PreflightInboxPathV1(
		state.authorityRoot, state.publication.SamplerContract.ArtifactID,
		record.Receipt.Role)
	if err != nil {
		return err
	}
	_, _, err = formalGLMPhase21RockWriteJSON(state.authorityRoot, path, record)
	return err
}
