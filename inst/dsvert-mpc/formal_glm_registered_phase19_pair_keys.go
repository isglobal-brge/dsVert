package main

// Rock-local X25519 key agreement for the registered Phase19 compute pair.
// Only the public key leaves this provider. The local secret is a raw,
// owner-only key file and the derived backend exists only as a return value in
// server memory.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	formalGLMRegisteredPhase19PairKeyVersionV1 = "dsvert-formal-glm-registered-phase19-pair-key-v1"
	formalGLMRegisteredPhase19PairKeyPurposeV1 = "formal_glm_registered_phase19_rock_local_pair_key_v1"
	formalGLMRegisteredPhase19PairKeyDomainV1  = "dsVert/formal-glm/registered-phase19/pair-key/v1"

	formalGLMRegisteredPhase19PairKeyDirV1  = "registered-phase19-pair-keys-v1"
	formalGLMRegisteredPhase19PairKeyFileV1 = "pair-x25519.key"

	formalGLMRegisteredPhase19PairKeyBytesV1        = 64
	formalGLMRegisteredPhase19PairKeyWaitAttemptsV1 = 250
)

type formalGLMRegisteredPhase19PairKeyBindingV1 struct {
	Version                       string `json:"version"`
	Purpose                       string `json:"purpose"`
	ArtifactID                    string `json:"artifact_id"`
	SourceContractCoreSHA256      string `json:"source_contract_core_sha256"`
	SourceContractSHA256          string `json:"source_contract_sha256"`
	RegisteredExecutionPlanSHA256 string `json:"registered_execution_plan_sha256"`
	PinsetSHA256                  string `json:"pinset_sha256"`
	LocalPeerName                 string `json:"local_peer_name"`
	LocalPeerID                   string `json:"local_peer_id"`
	LocalRole                     string `json:"local_role"`
}

type formalGLMRegisteredPhase19PairContextV1 struct {
	Version                       string `json:"version"`
	Purpose                       string `json:"purpose"`
	ArtifactID                    string `json:"artifact_id"`
	SourceContractCoreSHA256      string `json:"source_contract_core_sha256"`
	SourceContractSHA256          string `json:"source_contract_sha256"`
	RegisteredExecutionPlanSHA256 string `json:"registered_execution_plan_sha256"`
	PinsetSHA256                  string `json:"pinset_sha256"`
	SemanticRootSHA256            string `json:"semantic_root_sha256"`
	GarblerPeerName               string `json:"garbler_peer_name"`
	GarblerPeerID                 string `json:"garbler_peer_id"`
	EvaluatorPeerName             string `json:"evaluator_peer_name"`
	EvaluatorPeerID               string `json:"evaluator_peer_id"`
	GarblerTicketSHA256           string `json:"garbler_ticket_sha256"`
	EvaluatorTicketSHA256         string `json:"evaluator_ticket_sha256"`
}

type formalGLMRegisteredPhase19PairKeyProviderV1 struct {
	mu         sync.Mutex
	root       *os.Root
	context    formalGLMRegisteredPhase18ProvenanceContextV1
	localPeer  string
	localIndex int
	binding    [32]byte
}

func formalGLMRegisteredPhase19PairKeyRelativeDirV1(
	artifactID string, peerIndex int,
) string {
	if !formalGLMIsSHA256(artifactID) || peerIndex < 0 || peerIndex > 1 {
		return ""
	}
	return filepath.Join(formalGLMRegisteredPhase19PairKeyDirV1,
		artifactID[:2], artifactID[2:4], artifactID,
		fmt.Sprintf("peer-%d", peerIndex))
}

func formalGLMRegisteredPhase19PairKeyDigestV1(
	domain string, value any,
) ([32]byte, error) {
	var zero [32]byte
	encoded, err := json.Marshal(value)
	if err != nil {
		return zero, err
	}
	defer clear(encoded)
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(encoded)
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	if !formalGLMPhase19KeyValid(digest) {
		return zero, fmt.Errorf("formal-glm registered Phase19 pair key: invalid binding digest")
	}
	return digest, nil
}

func formalGLMRegisteredPhase19PairKeyBindingDigestV1(
	contract formalGLMSourceContractV1, contractSHA256 string,
	localIndex int,
) ([32]byte, error) {
	var zero [32]byte
	plan := contract.Core.RegisteredExecutionPlan
	if localIndex < 0 || localIndex >= len(plan.NoiseAuthorities) ||
		localIndex >= len(plan.DesignatedComputePeers) {
		return zero, fmt.Errorf("formal-glm registered Phase19 pair key: invalid local binding")
	}
	authority := plan.NoiseAuthorities[localIndex]
	binding := formalGLMRegisteredPhase19PairKeyBindingV1{
		Version:                       formalGLMRegisteredPhase19PairKeyVersionV1,
		Purpose:                       formalGLMRegisteredPhase19PairKeyPurposeV1,
		ArtifactID:                    contract.Core.ArtifactID,
		SourceContractCoreSHA256:      contract.CoreSHA256,
		SourceContractSHA256:          contractSHA256,
		RegisteredExecutionPlanSHA256: plan.PlanSHA256,
		PinsetSHA256:                  plan.PinsetSHA256,
		LocalPeerName:                 authority.PeerName,
		LocalPeerID:                   authority.PeerID,
		LocalRole:                     authority.Role,
	}
	return formalGLMRegisteredPhase19PairKeyDigestV1(
		formalGLMRegisteredPhase19PairKeyDomainV1+"/binding", binding)
}

func newFormalGLMRegisteredPhase19PairKeyProviderV1(
	rockRoot, localPeer string,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) (*formalGLMRegisteredPhase19PairKeyProviderV1, error) {
	clonedPins := make(map[string]ed25519.PublicKey, len(pins))
	for peer, pin := range pins {
		clonedPins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	contractJSON, err := json.Marshal(contract)
	if err != nil {
		return nil, err
	}
	clonedContract, err := formalGLMDecodeSourceContractV1(
		contractJSON, clonedPins)
	clear(contractJSON)
	if err != nil {
		return nil, err
	}
	contractSHA256, err := formalGLMSourceContractSHA256V1(clonedContract)
	if err != nil {
		return nil, err
	}
	plan := clonedContract.Core.RegisteredExecutionPlan
	localIndex := -1
	for index, peer := range plan.DesignatedComputePeers {
		if peer == localPeer {
			localIndex = index
		}
	}
	if localIndex < 0 || len(plan.DesignatedComputePeers) != 2 ||
		len(plan.NoiseAuthorities) != 2 ||
		plan.NoiseAuthorities[0].Role != "garbler" ||
		plan.NoiseAuthorities[1].Role != "evaluator" {
		return nil, fmt.Errorf("formal-glm registered Phase19 pair key: local peer is not designated")
	}
	for index, authority := range plan.NoiseAuthorities {
		if authority.PeerName != plan.DesignatedComputePeers[index] {
			return nil, fmt.Errorf("formal-glm registered Phase19 pair key: invalid compute-peer order")
		}
	}
	binding, err := formalGLMRegisteredPhase19PairKeyBindingDigestV1(
		clonedContract, contractSHA256, localIndex)
	if err != nil {
		return nil, err
	}
	root, err := formalGLMRegisteredPhase18TicketStoreOpenRootV1(rockRoot)
	if err != nil {
		clear(binding[:])
		return nil, err
	}
	provider := &formalGLMRegisteredPhase19PairKeyProviderV1{
		root: root,
		context: formalGLMRegisteredPhase18ProvenanceContextV1{
			contract: clonedContract, contractSHA256: contractSHA256,
			pins: clonedPins,
		},
		localPeer: localPeer, localIndex: localIndex, binding: binding,
	}
	fail := func(cause error) (*formalGLMRegisteredPhase19PairKeyProviderV1, error) {
		provider.Close()
		return nil, cause
	}
	peerDir := provider.keyRelativeDirV1()
	if peerDir == "" || formalGLMRegisteredPhase18TicketStoreEnsureDirV1(
		root, filepath.Dir(peerDir)) != nil {
		return fail(fmt.Errorf("formal-glm registered Phase19 pair key: invalid durable path"))
	}
	createdPeer := false
	if err := root.Mkdir(peerDir, 0o700); err == nil {
		createdPeer = true
		if err := root.Chmod(peerDir, 0o700); err != nil {
			return fail(err)
		}
		if err := formalGLMPhase21RootSyncDir(root, peerDir); err != nil {
			return fail(err)
		}
	} else if !os.IsExist(err) {
		return fail(err)
	}
	if err := formalGLMRegisteredPhase18TicketStoreValidateDirV1(
		root, peerDir); err != nil {
		return fail(err)
	}
	var secret [32]byte
	if createdPeer {
		secret, err = provider.createKeyLockedV1()
	} else {
		for attempt := 0; attempt < formalGLMRegisteredPhase19PairKeyWaitAttemptsV1; attempt++ {
			secret, err = provider.readKeyLockedV1()
			if err == nil {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
	clear(secret[:])
	if err != nil {
		return fail(fmt.Errorf("formal-glm registered Phase19 pair key: durable key unavailable"))
	}
	return provider, nil
}

func (provider *formalGLMRegisteredPhase19PairKeyProviderV1) keyRelativeDirV1() string {
	if provider == nil {
		return ""
	}
	return formalGLMRegisteredPhase19PairKeyRelativeDirV1(
		provider.context.contract.Core.ArtifactID, provider.localIndex)
}

func (provider *formalGLMRegisteredPhase19PairKeyProviderV1) keyRelativePathV1() string {
	directory := provider.keyRelativeDirV1()
	if directory == "" {
		return ""
	}
	return filepath.Join(directory, formalGLMRegisteredPhase19PairKeyFileV1)
}

func formalGLMRegisteredPhase19PairKeyTagV1(
	secret, binding [32]byte,
) [32]byte {
	mac := hmac.New(sha256.New, secret[:])
	_, _ = mac.Write([]byte(
		formalGLMRegisteredPhase19PairKeyDomainV1 + "/key-file"))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(binding[:])
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func (provider *formalGLMRegisteredPhase19PairKeyProviderV1) readKeyLockedV1() (
	[32]byte, error,
) {
	var zero [32]byte
	if provider == nil || provider.root == nil ||
		!formalGLMPhase19KeyValid(provider.binding) {
		return zero, fmt.Errorf("formal-glm registered Phase19 pair key: provider is closed")
	}
	relative := provider.keyRelativePathV1()
	info, err := provider.root.Lstat(relative)
	if err != nil {
		return zero, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 ||
		info.Size() != formalGLMRegisteredPhase19PairKeyBytesV1 ||
		!exactGCPrivateOwnedRegular(info) {
		return zero, fmt.Errorf("formal-glm registered Phase19 pair key: unsafe key file")
	}
	file, err := provider.root.Open(relative)
	if err != nil {
		return zero, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, opened) ||
		!opened.Mode().IsRegular() || opened.Mode().Perm() != 0o600 ||
		opened.Size() != formalGLMRegisteredPhase19PairKeyBytesV1 ||
		!exactGCPrivateOwnedRegular(opened) {
		_ = file.Close()
		return zero, fmt.Errorf("formal-glm registered Phase19 pair key: unstable key file")
	}
	var record [formalGLMRegisteredPhase19PairKeyBytesV1]byte
	_, readErr := io.ReadFull(file, record[:])
	var extra [1]byte
	_, trailingErr := file.Read(extra[:])
	closeErr := file.Close()
	if readErr != nil || trailingErr != io.EOF || closeErr != nil {
		clear(record[:])
		return zero, fmt.Errorf("formal-glm registered Phase19 pair key: invalid key file")
	}
	var secret, tag [32]byte
	copy(secret[:], record[:32])
	copy(tag[:], record[32:])
	clear(record[:])
	want := formalGLMRegisteredPhase19PairKeyTagV1(secret, provider.binding)
	if !formalGLMPhase19KeyValid(secret) || !hmac.Equal(tag[:], want[:]) {
		clear(secret[:])
		clear(tag[:])
		clear(want[:])
		return zero, fmt.Errorf("formal-glm registered Phase19 pair key: key binding failed")
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(secret[:])
	if err != nil {
		clear(secret[:])
		return zero, fmt.Errorf("formal-glm registered Phase19 pair key: invalid X25519 secret")
	}
	if _, err := formalGLMRegisteredPhase18TransportPKV1(
		privateKey.PublicKey().Bytes()); err != nil {
		clear(secret[:])
		return zero, err
	}
	clear(tag[:])
	clear(want[:])
	return secret, nil
}

func (provider *formalGLMRegisteredPhase19PairKeyProviderV1) createKeyLockedV1() (
	[32]byte, error,
) {
	var zero [32]byte
	key, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		return zero, err
	}
	var secret [32]byte
	copy(secret[:], key.Bytes())
	if !formalGLMPhase19KeyValid(secret) {
		clear(secret[:])
		return zero, fmt.Errorf("formal-glm registered Phase19 pair key: X25519 generation failed")
	}
	tag := formalGLMRegisteredPhase19PairKeyTagV1(secret, provider.binding)
	var record [formalGLMRegisteredPhase19PairKeyBytesV1]byte
	copy(record[:32], secret[:])
	copy(record[32:], tag[:])
	clear(tag[:])
	file, err := provider.root.OpenFile(provider.keyRelativePathV1(),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		clear(record[:])
		clear(secret[:])
		return zero, err
	}
	writeErr := file.Chmod(0o600)
	if writeErr == nil {
		writeErr = exactGCWriteFull(file, record[:])
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	clear(record[:])
	if writeErr != nil {
		clear(secret[:])
		return zero, writeErr
	}
	if closeErr != nil {
		clear(secret[:])
		return zero, closeErr
	}
	if err := formalGLMPhase21RootSyncDir(
		provider.root, provider.keyRelativePathV1()); err != nil {
		clear(secret[:])
		return zero, err
	}
	loaded, err := provider.readKeyLockedV1()
	if err != nil || !bytes.Equal(loaded[:], secret[:]) {
		clear(loaded[:])
		clear(secret[:])
		return zero, fmt.Errorf("formal-glm registered Phase19 pair key: persistence failed")
	}
	clear(secret[:])
	return loaded, nil
}

func (provider *formalGLMRegisteredPhase19PairKeyProviderV1) PublicKeyV1() (
	[]byte, error,
) {
	if provider == nil {
		return nil, fmt.Errorf("formal-glm registered Phase19 pair key: provider is unavailable")
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	secret, err := provider.readKeyLockedV1()
	if err != nil {
		return nil, err
	}
	defer clear(secret[:])
	privateKey, err := ecdh.X25519().NewPrivateKey(secret[:])
	if err != nil {
		return nil, fmt.Errorf("formal-glm registered Phase19 pair key: invalid X25519 secret")
	}
	return append([]byte(nil), privateKey.PublicKey().Bytes()...), nil
}

func formalGLMRegisteredPhase19PairContextSHA256V1(
	context formalGLMRegisteredPhase19PairContextV1,
) (string, error) {
	digest, err := formalGLMRegisteredPhase19PairKeyDigestV1(
		formalGLMRegisteredPhase19PairKeyDomainV1+"/derive-context", context)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

func (provider *formalGLMRegisteredPhase19PairKeyProviderV1) deriveBackendLockedV1(
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
	semanticRootSHA256 string,
) ([32]byte, error) {
	var zero [32]byte
	if provider == nil || provider.root == nil ||
		!formalGLMIsSHA256(semanticRootSHA256) {
		return zero, fmt.Errorf("formal-glm registered Phase19 pair key: invalid derivation request")
	}
	ordered, err := formalGLMRegisteredPhase18CanonicalTicketsWithContextV1(
		provider.context, tickets)
	if err != nil {
		return zero, err
	}
	ticketHashes := make([]string, 2)
	for index := range ordered {
		ticketHashes[index], err =
			formalGLMRegisteredPhase18RecipientTicketSHA256V1(ordered[index])
		if err != nil {
			return zero, err
		}
	}
	secret, err := provider.readKeyLockedV1()
	if err != nil {
		return zero, err
	}
	defer clear(secret[:])
	privateKey, err := ecdh.X25519().NewPrivateKey(secret[:])
	if err != nil || !bytes.Equal(privateKey.PublicKey().Bytes(),
		ordered[provider.localIndex].TransportPK) {
		return zero, fmt.Errorf("formal-glm registered Phase19 pair key: local ticket key mismatch")
	}
	plan := provider.context.contract.Core.RegisteredExecutionPlan
	context := formalGLMRegisteredPhase19PairContextV1{
		Version:                       formalGLMRegisteredPhase19PairKeyVersionV1,
		Purpose:                       formalGLMRegisteredPhase19PairKeyPurposeV1,
		ArtifactID:                    provider.context.contract.Core.ArtifactID,
		SourceContractCoreSHA256:      provider.context.contract.CoreSHA256,
		SourceContractSHA256:          provider.context.contractSHA256,
		RegisteredExecutionPlanSHA256: plan.PlanSHA256,
		PinsetSHA256:                  plan.PinsetSHA256,
		SemanticRootSHA256:            semanticRootSHA256,
		GarblerPeerName:               plan.NoiseAuthorities[0].PeerName,
		GarblerPeerID:                 plan.NoiseAuthorities[0].PeerID,
		EvaluatorPeerName:             plan.NoiseAuthorities[1].PeerName,
		EvaluatorPeerID:               plan.NoiseAuthorities[1].PeerID,
		GarblerTicketSHA256:           ticketHashes[0],
		EvaluatorTicketSHA256:         ticketHashes[1],
	}
	sessionID, err := formalGLMRegisteredPhase19PairContextSHA256V1(context)
	if err != nil {
		return zero, err
	}
	peerIndex := 1 - provider.localIndex
	input := exactGCDeriveMasterInput{
		LocalSecret: base64.StdEncoding.EncodeToString(secret[:]),
		LocalPublic: base64.StdEncoding.EncodeToString(
			privateKey.PublicKey().Bytes()),
		PeerPublic: base64.StdEncoding.EncodeToString(
			ordered[peerIndex].TransportPK),
		SessionID:   sessionID,
		GarblerID:   plan.NoiseAuthorities[0].PeerID,
		EvaluatorID: plan.NoiseAuthorities[1].PeerID,
		Purpose:     formalGLMRegisteredPhase19PairKeyDomainV1 + "/backend",
		Operation:   string(exactGCFormalGLMOneIteration),
		RingBits:    plan.RingBits,
		FracBits:    plan.ExecutionKernel.FractionBits,
		VectorLen:   1,
	}
	derived, err := exactGCDeriveMaster(input)
	input.LocalSecret = ""
	if err != nil || !formalGLMIsSHA256(derived.ContextHash) {
		derived.MasterKey = ""
		return zero, fmt.Errorf("formal-glm registered Phase19 pair key: backend derivation failed")
	}
	decoded, err := exactGCStrictBase64(derived.MasterKey, 32)
	derived.MasterKey = ""
	if err != nil {
		return zero, err
	}
	defer clear(decoded)
	var backend [32]byte
	copy(backend[:], decoded)
	if !formalGLMPhase19KeyValid(backend) {
		clear(backend[:])
		return zero, fmt.Errorf("formal-glm registered Phase19 pair key: invalid derived backend")
	}
	return backend, nil
}

func (provider *formalGLMRegisteredPhase19PairKeyProviderV1) DeriveBackendV1(
	record formalGLMRegisteredPhase19BindingRecordV1,
) ([32]byte, error) {
	var zero [32]byte
	if provider == nil {
		return zero, fmt.Errorf("formal-glm registered Phase19 pair key: provider is unavailable")
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.root == nil {
		return zero, fmt.Errorf("formal-glm registered Phase19 pair key: provider is closed")
	}
	if err := formalGLMValidateRegisteredPhase19BindingRecordV1(
		record, provider.context.contract, provider.context.pins); err != nil {
		return zero, fmt.Errorf(
			"formal-glm registered Phase19 pair key: invalid binding record: %w", err)
	}
	return provider.deriveBackendLockedV1(
		record.RecipientTickets, record.Binding.SemanticRootSHA256)
}

func (provider *formalGLMRegisteredPhase19PairKeyProviderV1) Close() {
	if provider == nil {
		return
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.root != nil {
		_ = provider.root.Close()
		provider.root = nil
	}
	for peer := range provider.context.pins {
		clear(provider.context.pins[peer])
		delete(provider.context.pins, peer)
	}
	clear(provider.binding[:])
}
