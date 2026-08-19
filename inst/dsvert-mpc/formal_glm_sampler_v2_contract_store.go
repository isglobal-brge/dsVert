package main

// Separate exact-CAS storage for the public K-of-K SamplerV2 contract. This
// record contains commitments and signatures only; authority roots and
// derived seeds remain in the private key store.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const (
	formalGLMSamplerV2ContractRecordVersion = "dsvert-formal-glm-sampler-v2-contract-record-v1"
	formalGLMSamplerV2ContractRecordPurpose = "formal_glm_sampler_v2_k_of_k_contract_record_v1"
	formalGLMSamplerV2ContractRecordDir     = "sampler-v2-contracts-v1"
	formalGLMSamplerV2ContractMaxRecord     = 4 << 20
)

type formalGLMSamplerV2ContractRecordV1 struct {
	Version        string                            `json:"version"`
	Purpose        string                            `json:"purpose"`
	ArtifactID     string                            `json:"artifact_id"`
	PinsetSHA256   string                            `json:"pinset_sha256"`
	ContractSHA256 string                            `json:"contract_sha256"`
	Contract       formalGLMPhase21SamplerV2Contract `json:"contract"`
}

type formalGLMSamplerV2ContractStoreV1 struct {
	mu           sync.Mutex
	dir          string
	root         *os.Root
	pins         map[string]ed25519.PublicKey
	pinsetSHA256 string
}

func newFormalGLMSamplerV2ContractStoreV1(
	dir string, pins map[string]ed25519.PublicKey,
) (*formalGLMSamplerV2ContractStoreV1, error) {
	pinsetSHA256, err := formalGLMPhase16PinsetSHA256(pins)
	if err != nil {
		return nil, err
	}
	dir, root, err := formalGLMSamplerV2OpenRockRootV1(dir)
	if err != nil {
		return nil, err
	}
	if err := formalGLMPhase21EnsureRootPrivateDir(
		root, formalGLMSamplerV2ContractRecordDir); err != nil {
		_ = root.Close()
		return nil, err
	}
	clonedPins := make(map[string]ed25519.PublicKey, len(pins))
	for peer, pin := range pins {
		clonedPins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	return &formalGLMSamplerV2ContractStoreV1{
		dir: dir, root: root, pins: clonedPins, pinsetSHA256: pinsetSHA256,
	}, nil
}

func (store *formalGLMSamplerV2ContractStoreV1) Close() {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root != nil {
		_ = store.root.Close()
		store.root = nil
	}
	for peer := range store.pins {
		clear(store.pins[peer])
		delete(store.pins, peer)
	}
}

func (store *formalGLMSamplerV2ContractStoreV1) recordRelativePath(
	artifactID string, create bool,
) (string, error) {
	if store == nil || store.root == nil || !formalGLMIsSHA256(artifactID) {
		return "", fmt.Errorf("formal-glm sampler-v2 contract store: invalid artifact")
	}
	shard := filepath.Join(formalGLMSamplerV2ContractRecordDir,
		artifactID[:2], artifactID[2:4])
	if create {
		if err := formalGLMPhase21EnsureRootPrivateDir(store.root, shard); err != nil {
			return "", err
		}
	} else if err := formalGLMPhase21ValidateRootPrivateDir(
		store.root, shard, false); err != nil {
		return "", err
	}
	return filepath.Join(shard, "contract-"+artifactID+".json"), nil
}

func (store *formalGLMSamplerV2ContractStoreV1) recordPath(
	artifactID string, create bool,
) (string, error) {
	relative, err := store.recordRelativePath(artifactID, create)
	if err != nil {
		return "", err
	}
	return filepath.Join(store.dir, relative), nil
}

func formalGLMSamplerV2ValidateContractRecordV1(
	record formalGLMSamplerV2ContractRecordV1,
	pinsetSHA256 string, pins map[string]ed25519.PublicKey,
) error {
	contractSHA256, err := formalGLMPhase21SamplerV2ContractSHA256(
		record.Contract)
	if record.Version != formalGLMSamplerV2ContractRecordVersion ||
		record.Purpose != formalGLMSamplerV2ContractRecordPurpose ||
		!formalGLMIsSHA256(record.ArtifactID) ||
		record.ArtifactID != record.Contract.ArtifactID ||
		record.PinsetSHA256 != pinsetSHA256 ||
		record.PinsetSHA256 != record.Contract.PinsetSHA256 ||
		err != nil || record.ContractSHA256 != contractSHA256 ||
		formalGLMPhase21ValidateSamplerV2Contract(record.Contract, pins) != nil {
		return fmt.Errorf("formal-glm sampler-v2 contract store: invalid sealed contract")
	}
	return nil
}

func (store *formalGLMSamplerV2ContractStoreV1) Commit(
	contract formalGLMPhase21SamplerV2Contract,
) (bool, error) {
	if store == nil {
		return false, fmt.Errorf("formal-glm sampler-v2 contract store: unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil ||
		formalGLMPhase21ValidateSamplerV2Contract(contract, store.pins) != nil {
		return false, fmt.Errorf("formal-glm sampler-v2 contract store: invalid commit")
	}
	contractSHA256, err := formalGLMPhase21SamplerV2ContractSHA256(contract)
	if err != nil {
		return false, err
	}
	record := formalGLMSamplerV2ContractRecordV1{
		Version:    formalGLMSamplerV2ContractRecordVersion,
		Purpose:    formalGLMSamplerV2ContractRecordPurpose,
		ArtifactID: contract.ArtifactID, PinsetSHA256: store.pinsetSHA256,
		ContractSHA256: contractSHA256, Contract: contract,
	}
	if err := formalGLMSamplerV2ValidateContractRecordV1(
		record, store.pinsetSHA256, store.pins); err != nil {
		return false, err
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > formalGLMSamplerV2ContractMaxRecord {
		return false, fmt.Errorf("formal-glm sampler-v2 contract store: invalid record size")
	}
	relative, err := store.recordRelativePath(contract.ArtifactID, true)
	if err != nil {
		return false, err
	}
	created, err := formalGLMPhase21RootCreateRecord(store.root, relative, encoded)
	if err != nil {
		return false, err
	}
	existing, err := formalGLMPhase21RootReadRecord(
		store.root, relative, formalGLMSamplerV2ContractMaxRecord)
	if err != nil || !bytes.Equal(existing, encoded) {
		return false, fmt.Errorf("formal-glm sampler-v2 contract store: CAS conflict")
	}
	return !created, nil
}

func (store *formalGLMSamplerV2ContractStoreV1) Load(
	artifactID string,
) (formalGLMPhase21SamplerV2Contract, error) {
	var zero formalGLMPhase21SamplerV2Contract
	if store == nil {
		return zero, fmt.Errorf("formal-glm sampler-v2 contract store: unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil {
		return zero, fmt.Errorf("formal-glm sampler-v2 contract store: closed")
	}
	relative, err := store.recordRelativePath(artifactID, false)
	if err != nil {
		return zero, err
	}
	encoded, err := formalGLMPhase21RootReadRecord(
		store.root, relative, formalGLMSamplerV2ContractMaxRecord)
	if err != nil {
		return zero, err
	}
	var record formalGLMSamplerV2ContractRecordV1
	if err := formalGLMPhase21RockStrictDecode(encoded, &record); err != nil ||
		record.ArtifactID != artifactID ||
		formalGLMSamplerV2ValidateContractRecordV1(
			record, store.pinsetSHA256, store.pins) != nil {
		return zero, fmt.Errorf("formal-glm sampler-v2 contract store: invalid persisted record")
	}
	return record.Contract, nil
}
