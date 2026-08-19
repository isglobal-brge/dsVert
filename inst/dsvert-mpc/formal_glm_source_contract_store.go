package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

const (
	formalGLMSourceContractStoreDir = "source-contracts-v1"

	formalGLMSourceContractIntentRecordVersion = "dsvert-formal-glm-source-contract-intent-record-v1"
	formalGLMSourceContractIntentRecordPurpose = "formal_glm_source_contract_no_equivocation_intent_v1"
	formalGLMSourceContractRecordVersion       = "dsvert-formal-glm-source-contract-record-v1"
	formalGLMSourceContractRecordPurpose       = "formal_glm_k_signed_source_contract_record_v1"
	formalGLMSourceContractStoreMaxRecord      = 32 << 20
)

type formalGLMSourceContractIntentRecordV1 struct {
	Version         string                        `json:"version"`
	Purpose         string                        `json:"purpose"`
	ArtifactID      string                        `json:"artifact_id"`
	PinsetSHA256    string                        `json:"pinset_sha256"`
	CoreSHA256      string                        `json:"core_sha256"`
	Core            formalGLMSourceContractCoreV1 `json:"core"`
	ProductionReady bool                          `json:"production_ready"`
}

type formalGLMSourceContractRecordV1 struct {
	Version         string                    `json:"version"`
	Purpose         string                    `json:"purpose"`
	ArtifactID      string                    `json:"artifact_id"`
	PinsetSHA256    string                    `json:"pinset_sha256"`
	CoreSHA256      string                    `json:"core_sha256"`
	ContractSHA256  string                    `json:"contract_sha256"`
	Contract        formalGLMSourceContractV1 `json:"contract"`
	ProductionReady bool                      `json:"production_ready"`
}

type formalGLMSourceContractStoreV1 struct {
	mu           sync.Mutex
	dir          string
	root         *os.Root
	pins         map[string]ed25519.PublicKey
	pinsetSHA256 string
}

func newFormalGLMSourceContractStoreV1(
	dir string,
	pins map[string]ed25519.PublicKey,
) (*formalGLMSourceContractStoreV1, error) {
	pinsetSHA256, err := formalGLMPhase16PinsetSHA256(pins)
	if err != nil {
		return nil, err
	}
	dir, root, err := formalGLMSamplerV2OpenRockRootV1(dir)
	if err != nil {
		return nil, err
	}
	if err := formalGLMPhase21EnsureRootPrivateDir(
		root, formalGLMSourceContractStoreDir); err != nil {
		_ = root.Close()
		return nil, err
	}
	clonedPins := make(map[string]ed25519.PublicKey, len(pins))
	for peer, pin := range pins {
		clonedPins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	return &formalGLMSourceContractStoreV1{
		dir: dir, root: root, pins: clonedPins, pinsetSHA256: pinsetSHA256,
	}, nil
}

func (store *formalGLMSourceContractStoreV1) Close() {
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

func (store *formalGLMSourceContractStoreV1) recordRelativePath(
	artifactID, kind string,
	create bool,
) (string, error) {
	if store == nil || store.root == nil || !formalGLMIsSHA256(artifactID) ||
		(kind != "intent" && kind != "contract") {
		return "", fmt.Errorf("formal-glm source contract store: invalid record")
	}
	shard := filepath.Join(formalGLMSourceContractStoreDir,
		artifactID[:2], artifactID[2:4])
	if create {
		if err := formalGLMPhase21EnsureRootPrivateDir(
			store.root, shard); err != nil {
			return "", err
		}
	} else if err := formalGLMPhase21ValidateRootPrivateDir(
		store.root, shard, false); err != nil {
		return "", err
	}
	return filepath.Join(shard, kind+"-"+artifactID+".json"), nil
}

func (store *formalGLMSourceContractStoreV1) recordPath(
	artifactID, kind string,
	create bool,
) (string, error) {
	relative, err := store.recordRelativePath(artifactID, kind, create)
	if err != nil {
		return "", err
	}
	return filepath.Join(store.dir, relative), nil
}

func formalGLMValidateSourceContractIntentRecordV1(
	record formalGLMSourceContractIntentRecordV1,
	pinsetSHA256 string,
	pins map[string]ed25519.PublicKey,
) error {
	coreSHA256, err := formalGLMSourceContractCoreSHA256V1(record.Core)
	if record.Version != formalGLMSourceContractIntentRecordVersion ||
		record.Purpose != formalGLMSourceContractIntentRecordPurpose ||
		record.ProductionReady || record.ArtifactID != record.Core.ArtifactID ||
		record.PinsetSHA256 != pinsetSHA256 ||
		record.PinsetSHA256 !=
			record.Core.RegisteredExecutionPlan.PinsetSHA256 ||
		err != nil || record.CoreSHA256 != coreSHA256 ||
		formalGLMValidateSourceContractCoreV1(record.Core, pins) != nil {
		return fmt.Errorf("formal-glm source contract store: invalid intent")
	}
	return nil
}

func formalGLMValidateSourceContractRecordV1(
	record formalGLMSourceContractRecordV1,
	pinsetSHA256 string,
	pins map[string]ed25519.PublicKey,
) error {
	contractSHA256, err := formalGLMSourceContractSHA256V1(record.Contract)
	if record.Version != formalGLMSourceContractRecordVersion ||
		record.Purpose != formalGLMSourceContractRecordPurpose ||
		record.ProductionReady ||
		record.ArtifactID != record.Contract.Core.ArtifactID ||
		record.PinsetSHA256 != pinsetSHA256 ||
		record.PinsetSHA256 !=
			record.Contract.Core.RegisteredExecutionPlan.PinsetSHA256 ||
		record.CoreSHA256 != record.Contract.CoreSHA256 ||
		err != nil || record.ContractSHA256 != contractSHA256 ||
		formalGLMValidateSourceContractV1(record.Contract, pins) != nil {
		return fmt.Errorf("formal-glm source contract store: invalid contract")
	}
	return nil
}

func (store *formalGLMSourceContractStoreV1) reserveLocked(
	core formalGLMSourceContractCoreV1,
) (bool, error) {
	if store.root == nil ||
		formalGLMValidateSourceContractCoreV1(core, store.pins) != nil {
		return false, fmt.Errorf("formal-glm source contract store: invalid reserve")
	}
	coreSHA256, err := formalGLMSourceContractCoreSHA256V1(core)
	if err != nil {
		return false, err
	}
	record := formalGLMSourceContractIntentRecordV1{
		Version:    formalGLMSourceContractIntentRecordVersion,
		Purpose:    formalGLMSourceContractIntentRecordPurpose,
		ArtifactID: core.ArtifactID, PinsetSHA256: store.pinsetSHA256,
		CoreSHA256: coreSHA256, Core: core, ProductionReady: false,
	}
	if err := formalGLMValidateSourceContractIntentRecordV1(
		record, store.pinsetSHA256, store.pins); err != nil {
		return false, err
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > formalGLMSourceContractStoreMaxRecord {
		return false,
			fmt.Errorf("formal-glm source contract store: invalid intent size")
	}
	relative, err := store.recordRelativePath(core.ArtifactID, "intent", true)
	if err != nil {
		return false, err
	}
	created, err := formalGLMPhase21RootCreateRecord(
		store.root, relative, encoded)
	if err != nil {
		return false, err
	}
	existing, err := formalGLMPhase21RootReadRecord(
		store.root, relative, formalGLMSourceContractStoreMaxRecord)
	if err != nil || !bytes.Equal(existing, encoded) {
		return false,
			fmt.Errorf("formal-glm source contract store: intent CAS conflict")
	}
	return !created, nil
}

func (store *formalGLMSourceContractStoreV1) Reserve(
	core formalGLMSourceContractCoreV1,
) (bool, error) {
	if store == nil {
		return false, fmt.Errorf("formal-glm source contract store: unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.reserveLocked(core)
}

// Sign durably reserves the ArtifactID-to-core mapping before producing the
// approval. A crash can lose the returned signature, but can never authorize a
// second source core for the same ArtifactID.
func (store *formalGLMSourceContractStoreV1) Sign(
	core formalGLMSourceContractCoreV1,
	signer string,
	privateKey ed25519.PrivateKey,
) (jointDPBiomedicalGaussianSignature, error) {
	var zero jointDPBiomedicalGaussianSignature
	if store == nil {
		return zero, fmt.Errorf("formal-glm source contract store: unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	peers := core.RegisteredExecutionPlan.CustodianPeers
	index := sort.SearchStrings(peers, signer)
	if store.root == nil || index == len(peers) || peers[index] != signer ||
		len(privateKey) != ed25519.PrivateKeySize ||
		!bytes.Equal(privateKey.Public().(ed25519.PublicKey),
			store.pins[signer]) {
		return zero, fmt.Errorf("formal-glm source contract store: invalid signer")
	}
	if _, err := store.reserveLocked(core); err != nil {
		return zero, err
	}
	return formalGLMSignSourceContractV1(
		core, signer, privateKey, store.pins)
}

func (store *formalGLMSourceContractStoreV1) Commit(
	contract formalGLMSourceContractV1,
) (bool, error) {
	if store == nil {
		return false, fmt.Errorf("formal-glm source contract store: unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil ||
		formalGLMValidateSourceContractV1(contract, store.pins) != nil {
		return false, fmt.Errorf("formal-glm source contract store: invalid commit")
	}
	intent, err := store.loadIntentLocked(contract.Core.ArtifactID)
	if err != nil || !formalGLMSourceContractCoreEqualV1(intent, contract.Core) {
		return false,
			fmt.Errorf("formal-glm source contract store: missing or conflicting intent")
	}
	contractSHA256, err := formalGLMSourceContractSHA256V1(contract)
	if err != nil {
		return false, err
	}
	record := formalGLMSourceContractRecordV1{
		Version:        formalGLMSourceContractRecordVersion,
		Purpose:        formalGLMSourceContractRecordPurpose,
		ArtifactID:     contract.Core.ArtifactID,
		PinsetSHA256:   store.pinsetSHA256,
		CoreSHA256:     contract.CoreSHA256,
		ContractSHA256: contractSHA256,
		Contract:       contract, ProductionReady: false,
	}
	if err := formalGLMValidateSourceContractRecordV1(
		record, store.pinsetSHA256, store.pins); err != nil {
		return false, err
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > formalGLMSourceContractStoreMaxRecord {
		return false,
			fmt.Errorf("formal-glm source contract store: invalid contract size")
	}
	relative, err := store.recordRelativePath(
		contract.Core.ArtifactID, "contract", true)
	if err != nil {
		return false, err
	}
	created, err := formalGLMPhase21RootCreateRecord(
		store.root, relative, encoded)
	if err != nil {
		return false, err
	}
	existing, err := formalGLMPhase21RootReadRecord(
		store.root, relative, formalGLMSourceContractStoreMaxRecord)
	if err != nil || !bytes.Equal(existing, encoded) {
		return false,
			fmt.Errorf("formal-glm source contract store: contract CAS conflict")
	}
	return !created, nil
}

func (store *formalGLMSourceContractStoreV1) loadIntentLocked(
	artifactID string,
) (formalGLMSourceContractCoreV1, error) {
	var zero formalGLMSourceContractCoreV1
	relative, err := store.recordRelativePath(artifactID, "intent", false)
	if err != nil {
		return zero, err
	}
	encoded, err := formalGLMPhase21RootReadRecord(
		store.root, relative, formalGLMSourceContractStoreMaxRecord)
	if err != nil {
		return zero, err
	}
	var record formalGLMSourceContractIntentRecordV1
	if err := formalGLMPhase21RockStrictDecode(encoded, &record); err != nil ||
		record.ArtifactID != artifactID ||
		formalGLMValidateSourceContractIntentRecordV1(
			record, store.pinsetSHA256, store.pins) != nil {
		return zero,
			fmt.Errorf("formal-glm source contract store: invalid persisted intent")
	}
	return record.Core, nil
}

func (store *formalGLMSourceContractStoreV1) LoadIntent(
	artifactID string,
) (formalGLMSourceContractCoreV1, error) {
	var zero formalGLMSourceContractCoreV1
	if store == nil {
		return zero, fmt.Errorf("formal-glm source contract store: unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil {
		return zero, fmt.Errorf("formal-glm source contract store: closed")
	}
	return store.loadIntentLocked(artifactID)
}

func (store *formalGLMSourceContractStoreV1) Load(
	artifactID string,
) (formalGLMSourceContractV1, error) {
	var zero formalGLMSourceContractV1
	if store == nil {
		return zero, fmt.Errorf("formal-glm source contract store: unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil {
		return zero, fmt.Errorf("formal-glm source contract store: closed")
	}
	relative, err := store.recordRelativePath(artifactID, "contract", false)
	if err != nil {
		return zero, err
	}
	encoded, err := formalGLMPhase21RootReadRecord(
		store.root, relative, formalGLMSourceContractStoreMaxRecord)
	if err != nil {
		return zero, err
	}
	var record formalGLMSourceContractRecordV1
	if err := formalGLMPhase21RockStrictDecode(encoded, &record); err != nil ||
		record.ArtifactID != artifactID ||
		formalGLMValidateSourceContractRecordV1(
			record, store.pinsetSHA256, store.pins) != nil {
		return zero,
			fmt.Errorf("formal-glm source contract store: invalid persisted contract")
	}
	return record.Contract, nil
}

func formalGLMSourceContractCoreEqualV1(
	left, right formalGLMSourceContractCoreV1,
) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}
