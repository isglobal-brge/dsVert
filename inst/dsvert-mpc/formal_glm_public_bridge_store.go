package main

// Rock-local durable storage for the K-signed PSI bridge set selected by one
// public formal-GLM selector. The selector owns the record path; ArtifactID
// and bridge-set changes therefore collide under one exact CAS record.

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
	formalGLMPublicBridgeRecordVersion = "dsvert-formal-glm-public-bridge-record-v1"
	formalGLMPublicBridgeRecordDir     = "bridge-sets-v1"
	formalGLMPublicBridgeMaxRecord     = 16 << 20
)

type formalGLMPublicBridgeRecordV1 struct {
	Version         string                              `json:"version"`
	SelectorSHA256  string                              `json:"selector_sha256"`
	ArtifactID      string                              `json:"artifact_id"`
	BridgeSetSHA256 string                              `json:"bridge_set_sha256"`
	Receipts        []formalGLMPSISourceBridgeReceiptV1 `json:"receipts"`
	ProductionReady bool                                `json:"production_ready"`
}

type formalGLMPublicBridgeStoreV1 struct {
	mu   sync.Mutex
	dir  string
	root *os.Root
	pins map[string]ed25519.PublicKey
}

func newFormalGLMPublicBridgeStoreV1(
	dir string, pins map[string]ed25519.PublicKey,
) (*formalGLMPublicBridgeStoreV1, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, fmt.Errorf("formal-glm public bridge store: invalid Rock root")
	}
	if info, err := os.Lstat(dir); err == nil &&
		(info.Mode()&os.ModeSymlink != 0 || !info.IsDir()) {
		return nil, fmt.Errorf("formal-glm public bridge store: unsafe Rock root")
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err := formalGLMPhase18EnsurePrivateDir(dir); err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || !filepath.IsAbs(resolved) {
		return nil, fmt.Errorf("formal-glm public bridge store: redirected Rock root")
	}
	dir = filepath.Clean(resolved)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	if err := formalGLMPhase21EnsureRootPrivateDir(
		root, formalGLMPublicBridgeRecordDir); err != nil {
		_ = root.Close()
		return nil, err
	}
	clonedPins := make(map[string]ed25519.PublicKey, len(pins))
	for peer, pin := range pins {
		clonedPins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	if _, err := formalGLMPhase16PinsetSHA256(clonedPins); err != nil {
		_ = root.Close()
		return nil, err
	}
	return &formalGLMPublicBridgeStoreV1{
		dir: dir, root: root, pins: clonedPins,
	}, nil
}

func (store *formalGLMPublicBridgeStoreV1) Close() {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root != nil {
		_ = store.root.Close()
		store.root = nil
	}
}

func (store *formalGLMPublicBridgeStoreV1) recordRelativePath(
	selectorSHA256 string, create bool,
) (string, error) {
	if store == nil || store.root == nil ||
		!formalGLMIsSHA256(selectorSHA256) {
		return "", fmt.Errorf("formal-glm public bridge store: invalid selector")
	}
	shard := filepath.Join(formalGLMPublicBridgeRecordDir,
		selectorSHA256[:2], selectorSHA256[2:4])
	if create {
		if err := formalGLMPhase21EnsureRootPrivateDir(store.root, shard); err != nil {
			return "", err
		}
	} else if err := formalGLMPhase21ValidateRootPrivateDir(
		store.root, shard, false); err != nil {
		return "", err
	}
	return filepath.Join(shard, "bridge-"+selectorSHA256+".json"), nil
}

func formalGLMValidatePublicBridgeRecordV1(
	record formalGLMPublicBridgeRecordV1,
	pins map[string]ed25519.PublicKey,
) error {
	bridgeSetSHA256, err := formalGLMPSISourceBridgeSetSHA256V1(
		record.Receipts, pins)
	if record.Version != formalGLMPublicBridgeRecordVersion ||
		!formalGLMIsSHA256(record.SelectorSHA256) ||
		!formalGLMIsSHA256(record.ArtifactID) ||
		!formalGLMIsSHA256(record.BridgeSetSHA256) ||
		record.ProductionReady || err != nil ||
		bridgeSetSHA256 != record.BridgeSetSHA256 {
		return fmt.Errorf("formal-glm public bridge store: invalid durable record")
	}
	return nil
}

func (store *formalGLMPublicBridgeStoreV1) Commit(
	selectorSHA256, artifactID string,
	receipts []formalGLMPSISourceBridgeReceiptV1,
) (bool, error) {
	if store == nil {
		return false, fmt.Errorf("formal-glm public bridge store: unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil || !formalGLMIsSHA256(selectorSHA256) ||
		!formalGLMIsSHA256(artifactID) {
		return false, fmt.Errorf("formal-glm public bridge store: invalid commit")
	}
	bridgeSetSHA256, err := formalGLMPSISourceBridgeSetSHA256V1(
		receipts, store.pins)
	if err != nil {
		return false, err
	}
	record := formalGLMPublicBridgeRecordV1{
		Version:        formalGLMPublicBridgeRecordVersion,
		SelectorSHA256: selectorSHA256, ArtifactID: artifactID,
		BridgeSetSHA256: bridgeSetSHA256,
		Receipts:        append([]formalGLMPSISourceBridgeReceiptV1(nil), receipts...),
		ProductionReady: false,
	}
	if err := formalGLMValidatePublicBridgeRecordV1(record, store.pins); err != nil {
		return false, err
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > formalGLMPublicBridgeMaxRecord {
		return false, fmt.Errorf("formal-glm public bridge store: invalid record size")
	}
	relative, err := store.recordRelativePath(selectorSHA256, true)
	if err != nil {
		return false, err
	}
	created, err := formalGLMPhase21RootCreateRecord(store.root, relative, encoded)
	if err != nil {
		return false, err
	}
	existing, err := formalGLMPhase21RootReadRecord(
		store.root, relative, formalGLMPublicBridgeMaxRecord)
	if err != nil || !bytes.Equal(existing, encoded) {
		return false, fmt.Errorf("formal-glm public bridge store: CAS conflict")
	}
	return !created, nil
}

func (store *formalGLMPublicBridgeStoreV1) Load(
	selectorSHA256 string,
) (formalGLMPublicBridgeRecordV1, error) {
	var zero formalGLMPublicBridgeRecordV1
	if store == nil {
		return zero, fmt.Errorf("formal-glm public bridge store: unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil || !formalGLMIsSHA256(selectorSHA256) {
		return zero, fmt.Errorf("formal-glm public bridge store: invalid load")
	}
	relative, err := store.recordRelativePath(selectorSHA256, false)
	if err != nil {
		return zero, err
	}
	encoded, err := formalGLMPhase21RootReadRecord(
		store.root, relative, formalGLMPublicBridgeMaxRecord)
	if err != nil {
		return zero, err
	}
	var record formalGLMPublicBridgeRecordV1
	if err := formalGLMPhase21RockStrictDecode(encoded, &record); err != nil ||
		record.SelectorSHA256 != selectorSHA256 ||
		formalGLMValidatePublicBridgeRecordV1(record, store.pins) != nil {
		return zero, fmt.Errorf("formal-glm public bridge store: invalid persisted record")
	}
	return record, nil
}
