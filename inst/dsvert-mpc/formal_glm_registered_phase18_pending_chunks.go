package main

// Recipient-local, restart-safe assembly of a bounded opaque Phase-1.8 pair.
// The client may relay only one fixed-size encrypted frame at a time.  The
// signed pair is parsed exactly once, after its raw SHA-256 is complete; no
// fragment becomes an ingress record by itself.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
)

const (
	formalGLMRegisteredPhase18PendingPairChunkDirV1 = "formal-glm-registered-phase18-pending-pair-chunks-v1"

	formalGLMRegisteredPhase18PendingPairChunkVersionV1 = "dsvert-formal-glm-registered-phase18-pending-pair-chunk-v1"
	formalGLMRegisteredPhase18PendingPairChunkPurposeV1 = "formal_glm_recipient_local_bounded_signed_pair_chunk_v1"
	formalGLMRegisteredPhase18PendingPairChunkMaxV1     = formalGLMRegisteredPhase18SourceOutboxChunkMaxV3

	formalGLMRegisteredPhase18PendingPairChunkHeaderFileV1    = "header.json"
	formalGLMRegisteredPhase18PendingPairChunkCommittedFileV1 = "committed.json"
)

type formalGLMRegisteredPhase18PendingPairChunkHeaderV1 struct {
	Version              string `json:"version"`
	Purpose              string `json:"purpose"`
	ArtifactID           string `json:"artifact_id"`
	SourceContractSHA256 string `json:"source_contract_sha256"`
	AuthorizationSHA256  string `json:"authorization_sha256"`
	Recipient            string `json:"recipient"`
	Source               string `json:"source"`
	BlockIndex           int    `json:"block_index"`
	PairSHA256           string `json:"pair_sha256"`
	PairBytes            int    `json:"pair_bytes"`
	ProductionReady      bool   `json:"production_ready"`
}

type formalGLMRegisteredPhase18PendingPairChunkCommittedV1 struct {
	Version         string                                             `json:"version"`
	Purpose         string                                             `json:"purpose"`
	Header          formalGLMRegisteredPhase18PendingPairChunkHeaderV1 `json:"header"`
	PendingReceipt  formalGLMRegisteredPhase18PendingPairReceiptV1     `json:"pending_receipt"`
	ProductionReady bool                                               `json:"production_ready"`
}

// Safe routing evidence for one receiver-local transfer.  It never contains a
// fragment, a pair payload, input data, validity bits, keys, or a Rock path.
type formalGLMRegisteredPhase18PendingPairChunkReceiptV1 struct {
	Version              string                                          `json:"version"`
	Purpose              string                                          `json:"purpose"`
	ArtifactID           string                                          `json:"artifact_id"`
	SourceContractSHA256 string                                          `json:"source_contract_sha256"`
	AuthorizationSHA256  string                                          `json:"authorization_sha256"`
	Recipient            string                                          `json:"recipient"`
	Source               string                                          `json:"source"`
	BlockIndex           int                                             `json:"block_index"`
	PairSHA256           string                                          `json:"pair_sha256"`
	PairBytes            int                                             `json:"pair_bytes"`
	AcceptedThrough      int64                                           `json:"accepted_through"`
	Complete             bool                                            `json:"complete"`
	PendingReceipt       *formalGLMRegisteredPhase18PendingPairReceiptV1 `json:"pending_receipt,omitempty"`
	Replayed             bool                                            `json:"replayed"`
	ProductionReady      bool                                            `json:"production_ready"`
}

func formalGLMRegisteredPhase18PendingPairChunkFileV1(offset int64) string {
	return fmt.Sprintf("chunk-%08d.bin", offset/int64(formalGLMRegisteredPhase18PendingPairChunkMaxV1))
}

func formalGLMRegisteredPhase18PendingPairChunkReadV1(
	root *os.Root, relative string, maximum int64,
) ([]byte, error) {
	if root == nil || filepath.IsAbs(relative) || filepath.Clean(relative) != relative ||
		maximum < 1 {
		return nil, fmt.Errorf("formal-glm registered Phase-1.8 pending chunks: invalid rooted record")
	}
	info, err := root.Lstat(relative)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || !exactGCPrivateOwnedRegular(info) ||
		info.Size() < 1 || info.Size() > maximum {
		return nil, fmt.Errorf("formal-glm registered Phase-1.8 pending chunks: unsafe durable record")
	}
	file, err := root.Open(relative)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, opened) ||
		!exactGCPrivateOwnedRegular(opened) || opened.Mode().Perm() != 0o600 ||
		opened.Size() != info.Size() {
		_ = file.Close()
		return nil, fmt.Errorf("formal-glm registered Phase-1.8 pending chunks: record changed")
	}
	value := make([]byte, opened.Size())
	_, readErr := io.ReadFull(file, value)
	closeErr := file.Close()
	if readErr != nil {
		clear(value)
		return nil, readErr
	}
	if closeErr != nil {
		clear(value)
		return nil, closeErr
	}
	return value, nil
}

func formalGLMRegisteredPhase18PendingPairChunkCreateV1(
	root *os.Root, relative string, value []byte, maximum int64,
) (bool, error) {
	if len(value) == 0 || int64(len(value)) > maximum {
		return false, fmt.Errorf("formal-glm registered Phase-1.8 pending chunks: invalid record size")
	}
	file, err := root.OpenFile(relative, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if os.IsExist(err) {
		persisted, readErr := formalGLMRegisteredPhase18PendingPairChunkReadV1(root, relative, maximum)
		if readErr != nil {
			return false, readErr
		}
		defer clear(persisted)
		if !bytes.Equal(persisted, value) {
			return false, fmt.Errorf("formal-glm registered Phase-1.8 pending chunks: durable CAS conflict")
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return false, err
	}
	if err := exactGCWriteFull(file, value); err != nil {
		_ = file.Close()
		return false, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return false, err
	}
	if err := file.Close(); err != nil {
		return false, err
	}
	if err := formalGLMPhase21RootSyncDir(root, relative); err != nil {
		return false, err
	}
	persisted, err := formalGLMRegisteredPhase18PendingPairChunkReadV1(root, relative, maximum)
	if err != nil {
		return false, err
	}
	defer clear(persisted)
	if !bytes.Equal(persisted, value) {
		return false, fmt.Errorf("formal-glm registered Phase-1.8 pending chunks: durable readback conflict")
	}
	return true, nil
}

func (store *formalGLMRegisteredPhase18PendingPairStoreV1) chunkHeaderLocked(
	receipt formalGLMRegisteredPhase18SourceOutboxChunkReceiptV3,
	chunk []byte,
) (formalGLMRegisteredPhase18PendingPairChunkHeaderV1, error) {
	var zero formalGLMRegisteredPhase18PendingPairChunkHeaderV1
	if receipt.PairBytes < 2 ||
		int64(receipt.PairBytes) > formalGLMRegisteredPhase18PendingPairRecordMaxV1 ||
		receipt.Offset < 0 || receipt.Offset >= int64(receipt.PairBytes) {
		return zero, fmt.Errorf("formal-glm registered Phase-1.8 pending chunks: invalid source chunk")
	}
	expectedEnd := receipt.Offset + int64(formalGLMRegisteredPhase18PendingPairChunkMaxV1)
	if expectedEnd > int64(receipt.PairBytes) {
		expectedEnd = int64(receipt.PairBytes)
	}
	authorization, _, _, err := store.routeLocked(receipt.Source, receipt.BlockIndex)
	if err != nil || receipt.Version != formalGLMRegisteredPhase18SourceOutboxReceiptVersionV3 ||
		receipt.Purpose != "formal_glm_owner_local_bounded_signed_pair_chunk_v3" ||
		!formalGLMIsSHA256(receipt.Handle) ||
		receipt.ArtifactID != authorization.ArtifactID ||
		receipt.SourceContractSHA256 != authorization.SourceContractSHA256 ||
		receipt.AuthorizationSHA256 != authorization.AuthorizationSHA256 ||
		receipt.Source != authorization.LocalSource.SignerPeerName ||
		receipt.BlockIndex < 0 || !formalGLMIsSHA256(receipt.PairSHA256) ||
		receipt.Offset%int64(formalGLMRegisteredPhase18PendingPairChunkMaxV1) != 0 ||
		len(chunk) == 0 || len(chunk) > formalGLMRegisteredPhase18PendingPairChunkMaxV1 ||
		receipt.ChunkBytes != len(chunk) || !formalGLMIsSHA256(receipt.ChunkSHA256) ||
		int64(len(chunk)) != expectedEnd-receipt.Offset ||
		receipt.Offset+int64(len(chunk)) > int64(receipt.PairBytes) ||
		receipt.Complete != (receipt.Offset+int64(len(chunk)) == int64(receipt.PairBytes)) ||
		receipt.ProductionReady {
		return zero, fmt.Errorf("formal-glm registered Phase-1.8 pending chunks: invalid source chunk")
	}
	chunkDigest := sha256.Sum256(chunk)
	if hex.EncodeToString(chunkDigest[:]) != receipt.ChunkSHA256 {
		return zero, fmt.Errorf("formal-glm registered Phase-1.8 pending chunks: chunk digest mismatch")
	}
	return formalGLMRegisteredPhase18PendingPairChunkHeaderV1{
		Version:              formalGLMRegisteredPhase18PendingPairChunkVersionV1,
		Purpose:              formalGLMRegisteredPhase18PendingPairChunkPurposeV1,
		ArtifactID:           receipt.ArtifactID,
		SourceContractSHA256: receipt.SourceContractSHA256,
		AuthorizationSHA256:  receipt.AuthorizationSHA256,
		Recipient:            store.recipient,
		Source:               receipt.Source,
		BlockIndex:           receipt.BlockIndex,
		PairSHA256:           receipt.PairSHA256,
		PairBytes:            receipt.PairBytes,
		ProductionReady:      false,
	}, nil
}

func (store *formalGLMRegisteredPhase18PendingPairStoreV1) chunkRelativeLocked(
	header formalGLMRegisteredPhase18PendingPairChunkHeaderV1,
	create bool,
) (string, string, error) {
	_, sourceIndex, recipientIndex, err := store.routeLocked(header.Source, header.BlockIndex)
	artifactID := store.provenanceContext.contract.Core.ArtifactID
	if err != nil || header.ArtifactID != artifactID || !formalGLMIsSHA256(artifactID) {
		return "", "", fmt.Errorf("formal-glm registered Phase-1.8 pending chunks: invalid route")
	}
	directory := filepath.Join(formalGLMRegisteredPhase18PendingPairChunkDirV1,
		artifactID[:2], artifactID[2:4], artifactID,
		fmt.Sprintf("recipient-%d", recipientIndex), fmt.Sprintf("source-%d", sourceIndex),
		fmt.Sprintf("block-%08d", header.BlockIndex))
	if create {
		err = formalGLMRegisteredPhase18TicketStoreEnsureDirV1(store.root, directory)
	} else {
		err = formalGLMRegisteredPhase18TicketStoreValidateDirV1(store.root, directory)
	}
	if err != nil {
		return "", "", err
	}
	identity := struct {
		Version string                                             `json:"version"`
		Header  formalGLMRegisteredPhase18PendingPairChunkHeaderV1 `json:"header"`
	}{Version: formalGLMRegisteredPhase18PendingPairChunkVersionV1, Header: header}
	encoded, err := json.Marshal(identity)
	if err != nil {
		return "", "", err
	}
	digest := sha256.Sum256(append(
		[]byte("dsVert/formal-glm/registered-phase18/pending-chunks/v1/lock|"), encoded...))
	clear(encoded)
	return directory, hex.EncodeToString(digest[:]), nil
}

func formalGLMRegisteredPhase18PendingPairChunkMakeReceiptV1(
	header formalGLMRegisteredPhase18PendingPairChunkHeaderV1,
	accepted int64,
	complete bool,
	pending *formalGLMRegisteredPhase18PendingPairReceiptV1,
	replayed bool,
) formalGLMRegisteredPhase18PendingPairChunkReceiptV1 {
	return formalGLMRegisteredPhase18PendingPairChunkReceiptV1{
		Version:    formalGLMRegisteredPhase18PendingPairChunkVersionV1,
		Purpose:    formalGLMRegisteredPhase18PendingPairChunkPurposeV1,
		ArtifactID: header.ArtifactID, SourceContractSHA256: header.SourceContractSHA256,
		AuthorizationSHA256: header.AuthorizationSHA256, Recipient: header.Recipient,
		Source: header.Source, BlockIndex: header.BlockIndex,
		PairSHA256: header.PairSHA256, PairBytes: header.PairBytes,
		AcceptedThrough: accepted, Complete: complete, PendingReceipt: pending,
		Replayed: replayed, ProductionReady: false,
	}
}

func formalGLMRegisteredPhase18PendingPairChunkLoadHeaderV1(
	root *os.Root, relative string,
	header formalGLMRegisteredPhase18PendingPairChunkHeaderV1,
) error {
	encoded, err := formalGLMRegisteredPhase18PendingPairChunkReadV1(
		root, filepath.Join(relative, formalGLMRegisteredPhase18PendingPairChunkHeaderFileV1), 64<<10)
	if err != nil {
		return err
	}
	defer clear(encoded)
	var persisted formalGLMRegisteredPhase18PendingPairChunkHeaderV1
	if formalGLMPhase21RockStrictDecode(encoded, &persisted) != nil ||
		!reflect.DeepEqual(persisted, header) {
		return fmt.Errorf("formal-glm registered Phase-1.8 pending chunks: invalid durable header")
	}
	return nil
}

func formalGLMRegisteredPhase18PendingPairChunkAcceptedV1(
	root *os.Root, relative string,
	header formalGLMRegisteredPhase18PendingPairChunkHeaderV1,
) (int64, error) {
	for offset := int64(0); offset < int64(header.PairBytes); {
		end := offset + int64(formalGLMRegisteredPhase18PendingPairChunkMaxV1)
		if end > int64(header.PairBytes) {
			end = int64(header.PairBytes)
		}
		encoded, err := formalGLMRegisteredPhase18PendingPairChunkReadV1(
			root, filepath.Join(relative, formalGLMRegisteredPhase18PendingPairChunkFileV1(offset)),
			int64(formalGLMRegisteredPhase18PendingPairChunkMaxV1))
		if os.IsNotExist(err) {
			return offset, nil
		}
		if err != nil {
			return 0, err
		}
		if len(encoded) != int(end-offset) {
			clear(encoded)
			return 0, fmt.Errorf("formal-glm registered Phase-1.8 pending chunks: invalid durable chunk length")
		}
		clear(encoded)
		offset = end
	}
	return int64(header.PairBytes), nil
}

func formalGLMRegisteredPhase18PendingPairChunkAssembleV1(
	root *os.Root, relative string,
	header formalGLMRegisteredPhase18PendingPairChunkHeaderV1,
) ([]byte, error) {
	pairJSON := make([]byte, header.PairBytes)
	for offset := int64(0); offset < int64(header.PairBytes); {
		end := offset + int64(formalGLMRegisteredPhase18PendingPairChunkMaxV1)
		if end > int64(header.PairBytes) {
			end = int64(header.PairBytes)
		}
		chunk, err := formalGLMRegisteredPhase18PendingPairChunkReadV1(
			root, filepath.Join(relative, formalGLMRegisteredPhase18PendingPairChunkFileV1(offset)),
			int64(formalGLMRegisteredPhase18PendingPairChunkMaxV1))
		if err != nil || len(chunk) != int(end-offset) {
			clear(chunk)
			clear(pairJSON)
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("formal-glm registered Phase-1.8 pending chunks: incomplete pair")
		}
		copy(pairJSON[offset:end], chunk)
		clear(chunk)
		offset = end
	}
	digest := sha256.Sum256(pairJSON)
	if hex.EncodeToString(digest[:]) != header.PairSHA256 {
		clear(pairJSON)
		return nil, fmt.Errorf("formal-glm registered Phase-1.8 pending chunks: pair digest mismatch")
	}
	return pairJSON, nil
}

func formalGLMRegisteredPhase18PendingPairChunkLoadCommittedV1(
	root *os.Root, relative string,
	header formalGLMRegisteredPhase18PendingPairChunkHeaderV1,
) (formalGLMRegisteredPhase18PendingPairReceiptV1, bool, error) {
	var zero formalGLMRegisteredPhase18PendingPairReceiptV1
	encoded, err := formalGLMRegisteredPhase18PendingPairChunkReadV1(
		root, filepath.Join(relative, formalGLMRegisteredPhase18PendingPairChunkCommittedFileV1), 64<<10)
	if os.IsNotExist(err) {
		return zero, false, nil
	}
	if err != nil {
		return zero, false, err
	}
	defer clear(encoded)
	var committed formalGLMRegisteredPhase18PendingPairChunkCommittedV1
	if formalGLMPhase21RockStrictDecode(encoded, &committed) != nil ||
		committed.Version != formalGLMRegisteredPhase18PendingPairChunkVersionV1 ||
		committed.Purpose != formalGLMRegisteredPhase18PendingPairChunkPurposeV1 ||
		committed.ProductionReady || !reflect.DeepEqual(committed.Header, header) ||
		committed.PendingReceipt.ProductionReady ||
		committed.PendingReceipt.Recipient != header.Recipient ||
		committed.PendingReceipt.Source != header.Source ||
		committed.PendingReceipt.BlockIndex != header.BlockIndex ||
		committed.PendingReceipt.PairSHA256 != header.PairSHA256 {
		return zero, false, fmt.Errorf("formal-glm registered Phase-1.8 pending chunks: invalid completed transfer")
	}
	return committed.PendingReceipt, true, nil
}

func formalGLMRegisteredPhase18PendingPairChunkCleanupV1(
	root *os.Root, relative string,
	header formalGLMRegisteredPhase18PendingPairChunkHeaderV1,
) error {
	changed := false
	for offset := int64(0); offset < int64(header.PairBytes); offset += int64(formalGLMRegisteredPhase18PendingPairChunkMaxV1) {
		name := filepath.Join(relative, formalGLMRegisteredPhase18PendingPairChunkFileV1(offset))
		if err := root.Remove(name); err == nil {
			changed = true
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if changed {
		return formalGLMPhase21RootSyncDir(root, filepath.Join(relative, formalGLMRegisteredPhase18PendingPairChunkHeaderFileV1))
	}
	return nil
}

// CommitChunk persists exactly the next expected opaque fragment.  It may be
// replayed byte-for-byte, but a gap, overlap with different bytes, or a pair
// whose final signed digest differs fails closed before ingress can advance.
func (store *formalGLMRegisteredPhase18PendingPairStoreV1) CommitChunk(
	sourceReceipt formalGLMRegisteredPhase18SourceOutboxChunkReceiptV3,
	chunk []byte,
) (formalGLMRegisteredPhase18PendingPairChunkReceiptV1, error) {
	var zero formalGLMRegisteredPhase18PendingPairChunkReceiptV1
	if store == nil {
		return zero, fmt.Errorf("formal-glm registered Phase-1.8 pending chunks: unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil {
		return zero, fmt.Errorf("formal-glm registered Phase-1.8 pending chunks: closed")
	}
	frame := append([]byte(nil), chunk...)
	defer clear(frame)
	header, err := store.chunkHeaderLocked(sourceReceipt, frame)
	if err != nil {
		return zero, err
	}
	relative, lockSHA256, err := store.chunkRelativeLocked(header, true)
	if err != nil {
		return zero, err
	}
	lock, err := formalFinalizerHandoffAcquireAuthorityLock(store.root, lockSHA256)
	if err != nil {
		return zero, fmt.Errorf("formal-glm registered Phase-1.8 pending chunks: transfer busy")
	}
	defer func() {
		_ = formalFinalizerHandoffUnlockAuthority(lock)
		_ = lock.Close()
	}()
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return zero, err
	}
	defer clear(headerJSON)
	if _, err := formalGLMRegisteredPhase18PendingPairChunkCreateV1(
		store.root, filepath.Join(relative, formalGLMRegisteredPhase18PendingPairChunkHeaderFileV1), headerJSON, 64<<10); err != nil {
		return zero, err
	}
	if err := formalGLMRegisteredPhase18PendingPairChunkLoadHeaderV1(store.root, relative, header); err != nil {
		return zero, err
	}
	if pending, found, err := formalGLMRegisteredPhase18PendingPairChunkLoadCommittedV1(
		store.root, relative, header); err != nil {
		return zero, err
	} else if found {
		if err := formalGLMRegisteredPhase18PendingPairChunkCleanupV1(store.root, relative, header); err != nil {
			return zero, err
		}
		return formalGLMRegisteredPhase18PendingPairChunkMakeReceiptV1(
			header, int64(header.PairBytes), true, &pending, true), nil
	}
	accepted, err := formalGLMRegisteredPhase18PendingPairChunkAcceptedV1(store.root, relative, header)
	if err != nil {
		return zero, err
	}
	if sourceReceipt.Offset > accepted {
		return zero, fmt.Errorf("formal-glm registered Phase-1.8 pending chunks: chunk gap")
	}
	if sourceReceipt.Offset < accepted {
		return formalGLMRegisteredPhase18PendingPairChunkMakeReceiptV1(
			header, accepted, false, nil, true), nil
	}
	if _, err := formalGLMRegisteredPhase18PendingPairChunkCreateV1(
		store.root, filepath.Join(relative, formalGLMRegisteredPhase18PendingPairChunkFileV1(accepted)),
		frame, int64(formalGLMRegisteredPhase18PendingPairChunkMaxV1)); err != nil {
		return zero, err
	}
	accepted, err = formalGLMRegisteredPhase18PendingPairChunkAcceptedV1(store.root, relative, header)
	if err != nil || accepted <= sourceReceipt.Offset {
		if err != nil {
			return zero, err
		}
		return zero, fmt.Errorf("formal-glm registered Phase-1.8 pending chunks: chunk was not durable")
	}
	if accepted != int64(header.PairBytes) {
		return formalGLMRegisteredPhase18PendingPairChunkMakeReceiptV1(
			header, accepted, false, nil, false), nil
	}
	pairJSON, err := formalGLMRegisteredPhase18PendingPairChunkAssembleV1(store.root, relative, header)
	if err != nil {
		return zero, err
	}
	pending, pairReplayed, err := store.commitPairLocked(pairJSON)
	clear(pairJSON)
	if err != nil {
		return zero, err
	}
	committed := formalGLMRegisteredPhase18PendingPairChunkCommittedV1{
		Version: formalGLMRegisteredPhase18PendingPairChunkVersionV1,
		Purpose: formalGLMRegisteredPhase18PendingPairChunkPurposeV1,
		Header:  header, PendingReceipt: pending, ProductionReady: false,
	}
	committedJSON, err := json.Marshal(committed)
	if err != nil {
		return zero, err
	}
	defer clear(committedJSON)
	created, err := formalGLMRegisteredPhase18PendingPairChunkCreateV1(
		store.root, filepath.Join(relative, formalGLMRegisteredPhase18PendingPairChunkCommittedFileV1), committedJSON, 64<<10)
	if err != nil {
		return zero, err
	}
	if err := formalGLMRegisteredPhase18PendingPairChunkCleanupV1(store.root, relative, header); err != nil {
		return zero, err
	}
	return formalGLMRegisteredPhase18PendingPairChunkMakeReceiptV1(
		header, accepted, true, &pending, pairReplayed || !created), nil
}
