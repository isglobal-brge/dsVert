package main

// Authority-local durable assembler for the public K-signed registered
// Phase-1.8 receipt set. Authority identity is deliberately absent: any
// authority holding the same sealed contract and K receipts derives the same
// canonical receipt-set bytes.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
)

const formalGLMRegisteredPhase18ReceiptSetAssemblerDirV1 = "formal-glm-registered-phase18-receipt-set-assembler-v1"

type formalGLMRegisteredPhase18ReceiptSetAssemblerV1 struct {
	mu       sync.Mutex
	root     *os.Root
	contract formalGLMSourceContractV1
	pins     map[string]ed25519.PublicKey
	context  formalGLMRegisteredPhase18ProvenanceContextV1
}

func newFormalGLMRegisteredPhase18ReceiptSetAssemblerV1(
	rockRoot string,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) (*formalGLMRegisteredPhase18ReceiptSetAssemblerV1, error) {
	clonedPins := make(map[string]ed25519.PublicKey, len(pins))
	for peer, pin := range pins {
		clonedPins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	contractJSON, err := json.Marshal(contract)
	if err != nil {
		return nil, err
	}
	var clonedContract formalGLMSourceContractV1
	err = formalGLMPhase21RockStrictDecode(contractJSON, &clonedContract)
	clear(contractJSON)
	if err != nil {
		return nil, err
	}
	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		clonedContract, clonedPins)
	if err != nil {
		return nil, err
	}
	root, err := formalGLMRegisteredPhase18TicketStoreOpenRootV1(rockRoot)
	if err != nil {
		return nil, err
	}
	if err := formalGLMRegisteredPhase18TicketStoreEnsureDirV1(
		root, formalGLMRegisteredPhase18ReceiptSetAssemblerDirV1); err != nil {
		_ = root.Close()
		return nil, err
	}
	return &formalGLMRegisteredPhase18ReceiptSetAssemblerV1{
		root: root, contract: clonedContract,
		pins: clonedPins, context: context,
	}, nil
}

func (assembler *formalGLMRegisteredPhase18ReceiptSetAssemblerV1) Close() {
	if assembler == nil {
		return
	}
	assembler.mu.Lock()
	defer assembler.mu.Unlock()
	if assembler.root != nil {
		_ = assembler.root.Close()
		assembler.root = nil
	}
	for peer := range assembler.pins {
		clear(assembler.pins[peer])
		delete(assembler.pins, peer)
	}
}

func (assembler *formalGLMRegisteredPhase18ReceiptSetAssemblerV1) sourceIndexLocked(
	source string,
) (int, error) {
	if assembler == nil || assembler.root == nil {
		return -1, fmt.Errorf(
			"formal-glm registered Phase18 receipt-set assembler: closed")
	}
	for index, peer := range assembler.contract.Core.RegisteredExecutionPlan.CustodianPeers {
		if peer == source {
			return index, nil
		}
	}
	return -1, fmt.Errorf(
		"formal-glm registered Phase18 receipt-set assembler: source is not registered")
}

func (assembler *formalGLMRegisteredPhase18ReceiptSetAssemblerV1) artifactDirLocked(
	create bool,
) (string, error) {
	if assembler == nil || assembler.root == nil {
		return "", fmt.Errorf(
			"formal-glm registered Phase18 receipt-set assembler: closed")
	}
	artifactID := assembler.contract.Core.ArtifactID
	if !formalGLMIsSHA256(artifactID) {
		return "", fmt.Errorf(
			"formal-glm registered Phase18 receipt-set assembler: invalid artifact")
	}
	directory := filepath.Join(
		formalGLMRegisteredPhase18ReceiptSetAssemblerDirV1,
		artifactID[:2], artifactID[2:4], artifactID)
	var err error
	if create {
		err = formalGLMRegisteredPhase18TicketStoreEnsureDirV1(
			assembler.root, directory)
	} else {
		err = formalGLMRegisteredPhase18TicketStoreValidateDirV1(
			assembler.root, directory)
	}
	if err != nil {
		return "", err
	}
	return directory, nil
}

func (assembler *formalGLMRegisteredPhase18ReceiptSetAssemblerV1) localReceiptRelativeLocked(
	source string,
	create bool,
) (string, error) {
	index, err := assembler.sourceIndexLocked(source)
	if err != nil {
		return "", err
	}
	directory, err := assembler.artifactDirLocked(create)
	if err != nil {
		return "", err
	}
	return filepath.Join(directory,
		fmt.Sprintf("local-receipt-source-%d.json", index)), nil
}

func (assembler *formalGLMRegisteredPhase18ReceiptSetAssemblerV1) receiptSetRelativeLocked(
	create bool,
) (string, error) {
	directory, err := assembler.artifactDirLocked(create)
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, "receipt-set.json"), nil
}

func formalGLMRegisteredPhase18ReceiptSetAssemblerReadV1(
	root *os.Root,
	relative string,
	maximum int,
) ([]byte, error) {
	encoded, err := formalGLMPhase21RootReadRecord(
		root, relative, int64(maximum))
	if err != nil {
		return nil, err
	}
	info, err := root.Lstat(relative)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		!exactGCPrivateOwnedRegular(info) || info.Size() != int64(len(encoded)) {
		clear(encoded)
		return nil, fmt.Errorf(
			"formal-glm registered Phase18 receipt-set assembler: unsafe record")
	}
	return encoded, nil
}

func (assembler *formalGLMRegisteredPhase18ReceiptSetAssemblerV1) decodeLocalReceiptLocked(
	encoded []byte,
	expectedSource string,
) (formalGLMRegisteredPhase18LocalReceiptV1, error) {
	receipt, err := formalGLMDecodeRegisteredPhase18CanonicalV1[formalGLMRegisteredPhase18LocalReceiptV1](
		encoded, formalGLMRegisteredPhase18LocalReceiptMaxJSON)
	if err == nil {
		err = formalGLMRegisteredPhase18ValidateLocalReceiptWithContextV1(
			assembler.context, receipt)
	}
	if err != nil || receipt.ArtifactID != assembler.contract.Core.ArtifactID ||
		expectedSource != "" && receipt.SourceName != expectedSource {
		return formalGLMRegisteredPhase18LocalReceiptV1{}, fmt.Errorf(
			"formal-glm registered Phase18 receipt-set assembler: invalid local receipt")
	}
	return receipt, nil
}

func (assembler *formalGLMRegisteredPhase18ReceiptSetAssemblerV1) decodeReceiptSetLocked(
	encoded []byte,
) (formalGLMRegisteredPhase18ReceiptSetV1, error) {
	set, err := formalGLMDecodeRegisteredPhase18CanonicalV1[formalGLMRegisteredPhase18ReceiptSetV1](
		encoded, formalGLMRegisteredPhase18ReceiptSetMaxJSON)
	if err == nil {
		err = formalGLMRegisteredPhase18ValidateReceiptSetWithContextV1(
			assembler.context, set)
	}
	if err != nil {
		return formalGLMRegisteredPhase18ReceiptSetV1{}, fmt.Errorf(
			"formal-glm registered Phase18 receipt-set assembler: invalid receipt set")
	}
	return set, nil
}

// CommitLocalReceipt validates and immutably stores one canonical signed
// local receipt in the slot fixed by ArtifactID and SourceName.
func (assembler *formalGLMRegisteredPhase18ReceiptSetAssemblerV1) CommitLocalReceipt(
	encoded []byte,
) ([]byte, bool, error) {
	if assembler == nil {
		return nil, false, fmt.Errorf(
			"formal-glm registered Phase18 receipt-set assembler: unavailable")
	}
	assembler.mu.Lock()
	defer assembler.mu.Unlock()
	if assembler.root == nil {
		return nil, false, fmt.Errorf(
			"formal-glm registered Phase18 receipt-set assembler: closed")
	}
	candidate := append([]byte(nil), encoded...)
	receipt, err := assembler.decodeLocalReceiptLocked(candidate, "")
	if err != nil {
		return nil, false, err
	}
	relative, err := assembler.localReceiptRelativeLocked(
		receipt.SourceName, true)
	if err != nil {
		return nil, false, err
	}
	created, err := formalGLMPhase21RootCreateRecord(
		assembler.root, relative, candidate)
	if err != nil {
		return nil, false, err
	}
	persisted, err := formalGLMRegisteredPhase18ReceiptSetAssemblerReadV1(
		assembler.root, relative,
		formalGLMRegisteredPhase18LocalReceiptMaxJSON)
	if err != nil {
		return nil, false, err
	}
	if _, err := assembler.decodeLocalReceiptLocked(
		persisted, receipt.SourceName); err != nil ||
		!bytes.Equal(persisted, candidate) {
		clear(persisted)
		return nil, false, fmt.Errorf(
			"formal-glm registered Phase18 receipt-set assembler: local receipt CAS conflict")
	}
	return persisted, !created, nil
}

func (assembler *formalGLMRegisteredPhase18ReceiptSetAssemblerV1) loadLocalReceiptsLocked() (
	[]formalGLMRegisteredPhase18LocalReceiptV1, []string, error,
) {
	peers := assembler.contract.Core.RegisteredExecutionPlan.CustodianPeers
	receipts := make([]formalGLMRegisteredPhase18LocalReceiptV1, len(peers))
	paths := make([]string, len(peers))
	for index, peer := range peers {
		relative, err := assembler.localReceiptRelativeLocked(peer, false)
		if err != nil {
			return nil, nil, err
		}
		encoded, err := formalGLMRegisteredPhase18ReceiptSetAssemblerReadV1(
			assembler.root, relative,
			formalGLMRegisteredPhase18LocalReceiptMaxJSON)
		if err != nil {
			return nil, nil, err
		}
		receipt, err := assembler.decodeLocalReceiptLocked(encoded, peer)
		if err != nil {
			return nil, nil, err
		}
		receipts[index] = receipt
		paths[index] = relative
	}
	return receipts, paths, nil
}

func (assembler *formalGLMRegisteredPhase18ReceiptSetAssemblerV1) validateArtifactFilesLocked(
	receiptPaths []string,
	setPath string,
	requireSet bool,
) (bool, error) {
	if len(receiptPaths) != len(
		assembler.contract.Core.RegisteredExecutionPlan.CustodianPeers) ||
		len(receiptPaths) == 0 {
		return false, fmt.Errorf(
			"formal-glm registered Phase18 receipt-set assembler: incomplete receipt files")
	}
	directoryName := filepath.Dir(setPath)
	expected := make(map[string]bool, len(receiptPaths))
	for _, relative := range receiptPaths {
		if filepath.Dir(relative) != directoryName {
			return false, fmt.Errorf(
				"formal-glm registered Phase18 receipt-set assembler: cross-artifact record")
		}
		expected[filepath.Base(relative)] = false
	}
	directory, err := assembler.root.Open(directoryName)
	if err != nil {
		return false, err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil {
		return false, readErr
	}
	if closeErr != nil {
		return false, closeErr
	}
	setPresent := false
	for _, entry := range entries {
		if _, ok := expected[entry.Name()]; ok {
			expected[entry.Name()] = true
			continue
		}
		if entry.Name() == filepath.Base(setPath) {
			setPresent = true
			continue
		}
		if strings.HasPrefix(entry.Name(), ".formal-glm-sticky-") {
			continue
		}
		return false, fmt.Errorf(
			"formal-glm registered Phase18 receipt-set assembler: unexpected artifact record")
	}
	for _, present := range expected {
		if !present {
			return false, fmt.Errorf(
				"formal-glm registered Phase18 receipt-set assembler: incomplete receipt files")
		}
	}
	if requireSet && !setPresent {
		return false, fmt.Errorf(
			"formal-glm registered Phase18 receipt-set assembler: receipt set is missing")
	}
	return setPresent, nil
}

func (assembler *formalGLMRegisteredPhase18ReceiptSetAssemblerV1) buildCandidateSetLocked(
	receipts []formalGLMRegisteredPhase18LocalReceiptV1,
) ([]byte, error) {
	set, err := formalGLMRegisteredPhase18BuildReceiptSetV1(
		assembler.contract, receipts, assembler.pins)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(set)
	if err != nil || len(encoded) > formalGLMRegisteredPhase18ReceiptSetMaxJSON {
		return nil, fmt.Errorf(
			"formal-glm registered Phase18 receipt-set assembler: invalid receipt-set encoding")
	}
	if _, err := assembler.decodeReceiptSetLocked(encoded); err != nil {
		return nil, err
	}
	return encoded, nil
}

func (assembler *formalGLMRegisteredPhase18ReceiptSetAssemblerV1) validatePersistedSetLocked(
	encoded []byte,
) error {
	set, err := assembler.decodeReceiptSetLocked(encoded)
	if err != nil {
		return err
	}
	receipts, receiptPaths, err := assembler.loadLocalReceiptsLocked()
	if err != nil {
		return err
	}
	setPath, err := assembler.receiptSetRelativeLocked(false)
	if err != nil {
		return err
	}
	if _, err := assembler.validateArtifactFilesLocked(
		receiptPaths, setPath, true); err != nil ||
		!reflect.DeepEqual(set.Receipts, receipts) {
		return fmt.Errorf(
			"formal-glm registered Phase18 receipt-set assembler: durable receipt-set mismatch")
	}
	return nil
}

// SealReceiptSet constructs the canonical plan-ordered K receipt set and
// persists it before returning any public evidence.
func (assembler *formalGLMRegisteredPhase18ReceiptSetAssemblerV1) SealReceiptSet() (
	[]byte, bool, error,
) {
	if assembler == nil {
		return nil, false, fmt.Errorf(
			"formal-glm registered Phase18 receipt-set assembler: unavailable")
	}
	assembler.mu.Lock()
	defer assembler.mu.Unlock()
	if assembler.root == nil {
		return nil, false, fmt.Errorf(
			"formal-glm registered Phase18 receipt-set assembler: closed")
	}
	receipts, receiptPaths, err := assembler.loadLocalReceiptsLocked()
	if err != nil {
		return nil, false, err
	}
	setPath, err := assembler.receiptSetRelativeLocked(false)
	if err != nil {
		return nil, false, err
	}
	setPresent, err := assembler.validateArtifactFilesLocked(
		receiptPaths, setPath, false)
	if err != nil {
		return nil, false, err
	}
	if setPresent {
		persisted, err := formalGLMRegisteredPhase18ReceiptSetAssemblerReadV1(
			assembler.root, setPath,
			formalGLMRegisteredPhase18ReceiptSetMaxJSON)
		if err != nil || assembler.validatePersistedSetLocked(persisted) != nil {
			clear(persisted)
			return nil, false, fmt.Errorf(
				"formal-glm registered Phase18 receipt-set assembler: invalid durable receipt set")
		}
		return persisted, true, nil
	}
	candidate, err := assembler.buildCandidateSetLocked(receipts)
	if err != nil {
		return nil, false, err
	}
	created, err := formalGLMPhase21RootCreateRecord(
		assembler.root, setPath, candidate)
	if err != nil {
		return nil, false, err
	}
	persisted, err := formalGLMRegisteredPhase18ReceiptSetAssemblerReadV1(
		assembler.root, setPath,
		formalGLMRegisteredPhase18ReceiptSetMaxJSON)
	if err != nil {
		return nil, false, err
	}
	if !bytes.Equal(persisted, candidate) ||
		assembler.validatePersistedSetLocked(persisted) != nil {
		clear(persisted)
		return nil, false, fmt.Errorf(
			"formal-glm registered Phase18 receipt-set assembler: receipt-set CAS conflict")
	}
	return persisted, !created, nil
}

// LoadReceiptSet revalidates the canonical receipt set and every underlying
// local receipt record against the sealed SourceContract.
func (assembler *formalGLMRegisteredPhase18ReceiptSetAssemblerV1) LoadReceiptSet() (
	[]byte, error,
) {
	if assembler == nil {
		return nil, fmt.Errorf(
			"formal-glm registered Phase18 receipt-set assembler: unavailable")
	}
	assembler.mu.Lock()
	defer assembler.mu.Unlock()
	if assembler.root == nil {
		return nil, fmt.Errorf(
			"formal-glm registered Phase18 receipt-set assembler: closed")
	}
	setPath, err := assembler.receiptSetRelativeLocked(false)
	if err != nil {
		return nil, err
	}
	persisted, err := formalGLMRegisteredPhase18ReceiptSetAssemblerReadV1(
		assembler.root, setPath,
		formalGLMRegisteredPhase18ReceiptSetMaxJSON)
	if err != nil {
		return nil, err
	}
	if err := assembler.validatePersistedSetLocked(persisted); err != nil {
		clear(persisted)
		return nil, err
	}
	return persisted, nil
}
