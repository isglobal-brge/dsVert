package main

// Recipient-local durable CAS for capsule-free registered Phase-1.8 ingress.
// This is a low-level internal substrate for frames already authenticated by
// the registered codec, not a DSI/caller ingress or a provenance-complete E2E
// boundary. A later high-level ingress must construct those frames from the
// recipient ticket, signed source envelopes and K-receipt root. Only the
// authenticated outer frame is persisted here; this store never decrypts or
// returns the private block.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
)

const (
	formalGLMRegisteredPhase18IngressStoreReceiptVersionV3 = "dsvert-formal-glm-registered-phase18-ingress-store-receipt-v3"
	formalGLMRegisteredPhase18IngressStoreReceiptPurposeV3 = "formal_glm_recipient_local_registered_phase18_ingress_v3"
)

// formalGLMRegisteredPhase18IngressStoreReceiptV3 is safe routing evidence.
// It intentionally contains neither a filesystem path nor frame/ciphertext
// bytes.
type formalGLMRegisteredPhase18IngressStoreReceiptV3 struct {
	Version                   string
	Purpose                   string
	Handle                    string
	ArtifactID                string
	SourceContractSHA256      string
	AuthorizationSHA256       string
	GlobalMaterializationRoot string
	Source                    string
	Recipient                 string
	BlockIndex                int
	FrameSHA256               string
	ProductionReady           bool
}

type formalGLMRegisteredPhase18IngressStoreV3 struct {
	mu                                sync.Mutex
	root                              *os.Root
	recipient                         string
	localKey                          [32]byte
	contract                          formalGLMSourceContractV1
	expectedGlobalMaterializationRoot string
	pins                              map[string]ed25519.PublicKey
	context                           *formalGLMRegisteredPhase18ValidationContextV3
}

func formalGLMRegisteredPhase18ValidateStoreDirV3(root *os.Root,
	name string,
) error {
	if err := formalGLMPhase21ValidateRootPrivateDir(
		root, name, false); err != nil {
		return err
	}
	current := ""
	for _, part := range strings.Split(filepath.ToSlash(name), "/") {
		current = filepath.Join(current, part)
		info, err := root.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 ||
			!formalFinalizerHandoffPrivateOwnedDirectory(info) {
			return fmt.Errorf("formal-glm registered Phase-1.8 store: unsafe durable directory")
		}
	}
	return nil
}

func formalGLMRegisteredPhase18EnsureStoreDirV3(root *os.Root,
	name string,
) error {
	if root == nil || name == "" || filepath.IsAbs(name) ||
		filepath.Clean(name) != name {
		return fmt.Errorf("formal-glm registered Phase-1.8 store: invalid durable directory")
	}
	if err := root.MkdirAll(name, 0o700); err != nil {
		return err
	}
	return formalGLMRegisteredPhase18ValidateStoreDirV3(root, name)
}

func newFormalGLMRegisteredPhase18IngressStoreV3(
	rockRoot string,
	recipient string,
	localKey [32]byte,
	contract formalGLMSourceContractV1,
	expectedGlobalMaterializationRoot string,
	pins map[string]ed25519.PublicKey,
) (*formalGLMRegisteredPhase18IngressStoreV3, error) {
	if !filepath.IsAbs(rockRoot) || filepath.Clean(rockRoot) != rockRoot ||
		!formalGLMPhase19KeyValid(localKey) ||
		!formalGLMIsSHA256(expectedGlobalMaterializationRoot) ||
		exactGCValidateLabel("registered Phase-1.8 store recipient",
			recipient, 128) != nil ||
		formalGLMValidateSourceContractV1(contract, pins) != nil {
		return nil, fmt.Errorf("formal-glm registered Phase-1.8 store: invalid policy")
	}
	recipientFound := false
	for _, peer := range contract.Core.RegisteredExecutionPlan.DesignatedComputePeers {
		if peer == recipient {
			recipientFound = true
		}
	}
	if !recipientFound {
		return nil, fmt.Errorf("formal-glm registered Phase-1.8 store: recipient is not designated")
	}
	if err := formalFinalizerHandoffEnsurePrivateDir(rockRoot); err != nil {
		return nil, err
	}
	rootInfo, err := os.Lstat(rockRoot)
	if err != nil || rootInfo.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf("formal-glm registered Phase-1.8 store: unsafe Rock root")
	}
	resolved, err := filepath.EvalSymlinks(rockRoot)
	if err != nil || filepath.Clean(resolved) != rockRoot {
		return nil, fmt.Errorf("formal-glm registered Phase-1.8 store: unresolved Rock root")
	}
	root, err := os.OpenRoot(rockRoot)
	if err != nil {
		return nil, err
	}
	openedRootInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(rootInfo, openedRootInfo) ||
		openedRootInfo.Mode().Perm() != 0o700 ||
		!formalFinalizerHandoffPrivateOwnedDirectory(openedRootInfo) {
		_ = root.Close()
		return nil, fmt.Errorf("formal-glm registered Phase-1.8 store: Rock root changed while opening")
	}
	if err := formalGLMRegisteredPhase18EnsureStoreDirV3(
		root, formalGLMRegisteredPhase18RecordsDirectoryV3); err != nil {
		_ = root.Close()
		return nil, err
	}
	contractJSON, err := json.Marshal(contract)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	clonedContract, err := formalGLMDecodeSourceContractV1(contractJSON, pins)
	clear(contractJSON)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	clonedPins := make(map[string]ed25519.PublicKey, len(pins))
	for peer, pin := range pins {
		clonedPins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	contractSHA256, err := formalGLMSourceContractSHA256V1(clonedContract)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	provenanceContext := formalGLMRegisteredPhase18ProvenanceContextV1{
		contract: clonedContract, contractSHA256: contractSHA256,
		pins: clonedPins,
	}
	validationContext, err :=
		formalGLMRegisteredPhase18ValidationContextFromProvenanceV3(
			provenanceContext)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	return &formalGLMRegisteredPhase18IngressStoreV3{
		root: root, recipient: recipient, localKey: localKey,
		contract:                          clonedContract,
		expectedGlobalMaterializationRoot: expectedGlobalMaterializationRoot,
		pins:                              clonedPins,
		context:                           validationContext,
	}, nil
}

func (store *formalGLMRegisteredPhase18IngressStoreV3) Close() {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root != nil {
		_ = store.root.Close()
		store.root = nil
	}
	clear(store.localKey[:])
	for peer := range store.pins {
		clear(store.pins[peer])
		delete(store.pins, peer)
	}
}

func (store *formalGLMRegisteredPhase18IngressStoreV3) slotIDLocked(
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	blockIndex int,
) (string, error) {
	if store == nil || store.context == nil {
		return "", fmt.Errorf("formal-glm registered Phase-1.8 store: invalid authorization")
	}
	expected, found := store.context.authorization(
		authorization.LocalSource.SignerPeerName)
	if !found || !reflect.DeepEqual(expected, authorization) {
		return "", fmt.Errorf("formal-glm registered Phase-1.8 store: invalid authorization")
	}
	return store.slotIDWithContextLocked(
		authorization.LocalSource.SignerPeerName, blockIndex, store.context)
}

func (store *formalGLMRegisteredPhase18IngressStoreV3) slotIDWithContextLocked(
	source string,
	blockIndex int,
	context *formalGLMRegisteredPhase18ValidationContextV3,
) (string, error) {
	if store == nil || store.root == nil || context == nil ||
		context != store.context {
		return "", fmt.Errorf("formal-glm registered Phase-1.8 store: invalid authorization")
	}
	authorization, found := context.authorization(source)
	if !found {
		return "", fmt.Errorf("formal-glm registered Phase-1.8 store: invalid authorization")
	}
	recipientFound := false
	for _, peer := range authorization.DesignatedComputePeers {
		if peer == store.recipient {
			recipientFound = true
		}
	}
	if !recipientFound {
		return "", fmt.Errorf("formal-glm registered Phase-1.8 store: recipient mismatch")
	}
	if _, _, err := formalGLMRegisteredPhase18ExpectedShapeV3(
		authorization, blockIndex); err != nil {
		return "", err
	}
	message := formalGLMPhase15AppendString(
		nil, formalGLMRegisteredPhase18IngressSlotDomainV3)
	message = formalGLMPhase15AppendString(
		message, authorization.SourceContractSHA256)
	message = formalGLMPhase15AppendString(
		message, authorization.AuthorizationSHA256)
	message = formalGLMPhase15AppendString(
		message, store.expectedGlobalMaterializationRoot)
	message = formalGLMPhase15AppendString(
		message, authorization.LocalSource.SignerPeerName)
	message = formalGLMPhase15AppendString(message, store.recipient)
	message = formalGLMPhase15AppendUint64(message, uint64(blockIndex))
	digest := sha256.Sum256(message)
	return hex.EncodeToString(digest[:]), nil
}

func (store *formalGLMRegisteredPhase18IngressStoreV3) recordRelativePathLocked(
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	blockIndex int,
	create bool,
) (string, string, error) {
	if store == nil || store.context == nil {
		return "", "", fmt.Errorf(
			"formal-glm registered Phase-1.8 store: invalid authorization")
	}
	expected, found := store.context.authorization(
		authorization.LocalSource.SignerPeerName)
	if !found || !reflect.DeepEqual(expected, authorization) {
		return "", "", fmt.Errorf(
			"formal-glm registered Phase-1.8 store: invalid authorization")
	}
	return store.recordRelativePathWithContextLocked(
		authorization.LocalSource.SignerPeerName, blockIndex, create, store.context)
}

func (store *formalGLMRegisteredPhase18IngressStoreV3) recordRelativePathWithContextLocked(
	source string,
	blockIndex int,
	create bool,
	context *formalGLMRegisteredPhase18ValidationContextV3,
) (string, string, error) {
	slotID, err := store.slotIDWithContextLocked(
		source, blockIndex, context)
	if err != nil {
		return "", "", err
	}
	shard := filepath.Join(formalGLMRegisteredPhase18RecordsDirectoryV3,
		slotID[:2], slotID[2:4])
	if create {
		err = formalGLMRegisteredPhase18EnsureStoreDirV3(store.root, shard)
	} else {
		err = formalGLMRegisteredPhase18ValidateStoreDirV3(store.root, shard)
	}
	if err != nil {
		return "", "", err
	}
	return slotID, filepath.Join(shard, "frame-"+slotID+".bin"), nil
}

func formalGLMRegisteredPhase18ReadStoreRecordV3(root *os.Root,
	relative string,
) ([]byte, error) {
	encoded, err := formalGLMPhase21RootReadRecord(
		root, relative, formalGLMRegisteredPhase18MaxIngressFrameV3)
	if err != nil {
		return nil, err
	}
	info, err := root.Lstat(relative)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		!exactGCPrivateOwnedRegular(info) ||
		info.Size() != int64(len(encoded)) {
		clear(encoded)
		return nil, fmt.Errorf("formal-glm registered Phase-1.8 store: unsafe durable record")
	}
	return encoded, nil
}

func formalGLMRegisteredPhase18StoreReceiptForFrameV3(
	frame formalGLMRegisteredPhase18IngressFrameV3,
	handle string,
	encoded []byte,
) formalGLMRegisteredPhase18IngressStoreReceiptV3 {
	digest := sha256.Sum256(encoded)
	return formalGLMRegisteredPhase18IngressStoreReceiptV3{
		Version: formalGLMRegisteredPhase18IngressStoreReceiptVersionV3,
		Purpose: formalGLMRegisteredPhase18IngressStoreReceiptPurposeV3,
		Handle:  handle, ArtifactID: frame.ArtifactID,
		SourceContractSHA256:      frame.SourceContractSHA256,
		AuthorizationSHA256:       frame.RegisteredPhase18AuthorizationSHA256,
		GlobalMaterializationRoot: frame.GlobalMaterializationRoot,
		Source:                    frame.Source, Recipient: frame.Recipient,
		BlockIndex:  frame.BlockIndex,
		FrameSHA256: hex.EncodeToString(digest[:]), ProductionReady: false,
	}
}

func (store *formalGLMRegisteredPhase18IngressStoreV3) decodeLocked(
	encoded []byte,
	blockIndex int,
	expectedHandle string,
) (formalGLMRegisteredPhase18IngressStoreReceiptV3, error) {
	var zero formalGLMRegisteredPhase18IngressStoreReceiptV3
	frame, err := formalGLMRegisteredPhase18DecodeIngressFrameWithContextV3(
		encoded, store.context,
		store.expectedGlobalMaterializationRoot, store.localKey)
	if err != nil {
		return zero, err
	}
	defer clear(frame.Ciphertext)
	if frame.Recipient != store.recipient || frame.BlockIndex != blockIndex {
		return zero, fmt.Errorf("formal-glm registered Phase-1.8 store: local route mismatch")
	}
	handle, err := formalGLMRegisteredPhase18IngressSlotIDWithContextV3(
		frame, store.context, store.expectedGlobalMaterializationRoot)
	if err != nil || handle != expectedHandle {
		return zero, fmt.Errorf("formal-glm registered Phase-1.8 store: durable slot mismatch")
	}
	return formalGLMRegisteredPhase18StoreReceiptForFrameV3(
		frame, handle, encoded), nil
}

func (store *formalGLMRegisteredPhase18IngressStoreV3) Commit(
	encoded []byte,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
) (formalGLMRegisteredPhase18IngressStoreReceiptV3, bool, error) {
	if store == nil {
		return formalGLMRegisteredPhase18IngressStoreReceiptV3{}, false,
			fmt.Errorf("formal-glm registered Phase-1.8 store: unavailable")
	}
	expected, found := store.context.authorization(
		authorization.LocalSource.SignerPeerName)
	if !found || !reflect.DeepEqual(expected, authorization) {
		return formalGLMRegisteredPhase18IngressStoreReceiptV3{}, false,
			fmt.Errorf("formal-glm registered Phase-1.8 store: invalid authorization")
	}
	return store.CommitWithContextV3(encoded, store.context)
}

// CommitWithContextV3 is the typed inner-loop CAS. The supplied trust context
// contains no caller-controlled contract or pinset and must exactly match the
// context fixed when the recipient store was opened.
func (store *formalGLMRegisteredPhase18IngressStoreV3) CommitWithContextV3(
	encoded []byte,
	context *formalGLMRegisteredPhase18ValidationContextV3,
) (formalGLMRegisteredPhase18IngressStoreReceiptV3, bool, error) {
	var zero formalGLMRegisteredPhase18IngressStoreReceiptV3
	if store == nil {
		return zero, false,
			fmt.Errorf("formal-glm registered Phase-1.8 store: unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil {
		return zero, false,
			fmt.Errorf("formal-glm registered Phase-1.8 store: closed")
	}
	if context == nil || context != store.context {
		return zero, false,
			fmt.Errorf("formal-glm registered Phase-1.8 store: context mismatch")
	}
	candidate := append([]byte(nil), encoded...)
	defer clear(candidate)
	frame, err := formalGLMRegisteredPhase18DecodeIngressFrameWithContextV3(
		candidate, context,
		store.expectedGlobalMaterializationRoot, store.localKey)
	if err != nil {
		return zero, false, err
	}
	defer clear(frame.Ciphertext)
	if frame.Recipient != store.recipient {
		return zero, false,
			fmt.Errorf("formal-glm registered Phase-1.8 store: recipient mismatch")
	}
	handle, relative, err := store.recordRelativePathWithContextLocked(
		frame.Source, frame.BlockIndex, true, context)
	if err != nil {
		return zero, false, err
	}
	frameHandle, err := formalGLMRegisteredPhase18IngressSlotIDWithContextV3(
		frame, context, store.expectedGlobalMaterializationRoot)
	if err != nil || frameHandle != handle {
		return zero, false,
			fmt.Errorf("formal-glm registered Phase-1.8 store: slot derivation mismatch")
	}
	created, err := formalGLMPhase21RootCreateRecord(
		store.root, relative, candidate)
	if err != nil {
		return zero, false, err
	}
	persisted, err := formalGLMRegisteredPhase18ReadStoreRecordV3(
		store.root, relative)
	if err != nil {
		return zero, false, err
	}
	defer clear(persisted)
	if !bytes.Equal(persisted, candidate) {
		return zero, false,
			fmt.Errorf("formal-glm registered Phase-1.8 store: durable CAS conflict")
	}
	receipt, err := store.decodeLocked(
		persisted, frame.BlockIndex, handle)
	if err != nil {
		return zero, false, err
	}
	return receipt, !created, nil
}

func (store *formalGLMRegisteredPhase18IngressStoreV3) Load(
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	blockIndex int,
) (formalGLMRegisteredPhase18IngressStoreReceiptV3, error) {
	var zero formalGLMRegisteredPhase18IngressStoreReceiptV3
	if store == nil {
		return zero,
			fmt.Errorf("formal-glm registered Phase-1.8 store: unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil {
		return zero, fmt.Errorf("formal-glm registered Phase-1.8 store: closed")
	}
	handle, relative, err := store.recordRelativePathLocked(
		authorization, blockIndex, false)
	if err != nil {
		return zero, err
	}
	encoded, err := formalGLMRegisteredPhase18ReadStoreRecordV3(
		store.root, relative)
	if err != nil {
		return zero, err
	}
	defer clear(encoded)
	return store.decodeLocked(encoded, blockIndex, handle)
}
