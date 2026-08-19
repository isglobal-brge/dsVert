package main

// Rock-local terminal storage-key provider for registered Phase20 jobs. The
// only persisted payload is one random 32-byte root; attempt AEAD keys are
// domain-separated HKDF outputs that exist only in process memory.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/hkdf"
)

const (
	formalGLMRegisteredPhase20JobKeyDomainV1 = "dsVert/formal-glm/registered-phase20/job-key/v1"
	formalGLMRegisteredPhase20JobKeyDirV1    = "registered-phase20-job-key-v1"
	formalGLMRegisteredPhase20JobKeyFileV1   = "storage-root.key"
)

type formalGLMRegisteredPhase20JobKeyContextV1 struct {
	artifactID                    string
	sourceContractCoreSHA256      string
	sourceContractSHA256          string
	pinsetSHA256                  string
	semanticRootSHA256            string
	bindingRecordSHA256           string
	registeredExecutionPlanSHA256 string
	localPeer                     string
	localIndex                    int
}

// All fields are private. JSON marshalling therefore produces {} and cannot
// expose the root, filesystem slot, or any derived attempt key.
type formalGLMRegisteredPhase20JobKeyProviderV1 struct {
	mu sync.Mutex

	root            *os.Root
	context         formalGLMRegisteredPhase20JobKeyContextV1
	slotRelativeDir string
	keyRelativePath string
	storageRoot     [32]byte
}

func formalGLMRegisteredPhase20JobKeyNonzeroV1(value [32]byte) bool {
	return value != [32]byte{}
}

func formalGLMRegisteredPhase20JobKeyContextFromEvidenceV1(
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
	record formalGLMRegisteredPhase19BindingRecordV1,
	localPeer string,
) (formalGLMRegisteredPhase20JobKeyContextV1, error) {
	var zero formalGLMRegisteredPhase20JobKeyContextV1
	if formalGLMValidateSourceContractV1(contract, pins) != nil ||
		formalGLMValidateRegisteredPhase19BindingRecordV1(
			record, contract, pins) != nil {
		return zero, fmt.Errorf(
			"formal-glm registered Phase20 job key: invalid registered evidence")
	}
	plan := contract.Core.RegisteredExecutionPlan
	localIndex := -1
	for index, authority := range plan.NoiseAuthorities {
		if authority.PeerName == localPeer {
			localIndex = index
		}
	}
	if localIndex < 0 || len(plan.NoiseAuthorities) != 2 ||
		localPeer != plan.DesignatedComputePeers[localIndex] {
		return zero, fmt.Errorf(
			"formal-glm registered Phase20 job key: invalid local authority")
	}
	recordSHA256, err := formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase19AttemptDomainV1+"/binding-record", record)
	if err != nil {
		return zero, err
	}
	return formalGLMRegisteredPhase20JobKeyContextV1{
		artifactID:                    record.Binding.ArtifactID,
		sourceContractCoreSHA256:      record.Binding.SourceContractCoreSHA256,
		sourceContractSHA256:          record.Binding.SourceContractSHA256,
		pinsetSHA256:                  record.Binding.PinsetSHA256,
		semanticRootSHA256:            record.Binding.SemanticRootSHA256,
		bindingRecordSHA256:           recordSHA256,
		registeredExecutionPlanSHA256: record.Binding.RegisteredExecutionPlanSHA256,
		localPeer:                     localPeer, localIndex: localIndex,
	}, nil
}

func formalGLMRegisteredPhase20JobKeySlotV1(
	context formalGLMRegisteredPhase20JobKeyContextV1,
) (string, error) {
	if !formalGLMIsSHA256(context.artifactID) ||
		!formalGLMIsSHA256(context.semanticRootSHA256) ||
		!formalGLMIsSHA256(context.bindingRecordSHA256) ||
		context.localIndex < 0 || context.localIndex > 1 ||
		!jointDPBiomedicalGaussianValidPeerName(context.localPeer) {
		return "", fmt.Errorf(
			"formal-glm registered Phase20 job key: invalid storage slot")
	}
	slotSHA256, err := formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase20JobKeyDomainV1+"/slot",
		struct {
			ArtifactID          string `json:"artifact_id"`
			SemanticRootSHA256  string `json:"semantic_root_sha256"`
			BindingRecordSHA256 string `json:"binding_record_sha256"`
			LocalPeer           string `json:"local_peer"`
			LocalIndex          int    `json:"local_index"`
		}{
			ArtifactID:          context.artifactID,
			SemanticRootSHA256:  context.semanticRootSHA256,
			BindingRecordSHA256: context.bindingRecordSHA256,
			LocalPeer:           context.localPeer, LocalIndex: context.localIndex,
		})
	if err != nil {
		return "", err
	}
	return formalGLMRegisteredPhase20JobKeyDirV1 + "-" + slotSHA256, nil
}

func formalGLMRegisteredPhase20ValidateJobKeyDirV1(
	root *os.Root, relative string,
) error {
	if root == nil || relative == "" || filepath.IsAbs(relative) ||
		filepath.Clean(relative) != relative || filepath.Dir(relative) != "." {
		return fmt.Errorf(
			"formal-glm registered Phase20 job key: invalid private directory")
	}
	info, err := root.Lstat(relative)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o700 ||
		!formalFinalizerHandoffPrivateOwnedDirectory(info) {
		return fmt.Errorf(
			"formal-glm registered Phase20 job key: unsafe private directory")
	}
	return nil
}

func formalGLMRegisteredPhase20ReadJobStorageRootV1(
	root *os.Root, slotRelativeDir, keyRelativePath string,
) ([32]byte, error) {
	var zero [32]byte
	if err := formalGLMRegisteredPhase20ValidateJobKeyDirV1(
		root, slotRelativeDir); err != nil ||
		filepath.Dir(keyRelativePath) != slotRelativeDir ||
		filepath.Base(keyRelativePath) != formalGLMRegisteredPhase20JobKeyFileV1 {
		return zero, fmt.Errorf(
			"formal-glm registered Phase20 job key: invalid storage-root path")
	}
	info, err := root.Lstat(keyRelativePath)
	if err != nil {
		return zero, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || info.Size() != int64(len(zero)) ||
		!exactGCPrivateOwnedRegular(info) {
		return zero, fmt.Errorf(
			"formal-glm registered Phase20 job key: unsafe storage root")
	}
	file, err := root.Open(keyRelativePath)
	if err != nil {
		return zero, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) ||
		!opened.Mode().IsRegular() || opened.Mode().Perm() != 0o600 ||
		opened.Size() != int64(len(zero)) ||
		!exactGCPrivateOwnedRegular(opened) {
		_ = file.Close()
		return zero, fmt.Errorf(
			"formal-glm registered Phase20 job key: unstable storage root")
	}
	var storageRoot [32]byte
	_, readErr := io.ReadFull(file, storageRoot[:])
	var extra [1]byte
	readCount, trailingErr := file.Read(extra[:])
	closeErr := file.Close()
	if readErr != nil || readCount != 0 || trailingErr != io.EOF ||
		closeErr != nil || !formalGLMRegisteredPhase20JobKeyNonzeroV1(storageRoot) {
		clear(storageRoot[:])
		return zero, fmt.Errorf(
			"formal-glm registered Phase20 job key: invalid storage root")
	}
	return storageRoot, nil
}

func formalGLMRegisteredPhase20CreateJobStorageRootV1(
	root *os.Root, slotRelativeDir, keyRelativePath string,
) ([32]byte, error) {
	var zero [32]byte
	if err := formalGLMRegisteredPhase20ValidateJobKeyDirV1(
		root, slotRelativeDir); err != nil {
		return zero, err
	}
	var candidate [32]byte
	if _, err := io.ReadFull(rand.Reader, candidate[:]); err != nil ||
		!formalGLMRegisteredPhase20JobKeyNonzeroV1(candidate) {
		clear(candidate[:])
		return zero, fmt.Errorf(
			"formal-glm registered Phase20 job key: root generation failed")
	}
	file, err := root.OpenFile(keyRelativePath,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		clear(candidate[:])
		return zero, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		clear(candidate[:])
		return zero, err
	}
	if err := exactGCWriteFull(file, candidate[:]); err != nil {
		_ = file.Close()
		clear(candidate[:])
		return zero, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		clear(candidate[:])
		return zero, err
	}
	if err := file.Close(); err != nil {
		clear(candidate[:])
		return zero, err
	}
	if err := formalGLMPhase21RootSyncDir(root, keyRelativePath); err != nil {
		clear(candidate[:])
		return zero, err
	}
	loaded, err := formalGLMRegisteredPhase20ReadJobStorageRootV1(
		root, slotRelativeDir, keyRelativePath)
	if err != nil || subtle.ConstantTimeCompare(loaded[:], candidate[:]) != 1 {
		clear(loaded[:])
		clear(candidate[:])
		return zero, fmt.Errorf(
			"formal-glm registered Phase20 job key: root persistence failed")
	}
	clear(candidate[:])
	return loaded, nil
}

func newFormalGLMRegisteredPhase20JobKeyProviderV1(
	rockRoot string,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
	record formalGLMRegisteredPhase19BindingRecordV1,
	localPeer string,
) (*formalGLMRegisteredPhase20JobKeyProviderV1, error) {
	// Validate every signed binding before creating even the Rock directory.
	context, err := formalGLMRegisteredPhase20JobKeyContextFromEvidenceV1(
		contract, pins, record, localPeer)
	if err != nil {
		return nil, err
	}
	slot, err := formalGLMRegisteredPhase20JobKeySlotV1(context)
	if err != nil {
		return nil, err
	}
	root, err := formalGLMRegisteredPhase19OpenRockRootV1(rockRoot)
	if err != nil {
		return nil, err
	}
	provider := &formalGLMRegisteredPhase20JobKeyProviderV1{
		root: root, context: context, slotRelativeDir: slot,
		keyRelativePath: filepath.Join(
			slot, formalGLMRegisteredPhase20JobKeyFileV1),
	}
	fail := func(err error) (*formalGLMRegisteredPhase20JobKeyProviderV1, error) {
		_ = provider.Close()
		return nil, err
	}
	created := false
	if err := root.Mkdir(slot, 0o700); err == nil {
		created = true
		// The durable empty directory is the burn marker. No failure after
		// this sync may generate a replacement root in this slot.
		if err := formalGLMPhase21RootSyncDir(root, slot); err != nil {
			return fail(err)
		}
	} else if !os.IsExist(err) {
		return fail(err)
	}
	if err := formalGLMRegisteredPhase20ValidateJobKeyDirV1(
		root, slot); err != nil {
		return fail(err)
	}
	var storageRoot [32]byte
	if created {
		storageRoot, err = formalGLMRegisteredPhase20CreateJobStorageRootV1(
			root, slot, provider.keyRelativePath)
	} else {
		storageRoot, err = formalGLMRegisteredPhase20ReadJobStorageRootV1(
			root, slot, provider.keyRelativePath)
	}
	if err != nil {
		return fail(err)
	}
	provider.storageRoot = storageRoot
	clear(storageRoot[:])
	return provider, nil
}

func (provider *formalGLMRegisteredPhase20JobKeyProviderV1) validateLocked() error {
	if provider == nil || provider.root == nil ||
		!formalGLMRegisteredPhase20JobKeyNonzeroV1(provider.storageRoot) ||
		!formalGLMIsSHA256(provider.context.artifactID) ||
		!formalGLMIsSHA256(provider.context.sourceContractCoreSHA256) ||
		!formalGLMIsSHA256(provider.context.sourceContractSHA256) ||
		!formalGLMIsSHA256(provider.context.pinsetSHA256) ||
		!formalGLMIsSHA256(provider.context.semanticRootSHA256) ||
		!formalGLMIsSHA256(provider.context.bindingRecordSHA256) ||
		!formalGLMIsSHA256(provider.context.registeredExecutionPlanSHA256) {
		return fmt.Errorf(
			"formal-glm registered Phase20 job key: provider is unavailable")
	}
	return formalGLMRegisteredPhase20ValidateJobKeyDirV1(
		provider.root, provider.slotRelativeDir)
}

func (provider *formalGLMRegisteredPhase20JobKeyProviderV1) validateAttemptLocked(
	binding formalGLMRegisteredPhase19AttemptBindingV1,
) error {
	genesisAbandon := binding.PreviousAbandonSHA256 ==
		formalGLMRegisteredPhase19AttemptZeroPreviousV1
	genesisAttempt := binding.PreviousAttemptID ==
		formalGLMRegisteredPhase19AttemptZeroPreviousV1
	if genesisAbandon != genesisAttempt || (!genesisAbandon &&
		(!formalGLMIsSHA256(binding.PreviousAbandonSHA256) ||
			!formalGLMIsSHA256(binding.PreviousAttemptID))) {
		return fmt.Errorf(
			"formal-glm registered Phase20 job key: invalid attempt predecessor")
	}
	attemptID, err := formalGLMRegisteredPhase19AttemptIDV1(
		provider.context.semanticRootSHA256,
		binding.PreviousAbandonSHA256)
	if err != nil {
		return err
	}
	scheduleRoot, err := formalGLMRegisteredPhase19AttemptScheduleRootV1(
		provider.context.semanticRootSHA256, attemptID)
	if err != nil {
		return err
	}
	want := formalGLMRegisteredPhase19AttemptBindingV1{
		ArtifactID:               provider.context.artifactID,
		SourceContractCoreSHA256: provider.context.sourceContractCoreSHA256,
		SourceContractSHA256:     provider.context.sourceContractSHA256,
		PinsetSHA256:             provider.context.pinsetSHA256,
		SemanticRootSHA256:       provider.context.semanticRootSHA256,
		BindingRecordSHA256:      provider.context.bindingRecordSHA256,
		RegisteredExecutionPlanSHA256: provider.context.
			registeredExecutionPlanSHA256,
		PreviousAbandonSHA256: binding.PreviousAbandonSHA256,
		PreviousAttemptID:     binding.PreviousAttemptID,
		AttemptID:             attemptID,
		ScheduleRootSHA256:    scheduleRoot,
		OpeningsPerformed:     0,
		ProductionReady:       false,
	}
	if binding != want {
		return fmt.Errorf(
			"formal-glm registered Phase20 job key: invalid attempt binding")
	}
	return nil
}

// DeriveAttemptKey returns only the per-attempt AEAD key. The persistent root
// remains private and is revalidated against the owner-only file before use.
func (provider *formalGLMRegisteredPhase20JobKeyProviderV1) DeriveAttemptKey(
	binding formalGLMRegisteredPhase19AttemptBindingV1,
) ([32]byte, error) {
	var zero [32]byte
	if provider == nil {
		return zero, fmt.Errorf(
			"formal-glm registered Phase20 job key: provider is unavailable")
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if err := provider.validateLocked(); err != nil {
		return zero, err
	}
	if err := provider.validateAttemptLocked(binding); err != nil {
		return zero, err
	}
	persisted, err := formalGLMRegisteredPhase20ReadJobStorageRootV1(
		provider.root, provider.slotRelativeDir, provider.keyRelativePath)
	if err != nil || subtle.ConstantTimeCompare(
		persisted[:], provider.storageRoot[:]) != 1 {
		clear(persisted[:])
		return zero, fmt.Errorf(
			"formal-glm registered Phase20 job key: storage root changed")
	}
	clear(persisted[:])
	bindingSHA256, err := formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase20JobKeyDomainV1+"/attempt-binding", binding)
	if err != nil {
		return zero, err
	}
	salt, err := hex.DecodeString(bindingSHA256)
	if err != nil || len(salt) != sha256.Size {
		clear(salt)
		return zero, fmt.Errorf(
			"formal-glm registered Phase20 job key: invalid attempt digest")
	}
	info := []byte(formalGLMRegisteredPhase20JobKeyDomainV1 +
		"/attempt-aead/" + provider.context.localPeer)
	reader := hkdf.New(sha256.New, provider.storageRoot[:], salt, info)
	var key [32]byte
	_, err = io.ReadFull(reader, key[:])
	clear(salt)
	clear(info)
	if err != nil || !formalGLMRegisteredPhase20JobKeyNonzeroV1(key) {
		clear(key[:])
		return zero, fmt.Errorf(
			"formal-glm registered Phase20 job key: derivation failed")
	}
	return key, nil
}

func (provider *formalGLMRegisteredPhase20JobKeyProviderV1) Close() error {
	if provider == nil {
		return nil
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	clear(provider.storageRoot[:])
	if provider.root == nil {
		return nil
	}
	err := provider.root.Close()
	provider.root = nil
	return err
}
