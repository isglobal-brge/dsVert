package main

// Rock-local authority-root storage for SamplerV2. The root is a dedicated
// owner-only key file and is never marshalled. Signed metadata carries only
// its domain-separated identifiers and the exact authority bindings.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
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
	formalGLMSamplerV2AuthorityRootRecordVersion = "dsvert-formal-glm-sampler-v2-authority-root-v1"
	formalGLMSamplerV2AuthorityRootRecordPurpose = "formal_glm_sampler_v2_rock_local_authority_root_v1"
	formalGLMSamplerV2AuthorityRootDomain        = "dsVert/formal-glm/sampler-v2/authority-root/v1"
	formalGLMSamplerV2AuthorityRootDir           = "sampler-v2-authority-roots-v1"
	formalGLMSamplerV2AuthorityRootMaxRecord     = 16 << 10
	formalGLMSamplerV2AuthorityRootWaitAttempts  = 250
)

type formalGLMSamplerV2AuthorityRootRecordV1 struct {
	Version        string `json:"version"`
	Purpose        string `json:"purpose"`
	PeerName       string `json:"peer_name"`
	Role           string `json:"role"`
	PeerID         string `json:"peer_id"`
	PinsetSHA256   string `json:"pinset_sha256"`
	RockRootSHA256 string `json:"rock_root_sha256"`
	KeyID          string `json:"key_id"`
	RootSHA256     string `json:"root_sha256"`
	Signature      []byte `json:"signature"`
}

type formalGLMSamplerV2AuthorityRootStoreV1 struct {
	mu            sync.Mutex
	dir           string
	root          *os.Root
	peer          string
	role          string
	peerID        string
	pinsetSHA256  string
	authorityRoot [32]byte
}

func formalGLMSamplerV2OpenRockRootV1(dir string) (string, *os.Root, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return "", nil, fmt.Errorf("formal-glm sampler-v2 store: invalid Rock root")
	}
	if info, err := os.Lstat(dir); err == nil &&
		(info.Mode()&os.ModeSymlink != 0 || !info.IsDir()) {
		return "", nil, fmt.Errorf("formal-glm sampler-v2 store: unsafe Rock root")
	} else if err != nil && !os.IsNotExist(err) {
		return "", nil, err
	}
	if err := formalGLMPhase18EnsurePrivateDir(dir); err != nil {
		return "", nil, err
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || !filepath.IsAbs(resolved) {
		return "", nil, fmt.Errorf("formal-glm sampler-v2 store: redirected Rock root")
	}
	resolved = filepath.Clean(resolved)
	root, err := os.OpenRoot(resolved)
	if err != nil {
		return "", nil, err
	}
	return resolved, root, nil
}

func formalGLMSamplerV2HashV1(domain string, value []byte) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(domain))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(value)
	return hex.EncodeToString(digest.Sum(nil))
}

func formalGLMSamplerV2AuthorityRootRecordMessageV1(
	record formalGLMSamplerV2AuthorityRootRecordV1,
) ([]byte, error) {
	record.Signature = nil
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalGLMSamplerV2AuthorityRootDomain+"/record|"),
		encoded...), nil
}

func formalGLMSamplerV2AuthorityRootIdentifiersV1(
	authorityRoot [32]byte, peer, role, peerID string,
) (string, string) {
	rootSHA256 := formalGLMSamplerV2HashV1(
		formalGLMSamplerV2AuthorityRootDomain+"/root", authorityRoot[:])
	binding := []byte(peer + "\x00" + role + "\x00" + peerID + "\x00" + rootSHA256)
	keyID := formalGLMSamplerV2HashV1(
		formalGLMSamplerV2AuthorityRootDomain+"/key-id", binding)
	clear(binding)
	return keyID, rootSHA256
}

func formalGLMSamplerV2ValidateAuthorityRootRecordV1(
	record formalGLMSamplerV2AuthorityRootRecordV1,
	authorityRoot [32]byte,
	peer, role, peerID, pinsetSHA256, rockRootSHA256 string,
	pin ed25519.PublicKey,
) error {
	keyID, rootSHA256 := formalGLMSamplerV2AuthorityRootIdentifiersV1(
		authorityRoot, peer, role, peerID)
	message, messageErr := formalGLMSamplerV2AuthorityRootRecordMessageV1(record)
	defer clear(message)
	if record.Version != formalGLMSamplerV2AuthorityRootRecordVersion ||
		record.Purpose != formalGLMSamplerV2AuthorityRootRecordPurpose ||
		record.PeerName != peer || record.Role != role || record.PeerID != peerID ||
		record.PinsetSHA256 != pinsetSHA256 ||
		record.RockRootSHA256 != rockRootSHA256 || record.KeyID != keyID ||
		record.RootSHA256 != rootSHA256 ||
		!formalGLMPhase19KeyValid(authorityRoot) ||
		messageErr != nil || len(pin) != ed25519.PublicKeySize ||
		len(record.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pin, message, record.Signature) {
		return fmt.Errorf("formal-glm sampler-v2 store: invalid authority-root binding")
	}
	return nil
}

func (store *formalGLMSamplerV2AuthorityRootStoreV1) peerRelativeDir() string {
	return filepath.Join(formalGLMSamplerV2AuthorityRootDir, store.peer)
}

func (store *formalGLMSamplerV2AuthorityRootStoreV1) recordRelativePath() string {
	return filepath.Join(store.peerRelativeDir(), "authority-root.json")
}

func (store *formalGLMSamplerV2AuthorityRootStoreV1) keyRelativePath() string {
	return filepath.Join(store.peerRelativeDir(), "authority-root.key")
}

func (store *formalGLMSamplerV2AuthorityRootStoreV1) readKey() ([32]byte, error) {
	var zero [32]byte
	info, err := store.root.Lstat(store.keyRelativePath())
	if err != nil {
		return zero, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || info.Size() != int64(len(zero)) ||
		!exactGCPrivateOwnedRegular(info) {
		return zero, fmt.Errorf("formal-glm sampler-v2 store: unsafe authority key")
	}
	file, err := store.root.Open(store.keyRelativePath())
	if err != nil {
		return zero, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) ||
		!opened.Mode().IsRegular() || opened.Mode().Perm() != 0o600 ||
		opened.Size() != int64(len(zero)) || !exactGCPrivateOwnedRegular(opened) {
		_ = file.Close()
		return zero, fmt.Errorf("formal-glm sampler-v2 store: unstable authority key")
	}
	var authorityRoot [32]byte
	_, readErr := io.ReadFull(file, authorityRoot[:])
	var extra [1]byte
	_, trailingErr := file.Read(extra[:])
	closeErr := file.Close()
	if readErr != nil || trailingErr != io.EOF || closeErr != nil ||
		!formalGLMPhase19KeyValid(authorityRoot) {
		clear(authorityRoot[:])
		return zero, fmt.Errorf("formal-glm sampler-v2 store: invalid authority key")
	}
	return authorityRoot, nil
}

func (store *formalGLMSamplerV2AuthorityRootStoreV1) createKey() ([32]byte, error) {
	var zero [32]byte
	var authorityRoot [32]byte
	if _, err := io.ReadFull(rand.Reader, authorityRoot[:]); err != nil ||
		!formalGLMPhase19KeyValid(authorityRoot) {
		clear(authorityRoot[:])
		return zero, fmt.Errorf("formal-glm sampler-v2 store: authority-key generation failed")
	}
	file, err := store.root.OpenFile(store.keyRelativePath(),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		clear(authorityRoot[:])
		return zero, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		clear(authorityRoot[:])
		return zero, err
	}
	if err := exactGCWriteFull(file, authorityRoot[:]); err != nil {
		_ = file.Close()
		clear(authorityRoot[:])
		return zero, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		clear(authorityRoot[:])
		return zero, err
	}
	if err := file.Close(); err != nil {
		clear(authorityRoot[:])
		return zero, err
	}
	if err := formalGLMPhase21RootSyncDir(
		store.root, store.keyRelativePath()); err != nil {
		clear(authorityRoot[:])
		return zero, err
	}
	loaded, err := store.readKey()
	if err != nil || !bytes.Equal(loaded[:], authorityRoot[:]) {
		clear(loaded[:])
		clear(authorityRoot[:])
		return zero, fmt.Errorf("formal-glm sampler-v2 store: authority-key persistence failed")
	}
	clear(authorityRoot[:])
	return loaded, nil
}

func (store *formalGLMSamplerV2AuthorityRootStoreV1) loadRecord(
	authorityRoot [32]byte, pin ed25519.PublicKey, rockRootSHA256 string,
) error {
	encoded, err := formalGLMPhase21RootReadRecord(store.root,
		store.recordRelativePath(), formalGLMSamplerV2AuthorityRootMaxRecord)
	if err != nil {
		return err
	}
	var record formalGLMSamplerV2AuthorityRootRecordV1
	if err := formalGLMPhase21RockStrictDecode(encoded, &record); err != nil {
		return fmt.Errorf("formal-glm sampler-v2 store: invalid authority metadata")
	}
	return formalGLMSamplerV2ValidateAuthorityRootRecordV1(
		record, authorityRoot, store.peer, store.role, store.peerID,
		store.pinsetSHA256, rockRootSHA256, pin)
}

func (store *formalGLMSamplerV2AuthorityRootStoreV1) ensureRecord(
	authorityRoot [32]byte, signingKey ed25519.PrivateKey,
	pin ed25519.PublicKey, rockRootSHA256 string,
) error {
	if err := store.loadRecord(authorityRoot, pin, rockRootSHA256); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	keyID, rootSHA256 := formalGLMSamplerV2AuthorityRootIdentifiersV1(
		authorityRoot, store.peer, store.role, store.peerID)
	record := formalGLMSamplerV2AuthorityRootRecordV1{
		Version:  formalGLMSamplerV2AuthorityRootRecordVersion,
		Purpose:  formalGLMSamplerV2AuthorityRootRecordPurpose,
		PeerName: store.peer, Role: store.role, PeerID: store.peerID,
		PinsetSHA256: store.pinsetSHA256, RockRootSHA256: rockRootSHA256,
		KeyID: keyID, RootSHA256: rootSHA256,
	}
	message, err := formalGLMSamplerV2AuthorityRootRecordMessageV1(record)
	if err != nil {
		return err
	}
	record.Signature = ed25519.Sign(signingKey, message)
	clear(message)
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > formalGLMSamplerV2AuthorityRootMaxRecord {
		return fmt.Errorf("formal-glm sampler-v2 store: invalid authority metadata")
	}
	_, err = formalGLMPhase21RootCreateRecord(
		store.root, store.recordRelativePath(), encoded)
	if err != nil {
		return err
	}
	existing, err := formalGLMPhase21RootReadRecord(store.root,
		store.recordRelativePath(), formalGLMSamplerV2AuthorityRootMaxRecord)
	if err != nil || !bytes.Equal(existing, encoded) {
		return fmt.Errorf("formal-glm sampler-v2 store: authority metadata CAS conflict")
	}
	return store.loadRecord(authorityRoot, pin, rockRootSHA256)
}

func newFormalGLMSamplerV2AuthorityRootStoreV1(
	dir, peer, role string, signingKey ed25519.PrivateKey,
	pins map[string]ed25519.PublicKey,
) (*formalGLMSamplerV2AuthorityRootStoreV1, error) {
	if !jointDPBiomedicalGaussianValidPeerName(peer) ||
		(role != "garbler" && role != "evaluator") ||
		len(signingKey) != ed25519.PrivateKeySize ||
		len(pins[peer]) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("formal-glm sampler-v2 store: invalid authority identity")
	}
	public, ok := signingKey.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(public, pins[peer]) {
		return nil, fmt.Errorf("formal-glm sampler-v2 store: unpinned authority identity")
	}
	pinsetSHA256, err := formalGLMPhase16PinsetSHA256(pins)
	if err != nil {
		return nil, err
	}
	peerID, err := formalGLMPhase16PeerID(pins[peer])
	if err != nil {
		return nil, err
	}
	dir, root, err := formalGLMSamplerV2OpenRockRootV1(dir)
	if err != nil {
		return nil, err
	}
	store := &formalGLMSamplerV2AuthorityRootStoreV1{
		dir: dir, root: root, peer: peer, role: role,
		peerID: peerID, pinsetSHA256: pinsetSHA256,
	}
	fail := func(err error) (*formalGLMSamplerV2AuthorityRootStoreV1, error) {
		store.Close()
		return nil, err
	}
	if err := formalGLMPhase21EnsureRootPrivateDir(
		root, formalGLMSamplerV2AuthorityRootDir); err != nil {
		return fail(err)
	}
	// The peer directory is the burn-before-use marker. A crash after this
	// mkdir but before a complete O_EXCL key (including a partial key write)
	// intentionally leaves an unrecoverable store: retry never generates a
	// second root. Only a complete key with missing metadata is recoverable.
	createdPeer := false
	if err := root.Mkdir(store.peerRelativeDir(), 0o700); err == nil {
		createdPeer = true
	} else if !os.IsExist(err) {
		return fail(err)
	}
	if err := formalGLMPhase21ValidateRootPrivateDir(
		root, store.peerRelativeDir(), false); err != nil {
		return fail(err)
	}
	rockRootSHA256 := formalGLMSamplerV2HashV1(
		formalGLMSamplerV2AuthorityRootDomain+"/rock-root", []byte(dir))
	pin := append(ed25519.PublicKey(nil), pins[peer]...)
	var authorityRoot [32]byte
	if createdPeer {
		authorityRoot, err = store.createKey()
	} else {
		for attempt := 0; attempt < formalGLMSamplerV2AuthorityRootWaitAttempts; attempt++ {
			authorityRoot, err = store.readKey()
			if err == nil {
				break
			}
			if _, recordErr := root.Lstat(store.recordRelativePath()); recordErr == nil {
				break
			} else if !os.IsNotExist(recordErr) {
				err = recordErr
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
	if err == nil {
		err = store.ensureRecord(authorityRoot, signingKey, pin, rockRootSHA256)
	}
	clear(pin)
	if err != nil {
		clear(authorityRoot[:])
		return fail(fmt.Errorf("formal-glm sampler-v2 store: authority root unavailable"))
	}
	store.authorityRoot = authorityRoot
	clear(authorityRoot[:])
	return store, nil
}

func (store *formalGLMSamplerV2AuthorityRootStoreV1) Close() {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	clear(store.authorityRoot[:])
	if store.root != nil {
		_ = store.root.Close()
		store.root = nil
	}
}

func (store *formalGLMSamplerV2AuthorityRootStoreV1) DeriveCommitment(
	artifactID, samplerMode string,
) (formalGLMPhase21SamplerV2Commitment, error) {
	var zero formalGLMPhase21SamplerV2Commitment
	if store == nil {
		return zero, fmt.Errorf("formal-glm sampler-v2 store: unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil || !formalGLMPhase19KeyValid(store.authorityRoot) {
		return zero, fmt.Errorf("formal-glm sampler-v2 store: closed")
	}
	seed, commitment, err := formalGLMPhase21SamplerV2Derive(
		store.authorityRoot, artifactID, samplerMode,
		store.role, store.peer, store.peerID)
	clear(seed[:])
	if err != nil {
		return zero, err
	}
	return commitment, nil
}
