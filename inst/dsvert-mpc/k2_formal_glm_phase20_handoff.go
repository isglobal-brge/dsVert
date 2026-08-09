package main

// Durable, server-local handoff from the completed Phase-1.9 schedule to the
// internal Phase-1.6 release adapters.  The handoff is deliberately absent
// from the command surface: it contains one sealed Ring128 source share and
// may only be opened with a key derived from the server-local durable-state
// root.  The separate pairwise backend key authenticates the Phase-1.9
// evidence before that share can enter a release adapter.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	formalGLMPhase20HandoffVersion        = "dsvert-formal-glm-phase20-handoff-record-v1"
	formalGLMPhase20HandoffPayloadVersion = "dsvert-formal-glm-phase20-handoff-payload-v1"
	formalGLMPhase20HandoffDomain         = "dsVert/formal-glm/phase20/handoff/v1"
	formalGLMPhase20HandoffMaxBytes       = 4 << 20
)

type formalGLMPhase20HandoffRecord struct {
	Version            string `json:"version"`
	SemanticRootSHA256 string `json:"semantic_root_sha256"`
	Peer               string `json:"peer"`
	PayloadSHA256      string `json:"payload_sha256"`
	Nonce              string `json:"nonce"`
	Ciphertext         string `json:"ciphertext"`
}

type formalGLMPhase20HandoffPayload struct {
	Version            string                         `json:"version"`
	SemanticRootSHA256 string                         `json:"semantic_root_sha256"`
	Peer               string                         `json:"peer"`
	Plan               formalGLMPhase15Plan           `json:"plan"`
	Context            formalGLMPhase19Context        `json:"context"`
	Result             formalGLMPhase19ScheduleResult `json:"result"`
	OpeningsPerformed  int                            `json:"openings_performed"`
	ProductionReady    bool                           `json:"production_ready"`
}

type formalGLMPhase20HandoffCommit struct {
	SHA256   string
	Bytes    int64
	Replayed bool
}

type formalGLMPhase20HandoffSource struct {
	Plan     formalGLMPhase15Plan
	Context  formalGLMPhase19Context
	Result   formalGLMPhase19ScheduleResult
	DPShares []*big.Int
	backend  [32]byte
}

func (source *formalGLMPhase20HandoffSource) clear() {
	if source == nil {
		return
	}
	exactGCZeroBigInts(source.DPShares)
	clear(source.backend[:])
	*source = formalGLMPhase20HandoffSource{}
}

type formalGLMPhase20HandoffStore struct {
	dir          string
	recordPath   string
	semanticRoot string
	peer         string
	aeadKey      [32]byte
	backend      [32]byte
	pins         map[string]ed25519.PublicKey
}

func formalGLMPhase20HandoffSlotID(semanticRoot, peer string) (string, error) {
	if !formalGLMIsSHA256(semanticRoot) ||
		exactGCValidateLabel("Phase-2.0 handoff peer", peer, 128) != nil {
		return "", fmt.Errorf("formal-glm: invalid Phase-2.0 handoff identity")
	}
	message := formalGLMPhase15AppendString(nil,
		formalGLMPhase20HandoffDomain+"/slot")
	message = formalGLMPhase15AppendString(message, semanticRoot)
	message = formalGLMPhase15AppendString(message, peer)
	digest := sha256.Sum256(message)
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMPhase20HandoffKey(storageRoot [32]byte, semanticRoot, peer string) (
	[32]byte, error) {
	var result [32]byte
	if !formalGLMPhase19KeyValid(storageRoot) {
		return result, fmt.Errorf("formal-glm: missing Phase-2.0 handoff key")
	}
	salt, err := hex.DecodeString(semanticRoot)
	if err != nil || len(salt) != sha256.Size {
		clear(salt)
		return result, fmt.Errorf("formal-glm: invalid Phase-2.0 handoff root")
	}
	reader := hkdf.New(sha256.New, storageRoot[:], salt,
		[]byte(formalGLMPhase20HandoffDomain+"/aead/"+peer))
	_, err = io.ReadFull(reader, result[:])
	clear(salt)
	if err != nil || !formalGLMPhase19KeyValid(result) {
		clear(result[:])
		return result, fmt.Errorf("formal-glm: Phase-2.0 handoff key derivation failed")
	}
	return result, nil
}

func newFormalGLMPhase20HandoffStore(dir, semanticRoot, peer string,
	storageRoot, backend [32]byte, pins map[string]ed25519.PublicKey) (
	*formalGLMPhase20HandoffStore, error) {

	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, fmt.Errorf("formal-glm: invalid Phase-2.0 handoff directory")
	}
	slot, err := formalGLMPhase20HandoffSlotID(semanticRoot, peer)
	if err != nil {
		return nil, err
	}
	key, err := formalGLMPhase20HandoffKey(storageRoot, semanticRoot, peer)
	if err != nil {
		return nil, err
	}
	recordDir := filepath.Join(dir, "records-v1", slot[:2], slot[2:4])
	if err := formalGLMPhase18EnsurePrivateDir(recordDir); err != nil {
		clear(key[:])
		return nil, err
	}
	store := &formalGLMPhase20HandoffStore{
		dir: dir, recordPath: filepath.Join(recordDir, "slot-"+slot+".bin"),
		semanticRoot: semanticRoot, peer: peer, aeadKey: key, backend: backend,
		pins: pins,
	}
	if err := formalGLMPhase20CleanupStaleTemps(recordDir, store.recordPath); err != nil {
		store.close()
		return nil, err
	}
	return store, nil
}

func (store *formalGLMPhase20HandoffStore) close() {
	if store != nil {
		clear(store.aeadKey[:])
		clear(store.backend[:])
	}
}

// A hard-link CAS or consume quarantine can survive a process crash.  Reap
// only owner-only internal names after the same 24-hour grace used by the
// Phase-1.8 durable store.  The scan is streamed in bounded batches so a large
// shard does not become a memory spike.  A committed CAS temporary is removed
// immediately only through the existing same-inode reaper.
func formalGLMPhase20CleanupStaleTemps(root, recordPath string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		filepath.Dir(recordPath) != root {
		return fmt.Errorf("formal-glm: invalid Phase-2.0 cleanup directory")
	}
	directory, err := os.Open(root)
	if err != nil {
		return err
	}
	removed := false
	for {
		names, readErr := directory.Readdirnames(256)
		for _, name := range names {
			isCASTemp := strings.HasPrefix(name, ".gaussian-release-")
			isConsumeQuarantine := strings.HasPrefix(name, ".phase20-consume-")
			if !isCASTemp && !isConsumeQuarantine {
				continue
			}
			path := filepath.Join(root, name)
			info, err := os.Lstat(path)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil || !info.Mode().IsRegular() ||
				info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
				info.Size() > formalGLMPhase20HandoffMaxBytes ||
				(isConsumeQuarantine && info.Size() < 64) {
				_ = directory.Close()
				return fmt.Errorf("formal-glm: unsafe stale Phase-2.0 handoff file")
			}
			if !exactGCPrivateOwnedRegular(info) {
				target, targetErr := os.Lstat(recordPath)
				if targetErr == nil && os.SameFile(info, target) {
					reaped, reapErr := jointDPBiomedicalGaussianFullReapCommittedTemp(
						recordPath, target)
					if reapErr != nil {
						_ = directory.Close()
						return reapErr
					}
					if reaped {
						removed = true
						continue
					}
				}
				_ = directory.Close()
				return fmt.Errorf("formal-glm: unsafe linked Phase-2.0 handoff file")
			}
			if age := time.Since(info.ModTime()); age < formalGLMPhase18TempGrace {
				continue
			}
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				_ = directory.Close()
				return err
			}
			removed = true
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = directory.Close()
			return readErr
		}
	}
	if err := directory.Close(); err != nil {
		return err
	}
	if removed {
		return exactGCSyncDir(root)
	}
	return nil
}

func formalGLMPhase20HandoffAAD(record formalGLMPhase20HandoffRecord) ([]byte, error) {
	return json.Marshal(struct {
		Version            string `json:"version"`
		SemanticRootSHA256 string `json:"semantic_root_sha256"`
		Peer               string `json:"peer"`
		PayloadSHA256      string `json:"payload_sha256"`
	}{record.Version, record.SemanticRootSHA256, record.Peer,
		record.PayloadSHA256})
}

func formalGLMPhase20HandoffAEAD(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func formalGLMPhase20DecodeSeal(value, name string) ([32]byte, error) {
	var result [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(result) ||
		hex.EncodeToString(decoded) != value {
		clear(decoded)
		return result, fmt.Errorf("formal-glm: invalid Phase-2.0 %s", name)
	}
	copy(result[:], decoded)
	clear(decoded)
	return result, nil
}

func formalGLMPhase20ValidateScheduleResult(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, semanticRoot, peer string,
	result formalGLMPhase19ScheduleResult, pins map[string]ed25519.PublicKey,
	backend [32]byte) (formalGLMPhase19ScheduleResult, []*big.Int, error) {

	var zero formalGLMPhase19ScheduleResult
	if err := formalGLMPhase19ValidateContext(plan, ctx); err != nil {
		return zero, nil, err
	}
	planDigest, err := formalGLMPhase15PlanDigest(plan)
	if err != nil {
		return zero, nil, err
	}
	contextDigest, err := formalGLMPhase19ContextDigest(ctx)
	if err != nil {
		return zero, nil, err
	}
	if result.Version != formalGLMPhase19ScheduleResultVersion ||
		result.Kind != formalGLMPhase19ScheduleResultKind ||
		result.SemanticRootSHA256 != semanticRoot || result.Peer != peer ||
		!formalGLMPhase19Contains(ctx.ComputePeers, peer) ||
		result.ContextSHA256 != hex.EncodeToString(contextDigest[:]) ||
		result.PlanSHA256 != hex.EncodeToString(planDigest[:]) ||
		!formalGLMIsSHA256(result.ScheduleRootSHA256) ||
		!formalGLMIsSHA256(result.AttemptID) ||
		result.HandoffSHA256 != "" || result.HandoffBytes != 0 ||
		result.HandoffReplayed || !result.ExecutionValidSealed ||
		result.ExecutionValidityOpened || result.OpeningsPerformed != 0 ||
		result.ProductionReady {
		return zero, nil, fmt.Errorf("formal-glm: invalid Phase-2.0 schedule source")
	}
	pinsetSHA256, err := formalGLMPhase16PinsetSHA256(pins)
	if err != nil || len(pins) != len(plan.Kernel.CustodianPeers) ||
		pinsetSHA256 != plan.Kernel.PinsetSHA256 {
		return zero, nil, fmt.Errorf("formal-glm: incomplete Phase-2.0 K-of-K pinset")
	}
	if err := formalGLMPhase15VerifyReceiptPair(
		plan, result.FinalReceipts, pins); err != nil {
		return zero, nil, err
	}
	if len(result.FinalReceipts) != 2 ||
		result.FinalReceipts[0].StepIndex != plan.ScheduleSteps-1 ||
		result.FinalReceipts[1].StepIndex != plan.ScheduleSteps-1 {
		return zero, nil, fmt.Errorf("formal-glm: Phase-2.0 source is not final")
	}
	if err := validateFormalGLMPhase15DPBridgePlan(
		plan, result.FinalReceipts, pins, result.DPBridge); err != nil {
		return zero, nil, err
	}
	tokenSeal, err := formalGLMPhase20DecodeSeal(
		result.PostExecutionTokenSeal, "post-execution seal")
	if err != nil {
		return zero, nil, err
	}
	result.PostExecutionToken.seal = tokenSeal
	result.PostExecutionToken.verified = true
	if err := formalGLMPhase19VerifyPostExecutionToken(
		result.PostExecutionToken, backend); err != nil {
		return zero, nil, err
	}
	pairSeal, err := formalGLMPhase20DecodeSeal(
		result.ExecutionReceiptPairSeal, "execution-pair seal")
	if err != nil {
		return zero, nil, err
	}
	result.ExecutionReceiptPair.seal = pairSeal
	result.ExecutionReceiptPair.verified = true
	pairMessage, err := formalGLMPhase19ExecutionPairMessage(
		result.ExecutionReceiptPair)
	if err != nil {
		return zero, nil, err
	}
	wantPairSeal := formalGLMPhase19MAC(backend,
		formalGLMPhase19ExecDomain+"/receipt-pair-seal", pairMessage)
	if !hmac.Equal(wantPairSeal[:], pairSeal[:]) ||
		result.ExecutionReceiptPair.ContextSHA256 != result.ContextSHA256 ||
		result.ExecutionReceiptPair.AccumulatorRoot !=
			result.PostExecutionToken.AccumulatorRoot ||
		result.ExecutionReceiptPair.ExecutionReceiptPairSHA256 !=
			result.PostExecutionToken.ExecutionReceiptPairSHA256 ||
		result.PostExecutionToken.ContextSHA256 != result.ContextSHA256 ||
		result.PostExecutionToken.Phase15PlanSHA256 != result.PlanSHA256 ||
		result.PostExecutionToken.FinalCheckpointTranscriptSHA256 !=
			result.DPBridge.ExecutionTranscriptSHA256 {
		return zero, nil, fmt.Errorf("formal-glm: Phase-2.0 evidence binding failed")
	}
	spec := exactGCCircuitSpec{
		Operation: exactGCFormalGLMDPBridge, RingBits: 128, FracBits: 0,
		VectorLen: plan.Kernel.CoefficientCount,
	}
	shares, err := exactGCDecodeWorkerCanonicalShares(result.DPShare, spec)
	if err != nil {
		return zero, nil, err
	}
	canonical, err := exactGCEncodeWorkerCanonicalShares(shares, spec)
	if err != nil || canonical != result.DPShare {
		exactGCZeroBigInts(shares)
		return zero, nil, fmt.Errorf("formal-glm: non-canonical Phase-2.0 source share")
	}
	return result, shares, nil
}

func (store *formalGLMPhase20HandoffStore) validatePayload(
	payload formalGLMPhase20HandoffPayload) (
	formalGLMPhase20HandoffSource, error) {

	var zero formalGLMPhase20HandoffSource
	if store == nil || payload.Version != formalGLMPhase20HandoffPayloadVersion ||
		payload.SemanticRootSHA256 != store.semanticRoot ||
		payload.Peer != store.peer || payload.OpeningsPerformed != 0 ||
		payload.ProductionReady {
		return zero, fmt.Errorf("formal-glm: invalid Phase-2.0 handoff payload")
	}
	result, shares, err := formalGLMPhase20ValidateScheduleResult(
		payload.Plan, payload.Context, payload.SemanticRootSHA256, payload.Peer,
		payload.Result, store.pins, store.backend)
	if err != nil {
		return zero, err
	}
	return formalGLMPhase20HandoffSource{
		Plan: payload.Plan, Context: payload.Context, Result: result,
		DPShares: shares, backend: store.backend,
	}, nil
}

func formalGLMPhase20ReadHandoffRecordInfo(path string) (
	[]byte, os.FileInfo, error) {
	for attempt := 0; attempt < 32; attempt++ {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, nil, err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0o077 != 0 || info.Size() < 64 ||
			info.Size() > formalGLMPhase20HandoffMaxBytes {
			return nil, nil, fmt.Errorf("formal-glm: unsafe Phase-2.0 handoff record")
		}
		if !exactGCPrivateOwnedRegular(info) {
			reaped, reapErr := jointDPBiomedicalGaussianFullReapCommittedTemp(
				path, info)
			if reapErr != nil {
				return nil, nil, reapErr
			}
			if reaped {
				continue
			}
			return nil, nil, fmt.Errorf("formal-glm: unsafe linked Phase-2.0 handoff record")
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, nil, err
		}
		opened, err := file.Stat()
		if err != nil || !os.SameFile(info, opened) {
			_ = file.Close()
			return nil, nil,
				fmt.Errorf("formal-glm: Phase-2.0 handoff changed while opening")
		}
		value := make([]byte, opened.Size())
		_, readErr := io.ReadFull(file, value)
		closeErr := file.Close()
		if readErr != nil {
			return nil, nil, readErr
		}
		if closeErr != nil {
			return nil, nil, closeErr
		}
		return value, opened, nil
	}
	return nil, nil,
		fmt.Errorf("formal-glm: Phase-2.0 handoff CAS did not stabilize")
}

func formalGLMPhase20ReadHandoffRecord(path string) ([]byte, error) {
	value, _, err := formalGLMPhase20ReadHandoffRecordInfo(path)
	return value, err
}

func (store *formalGLMPhase20HandoffStore) decode(encoded []byte) (
	formalGLMPhase20HandoffPayload, error) {

	var zero formalGLMPhase20HandoffPayload
	if store == nil || len(encoded) < 64 ||
		len(encoded) > formalGLMPhase20HandoffMaxBytes {
		return zero, fmt.Errorf("formal-glm: invalid Phase-2.0 handoff record")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record formalGLMPhase20HandoffRecord
	if err := decoder.Decode(&record); err != nil {
		return zero, fmt.Errorf("formal-glm: invalid Phase-2.0 handoff record")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return zero, fmt.Errorf("formal-glm: trailing Phase-2.0 handoff record")
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, encoded) ||
		record.Version != formalGLMPhase20HandoffVersion ||
		record.SemanticRootSHA256 != store.semanticRoot ||
		record.Peer != store.peer || !formalGLMIsSHA256(record.PayloadSHA256) {
		return zero, fmt.Errorf("formal-glm: non-canonical Phase-2.0 handoff record")
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(record.Nonce)
	if err != nil || base64.StdEncoding.EncodeToString(nonce) != record.Nonce {
		clear(nonce)
		return zero, fmt.Errorf("formal-glm: invalid Phase-2.0 handoff nonce")
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(record.Ciphertext)
	if err != nil || base64.StdEncoding.EncodeToString(ciphertext) != record.Ciphertext {
		clear(nonce)
		clear(ciphertext)
		return zero, fmt.Errorf("formal-glm: invalid Phase-2.0 handoff ciphertext")
	}
	aead, err := formalGLMPhase20HandoffAEAD(store.aeadKey)
	if err != nil || len(nonce) != aead.NonceSize() ||
		len(ciphertext) < aead.Overhead() {
		clear(nonce)
		clear(ciphertext)
		return zero, fmt.Errorf("formal-glm: invalid Phase-2.0 handoff AEAD")
	}
	aad, err := formalGLMPhase20HandoffAAD(record)
	if err != nil {
		clear(nonce)
		clear(ciphertext)
		return zero, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	clear(nonce)
	clear(ciphertext)
	clear(aad)
	if err != nil {
		clear(plaintext)
		return zero, fmt.Errorf("formal-glm: Phase-2.0 handoff authentication failed")
	}
	defer clear(plaintext)
	digest := sha256.Sum256(plaintext)
	if record.PayloadSHA256 != hex.EncodeToString(digest[:]) {
		return zero, fmt.Errorf("formal-glm: Phase-2.0 handoff payload digest changed")
	}
	payloadDecoder := json.NewDecoder(bytes.NewReader(plaintext))
	payloadDecoder.DisallowUnknownFields()
	var payload formalGLMPhase20HandoffPayload
	if err := payloadDecoder.Decode(&payload); err != nil {
		return zero, fmt.Errorf("formal-glm: invalid Phase-2.0 handoff payload")
	}
	if err := payloadDecoder.Decode(&struct{}{}); err != io.EOF {
		return zero, fmt.Errorf("formal-glm: trailing Phase-2.0 handoff payload")
	}
	payloadCanonical, err := json.Marshal(payload)
	if err != nil || !bytes.Equal(payloadCanonical, plaintext) {
		return zero, fmt.Errorf("formal-glm: non-canonical Phase-2.0 handoff payload")
	}
	return payload, nil
}

func (store *formalGLMPhase20HandoffStore) Load() (
	formalGLMPhase20HandoffSource, formalGLMPhase20HandoffCommit, error) {

	var zero formalGLMPhase20HandoffSource
	encoded, err := formalGLMPhase20ReadHandoffRecord(store.recordPath)
	if err != nil {
		return zero, formalGLMPhase20HandoffCommit{}, err
	}
	digest := sha256.Sum256(encoded)
	payload, err := store.decode(encoded)
	if err != nil {
		return zero, formalGLMPhase20HandoffCommit{}, err
	}
	source, err := store.validatePayload(payload)
	if err != nil {
		return zero, formalGLMPhase20HandoffCommit{}, err
	}
	return source, formalGLMPhase20HandoffCommit{
		SHA256: hex.EncodeToString(digest[:]), Bytes: int64(len(encoded)),
		Replayed: true,
	}, nil
}

// Consume removes exactly the authenticated slot named by a completed
// release.  It is intentionally not called by Phase-1.9: a future release
// runner must first durably commit the sticky public DP receipt, then pass its
// recorded handoff digest here.
func (store *formalGLMPhase20HandoffStore) Consume(expectedSHA256 string) (
	int64, error) {
	if store == nil || !formalGLMIsSHA256(expectedSHA256) {
		return 0, fmt.Errorf("formal-glm: invalid Phase-2.0 consume receipt")
	}
	encoded, opened, err := formalGLMPhase20ReadHandoffRecordInfo(
		store.recordPath)
	if err != nil {
		return 0, err
	}
	digest := sha256.Sum256(encoded)
	if hex.EncodeToString(digest[:]) != expectedSHA256 {
		clear(encoded)
		return 0, fmt.Errorf("formal-glm: Phase-2.0 consume receipt mismatch")
	}
	payload, err := store.decode(encoded)
	clear(encoded)
	if err != nil {
		return 0, err
	}
	source, err := store.validatePayload(payload)
	if err != nil {
		return 0, err
	}
	source.clear()
	current, err := os.Lstat(store.recordPath)
	if err != nil || !os.SameFile(opened, current) ||
		!current.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 ||
		current.Mode().Perm()&0o077 != 0 ||
		!exactGCPrivateOwnedRegular(current) {
		return 0, fmt.Errorf("formal-glm: unsafe Phase-2.0 consume slot")
	}
	var suffix [16]byte
	if _, err := io.ReadFull(crand.Reader, suffix[:]); err != nil {
		return 0, err
	}
	quarantine := filepath.Join(filepath.Dir(store.recordPath),
		".phase20-consume-"+hex.EncodeToString(suffix[:])+".bin")
	clear(suffix[:])
	if _, err := os.Lstat(quarantine); !os.IsNotExist(err) {
		return 0, fmt.Errorf("formal-glm: unsafe Phase-2.0 consume quarantine")
	}
	if err := os.Rename(store.recordPath, quarantine); err != nil {
		return 0, err
	}
	quarantined, err := os.Lstat(quarantine)
	if err != nil || !os.SameFile(opened, quarantined) ||
		!quarantined.Mode().IsRegular() ||
		quarantined.Mode()&os.ModeSymlink != 0 ||
		quarantined.Mode().Perm()&0o077 != 0 ||
		!exactGCPrivateOwnedRegular(quarantined) {
		return 0, fmt.Errorf("formal-glm: Phase-2.0 consume slot changed before quarantine")
	}
	if err := os.Remove(quarantine); err != nil {
		return 0, err
	}
	if err := exactGCSyncDir(filepath.Dir(store.recordPath)); err != nil {
		return 0, err
	}
	return opened.Size(), nil
}

func (store *formalGLMPhase20HandoffStore) encode(
	payload formalGLMPhase20HandoffPayload) ([]byte, []byte, error) {

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	if len(plaintext) > formalGLMPhase20HandoffMaxBytes/2 {
		clear(plaintext)
		return nil, nil, fmt.Errorf("formal-glm: Phase-2.0 handoff payload too large")
	}
	payloadDigest := sha256.Sum256(plaintext)
	aead, err := formalGLMPhase20HandoffAEAD(store.aeadKey)
	if err != nil {
		clear(plaintext)
		return nil, nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(crand.Reader, nonce); err != nil {
		clear(plaintext)
		clear(nonce)
		return nil, nil, err
	}
	record := formalGLMPhase20HandoffRecord{
		Version:            formalGLMPhase20HandoffVersion,
		SemanticRootSHA256: store.semanticRoot, Peer: store.peer,
		PayloadSHA256: hex.EncodeToString(payloadDigest[:]),
		Nonce:         base64.StdEncoding.EncodeToString(nonce),
	}
	aad, err := formalGLMPhase20HandoffAAD(record)
	if err != nil {
		clear(plaintext)
		clear(nonce)
		return nil, nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	record.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	clear(nonce)
	clear(ciphertext)
	clear(aad)
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > formalGLMPhase20HandoffMaxBytes {
		clear(plaintext)
		clear(encoded)
		if err == nil {
			err = fmt.Errorf("formal-glm: Phase-2.0 handoff record too large")
		}
		return nil, nil, err
	}
	return encoded, plaintext, nil
}

func (store *formalGLMPhase20HandoffStore) Commit(
	plan formalGLMPhase15Plan, ctx formalGLMPhase19Context,
	result formalGLMPhase19ScheduleResult) (
	formalGLMPhase20HandoffCommit, error) {

	payload := formalGLMPhase20HandoffPayload{
		Version:            formalGLMPhase20HandoffPayloadVersion,
		SemanticRootSHA256: store.semanticRoot, Peer: store.peer,
		Plan: plan, Context: ctx, Result: result,
		OpeningsPerformed: 0, ProductionReady: false,
	}
	source, err := store.validatePayload(payload)
	if err != nil {
		return formalGLMPhase20HandoffCommit{}, err
	}
	source.clear()
	encoded, plaintext, err := store.encode(payload)
	if err != nil {
		return formalGLMPhase20HandoffCommit{}, err
	}
	defer clear(encoded)
	defer clear(plaintext)
	created, err := jointDPBiomedicalGaussianFullCreateRecord(
		store.recordPath, encoded)
	if err != nil {
		return formalGLMPhase20HandoffCommit{}, err
	}
	if !created {
		existing, err := formalGLMPhase20ReadHandoffRecord(store.recordPath)
		if err != nil {
			return formalGLMPhase20HandoffCommit{}, err
		}
		defer clear(existing)
		existingPayload, err := store.decode(existing)
		if err != nil {
			return formalGLMPhase20HandoffCommit{}, err
		}
		existingPlaintext, err := json.Marshal(existingPayload)
		if err != nil {
			return formalGLMPhase20HandoffCommit{}, err
		}
		defer clear(existingPlaintext)
		if !bytes.Equal(existingPlaintext, plaintext) {
			return formalGLMPhase20HandoffCommit{},
				fmt.Errorf("formal-glm: conflicting Phase-2.0 handoff replay")
		}
		digest := sha256.Sum256(existing)
		return formalGLMPhase20HandoffCommit{
			SHA256: hex.EncodeToString(digest[:]), Bytes: int64(len(existing)),
			Replayed: true,
		}, nil
	}
	digest := sha256.Sum256(encoded)
	return formalGLMPhase20HandoffCommit{
		SHA256: hex.EncodeToString(digest[:]), Bytes: int64(len(encoded)),
		Replayed: false,
	}, nil
}

// Phase20RuntimeAdmission is an internal two-round admission object.  Build
// returns the exact contracts custodians must sign; Admit refuses to choose or
// substitute a backend after those K-of-K signatures have been produced.
type formalGLMPhase20RuntimeAdmission struct {
	Productive formalGLMPhase16ProductiveAdmission
	Full       *jointDPBiomedicalGaussianFullAdmission
}

// formalGLMPhase20LocalRuntime is the deployable server-local shape: each
// compute peer opens only its own durable handoff, independently derives the
// same public release contracts, and retains only its own source share for the
// selected existing Phase-1.6 worker.
type formalGLMPhase20LocalRuntime struct {
	Source    formalGLMPhase20HandoffSource
	Admission formalGLMPhase20RuntimeAdmission
	capsule   formalGLMPhase16CapsuleBinding
	request   formalGLMPhase16ProductiveRequest
}

func (runtime *formalGLMPhase20LocalRuntime) clear() {
	if runtime != nil {
		runtime.Source.clear()
		*runtime = formalGLMPhase20LocalRuntime{}
	}
}

func formalGLMPhase20BuildLocalRuntime(
	store *formalGLMPhase20HandoffStore, pins map[string]ed25519.PublicKey,
	capsule formalGLMPhase16CapsuleBinding,
	request formalGLMPhase16ProductiveRequest) (
	formalGLMPhase20LocalRuntime, error) {

	var zero formalGLMPhase20LocalRuntime
	if store == nil {
		return zero, fmt.Errorf("formal-glm: missing Phase-2.0 local handoff")
	}
	source, _, err := store.Load()
	if err != nil {
		return zero, err
	}
	productive, err := formalGLMPhase16BuildProductiveEnvelope(
		source.Plan, source.Result.FinalReceipts, pins, source.Result.DPBridge,
		capsule, source.Result.PostExecutionToken, source.backend, request)
	if err != nil {
		source.clear()
		return zero, err
	}
	return formalGLMPhase20LocalRuntime{
		Source:    source,
		Admission: formalGLMPhase20RuntimeAdmission{Productive: productive},
		capsule:   capsule, request: request,
	}, nil
}

func formalGLMPhase20AdmitLocalRuntime(runtime formalGLMPhase20LocalRuntime,
	backendSignatures, workerSignatures []jointDPBiomedicalGaussianSignature,
	fullRequest *formalGLMPhase16FullFallbackRequest,
	fullAttestation *formalGLMPhase16FullFallbackContractAttestation,
	pins map[string]ed25519.PublicKey) (formalGLMPhase20LocalRuntime, error) {

	expected, err := formalGLMPhase16BuildProductiveEnvelope(
		runtime.Source.Plan, runtime.Source.Result.FinalReceipts, pins,
		runtime.Source.Result.DPBridge, runtime.capsule,
		runtime.Source.Result.PostExecutionToken, runtime.Source.backend,
		runtime.request)
	if err != nil || !reflect.DeepEqual(expected, runtime.Admission.Productive) {
		return formalGLMPhase20LocalRuntime{},
			fmt.Errorf("formal-glm: modified Phase-2.0 local runtime admission")
	}
	admitted, err := formalGLMPhase20AdmitRuntime(
		runtime.Admission, backendSignatures, workerSignatures,
		fullRequest, fullAttestation, pins)
	if err != nil {
		return formalGLMPhase20LocalRuntime{}, err
	}
	runtime.Admission = admitted
	return runtime, nil
}

func formalGLMPhase20AdmitRuntime(
	draft formalGLMPhase20RuntimeAdmission,
	backendSignatures, workerSignatures []jointDPBiomedicalGaussianSignature,
	fullRequest *formalGLMPhase16FullFallbackRequest,
	fullAttestation *formalGLMPhase16FullFallbackContractAttestation,
	pins map[string]ed25519.PublicKey) (formalGLMPhase20RuntimeAdmission, error) {

	productive, err := formalGLMPhase16AdmitProductiveBackendSignatures(
		draft.Productive, backendSignatures)
	if err != nil {
		return formalGLMPhase20RuntimeAdmission{}, err
	}
	switch productive.BackendSelection.Contract.SelectedBackend {
	case formalGLMPhase16BackendOneDraw:
		if len(workerSignatures) == 0 || fullRequest != nil ||
			fullAttestation != nil {
			return formalGLMPhase20RuntimeAdmission{},
				fmt.Errorf("formal-glm: incomplete or type-confused one-draw admission")
		}
		productive, err = formalGLMPhase16AdmitProductiveSignatures(
			productive, workerSignatures)
		if err != nil {
			return formalGLMPhase20RuntimeAdmission{}, err
		}
		return formalGLMPhase20RuntimeAdmission{Productive: productive}, nil
	case formalGLMPhase16BackendFull:
		if len(workerSignatures) != 0 || fullRequest == nil ||
			fullAttestation == nil {
			return formalGLMPhase20RuntimeAdmission{},
				fmt.Errorf("formal-glm: incomplete or type-confused full admission")
		}
		full, err := formalGLMPhase16AdmitFullFallback(
			productive.BackendSelection, productive.Compiled.Binding,
			productive.Token, pins, *fullRequest, *fullAttestation)
		if err != nil {
			return formalGLMPhase20RuntimeAdmission{}, err
		}
		return formalGLMPhase20RuntimeAdmission{
			Productive: productive, Full: &full,
		}, nil
	default:
		return formalGLMPhase20RuntimeAdmission{},
			fmt.Errorf("formal-glm: unsupported signed Phase-2.0 backend")
	}
}
