package main

// Authenticated step checkpoints for the Phase-1.5 GLM worker.  Checkpoints
// contain only one compute peer's additive shares.  They make completed-step
// recovery durable but never attempt to resume OT/garbling mid-transcript.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sync"
)

const (
	formalGLMPhase15CheckpointVersion = "dsvert-formal-glm-phase15-checkpoint-v2"
	formalGLMPhase15ReceiptVersion    = "dsvert-formal-glm-phase15-step-receipt-v2"
	formalGLMPhase15ReceiptDomain     = "dsVert/formal-glm/phase15/step-receipt/v2"
	formalGLMPhase15TranscriptDomain  = "dsVert/formal-glm/phase15/execution-transcript/v1"
	formalGLMPhase15CheckpointMax     = 1 << 20
	formalGLMPhase15ReplayVersion     = "dsvert-formal-glm-phase15-replay-ledger-v1"
	formalGLMPhase15ReplayRecordMax   = 8 << 10
)

type formalGLMPhase15ReplayRecord struct {
	Version string `json:"version"`
	Key     string `json:"key"`
	Digest  string `json:"digest"`
	MAC     string `json:"mac"`
}

type formalGLMPhase15PendingState struct {
	StepIndex        int      `json:"step_index"`
	AttemptID        string   `json:"attempt_id"`
	OutputRecorded   bool     `json:"output_recorded"`
	Beta             []string `json:"beta"`
	Gradient         []string `json:"gradient"`
	StateSHA256      string   `json:"state_sha256"`
	StepPurpose      string   `json:"step_purpose"`
	TranscriptSHA256 string   `json:"transcript_sha256"`
}

type formalGLMPhase15Checkpoint struct {
	Version          string                        `json:"version"`
	PlanSHA256       string                        `json:"plan_sha256"`
	Peer             string                        `json:"peer"`
	Generation       uint64                        `json:"generation"`
	NextStep         int                           `json:"next_step"`
	Beta             []string                      `json:"beta"`
	Gradient         []string                      `json:"gradient"`
	TranscriptSHA256 string                        `json:"transcript_sha256"`
	Pending          *formalGLMPhase15PendingState `json:"pending,omitempty"`
	LastReceipt      *formalGLMPhase15StepReceipt  `json:"last_receipt,omitempty"`
	PreviousMAC      string                        `json:"previous_mac"`
	MAC              string                        `json:"mac"`
}

type formalGLMPhase15StepReceipt struct {
	Version          string `json:"version"`
	PlanSHA256       string `json:"plan_sha256"`
	Peer             string `json:"peer"`
	StepIndex        int    `json:"step_index"`
	AttemptID        string `json:"attempt_id"`
	StateSHA256      string `json:"state_sha256"`
	TranscriptSHA256 string `json:"transcript_sha256"`
	Signature        []byte `json:"signature"`
}

type formalGLMPhase15CheckpointStore struct {
	mu    sync.Mutex
	runMu sync.Mutex
	dir   string
	path  string
	key   [32]byte
	plan  formalGLMPhase15Plan
	peer  string
}

func formalGLMPhase15InitialTranscript(planHash string) string {
	message := formalGLMPhase15AppendString(nil,
		formalGLMPhase15TranscriptDomain)
	message = formalGLMPhase15AppendString(message, planHash)
	digest := sha256.Sum256(message)
	return hex.EncodeToString(digest[:])
}

func formalGLMPhase15AdvanceTranscript(current string, stepIndex int,
	stepPurpose string) (string, error) {
	if !formalGLMIsSHA256(current) || stepIndex < 0 ||
		exactGCValidateLabel("formal GLM step purpose", stepPurpose, 512) != nil {
		return "", fmt.Errorf("formal-glm: invalid execution transcript step")
	}
	message := formalGLMPhase15AppendString(nil,
		formalGLMPhase15TranscriptDomain)
	message = formalGLMPhase15AppendString(message, current)
	message = formalGLMPhase15AppendUint64(message, uint64(stepIndex))
	message = formalGLMPhase15AppendString(message, stepPurpose)
	digest := sha256.Sum256(message)
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMPhase15ReplayMAC(key [32]byte,
	record formalGLMPhase15ReplayRecord) (string, error) {
	record.MAC = ""
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("dsVert/formal-glm/phase15/replay-ledger-mac/v1|"))
	_, _ = mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func newFormalGLMPhase15DurableReplayLedger(dir string,
	key [32]byte) (*formalGLMPhase15ReplayLedger, error) {
	if bytes.Equal(key[:], make([]byte, len(key))) {
		return nil, fmt.Errorf("formal-glm: replay-ledger key is missing")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	replayDir := filepath.Join(dir, "formal-glm-phase15-replay")
	if err := os.MkdirAll(replayDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(replayDir, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(replayDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("formal-glm: unsafe replay-ledger directory")
	}
	ledger := &formalGLMPhase15ReplayLedger{
		entries: make(map[string][32]byte),
		path:    replayDir, key: key,
	}
	return ledger, nil
}

func (ledger *formalGLMPhase15ReplayLedger) replayRecordPath(key string) (string, error) {
	if key == "" || len(key) > 2048 {
		return "", fmt.Errorf("formal-glm: invalid replay-ledger key")
	}
	digest := sha256.Sum256([]byte(key))
	name := hex.EncodeToString(digest[:])
	shard := filepath.Join(ledger.path, name[:2], name[2:4])
	if err := os.MkdirAll(shard, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(shard, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(shard, "entry-"+name+".json"), nil
}

func (ledger *formalGLMPhase15ReplayLedger) readReplayRecord(path string) (
	formalGLMPhase15ReplayRecord, error) {
	var record formalGLMPhase15ReplayRecord
	info, err := os.Lstat(path)
	if err != nil {
		return record, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 || !exactGCPrivateOwnedRegular(info) ||
		info.Size() < 2 || info.Size() > formalGLMPhase15ReplayRecordMax {
		return record, fmt.Errorf("formal-glm: unsafe replay-ledger record")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return record, err
	}
	if json.Unmarshal(encoded, &record) != nil {
		return record, fmt.Errorf("formal-glm: invalid replay-ledger record")
	}
	canonical, _ := json.Marshal(record)
	wantMAC, macErr := formalGLMPhase15ReplayMAC(ledger.key, record)
	if macErr != nil || !bytes.Equal(canonical, encoded) ||
		record.Version != formalGLMPhase15ReplayVersion || record.Key == "" ||
		!formalGLMIsSHA256(record.Digest) ||
		!hmac.Equal([]byte(wantMAC), []byte(record.MAC)) {
		return record, fmt.Errorf("formal-glm: replay-ledger authentication failed")
	}
	return record, nil
}

func (ledger *formalGLMPhase15ReplayLedger) durableAcceptLocked(
	key string, digest [32]byte) error {
	path, err := ledger.replayRecordPath(key)
	if err != nil {
		return err
	}
	wantDigest := hex.EncodeToString(digest[:])
	if existing, err := ledger.readReplayRecord(path); err == nil {
		if existing.Key != key || existing.Digest != wantDigest {
			return fmt.Errorf("formal-glm: conflicting source replay")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	record := formalGLMPhase15ReplayRecord{
		Version: formalGLMPhase15ReplayVersion, Key: key, Digest: wantDigest,
	}
	record.MAC, err = formalGLMPhase15ReplayMAC(ledger.key, record)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > formalGLMPhase15ReplayRecordMax {
		return fmt.Errorf("formal-glm: invalid durable replay record")
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".phase15-replay-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := exactGCWriteFull(tmp, encoded); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpPath, path); err != nil {
		// Another worker may have won the immutable slot race.  Its complete,
		// authenticated record is authoritative.
		existing, readErr := ledger.readReplayRecord(path)
		if readErr != nil {
			return err
		}
		if existing.Key != key || existing.Digest != wantDigest {
			return fmt.Errorf("formal-glm: conflicting source replay")
		}
		return nil
	}
	if err := os.Remove(tmpPath); err != nil {
		return err
	}
	return exactGCSyncDir(filepath.Dir(path))
}

func formalGLMPhase15EncodeStateValues(values []*big.Int,
	ringBits int) ([]string, error) {
	result := make([]string, len(values))
	modulus := exactGCModulus(ringBits)
	for i, value := range values {
		if value == nil || value.Sign() < 0 || value.Cmp(modulus) >= 0 {
			return nil, fmt.Errorf("formal-glm: invalid checkpoint share")
		}
		result[i] = value.Text(16)
	}
	return result, nil
}

func formalGLMPhase15DecodeStateValues(values []string, count, ringBits int) (
	[]*big.Int, error) {

	if len(values) != count {
		return nil, fmt.Errorf("formal-glm: invalid checkpoint state shape")
	}
	result := make([]*big.Int, count)
	for i, value := range values {
		if value == "" || (len(value) > 1 && value[0] == '0') {
			return nil, fmt.Errorf("formal-glm: non-canonical checkpoint share")
		}
		result[i] = new(big.Int)
		if _, ok := result[i].SetString(value, 16); !ok || result[i].Text(16) != value ||
			result[i].BitLen() > ringBits {
			return nil, fmt.Errorf("formal-glm: invalid checkpoint share encoding")
		}
	}
	return result, nil
}

func formalGLMPhase15StateDigest(beta, gradient []string) string {
	message := formalGLMPhase15AppendString(nil,
		"dsVert/formal-glm/phase15/sealed-state/v1")
	for _, values := range [][]string{beta, gradient} {
		message = formalGLMPhase15AppendUint64(message, uint64(len(values)))
		for _, value := range values {
			message = formalGLMPhase15AppendString(message, value)
		}
	}
	digest := sha256.Sum256(message)
	return hex.EncodeToString(digest[:])
}

func formalGLMPhase15CheckpointUnsigned(state formalGLMPhase15Checkpoint) ([]byte, error) {
	state.MAC = ""
	return json.Marshal(state)
}

func formalGLMPhase15CheckpointMAC(key [32]byte,
	state formalGLMPhase15Checkpoint) (string, error) {

	encoded, err := formalGLMPhase15CheckpointUnsigned(state)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("dsVert/formal-glm/phase15/checkpoint-mac/v1|"))
	_, _ = mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func newFormalGLMPhase15CheckpointStore(dir string, key [32]byte,
	plan formalGLMPhase15Plan, peer string) (*formalGLMPhase15CheckpointStore, error) {

	if bytes.Equal(key[:], make([]byte, len(key))) {
		return nil, fmt.Errorf("formal-glm: checkpoint authentication key is missing")
	}
	if err := validateFormalGLMPhase15Plan(plan); err != nil {
		return nil, err
	}
	if peer != plan.Kernel.ComputePeers[0] && peer != plan.Kernel.ComputePeers[1] {
		return nil, fmt.Errorf("formal-glm: checkpoint peer is not a compute peer")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("formal-glm: unsafe checkpoint directory")
	}
	return &formalGLMPhase15CheckpointStore{
		dir: dir, path: filepath.Join(dir, "formal-glm-phase15-state.json"),
		key: key, plan: plan, peer: peer,
	}, nil
}

func (store *formalGLMPhase15CheckpointStore) validateState(
	state formalGLMPhase15Checkpoint) error {

	digest, _ := formalGLMPhase15PlanDigest(store.plan)
	p := store.plan.Kernel.CoefficientCount
	if state.Version != formalGLMPhase15CheckpointVersion ||
		state.PlanSHA256 != hex.EncodeToString(digest[:]) || state.Peer != store.peer ||
		state.NextStep < 0 || state.NextStep > store.plan.ScheduleSteps ||
		!formalGLMIsSHA256(state.TranscriptSHA256) ||
		!formalGLMIsSHA256(state.MAC) ||
		(state.PreviousMAC != "" && !formalGLMIsSHA256(state.PreviousMAC)) {
		return fmt.Errorf("formal-glm: invalid checkpoint context")
	}
	if _, err := formalGLMPhase15DecodeStateValues(state.Beta, p,
		store.plan.RingBits); err != nil {
		return err
	}
	if _, err := formalGLMPhase15DecodeStateValues(state.Gradient, p,
		store.plan.RingBits); err != nil {
		return err
	}
	if state.LastReceipt != nil {
		receipt := state.LastReceipt
		gradient := state.Gradient
		if receipt.StepIndex >= 0 && store.isFinalizeStep(receipt.StepIndex) {
			gradient = nil
		}
		if state.NextStep < 1 || receipt.Version != formalGLMPhase15ReceiptVersion ||
			receipt.PlanSHA256 != state.PlanSHA256 || receipt.Peer != state.Peer ||
			receipt.StepIndex != state.NextStep-1 ||
			!formalGLMIsSHA256(receipt.AttemptID) ||
			receipt.StateSHA256 != formalGLMPhase15StateDigest(state.Beta, gradient) ||
			receipt.TranscriptSHA256 != state.TranscriptSHA256 ||
			len(receipt.Signature) != ed25519.SignatureSize {
			return fmt.Errorf("formal-glm: invalid committed checkpoint receipt")
		}
	}
	if state.Pending != nil {
		pending := state.Pending
		if pending.StepIndex != state.NextStep || !formalGLMIsSHA256(pending.AttemptID) {
			return fmt.Errorf("formal-glm: invalid pending checkpoint step")
		}
		if pending.OutputRecorded {
			if _, err := formalGLMPhase15DecodeStateValues(pending.Beta, p,
				store.plan.RingBits); err != nil {
				return err
			}
			gradientCount := p
			if store.isFinalizeStep(pending.StepIndex) {
				gradientCount = 0
			}
			if _, err := formalGLMPhase15DecodeStateValues(pending.Gradient,
				gradientCount, store.plan.RingBits); err != nil {
				return err
			}
			if pending.StateSHA256 != formalGLMPhase15StateDigest(
				pending.Beta, pending.Gradient) {
				return fmt.Errorf("formal-glm: pending state commitment mismatch")
			}
			wantTranscript, transcriptErr := formalGLMPhase15AdvanceTranscript(
				state.TranscriptSHA256, pending.StepIndex, pending.StepPurpose)
			if transcriptErr != nil || pending.TranscriptSHA256 != wantTranscript {
				return fmt.Errorf("formal-glm: pending execution transcript mismatch")
			}
		} else if len(pending.Beta) != 0 || len(pending.Gradient) != 0 ||
			pending.StateSHA256 != "" || pending.StepPurpose != "" ||
			pending.TranscriptSHA256 != "" {
			return fmt.Errorf("formal-glm: invalid in-flight checkpoint")
		}
	}
	wantMAC, err := formalGLMPhase15CheckpointMAC(store.key, state)
	if err != nil || !hmac.Equal([]byte(wantMAC), []byte(state.MAC)) {
		return fmt.Errorf("formal-glm: checkpoint authentication failed")
	}
	return nil
}

func (store *formalGLMPhase15CheckpointStore) readUnlocked() (
	formalGLMPhase15Checkpoint, error) {

	var state formalGLMPhase15Checkpoint
	info, err := os.Lstat(store.path)
	if err != nil {
		return state, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 || !exactGCPrivateOwnedRegular(info) ||
		info.Size() < 2 || info.Size() > formalGLMPhase15CheckpointMax {
		return state, fmt.Errorf("formal-glm: unsafe checkpoint artifact")
	}
	encoded, err := os.ReadFile(store.path)
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(encoded, &state); err != nil {
		return state, fmt.Errorf("formal-glm: decode checkpoint: %w", err)
	}
	canonical, err := json.Marshal(state)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return state, fmt.Errorf("formal-glm: non-canonical checkpoint")
	}
	if err := store.validateState(state); err != nil {
		return state, err
	}
	return state, nil
}

func (store *formalGLMPhase15CheckpointStore) writeUnlocked(
	state formalGLMPhase15Checkpoint) error {

	previous := ""
	if old, err := store.readUnlocked(); err == nil {
		previous = old.MAC
	} else if !os.IsNotExist(err) {
		return err
	}
	state.PreviousMAC = previous
	state.MAC = ""
	mac, err := formalGLMPhase15CheckpointMAC(store.key, state)
	if err != nil {
		return err
	}
	state.MAC = mac
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(encoded) > formalGLMPhase15CheckpointMax {
		return fmt.Errorf("formal-glm: checkpoint exceeds fixed public bound")
	}
	return exactGCAtomicReplace(store.path, encoded)
}

func (store *formalGLMPhase15CheckpointStore) Bootstrap() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, err := store.readUnlocked(); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	p := store.plan.Kernel.CoefficientCount
	beta := make([]*big.Int, p)
	gradient := make([]*big.Int, p)
	for j := 0; j < p; j++ {
		// BetaStart is public and Phase 1 requires zero.  Zero/zero shares do
		// not disclose a private state and are refreshed by the first block.
		beta[j] = new(big.Int)
		gradient[j] = new(big.Int)
	}
	betaEncoded, _ := formalGLMPhase15EncodeStateValues(beta, store.plan.RingBits)
	gradientEncoded, _ := formalGLMPhase15EncodeStateValues(gradient, store.plan.RingBits)
	digest, _ := formalGLMPhase15PlanDigest(store.plan)
	planHash := hex.EncodeToString(digest[:])
	return store.writeUnlocked(formalGLMPhase15Checkpoint{
		Version:    formalGLMPhase15CheckpointVersion,
		PlanSHA256: planHash, Peer: store.peer,
		Beta: betaEncoded, Gradient: gradientEncoded,
		TranscriptSHA256: formalGLMPhase15InitialTranscript(planHash),
	})
}

func (store *formalGLMPhase15CheckpointStore) Load() (
	formalGLMPhase15Checkpoint, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.readUnlocked()
}

func (store *formalGLMPhase15CheckpointStore) isFinalizeStep(index int) bool {
	return index%(store.plan.TotalBlocks+1) == store.plan.TotalBlocks
}

func (store *formalGLMPhase15CheckpointStore) BeginFreshAttempt() (
	formalGLMPhase15Step, [32]byte, error) {
	var attempt [32]byte
	if _, err := crand.Read(attempt[:]); err != nil {
		return formalGLMPhase15Step{}, [32]byte{}, err
	}
	step, err := store.BeginAttempt(attempt)
	return step, attempt, err
}

func (store *formalGLMPhase15CheckpointStore) BeginAttempt(attempt [32]byte) (
	formalGLMPhase15Step, error) {
	if bytes.Equal(attempt[:], make([]byte, len(attempt))) {
		return formalGLMPhase15Step{}, fmt.Errorf("formal-glm: attempt id must be non-zero")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.readUnlocked()
	if err != nil {
		return formalGLMPhase15Step{}, err
	}
	if state.NextStep >= store.plan.ScheduleSteps {
		return formalGLMPhase15Step{}, fmt.Errorf("formal-glm: fixed schedule is complete")
	}
	state.Generation++
	state.Pending = &formalGLMPhase15PendingState{
		StepIndex: state.NextStep, AttemptID: hex.EncodeToString(attempt[:]),
	}
	if err := store.writeUnlocked(state); err != nil {
		return formalGLMPhase15Step{}, err
	}
	iteration := state.NextStep / (store.plan.TotalBlocks + 1)
	within := state.NextStep % (store.plan.TotalBlocks + 1)
	block := within
	if within == store.plan.TotalBlocks {
		block = -1
	}
	return formalGLMPhase15Step{Iteration: iteration, BlockIndex: block}, nil
}

func (store *formalGLMPhase15CheckpointStore) RecordPendingOutput(
	step formalGLMPhase15Step, session exactGCSession,
	beta, gradient []*big.Int) error {

	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.readUnlocked()
	if err != nil {
		return err
	}
	if state.Pending == nil ||
		state.Pending.AttemptID != hex.EncodeToString(session.SessionID[:]) ||
		state.Pending.OutputRecorded {
		return fmt.Errorf("formal-glm: no matching in-flight step")
	}
	wantIteration := state.NextStep / (store.plan.TotalBlocks + 1)
	wantWithin := state.NextStep % (store.plan.TotalBlocks + 1)
	wantBlock := wantWithin
	if wantWithin == store.plan.TotalBlocks {
		wantBlock = -1
	}
	if step.Iteration != wantIteration || step.BlockIndex != wantBlock ||
		validateFormalGLMPhase15StepSession(store.plan, step, session) != nil {
		return fmt.Errorf("formal-glm: pending output is not bound to its exact step")
	}
	p := store.plan.Kernel.CoefficientCount
	gradientCount := p
	if store.isFinalizeStep(state.NextStep) {
		gradientCount = 0
	}
	if len(beta) != p || len(gradient) != gradientCount {
		return fmt.Errorf("formal-glm: invalid pending output shape")
	}
	betaEncoded, err := formalGLMPhase15EncodeStateValues(beta, store.plan.RingBits)
	if err != nil {
		return err
	}
	gradientEncoded, err := formalGLMPhase15EncodeStateValues(gradient, store.plan.RingBits)
	if err != nil {
		return err
	}
	state.Pending.OutputRecorded = true
	state.Pending.Beta = betaEncoded
	state.Pending.Gradient = gradientEncoded
	state.Pending.StateSHA256 = formalGLMPhase15StateDigest(betaEncoded, gradientEncoded)
	state.Pending.StepPurpose = session.Purpose
	state.Pending.TranscriptSHA256, err = formalGLMPhase15AdvanceTranscript(
		state.TranscriptSHA256, state.NextStep, session.Purpose)
	if err != nil {
		return err
	}
	return store.writeUnlocked(state)
}

func formalGLMPhase15ReceiptUnsigned(receipt formalGLMPhase15StepReceipt) []byte {
	message := formalGLMPhase15AppendString(nil, formalGLMPhase15ReceiptDomain)
	for _, value := range []string{
		receipt.Version, receipt.PlanSHA256, receipt.Peer,
		receipt.AttemptID, receipt.StateSHA256, receipt.TranscriptSHA256,
	} {
		message = formalGLMPhase15AppendString(message, value)
	}
	return formalGLMPhase15AppendUint64(message, uint64(receipt.StepIndex))
}

func (store *formalGLMPhase15CheckpointStore) PendingReceipt(
	privateKey ed25519.PrivateKey) (formalGLMPhase15StepReceipt, error) {

	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.readUnlocked()
	if err != nil {
		return formalGLMPhase15StepReceipt{}, err
	}
	if state.Pending == nil || !state.Pending.OutputRecorded ||
		len(privateKey) != ed25519.PrivateKeySize {
		return formalGLMPhase15StepReceipt{}, fmt.Errorf("formal-glm: pending result is not receiptable")
	}
	receipt := formalGLMPhase15StepReceipt{
		Version:    formalGLMPhase15ReceiptVersion,
		PlanSHA256: state.PlanSHA256, Peer: store.peer,
		StepIndex: state.NextStep, AttemptID: state.Pending.AttemptID,
		StateSHA256:      state.Pending.StateSHA256,
		TranscriptSHA256: state.Pending.TranscriptSHA256,
	}
	receipt.Signature = ed25519.Sign(privateKey,
		formalGLMPhase15ReceiptUnsigned(receipt))
	return receipt, nil
}

func formalGLMPhase15VerifyReceiptPair(plan formalGLMPhase15Plan,
	receipts []formalGLMPhase15StepReceipt,
	pins map[string]ed25519.PublicKey) error {

	if len(receipts) != 2 {
		return fmt.Errorf("formal-glm: incomplete step commit barrier")
	}
	digest, _ := formalGLMPhase15PlanDigest(plan)
	planHash := hex.EncodeToString(digest[:])
	seen := make(map[string]bool, 2)
	for _, receipt := range receipts {
		pin, ok := pins[receipt.Peer]
		if !ok || seen[receipt.Peer] ||
			(receipt.Peer != plan.Kernel.ComputePeers[0] &&
				receipt.Peer != plan.Kernel.ComputePeers[1]) ||
			receipt.Version != formalGLMPhase15ReceiptVersion ||
			receipt.PlanSHA256 != planHash || !formalGLMIsSHA256(receipt.AttemptID) ||
			!formalGLMIsSHA256(receipt.StateSHA256) ||
			!formalGLMIsSHA256(receipt.TranscriptSHA256) ||
			len(receipt.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(pin, formalGLMPhase15ReceiptUnsigned(receipt),
				receipt.Signature) {
			return fmt.Errorf("formal-glm: invalid step commit receipt")
		}
		seen[receipt.Peer] = true
	}
	if receipts[0].StepIndex != receipts[1].StepIndex ||
		receipts[0].AttemptID != receipts[1].AttemptID ||
		receipts[0].TranscriptSHA256 != receipts[1].TranscriptSHA256 {
		return fmt.Errorf("formal-glm: step receipts bind different attempts")
	}
	return nil
}

func (store *formalGLMPhase15CheckpointStore) CommitPending(
	receipts []formalGLMPhase15StepReceipt,
	pins map[string]ed25519.PublicKey) error {

	if err := formalGLMPhase15VerifyReceiptPair(store.plan, receipts, pins); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.readUnlocked()
	if err != nil {
		return err
	}
	if state.Pending == nil || !state.Pending.OutputRecorded {
		return fmt.Errorf("formal-glm: no pending result for commit")
	}
	var local *formalGLMPhase15StepReceipt
	for i := range receipts {
		if receipts[i].Peer == store.peer {
			local = &receipts[i]
		}
	}
	if local == nil || local.StepIndex != state.NextStep ||
		local.AttemptID != state.Pending.AttemptID ||
		local.StateSHA256 != state.Pending.StateSHA256 ||
		local.TranscriptSHA256 != state.Pending.TranscriptSHA256 {
		return fmt.Errorf("formal-glm: commit barrier does not match local pending state")
	}
	state.Beta = append([]string(nil), state.Pending.Beta...)
	if store.isFinalizeStep(state.NextStep) {
		state.Gradient = make([]string, store.plan.Kernel.CoefficientCount)
		for i := range state.Gradient {
			state.Gradient[i] = "0"
		}
	} else {
		state.Gradient = append([]string(nil), state.Pending.Gradient...)
	}
	state.Pending = nil
	state.TranscriptSHA256 = local.TranscriptSHA256
	committed := *local
	committed.Signature = append([]byte(nil), local.Signature...)
	state.LastReceipt = &committed
	state.NextStep++
	state.Generation++
	return store.writeUnlocked(state)
}

// CommittedFinalReceipt returns the signed local side of the final commit
// barrier after a restart.  The receipt is part of the MAC-authenticated
// checkpoint; it contains no coefficient share.
func (store *formalGLMPhase15CheckpointStore) CommittedFinalReceipt() (
	formalGLMPhase15StepReceipt, error) {
	state, err := store.Load()
	if err != nil {
		return formalGLMPhase15StepReceipt{}, err
	}
	if state.NextStep != store.plan.ScheduleSteps || state.Pending != nil ||
		state.LastReceipt == nil ||
		state.LastReceipt.StepIndex != store.plan.ScheduleSteps-1 {
		return formalGLMPhase15StepReceipt{},
			fmt.Errorf("formal-glm: final checkpoint receipt is unavailable")
	}
	result := *state.LastReceipt
	result.Signature = append([]byte(nil), state.LastReceipt.Signature...)
	return result, nil
}

// RunPendingWorkerStep is the internal DSI-worker adapter.  rw may be a live
// peer socket or exactGCSpoolRW; the latter provides absolute-offset retry,
// bounded buffering and backpressure across temporary DSI disconnects.
// Successful output is durable before a signed receipt can be returned.
func (store *formalGLMPhase15CheckpointStore) RunPendingWorkerStep(
	rw io.ReadWriter, session exactGCSession,
	fanIn *formalGLMPhase15FanInResult,
	signingKey ed25519.PrivateKey) (formalGLMPhase15StepReceipt, error) {

	store.runMu.Lock()
	defer store.runMu.Unlock()
	state, err := store.Load()
	if err != nil {
		return formalGLMPhase15StepReceipt{}, err
	}
	if state.Pending == nil || state.Pending.OutputRecorded {
		return formalGLMPhase15StepReceipt{}, fmt.Errorf("formal-glm: worker has no unexecuted pending step")
	}
	attemptBytes, err := hex.DecodeString(state.Pending.AttemptID)
	if err != nil || len(attemptBytes) != 32 {
		return formalGLMPhase15StepReceipt{}, fmt.Errorf("formal-glm: invalid pending attempt id")
	}
	var attempt [32]byte
	copy(attempt[:], attemptBytes)
	iteration := state.NextStep / (store.plan.TotalBlocks + 1)
	within := state.NextStep % (store.plan.TotalBlocks + 1)
	step := formalGLMPhase15Step{Iteration: iteration, BlockIndex: within}
	if within == store.plan.TotalBlocks {
		step.BlockIndex = -1
	}
	if session.SessionID != attempt {
		return formalGLMPhase15StepReceipt{}, fmt.Errorf("formal-glm: worker session is not the pending attempt")
	}
	p := store.plan.Kernel.CoefficientCount
	beta, err := formalGLMPhase15DecodeStateValues(state.Beta, p, store.plan.RingBits)
	if err != nil {
		return formalGLMPhase15StepReceipt{}, err
	}
	gradient, err := formalGLMPhase15DecodeStateValues(state.Gradient, p,
		store.plan.RingBits)
	if err != nil {
		return formalGLMPhase15StepReceipt{}, err
	}
	local := make([]*big.Int, 0, session.Spec.VectorLen)
	if step.BlockIndex >= 0 {
		if fanIn == nil || fanIn.PlanSHA256 != state.PlanSHA256 ||
			fanIn.Recipient != store.peer || fanIn.BlockIndex != step.BlockIndex ||
			len(fanIn.Shares) != store.plan.BlockCapacity*(p+3) ||
			!fanIn.verified || !formalGLMIsSHA256(fanIn.FanInRoot) {
			return formalGLMPhase15StepReceipt{}, fmt.Errorf("formal-glm: worker source fan-in does not match pending block")
		}
		step.SourceRoot = fanIn.FanInRoot
		local = append(local, fanIn.Shares...)
	} else if fanIn != nil {
		return formalGLMPhase15StepReceipt{}, fmt.Errorf("formal-glm: finalizer must not receive a source block")
	}
	local = append(local, beta...)
	local = append(local, gradient...)
	var output []*big.Int
	if store.peer == store.plan.Kernel.ComputePeers[0] {
		output, err = formalGLMPhase15RunGarbler(rw, store.plan, step, session, local)
	} else {
		output, err = formalGLMPhase15RunEvaluator(rw, store.plan, step, session, local)
	}
	if err != nil {
		return formalGLMPhase15StepReceipt{}, err
	}
	wantOutput := p
	if step.BlockIndex >= 0 {
		wantOutput = 2 * p
	}
	if len(output) != wantOutput {
		return formalGLMPhase15StepReceipt{}, fmt.Errorf("formal-glm: worker produced an invalid sealed output shape")
	}
	newBeta := output[:p]
	var newGradient []*big.Int
	if step.BlockIndex >= 0 {
		newGradient = output[p:]
	}
	if err := store.RecordPendingOutput(step, session, newBeta, newGradient); err != nil {
		return formalGLMPhase15StepReceipt{}, err
	}
	return store.PendingReceipt(signingKey)
}
