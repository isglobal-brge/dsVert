package main

// Durable validity barrier for the formal independent-full fallback.  The
// reservation is committed before the two private validity shares are
// combined.  An invalid source is memoized as a terminal no-release state;
// a valid source authorizes exactly one call into the already durable sticky
// independent-full finalizer.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
)

const (
	formalGLMPhase16FullGuardRecordVersion = "dsvert-formal-glm-phase16-independent-full-guard-record-v1"
	formalGLMPhase16FullGuardRecordDomain  = "dsVert/formal-glm/phase16/independent-full-guard-record/v1"
)

type formalGLMPhase16FullFallbackHandoff struct {
	Full      jointDPBiomedicalGaussianFullPhase19FinalizerHandoff
	Garbler   formalGLMPhase16FullRangeGuardReceipt
	Evaluator formalGLMPhase16FullRangeGuardReceipt
}

type formalGLMPhase16FullGuardRecord struct {
	Version                    string `json:"version"`
	State                      string `json:"state"`
	PeerName                   string `json:"peer_name"`
	ReleaseInstanceID          string `json:"release_instance_id"`
	ReleaseContractSHA256      string `json:"release_contract_sha256"`
	BackendSelectionSHA256     string `json:"backend_selection_sha256"`
	InputCommitmentSHA256      string `json:"input_commitment_sha256"`
	LedgerAppendBeforeValidity bool   `json:"ledger_append_before_validity"`
	ValidityChecked            bool   `json:"validity_checked"`
	AllChunksValid             bool   `json:"all_chunks_valid"`
	HistoryCanDenyOperation    bool   `json:"history_can_deny_operation"`
	OperationLimit             bool   `json:"operation_limit"`
	RequestLimit               bool   `json:"request_limit"`
	RecordMAC                  string `json:"record_mac"`
}

type formalGLMPhase16FullDurableReleaseStore struct {
	mu    sync.Mutex
	dir   string
	peer  string
	key   [32]byte
	inner *jointDPBiomedicalGaussianFullDurableReleaseStore
}

func newFormalGLMPhase16FullDurableReleaseStore(dir, peer string,
	key [32]byte, signer ed25519.PrivateKey,
) (*formalGLMPhase16FullDurableReleaseStore, error) {
	if !jointDPBiomedicalGaussianValidPeerName(peer) || key == ([32]byte{}) ||
		len(signer) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("formal-glm: invalid full-fallback durable store")
	}
	guardDir := filepath.Join(dir, "formal-full-range-guard")
	if err := formalGLMPhase18EnsurePrivateDir(guardDir); err != nil {
		return nil, err
	}
	inner, err := newJointDPBiomedicalGaussianFullDurableReleaseStore(
		filepath.Join(dir, "independent-full-release"), peer, key, signer)
	if err != nil {
		return nil, err
	}
	return &formalGLMPhase16FullDurableReleaseStore{
		dir: guardDir, peer: peer, key: key, inner: inner,
	}, nil
}

func formalGLMPhase16BuildFullFallbackHandoff(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
	full jointDPBiomedicalGaussianFullPhase19FinalizerHandoff,
	garbler, evaluator formalGLMPhase16FullRangeGuardReceipt,
	backendKey [32]byte,
) (formalGLMPhase16FullFallbackHandoff, error) {
	var zero formalGLMPhase16FullFallbackHandoff
	if admission.formalBinding == nil {
		return zero, fmt.Errorf("formal-glm: range-gated handoff requires a formal admission")
	}
	if err := jointDPBiomedicalGaussianValidateFullPhase19FinalizerHandoff(
		admission, pins, full, backendKey); err != nil {
		return zero, err
	}
	sourceByPeer := map[string]string{
		full.left.PeerName:  full.left.source.source.BindingSHA256,
		full.right.PeerName: full.right.source.source.BindingSHA256,
	}
	if err := formalGLMPhase16ValidateFullRangeGuardReceipt(
		admission, pins, garbler,
		sourceByPeer[admission.formalBinding.GarblerPeerName],
		"garbler"); err != nil {
		return zero, err
	}
	if err := formalGLMPhase16ValidateFullRangeGuardReceipt(
		admission, pins, evaluator,
		sourceByPeer[admission.formalBinding.EvaluatorPeerName],
		"evaluator"); err != nil {
		return zero, err
	}
	if garbler.ChunkStart != full.ChunkStart ||
		evaluator.ChunkStart != full.ChunkStart ||
		garbler.CoordinateCount != full.CoordinateCount ||
		evaluator.CoordinateCount != full.CoordinateCount ||
		garbler.SessionContextSHA256 != evaluator.SessionContextSHA256 {
		return zero, fmt.Errorf("formal-glm: range guard and noised chunk differ")
	}
	return formalGLMPhase16FullFallbackHandoff{
		Full: full, Garbler: garbler, Evaluator: evaluator,
	}, nil
}

func formalGLMPhase16FullGuardRecordMAC(key [32]byte,
	record formalGLMPhase16FullGuardRecord,
) (string, error) {
	record.RecordMAC = ""
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(formalGLMPhase16FullGuardRecordDomain))
	mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func formalGLMPhase16FullEncodeGuardRecord(key [32]byte,
	record formalGLMPhase16FullGuardRecord,
) ([]byte, error) {
	mac, err := formalGLMPhase16FullGuardRecordMAC(key, record)
	if err != nil {
		return nil, err
	}
	record.RecordMAC = mac
	return json.Marshal(record)
}

func formalGLMPhase16FullDecodeGuardRecord(key [32]byte,
	encoded []byte,
) (formalGLMPhase16FullGuardRecord, error) {
	var zero formalGLMPhase16FullGuardRecord
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record formalGLMPhase16FullGuardRecord
	if err := decoder.Decode(&record); err != nil {
		return zero, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return zero, fmt.Errorf("formal-glm: trailing durable guard data")
	}
	want, err := formalGLMPhase16FullGuardRecordMAC(key, record)
	validState := record.State == "ledger_committed" ||
		record.State == "invalid_source" || record.State == "valid_source"
	stateValid := record.State == "ledger_committed" &&
		!record.ValidityChecked && !record.AllChunksValid ||
		record.State == "invalid_source" && record.ValidityChecked &&
			!record.AllChunksValid ||
		record.State == "valid_source" && record.ValidityChecked &&
			record.AllChunksValid
	if err != nil || !hmac.Equal([]byte(want), []byte(record.RecordMAC)) ||
		record.Version != formalGLMPhase16FullGuardRecordVersion ||
		!validState || !stateValid ||
		!jointDPBiomedicalGaussianValidPeerName(record.PeerName) ||
		!formalGLMIsSHA256(record.ReleaseInstanceID) ||
		!formalGLMIsSHA256(record.ReleaseContractSHA256) ||
		!formalGLMIsSHA256(record.BackendSelectionSHA256) ||
		!formalGLMIsSHA256(record.InputCommitmentSHA256) ||
		!record.LedgerAppendBeforeValidity ||
		record.HistoryCanDenyOperation || record.OperationLimit ||
		record.RequestLimit {
		return zero, fmt.Errorf("formal-glm: invalid durable range-guard record")
	}
	canonical, err := formalGLMPhase16FullEncodeGuardRecord(key, record)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return zero, fmt.Errorf("formal-glm: non-canonical durable range-guard record")
	}
	return record, nil
}

func formalGLMPhase16FullGuardInputDigest(
	handoffs []formalGLMPhase16FullFallbackHandoff,
) (string, error) {
	hash := sha256.New()
	for _, handoff := range handoffs {
		fullMessage, err := jointDPBiomedicalGaussianFullPhase19HandoffMessage(
			handoff.Full)
		if err != nil {
			return "", err
		}
		garblerMessage, err := formalGLMPhase16FullRangeGuardReceiptMessage(
			handoff.Garbler)
		if err != nil {
			return "", err
		}
		evaluatorMessage, err := formalGLMPhase16FullRangeGuardReceiptMessage(
			handoff.Evaluator)
		if err != nil {
			return "", err
		}
		for _, value := range [][]byte{
			fullMessage, garblerMessage, handoff.Garbler.Signature,
			evaluatorMessage, handoff.Evaluator.Signature,
		} {
			_, _ = hash.Write(value)
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func formalGLMPhase16FullNormalizeGuardHandoffs(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
	handoffs []formalGLMPhase16FullFallbackHandoff,
	backendKey [32]byte,
) ([]formalGLMPhase16FullFallbackHandoff, string, error) {
	if len(handoffs) < 1 ||
		len(handoffs) > admission.selection.Contract.TotalCoordinateCount {
		return nil, "", fmt.Errorf("formal-glm: incomplete range-guard schedule")
	}
	ordered := append([]formalGLMPhase16FullFallbackHandoff(nil), handoffs...)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].Full.ChunkStart < ordered[j].Full.ChunkStart
	})
	next := 0
	for _, handoff := range ordered {
		verified, err := formalGLMPhase16BuildFullFallbackHandoff(
			admission, pins, handoff.Full, handoff.Garbler,
			handoff.Evaluator, backendKey)
		if err != nil || !reflect.DeepEqual(verified, handoff) ||
			handoff.Full.ChunkStart != next {
			if err != nil {
				return nil, "", err
			}
			return nil, "", fmt.Errorf("formal-glm: overlapping or modified range-guard schedule")
		}
		next += handoff.Full.CoordinateCount
	}
	if next != admission.selection.Contract.TotalCoordinateCount {
		return nil, "", fmt.Errorf("formal-glm: incomplete range-guard coverage")
	}
	digest, err := formalGLMPhase16FullGuardInputDigest(ordered)
	return ordered, digest, err
}

func (store *formalGLMPhase16FullDurableReleaseStore) FinalizeVector(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
	handoffs []formalGLMPhase16FullFallbackHandoff,
	backendKey [32]byte, phaseHook func(string),
) (jointDPBiomedicalGaussianFullLocalRelease, error) {
	var zero jointDPBiomedicalGaussianFullLocalRelease
	if store == nil || store.inner == nil || store.key != backendKey {
		return zero, fmt.Errorf("formal-glm: invalid durable range-guard store")
	}
	if err := jointDPBiomedicalGaussianValidateFullAdmissionCached(
		admission, pins); err != nil {
		return zero, err
	}
	contract := admission.selection.Contract
	if !formalGLMPhase19Contains(contract.DesignatedComputePeers, store.peer) {
		return zero, fmt.Errorf("formal-glm: range-guard finalizer is not designated")
	}
	ordered, inputDigest, err := formalGLMPhase16FullNormalizeGuardHandoffs(
		admission, pins, handoffs, backendKey)
	if err != nil {
		return zero, err
	}
	selectionSHA256, err := formalGLMPhase16BackendSelectionSHA256(
		*admission.formalSelection)
	if err != nil {
		return zero, err
	}
	record := formalGLMPhase16FullGuardRecord{
		Version: formalGLMPhase16FullGuardRecordVersion,
		State:   "ledger_committed", PeerName: store.peer,
		ReleaseInstanceID:          contract.ReleaseInstanceID,
		ReleaseContractSHA256:      contract.ReleaseContractSHA256,
		BackendSelectionSHA256:     selectionSHA256,
		InputCommitmentSHA256:      inputDigest,
		LedgerAppendBeforeValidity: true,
		ValidityChecked:            false, AllChunksValid: false,
		HistoryCanDenyOperation: false,
		OperationLimit:          false, RequestLimit: false,
	}
	shard := filepath.Join(store.dir, contract.ReleaseInstanceID[:2],
		contract.ReleaseInstanceID[2:4])
	if err := formalGLMPhase18EnsurePrivateDir(shard); err != nil {
		return zero, err
	}
	path := filepath.Join(shard, "guard-"+contract.ReleaseInstanceID+".json")
	store.mu.Lock()
	defer store.mu.Unlock()
	read := func() (formalGLMPhase16FullGuardRecord, error) {
		encoded, readErr := jointDPBiomedicalGaussianFullReadDurableRecord(path)
		if readErr != nil {
			return formalGLMPhase16FullGuardRecord{}, readErr
		}
		return formalGLMPhase16FullDecodeGuardRecord(store.key, encoded)
	}
	existing, readErr := read()
	created := false
	if os.IsNotExist(readErr) {
		encoded, encodeErr := formalGLMPhase16FullEncodeGuardRecord(
			store.key, record)
		if encodeErr != nil {
			return zero, encodeErr
		}
		created, err = jointDPBiomedicalGaussianFullCreateRecord(path, encoded)
		if err != nil {
			return zero, err
		}
		existing, err = read()
		if err != nil {
			return zero, err
		}
	} else if readErr != nil {
		return zero, readErr
	}
	if existing.PeerName != record.PeerName ||
		existing.ReleaseInstanceID != record.ReleaseInstanceID ||
		existing.ReleaseContractSHA256 != record.ReleaseContractSHA256 ||
		existing.BackendSelectionSHA256 != record.BackendSelectionSHA256 ||
		existing.InputCommitmentSHA256 != record.InputCommitmentSHA256 {
		return zero, fmt.Errorf("formal-glm: conflicting durable range-guard replay")
	}
	if created && phaseHook != nil {
		phaseHook("after_ledger_append_before_validity_or_release")
	}
	if existing.State == "invalid_source" {
		return zero, exactGCFailure(exactGCFailureBoundExceeded,
			fmt.Errorf("formal-glm: source rejected by the durable exact range gate"))
	}
	if existing.State == "ledger_committed" {
		allValid := true
		for _, handoff := range ordered {
			allValid = allValid &&
				handoff.Garbler.validityShare^
					handoff.Evaluator.validityShare == 1
		}
		existing.ValidityChecked = true
		existing.AllChunksValid = allValid
		if allValid {
			existing.State = "valid_source"
		} else {
			existing.State = "invalid_source"
		}
		encoded, err := formalGLMPhase16FullEncodeGuardRecord(
			store.key, existing)
		if err != nil {
			return zero, err
		}
		if err := exactGCAtomicReplace(path, encoded); err != nil {
			return zero, err
		}
		committed, err := read()
		if err != nil || committed.State != existing.State ||
			!committed.ValidityChecked ||
			committed.AllChunksValid != allValid {
			return zero, fmt.Errorf("formal-glm: durable range-gate commit failed")
		}
		if !allValid {
			if phaseHook != nil {
				phaseHook("after_invalid_source_durable_no_release")
			}
			return zero, exactGCFailure(exactGCFailureBoundExceeded,
				fmt.Errorf("formal-glm: source rejected by the durable exact range gate"))
		}
		if phaseHook != nil {
			phaseHook("after_validity_durable_before_dp_release")
		}
	}
	full := make([]jointDPBiomedicalGaussianFullPhase19FinalizerHandoff,
		len(ordered))
	for index := range ordered {
		full[index] = ordered[index].Full
	}
	return store.inner.finalizeVector(
		admission, pins, full, phaseHook, true)
}
