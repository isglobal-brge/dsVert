package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
)

// One private directory per authority/release, held under a process lock for the
// entire graph. PREPARE and COMMIT are atomic authenticated snapshots; fsync of
// both file and directory precedes every peer acknowledgement.
type crossGridStageStore struct {
	root  *os.Root
	lock  *os.File
	key   [32]byte // authority-local policy secret, independent of transport retries
	graph crossGridStageGraph
	plan  [32]byte
	role  exactGCRole
}

func crossGridStageOpenStore(dir string, key [32]byte, graph crossGridStageGraph, role exactGCRole) (*crossGridStageStore, error) {
	if graph.validate() != nil || role > exactGCRoleEvaluator || key == ([32]byte{}) ||
		!filepath.IsAbs(dir) || filepath.Clean(dir) != dir || formalFinalizerHandoffEnsurePrivateDir(dir) != nil {
		return nil, errCrossGridStage
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, errCrossGridStage
	}
	lockID := crossGridStageHash("authority-lock", graph.Session)
	lock, err := formalFinalizerHandoffAcquireAuthorityLock(root, hex.EncodeToString(lockID[:]))
	if err != nil {
		root.Close()
		return nil, err
	}
	// Own an immutable copy of the signed plan, including slices and maps.
	data, _ := json.Marshal(graph)
	var pinned crossGridStageGraph
	if json.Unmarshal(data, &pinned) != nil {
		lock.Close()
		root.Close()
		return nil, errCrossGridStage
	}
	return &crossGridStageStore{root, lock, key, pinned, crossGridStageHash("public-plan", pinned), role}, nil
}

func (s *crossGridStageStore) Close() error {
	if s.lock == nil {
		return nil
	}
	_ = formalFinalizerHandoffUnlockAuthority(s.lock)
	err := s.lock.Close()
	s.lock = nil
	if e := s.root.Close(); err == nil {
		err = e
	}
	clear(s.key[:])
	return err
}

func (s *crossGridStageStore) name(stage string) string {
	id := crossGridStageHash("record-path", []string{s.graph.Session, stage})
	return hex.EncodeToString(id[:]) + ".stage"
}

func (s *crossGridStageStore) recordMAC(data []byte) []byte {
	h := hmac.New(sha256.New, s.key[:])
	h.Write([]byte("dsvert/staged-grid/v1/private-record\x00"))
	h.Write(data)
	return h.Sum(nil)
}

func (s *crossGridStageStore) empty(abi crossGridStagePlan, previous [][32]byte) crossGridStageRecord {
	return crossGridStageRecord{Version: "cross-grid-stage-record-v1", Session: s.graph.Session,
		StageID: abi.ID, State: "EMPTY", Role: s.role, PlanDigest: s.plan, ABI: abi, PredecessorReceipts: previous}
}

func (s *crossGridStageStore) validate(r crossGridStageRecord, abi crossGridStagePlan, previous [][32]byte) error {
	if r.Version != "cross-grid-stage-record-v1" || r.Session != s.graph.Session || r.StageID != abi.ID ||
		r.Role != s.role || r.PlanDigest != s.plan || !reflect.DeepEqual(r.ABI, abi) ||
		!reflect.DeepEqual(r.PredecessorReceipts, previous) || r.Generation == 0 {
		return errCrossGridStage
	}
	switch r.State {
	case "ABORTED", "RUNNING":
		if len(r.Output.Share) != 0 || len(r.Output.Validity) != 0 || len(r.ShareMAC) != 0 ||
			r.Commitments != ([2][32]byte{}) || r.StageReceipt != ([32]byte{}) {
			return errCrossGridStage
		}
		if r.State == "ABORTED" {
			if r.AttemptNonce != ([32]byte{}) || r.OutputMaskDomainTag != ([32]byte{}) {
				return errCrossGridStage
			}
		} else if r.AttemptNonce == ([32]byte{}) ||
			r.OutputMaskDomainTag != crossGridStageMaskDomain(r.Session, r.StageID, r.AttemptNonce) {
			return errCrossGridStage
		}
	case "PREPARE", "COMMIT":
		if abi.validateOutput(r.Output) != nil || r.AttemptNonce == ([32]byte{}) ||
			r.OutputMaskDomainTag != crossGridStageMaskDomain(r.Session, r.StageID, r.AttemptNonce) ||
			r.Commitments[s.role] != crossGridStageCommitment(r) || r.Commitments[1-s.role] == ([32]byte{}) ||
			r.StageReceipt != crossGridStageReceipt(r) || !hmac.Equal(r.ShareMAC, crossGridStageShareMAC(s.key, r)) {
			return errCrossGridStage
		}
	default:
		return errCrossGridStage
	}
	return nil
}

const crossGridStageMaxRecordBytes = 128 << 20

func (s *crossGridStageStore) load(abi crossGridStagePlan, previous [][32]byte) (crossGridStageRecord, error) {
	name := s.name(abi.ID)
	info, err := s.root.Lstat(name)
	if os.IsNotExist(err) {
		return s.empty(abi, previous), nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 ||
		!exactGCPrivateOwnedRegular(info) || info.Size() < 32 || info.Size() > crossGridStageMaxRecordBytes {
		return crossGridStageRecord{}, errCrossGridStage
	}
	f, err := s.root.Open(name)
	if err != nil {
		return crossGridStageRecord{}, errCrossGridStage
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return crossGridStageRecord{}, errCrossGridStage
	}
	data, err := io.ReadAll(io.LimitReader(f, crossGridStageMaxRecordBytes+1))
	if err != nil || len(data) < 32 || len(data) > crossGridStageMaxRecordBytes || !hmac.Equal(data[:32], s.recordMAC(data[32:])) {
		return crossGridStageRecord{}, errCrossGridStage
	}
	var r crossGridStageRecord
	decoder := json.NewDecoder(bytes.NewReader(data[32:]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&r) != nil || decoder.Decode(new(any)) != io.EOF || s.validate(r, abi, previous) != nil {
		return crossGridStageRecord{}, errCrossGridStage
	}
	return r, nil
}

func (s *crossGridStageStore) save(r crossGridStageRecord) error {
	var abi *crossGridStagePlan
	for i := range s.graph.Stages {
		if s.graph.Stages[i].ID == r.StageID {
			abi = &s.graph.Stages[i]
			break
		}
	}
	if abi == nil || s.validate(r, *abi, r.PredecessorReceipts) != nil {
		return errCrossGridStage
	}
	old, err := s.load(r.ABI, r.PredecessorReceipts)
	if err != nil {
		return err
	}
	if old.State == "COMMIT" {
		if !reflect.DeepEqual(old, r) {
			return errCrossGridStage
		}
		return nil
	}
	if reflect.DeepEqual(old, r) {
		return nil
	}
	switch r.State {
	case "ABORTED":
		if r.Generation <= old.Generation {
			return errCrossGridStage
		}
	case "RUNNING":
		if old.State != "ABORTED" || r.Generation != old.Generation {
			return errCrossGridStage
		}
	case "PREPARE":
		if old.State != "RUNNING" || r.Generation != old.Generation || r.AttemptNonce != old.AttemptNonce ||
			r.OutputMaskDomainTag != old.OutputMaskDomainTag {
			return errCrossGridStage
		}
	}
	// COMMIT may only publish the exact persisted PREPARE, never a recomputation.
	if r.State == "COMMIT" {
		prepared := r
		prepared.State = "PREPARE"
		if !reflect.DeepEqual(old, prepared) {
			return errCrossGridStage
		}
	}
	data, err := json.Marshal(r)
	if err != nil || len(data)+32 > crossGridStageMaxRecordBytes {
		return errCrossGridStage
	}
	data = append(s.recordMAC(data), data...)
	token, err := newExactGCSessionID()
	if err != nil {
		return err
	}
	temporary := ".stage-" + hex.EncodeToString(token[:])
	f, err := s.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer s.root.Remove(temporary)
	err = exactGCWriteFull(f, data)
	if err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	if err := s.root.Rename(temporary, s.name(r.StageID)); err != nil {
		return err
	}
	dir, err := s.root.Open(".")
	if err != nil {
		return err
	}
	err = dir.Sync()
	if e := dir.Close(); err == nil {
		err = e
	}
	return err
}
