package main

// Non-production, one-shot relay reopening for a burned transport epoch. The
// worker remains the sole spool owner; worker lease/heartbeat is an A1.5b cut.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"time"
)

const (
	formalGLMRegisteredPhase20JobRelayStoreVersionV1 = "dsvert-formal-glm-registered-phase20-job-relay-store-v1"
	formalGLMRegisteredPhase20JobRelayStorePurposeV1 = "formal_glm_registered_phase20_job_relay_store_v1"
	formalGLMRegisteredPhase20JobRelayStoreDomainV1  = "dsVert/formal-glm/registered-phase20/job-relay-store/v1"

	formalGLMRegisteredPhase20JobPeerBindFileV1     = "peer-bind.json"
	formalGLMRegisteredPhase20JobRelayFailedFileV1  = "relay-failed.json"
	formalGLMRegisteredPhase20JobRelayStateFileV1   = "relay-state.json"
	formalGLMRegisteredPhase20JobRelayInboundNextV1 = ".relay-inbound.next"
	formalGLMRegisteredPhase20JobRelayRecordMaxV1   = int64(16 << 10)
	formalGLMRegisteredPhase20JobPeerBindKindV1     = "peer_bound"
	formalGLMRegisteredPhase20JobRelayFailedKindV1  = "failed_closed"
)

type formalGLMRegisteredPhase20JobRelayRangeV1 struct {
	Start         int64  `json:"start"`
	End           int64  `json:"end"`
	PayloadSHA256 string `json:"payload_sha256"`
}

type formalGLMRegisteredPhase20JobPeerBindRecordV1 struct {
	Version         string `json:"version"`
	Purpose         string `json:"purpose"`
	JobSHA256       string `json:"job_sha256"`
	TransportSHA256 string `json:"transport_sha256"`
	Kind            string `json:"kind"`
	ProductionReady bool   `json:"production_ready"`
	MACSHA256       string `json:"mac_sha256"`
}

type formalGLMRegisteredPhase20JobRelayStateV1 struct {
	Version         string                                     `json:"version"`
	Purpose         string                                     `json:"purpose"`
	JobSHA256       string                                     `json:"job_sha256"`
	TransportSHA256 string                                     `json:"transport_sha256"`
	State           string                                     `json:"state"`
	Generation      uint64                                     `json:"generation"`
	InboundAccepted int64                                      `json:"inbound_accepted"`
	PendingInbound  *formalGLMRegisteredPhase20JobRelayRangeV1 `json:"pending_inbound,omitempty"`
	LastInbound     *formalGLMRegisteredPhase20JobRelayRangeV1 `json:"last_inbound,omitempty"`
	OutboundAck     int64                                      `json:"outbound_ack"`
	LastOffer       *formalGLMRegisteredPhase20JobRelayRangeV1 `json:"last_offer,omitempty"`
	ProductionReady bool                                       `json:"production_ready"`
	MACSHA256       string                                     `json:"mac_sha256"`
}

// Every field is private so a command cannot serialize roots or MAC material.
// AttemptStore and JobKeyProvider are borrowed only while opening this handle.
type formalGLMRegisteredPhase20JobTransportRelayStoreV1 struct {
	mu sync.Mutex

	scratch      *os.Root
	segmentRoots [2]*os.Root
	scratchPath  string
	ref          formalGLMRegisteredPhase20JobRefV1
	macKey       [32]byte
	closed       bool
}

type formalGLMRegisteredPhase20JobRelayTrustV1 struct {
	binding      formalGLMRegisteredPhase20JobTransportBindingV1
	jobSHA       string
	transportSHA string
	macKey       [32]byte
	scratch      *os.Root
}

func formalGLMRegisteredPhase20JobRelayRangeFromChunkV1(
	chunk formalGLMRegisteredPhase20RelayChunkV1,
) *formalGLMRegisteredPhase20JobRelayRangeV1 {
	return &formalGLMRegisteredPhase20JobRelayRangeV1{
		Start: chunk.Offset, End: chunk.Offset + int64(len(chunk.Payload)),
		PayloadSHA256: chunk.PayloadSHA256,
	}
}

func formalGLMRegisteredPhase20JobRelayValidStateV1(state string) bool {
	// A1.5a writes negotiating/failed_closed. A1.5b will persist the other
	// owner lifecycle values under the same relay command lock.
	switch state {
	case formalGLMRegisteredPhase20JobNegotiatingV1,
		formalGLMRegisteredPhase20JobRunningV1,
		formalGLMRegisteredPhase20JobAbandonPendingV1,
		formalGLMRegisteredPhase20JobAbandonedV1,
		formalGLMRegisteredPhase20JobEvidenceSealedV1,
		formalGLMRegisteredPhase20JobPreparedV1,
		formalGLMRegisteredPhase20JobSelectVotedV1,
		formalGLMRegisteredPhase20JobSelectedV1,
		formalGLMRegisteredPhase20JobFailedClosedV1:
		return true
	default:
		return false
	}
}

func formalGLMRegisteredPhase20JobRelayValidRangeV1(
	value *formalGLMRegisteredPhase20JobRelayRangeV1,
) bool {
	return value != nil && value.Start >= 0 && value.End > value.Start &&
		value.End <= exactGCMaxAbsoluteOffset &&
		value.End-value.Start <= formalGLMRegisteredPhase20JobRelayMaxPayloadV1 &&
		formalGLMIsSHA256(value.PayloadSHA256)
}

func formalGLMRegisteredPhase20JobRelayDeriveTrustV1(
	attempts *formalGLMRegisteredPhase19AttemptStoreV1,
	jobKeys *formalGLMRegisteredPhase20JobKeyProviderV1,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	epoch formalGLMRegisteredPhase20JobTransportEpochV1,
) (formalGLMRegisteredPhase20JobRelayTrustV1, error) {
	var trust formalGLMRegisteredPhase20JobRelayTrustV1
	if attempts == nil || jobKeys == nil {
		return trust,
			fmt.Errorf("formal-glm registered Phase20 relay store: unavailable trust context")
	}
	attempts.mu.Lock()
	plan := attempts.contract.Core.RegisteredExecutionPlan
	if attempts.root == nil || attempts.localIndex < 0 || attempts.localIndex > 1 ||
		len(plan.DesignatedComputePeers) != 2 || len(plan.NoiseAuthorities) != 2 ||
		plan.NoiseAuthorities[attempts.localIndex].PeerName !=
			plan.DesignatedComputePeers[attempts.localIndex] ||
		attempts.validateAcceptV1(proposal, accept) != nil ||
		attempts.requirePreviousBindingV1(proposal.Binding) != nil ||
		!reflect.DeepEqual(proposal.Binding, accept.Binding) {
		attempts.mu.Unlock()
		return trust,
			fmt.Errorf("formal-glm registered Phase20 relay store: invalid signed attempt")
	}
	attemptRoot, localIndex := attempts.root, attempts.localIndex
	localPeer := plan.DesignatedComputePeers[localIndex]
	attemptRelative := attempts.attemptRelativeDirV1(proposal.Binding.AttemptID)
	receiptSetSHA256 := attempts.record.Binding.ReceiptSetSHA256
	wantContext := formalGLMRegisteredPhase20JobKeyContextV1{
		artifactID:                    attempts.record.Binding.ArtifactID,
		sourceContractCoreSHA256:      attempts.record.Binding.SourceContractCoreSHA256,
		sourceContractSHA256:          attempts.record.Binding.SourceContractSHA256,
		pinsetSHA256:                  attempts.record.Binding.PinsetSHA256,
		semanticRootSHA256:            attempts.record.Binding.SemanticRootSHA256,
		bindingRecordSHA256:           attempts.recordSHA256,
		registeredExecutionPlanSHA256: attempts.record.Binding.RegisteredExecutionPlanSHA256,
		localPeer:                     localPeer, localIndex: localIndex,
	}
	attempts.mu.Unlock()

	jobKeys.mu.Lock()
	contextOK := jobKeys.validateLocked() == nil && jobKeys.context == wantContext
	keyRoot := jobKeys.root
	jobKeys.mu.Unlock()
	if !contextOK || !formalGLMRegisteredPhase19ScheduleTailSameRootV1(
		attemptRoot, keyRoot) {
		return trust,
			fmt.Errorf("formal-glm registered Phase20 relay store: split Rock ownership")
	}
	acceptSHA256, err := formalGLMRegisteredPhase19ClaimAcceptSHA256V1(accept)
	// ClaimAccept is the last common signed record before either the run or the
	// role-ordered abandon channel; Mode domain-separates their immutable slots.
	if err != nil || epoch.BasisSHA256 != acceptSHA256 {
		return trust,
			fmt.Errorf("formal-glm registered Phase20 relay store: untrusted epoch basis")
	}
	trust.binding = formalGLMRegisteredPhase20JobTransportBindingV1{
		ArtifactID:          proposal.Binding.ArtifactID,
		ReceiptSetSHA256:    receiptSetSHA256,
		SemanticRootSHA256:  proposal.Binding.SemanticRootSHA256,
		BindingRecordSHA256: proposal.Binding.BindingRecordSHA256,
		AttemptID:           proposal.Binding.AttemptID,
		ScheduleRootSHA256:  proposal.Binding.ScheduleRootSHA256,
		ProductionReady:     false,
	}
	jobSHA256, transportSHA256, err :=
		formalGLMRegisteredPhase20JobTransportIdentityV1(trust.binding, epoch)
	if err != nil {
		return trust, err
	}
	trust.jobSHA = jobSHA256
	trust.transportSHA = transportSHA256
	attemptKey, err := jobKeys.DeriveAttemptKey(proposal.Binding)
	if err != nil {
		return trust, err
	}
	mac := hmac.New(sha256.New, attemptKey[:])
	_, _ = mac.Write([]byte(formalGLMRegisteredPhase20JobRelayStoreDomainV1 +
		"/mac-key|" + transportSHA256))
	copy(trust.macKey[:], mac.Sum(nil))
	clear(attemptKey[:])

	attempts.mu.Lock()
	defer attempts.mu.Unlock()
	if attempts.root == nil {
		clear(trust.macKey[:])
		return trust,
			fmt.Errorf("formal-glm registered Phase20 relay store: attempt store closed")
	}
	burned, err := formalGLMRegisteredPhase20JobTransportBurnedV1(
		attempts.root, attemptRelative, trust.binding, epoch)
	if err != nil || !burned {
		clear(trust.macKey[:])
		return trust,
			fmt.Errorf("formal-glm registered Phase20 relay store: epoch is not burned")
	}
	relative, err := formalGLMRegisteredPhase20JobTransportRelativeV1(
		attemptRelative, transportSHA256)
	if err != nil {
		clear(trust.macKey[:])
		return trust, err
	}
	trust.scratch, err = attempts.root.OpenRoot(relative)
	if err != nil {
		clear(trust.macKey[:])
		return trust, err
	}
	return trust, nil
}

func openFormalGLMRegisteredPhase20JobTransportRelayStoreV1(
	attempts *formalGLMRegisteredPhase19AttemptStoreV1,
	jobKeys *formalGLMRegisteredPhase20JobKeyProviderV1,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	epoch formalGLMRegisteredPhase20JobTransportEpochV1,
) (*formalGLMRegisteredPhase20JobTransportRelayStoreV1, error) {
	trust, err := formalGLMRegisteredPhase20JobRelayDeriveTrustV1(
		attempts, jobKeys, proposal, accept, epoch)
	if err != nil {
		return nil, err
	}
	store := &formalGLMRegisteredPhase20JobTransportRelayStoreV1{
		scratch: trust.scratch, scratchPath: trust.scratch.Name(), macKey: trust.macKey,
	}
	clear(trust.macKey[:])
	store.ref = formalGLMRegisteredPhase20JobRefV1{
		ArtifactID:       trust.binding.ArtifactID,
		ReceiptSetSHA256: trust.binding.ReceiptSetSHA256,
		AttemptID:        trust.binding.AttemptID, JobSHA256: trust.jobSHA,
		TransportSHA256: trust.transportSHA, ProductionReady: false,
	}
	fail := func(err error) (*formalGLMRegisteredPhase20JobTransportRelayStoreV1, error) {
		_ = store.CloseRelayV1()
		return nil, err
	}
	for index, name := range []string{"inbound.segments", "outbound.segments"} {
		store.segmentRoots[index], err = trust.scratch.OpenRoot(name)
		if err != nil {
			return fail(err)
		}
	}
	if err := store.validateScratchV1(); err != nil {
		return fail(err)
	}
	lock, err := store.acquireRelayLockV1()
	if err != nil {
		return fail(err)
	}
	defer store.releaseRelayLockV1(lock)
	if err := store.initializeOrLoadStateLockedV1(); err != nil {
		return fail(err)
	}
	return store, nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) validateScratchV1() error {
	if store == nil || store.scratch == nil {
		return fmt.Errorf("formal-glm registered Phase20 relay store: closed")
	}
	return formalGLMRegisteredPhase20JobTransportValidateScratchV1(
		store.scratch, store.scratchPath, store.segmentRoots)
}

func formalGLMRegisteredPhase20JobRelayRemoveTempV1(
	root *os.Root, name string, maximum int64,
) (bool, error) {
	info, err := root.Lstat(name)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		!exactGCPrivateOwnedRegular(info) || info.Size() < 0 || info.Size() > maximum {
		return false, fmt.Errorf("formal-glm registered Phase20 relay store: unsafe next state")
	}
	if err := root.Remove(name); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	return true, nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) reapRelayTempsLockedV1() error {
	changed := false
	for _, name := range []string{
		formalGLMRegisteredPhase20JobRelayStateFileV1 + ".next",
		formalGLMRegisteredPhase20JobPeerBindFileV1 + ".next",
		formalGLMRegisteredPhase20JobRelayFailedFileV1 + ".next",
		"outbound.ack.next",
	} {
		removed, err := formalGLMRegisteredPhase20JobRelayRemoveTempV1(
			store.scratch, name, formalGLMRegisteredPhase20JobRelayRecordMaxV1)
		if err != nil {
			return err
		}
		changed = changed || removed
	}
	if changed {
		if err := formalGLMPhase21RootSyncDir(
			store.scratch, formalGLMRegisteredPhase20JobRelayStateFileV1); err != nil {
			return err
		}
	}
	removed, err := formalGLMRegisteredPhase20JobRelayRemoveTempV1(
		store.segmentRoots[0], formalGLMRegisteredPhase20JobRelayInboundNextV1,
		formalGLMRegisteredPhase20JobRelayMaxPayloadV1)
	if err != nil {
		return err
	}
	if removed {
		if err := store.syncSegmentDirV1(0); err != nil {
			return err
		}
	}
	return nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) readRecordV1(
	name string,
) ([]byte, error) {
	encoded, err := formalGLMPhase21RootReadRecord(
		store.scratch, name, formalGLMRegisteredPhase20JobRelayRecordMaxV1)
	if err != nil {
		return nil, err
	}
	info, err := store.scratch.Lstat(name)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		info.Size() != int64(len(encoded)) || !exactGCPrivateOwnedRegular(info) {
		clear(encoded)
		return nil, fmt.Errorf("formal-glm registered Phase20 relay store: unsafe record")
	}
	return encoded, nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) replaceRecordV1(
	name string, encoded []byte,
) error {
	if err := store.validateScratchV1(); err != nil {
		return err
	}
	temporary := name + ".next"
	if info, err := store.scratch.Lstat(temporary); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
			!exactGCPrivateOwnedRegular(info) {
			return fmt.Errorf("formal-glm registered Phase20 relay store: unsafe next record")
		}
		if err := store.scratch.Remove(temporary); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := formalGLMRegisteredPhase20JobTransportWriteInitialV1(
		store.scratch, temporary, encoded); err != nil {
		return err
	}
	if err := store.scratch.Rename(temporary, name); err != nil {
		return err
	}
	if err := formalGLMPhase21RootSyncDir(store.scratch, name); err != nil {
		return err
	}
	return store.validateScratchV1()
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) recordMACV1(
	domain string, value any,
) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, store.macKey[:])
	_, _ = mac.Write([]byte(domain + "|"))
	_, _ = mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) signStateV1(
	state *formalGLMRegisteredPhase20JobRelayStateV1,
) ([]byte, error) {
	state.MACSHA256 = ""
	mac, err := store.recordMACV1(
		formalGLMRegisteredPhase20JobRelayStoreDomainV1+"/state", *state)
	if err != nil {
		return nil, err
	}
	state.MACSHA256 = mac
	return json.Marshal(*state)
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) validateStateV1(
	state formalGLMRegisteredPhase20JobRelayStateV1,
) error {
	mac := state.MACSHA256
	unsigned := state
	unsigned.MACSHA256 = ""
	wantMAC, err := store.recordMACV1(
		formalGLMRegisteredPhase20JobRelayStoreDomainV1+"/state", unsigned)
	if err != nil || !hmac.Equal([]byte(mac), []byte(wantMAC)) ||
		state.Version != formalGLMRegisteredPhase20JobRelayStoreVersionV1 ||
		state.Purpose != formalGLMRegisteredPhase20JobRelayStorePurposeV1 ||
		state.JobSHA256 != store.ref.JobSHA256 ||
		state.TransportSHA256 != store.ref.TransportSHA256 ||
		state.ProductionReady || !formalGLMRegisteredPhase20JobRelayValidStateV1(state.State) ||
		state.InboundAccepted < 0 || state.InboundAccepted > exactGCMaxAbsoluteOffset ||
		state.OutboundAck < 0 || state.OutboundAck > exactGCMaxAbsoluteOffset {
		return fmt.Errorf("formal-glm registered Phase20 relay store: invalid relay state")
	}
	if state.InboundAccepted == 0 && state.LastInbound != nil ||
		state.InboundAccepted > 0 &&
			(!formalGLMRegisteredPhase20JobRelayValidRangeV1(state.LastInbound) ||
				state.LastInbound.End != state.InboundAccepted) ||
		state.PendingInbound != nil &&
			(!formalGLMRegisteredPhase20JobRelayValidRangeV1(state.PendingInbound) ||
				state.PendingInbound.Start != state.InboundAccepted) ||
		state.LastOffer != nil &&
			(!formalGLMRegisteredPhase20JobRelayValidRangeV1(state.LastOffer) ||
				state.LastOffer.Start != state.OutboundAck) {
		return fmt.Errorf("formal-glm registered Phase20 relay store: invalid relay cursor")
	}
	return nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) loadRelayStateLockedV1() (formalGLMRegisteredPhase20JobRelayStateV1, error) {
	var state formalGLMRegisteredPhase20JobRelayStateV1
	encoded, err := store.readRecordV1(formalGLMRegisteredPhase20JobRelayStateFileV1)
	if err != nil {
		return state, err
	}
	defer clear(encoded)
	if formalGLMPhase21RockStrictDecode(encoded, &state) != nil ||
		store.validateStateV1(state) != nil {
		return formalGLMRegisteredPhase20JobRelayStateV1{},
			fmt.Errorf("formal-glm registered Phase20 relay store: invalid durable state")
	}
	if _, err := store.scratch.Lstat(formalGLMRegisteredPhase20JobRelayFailedFileV1); err == nil {
		if err := store.requireAnchorV1(formalGLMRegisteredPhase20JobRelayFailedFileV1,
			formalGLMRegisteredPhase20JobRelayFailedKindV1); err != nil {
			return formalGLMRegisteredPhase20JobRelayStateV1{}, err
		}
		if err := formalGLMRegisteredPhase20JobTransportSignalAbortV1(
			store.scratch); err != nil {
			return formalGLMRegisteredPhase20JobRelayStateV1{}, err
		}
		state.State = formalGLMRegisteredPhase20JobFailedClosedV1
	} else if !os.IsNotExist(err) {
		return formalGLMRegisteredPhase20JobRelayStateV1{}, err
	}
	return state, nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) commitRelayStateLockedV1(
	state *formalGLMRegisteredPhase20JobRelayStateV1,
) error {
	current, err := store.loadRelayStateLockedV1()
	if err != nil || current.Generation != state.Generation ||
		current.MACSHA256 != state.MACSHA256 || state.Generation == ^uint64(0) {
		return fmt.Errorf("formal-glm registered Phase20 relay store: relay state CAS failed")
	}
	state.Generation++
	encoded, err := store.signStateV1(state)
	if err != nil || store.validateStateV1(*state) != nil {
		return fmt.Errorf("formal-glm registered Phase20 relay store: invalid relay state update")
	}
	if err := store.replaceRecordV1(
		formalGLMRegisteredPhase20JobRelayStateFileV1, encoded); err != nil {
		return err
	}
	readback, err := store.loadRelayStateLockedV1()
	if err != nil || !reflect.DeepEqual(readback, *state) {
		return fmt.Errorf("formal-glm registered Phase20 relay store: relay state readback failed")
	}
	return nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) initializeOrLoadStateLockedV1() error {
	if err := store.reapRelayTempsLockedV1(); err != nil {
		return err
	}
	if _, err := store.scratch.Lstat(formalGLMRegisteredPhase20JobRelayStateFileV1); err == nil {
		state, loadErr := store.loadRelayStateLockedV1()
		if loadErr != nil {
			return loadErr
		}
		return store.reconcileStateLockedV1(&state)
	} else if !os.IsNotExist(err) {
		return err
	}
	for _, name := range []string{"inbound.ack", "outbound.head", "outbound.ack"} {
		value, err := store.readOffsetLockedV1(name)
		if err != nil || value != 0 {
			return fmt.Errorf("formal-glm registered Phase20 relay store: state created after bytes")
		}
	}
	for index := 0; index < 2; index++ {
		segments, err := store.listSegmentsV1(index)
		if err != nil || len(segments) != 0 {
			return fmt.Errorf("formal-glm registered Phase20 relay store: state created after segments")
		}
	}
	state := formalGLMRegisteredPhase20JobRelayStateV1{
		Version:         formalGLMRegisteredPhase20JobRelayStoreVersionV1,
		Purpose:         formalGLMRegisteredPhase20JobRelayStorePurposeV1,
		JobSHA256:       store.ref.JobSHA256,
		TransportSHA256: store.ref.TransportSHA256,
		State:           formalGLMRegisteredPhase20JobNegotiatingV1,
		ProductionReady: false,
	}
	encoded, err := store.signStateV1(&state)
	if err != nil {
		return err
	}
	if err := store.replaceRecordV1(
		formalGLMRegisteredPhase20JobRelayStateFileV1, encoded); err != nil {
		return fmt.Errorf("formal-glm registered Phase20 relay store: initial state CAS failed")
	}
	readback, err := store.loadRelayStateLockedV1()
	if err != nil || !reflect.DeepEqual(readback, state) {
		return fmt.Errorf("formal-glm registered Phase20 relay store: initial state readback failed")
	}
	return nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) acquireRelayLockV1() (*os.File, error) {
	if store == nil || store.scratch == nil {
		return nil, fmt.Errorf("formal-glm registered Phase20 relay store: closed")
	}
	name := "authority-lock-" + store.ref.TransportSHA256 + ".bin"
	if info, err := store.scratch.Lstat(name); err == nil &&
		(info.Mode().Perm() != 0o600 || !exactGCPrivateOwnedRegular(info)) {
		return nil, fmt.Errorf("formal-glm registered Phase20 relay store: unsafe relay lock")
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	lock, err := formalFinalizerHandoffAcquireAuthorityLock(
		store.scratch, store.ref.TransportSHA256)
	if err != nil {
		return nil, fmt.Errorf("formal-glm registered Phase20 relay store: relay lock busy")
	}
	return lock, nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) releaseRelayLockV1(
	lock *os.File,
) {
	if lock != nil {
		_ = formalFinalizerHandoffUnlockAuthority(lock)
		_ = lock.Close()
	}
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) readOffsetLockedV1(
	name string,
) (int64, error) {
	if name != "inbound.ack" && name != "outbound.head" && name != "outbound.ack" {
		return 0, fmt.Errorf("formal-glm registered Phase20 relay store: invalid offset")
	}
	if err := store.validateScratchV1(); err != nil {
		return 0, err
	}
	value, err := exactGCReadOffset(filepath.Join(store.scratchPath, name))
	if afterErr := store.validateScratchV1(); err == nil {
		err = afterErr
	}
	return value, err
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) writeOffsetLockedV1(
	name string, value int64,
) error {
	if name != "outbound.ack" || value < 0 ||
		value > exactGCMaxAbsoluteOffset {
		return fmt.Errorf("formal-glm registered Phase20 relay store: invalid offset update")
	}
	if err := store.replaceRecordV1(
		name, []byte(strconv.FormatInt(value, 10))); err != nil {
		return err
	}
	readback, err := store.readOffsetLockedV1(name)
	if err != nil || readback != value {
		return fmt.Errorf("formal-glm registered Phase20 relay store: offset readback failed")
	}
	return nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) listSegmentsV1(
	index int,
) ([]exactGCSegment, error) {
	if index < 0 || index > 1 || store.validateScratchV1() != nil {
		return nil, fmt.Errorf("formal-glm registered Phase20 relay store: unsafe segment root")
	}
	segments, err := exactGCListSegments(store.segmentRoots[index].Name())
	if afterErr := store.validateScratchV1(); err == nil {
		err = afterErr
	}
	return segments, err
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) publishInboundLockedV1(
	chunk formalGLMRegisteredPhase20RelayChunkV1,
) error {
	end := chunk.Offset + int64(len(chunk.Payload))
	name, err := exactGCSegmentName(chunk.Offset, end, chunk.PayloadSHA256)
	if err != nil {
		return err
	}
	segments, err := store.listSegmentsV1(0)
	if err != nil {
		return err
	}
	for _, segment := range segments {
		if segment.start == chunk.Offset && segment.end == end {
			if segment.name != name {
				return fmt.Errorf("formal-glm registered Phase20 relay store: inbound retry fork")
			}
			if err := exactGCVerifySegment(segment); err != nil &&
				!errors.Is(err, errExactGCSegmentChanged) {
				return err
			}
			return nil
		}
		if segment.start < end && segment.end > chunk.Offset {
			return fmt.Errorf("formal-glm registered Phase20 relay store: inbound overlap")
		}
	}
	removed, err := formalGLMRegisteredPhase20JobRelayRemoveTempV1(
		store.segmentRoots[0], formalGLMRegisteredPhase20JobRelayInboundNextV1,
		formalGLMRegisteredPhase20JobRelayMaxPayloadV1)
	if err != nil {
		return err
	}
	if removed {
		if err := store.syncSegmentDirV1(0); err != nil {
			return err
		}
	}
	published := false
	defer func() {
		if !published {
			_ = store.segmentRoots[0].Remove(
				formalGLMRegisteredPhase20JobRelayInboundNextV1)
			_ = store.syncSegmentDirV1(0)
		}
	}()
	if err := formalGLMRegisteredPhase20JobTransportWriteInitialV1(
		store.segmentRoots[0], formalGLMRegisteredPhase20JobRelayInboundNextV1,
		chunk.Payload); err != nil {
		return err
	}
	if err := store.validateScratchV1(); err != nil {
		return err
	}
	if err := store.segmentRoots[0].Rename(
		formalGLMRegisteredPhase20JobRelayInboundNextV1, name); err != nil {
		return err
	}
	published = true
	if err := store.syncSegmentDirV1(0); err != nil {
		return err
	}
	return store.validateScratchV1()
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) syncSegmentDirV1(
	index int,
) error {
	directory, err := store.segmentRoots[index].Open(".")
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) cleanupSegmentsLockedV1(
	index int, through int64,
) error {
	segments, err := store.listSegmentsV1(index)
	if err != nil {
		return err
	}
	changed := false
	for _, segment := range segments {
		if segment.end <= through {
			if err := store.segmentRoots[index].Remove(segment.name); err != nil &&
				!os.IsNotExist(err) {
				return err
			}
			changed = true
		}
	}
	if changed {
		return store.syncSegmentDirV1(index)
	}
	return nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) stableInboundAckLockedV1(
	state *formalGLMRegisteredPhase20JobRelayStateV1,
) (int64, bool, error) {
	before, err := store.readOffsetLockedV1("inbound.ack")
	if err != nil {
		return 0, false, err
	}
	return store.stableInboundAckFromSnapshotLockedV1(state, before)
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) stableInboundAckFromSnapshotLockedV1(
	state *formalGLMRegisteredPhase20JobRelayStateV1,
	before int64,
) (int64, bool, error) {
	for attempt := 0; attempt < 4; attempt++ {
		accepted, last := state.InboundAccepted, state.LastInbound
		consumedPending := state.PendingInbound != nil &&
			before == state.PendingInbound.End
		if consumedPending {
			accepted, last = state.PendingInbound.End, state.PendingInbound
		}
		cursor, missing, verifyErr := before, before > accepted, error(nil)
		if before < accepted {
			segments, err := store.listSegmentsV1(0)
			if err != nil {
				if !errors.Is(err, errExactGCSegmentChanged) {
					return 0, false, err
				}
				verifyErr = err
			}
			for _, segment := range segments {
				if segment.end <= cursor {
					continue
				}
				if segment.start > cursor || segment.end > accepted {
					break
				}
				if verifyErr = exactGCVerifySegment(segment); verifyErr != nil {
					break
				}
				cursor = segment.end
				if cursor == accepted &&
					(segment.start != last.Start || segment.hash != last.PayloadSHA256) {
					break
				}
			}
			missing = cursor != accepted
		}
		after, err := store.readOffsetLockedV1("inbound.ack")
		if err != nil {
			return 0, false, err
		}
		if after != before || errors.Is(verifyErr, errExactGCSegmentChanged) {
			before = after
			continue
		}
		if verifyErr != nil || missing {
			return 0, false, store.failClosedLockedV1(state,
				errors.New("formal-glm registered Phase20 relay store: missing inbound"))
		}
		return before, consumedPending, nil
	}
	return 0, false,
		fmt.Errorf("formal-glm registered Phase20 relay store: inbound cursor changed")
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) reconcileStateLockedV1(
	state *formalGLMRegisteredPhase20JobRelayStateV1,
) error {
	inboundAck, consumedPending, inErr := store.stableInboundAckLockedV1(state)
	outboundAck, outErr := store.readOffsetLockedV1("outbound.ack")
	head, headErr := store.readOffsetLockedV1("outbound.head")
	if inErr != nil || outErr != nil || headErr != nil || head < outboundAck {
		return fmt.Errorf("formal-glm registered Phase20 relay store: invalid durable cursors")
	}
	if state.LastOffer != nil && state.LastOffer.End > head {
		return fmt.Errorf("formal-glm registered Phase20 relay store: offer exceeds durable head")
	}
	if consumedPending {
		state.InboundAccepted = state.PendingInbound.End
		state.LastInbound = state.PendingInbound
		state.PendingInbound = nil
		if err := store.commitRelayStateLockedV1(state); err != nil {
			return err
		}
	}
	if err := store.cleanupSegmentsLockedV1(0, inboundAck); err != nil {
		return err
	}
	if outboundAck != state.OutboundAck {
		if state.LastOffer == nil || outboundAck != state.LastOffer.End {
			return fmt.Errorf("formal-glm registered Phase20 relay store: invalid ack reconciliation")
		}
		state.OutboundAck = outboundAck
		state.LastOffer = nil
		if err := store.commitRelayStateLockedV1(state); err != nil {
			return err
		}
	}
	return store.cleanupSegmentsLockedV1(1, state.OutboundAck)
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) anchorRecordV1(
	kind string,
) (formalGLMRegisteredPhase20JobPeerBindRecordV1, []byte, error) {
	record := formalGLMRegisteredPhase20JobPeerBindRecordV1{
		Version:         formalGLMRegisteredPhase20JobRelayStoreVersionV1,
		Purpose:         formalGLMRegisteredPhase20JobRelayStorePurposeV1,
		JobSHA256:       store.ref.JobSHA256,
		TransportSHA256: store.ref.TransportSHA256, Kind: kind,
		ProductionReady: false,
	}
	mac, err := store.recordMACV1(
		formalGLMRegisteredPhase20JobRelayStoreDomainV1+"/anchor", record)
	if err != nil {
		return record, nil, err
	}
	record.MACSHA256 = mac
	encoded, err := json.Marshal(record)
	return record, encoded, err
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) requireAnchorV1(
	name, kind string,
) error {
	want, canonical, err := store.anchorRecordV1(kind)
	if err != nil {
		return err
	}
	encoded, err := store.readRecordV1(name)
	if err != nil {
		return err
	}
	defer clear(encoded)
	var got formalGLMRegisteredPhase20JobPeerBindRecordV1
	if formalGLMPhase21RockStrictDecode(encoded, &got) != nil ||
		!bytes.Equal(encoded, canonical) || !reflect.DeepEqual(got, want) {
		return fmt.Errorf("formal-glm registered Phase20 relay store: invalid anchor")
	}
	return nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) commitAnchorV1(
	name, kind string,
) error {
	_, encoded, err := store.anchorRecordV1(kind)
	if err != nil {
		return err
	}
	if _, err := store.scratch.Lstat(name); err == nil {
		return store.requireAnchorV1(name, kind)
	} else if !os.IsNotExist(err) {
		return err
	}
	// The relay flock serializes every legitimate creator, so the deterministic
	// rooted rename is an immutable create within this transport epoch.
	if err := store.replaceRecordV1(name, encoded); err != nil {
		return err
	}
	return store.requireAnchorV1(name, kind)
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) peerBoundLockedV1() error {
	if err := store.requireAnchorV1(formalGLMRegisteredPhase20JobPeerBindFileV1,
		formalGLMRegisteredPhase20JobPeerBindKindV1); err != nil {
		return fmt.Errorf("formal-glm registered Phase20 relay store: peer epoch is not bound")
	}
	return nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) BindPeerEpochV1(
	peer formalGLMRegisteredPhase20JobRefV1,
) error {
	if store == nil {
		return fmt.Errorf("formal-glm registered Phase20 relay store: unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed || !reflect.DeepEqual(peer, store.ref) || peer.ProductionReady {
		return fmt.Errorf("formal-glm registered Phase20 relay store: peer epoch mismatch")
	}
	lock, err := store.acquireRelayLockV1()
	if err != nil {
		return err
	}
	defer store.releaseRelayLockV1(lock)
	if err := store.validateScratchV1(); err != nil {
		return err
	}
	return store.commitAnchorV1(formalGLMRegisteredPhase20JobPeerBindFileV1,
		formalGLMRegisteredPhase20JobPeerBindKindV1)
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) touchLockedV1() error {
	if err := store.validateScratchV1(); err != nil {
		return err
	}
	if _, err := store.scratch.Lstat("abort"); err == nil {
		return fmt.Errorf("formal-glm registered Phase20 relay store: worker epoch closed")
	} else if !os.IsNotExist(err) {
		return err
	}
	now := time.Now()
	if err := store.scratch.Chtimes("exchange.hb", now, now); err != nil {
		return err
	}
	return store.validateScratchV1()
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) failStateLockedV1(
	state *formalGLMRegisteredPhase20JobRelayStateV1,
) error {
	if state.State == formalGLMRegisteredPhase20JobFailedClosedV1 {
		return nil
	}
	state.State = formalGLMRegisteredPhase20JobFailedClosedV1
	return store.commitRelayStateLockedV1(state)
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) failClosedLockedV1(
	state *formalGLMRegisteredPhase20JobRelayStateV1, cause error,
) error {
	if err := store.commitAnchorV1(formalGLMRegisteredPhase20JobRelayFailedFileV1,
		formalGLMRegisteredPhase20JobRelayFailedKindV1); err != nil {
		return err
	}
	if err := formalGLMRegisteredPhase20JobTransportSignalAbortV1(
		store.scratch); err != nil {
		return err
	}
	if err := store.failStateLockedV1(state); err != nil {
		return err
	}
	return cause
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) offerPayloadLockedV1(
	offer *formalGLMRegisteredPhase20JobRelayRangeV1,
) ([]byte, error) {
	segments, err := store.listSegmentsV1(1)
	if err != nil {
		return nil, err
	}
	var selected *exactGCSegment
	for index := range segments {
		if segments[index].start <= offer.Start && segments[index].end >= offer.End {
			selected = &segments[index]
			break
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("formal-glm registered Phase20 relay store: outbound gap")
	}
	file, err := exactGCOpenVerifiedSegment(*selected)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, offer.End-offer.Start)
	n, readErr := file.ReadAt(payload, offer.Start-selected.start)
	closeErr := file.Close()
	if n != len(payload) || readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil {
		clear(payload)
		return nil, fmt.Errorf("formal-glm registered Phase20 relay store: truncated offer")
	}
	digest := sha256.Sum256(payload)
	if offer.PayloadSHA256 != "" &&
		hex.EncodeToString(digest[:]) != offer.PayloadSHA256 ||
		store.validateScratchV1() != nil {
		clear(payload)
		return nil, fmt.Errorf("formal-glm registered Phase20 relay store: changed offer")
	}
	return payload, nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) Poll(
	ref formalGLMRegisteredPhase20JobRefV1, ack int64,
) (formalGLMRegisteredPhase20JobPollResultV1, error) {
	var zero formalGLMRegisteredPhase20JobPollResultV1
	if store == nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 relay store: unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return zero, fmt.Errorf("formal-glm registered Phase20 relay store: closed")
	}
	if !reflect.DeepEqual(ref, store.ref) || ref.ProductionReady {
		return zero, fmt.Errorf("formal-glm registered Phase20 relay store: JobRef mismatch")
	}
	lock, err := store.acquireRelayLockV1()
	if err != nil {
		return zero, err
	}
	defer store.releaseRelayLockV1(lock)
	state, err := store.loadRelayStateLockedV1()
	if err != nil || store.reconcileStateLockedV1(&state) != nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 relay store: invalid durable state")
	}
	result := formalGLMRegisteredPhase20JobPollResultV1{
		State: state.State, AcceptedThrough: state.InboundAccepted,
		ProductionReady: false,
	}
	if state.State == formalGLMRegisteredPhase20JobFailedClosedV1 {
		return result, nil
	}
	if err := store.peerBoundLockedV1(); err != nil {
		return zero, err
	}
	if err := store.touchLockedV1(); err != nil {
		return zero, err
	}
	if ack != state.OutboundAck {
		if state.LastOffer == nil || ack != state.LastOffer.End {
			return zero, store.failClosedLockedV1(&state,
				errors.New("formal-glm registered Phase20 relay store: non-exact ack"))
		}
		if err := store.writeOffsetLockedV1("outbound.ack", ack); err != nil {
			return zero, err
		}
		state.OutboundAck = ack
		state.LastOffer = nil
		if err := store.commitRelayStateLockedV1(&state); err != nil {
			return zero, err
		}
		if err := store.cleanupSegmentsLockedV1(1, ack); err != nil {
			return zero, err
		}
	}
	if state.LastOffer == nil {
		head, err := store.readOffsetLockedV1("outbound.head")
		if err != nil || head < state.OutboundAck {
			return zero, store.failClosedLockedV1(&state,
				errors.New("formal-glm registered Phase20 relay store: invalid outbound head"))
		}
		if head == state.OutboundAck {
			result.AcceptedThrough = state.InboundAccepted
			return result, nil
		}
		segments, err := store.listSegmentsV1(1)
		if err != nil {
			return zero, err
		}
		var selected *exactGCSegment
		for index := range segments {
			if segments[index].start <= state.OutboundAck &&
				segments[index].end > state.OutboundAck {
				selected = &segments[index]
				break
			}
		}
		if selected == nil {
			return zero, store.failClosedLockedV1(&state,
				errors.New("formal-glm registered Phase20 relay store: outbound gap"))
		}
		end := selected.end
		if end > head {
			end = head
		}
		if end-state.OutboundAck > formalGLMRegisteredPhase20JobRelayMaxPayloadV1 {
			end = state.OutboundAck + formalGLMRegisteredPhase20JobRelayMaxPayloadV1
		}
		candidate := &formalGLMRegisteredPhase20JobRelayRangeV1{
			Start: state.OutboundAck, End: end,
		}
		payload, err := store.offerPayloadLockedV1(candidate)
		if err != nil {
			return zero, store.failClosedLockedV1(&state, err)
		}
		digest := sha256.Sum256(payload)
		candidate.PayloadSHA256 = hex.EncodeToString(digest[:])
		state.LastOffer = candidate
		if err := store.commitRelayStateLockedV1(&state); err != nil {
			clear(payload)
			return zero, err
		}
		result.RelayChunk = &formalGLMRegisteredPhase20RelayChunkV1{
			JobSHA256:       store.ref.JobSHA256,
			TransportSHA256: store.ref.TransportSHA256,
			Offset:          candidate.Start, PayloadSHA256: candidate.PayloadSHA256,
			Payload: payload,
		}
		return result, nil
	}
	payload, err := store.offerPayloadLockedV1(state.LastOffer)
	if err != nil {
		return zero, store.failClosedLockedV1(&state, err)
	}
	result.RelayChunk = &formalGLMRegisteredPhase20RelayChunkV1{
		JobSHA256:       store.ref.JobSHA256,
		TransportSHA256: store.ref.TransportSHA256,
		Offset:          state.LastOffer.Start, PayloadSHA256: state.LastOffer.PayloadSHA256,
		Payload: payload,
	}
	return result, nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) Relay(
	ref formalGLMRegisteredPhase20JobRefV1,
	chunk formalGLMRegisteredPhase20RelayChunkV1,
) (int64, error) {
	if store == nil {
		return 0, fmt.Errorf("formal-glm registered Phase20 relay store: unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return 0, fmt.Errorf("formal-glm registered Phase20 relay store: closed")
	}
	digest := sha256.Sum256(chunk.Payload)
	end := chunk.Offset + int64(len(chunk.Payload))
	if !reflect.DeepEqual(ref, store.ref) || ref.ProductionReady ||
		chunk.JobSHA256 != store.ref.JobSHA256 ||
		chunk.TransportSHA256 != store.ref.TransportSHA256 || chunk.Offset < 0 ||
		len(chunk.Payload) == 0 ||
		len(chunk.Payload) > formalGLMRegisteredPhase20JobRelayMaxPayloadV1 ||
		end < chunk.Offset || end > exactGCMaxAbsoluteOffset ||
		chunk.PayloadSHA256 != hex.EncodeToString(digest[:]) {
		return 0, fmt.Errorf("formal-glm registered Phase20 relay store: invalid relay identity")
	}
	lock, err := store.acquireRelayLockV1()
	if err != nil {
		return 0, err
	}
	defer store.releaseRelayLockV1(lock)
	state, err := store.loadRelayStateLockedV1()
	if err != nil || store.reconcileStateLockedV1(&state) != nil ||
		state.State == formalGLMRegisteredPhase20JobFailedClosedV1 {
		return 0, fmt.Errorf("formal-glm registered Phase20 relay store: epoch unavailable")
	}
	if err := store.peerBoundLockedV1(); err != nil {
		return 0, err
	}
	want := formalGLMRegisteredPhase20JobRelayRangeFromChunkV1(chunk)
	if chunk.Offset < state.InboundAccepted {
		if state.LastInbound != nil && reflect.DeepEqual(state.LastInbound, want) {
			return state.InboundAccepted, nil
		}
		return 0, store.failClosedLockedV1(&state,
			errors.New("formal-glm registered Phase20 relay store: overlap or fork"))
	}
	if chunk.Offset != state.InboundAccepted ||
		state.PendingInbound != nil && !reflect.DeepEqual(state.PendingInbound, want) {
		return 0, store.failClosedLockedV1(&state,
			errors.New("formal-glm registered Phase20 relay store: gap or pending fork"))
	}
	if err := store.touchLockedV1(); err != nil {
		return 0, err
	}
	if state.PendingInbound == nil {
		segments, err := store.listSegmentsV1(0)
		retained, sizeErr := exactGCSegmentBytes(segments)
		if err != nil || sizeErr != nil {
			return 0, fmt.Errorf("formal-glm registered Phase20 relay store: invalid inbound segments")
		}
		if retained > formalGLMRegisteredPhase20JobSpoolBytesV1 {
			return 0, store.failClosedLockedV1(&state,
				errors.New("formal-glm registered Phase20 relay store: inbound bound exceeded"))
		}
		for _, segment := range segments {
			if segment.start < end && segment.end > chunk.Offset {
				return 0, store.failClosedLockedV1(&state,
					errors.New("formal-glm registered Phase20 relay store: orphan inbound segment"))
			}
		}
		if int64(len(chunk.Payload)) >
			formalGLMRegisteredPhase20JobSpoolBytesV1-retained {
			return 0, fmt.Errorf("formal-glm registered Phase20 relay store: backpressure")
		}
		state.PendingInbound = want
		if err := store.commitRelayStateLockedV1(&state); err != nil {
			return 0, err
		}
	}
	inboundAck, err := store.readOffsetLockedV1("inbound.ack")
	if err != nil {
		return 0, err
	}
	if inboundAck < end {
		if err := store.publishInboundLockedV1(chunk); err != nil {
			return 0, err
		}
		if err := store.validateScratchV1(); err != nil {
			return 0, err
		}
	} else if inboundAck != end {
		return 0, store.failClosedLockedV1(&state,
			errors.New("formal-glm registered Phase20 relay store: invalid consumed prefix"))
	}
	state.InboundAccepted = end
	state.LastInbound = want
	state.PendingInbound = nil
	if err := store.commitRelayStateLockedV1(&state); err != nil {
		return 0, err
	}
	return end, nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) CloseRelayV1() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	clear(store.macKey[:])
	var first error
	for index := range store.segmentRoots {
		if store.segmentRoots[index] != nil {
			if err := store.segmentRoots[index].Close(); err != nil && first == nil {
				first = err
			}
			store.segmentRoots[index] = nil
		}
	}
	if store.scratch != nil {
		if err := store.scratch.Close(); err != nil && first == nil {
			first = err
		}
		store.scratch = nil
	}
	return first
}
