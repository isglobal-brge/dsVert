package main

// Non-production, owner-only byte transport for one registered job epoch.
// Attempt negotiation, terminal decisions and compute remain outside this cut.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"
)

const (
	formalGLMRegisteredPhase20JobTransportVersionV1 = "dsvert-formal-glm-registered-phase20-job-transport-v1"
	formalGLMRegisteredPhase20JobTransportPurposeV1 = "formal_glm_registered_phase20_opaque_job_transport_v1"
	formalGLMRegisteredPhase20JobTransportDomainV1  = "dsVert/formal-glm/registered-phase20/job-transport/v1"
	formalGLMRegisteredPhase20JobTransportDirV1     = "registered-phase20-job-transport-v1"
	formalGLMRegisteredPhase20JobTransportBurnV1    = "burn.json"

	formalGLMRegisteredPhase20JobNegotiatingV1    = "negotiating"
	formalGLMRegisteredPhase20JobRunningV1        = "running"
	formalGLMRegisteredPhase20JobAbandonPendingV1 = "abandon_pending"
	formalGLMRegisteredPhase20JobAbandonedV1      = "abandoned"
	formalGLMRegisteredPhase20JobEvidenceSealedV1 = "evidence_sealed"
	formalGLMRegisteredPhase20JobPreparedV1       = "prepared"
	formalGLMRegisteredPhase20JobSelectVotedV1    = "select_voted"
	formalGLMRegisteredPhase20JobSelectedV1       = "selected"
	formalGLMRegisteredPhase20JobFailedClosedV1   = "failed_closed"

	formalGLMRegisteredPhase20JobRunTransportV1     = "run"
	formalGLMRegisteredPhase20JobAbandonTransportV1 = "abandon"
	formalGLMRegisteredPhase20JobRelayMaxPayloadV1  = 1 << 20
	formalGLMRegisteredPhase20JobSpoolBytesV1       = int64(16 << 20)
	formalGLMRegisteredPhase20JobHeartbeatTTLV1     = 2 * time.Minute
)

type formalGLMRegisteredPhase20JobStartV1 struct {
	ArtifactID       string `json:"artifact_id"`
	ReceiptSetSHA256 string `json:"receipt_set_sha256"`
}

type formalGLMRegisteredPhase20JobRefV1 struct {
	ArtifactID       string `json:"artifact_id"`
	ReceiptSetSHA256 string `json:"receipt_set_sha256"`
	AttemptID        string `json:"attempt_id"`
	JobSHA256        string `json:"job_sha256"`
	TransportSHA256  string `json:"transport_sha256"`
	ProductionReady  bool   `json:"production_ready"`
}

type formalGLMRegisteredPhase20RelayChunkV1 struct {
	JobSHA256       string `json:"job_sha256"`
	TransportSHA256 string `json:"transport_sha256"`
	Offset          int64  `json:"offset"`
	PayloadSHA256   string `json:"payload_sha256"`
	Payload         []byte `json:"payload"`
}

type formalGLMRegisteredPhase20JobPollResultV1 struct {
	State           string                                  `json:"state"`
	AcceptedThrough int64                                   `json:"accepted_through"`
	RelayChunk      *formalGLMRegisteredPhase20RelayChunkV1 `json:"relay_chunk,omitempty"`
	ProductionReady bool                                    `json:"production_ready"`
}

// A2 constructs this only from an already validated registered binding.
type formalGLMRegisteredPhase20JobTransportBindingV1 struct {
	ArtifactID          string
	ReceiptSetSHA256    string
	SemanticRootSHA256  string
	BindingRecordSHA256 string
	AttemptID           string
	ScheduleRootSHA256  string
	ProductionReady     bool
}

// BasisSHA256 is a common signed/durable epoch preimage chosen by A2. It is
// never a local counter. A changed durable basis creates a new immutable slot.
type formalGLMRegisteredPhase20JobTransportEpochV1 struct {
	Mode        string
	BasisSHA256 string
}

type formalGLMRegisteredPhase20JobTransportBurnRecordV1 struct {
	Version          string `json:"version"`
	Purpose          string `json:"purpose"`
	ArtifactID       string `json:"artifact_id"`
	ReceiptSetSHA256 string `json:"receipt_set_sha256"`
	AttemptID        string `json:"attempt_id"`
	JobSHA256        string `json:"job_sha256"`
	TransportSHA256  string `json:"transport_sha256"`
	Mode             string `json:"mode"`
	BasisSHA256      string `json:"basis_sha256"`
	ProductionReady  bool   `json:"production_ready"`
}

type formalGLMRegisteredPhase20JobRelayReceiptV1 struct {
	start         int64
	end           int64
	payloadSHA256 string
}

// All fields are private: the root, epoch and spool never serialize.
type formalGLMRegisteredPhase20JobTransportV1 struct {
	mu        sync.Mutex
	ops       sync.WaitGroup
	activeOps int

	ref             formalGLMRegisteredPhase20JobRefV1
	epochSHA256     string
	state           string
	peerEpochBound  bool
	scratch         *os.Root
	segmentRoots    [2]*os.Root
	scratchPath     string
	spool           *exactGCSpoolRW
	inboundAccepted int64
	lastInbound     *formalGLMRegisteredPhase20JobRelayReceiptV1
	outboundAck     int64
	lastOffer       *formalGLMRegisteredPhase20RelayChunkV1
	closed          bool
	closeDone       chan struct{}
	closeErr        error
}

func formalGLMRegisteredPhase20JobTransportIdentityV1(
	binding formalGLMRegisteredPhase20JobTransportBindingV1,
	epoch formalGLMRegisteredPhase20JobTransportEpochV1,
) (jobSHA256, transportSHA256 string, err error) {
	for _, value := range []string{
		binding.ArtifactID, binding.ReceiptSetSHA256, binding.SemanticRootSHA256,
		binding.BindingRecordSHA256, binding.AttemptID, binding.ScheduleRootSHA256,
		epoch.BasisSHA256,
	} {
		if !formalGLMIsSHA256(value) {
			return "", "", fmt.Errorf("formal-glm registered Phase20 transport: invalid identity")
		}
	}
	if binding.ProductionReady ||
		(epoch.Mode != formalGLMRegisteredPhase20JobRunTransportV1 &&
			epoch.Mode != formalGLMRegisteredPhase20JobAbandonTransportV1) {
		return "", "", fmt.Errorf("formal-glm registered Phase20 transport: invalid epoch")
	}
	jobSHA256, err = formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase20JobTransportDomainV1+"/job", binding)
	if err != nil {
		return "", "", err
	}
	transportSHA256, err = formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase20JobTransportDomainV1+"/epoch", struct {
			Binding formalGLMRegisteredPhase20JobTransportBindingV1 `json:"binding"`
			Epoch   formalGLMRegisteredPhase20JobTransportEpochV1   `json:"epoch"`
		}{binding, epoch})
	return jobSHA256, transportSHA256, err
}

func formalGLMRegisteredPhase20JobTransportBuildBurnRecordV1(
	binding formalGLMRegisteredPhase20JobTransportBindingV1,
	epoch formalGLMRegisteredPhase20JobTransportEpochV1,
	jobSHA256, transportSHA256 string,
) formalGLMRegisteredPhase20JobTransportBurnRecordV1 {
	return formalGLMRegisteredPhase20JobTransportBurnRecordV1{
		Version:    formalGLMRegisteredPhase20JobTransportVersionV1,
		Purpose:    formalGLMRegisteredPhase20JobTransportPurposeV1,
		ArtifactID: binding.ArtifactID, ReceiptSetSHA256: binding.ReceiptSetSHA256,
		AttemptID: binding.AttemptID, JobSHA256: jobSHA256,
		TransportSHA256: transportSHA256, Mode: epoch.Mode,
		BasisSHA256: epoch.BasisSHA256, ProductionReady: false,
	}
}

func formalGLMRegisteredPhase20JobTransportRelativeV1(
	attemptRelative string, transportSHA256 string,
) (string, error) {
	if attemptRelative == "" || filepath.IsAbs(attemptRelative) ||
		filepath.Clean(attemptRelative) != attemptRelative ||
		!formalGLMIsSHA256(transportSHA256) {
		return "", fmt.Errorf("formal-glm registered Phase20 transport: invalid rooted slot")
	}
	return filepath.Join(attemptRelative,
		formalGLMRegisteredPhase20JobTransportDirV1,
		"transport-"+transportSHA256), nil
}

func formalGLMRegisteredPhase20JobTransportBurnedV1(
	root *os.Root,
	attemptRelative string,
	binding formalGLMRegisteredPhase20JobTransportBindingV1,
	epoch formalGLMRegisteredPhase20JobTransportEpochV1,
) (bool, error) {
	jobSHA256, transportSHA256, err :=
		formalGLMRegisteredPhase20JobTransportIdentityV1(binding, epoch)
	if err != nil {
		return false, err
	}
	relative, err := formalGLMRegisteredPhase20JobTransportRelativeV1(
		attemptRelative, transportSHA256)
	if err != nil {
		return false, err
	}
	info, err := root.Lstat(relative)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o700 ||
		!formalFinalizerHandoffPrivateOwnedDirectory(info) {
		return false, fmt.Errorf("formal-glm registered Phase20 transport: unsafe burn slot")
	}
	marker := filepath.Join(relative, formalGLMRegisteredPhase20JobTransportBurnV1)
	markerInfo, markerErr := root.Lstat(marker)
	if os.IsNotExist(markerErr) {
		// A synced private slot also burns the epoch if a crash preceded marker CAS.
		return true, nil
	}
	if markerErr != nil || !markerInfo.Mode().IsRegular() ||
		markerInfo.Mode()&os.ModeSymlink != 0 || markerInfo.Mode().Perm() != 0o600 ||
		!exactGCPrivateOwnedRegular(markerInfo) {
		return false, fmt.Errorf("formal-glm registered Phase20 transport: unsafe burn marker")
	}
	encoded, err := formalGLMPhase21RootReadRecord(root, marker, 1<<20)
	if err != nil {
		return false, err
	}
	want := formalGLMRegisteredPhase20JobTransportBuildBurnRecordV1(
		binding, epoch, jobSHA256, transportSHA256)
	canonical, marshalErr := json.Marshal(want)
	var got formalGLMRegisteredPhase20JobTransportBurnRecordV1
	if marshalErr != nil || formalGLMPhase21RockStrictDecode(encoded, &got) != nil ||
		!bytes.Equal(encoded, canonical) || !reflect.DeepEqual(got, want) ||
		got.ProductionReady {
		return false, fmt.Errorf("formal-glm registered Phase20 transport: invalid burn marker")
	}
	return true, nil
}

func formalGLMRegisteredPhase20JobTransportWriteInitialV1(
	root *os.Root, name string, data []byte,
) error {
	file, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err = file.Chmod(0o600); err == nil {
		err = exactGCWriteFull(file, data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func formalGLMRegisteredPhase20JobTransportValidateRootV1(
	root *os.Root, absolute string,
) error {
	if root == nil || !filepath.IsAbs(absolute) || filepath.Clean(absolute) != absolute {
		return fmt.Errorf("formal-glm registered Phase20 transport: invalid scratch")
	}
	rootInfo, rootErr := root.Stat(".")
	pathInfo, pathErr := os.Lstat(absolute)
	if rootErr != nil || pathErr != nil || !rootInfo.IsDir() || !pathInfo.IsDir() ||
		rootInfo.Mode().Perm() != 0o700 || pathInfo.Mode().Perm() != 0o700 ||
		!os.SameFile(rootInfo, pathInfo) ||
		!formalFinalizerHandoffPrivateOwnedDirectory(rootInfo) ||
		!formalFinalizerHandoffPrivateOwnedDirectory(pathInfo) {
		return fmt.Errorf("formal-glm registered Phase20 transport: scratch inode changed")
	}
	return nil
}

func formalGLMRegisteredPhase20JobTransportValidateScratchV1(
	root *os.Root, absolute string, segmentRoots [2]*os.Root,
) error {
	if err := formalGLMRegisteredPhase20JobTransportValidateRootV1(
		root, absolute); err != nil {
		return err
	}
	for _, name := range []string{
		formalGLMRegisteredPhase20JobTransportBurnV1,
		"inbound.bin", "outbound.bin", "exchange.hb", "worker.hb",
		"inbound.state", "inbound.ack", "outbound.head", "outbound.ack",
	} {
		info, err := root.Lstat(name)
		if err != nil || !info.Mode().IsRegular() ||
			info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
			!exactGCPrivateOwnedRegular(info) {
			return fmt.Errorf("formal-glm registered Phase20 transport: unsafe scratch file")
		}
	}
	for index, name := range []string{"inbound.segments", "outbound.segments"} {
		info, pathErr := root.Lstat(name)
		var pinned os.FileInfo
		var pinErr error
		if segmentRoots[index] != nil {
			pinned, pinErr = segmentRoots[index].Stat(".")
		}
		if pathErr != nil || pinErr != nil || info == nil || !info.IsDir() ||
			info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm() != 0o700 ||
			!formalFinalizerHandoffPrivateOwnedDirectory(info) || pinned == nil ||
			!os.SameFile(info, pinned) {
			return fmt.Errorf("formal-glm registered Phase20 transport: unsafe segment directory")
		}
		directory, err := root.Open(name)
		if err != nil {
			return err
		}
		entries, readErr := directory.ReadDir(-1)
		closeErr := directory.Close()
		if readErr != nil || closeErr != nil {
			if readErr != nil {
				return readErr
			}
			return closeErr
		}
		for _, entry := range entries {
			entryInfo, err := entry.Info()
			if os.IsNotExist(err) {
				continue
			}
			if err != nil || !entryInfo.Mode().IsRegular() ||
				entryInfo.Mode()&os.ModeSymlink != 0 ||
				entryInfo.Mode().Perm() != 0o600 ||
				!exactGCPrivateOwnedRegular(entryInfo) {
				return fmt.Errorf("formal-glm registered Phase20 transport: unsafe segment file")
			}
		}
	}
	if info, err := root.Lstat("abort"); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm() != 0o600 || info.Size() != 1 ||
			!exactGCPrivateOwnedRegular(info) {
			return fmt.Errorf("formal-glm registered Phase20 transport: unsafe abort marker")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func newFormalGLMRegisteredPhase20JobTransportV1(
	root *os.Root,
	attemptRelative string,
	binding formalGLMRegisteredPhase20JobTransportBindingV1,
	epoch formalGLMRegisteredPhase20JobTransportEpochV1,
) (*formalGLMRegisteredPhase20JobTransportV1, error) {
	jobSHA256, transportSHA256, err :=
		formalGLMRegisteredPhase20JobTransportIdentityV1(binding, epoch)
	if err != nil {
		return nil, err
	}
	relative, err := formalGLMRegisteredPhase20JobTransportRelativeV1(
		attemptRelative, transportSHA256)
	if err != nil {
		return nil, err
	}
	base := filepath.Dir(relative)
	if root == nil ||
		formalGLMRegisteredPhase18TicketStoreEnsureDirV1(root, base) != nil {
		return nil, fmt.Errorf("formal-glm registered Phase20 transport: unavailable Rock root")
	}
	if err := root.Mkdir(relative, 0o700); err != nil {
		return nil, fmt.Errorf("formal-glm registered Phase20 transport: epoch already burned")
	}
	if err := root.Chmod(relative, 0o700); err != nil {
		return nil, err
	}
	if err := formalGLMPhase21RootSyncDir(root, filepath.Join(base, "entry")); err != nil {
		return nil, err
	}
	burn := formalGLMRegisteredPhase20JobTransportBuildBurnRecordV1(
		binding, epoch, jobSHA256, transportSHA256)
	encoded, err := json.Marshal(burn)
	if err != nil {
		return nil, err
	}
	created, err := formalGLMPhase21RootCreateRecord(root,
		filepath.Join(relative, formalGLMRegisteredPhase20JobTransportBurnV1), encoded)
	if err != nil || !created {
		return nil, fmt.Errorf("formal-glm registered Phase20 transport: burn marker failed")
	}
	scratch, err := root.OpenRoot(relative)
	if err != nil {
		return nil, err
	}
	absolute := scratch.Name()
	var segmentRoots [2]*os.Root
	fail := func(err error) (*formalGLMRegisteredPhase20JobTransportV1, error) {
		for _, segmentRoot := range segmentRoots {
			if segmentRoot != nil {
				_ = segmentRoot.Close()
			}
		}
		_ = scratch.Close()
		return nil, err
	}
	if err := formalGLMRegisteredPhase20JobTransportValidateRootV1(
		scratch, absolute); err != nil {
		return fail(err)
	}
	files := []struct {
		name string
		data []byte
	}{
		{"inbound.bin", nil}, {"outbound.bin", nil},
		{"exchange.hb", []byte(".")}, {"worker.hb", []byte(".")},
		{"inbound.state", []byte(exactGCInboundStateInitial)},
		{"inbound.ack", []byte("0")}, {"outbound.head", []byte("0")},
		{"outbound.ack", []byte("0")},
	}
	for _, file := range files {
		if err := formalGLMRegisteredPhase20JobTransportWriteInitialV1(
			scratch, file.name, file.data); err != nil {
			return fail(err)
		}
	}
	for _, directory := range []string{"inbound.segments", "outbound.segments"} {
		if err := scratch.Mkdir(directory, 0o700); err != nil {
			return fail(err)
		}
		if err := scratch.Chmod(directory, 0o700); err != nil {
			return fail(err)
		}
	}
	for index, directory := range []string{"inbound.segments", "outbound.segments"} {
		segmentRoots[index], err = scratch.OpenRoot(directory)
		if err != nil {
			return fail(err)
		}
	}
	if err := formalGLMPhase21RootSyncDir(scratch, "state"); err != nil {
		return fail(err)
	}
	if err := formalGLMRegisteredPhase20JobTransportValidateScratchV1(
		scratch, absolute, segmentRoots); err != nil {
		return fail(err)
	}
	if err := exactGCPrepareWorkerSpool(absolute); err != nil {
		return fail(err)
	}
	spool, err := newExactGCSpoolRW(absolute,
		formalGLMRegisteredPhase20JobSpoolBytesV1,
		formalGLMRegisteredPhase20JobHeartbeatTTLV1)
	if err != nil {
		return fail(err)
	}
	return &formalGLMRegisteredPhase20JobTransportV1{
		ref: formalGLMRegisteredPhase20JobRefV1{
			ArtifactID: binding.ArtifactID, ReceiptSetSHA256: binding.ReceiptSetSHA256,
			AttemptID: binding.AttemptID, JobSHA256: jobSHA256,
			TransportSHA256: transportSHA256, ProductionReady: false,
		},
		epochSHA256: transportSHA256,
		state:       formalGLMRegisteredPhase20JobNegotiatingV1,
		scratch:     scratch, segmentRoots: segmentRoots,
		scratchPath: absolute, spool: spool, closeDone: make(chan struct{}),
	}, nil
}

func formalGLMRegisteredPhase20JobTransportAbortValidV1(root *os.Root) bool {
	before, err := root.Lstat("abort")
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Mode().Perm() != 0o600 || before.Size() != 1 ||
		!exactGCPrivateOwnedRegular(before) {
		return false
	}
	data, err := root.ReadFile("abort")
	after, afterErr := root.Lstat("abort")
	return err == nil && afterErr == nil && bytes.Equal(data, []byte("1")) &&
		os.SameFile(before, after) && exactGCPrivateOwnedRegular(after)
}

func formalGLMRegisteredPhase20JobTransportSignalAbortV1(root *os.Root) error {
	for attempt := 0; attempt < 2; attempt++ {
		if formalGLMRegisteredPhase20JobTransportAbortValidV1(root) {
			return nil
		}
		if err := root.Remove("abort"); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := formalGLMRegisteredPhase20JobTransportWriteInitialV1(
			root, "abort", []byte("1")); err != nil {
			if os.IsExist(err) {
				continue
			}
			return err
		}
		if err := formalGLMPhase21RootSyncDir(root, "abort"); err != nil {
			return err
		}
	}
	if !formalGLMRegisteredPhase20JobTransportAbortValidV1(root) {
		return fmt.Errorf("formal-glm registered Phase20 transport: unsafe abort marker")
	}
	return nil
}

func (transport *formalGLMRegisteredPhase20JobTransportV1) failLockedV1() {
	if transport.closed {
		return
	}
	transport.state = formalGLMRegisteredPhase20JobFailedClosedV1
	if transport.scratch != nil {
		_ = formalGLMRegisteredPhase20JobTransportSignalAbortV1(transport.scratch)
	}
}

// A2 calls this only after comparing the two refs through authenticated
// control. No worker or Relay byte is accepted before the common epoch binds.
func (transport *formalGLMRegisteredPhase20JobTransportV1) BindPeerEpochV1(
	peerEpochSHA256 string,
) error {
	if transport == nil {
		return fmt.Errorf("formal-glm registered Phase20 transport: unavailable")
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.closed || transport.state == formalGLMRegisteredPhase20JobFailedClosedV1 ||
		peerEpochSHA256 != transport.epochSHA256 {
		transport.failLockedV1()
		return fmt.Errorf("formal-glm registered Phase20 transport: peer epoch mismatch")
	}
	transport.peerEpochBound = true
	return nil
}

func (transport *formalGLMRegisteredPhase20JobTransportV1) validatePeerEpochV1(
	peerEpochSHA256 string,
) error {
	return transport.BindPeerEpochV1(peerEpochSHA256)
}

func (transport *formalGLMRegisteredPhase20JobTransportV1) beginOpV1() error {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.closed || !transport.peerEpochBound ||
		transport.state == formalGLMRegisteredPhase20JobFailedClosedV1 {
		return fmt.Errorf("formal-glm registered Phase20 transport: epoch is not bound")
	}
	if err := formalGLMRegisteredPhase20JobTransportValidateScratchV1(
		transport.scratch, transport.scratchPath, transport.segmentRoots); err != nil {
		return err
	}
	transport.activeOps++
	transport.ops.Add(1)
	return nil
}

func (transport *formalGLMRegisteredPhase20JobTransportV1) endOpV1() {
	transport.mu.Lock()
	transport.activeOps--
	transport.mu.Unlock()
	transport.ops.Done()
}

func (transport *formalGLMRegisteredPhase20JobTransportV1) afterPathV1(
	operationErr error,
) error {
	validationErr := formalGLMRegisteredPhase20JobTransportValidateScratchV1(
		transport.scratch, transport.scratchPath, transport.segmentRoots)
	if operationErr != nil {
		return operationErr
	}
	return validationErr
}

func (transport *formalGLMRegisteredPhase20JobTransportV1) Read(p []byte) (int, error) {
	if err := transport.beginOpV1(); err != nil {
		return 0, err
	}
	defer transport.endOpV1()
	n, err := transport.spool.Read(p)
	return n, transport.afterPathV1(err)
}

func (transport *formalGLMRegisteredPhase20JobTransportV1) Write(p []byte) (int, error) {
	if err := transport.beginOpV1(); err != nil {
		return 0, err
	}
	defer transport.endOpV1()
	n, err := transport.spool.Write(p)
	return n, transport.afterPathV1(err)
}

func (transport *formalGLMRegisteredPhase20JobTransportV1) Flush() error {
	if err := transport.beginOpV1(); err != nil {
		return err
	}
	defer transport.endOpV1()
	return transport.afterPathV1(transport.spool.Flush())
}

// Poll must not wait for writeMu: a backpressured writer holds it until Poll
// acknowledges already-durable segments. Pending bytes are flushed only when
// the writer is not active; otherwise Poll offers the durable head as-is.
func (transport *formalGLMRegisteredPhase20JobTransportV1) tryFlushLockedV1() error {
	if !transport.spool.writeMu.TryLock() {
		return nil
	}
	err := transport.spool.flushOutboundLocked()
	transport.spool.writeMu.Unlock()
	return transport.afterPathV1(err)
}

func formalGLMRegisteredPhase20JobTransportCloneChunkV1(
	chunk *formalGLMRegisteredPhase20RelayChunkV1,
) *formalGLMRegisteredPhase20RelayChunkV1 {
	if chunk == nil {
		return nil
	}
	cloned := *chunk
	cloned.Payload = append([]byte(nil), chunk.Payload...)
	return &cloned
}

func (transport *formalGLMRegisteredPhase20JobTransportV1) touchLockedV1() error {
	if err := formalGLMRegisteredPhase20JobTransportValidateScratchV1(
		transport.scratch, transport.scratchPath, transport.segmentRoots); err != nil {
		return err
	}
	now := time.Now()
	return transport.scratch.Chtimes("exchange.hb", now, now)
}

func (transport *formalGLMRegisteredPhase20JobTransportV1) Poll(
	ack int64,
) (formalGLMRegisteredPhase20JobPollResultV1, error) {
	var zero formalGLMRegisteredPhase20JobPollResultV1
	if transport == nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 transport: unavailable")
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	result := formalGLMRegisteredPhase20JobPollResultV1{
		State: transport.state, AcceptedThrough: transport.inboundAccepted,
		ProductionReady: false,
	}
	if transport.closed || transport.state == formalGLMRegisteredPhase20JobFailedClosedV1 {
		return result, nil
	}
	if !transport.peerEpochBound {
		return zero, fmt.Errorf("formal-glm registered Phase20 transport: peer epoch is not bound")
	}
	if ack != transport.outboundAck {
		if transport.lastOffer == nil ||
			ack != transport.lastOffer.Offset+int64(len(transport.lastOffer.Payload)) {
			return zero, fmt.Errorf("formal-glm registered Phase20 transport: non-exact ack")
		}
		if err := transport.touchLockedV1(); err != nil {
			transport.failLockedV1()
			return zero, err
		}
		if err := transport.afterPathV1(exactGCWriteOffset(
			filepath.Join(transport.scratchPath, "outbound.ack"), ack)); err != nil {
			transport.failLockedV1()
			return zero, err
		}
		segments, err := exactGCListSegments(
			filepath.Join(transport.scratchPath, "outbound.segments"))
		err = transport.afterPathV1(err)
		if err != nil {
			transport.failLockedV1()
			return zero, err
		}
		for _, segment := range segments {
			if segment.end <= ack {
				if err := os.Remove(segment.path); err != nil && !os.IsNotExist(err) {
					transport.failLockedV1()
					return zero, err
				}
			}
		}
		if err := transport.afterPathV1(nil); err != nil {
			transport.failLockedV1()
			return zero, err
		}
		transport.outboundAck, transport.lastOffer = ack, nil
	}
	if transport.lastOffer != nil {
		result.RelayChunk = formalGLMRegisteredPhase20JobTransportCloneChunkV1(
			transport.lastOffer)
		return result, nil
	}
	if err := transport.touchLockedV1(); err != nil {
		transport.failLockedV1()
		return zero, err
	}
	if err := transport.tryFlushLockedV1(); err != nil {
		transport.failLockedV1()
		return zero, err
	}
	head, err := exactGCReadOffset(filepath.Join(transport.scratchPath, "outbound.head"))
	err = transport.afterPathV1(err)
	if err != nil || head < transport.outboundAck {
		transport.failLockedV1()
		return zero, fmt.Errorf("formal-glm registered Phase20 transport: invalid head")
	}
	if head == transport.outboundAck {
		return result, nil
	}
	segments, err := exactGCListSegments(
		filepath.Join(transport.scratchPath, "outbound.segments"))
	err = transport.afterPathV1(err)
	if err != nil {
		transport.failLockedV1()
		return zero, err
	}
	var selected *exactGCSegment
	for index := range segments {
		if segments[index].start <= transport.outboundAck &&
			segments[index].end > transport.outboundAck {
			selected = &segments[index]
			break
		}
	}
	if selected == nil {
		transport.failLockedV1()
		return zero, fmt.Errorf("formal-glm registered Phase20 transport: outbound gap")
	}
	end := selected.end
	if end > head {
		end = head
	}
	if end-transport.outboundAck > formalGLMRegisteredPhase20JobRelayMaxPayloadV1 {
		end = transport.outboundAck + formalGLMRegisteredPhase20JobRelayMaxPayloadV1
	}
	payload := make([]byte, end-transport.outboundAck)
	file, err := exactGCOpenVerifiedSegment(*selected)
	if err == nil {
		var n int
		n, err = file.ReadAt(payload, transport.outboundAck-selected.start)
		_ = file.Close()
		if n != len(payload) {
			err = io.ErrUnexpectedEOF
		}
	}
	err = transport.afterPathV1(err)
	if err != nil && !errors.Is(err, io.EOF) {
		transport.failLockedV1()
		return zero, err
	}
	digest := sha256.Sum256(payload)
	transport.lastOffer = &formalGLMRegisteredPhase20RelayChunkV1{
		JobSHA256:       transport.ref.JobSHA256,
		TransportSHA256: transport.ref.TransportSHA256,
		Offset:          transport.outboundAck,
		PayloadSHA256:   hex.EncodeToString(digest[:]), Payload: payload,
	}
	result.RelayChunk = formalGLMRegisteredPhase20JobTransportCloneChunkV1(
		transport.lastOffer)
	return result, nil
}

func (transport *formalGLMRegisteredPhase20JobTransportV1) Relay(
	chunk formalGLMRegisteredPhase20RelayChunkV1,
) (int64, error) {
	if transport == nil {
		return 0, fmt.Errorf("formal-glm registered Phase20 transport: unavailable")
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.closed || !transport.peerEpochBound ||
		transport.state == formalGLMRegisteredPhase20JobFailedClosedV1 {
		return 0, fmt.Errorf("formal-glm registered Phase20 transport: epoch unavailable")
	}
	digest := sha256.Sum256(chunk.Payload)
	if chunk.JobSHA256 != transport.ref.JobSHA256 ||
		chunk.TransportSHA256 != transport.ref.TransportSHA256 || chunk.Offset < 0 ||
		len(chunk.Payload) == 0 ||
		len(chunk.Payload) > formalGLMRegisteredPhase20JobRelayMaxPayloadV1 ||
		chunk.PayloadSHA256 != hex.EncodeToString(digest[:]) {
		transport.failLockedV1()
		return 0, fmt.Errorf("formal-glm registered Phase20 transport: invalid Relay chunk")
	}
	end := chunk.Offset + int64(len(chunk.Payload))
	if end > exactGCMaxAbsoluteOffset || end < chunk.Offset {
		transport.failLockedV1()
		return 0, fmt.Errorf("formal-glm registered Phase20 transport: offset overflow")
	}
	if chunk.Offset < transport.inboundAccepted {
		receipt := transport.lastInbound
		if receipt != nil && receipt.start == chunk.Offset &&
			receipt.end == end && receipt.payloadSHA256 == chunk.PayloadSHA256 {
			return transport.inboundAccepted, nil
		}
		transport.failLockedV1()
		return 0, fmt.Errorf("formal-glm registered Phase20 transport: overlap or fork")
	}
	if chunk.Offset != transport.inboundAccepted {
		transport.failLockedV1()
		return 0, fmt.Errorf("formal-glm registered Phase20 transport: gap")
	}
	if err := transport.touchLockedV1(); err != nil {
		transport.failLockedV1()
		return 0, err
	}
	directory := filepath.Join(transport.scratchPath, "inbound.segments")
	segments, err := exactGCListSegments(directory)
	err = transport.afterPathV1(err)
	if err != nil {
		transport.failLockedV1()
		return 0, err
	}
	retained, err := exactGCSegmentBytes(segments)
	if err != nil || int64(len(chunk.Payload)) >
		formalGLMRegisteredPhase20JobSpoolBytesV1-retained {
		return 0, fmt.Errorf("formal-glm registered Phase20 transport: backpressure")
	}
	_, err = exactGCPublishSegment(directory, chunk.Offset, chunk.Payload)
	err = transport.afterPathV1(err)
	if err != nil {
		transport.failLockedV1()
		return 0, err
	}
	transport.lastInbound = &formalGLMRegisteredPhase20JobRelayReceiptV1{
		start: chunk.Offset, end: end, payloadSHA256: chunk.PayloadSHA256,
	}
	transport.inboundAccepted = end
	return end, nil
}

func (transport *formalGLMRegisteredPhase20JobTransportV1) setStateV1(
	state string,
) error {
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
	default:
		return fmt.Errorf("formal-glm registered Phase20 transport: invalid state")
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.closed {
		return fmt.Errorf("formal-glm registered Phase20 transport: closed")
	}
	if transport.state == formalGLMRegisteredPhase20JobFailedClosedV1 &&
		state != formalGLMRegisteredPhase20JobFailedClosedV1 {
		return fmt.Errorf("formal-glm registered Phase20 transport: failed state is absorbing")
	}
	if state == formalGLMRegisteredPhase20JobFailedClosedV1 {
		transport.failLockedV1()
		return nil
	}
	transport.state = state
	return nil
}

func (transport *formalGLMRegisteredPhase20JobTransportV1) Close() error {
	if transport == nil {
		return nil
	}
	transport.mu.Lock()
	if transport.closed {
		done := transport.closeDone
		transport.mu.Unlock()
		if done != nil {
			<-done
		}
		transport.mu.Lock()
		err := transport.closeErr
		transport.mu.Unlock()
		return err
	}
	if transport.closeDone == nil {
		transport.closeDone = make(chan struct{})
	}
	transport.closed = true
	abortErr := error(nil)
	if transport.scratch != nil {
		abortErr = formalGLMRegisteredPhase20JobTransportSignalAbortV1(
			transport.scratch)
	}
	transport.mu.Unlock()
	transport.ops.Wait()
	transport.mu.Lock()
	closeErr := abortErr
	if transport.spool != nil {
		if err := transport.spool.Close(); closeErr == nil {
			closeErr = err
		}
		transport.spool = nil
	}
	for index, segmentRoot := range transport.segmentRoots {
		if segmentRoot != nil {
			if err := segmentRoot.Close(); closeErr == nil {
				closeErr = err
			}
			transport.segmentRoots[index] = nil
		}
	}
	if transport.scratch != nil {
		if err := transport.scratch.Close(); closeErr == nil {
			closeErr = err
		}
		transport.scratch = nil
	}
	transport.closeErr = closeErr
	close(transport.closeDone)
	transport.mu.Unlock()
	return closeErr
}
