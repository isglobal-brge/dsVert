package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"sync"
	"syscall"
	"time"
)

const (
	formalGLMRegisteredPhase20JobWorkerVersionV1 = "dsvert-formal-glm-registered-phase20-job-worker-controller-v1"
	formalGLMRegisteredPhase20JobWorkerPurposeV1 = "formal_glm_registered_phase20_job_worker_controller_v1"
	formalGLMRegisteredPhase20JobWorkerDomainV1  = "dsVert/formal-glm/registered-phase20/job-worker-controller/v1"

	formalGLMRegisteredPhase20JobWorkerOwnerFileV1     = "worker-owner.json"
	formalGLMRegisteredPhase20JobWorkerReadyFileV1     = "worker-ready.json"
	formalGLMRegisteredPhase20JobWorkerHeartbeatFileV1 = "worker-controller.hb"
	formalGLMRegisteredPhase20JobWorkerExitFileV1      = "worker-owner-exit.json"
	formalGLMRegisteredPhase20JobWorkerAbortFileV1     = "worker-abort-request.json"
	formalGLMRegisteredPhase20JobWorkerRecordMaxV1     = int64(16 << 10)
	formalGLMRegisteredPhase20JobWorkerHeartbeatTTLV1  = 30 * time.Second

	formalGLMRegisteredPhase20JobWorkerReadyKindV1 = "worker_ready"
	formalGLMRegisteredPhase20JobWorkerExitKindV1  = "worker_exited"
	formalGLMRegisteredPhase20JobWorkerAbortKindV1 = "worker_abort_requested"

	formalGLMRegisteredPhase20JobWorkerStartingV1            = "starting"
	formalGLMRegisteredPhase20JobWorkerRunningV1             = "running"
	formalGLMRegisteredPhase20JobWorkerStalledV1             = "stalled"
	formalGLMRegisteredPhase20JobWorkerAbortRequestedV1      = "abort_requested"
	formalGLMRegisteredPhase20JobWorkerExitedV1              = "exited"
	formalGLMRegisteredPhase20JobWorkerOwnerLostV1           = "owner_lost"
	formalGLMRegisteredPhase20JobWorkerInvalidDurableStateV1 = "invalid_durable_state"
)

var errFormalGLMRegisteredPhase20JobWorkerOwnerLockBusyV1 = errors.New("formal-glm registered Phase20 worker controller: owner lock busy")

type formalGLMRegisteredPhase20JobWorkerOwnerRecordV1 struct {
	Version         string `json:"version"`
	Purpose         string `json:"purpose"`
	JobSHA256       string `json:"job_sha256"`
	TransportSHA256 string `json:"transport_sha256"`
	OwnerSHA256     string `json:"owner_sha256"`
	PID             int    `json:"pid"`
	ProductionReady bool   `json:"production_ready"`
	MACSHA256       string `json:"mac_sha256"`
}

type formalGLMRegisteredPhase20JobWorkerHeartbeatRecordV1 struct {
	Version         string `json:"version"`
	Purpose         string `json:"purpose"`
	JobSHA256       string `json:"job_sha256"`
	TransportSHA256 string `json:"transport_sha256"`
	OwnerSHA256     string `json:"owner_sha256"`
	Counter         uint64 `json:"counter"`
	UnixNano        int64  `json:"unix_nano"`
	PID             int    `json:"pid"`
	ProductionReady bool   `json:"production_ready"`
	MACSHA256       string `json:"mac_sha256"`
}

type formalGLMRegisteredPhase20JobWorkerObservationV1 struct {
	state            string
	ownerAlive       bool
	cleanExit        bool
	heartbeatCounter uint64
	productionReady  bool
}

type formalGLMRegisteredPhase20JobWorkerControllerV1 struct {
	mu sync.Mutex

	transport *formalGLMRegisteredPhase20JobTransportV1
	metadata  *formalGLMRegisteredPhase20JobTransportRelayStoreV1
	ownerLock *os.File

	ownerLockSHA256 string
	ownerSHA256     string
	counter         uint64
	lastHeartbeat   formalGLMRegisteredPhase20JobWorkerHeartbeatRecordV1
	closed          bool
	closeDone       chan struct{}
	closeErr        error
}

func formalGLMRegisteredPhase20JobWorkerLockSupportedV1() bool {
	switch runtime.GOOS {
	case "aix", "darwin", "dragonfly", "freebsd", "linux", "netbsd", "openbsd", "solaris":
		return true
	default:
		return false
	}
}

func formalGLMRegisteredPhase20JobWorkerOwnerLockSHA256V1(
	transportSHA256 string,
) (string, error) {
	if !formalGLMIsSHA256(transportSHA256) {
		return "", fmt.Errorf("formal-glm registered Phase20 worker controller: invalid transport")
	}
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase20JobWorkerDomainV1+"/owner-lock",
		transportSHA256)
}

func formalGLMRegisteredPhase20JobWorkerLockNameV1(lockSHA256 string) string {
	return "authority-lock-" + lockSHA256 + ".bin"
}

func formalGLMRegisteredPhase20JobWorkerOpenLifetimeLockV1(
	root *os.Root, lockSHA256 string, create bool,
) (*os.File, error) {
	if root == nil || !formalGLMIsSHA256(lockSHA256) ||
		!formalGLMRegisteredPhase20JobWorkerLockSupportedV1() {
		return nil, fmt.Errorf("formal-glm registered Phase20 worker controller: owner lock unavailable")
	}
	name := formalGLMRegisteredPhase20JobWorkerLockNameV1(lockSHA256)
	if create {
		file, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			if chmodErr := file.Chmod(0o600); chmodErr != nil {
				_ = file.Close()
				return nil, chmodErr
			}
			if closeErr := file.Close(); closeErr != nil {
				return nil, closeErr
			}
			if err := formalGLMPhase21RootSyncDir(root, name); err != nil {
				return nil, err
			}
		} else if !os.IsExist(err) {
			return nil, err
		}
	}
	pathInfo, err := root.Lstat(name)
	if os.IsNotExist(err) {
		return nil, err
	}
	if err != nil || !pathInfo.Mode().IsRegular() ||
		pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Mode().Perm() != 0o600 ||
		!exactGCPrivateOwnedRegular(pathInfo) {
		return nil, fmt.Errorf("formal-glm registered Phase20 worker controller: unsafe owner lock")
	}
	file, err := root.OpenFile(name, os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	opened, fileErr := file.Stat()
	current, pathErr := root.Lstat(name)
	if fileErr != nil || pathErr != nil || !os.SameFile(opened, current) ||
		!os.SameFile(pathInfo, current) || current.Mode().Perm() != 0o600 ||
		!exactGCPrivateOwnedRegular(current) {
		_ = file.Close()
		return nil, fmt.Errorf("formal-glm registered Phase20 worker controller: owner lock changed")
	}
	return file, nil
}

func formalGLMRegisteredPhase20JobWorkerAcquireLifetimeLockV1(
	root *os.Root, lockSHA256 string,
) (*os.File, error) {
	file, err := formalGLMRegisteredPhase20JobWorkerOpenLifetimeLockV1(
		root, lockSHA256, true)
	if err != nil {
		return nil, err
	}
	if err := formalFinalizerHandoffTryAuthorityLock(file); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errFormalGLMRegisteredPhase20JobWorkerOwnerLockBusyV1
		}
		return nil, fmt.Errorf("formal-glm registered Phase20 worker controller: owner lock failed: %w", err)
	}
	return file, nil
}

func formalGLMRegisteredPhase20JobWorkerReleaseLifetimeLockV1(file *os.File) {
	if file != nil {
		_ = formalFinalizerHandoffUnlockAuthority(file)
		_ = file.Close()
	}
}

func formalGLMRegisteredPhase20JobWorkerValidateLifetimeLockV1(
	root *os.Root, lockSHA256 string, file *os.File,
) error {
	if root == nil || file == nil {
		return fmt.Errorf("formal-glm registered Phase20 worker controller: owner lock unavailable")
	}
	pathInfo, pathErr := root.Lstat(
		formalGLMRegisteredPhase20JobWorkerLockNameV1(lockSHA256))
	opened, fileErr := file.Stat()
	if pathErr != nil || fileErr != nil || !os.SameFile(pathInfo, opened) ||
		pathInfo.Mode().Perm() != 0o600 || !exactGCPrivateOwnedRegular(pathInfo) {
		return fmt.Errorf("formal-glm registered Phase20 worker controller: owner lock changed")
	}
	return nil
}

func formalGLMRegisteredPhase20JobWorkerLifetimeLockHeldV1(
	root *os.Root, lockSHA256 string,
) (bool, *os.File, error) {
	file, err := formalGLMRegisteredPhase20JobWorkerOpenLifetimeLockV1(
		root, lockSHA256, false)
	if os.IsNotExist(err) {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	if err := formalFinalizerHandoffTryAuthorityLock(file); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return true, nil, nil
		}
		return false, nil, fmt.Errorf("formal-glm registered Phase20 worker controller: owner lock failed: %w", err)
	}
	return false, file, nil
}

func formalGLMRegisteredPhase20JobWorkerStartBindingV1(
	attempts *formalGLMRegisteredPhase19AttemptStoreV1,
	jobKeys *formalGLMRegisteredPhase20JobKeyProviderV1,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	epoch formalGLMRegisteredPhase20JobTransportEpochV1,
) (*os.Root, string, formalGLMRegisteredPhase20JobTransportBindingV1, error) {
	var zero formalGLMRegisteredPhase20JobTransportBindingV1
	if attempts == nil || jobKeys == nil ||
		epoch.Mode != formalGLMRegisteredPhase20JobRunTransportV1 {
		return nil, "", zero, fmt.Errorf("formal-glm registered Phase20 worker controller: invalid start")
	}
	acceptSHA256, err := formalGLMRegisteredPhase19ClaimAcceptSHA256V1(accept)
	if err != nil || epoch.BasisSHA256 != acceptSHA256 {
		return nil, "", zero, fmt.Errorf("formal-glm registered Phase20 worker controller: invalid epoch basis")
	}
	attempts.mu.Lock()
	plan := attempts.contract.Core.RegisteredExecutionPlan
	if attempts.root == nil || attempts.localIndex < 0 || attempts.localIndex > 1 ||
		len(plan.DesignatedComputePeers) != 2 || len(plan.NoiseAuthorities) != 2 ||
		plan.DesignatedComputePeers[attempts.localIndex] !=
			plan.NoiseAuthorities[attempts.localIndex].PeerName ||
		attempts.validateAcceptV1(proposal, accept) != nil ||
		attempts.requirePreviousBindingV1(proposal.Binding) != nil ||
		!reflect.DeepEqual(proposal.Binding, accept.Binding) {
		attempts.mu.Unlock()
		return nil, "", zero, fmt.Errorf("formal-glm registered Phase20 worker controller: invalid signed attempt")
	}
	attemptRoot := attempts.root
	localIndex := attempts.localIndex
	localPeer := plan.DesignatedComputePeers[localIndex]
	record := attempts.record.Binding
	recordSHA256 := attempts.recordSHA256
	attemptRelative := attempts.attemptRelativeDirV1(proposal.Binding.AttemptID)
	attempts.mu.Unlock()
	wantContext := formalGLMRegisteredPhase20JobKeyContextV1{
		artifactID:                    record.ArtifactID,
		sourceContractCoreSHA256:      record.SourceContractCoreSHA256,
		sourceContractSHA256:          record.SourceContractSHA256,
		pinsetSHA256:                  record.PinsetSHA256,
		semanticRootSHA256:            record.SemanticRootSHA256,
		bindingRecordSHA256:           recordSHA256,
		registeredExecutionPlanSHA256: record.RegisteredExecutionPlanSHA256,
		localPeer:                     localPeer, localIndex: localIndex,
	}
	jobKeys.mu.Lock()
	jobRoot := jobKeys.root
	contextOK := jobKeys.validateLocked() == nil && jobKeys.context == wantContext
	jobKeys.mu.Unlock()
	key, keyErr := jobKeys.DeriveAttemptKey(proposal.Binding)
	clear(key[:])
	if !contextOK || keyErr != nil ||
		!formalGLMRegisteredPhase19ScheduleTailSameRootV1(attemptRoot, jobRoot) {
		return nil, "", zero, fmt.Errorf("formal-glm registered Phase20 worker controller: invalid storage owner")
	}
	binding := formalGLMRegisteredPhase20JobTransportBindingV1{
		ArtifactID:          proposal.Binding.ArtifactID,
		ReceiptSetSHA256:    record.ReceiptSetSHA256,
		SemanticRootSHA256:  proposal.Binding.SemanticRootSHA256,
		BindingRecordSHA256: proposal.Binding.BindingRecordSHA256,
		AttemptID:           proposal.Binding.AttemptID,
		ScheduleRootSHA256:  proposal.Binding.ScheduleRootSHA256,
		ProductionReady:     false,
	}
	return attemptRoot, attemptRelative, binding, nil
}

func formalGLMRegisteredPhase20JobWorkerRandomOwnerSHA256V1() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	encoded := hex.EncodeToString(value[:])
	clear(value[:])
	return encoded, nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) workerMACV1(
	kind string, value any,
) (string, error) {
	return store.recordMACV1(
		formalGLMRegisteredPhase20JobWorkerDomainV1+"/"+kind, value)
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) workerReadOptionalV1(
	name string,
) ([]byte, bool, error) {
	if _, err := store.scratch.Lstat(name); os.IsNotExist(err) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}
	encoded, err := store.readRecordV1(name)
	return encoded, err == nil, err
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) workerReapTempsLockedV1() error {
	changed := false
	for _, name := range []string{
		formalGLMRegisteredPhase20JobWorkerOwnerFileV1 + ".next",
		formalGLMRegisteredPhase20JobWorkerReadyFileV1 + ".next",
		formalGLMRegisteredPhase20JobWorkerHeartbeatFileV1 + ".next",
		formalGLMRegisteredPhase20JobWorkerExitFileV1 + ".next",
		formalGLMRegisteredPhase20JobWorkerAbortFileV1 + ".next",
	} {
		removed, err := formalGLMRegisteredPhase20JobRelayRemoveTempV1(
			store.scratch, name, formalGLMRegisteredPhase20JobWorkerRecordMaxV1)
		if err != nil {
			return err
		}
		changed = changed || removed
	}
	if changed {
		return formalGLMPhase21RootSyncDir(
			store.scratch, formalGLMRegisteredPhase20JobWorkerHeartbeatFileV1)
	}
	return nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) workerTransportAbortV1() (bool, error) {
	if _, err := store.scratch.Lstat("abort"); os.IsNotExist(err) {
		return false, nil
	} else if err != nil || !formalGLMRegisteredPhase20JobTransportAbortValidV1(store.scratch) {
		return true, fmt.Errorf("formal-glm registered Phase20 worker controller: invalid transport abort")
	}
	return true, nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) workerOwnerRecordV1(
	ownerSHA256 string, pid int,
) (formalGLMRegisteredPhase20JobWorkerOwnerRecordV1, []byte, error) {
	record := formalGLMRegisteredPhase20JobWorkerOwnerRecordV1{
		Version:         formalGLMRegisteredPhase20JobWorkerVersionV1,
		Purpose:         formalGLMRegisteredPhase20JobWorkerPurposeV1,
		JobSHA256:       store.ref.JobSHA256,
		TransportSHA256: store.ref.TransportSHA256,
		OwnerSHA256:     ownerSHA256, PID: pid, ProductionReady: false,
	}
	mac, err := store.workerMACV1("owner", record)
	if err != nil {
		return record, nil, err
	}
	record.MACSHA256 = mac
	encoded, err := json.Marshal(record)
	return record, encoded, err
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) workerValidateOwnerV1(
	record formalGLMRegisteredPhase20JobWorkerOwnerRecordV1, encoded []byte,
) error {
	mac := record.MACSHA256
	unsigned := record
	unsigned.MACSHA256 = ""
	wantMAC, err := store.workerMACV1("owner", unsigned)
	canonical, canonicalErr := json.Marshal(record)
	if err != nil || canonicalErr != nil || !bytes.Equal(encoded, canonical) ||
		!hmac.Equal([]byte(mac), []byte(wantMAC)) ||
		record.Version != formalGLMRegisteredPhase20JobWorkerVersionV1 ||
		record.Purpose != formalGLMRegisteredPhase20JobWorkerPurposeV1 ||
		record.JobSHA256 != store.ref.JobSHA256 ||
		record.TransportSHA256 != store.ref.TransportSHA256 ||
		!formalGLMIsSHA256(record.OwnerSHA256) || record.PID <= 0 ||
		record.ProductionReady {
		return fmt.Errorf("formal-glm registered Phase20 worker controller: invalid owner manifest")
	}
	return nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) workerLoadOwnerV1() (
	formalGLMRegisteredPhase20JobWorkerOwnerRecordV1, bool, error,
) {
	var record formalGLMRegisteredPhase20JobWorkerOwnerRecordV1
	encoded, exists, err := store.workerReadOptionalV1(
		formalGLMRegisteredPhase20JobWorkerOwnerFileV1)
	if err != nil || !exists {
		return record, exists, err
	}
	defer clear(encoded)
	if formalGLMPhase21RockStrictDecode(encoded, &record) != nil ||
		store.workerValidateOwnerV1(record, encoded) != nil {
		return record, true, fmt.Errorf("formal-glm registered Phase20 worker controller: invalid owner manifest")
	}
	return record, true, nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) workerCommitOwnerV1(
	ownerSHA256 string, pid int,
) error {
	if _, exists, err := store.workerLoadOwnerV1(); err != nil || exists {
		return fmt.Errorf("formal-glm registered Phase20 worker controller: owner manifest already exists")
	}
	want, encoded, err := store.workerOwnerRecordV1(ownerSHA256, pid)
	if err != nil {
		return err
	}
	if err := store.replaceRecordV1(
		formalGLMRegisteredPhase20JobWorkerOwnerFileV1, encoded); err != nil {
		return err
	}
	got, exists, err := store.workerLoadOwnerV1()
	if err != nil || !exists || !reflect.DeepEqual(got, want) {
		return fmt.Errorf("formal-glm registered Phase20 worker controller: owner manifest commit failed")
	}
	return nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) workerLoadAnchorV1(
	name, kind string,
) (bool, error) {
	if _, err := store.scratch.Lstat(name); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, store.requireAnchorV1(name, kind)
}

func (controller *formalGLMRegisteredPhase20JobWorkerControllerV1) heartbeatRecordV1(
	counter uint64, at time.Time, pid int,
) formalGLMRegisteredPhase20JobWorkerHeartbeatRecordV1 {
	return formalGLMRegisteredPhase20JobWorkerHeartbeatRecordV1{
		Version:         formalGLMRegisteredPhase20JobWorkerVersionV1,
		Purpose:         formalGLMRegisteredPhase20JobWorkerPurposeV1,
		JobSHA256:       controller.metadata.ref.JobSHA256,
		TransportSHA256: controller.metadata.ref.TransportSHA256,
		OwnerSHA256:     controller.ownerSHA256, Counter: counter,
		UnixNano: at.UnixNano(), PID: pid, ProductionReady: false,
	}
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) workerSignHeartbeatV1(
	record formalGLMRegisteredPhase20JobWorkerHeartbeatRecordV1,
) ([]byte, error) {
	record.MACSHA256 = ""
	mac, err := store.workerMACV1("heartbeat", record)
	if err != nil {
		return nil, err
	}
	record.MACSHA256 = mac
	return json.Marshal(record)
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) workerValidateHeartbeatV1(
	record formalGLMRegisteredPhase20JobWorkerHeartbeatRecordV1,
	encoded []byte, ownerSHA256 string,
) error {
	mac := record.MACSHA256
	unsigned := record
	unsigned.MACSHA256 = ""
	wantMAC, err := store.workerMACV1("heartbeat", unsigned)
	canonical, canonicalErr := json.Marshal(record)
	if err != nil || canonicalErr != nil || !bytes.Equal(encoded, canonical) ||
		!hmac.Equal([]byte(mac), []byte(wantMAC)) ||
		record.Version != formalGLMRegisteredPhase20JobWorkerVersionV1 ||
		record.Purpose != formalGLMRegisteredPhase20JobWorkerPurposeV1 ||
		record.JobSHA256 != store.ref.JobSHA256 ||
		record.TransportSHA256 != store.ref.TransportSHA256 ||
		record.OwnerSHA256 != ownerSHA256 || record.Counter == 0 ||
		record.UnixNano <= 0 || record.PID <= 0 || record.ProductionReady {
		return fmt.Errorf("formal-glm registered Phase20 worker controller: invalid heartbeat")
	}
	return nil
}

func (store *formalGLMRegisteredPhase20JobTransportRelayStoreV1) workerLoadHeartbeatV1(
	ownerSHA256 string,
) (formalGLMRegisteredPhase20JobWorkerHeartbeatRecordV1, bool, error) {
	var record formalGLMRegisteredPhase20JobWorkerHeartbeatRecordV1
	encoded, exists, err := store.workerReadOptionalV1(
		formalGLMRegisteredPhase20JobWorkerHeartbeatFileV1)
	if err != nil || !exists {
		return record, exists, err
	}
	defer clear(encoded)
	if formalGLMPhase21RockStrictDecode(encoded, &record) != nil ||
		store.workerValidateHeartbeatV1(record, encoded, ownerSHA256) != nil {
		return record, true, fmt.Errorf("formal-glm registered Phase20 worker controller: invalid heartbeat")
	}
	return record, true, nil
}

func (controller *formalGLMRegisteredPhase20JobWorkerControllerV1) commitHeartbeatLockedV1(
	record formalGLMRegisteredPhase20JobWorkerHeartbeatRecordV1,
) error {
	current, exists, err := controller.metadata.workerLoadHeartbeatV1(
		controller.ownerSHA256)
	if err != nil || !exists && record.Counter != 1 || exists &&
		(current.Counter == ^uint64(0) || record.Counter != current.Counter+1) {
		return fmt.Errorf("formal-glm registered Phase20 worker controller: non-monotonic heartbeat")
	}
	encoded, err := controller.metadata.workerSignHeartbeatV1(record)
	if err != nil {
		return err
	}
	if err := controller.metadata.replaceRecordV1(
		formalGLMRegisteredPhase20JobWorkerHeartbeatFileV1, encoded); err != nil {
		return err
	}
	got, exists, err := controller.metadata.workerLoadHeartbeatV1(
		controller.ownerSHA256)
	got.MACSHA256 = ""
	record.MACSHA256 = ""
	if err != nil || !exists || !reflect.DeepEqual(got, record) {
		return fmt.Errorf("formal-glm registered Phase20 worker controller: heartbeat commit failed")
	}
	return nil
}

func startFormalGLMRegisteredPhase20JobWorkerControllerV1(
	attempts *formalGLMRegisteredPhase19AttemptStoreV1,
	jobKeys *formalGLMRegisteredPhase20JobKeyProviderV1,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	epoch formalGLMRegisteredPhase20JobTransportEpochV1,
) (*formalGLMRegisteredPhase20JobWorkerControllerV1, error) {
	root, attemptRelative, binding, err :=
		formalGLMRegisteredPhase20JobWorkerStartBindingV1(
			attempts, jobKeys, proposal, accept, epoch)
	if err != nil {
		return nil, err
	}
	transport, err := newFormalGLMRegisteredPhase20JobTransportV1(
		root, attemptRelative, binding, epoch)
	if err != nil {
		return nil, err
	}
	metadata, err := openFormalGLMRegisteredPhase20JobTransportRelayStoreV1(
		attempts, jobKeys, proposal, accept, epoch)
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	controller := &formalGLMRegisteredPhase20JobWorkerControllerV1{
		transport: transport, metadata: metadata,
		closeDone: make(chan struct{}),
	}
	fail := func(cause error) (*formalGLMRegisteredPhase20JobWorkerControllerV1, error) {
		_ = transport.Close()
		_ = metadata.CloseRelayV1()
		formalGLMRegisteredPhase20JobWorkerReleaseLifetimeLockV1(controller.ownerLock)
		controller.ownerLock = nil
		return nil, cause
	}
	controller.ownerLockSHA256, err =
		formalGLMRegisteredPhase20JobWorkerOwnerLockSHA256V1(
			transport.ref.TransportSHA256)
	if err != nil {
		return fail(err)
	}
	controller.ownerLock, err =
		formalGLMRegisteredPhase20JobWorkerAcquireLifetimeLockV1(
			metadata.scratch, controller.ownerLockSHA256)
	if err != nil {
		return fail(err)
	}
	controller.ownerSHA256, err =
		formalGLMRegisteredPhase20JobWorkerRandomOwnerSHA256V1()
	if err != nil {
		return fail(err)
	}
	commandLock, err := metadata.acquireRelayLockV1()
	if err != nil {
		return fail(err)
	}
	defer metadata.releaseRelayLockV1(commandLock)
	if err := metadata.workerReapTempsLockedV1(); err != nil {
		return fail(err)
	}
	if err := metadata.workerCommitOwnerV1(
		controller.ownerSHA256, os.Getpid()); err != nil {
		return fail(err)
	}
	heartbeat := controller.heartbeatRecordV1(1, time.Now(), os.Getpid())
	if err := controller.commitHeartbeatLockedV1(heartbeat); err != nil {
		return fail(err)
	}
	controller.counter = 1
	controller.lastHeartbeat = heartbeat
	if err := metadata.commitAnchorV1(
		formalGLMRegisteredPhase20JobWorkerReadyFileV1,
		formalGLMRegisteredPhase20JobWorkerReadyKindV1); err != nil {
		return fail(err)
	}
	state, err := metadata.loadRelayStateLockedV1()
	if err != nil || state.State != formalGLMRegisteredPhase20JobNegotiatingV1 {
		return fail(fmt.Errorf("formal-glm registered Phase20 worker controller: relay state unavailable"))
	}
	state.State = formalGLMRegisteredPhase20JobRunningV1
	if err := metadata.commitRelayStateLockedV1(&state); err != nil {
		return fail(err)
	}
	if err := transport.setStateV1(formalGLMRegisteredPhase20JobRunningV1); err != nil {
		return fail(err)
	}
	return controller, nil
}

func (controller *formalGLMRegisteredPhase20JobWorkerControllerV1) HeartbeatV1() error {
	if controller == nil {
		return fmt.Errorf("formal-glm registered Phase20 worker controller: unavailable")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed || controller.metadata == nil || controller.counter == ^uint64(0) {
		return fmt.Errorf("formal-glm registered Phase20 worker controller: closed")
	}
	if err := formalGLMRegisteredPhase20JobWorkerValidateLifetimeLockV1(
		controller.metadata.scratch, controller.ownerLockSHA256,
		controller.ownerLock); err != nil {
		return err
	}
	lock, err := controller.metadata.acquireRelayLockV1()
	if err != nil {
		return err
	}
	defer controller.metadata.releaseRelayLockV1(lock)
	if err := controller.metadata.workerReapTempsLockedV1(); err != nil {
		return err
	}
	state, err := controller.metadata.loadRelayStateLockedV1()
	if err != nil || state.State == formalGLMRegisteredPhase20JobFailedClosedV1 {
		return fmt.Errorf("formal-glm registered Phase20 worker controller: relay failed closed")
	}
	if transportAbort, err := controller.metadata.workerTransportAbortV1(); err != nil || transportAbort {
		return fmt.Errorf("formal-glm registered Phase20 worker controller: transport stopping")
	}
	if abort, err := controller.metadata.workerLoadAnchorV1(
		formalGLMRegisteredPhase20JobWorkerAbortFileV1,
		formalGLMRegisteredPhase20JobWorkerAbortKindV1); err != nil || abort {
		return fmt.Errorf("formal-glm registered Phase20 worker controller: abort requested")
	}
	current, exists, err := controller.metadata.workerLoadHeartbeatV1(
		controller.ownerSHA256)
	current.MACSHA256 = ""
	if err != nil || !exists || current.Counter != controller.counter ||
		!reflect.DeepEqual(current, controller.lastHeartbeat) {
		return fmt.Errorf("formal-glm registered Phase20 worker controller: heartbeat changed")
	}
	next := controller.heartbeatRecordV1(
		controller.counter+1, time.Now(), os.Getpid())
	if err := controller.commitHeartbeatLockedV1(next); err != nil {
		return err
	}
	controller.counter++
	controller.lastHeartbeat = next
	return nil
}

func formalGLMRegisteredPhase20JobWorkerAbortLockedV1(
	store *formalGLMRegisteredPhase20JobTransportRelayStoreV1,
) error {
	if err := store.commitAnchorV1(
		formalGLMRegisteredPhase20JobWorkerAbortFileV1,
		formalGLMRegisteredPhase20JobWorkerAbortKindV1); err != nil {
		return err
	}
	return formalGLMRegisteredPhase20JobTransportSignalAbortV1(store.scratch)
}

func formalGLMRegisteredPhase20JobWorkerInvalidObservationV1(
	store *formalGLMRegisteredPhase20JobTransportRelayStoreV1,
) (formalGLMRegisteredPhase20JobWorkerObservationV1, error) {
	observation := formalGLMRegisteredPhase20JobWorkerObservationV1{
		state:           formalGLMRegisteredPhase20JobWorkerInvalidDurableStateV1,
		productionReady: false,
	}
	if err := formalGLMRegisteredPhase20JobWorkerAbortLockedV1(store); err != nil {
		return observation, err
	}
	return observation, nil
}

func inspectFormalGLMRegisteredPhase20JobWorkerControllerV1(
	attempts *formalGLMRegisteredPhase19AttemptStoreV1,
	jobKeys *formalGLMRegisteredPhase20JobKeyProviderV1,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	epoch formalGLMRegisteredPhase20JobTransportEpochV1,
) (formalGLMRegisteredPhase20JobWorkerObservationV1, error) {
	var zero formalGLMRegisteredPhase20JobWorkerObservationV1
	store, err := openFormalGLMRegisteredPhase20JobTransportRelayStoreV1(
		attempts, jobKeys, proposal, accept, epoch)
	if err != nil {
		return zero, err
	}
	defer store.CloseRelayV1()
	lock, err := store.acquireRelayLockV1()
	if err != nil {
		return zero, err
	}
	defer store.releaseRelayLockV1(lock)
	if err := store.workerReapTempsLockedV1(); err != nil {
		return zero, err
	}
	relayState, relayErr := store.loadRelayStateLockedV1()
	transportAbort, transportAbortErr := store.workerTransportAbortV1()
	if relayErr != nil || relayState.State == formalGLMRegisteredPhase20JobFailedClosedV1 ||
		transportAbortErr != nil {
		return formalGLMRegisteredPhase20JobWorkerInvalidObservationV1(store)
	}
	owner, hasOwner, ownerErr := store.workerLoadOwnerV1()
	ownerLockSHA256, hashErr :=
		formalGLMRegisteredPhase20JobWorkerOwnerLockSHA256V1(
			store.ref.TransportSHA256)
	held, acquired, lockErr :=
		formalGLMRegisteredPhase20JobWorkerLifetimeLockHeldV1(
			store.scratch, ownerLockSHA256)
	defer formalGLMRegisteredPhase20JobWorkerReleaseLifetimeLockV1(acquired)
	if hashErr != nil || lockErr != nil {
		return formalGLMRegisteredPhase20JobWorkerInvalidObservationV1(store)
	}
	if ownerErr != nil {
		return formalGLMRegisteredPhase20JobWorkerInvalidObservationV1(store)
	}
	if hasOwner && !held && acquired == nil {
		return formalGLMRegisteredPhase20JobWorkerInvalidObservationV1(store)
	}
	ownerSHA256 := ""
	if hasOwner {
		ownerSHA256 = owner.OwnerSHA256
	}
	ready, readyErr := store.workerLoadAnchorV1(
		formalGLMRegisteredPhase20JobWorkerReadyFileV1,
		formalGLMRegisteredPhase20JobWorkerReadyKindV1)
	heartbeat, hasHeartbeat, heartbeatErr :=
		store.workerLoadHeartbeatV1(ownerSHA256)
	exited, exitErr := store.workerLoadAnchorV1(
		formalGLMRegisteredPhase20JobWorkerExitFileV1,
		formalGLMRegisteredPhase20JobWorkerExitKindV1)
	aborted, abortErr := store.workerLoadAnchorV1(
		formalGLMRegisteredPhase20JobWorkerAbortFileV1,
		formalGLMRegisteredPhase20JobWorkerAbortKindV1)
	if readyErr != nil || heartbeatErr != nil || exitErr != nil || abortErr != nil ||
		ready && !hasOwner || hasHeartbeat && !hasOwner ||
		exited && (!hasOwner || !ready || !hasHeartbeat) {
		return formalGLMRegisteredPhase20JobWorkerInvalidObservationV1(store)
	}
	if exited && held {
		return formalGLMRegisteredPhase20JobWorkerInvalidObservationV1(store)
	}
	if !held {
		if exited {
			return formalGLMRegisteredPhase20JobWorkerObservationV1{
				state:     formalGLMRegisteredPhase20JobWorkerExitedV1,
				cleanExit: !aborted, productionReady: false,
			}, nil
		}
		return formalGLMRegisteredPhase20JobWorkerObservationV1{
			state:           formalGLMRegisteredPhase20JobWorkerOwnerLostV1,
			productionReady: false,
		}, nil
	}
	if aborted {
		if err := formalGLMRegisteredPhase20JobTransportSignalAbortV1(
			store.scratch); err != nil {
			return zero, err
		}
		return formalGLMRegisteredPhase20JobWorkerObservationV1{
			state:           formalGLMRegisteredPhase20JobWorkerAbortRequestedV1,
			productionReady: false,
		}, nil
	}
	if transportAbort {
		return formalGLMRegisteredPhase20JobWorkerObservationV1{
			state:           formalGLMRegisteredPhase20JobWorkerStalledV1,
			productionReady: false,
		}, nil
	}
	if ready && !hasHeartbeat {
		if err := formalGLMRegisteredPhase20JobWorkerAbortLockedV1(store); err != nil {
			return zero, err
		}
		return formalGLMRegisteredPhase20JobWorkerObservationV1{
			state:           formalGLMRegisteredPhase20JobWorkerAbortRequestedV1,
			productionReady: false,
		}, nil
	}
	if !ready {
		return formalGLMRegisteredPhase20JobWorkerObservationV1{
			state:      formalGLMRegisteredPhase20JobWorkerStartingV1,
			ownerAlive: true, productionReady: false,
		}, nil
	}
	now := time.Now()
	heartbeatAt := time.Unix(0, heartbeat.UnixNano)
	if heartbeatAt.After(now.Add(formalGLMRegisteredPhase20JobWorkerHeartbeatTTLV1)) {
		return formalGLMRegisteredPhase20JobWorkerInvalidObservationV1(store)
	}
	if now.Sub(heartbeatAt) > formalGLMRegisteredPhase20JobWorkerHeartbeatTTLV1 {
		if err := formalGLMRegisteredPhase20JobWorkerAbortLockedV1(store); err != nil {
			return zero, err
		}
		return formalGLMRegisteredPhase20JobWorkerObservationV1{
			state:            formalGLMRegisteredPhase20JobWorkerAbortRequestedV1,
			heartbeatCounter: heartbeat.Counter, productionReady: false,
		}, nil
	}
	return formalGLMRegisteredPhase20JobWorkerObservationV1{
		state:      formalGLMRegisteredPhase20JobWorkerRunningV1,
		ownerAlive: true, heartbeatCounter: heartbeat.Counter,
		productionReady: false,
	}, nil
}

func (controller *formalGLMRegisteredPhase20JobWorkerControllerV1) Close() error {
	if controller == nil {
		return nil
	}
	controller.mu.Lock()
	if controller.closed {
		done := controller.closeDone
		controller.mu.Unlock()
		if done != nil {
			<-done
		}
		controller.mu.Lock()
		err := controller.closeErr
		controller.mu.Unlock()
		return err
	}
	controller.closed = true
	if controller.closeDone == nil {
		controller.closeDone = make(chan struct{})
	}
	metadata, transport, ownerLock := controller.metadata,
		controller.transport, controller.ownerLock
	var closeErr error
	if metadata != nil {
		closeErr = formalGLMRegisteredPhase20JobWorkerValidateLifetimeLockV1(
			metadata.scratch, controller.ownerLockSHA256, ownerLock)
	}
	if transport != nil {
		if err := transport.Close(); closeErr == nil {
			closeErr = err
		}
	}
	if closeErr == nil && metadata != nil {
		lock, err := metadata.acquireRelayLockV1()
		if err == nil {
			err = metadata.commitAnchorV1(
				formalGLMRegisteredPhase20JobWorkerExitFileV1,
				formalGLMRegisteredPhase20JobWorkerExitKindV1)
			if err == nil {
				formalGLMRegisteredPhase20JobWorkerReleaseLifetimeLockV1(ownerLock)
				ownerLock = nil
			}
			metadata.releaseRelayLockV1(lock)
		}
		closeErr = err
	}
	if metadata != nil {
		if err := metadata.CloseRelayV1(); closeErr == nil {
			closeErr = err
		}
	}
	// The durable, fsynced exit record and all worker-owned I/O precede unlock.
	formalGLMRegisteredPhase20JobWorkerReleaseLifetimeLockV1(ownerLock)
	controller.ownerLock = nil
	controller.transport = nil
	controller.metadata = nil
	controller.ownerLockSHA256 = ""
	controller.ownerSHA256 = ""
	controller.counter = 0
	controller.lastHeartbeat = formalGLMRegisteredPhase20JobWorkerHeartbeatRecordV1{}
	controller.closeErr = closeErr
	done := controller.closeDone
	close(done)
	controller.mu.Unlock()
	return closeErr
}
