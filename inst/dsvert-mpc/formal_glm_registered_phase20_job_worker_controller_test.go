package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const formalGLMRegisteredPhase20JobWorkerLockHelperEnvV1 = "DSVERT_FORMAL_GLM_JOB_WORKER_LOCK_HELPER"

func TestFormalGLMRegisteredPhase20JobWorkerLockHelperProcess(t *testing.T) {
	slot := os.Getenv(formalGLMRegisteredPhase20JobWorkerLockHelperEnvV1)
	if slot == "" {
		return
	}
	root, err := os.OpenRoot(slot)
	if err != nil {
		os.Exit(42)
	}
	lock, err := formalGLMRegisteredPhase20JobWorkerAcquireLifetimeLockV1(
		root, os.Getenv("DSVERT_FORMAL_GLM_JOB_WORKER_LOCK_SHA"))
	if err != nil {
		_ = root.Close()
		if errors.Is(err,
			errFormalGLMRegisteredPhase20JobWorkerOwnerLockBusyV1) {
			os.Exit(41)
		}
		os.Exit(42)
	}
	formalGLMRegisteredPhase20JobWorkerReleaseLifetimeLockV1(lock)
	_ = root.Close()
}

type formalGLMRegisteredPhase20JobWorkerTestFixtureV1 struct {
	rootPath string
	attempts *formalGLMRegisteredPhase19AttemptStoreV1
	jobKeys  *formalGLMRegisteredPhase20JobKeyProviderV1
	proposal formalGLMRegisteredPhase19ClaimProposalV1
	accept   formalGLMRegisteredPhase19ClaimAcceptV1
	epoch    formalGLMRegisteredPhase20JobTransportEpochV1
}

func newFormalGLMRegisteredPhase20JobWorkerTestFixtureV1(
	t testing.TB,
) *formalGLMRegisteredPhase20JobWorkerTestFixtureV1 {
	t.Helper()
	core := formalGLMRegisteredPhase19AttemptTestCoreK2(t)
	peers := core.source.plan.DesignatedComputePeers
	rootPath := filepath.Join(t.TempDir(), "local-rock")
	peerPath := filepath.Join(t.TempDir(), "peer-rock")
	attempts := formalGLMRegisteredPhase20JobRelayTestOpenAttemptV1(
		t, rootPath, peers[0], core)
	peerAttempts := formalGLMRegisteredPhase20JobRelayTestOpenAttemptV1(
		t, peerPath, peers[1], core)
	proposal, _, err := attempts.Begin(nil)
	if err != nil {
		t.Fatal(err)
	}
	accept, _, err := peerAttempts.Accept(proposal)
	if err != nil {
		t.Fatal(err)
	}
	acceptSHA256, err := formalGLMRegisteredPhase19ClaimAcceptSHA256V1(accept)
	if err != nil {
		t.Fatal(err)
	}
	return &formalGLMRegisteredPhase20JobWorkerTestFixtureV1{
		rootPath: rootPath, attempts: attempts,
		jobKeys: formalGLMRegisteredPhase20JobRelayTestOpenJobKeyV1(
			t, rootPath, peers[0], core),
		proposal: proposal, accept: accept,
		epoch: formalGLMRegisteredPhase20JobTransportEpochV1{
			Mode:        formalGLMRegisteredPhase20JobRunTransportV1,
			BasisSHA256: acceptSHA256,
		},
	}
}

func (fixture *formalGLMRegisteredPhase20JobWorkerTestFixtureV1) start(
	t testing.TB,
) *formalGLMRegisteredPhase20JobWorkerControllerV1 {
	t.Helper()
	controller, err := startFormalGLMRegisteredPhase20JobWorkerControllerV1(
		fixture.attempts, fixture.jobKeys, fixture.proposal,
		fixture.accept, fixture.epoch)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	return controller
}

func (fixture *formalGLMRegisteredPhase20JobWorkerTestFixtureV1) inspect(
	t testing.TB,
) formalGLMRegisteredPhase20JobWorkerObservationV1 {
	t.Helper()
	observation, err := inspectFormalGLMRegisteredPhase20JobWorkerControllerV1(
		fixture.attempts, fixture.jobKeys, fixture.proposal,
		fixture.accept, fixture.epoch)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func formalGLMRegisteredPhase20JobWorkerTestRunLockHelperV1(
	t testing.TB, slot, lockSHA string,
) int {
	t.Helper()
	command := exec.Command(os.Args[0],
		"-test.run=^TestFormalGLMRegisteredPhase20JobWorkerLockHelperProcess$")
	command.Env = append(os.Environ(),
		formalGLMRegisteredPhase20JobWorkerLockHelperEnvV1+"="+slot,
		"DSVERT_FORMAL_GLM_JOB_WORKER_LOCK_SHA="+lockSHA)
	err := command.Run()
	if err == nil {
		return 0
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return exit.ExitCode()
	}
	t.Fatal(err)
	return -1
}

func formalGLMRegisteredPhase20JobWorkerTestRewriteHeartbeatV1(
	t testing.TB, controller *formalGLMRegisteredPhase20JobWorkerControllerV1,
	counter uint64, at time.Time, pid int,
) {
	t.Helper()
	controller.mu.Lock()
	defer controller.mu.Unlock()
	lock, err := controller.metadata.acquireRelayLockV1()
	if err != nil {
		t.Fatal(err)
	}
	defer controller.metadata.releaseRelayLockV1(lock)
	record := controller.heartbeatRecordV1(counter, at, pid)
	if err := controller.commitHeartbeatLockedV1(record); err != nil {
		t.Fatal(err)
	}
}

func formalGLMRegisteredPhase20JobWorkerTestReplaceHeartbeatV1(
	t testing.TB, controller *formalGLMRegisteredPhase20JobWorkerControllerV1,
	record formalGLMRegisteredPhase20JobWorkerHeartbeatRecordV1,
) {
	t.Helper()
	controller.mu.Lock()
	defer controller.mu.Unlock()
	lock, err := controller.metadata.acquireRelayLockV1()
	if err != nil {
		t.Fatal(err)
	}
	defer controller.metadata.releaseRelayLockV1(lock)
	encoded, err := controller.metadata.workerSignHeartbeatV1(record)
	if err == nil {
		err = controller.metadata.replaceRecordV1(
			formalGLMRegisteredPhase20JobWorkerHeartbeatFileV1, encoded)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func formalGLMRegisteredPhase20JobWorkerTestCrashV1(
	t testing.TB, controller *formalGLMRegisteredPhase20JobWorkerControllerV1,
) {
	t.Helper()
	controller.mu.Lock()
	if controller.closed {
		controller.mu.Unlock()
		return
	}
	controller.closed = true
	formalGLMRegisteredPhase20JobWorkerReleaseLifetimeLockV1(
		controller.ownerLock)
	controller.ownerLock = nil
	transport := controller.transport
	controller.transport = nil
	metadata := controller.metadata
	controller.metadata = nil
	if controller.closeDone != nil {
		close(controller.closeDone)
	}
	controller.mu.Unlock()
	if transport != nil {
		_ = transport.Close()
	}
	if metadata != nil {
		_ = metadata.CloseRelayV1()
	}
}

func formalGLMRegisteredPhase20JobWorkerTestAssertRelayHealthyV1(
	t testing.TB, fixture *formalGLMRegisteredPhase20JobWorkerTestFixtureV1,
) {
	t.Helper()
	store, err := openFormalGLMRegisteredPhase20JobTransportRelayStoreV1(
		fixture.attempts, fixture.jobKeys, fixture.proposal,
		fixture.accept, fixture.epoch)
	if err != nil {
		t.Fatal(err)
	}
	defer store.CloseRelayV1()
	lock, err := store.acquireRelayLockV1()
	if err != nil {
		t.Fatal(err)
	}
	defer store.releaseRelayLockV1(lock)
	state, err := store.loadRelayStateLockedV1()
	if err != nil || state.State == formalGLMRegisteredPhase20JobFailedClosedV1 {
		t.Fatalf("worker recovery poisoned relay state: %+v / %v", state, err)
	}
	if _, err := store.scratch.Lstat(
		formalGLMRegisteredPhase20JobRelayFailedFileV1); !os.IsNotExist(err) {
		t.Fatalf("worker recovery created relay failed anchor: %v", err)
	}
}

func formalGLMRegisteredPhase20JobWorkerTestStartPrefixV1(
	t testing.TB, fixture *formalGLMRegisteredPhase20JobWorkerTestFixtureV1,
) *formalGLMRegisteredPhase20JobWorkerControllerV1 {
	t.Helper()
	root, attemptRelative, binding, err :=
		formalGLMRegisteredPhase20JobWorkerStartBindingV1(
			fixture.attempts, fixture.jobKeys, fixture.proposal,
			fixture.accept, fixture.epoch)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := newFormalGLMRegisteredPhase20JobTransportV1(
		root, attemptRelative, binding, fixture.epoch)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := openFormalGLMRegisteredPhase20JobTransportRelayStoreV1(
		fixture.attempts, fixture.jobKeys, fixture.proposal,
		fixture.accept, fixture.epoch)
	if err != nil {
		t.Fatal(err)
	}
	lockSHA, err := formalGLMRegisteredPhase20JobWorkerOwnerLockSHA256V1(
		transport.ref.TransportSHA256)
	if err != nil {
		t.Fatal(err)
	}
	ownerLock, err := formalGLMRegisteredPhase20JobWorkerAcquireLifetimeLockV1(
		metadata.scratch, lockSHA)
	if err != nil {
		t.Fatal(err)
	}
	ownerSHA, err := formalGLMRegisteredPhase20JobWorkerRandomOwnerSHA256V1()
	if err != nil {
		t.Fatal(err)
	}
	controller := &formalGLMRegisteredPhase20JobWorkerControllerV1{
		transport: transport, metadata: metadata, ownerLock: ownerLock,
		ownerLockSHA256: lockSHA, ownerSHA256: ownerSHA,
		closeDone: make(chan struct{}),
	}
	commandLock, err := metadata.acquireRelayLockV1()
	if err == nil {
		err = metadata.workerCommitOwnerV1(ownerSHA, os.Getpid())
	}
	heartbeat := controller.heartbeatRecordV1(1, time.Now(), os.Getpid())
	if err == nil {
		err = controller.commitHeartbeatLockedV1(heartbeat)
	}
	metadata.releaseRelayLockV1(commandLock)
	if err != nil {
		t.Fatal(err)
	}
	controller.counter = 1
	controller.lastHeartbeat = heartbeat
	t.Cleanup(func() { _ = controller.Close() })
	return controller
}

func TestFormalGLMRegisteredPhase20JobWorkerControllerLifecycleAndRelayReattach(
	t *testing.T,
) {
	fixture := newFormalGLMRegisteredPhase20JobWorkerTestFixtureV1(t)
	controller := fixture.start(t)
	ref := controller.transport.ref
	if ref.ProductionReady {
		t.Fatal("worker controller claimed production readiness")
	}
	encodedController, err := json.Marshal(controller)
	if err != nil || string(encodedController) != "{}" {
		t.Fatalf("worker handle leaked JSON fields: %s / %v", encodedController, err)
	}
	observation := fixture.inspect(t)
	encodedObservation, err := json.Marshal(observation)
	if err != nil || string(encodedObservation) != "{}" ||
		observation.state != formalGLMRegisteredPhase20JobWorkerRunningV1 ||
		!observation.ownerAlive || observation.productionReady {
		t.Fatalf("unexpected live observation: %s / %+v / %v",
			encodedObservation, observation, err)
	}
	if controller.counter != 1 || controller.HeartbeatV1() != nil ||
		controller.counter != 2 {
		t.Fatalf("heartbeat counter did not advance: %d", controller.counter)
	}

	if err := controller.transport.BindPeerEpochV1(ref.TransportSHA256); err != nil {
		t.Fatal(err)
	}
	relay, err := openFormalGLMRegisteredPhase20JobTransportRelayStoreV1(
		fixture.attempts, fixture.jobKeys, fixture.proposal,
		fixture.accept, fixture.epoch)
	if err != nil {
		t.Fatal(err)
	}
	if err := relay.BindPeerEpochV1(ref); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.transport.Write([]byte("restart-relay")); err != nil {
		t.Fatal(err)
	}
	if err := controller.transport.Flush(); err != nil {
		t.Fatal(err)
	}
	first, err := relay.Poll(ref, 0)
	if err != nil || first.RelayChunk == nil {
		t.Fatalf("first relay offer failed: %+v / %v", first, err)
	}
	if err := relay.CloseRelayV1(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openFormalGLMRegisteredPhase20JobTransportRelayStoreV1(
		fixture.attempts, fixture.jobKeys, fixture.proposal,
		fixture.accept, fixture.epoch)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.CloseRelayV1()
	replay, err := reopened.Poll(ref, 0)
	if err != nil || !reflect.DeepEqual(first, replay) {
		t.Fatalf("one-shot relay did not replay exactly: %+v / %+v / %v",
			first, replay, err)
	}
	if controller.transport == nil || controller.transport.spool == nil {
		t.Fatal("relay reopening displaced the sole worker spool owner")
	}

	if _, err := startFormalGLMRegisteredPhase20JobWorkerControllerV1(
		fixture.attempts, fixture.jobKeys, fixture.proposal,
		fixture.accept, fixture.epoch); err == nil {
		t.Fatal("second owner reopened the burned epoch")
	}
	if code := formalGLMRegisteredPhase20JobWorkerTestRunLockHelperV1(
		t, controller.transport.scratchPath, controller.ownerLockSHA256); code != 41 {
		t.Fatalf("subprocess acquired live owner lock: exit=%d", code)
	}
	slotPath, lockSHA, metadata := controller.metadata.scratchPath,
		controller.ownerLockSHA256, controller.metadata
	if err := controller.Close(); err != nil || controller.Close() != nil {
		t.Fatalf("idempotent normal Close failed: %v", err)
	}
	if controller.HeartbeatV1() == nil || controller.counter != 0 ||
		controller.ownerSHA256 != "" || controller.ownerLockSHA256 != "" ||
		!bytes.Equal(metadata.macKey[:], make([]byte, len(metadata.macKey))) {
		t.Fatal("closed controller retained authority or heartbeat capability")
	}
	if code := formalGLMRegisteredPhase20JobWorkerTestRunLockHelperV1(
		t, slotPath, lockSHA); code != 0 {
		t.Fatalf("subprocess could not acquire released owner lock: exit=%d", code)
	}
	exited := fixture.inspect(t)
	if exited.state != formalGLMRegisteredPhase20JobWorkerExitedV1 ||
		exited.ownerAlive || !exited.cleanExit {
		t.Fatalf("normal owner exit was not durable: %+v", exited)
	}
}

func TestFormalGLMRegisteredPhase20JobWorkerControllerHeartbeatRecovery(
	t *testing.T,
) {
	t.Run("pid-is-diagnostic", func(t *testing.T) {
		fixture := newFormalGLMRegisteredPhase20JobWorkerTestFixtureV1(t)
		controller := fixture.start(t)
		formalGLMRegisteredPhase20JobWorkerTestRewriteHeartbeatV1(
			t, controller, controller.counter+1, time.Now(), 1)
		controller.counter++
		observation := fixture.inspect(t)
		if observation.state != formalGLMRegisteredPhase20JobWorkerRunningV1 ||
			!observation.ownerAlive {
			t.Fatalf("diagnostic PID changed liveness: %+v", observation)
		}
	})

	t.Run("stale-requests-abort-without-takeover", func(t *testing.T) {
		fixture := newFormalGLMRegisteredPhase20JobWorkerTestFixtureV1(t)
		controller := fixture.start(t)
		formalGLMRegisteredPhase20JobWorkerTestRewriteHeartbeatV1(
			t, controller, controller.counter+1,
			time.Now().Add(-2*formalGLMRegisteredPhase20JobWorkerHeartbeatTTLV1),
			os.Getpid())
		controller.counter++
		observation := fixture.inspect(t)
		if observation.state != formalGLMRegisteredPhase20JobWorkerAbortRequestedV1 ||
			observation.ownerAlive {
			t.Fatalf("stale locked owner was not fenced: %+v", observation)
		}
		if !formalGLMRegisteredPhase20JobTransportAbortValidV1(
			controller.metadata.scratch) {
			t.Fatal("stale heartbeat did not signal the sole spool owner")
		}
		if _, err := formalGLMRegisteredPhase20JobWorkerAcquireLifetimeLockV1(
			controller.metadata.scratch, controller.ownerLockSHA256); err == nil {
			t.Fatal("stale heartbeat authorized owner takeover")
		}
		formalGLMRegisteredPhase20JobWorkerTestAssertRelayHealthyV1(t, fixture)
		if err := controller.Close(); err != nil {
			t.Fatal(err)
		}
		exited := fixture.inspect(t)
		if exited.state != formalGLMRegisteredPhase20JobWorkerExitedV1 ||
			exited.cleanExit {
			t.Fatalf("abort dominated a later owner exit: %+v", exited)
		}
	})

	t.Run("plain-abort-stalls-without-relay-failure", func(t *testing.T) {
		fixture := newFormalGLMRegisteredPhase20JobWorkerTestFixtureV1(t)
		controller := fixture.start(t)
		if err := formalGLMRegisteredPhase20JobTransportSignalAbortV1(
			controller.metadata.scratch); err != nil {
			t.Fatal(err)
		}
		observation := fixture.inspect(t)
		if observation.state != formalGLMRegisteredPhase20JobWorkerStalledV1 ||
			controller.HeartbeatV1() == nil {
			t.Fatalf("plain spool abort left owner running: %+v", observation)
		}
		formalGLMRegisteredPhase20JobWorkerTestAssertRelayHealthyV1(t, fixture)
	})

	t.Run("missing-heartbeat-requests-abort", func(t *testing.T) {
		fixture := newFormalGLMRegisteredPhase20JobWorkerTestFixtureV1(t)
		controller := fixture.start(t)
		controller.mu.Lock()
		lock, err := controller.metadata.acquireRelayLockV1()
		if err == nil {
			err = controller.metadata.scratch.Remove(
				formalGLMRegisteredPhase20JobWorkerHeartbeatFileV1)
		}
		if err == nil {
			err = formalGLMPhase21RootSyncDir(controller.metadata.scratch,
				formalGLMRegisteredPhase20JobWorkerHeartbeatFileV1)
		}
		controller.metadata.releaseRelayLockV1(lock)
		controller.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		observation := fixture.inspect(t)
		if observation.state != formalGLMRegisteredPhase20JobWorkerAbortRequestedV1 {
			t.Fatalf("missing live heartbeat did not request abort: %+v", observation)
		}
		formalGLMRegisteredPhase20JobWorkerTestAssertRelayHealthyV1(t, fixture)
	})

	t.Run("counter-rollback-and-fork-stop-owner", func(t *testing.T) {
		fixture := newFormalGLMRegisteredPhase20JobWorkerTestFixtureV1(t)
		controller := fixture.start(t)
		first := controller.lastHeartbeat
		if err := controller.HeartbeatV1(); err != nil {
			t.Fatal(err)
		}
		formalGLMRegisteredPhase20JobWorkerTestReplaceHeartbeatV1(
			t, controller, first)
		if err := controller.HeartbeatV1(); err == nil {
			t.Fatal("heartbeat rollback advanced the live owner")
		}

		forkFixture := newFormalGLMRegisteredPhase20JobWorkerTestFixtureV1(t)
		fork := forkFixture.start(t)
		sameCounter := fork.heartbeatRecordV1(
			fork.counter, time.Now().Add(time.Second), 1)
		formalGLMRegisteredPhase20JobWorkerTestReplaceHeartbeatV1(
			t, fork, sameCounter)
		if err := fork.HeartbeatV1(); err == nil {
			t.Fatal("same-counter heartbeat fork advanced the live owner")
		}
	})

	t.Run("zero-and-future-are-invalid", func(t *testing.T) {
		fixture := newFormalGLMRegisteredPhase20JobWorkerTestFixtureV1(t)
		controller := fixture.start(t)
		zero := controller.heartbeatRecordV1(0, time.Now(), os.Getpid())
		formalGLMRegisteredPhase20JobWorkerTestReplaceHeartbeatV1(
			t, controller, zero)
		observation := fixture.inspect(t)
		if observation.state !=
			formalGLMRegisteredPhase20JobWorkerInvalidDurableStateV1 {
			t.Fatalf("zero heartbeat counter was accepted: %+v", observation)
		}

		futureFixture := newFormalGLMRegisteredPhase20JobWorkerTestFixtureV1(t)
		future := futureFixture.start(t)
		formalGLMRegisteredPhase20JobWorkerTestRewriteHeartbeatV1(
			t, future, future.counter+1,
			time.Now().Add(2*formalGLMRegisteredPhase20JobWorkerHeartbeatTTLV1),
			os.Getpid())
		future.counter++
		futureObservation := futureFixture.inspect(t)
		if futureObservation.state !=
			formalGLMRegisteredPhase20JobWorkerInvalidDurableStateV1 {
			t.Fatalf("future heartbeat was accepted: %+v", futureObservation)
		}
	})

	t.Run("tamper-is-invalid-durable-state", func(t *testing.T) {
		fixture := newFormalGLMRegisteredPhase20JobWorkerTestFixtureV1(t)
		controller := fixture.start(t)
		controller.mu.Lock()
		lock, err := controller.metadata.acquireRelayLockV1()
		if err != nil {
			controller.mu.Unlock()
			t.Fatal(err)
		}
		encoded, err := controller.metadata.readRecordV1(
			formalGLMRegisteredPhase20JobWorkerHeartbeatFileV1)
		if err == nil {
			var heartbeat formalGLMRegisteredPhase20JobWorkerHeartbeatRecordV1
			err = json.Unmarshal(encoded, &heartbeat)
			heartbeat.MACSHA256 = strings.Repeat("0", 64)
			encoded, _ = json.Marshal(heartbeat)
		}
		if err == nil {
			err = controller.metadata.replaceRecordV1(
				formalGLMRegisteredPhase20JobWorkerHeartbeatFileV1, encoded)
		}
		controller.metadata.releaseRelayLockV1(lock)
		controller.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		observation := fixture.inspect(t)
		if observation.state !=
			formalGLMRegisteredPhase20JobWorkerInvalidDurableStateV1 {
			t.Fatalf("tampered heartbeat was not rejected: %+v", observation)
		}
		formalGLMRegisteredPhase20JobWorkerTestAssertRelayHealthyV1(t, fixture)
	})

	t.Run("crash-never-reopens-epoch", func(t *testing.T) {
		fixture := newFormalGLMRegisteredPhase20JobWorkerTestFixtureV1(t)
		controller := fixture.start(t)
		formalGLMRegisteredPhase20JobWorkerTestCrashV1(t, controller)
		lost := fixture.inspect(t)
		if lost.state != formalGLMRegisteredPhase20JobWorkerOwnerLostV1 ||
			lost.ownerAlive || lost.cleanExit {
			t.Fatalf("crashed owner was not classified lost: %+v", lost)
		}
		if _, err := startFormalGLMRegisteredPhase20JobWorkerControllerV1(
			fixture.attempts, fixture.jobKeys, fixture.proposal,
			fixture.accept, fixture.epoch); err == nil {
			t.Fatal("owner crash reopened the same burned epoch")
		}
		formalGLMRegisteredPhase20JobWorkerTestAssertRelayHealthyV1(t, fixture)
	})
}

func TestFormalGLMRegisteredPhase20JobWorkerControllerPrefixesAndFS(
	t *testing.T,
) {
	t.Run("held-before-ready-is-starting", func(t *testing.T) {
		fixture := newFormalGLMRegisteredPhase20JobWorkerTestFixtureV1(t)
		_ = formalGLMRegisteredPhase20JobWorkerTestStartPrefixV1(t, fixture)
		starting := fixture.inspect(t)
		if starting.state != formalGLMRegisteredPhase20JobWorkerStartingV1 ||
			!starting.ownerAlive {
			t.Fatalf("start prefix was misclassified: %+v", starting)
		}
	})

	t.Run("relay-failed-is-invalid-not-running", func(t *testing.T) {
		fixture := newFormalGLMRegisteredPhase20JobWorkerTestFixtureV1(t)
		controller := fixture.start(t)
		controller.mu.Lock()
		lock, err := controller.metadata.acquireRelayLockV1()
		if err == nil {
			var state formalGLMRegisteredPhase20JobRelayStateV1
			state, err = controller.metadata.loadRelayStateLockedV1()
			if err == nil {
				err = controller.metadata.failClosedLockedV1(
					&state, errors.New("test relay failure"))
			}
		}
		controller.metadata.releaseRelayLockV1(lock)
		controller.mu.Unlock()
		if err == nil {
			t.Fatal("test relay failure did not fail closed")
		}
		observation, _ := inspectFormalGLMRegisteredPhase20JobWorkerControllerV1(
			fixture.attempts, fixture.jobKeys, fixture.proposal,
			fixture.accept, fixture.epoch)
		if observation.state !=
			formalGLMRegisteredPhase20JobWorkerInvalidDurableStateV1 {
			t.Fatalf("failed relay was reported live: %+v", observation)
		}
	})

	for _, attack := range []struct {
		name string
		run  func(*testing.T, *formalGLMRegisteredPhase20JobWorkerControllerV1)
	}{
		{"heartbeat-mode", func(t *testing.T, controller *formalGLMRegisteredPhase20JobWorkerControllerV1) {
			if err := os.Chmod(filepath.Join(controller.metadata.scratchPath,
				formalGLMRegisteredPhase20JobWorkerHeartbeatFileV1), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"owner-hardlink", func(t *testing.T, controller *formalGLMRegisteredPhase20JobWorkerControllerV1) {
			if err := os.Link(filepath.Join(controller.metadata.scratchPath,
				formalGLMRegisteredPhase20JobWorkerOwnerFileV1),
				filepath.Join(controller.metadata.scratchPath, "owner-link")); err != nil {
				t.Fatal(err)
			}
		}},
		{"ready-noncanonical", func(t *testing.T, controller *formalGLMRegisteredPhase20JobWorkerControllerV1) {
			encoded, err := controller.metadata.readRecordV1(
				formalGLMRegisteredPhase20JobWorkerReadyFileV1)
			if err != nil {
				t.Fatal(err)
			}
			if err := controller.metadata.replaceRecordV1(
				formalGLMRegisteredPhase20JobWorkerReadyFileV1,
				append(encoded, '\n')); err != nil {
				t.Fatal(err)
			}
		}},
		{"lock-hardlink", func(t *testing.T, controller *formalGLMRegisteredPhase20JobWorkerControllerV1) {
			name := "authority-lock-" + controller.ownerLockSHA256 + ".bin"
			if err := os.Link(filepath.Join(controller.metadata.scratchPath, name),
				filepath.Join(controller.metadata.scratchPath, "lock-link")); err != nil {
				t.Fatal(err)
			}
			if code := formalGLMRegisteredPhase20JobWorkerTestRunLockHelperV1(
				t, controller.metadata.scratchPath, controller.ownerLockSHA256); code != 42 {
				t.Fatalf("unsafe owner lock was reported busy: exit=%d", code)
			}
		}},
		{"lock-unlink", func(t *testing.T, controller *formalGLMRegisteredPhase20JobWorkerControllerV1) {
			name := "authority-lock-" + controller.ownerLockSHA256 + ".bin"
			if err := controller.metadata.scratch.Remove(name); err != nil {
				t.Fatal(err)
			}
			if err := formalGLMPhase21RootSyncDir(
				controller.metadata.scratch, name); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(attack.name, func(t *testing.T) {
			fixture := newFormalGLMRegisteredPhase20JobWorkerTestFixtureV1(t)
			controller := fixture.start(t)
			attack.run(t, controller)
			observation, err :=
				inspectFormalGLMRegisteredPhase20JobWorkerControllerV1(
					fixture.attempts, fixture.jobKeys, fixture.proposal,
					fixture.accept, fixture.epoch)
			if err == nil && observation.state !=
				formalGLMRegisteredPhase20JobWorkerInvalidDurableStateV1 {
				t.Fatalf("filesystem attack was accepted: %+v", observation)
			}
		})
	}

	fixture := newFormalGLMRegisteredPhase20JobWorkerTestFixtureV1(t)
	controller := fixture.start(t)
	ownerJSON, err := controller.metadata.readRecordV1(
		formalGLMRegisteredPhase20JobWorkerOwnerFileV1)
	keyHex := hex.EncodeToString(controller.metadata.macKey[:])
	keyBase64 := base64.StdEncoding.EncodeToString(controller.metadata.macKey[:])
	if err != nil || bytes.Contains(ownerJSON, []byte(fixture.rootPath)) ||
		bytes.Contains(ownerJSON, controller.metadata.macKey[:]) ||
		bytes.Contains(ownerJSON, []byte(keyHex)) ||
		bytes.Contains(ownerJSON, []byte(keyBase64)) {
		t.Fatalf("owner manifest leaked root/key material: %s / %v", ownerJSON, err)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(ownerJSON, &fields) != nil || len(fields) != 8 {
		t.Fatalf("owner manifest field allowlist changed: %v", fields)
	}
}
