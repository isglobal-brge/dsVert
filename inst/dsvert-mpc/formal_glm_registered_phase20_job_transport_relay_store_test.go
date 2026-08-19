package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const formalGLMRegisteredPhase20JobRelayLockHelperEnvV1 = "DSVERT_FORMAL_GLM_JOB_RELAY_LOCK_HELPER"

func TestFormalGLMRegisteredPhase20JobTransportRelayLockHelperProcess(
	t *testing.T,
) {
	slot := os.Getenv(formalGLMRegisteredPhase20JobRelayLockHelperEnvV1)
	if slot == "" {
		return
	}
	root, err := os.OpenRoot(slot)
	if err != nil {
		os.Exit(24)
	}
	store := &formalGLMRegisteredPhase20JobTransportRelayStoreV1{
		scratch: root,
		ref: formalGLMRegisteredPhase20JobRefV1{
			TransportSHA256: os.Getenv("DSVERT_FORMAL_GLM_JOB_RELAY_LOCK_SHA"),
		},
	}
	lock, err := store.acquireRelayLockV1()
	if err != nil {
		_ = root.Close()
		if strings.Contains(err.Error(), "lock busy") {
			os.Exit(23)
		}
		os.Exit(24)
	}
	store.releaseRelayLockV1(lock)
	_ = root.Close()
}

// Phase19 and JobKey tests cover the validating constructors. Relay cases use
// the already validated immutable K2 evidence, but always fresh roots, handles,
// signing-key clones, and storage roots so no mutable test state is shared.
func formalGLMRegisteredPhase20JobRelayTestOpenAttemptV1(
	t testing.TB, path, peer string,
	core formalGLMRegisteredPhase19AttemptTestCoreV1,
) *formalGLMRegisteredPhase19AttemptStoreV1 {
	t.Helper()
	plan := core.source.plan
	localIndex := -1
	for index, candidate := range plan.DesignatedComputePeers {
		if candidate == peer {
			localIndex = index
		}
	}
	root, err := formalGLMRegisteredPhase19OpenRockRootV1(path)
	recordSHA256, hashErr := formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase19AttemptDomainV1+"/binding-record", core.record)
	if err != nil || hashErr != nil || localIndex < 0 || localIndex > 1 {
		if root != nil {
			_ = root.Close()
		}
		t.Fatal("could not open trusted attempt fixture")
	}
	pins := make(map[string]ed25519.PublicKey,
		len(core.source.inputs.identities.public))
	for name, pin := range core.source.inputs.identities.public {
		pins[name] = append(ed25519.PublicKey(nil), pin...)
	}
	store := &formalGLMRegisteredPhase19AttemptStoreV1{
		root: root, record: core.record, contract: core.source.contract,
		recordSHA256: recordSHA256, pins: pins, localIndex: localIndex,
		signingKey: append(ed25519.PrivateKey(nil),
			core.source.inputs.identities.private[peer]...),
	}
	if err := formalGLMRegisteredPhase18TicketStoreEnsureDirV1(
		root, store.baseRelativeDirV1()); err != nil {
		store.Close()
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return store
}

func formalGLMRegisteredPhase20JobRelayTestJobKeyContextV1(
	t testing.TB, core formalGLMRegisteredPhase19AttemptTestCoreV1, peer string,
) formalGLMRegisteredPhase20JobKeyContextV1 {
	t.Helper()
	localIndex := -1
	for index, candidate := range core.source.plan.DesignatedComputePeers {
		if candidate == peer {
			localIndex = index
		}
	}
	recordSHA256, err := formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase19AttemptDomainV1+"/binding-record", core.record)
	if err != nil || localIndex < 0 || localIndex > 1 {
		t.Fatal("could not derive trusted job-key context")
	}
	return formalGLMRegisteredPhase20JobKeyContextV1{
		artifactID:                    core.record.Binding.ArtifactID,
		sourceContractCoreSHA256:      core.record.Binding.SourceContractCoreSHA256,
		sourceContractSHA256:          core.record.Binding.SourceContractSHA256,
		pinsetSHA256:                  core.record.Binding.PinsetSHA256,
		semanticRootSHA256:            core.record.Binding.SemanticRootSHA256,
		bindingRecordSHA256:           recordSHA256,
		registeredExecutionPlanSHA256: core.record.Binding.RegisteredExecutionPlanSHA256,
		localPeer:                     peer,
		localIndex:                    localIndex,
	}
}

func formalGLMRegisteredPhase20JobRelayTestOpenJobKeyContextV1(
	t testing.TB, path string, context formalGLMRegisteredPhase20JobKeyContextV1,
) *formalGLMRegisteredPhase20JobKeyProviderV1 {
	t.Helper()
	slot, slotErr := formalGLMRegisteredPhase20JobKeySlotV1(context)
	root, rootErr := formalGLMRegisteredPhase19OpenRockRootV1(path)
	if slotErr != nil || rootErr != nil {
		if root != nil {
			_ = root.Close()
		}
		t.Fatal("could not open trusted job-key fixture")
	}
	created := false
	if err := root.Mkdir(slot, 0o700); err == nil {
		created = true
	} else if !os.IsExist(err) {
		_ = root.Close()
		t.Fatal("could not burn trusted job-key fixture")
	}
	if err := root.Chmod(slot, 0o700); err != nil ||
		formalGLMPhase21RootSyncDir(root, slot) != nil ||
		formalGLMRegisteredPhase20ValidateJobKeyDirV1(root, slot) != nil {
		_ = root.Close()
		t.Fatal("could not validate trusted job-key fixture")
	}
	keyPath := filepath.Join(slot, formalGLMRegisteredPhase20JobKeyFileV1)
	var storageRoot [32]byte
	if created {
		if _, err := rand.Read(storageRoot[:]); err != nil ||
			formalGLMRegisteredPhase20JobTransportWriteInitialV1(
				root, keyPath, storageRoot[:]) != nil ||
			formalGLMPhase21RootSyncDir(root, keyPath) != nil {
			_ = root.Close()
			t.Fatal("could not persist trusted job-key fixture")
		}
	}
	loaded, err := formalGLMRegisteredPhase20ReadJobStorageRootV1(root, slot, keyPath)
	if err != nil || created && loaded != storageRoot {
		_ = root.Close()
		t.Fatal("trusted job-key fixture changed on disk")
	}
	provider := &formalGLMRegisteredPhase20JobKeyProviderV1{
		root: root, context: context, slotRelativeDir: slot,
		keyRelativePath: keyPath, storageRoot: loaded,
	}
	t.Cleanup(func() { _ = provider.Close() })
	return provider
}

func formalGLMRegisteredPhase20JobRelayTestOpenJobKeyV1(
	t testing.TB, path, peer string,
	core formalGLMRegisteredPhase19AttemptTestCoreV1,
) *formalGLMRegisteredPhase20JobKeyProviderV1 {
	t.Helper()
	context := formalGLMRegisteredPhase20JobRelayTestJobKeyContextV1(
		t, core, peer)
	return formalGLMRegisteredPhase20JobRelayTestOpenJobKeyContextV1(
		t, path, context)
}

type formalGLMRegisteredPhase20JobRelayStoreTestFixtureV1 struct {
	core     formalGLMRegisteredPhase19AttemptTestCoreV1
	rootPath string
	attempts *formalGLMRegisteredPhase19AttemptStoreV1
	jobKeys  *formalGLMRegisteredPhase20JobKeyProviderV1
	proposal formalGLMRegisteredPhase19ClaimProposalV1
	accept   formalGLMRegisteredPhase19ClaimAcceptV1
	epoch    formalGLMRegisteredPhase20JobTransportEpochV1
	owner    *formalGLMRegisteredPhase20JobTransportV1
	relay    *formalGLMRegisteredPhase20JobTransportRelayStoreV1
	slot     string
	bound    bool
}

func formalGLMRegisteredPhase20JobRelayStoreTestFixture(
	t testing.TB, _ string,
) *formalGLMRegisteredPhase20JobRelayStoreTestFixtureV1 {
	t.Helper()
	core := formalGLMRegisteredPhase19AttemptTestCoreK2(t)
	peers := core.source.plan.DesignatedComputePeers
	localRoot := filepath.Join(t.TempDir(), "local-rock")
	peerRoot := filepath.Join(t.TempDir(), "peer-rock")
	attempts := formalGLMRegisteredPhase20JobRelayTestOpenAttemptV1(
		t, localRoot, peers[0], core)
	peerAttempts := formalGLMRegisteredPhase20JobRelayTestOpenAttemptV1(
		t, peerRoot, peers[1], core)
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
	epoch := formalGLMRegisteredPhase20JobTransportEpochV1{
		Mode:        formalGLMRegisteredPhase20JobRunTransportV1,
		BasisSHA256: acceptSHA256,
	}
	jobKeys := formalGLMRegisteredPhase20JobRelayTestOpenJobKeyV1(
		t, localRoot, peers[0], core)
	binding := formalGLMRegisteredPhase20JobTransportBindingV1{
		ArtifactID:          proposal.Binding.ArtifactID,
		ReceiptSetSHA256:    core.record.Binding.ReceiptSetSHA256,
		SemanticRootSHA256:  proposal.Binding.SemanticRootSHA256,
		BindingRecordSHA256: proposal.Binding.BindingRecordSHA256,
		AttemptID:           proposal.Binding.AttemptID,
		ScheduleRootSHA256:  proposal.Binding.ScheduleRootSHA256,
		ProductionReady:     false,
	}
	attemptRelative := attempts.attemptRelativeDirV1(binding.AttemptID)
	owner, err := newFormalGLMRegisteredPhase20JobTransportV1(
		attempts.root, attemptRelative, binding, epoch)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	relay, err := openFormalGLMRegisteredPhase20JobTransportRelayStoreV1(
		attempts, jobKeys, proposal, accept, epoch)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = relay.CloseRelayV1() })
	return &formalGLMRegisteredPhase20JobRelayStoreTestFixtureV1{
		core: core, rootPath: localRoot, attempts: attempts,
		jobKeys: jobKeys, proposal: proposal,
		accept: accept, epoch: epoch, owner: owner, relay: relay,
		slot: owner.scratchPath,
	}
}

func (fixture *formalGLMRegisteredPhase20JobRelayStoreTestFixtureV1) bind(
	t testing.TB,
) {
	t.Helper()
	if fixture.bound {
		return
	}
	if err := fixture.relay.BindPeerEpochV1(fixture.owner.ref); err != nil {
		t.Fatal(err)
	}
	if err := fixture.owner.BindPeerEpochV1(
		fixture.owner.epochSHA256); err != nil {
		t.Fatal(err)
	}
	fixture.bound = true
}

func (fixture *formalGLMRegisteredPhase20JobRelayStoreTestFixtureV1) reopen(
	t testing.TB,
) *formalGLMRegisteredPhase20JobTransportRelayStoreV1 {
	t.Helper()
	relay, err := openFormalGLMRegisteredPhase20JobTransportRelayStoreV1(
		fixture.attempts, fixture.jobKeys, fixture.proposal,
		fixture.accept, fixture.epoch)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = relay.CloseRelayV1() })
	return relay
}

func TestFormalGLMRegisteredPhase20JobTransportRelayStoreReopenAndPrivacy(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase20JobRelayStoreTestFixture(t, "reopen")
	preBind := formalGLMRegisteredPhase20JobTransportTestChunkV1(
		fixture.owner.ref, 0, []byte("pre-bind"))
	if _, err := fixture.relay.Poll(fixture.owner.ref, 0); err == nil {
		t.Fatal("Poll accepted bytes before durable peer bind")
	}
	if _, err := fixture.relay.Relay(fixture.owner.ref, preBind); err == nil {
		t.Fatal("Relay accepted bytes before durable peer bind")
	}
	fixture.bind(t)
	if err := fixture.relay.BindPeerEpochV1(fixture.owner.ref); err != nil {
		t.Fatalf("exact peer-bind replay failed: %v", err)
	}

	payload := []byte("durable-outbound")
	if _, err := fixture.owner.Write(payload); err != nil {
		t.Fatal(err)
	}
	if pending, err := fixture.relay.Poll(fixture.owner.ref, 0); err != nil || pending.RelayChunk != nil {
		t.Fatalf("Poll exposed worker-pending RAM: %+v / %v", pending, err)
	}
	if err := fixture.owner.Flush(); err != nil {
		t.Fatal(err)
	}
	first, err := fixture.relay.Poll(fixture.owner.ref, 0)
	if err != nil || first.RelayChunk == nil ||
		!bytes.Equal(first.RelayChunk.Payload, payload) {
		t.Fatalf("missing first durable offer: %+v / %v", first, err)
	}
	if first.ProductionReady || first.RelayChunk.TransportSHA256 !=
		fixture.owner.ref.TransportSHA256 || first.RelayChunk.JobSHA256 !=
		fixture.owner.ref.JobSHA256 || first.RelayChunk.PayloadSHA256 !=
		formalGLMRegisteredPhase20JobTransportTestChunkV1(
			fixture.owner.ref, 0, payload).PayloadSHA256 {
		t.Fatal("relay store emitted a production or cross-epoch offer")
	}
	if _, err := fixture.owner.Write([]byte("worker-pending")); err != nil {
		t.Fatal(err)
	}
	headBeforeClose, err := exactGCReadOffset(
		filepath.Join(fixture.slot, "outbound.head"))
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.relay.CloseRelayV1(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(fixture.slot, "abort")); !os.IsNotExist(err) {
		t.Fatal("CloseRelay created or changed the worker abort marker")
	}
	headAfterClose, err := exactGCReadOffset(
		filepath.Join(fixture.slot, "outbound.head"))
	if err != nil || headAfterClose != headBeforeClose {
		t.Fatalf("CloseRelay flushed or closed worker-pending bytes: %d/%d/%v",
			headBeforeClose, headAfterClose, err)
	}
	if err := fixture.owner.Flush(); err != nil {
		t.Fatalf("CloseRelay affected the worker spool: %v", err)
	}

	reopened := fixture.reopen(t)
	replay, err := reopened.Poll(fixture.owner.ref, 0)
	if err != nil || !reflect.DeepEqual(replay.RelayChunk, first.RelayChunk) {
		t.Fatalf("one-shot reopen changed the offer: %+v / %v", replay, err)
	}
	ack := first.RelayChunk.Offset + int64(len(first.RelayChunk.Payload))
	if _, err := reopened.Poll(fixture.owner.ref, ack); err != nil {
		t.Fatal(err)
	}

	encoded, err := json.Marshal(reopened)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("relay handle exposed private state: %s / %v", encoded, err)
	}
	typ := reflect.TypeOf(reopened).Elem()
	spoolType := reflect.TypeOf((*exactGCSpoolRW)(nil))
	for index := 0; index < typ.NumField(); index++ {
		if typ.Field(index).IsExported() || typ.Field(index).Type == spoolType ||
			strings.Contains(strings.ToLower(typ.Field(index).Name), "spool") {
			t.Fatalf("relay handle owns exposed or worker-spool state: %s",
				typ.Field(index).Name)
		}
	}
}

func TestFormalGLMRegisteredPhase20JobTransportRelayStoreReplayForkAndLock(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase20JobRelayStoreTestFixture(t, "replay")
	fixture.bind(t)
	statePath := filepath.Join(fixture.slot,
		formalGLMRegisteredPhase20JobRelayStateFileV1)
	rollback, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	staleLock, err := fixture.relay.acquireRelayLockV1()
	if err != nil {
		t.Fatal(err)
	}
	stale, err := fixture.relay.loadRelayStateLockedV1()
	fixture.relay.releaseRelayLockV1(staleLock)
	if err != nil {
		t.Fatal(err)
	}
	second := fixture.reopen(t)
	chunk := formalGLMRegisteredPhase20JobTransportTestChunkV1(
		fixture.owner.ref, 0, []byte("inbound-one"))
	accepted, err := fixture.relay.Relay(fixture.owner.ref, chunk)
	if err != nil {
		t.Fatal(err)
	}
	staleLock, err = fixture.relay.acquireRelayLockV1()
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.relay.commitRelayStateLockedV1(&stale); err == nil {
		t.Fatal("stale relay-state generation won CAS")
	}
	fixture.relay.releaseRelayLockV1(staleLock)
	if replay, err := second.Relay(fixture.owner.ref, chunk); err != nil || replay != accepted {
		t.Fatalf("competing handle changed exact replay: %d / %v", replay, err)
	}
	fork := formalGLMRegisteredPhase20JobTransportTestChunkV1(
		fixture.owner.ref, 0, []byte("inbound-two"))
	if _, err := second.Relay(fixture.owner.ref, fork); err == nil {
		t.Fatal("same-offset fork was accepted")
	}
	if err := os.WriteFile(statePath, rollback, 0o600); err != nil {
		t.Fatal(err)
	}
	if !formalGLMRegisteredPhase20JobTransportAbortValidV1(fixture.relay.scratch) {
		t.Fatal("protocol fork did not abort the sole worker")
	}
	failed := fixture.reopen(t)
	wrongRef := fixture.owner.ref
	wrongRef.ArtifactID = formalGLMRegisteredPhase20JobTransportTestSHA256V1(
		"wrong-failed-ref")
	if _, err := failed.Poll(wrongRef, 0); err == nil {
		t.Fatal("failed state leaked its cursor to an unrelated JobRef")
	}
	result, err := failed.Poll(fixture.owner.ref, 0)
	if err != nil || result.State != formalGLMRegisteredPhase20JobFailedClosedV1 ||
		result.RelayChunk != nil {
		t.Fatalf("failed_closed was not durable and absorbing: %+v / %v",
			result, err)
	}

	lockedFixture := formalGLMRegisteredPhase20JobRelayStoreTestFixture(
		t, "lock")
	lockedFixture.bind(t)
	competing := lockedFixture.reopen(t)
	lock, err := lockedFixture.relay.acquireRelayLockV1()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { lockedFixture.relay.releaseRelayLockV1(lock) }()
	done := make(chan error, 1)
	go func() {
		_, err := competing.Poll(lockedFixture.owner.ref, 0)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("competing relay command acquired the nonblocking lock")
		}
	case <-time.After(time.Second):
		t.Fatal("relay flock blocked instead of failing immediately")
	}
	runHelper := func() ([]byte, error) {
		command := exec.Command(os.Args[0],
			"-test.run=^TestFormalGLMRegisteredPhase20JobTransportRelayLockHelperProcess$")
		command.Env = append(os.Environ(),
			formalGLMRegisteredPhase20JobRelayLockHelperEnvV1+"="+lockedFixture.slot,
			"DSVERT_FORMAL_GLM_JOB_RELAY_LOCK_SHA="+
				lockedFixture.owner.ref.TransportSHA256)
		return command.CombinedOutput()
	}
	output, runErr := runHelper()
	exitErr, ok := runErr.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 23 {
		t.Fatalf("subprocess relay lock was not exclusive: %v / %q", runErr, output)
	}
	lockedFixture.relay.releaseRelayLockV1(lock)
	lock = nil
	if output, runErr = runHelper(); runErr != nil {
		t.Fatalf("subprocess relay lock failed after release: %v / %q", runErr, output)
	}
}

func TestFormalGLMRegisteredPhase20JobTransportRelayStoreTrustContext(
	t *testing.T,
) {
	for _, test := range []string{"wrong-peer", "wrong-root", "wrong-context"} {
		t.Run(test, func(t *testing.T) {
			fixture := formalGLMRegisteredPhase20JobRelayStoreTestFixture(t, test)
			peers := fixture.core.source.plan.DesignatedComputePeers
			var provider *formalGLMRegisteredPhase20JobKeyProviderV1
			switch test {
			case "wrong-peer":
				provider = formalGLMRegisteredPhase20JobRelayTestOpenJobKeyV1(
					t, fixture.rootPath, peers[1], fixture.core)
			case "wrong-root":
				provider = formalGLMRegisteredPhase20JobRelayTestOpenJobKeyV1(
					t, filepath.Join(t.TempDir(), "other-rock"), peers[0], fixture.core)
			case "wrong-context":
				alien := formalGLMRegisteredPhase20JobRelayTestJobKeyContextV1(
					t, fixture.core, peers[0])
				alien.bindingRecordSHA256 =
					formalGLMRegisteredPhase20JobTransportTestSHA256V1("wrong-context")
				provider = formalGLMRegisteredPhase20JobRelayTestOpenJobKeyContextV1(
					t, fixture.rootPath, alien)
				provider.mu.Lock()
				validErr := provider.validateLocked()
				provider.mu.Unlock()
				if validErr != nil {
					t.Fatalf("fresh alien provider was internally invalid: %v", validErr)
				}
			}
			opened, err := openFormalGLMRegisteredPhase20JobTransportRelayStoreV1(
				fixture.attempts, provider, fixture.proposal,
				fixture.accept, fixture.epoch)
			if err == nil {
				_ = opened.CloseRelayV1()
				t.Fatalf("%s trust context was accepted", test)
			}
		})
	}
	fixture := formalGLMRegisteredPhase20JobRelayStoreTestFixture(t, "epoch-basis")
	binding := formalGLMRegisteredPhase20JobTransportBindingV1{
		ArtifactID:          fixture.proposal.Binding.ArtifactID,
		ReceiptSetSHA256:    fixture.core.record.Binding.ReceiptSetSHA256,
		SemanticRootSHA256:  fixture.proposal.Binding.SemanticRootSHA256,
		BindingRecordSHA256: fixture.proposal.Binding.BindingRecordSHA256,
		AttemptID:           fixture.proposal.Binding.AttemptID,
		ScheduleRootSHA256:  fixture.proposal.Binding.ScheduleRootSHA256,
	}
	abandon := fixture.epoch
	abandon.Mode = formalGLMRegisteredPhase20JobAbandonTransportV1
	runJob, runTransport, err := formalGLMRegisteredPhase20JobTransportIdentityV1(
		binding, fixture.epoch)
	abandonJob, abandonTransport, abandonErr :=
		formalGLMRegisteredPhase20JobTransportIdentityV1(binding, abandon)
	if err != nil || abandonErr != nil || runJob != abandonJob ||
		runTransport == abandonTransport {
		t.Fatal("run and abandon were not domain-separated under the signed accept")
	}
	tampered := fixture.epoch
	tampered.BasisSHA256 = formalGLMRegisteredPhase20JobTransportTestSHA256V1(
		"local-counter")
	if opened, err := openFormalGLMRegisteredPhase20JobTransportRelayStoreV1(
		fixture.attempts, fixture.jobKeys, fixture.proposal,
		fixture.accept, tampered); err == nil {
		_ = opened.CloseRelayV1()
		t.Fatal("unsigned local epoch basis was accepted")
	}
}

func TestFormalGLMRegisteredPhase20JobTransportRelayStoreCrashRecovery(
	t *testing.T,
) {
	for _, crash := range []string{"pending", "published", "consumed"} {
		t.Run("inbound-"+crash, func(t *testing.T) {
			fixture := formalGLMRegisteredPhase20JobRelayStoreTestFixture(t, crash)
			fixture.bind(t)
			chunk := formalGLMRegisteredPhase20JobTransportTestChunkV1(
				fixture.owner.ref, 0, []byte("crash-inbound"))
			lock, err := fixture.relay.acquireRelayLockV1()
			if err != nil {
				t.Fatal(err)
			}
			state, err := fixture.relay.loadRelayStateLockedV1()
			if err != nil {
				t.Fatal(err)
			}
			state.PendingInbound = formalGLMRegisteredPhase20JobRelayRangeFromChunkV1(
				chunk)
			if err := fixture.relay.commitRelayStateLockedV1(&state); err != nil {
				t.Fatal(err)
			}
			if crash != "pending" {
				if _, err := exactGCPublishSegment(
					filepath.Join(fixture.slot, "inbound.segments"),
					chunk.Offset, chunk.Payload); err != nil {
					t.Fatal(err)
				}
			}
			var staleAck int64
			if crash == "consumed" {
				staleAck, err = fixture.relay.readOffsetLockedV1("inbound.ack")
				if err != nil {
					t.Fatal(err)
				}
				end := int64(len(chunk.Payload))
				if err := exactGCWriteOffset(
					filepath.Join(fixture.slot, "inbound.ack"), end); err != nil {
					t.Fatal(err)
				}
				segments, err := exactGCListSegments(
					filepath.Join(fixture.slot, "inbound.segments"))
				if err != nil || len(segments) != 1 {
					t.Fatalf("missing crash segment: %+v / %v", segments, err)
				}
				if err := fixture.relay.segmentRoots[0].Remove(
					segments[0].name); err != nil {
					t.Fatal(err)
				}
				if err := fixture.relay.syncSegmentDirV1(0); err != nil {
					t.Fatal(err)
				}
				ack, consumed, retryErr := fixture.relay.
					stableInboundAckFromSnapshotLockedV1(&state, staleAck)
				if retryErr != nil || !consumed || ack != end {
					t.Fatalf("ack advance was not retried: %d / %v / %v",
						ack, consumed, retryErr)
				}
			}
			fixture.relay.releaseRelayLockV1(lock)
			if err := fixture.relay.CloseRelayV1(); err != nil {
				t.Fatal(err)
			}
			reopened := fixture.reopen(t)
			accepted, err := reopened.Relay(fixture.owner.ref, chunk)
			if err != nil || accepted != int64(len(chunk.Payload)) {
				t.Fatalf("%s prefix did not recover exactly: %d / %v",
					crash, accepted, err)
			}
		})
	}

	t.Run("pending-fork", func(t *testing.T) {
		fixture := formalGLMRegisteredPhase20JobRelayStoreTestFixture(t, "pending-fork")
		fixture.bind(t)
		first := formalGLMRegisteredPhase20JobTransportTestChunkV1(
			fixture.owner.ref, 0, []byte("first"))
		lock, err := fixture.relay.acquireRelayLockV1()
		if err != nil {
			t.Fatal(err)
		}
		state, err := fixture.relay.loadRelayStateLockedV1()
		if err != nil {
			t.Fatal(err)
		}
		state.PendingInbound = formalGLMRegisteredPhase20JobRelayRangeFromChunkV1(first)
		if err := fixture.relay.commitRelayStateLockedV1(&state); err != nil {
			t.Fatal(err)
		}
		fixture.relay.releaseRelayLockV1(lock)
		fork := formalGLMRegisteredPhase20JobTransportTestChunkV1(
			fixture.owner.ref, 0, []byte("second"))
		if _, err := fixture.relay.Relay(fixture.owner.ref, fork); err == nil {
			t.Fatal("different payload replaced durable pending inbound")
		}
	})

	t.Run("offer-and-ack", func(t *testing.T) {
		fixture := formalGLMRegisteredPhase20JobRelayStoreTestFixture(t, "offer")
		fixture.bind(t)
		payload := []byte("offer-before-response")
		if _, err := fixture.owner.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := fixture.owner.Flush(); err != nil {
			t.Fatal(err)
		}
		offer, err := fixture.relay.Poll(fixture.owner.ref, 0)
		if err != nil || offer.RelayChunk == nil {
			t.Fatalf("missing committed offer: %+v / %v", offer, err)
		}
		end := offer.RelayChunk.Offset + int64(len(offer.RelayChunk.Payload))
		if err := fixture.relay.CloseRelayV1(); err != nil {
			t.Fatal(err)
		}
		reopened := fixture.reopen(t)
		replay, err := reopened.Poll(fixture.owner.ref, 0)
		if err != nil || !reflect.DeepEqual(replay.RelayChunk, offer.RelayChunk) {
			t.Fatalf("offer CAS did not survive lost response: %+v / %v", replay, err)
		}
		lock, err := reopened.acquireRelayLockV1()
		if err != nil {
			t.Fatal(err)
		}
		if err := reopened.writeOffsetLockedV1("outbound.ack", end); err != nil {
			t.Fatal(err)
		}
		reopened.releaseRelayLockV1(lock)
		if err := reopened.CloseRelayV1(); err != nil {
			t.Fatal(err)
		}
		reconciled := fixture.reopen(t)
		result, err := reconciled.Poll(fixture.owner.ref, end)
		if err != nil || result.RelayChunk != nil {
			t.Fatalf("offset/state prefix did not reconcile: %+v / %v", result, err)
		}
		segments, err := exactGCListSegments(
			filepath.Join(fixture.slot, "outbound.segments"))
		if err != nil || len(segments) != 0 {
			t.Fatalf("ack cleanup was not resumed: %+v / %v", segments, err)
		}
		if _, err := exactGCPublishSegment(
			filepath.Join(fixture.slot, "outbound.segments"), 0, payload); err != nil {
			t.Fatal(err)
		}
		if err := reconciled.CloseRelayV1(); err != nil {
			t.Fatal(err)
		}
		_ = fixture.reopen(t)
		segments, err = exactGCListSegments(
			filepath.Join(fixture.slot, "outbound.segments"))
		if err != nil || len(segments) != 0 {
			t.Fatalf("state-committed cleanup prefix was not resumed: %+v / %v",
				segments, err)
		}
	})

	t.Run("bounded-crash-temps", func(t *testing.T) {
		fixture := formalGLMRegisteredPhase20JobRelayStoreTestFixture(t, "temps")
		fixture.bind(t)
		names := func(path string) []string {
			entries, err := os.ReadDir(path)
			if err != nil {
				t.Fatal(err)
			}
			result := make([]string, len(entries))
			for index := range entries {
				result[index] = entries[index].Name()
			}
			return result
		}
		rootBefore := names(fixture.slot)
		inboundPath := filepath.Join(fixture.slot, "inbound.segments")
		inboundBefore := names(inboundPath)
		if err := fixture.relay.CloseRelayV1(); err != nil {
			t.Fatal(err)
		}
		for iteration := 0; iteration < 8; iteration++ {
			for _, name := range []string{
				formalGLMRegisteredPhase20JobRelayStateFileV1 + ".next",
				formalGLMRegisteredPhase20JobPeerBindFileV1 + ".next",
				formalGLMRegisteredPhase20JobRelayFailedFileV1 + ".next",
				"outbound.ack.next",
			} {
				if err := formalGLMRegisteredPhase20JobTransportWriteInitialV1(
					fixture.owner.scratch, name, []byte("partial")); err != nil {
					t.Fatal(err)
				}
			}
			if err := formalGLMRegisteredPhase20JobTransportWriteInitialV1(
				fixture.owner.segmentRoots[0],
				formalGLMRegisteredPhase20JobRelayInboundNextV1,
				[]byte("partial")); err != nil {
				t.Fatal(err)
			}
			if err := formalGLMPhase21RootSyncDir(
				fixture.owner.scratch, formalGLMRegisteredPhase20JobRelayStateFileV1); err != nil {
				t.Fatal(err)
			}
			if err := formalGLMPhase21RootSyncDir(
				fixture.owner.segmentRoots[0], "entry"); err != nil {
				t.Fatal(err)
			}
			reopened := fixture.reopen(t)
			if err := reopened.CloseRelayV1(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(names(fixture.slot), rootBefore) ||
				!reflect.DeepEqual(names(inboundPath), inboundBefore) {
				t.Fatalf("crash temporaries grew durable state at iteration %d", iteration)
			}
		}
	})
}

func TestFormalGLMRegisteredPhase20JobTransportRelayStoreTamperAndFilesystem(
	t *testing.T,
) {
	t.Run("noncanonical", func(t *testing.T) {
		fixture := formalGLMRegisteredPhase20JobRelayStoreTestFixture(t, "noncanonical")
		statePath := filepath.Join(fixture.slot,
			formalGLMRegisteredPhase20JobRelayStateFileV1)
		encoded, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(statePath, append(encoded, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := openFormalGLMRegisteredPhase20JobTransportRelayStoreV1(
			fixture.attempts, fixture.jobKeys, fixture.proposal,
			fixture.accept, fixture.epoch); err == nil {
			t.Fatal("noncanonical relay state was accepted")
		}
	})

	t.Run("mac", func(t *testing.T) {
		fixture := formalGLMRegisteredPhase20JobRelayStoreTestFixture(t, "mac")
		statePath := filepath.Join(fixture.slot,
			formalGLMRegisteredPhase20JobRelayStateFileV1)
		encoded, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		var state formalGLMRegisteredPhase20JobRelayStateV1
		if err := json.Unmarshal(encoded, &state); err != nil {
			t.Fatal(err)
		}
		state.MACSHA256 = formalGLMRegisteredPhase20JobTransportTestSHA256V1(
			"wrong-state-mac")
		tampered, err := json.Marshal(state)
		if err != nil || os.WriteFile(statePath, tampered, 0o600) != nil {
			t.Fatal("could not write canonical MAC tamper")
		}
		if _, err := openFormalGLMRegisteredPhase20JobTransportRelayStoreV1(
			fixture.attempts, fixture.jobKeys, fixture.proposal,
			fixture.accept, fixture.epoch); err == nil {
			t.Fatal("canonical state with invalid MAC was accepted")
		}
	})

	t.Run("peer-bind-mac", func(t *testing.T) {
		fixture := formalGLMRegisteredPhase20JobRelayStoreTestFixture(t, "peer-mac")
		fixture.bind(t)
		path := filepath.Join(fixture.slot,
			formalGLMRegisteredPhase20JobPeerBindFileV1)
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var record formalGLMRegisteredPhase20JobPeerBindRecordV1
		if err := json.Unmarshal(encoded, &record); err != nil {
			t.Fatal(err)
		}
		record.MACSHA256 = formalGLMRegisteredPhase20JobTransportTestSHA256V1(
			"wrong-peer-bind-mac")
		tampered, err := json.Marshal(record)
		if err != nil || os.WriteFile(path, tampered, 0o600) != nil {
			t.Fatal("could not write peer-bind MAC tamper")
		}
		if _, err := fixture.relay.Poll(fixture.owner.ref, 0); err == nil {
			t.Fatal("tampered immutable peer bind was accepted")
		}
	})

	t.Run("offer-beyond-head", func(t *testing.T) {
		fixture := formalGLMRegisteredPhase20JobRelayStoreTestFixture(t, "bad-offer")
		fixture.bind(t)
		lock, err := fixture.relay.acquireRelayLockV1()
		if err != nil {
			t.Fatal(err)
		}
		state, err := fixture.relay.loadRelayStateLockedV1()
		if err != nil {
			t.Fatal(err)
		}
		state.LastOffer = &formalGLMRegisteredPhase20JobRelayRangeV1{
			Start: 0, End: 1,
			PayloadSHA256: formalGLMRegisteredPhase20JobTransportTestSHA256V1("x"),
		}
		if err := fixture.relay.commitRelayStateLockedV1(&state); err != nil {
			t.Fatal(err)
		}
		fixture.relay.releaseRelayLockV1(lock)
		if _, err := openFormalGLMRegisteredPhase20JobTransportRelayStoreV1(
			fixture.attempts, fixture.jobKeys, fixture.proposal,
			fixture.accept, fixture.epoch); err == nil {
			t.Fatal("MAC-valid offer beyond durable outbound.head was accepted")
		}
	})

	for _, attack := range []string{
		"mode", "hardlink", "bind-mode", "bind-hardlink", "bind-noncanonical",
		"lock-mode", "lock-hardlink", "segment-dir-swap",
	} {
		t.Run(attack, func(t *testing.T) {
			fixture := formalGLMRegisteredPhase20JobRelayStoreTestFixture(t, attack)
			fixture.bind(t)
			statePath := filepath.Join(fixture.slot,
				formalGLMRegisteredPhase20JobRelayStateFileV1)
			switch attack {
			case "mode":
				if err := os.Chmod(statePath, 0o400); err != nil {
					t.Fatal(err)
				}
				defer os.Chmod(statePath, 0o600)
			case "hardlink":
				linked := filepath.Join(fixture.slot, "relay-state-link")
				if err := os.Link(statePath, linked); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(linked)
			case "bind-mode":
				path := filepath.Join(fixture.slot,
					formalGLMRegisteredPhase20JobPeerBindFileV1)
				if err := os.Chmod(path, 0o400); err != nil {
					t.Fatal(err)
				}
				defer os.Chmod(path, 0o600)
			case "bind-hardlink":
				path := filepath.Join(fixture.slot,
					formalGLMRegisteredPhase20JobPeerBindFileV1)
				linked := filepath.Join(fixture.slot, "peer-bind-link")
				if err := os.Link(path, linked); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(linked)
			case "bind-noncanonical":
				path := filepath.Join(fixture.slot,
					formalGLMRegisteredPhase20JobPeerBindFileV1)
				encoded, err := os.ReadFile(path)
				if err != nil || os.WriteFile(path, append(encoded, '\n'), 0o600) != nil {
					t.Fatal("could not write noncanonical peer bind")
				}
			case "lock-mode":
				path := filepath.Join(fixture.slot, "authority-lock-"+
					fixture.owner.ref.TransportSHA256+".bin")
				if err := os.Chmod(path, 0o400); err != nil {
					t.Fatal(err)
				}
				defer os.Chmod(path, 0o600)
			case "lock-hardlink":
				path := filepath.Join(fixture.slot, "authority-lock-"+
					fixture.owner.ref.TransportSHA256+".bin")
				linked := filepath.Join(fixture.slot, "relay-lock-link")
				if err := os.Link(path, linked); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(linked)
			case "segment-dir-swap":
				original := filepath.Join(fixture.slot, "inbound.segments")
				moved := original + "-moved"
				if err := os.Rename(original, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(original, 0o700); err != nil {
					t.Fatal(err)
				}
				defer func() {
					_ = os.Remove(original)
					_ = os.Rename(moved, original)
				}()
			}
			if _, err := fixture.relay.Poll(fixture.owner.ref, 0); err == nil {
				t.Fatalf("%s filesystem attack was accepted", attack)
			}
		})
	}
}
