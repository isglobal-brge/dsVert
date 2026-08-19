package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

type formalGLMRegisteredPhase20JobControlTestFixtureV1 struct {
	core     formalGLMRegisteredPhase19AttemptTestCoreV1
	roots    [2]string
	attempts [2]*formalGLMRegisteredPhase19AttemptStoreV1
	jobKeys  [2]*formalGLMRegisteredPhase20JobKeyProviderV1
	controls [2]*formalGLMRegisteredPhase20JobControlV1
	start    formalGLMRegisteredPhase20JobStartV1
}

func newFormalGLMRegisteredPhase20JobControlTestFixtureV1(
	t testing.TB,
) *formalGLMRegisteredPhase20JobControlTestFixtureV1 {
	t.Helper()
	fixture := &formalGLMRegisteredPhase20JobControlTestFixtureV1{
		core: formalGLMRegisteredPhase19AttemptTestCoreK2(t),
	}
	fixture.start = formalGLMRegisteredPhase20JobStartV1{
		ArtifactID:       fixture.core.record.Binding.ArtifactID,
		ReceiptSetSHA256: fixture.core.record.Binding.ReceiptSetSHA256,
	}
	for index := range 2 {
		fixture.roots[index] = filepath.Join(
			t.TempDir(), []string{"garbler-rock", "evaluator-rock"}[index])
		fixture.reopen(t, index)
	}
	return fixture
}

func (fixture *formalGLMRegisteredPhase20JobControlTestFixtureV1) reopen(
	t testing.TB, index int,
) {
	t.Helper()
	if fixture.attempts[index] != nil {
		fixture.attempts[index].Close()
	}
	if fixture.jobKeys[index] != nil {
		if err := fixture.jobKeys[index].Close(); err != nil {
			t.Fatal(err)
		}
	}
	peer := fixture.core.source.plan.DesignatedComputePeers[index]
	fixture.attempts[index] =
		formalGLMRegisteredPhase20JobRelayTestOpenAttemptV1(
			t, fixture.roots[index], peer, fixture.core)
	fixture.jobKeys[index] =
		formalGLMRegisteredPhase20JobRelayTestOpenJobKeyV1(
			t, fixture.roots[index], peer, fixture.core)
	control, err := newFormalGLMRegisteredPhase20JobControlV1(
		fixture.attempts[index], fixture.jobKeys[index])
	if err != nil {
		t.Fatal(err)
	}
	fixture.controls[index] = control
}

func (fixture *formalGLMRegisteredPhase20JobControlTestFixtureV1) negotiate(
	t testing.TB,
) (proposalFrame, acceptFrame []byte) {
	t.Helper()
	waiting, err := fixture.controls[1].StartV1(fixture.start, nil)
	if err != nil || waiting.state !=
		formalGLMRegisteredPhase20JobControlWaitingProposalStateV1 ||
		len(waiting.outbound) != 0 || waiting.productionReady {
		t.Fatalf("evaluator did not wait for proposal: %+v / %v", waiting, err)
	}
	proposal, err := fixture.controls[0].StartV1(fixture.start, nil)
	if err != nil || proposal.state !=
		formalGLMRegisteredPhase20JobControlProposalStateV1 ||
		len(proposal.outbound) == 0 || proposal.productionReady {
		t.Fatalf("garbler did not emit proposal: %+v / %v", proposal, err)
	}
	proposalReplay, err := fixture.controls[0].StartV1(fixture.start, nil)
	if err != nil || !bytes.Equal(proposalReplay.outbound, proposal.outbound) {
		t.Fatalf("proposal frame did not replay exactly: %v", err)
	}
	accepted, err := fixture.controls[1].StartV1(
		fixture.start, proposal.outbound)
	if err != nil || accepted.state !=
		formalGLMRegisteredPhase20JobControlAcceptedStateV1 ||
		len(accepted.outbound) == 0 || accepted.productionReady {
		t.Fatalf("evaluator did not emit accept: %+v / %v", accepted, err)
	}
	acceptReplay, err := fixture.controls[1].StartV1(fixture.start, nil)
	if err != nil || !bytes.Equal(acceptReplay.outbound, accepted.outbound) {
		t.Fatalf("accept frame did not replay exactly: %v", err)
	}
	adopted, err := fixture.controls[0].StartV1(
		fixture.start, accepted.outbound)
	if err != nil || adopted.state !=
		formalGLMRegisteredPhase20JobControlAcceptedStateV1 ||
		len(adopted.outbound) != 0 || adopted.productionReady {
		t.Fatalf("garbler did not adopt accept: %+v / %v", adopted, err)
	}
	if replay, err := fixture.controls[0].StartV1(
		fixture.start, accepted.outbound); err != nil ||
		replay.state != formalGLMRegisteredPhase20JobControlAcceptedStateV1 {
		t.Fatalf("garbler accept replay failed: %+v / %v", replay, err)
	}
	return proposal.outbound, accepted.outbound
}

func (fixture *formalGLMRegisteredPhase20JobControlTestFixtureV1) pair(
	t testing.TB, index int,
) (formalGLMRegisteredPhase19ClaimProposalV1,
	formalGLMRegisteredPhase19ClaimAcceptV1,
) {
	t.Helper()
	status, err := fixture.attempts[index].LoadStatus(nil)
	if err != nil || status.proposal == nil || status.accept == nil {
		t.Fatalf("accepted fixture pair unavailable: %v", err)
	}
	return *status.proposal, *status.accept
}

func formalGLMRegisteredPhase20JobControlTestAssertPrivateV1(
	t testing.TB, value any,
) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("private control handle serialized: %s / %v", encoded, err)
	}
}

func formalGLMRegisteredPhase20JobControlTestAssertFrameV1(
	t testing.TB, encoded []byte,
) {
	t.Helper()
	lower := strings.ToLower(string(encoded))
	for _, forbidden := range []string{"\"path", "\"key", "secret", "\"pid"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("control frame exposed %q: %s", forbidden, encoded)
		}
	}
	if !strings.Contains(lower, `"production_ready":false`) {
		t.Fatalf("control frame omitted non-production status: %s", encoded)
	}
}

func formalGLMRegisteredPhase20JobControlTestSignClaimV1(
	t testing.TB, control *formalGLMRegisteredPhase20JobControlV1,
	claim formalGLMRegisteredPhase20PeerJobRefClaimV1,
) []byte {
	t.Helper()
	claim.Signature = nil
	message, err := formalGLMRegisteredPhase20PeerJobRefClaimMessageV1(claim)
	if err != nil {
		t.Fatal(err)
	}
	control.attempts.mu.Lock()
	claim.Signature = ed25519.Sign(control.attempts.signingKey, message)
	control.attempts.mu.Unlock()
	clear(message)
	encoded, err := json.Marshal(claim)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func formalGLMRegisteredPhase20JobControlTestPeerBoundV1(
	controller *formalGLMRegisteredPhase20JobWorkerControllerV1,
) bool {
	controller.metadata.mu.Lock()
	err := controller.metadata.peerBoundLockedV1()
	controller.metadata.mu.Unlock()
	return err == nil
}

func TestFormalGLMRegisteredPhase20JobControlK2FramesRestartAndReplay(
	t *testing.T,
) {
	fixture := newFormalGLMRegisteredPhase20JobControlTestFixtureV1(t)
	formalGLMRegisteredPhase20JobControlTestAssertPrivateV1(
		t, fixture.controls[0])
	proposalBytes, acceptBytes := fixture.negotiate(t)
	proposal, err := formalGLMRegisteredPhase20JobControlDecodeProposalV1(
		fixture.attempts[1], proposalBytes)
	if err != nil || proposal.Binding.ProductionReady {
		t.Fatalf("invalid proposal frame: %+v / %v", proposal, err)
	}
	accept, err := formalGLMRegisteredPhase20JobControlDecodeAcceptV1(
		fixture.attempts[0], proposal, acceptBytes)
	if err != nil || accept.Binding.ProductionReady ||
		accept.ClaimProposalSHA256 == "" {
		t.Fatalf("invalid accept frame: %+v / %v", accept, err)
	}
	for index := range 2 {
		status, err := fixture.attempts[index].LoadStatus(nil)
		if err != nil || status.proposal == nil || status.accept == nil ||
			!reflect.DeepEqual(*status.proposal, proposal) ||
			!reflect.DeepEqual(*status.accept, accept) {
			t.Fatalf("accepted pair was not durable at role %d: %v", index, err)
		}
	}
	formalGLMRegisteredPhase20JobControlTestAssertFrameV1(t, proposalBytes)
	formalGLMRegisteredPhase20JobControlTestAssertFrameV1(t, acceptBytes)
	if _, err := formalGLMRegisteredPhase20JobControlDecodeProposalV1(
		fixture.attempts[1],
		append(append([]byte(nil), proposalBytes...), ' ')); err == nil {
		t.Fatal("non-canonical proposal frame was accepted")
	}
	changed := accept
	changed.Signature = append([]byte(nil), accept.Signature...)
	changed.Signature[0] ^= 1
	changedJSON, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.controls[0].StartV1(
		fixture.start, changedJSON); err == nil {
		t.Fatal("tampered accept signature was adopted")
	}

	fixture.reopen(t, 0)
	fixture.reopen(t, 1)
	replayedAccept, err := fixture.controls[1].StartV1(fixture.start, nil)
	if err != nil || !bytes.Equal(replayedAccept.outbound, acceptBytes) {
		t.Fatalf("restart changed accept frame: %v", err)
	}
	status, err := fixture.attempts[0].LoadStatus(nil)
	if err != nil || status.accept == nil ||
		!reflect.DeepEqual(*status.accept, accept) {
		t.Fatalf("restart lost remote accept adoption: %v", err)
	}
}

func TestFormalGLMRegisteredPhase20JobControlAbandonedHeadAndPartialVote(
	t *testing.T,
) {
	t.Run("abandoned-advances", func(t *testing.T) {
		fixture := newFormalGLMRegisteredPhase20JobControlTestFixtureV1(t)
		peers := fixture.core.source.plan.DesignatedComputePeers
		stores := map[string]*formalGLMRegisteredPhase19AttemptStoreV1{
			peers[0]: fixture.attempts[0], peers[1]: fixture.attempts[1],
		}
		firstProposal, _, _, abandoned :=
			formalGLMRegisteredPhase19AttemptTestPair(t, stores, fixture.core, nil)
		stale, err := json.Marshal(firstProposal)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.controls[1].StartV1(
			fixture.start, stale); err == nil {
			t.Fatal("evaluator accepted a proposal from an abandoned attempt")
		}
		next, err := fixture.controls[0].StartV1(fixture.start, nil)
		if err != nil || next.state !=
			formalGLMRegisteredPhase20JobControlProposalStateV1 {
			t.Fatalf("garbler did not advance abandoned head: %+v / %v", next, err)
		}
		proposal, err := formalGLMRegisteredPhase20JobControlDecodeProposalV1(
			fixture.attempts[1], next.outbound)
		wantPrevious, hashErr :=
			formalGLMRegisteredPhase19AttemptAbandonedSHA256V1(abandoned)
		if err != nil || hashErr != nil ||
			proposal.Binding.PreviousAttemptID != firstProposal.Binding.AttemptID ||
			proposal.Binding.PreviousAbandonSHA256 != wantPrevious ||
			proposal.Binding.AttemptID == firstProposal.Binding.AttemptID {
			t.Fatalf("next attempt did not bind predecessor: %+v / %v / %v",
				proposal, err, hashErr)
		}
		accepted, err := fixture.controls[1].StartV1(fixture.start, next.outbound)
		if err != nil || accepted.state !=
			formalGLMRegisteredPhase20JobControlAcceptedStateV1 {
			t.Fatalf("evaluator did not accept next attempt: %+v / %v", accepted, err)
		}
		if _, err := fixture.controls[0].StartV1(
			fixture.start, accepted.outbound); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("partial-vote-stops", func(t *testing.T) {
		fixture := newFormalGLMRegisteredPhase20JobControlTestFixtureV1(t)
		fixture.negotiate(t)
		proposal, accept := fixture.pair(t, 1)
		if _, _, err := fixture.attempts[1].VoteAbandon(
			proposal, accept); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.controls[1].ResolveV1(fixture.start); err == nil {
			t.Fatal("partial abandonment vote reached scratch gate")
		}
		if _, err := fixture.controls[1].StartV1(
			fixture.start, nil); err == nil {
			t.Fatal("partial abandonment vote reopened negotiation")
		}
	})
}

func TestFormalGLMRegisteredPhase20JobControlRejectsSplitOwners(t *testing.T) {
	fixture := newFormalGLMRegisteredPhase20JobControlTestFixtureV1(t)
	peers := fixture.core.source.plan.DesignatedComputePeers
	wrongContext := formalGLMRegisteredPhase20JobRelayTestOpenJobKeyV1(
		t, fixture.roots[0], peers[1], fixture.core)
	if _, err := newFormalGLMRegisteredPhase20JobControlV1(
		fixture.attempts[0], wrongContext); err == nil {
		t.Fatal("same-root wrong JobKey context was accepted")
	}
	splitRoot := formalGLMRegisteredPhase20JobRelayTestOpenJobKeyV1(
		t, filepath.Join(t.TempDir(), "split-rock"), peers[0], fixture.core)
	if _, err := newFormalGLMRegisteredPhase20JobControlV1(
		fixture.attempts[0], splitRoot); err == nil {
		t.Fatal("matching JobKey context from another Rock root was accepted")
	}
}

func TestFormalGLMRegisteredPhase20JobControlResolveRefAndBind(
	t *testing.T,
) {
	fixture := newFormalGLMRegisteredPhase20JobControlTestFixtureV1(t)
	fixture.negotiate(t)
	wrongStart := fixture.start
	wrongStart.ReceiptSetSHA256 = strings.Repeat("a", 64)
	if wrongStart.ReceiptSetSHA256 == fixture.start.ReceiptSetSHA256 {
		wrongStart.ReceiptSetSHA256 = strings.Repeat("b", 64)
	}
	if _, err := fixture.controls[0].ResolveV1(wrongStart); err == nil {
		t.Fatal("wrong JobStart reached scratch recovery")
	}

	gates := [2]formalGLMRegisteredPhase20JobControlGateV1{}
	controllers := [2]*formalGLMRegisteredPhase20JobWorkerControllerV1{}
	for index := range 2 {
		gate, err := fixture.controls[index].ResolveV1(fixture.start)
		if err != nil || !gate.startAllowed || gate.inspectOnly ||
			gate.productionReady ||
			gate.epoch.Mode != formalGLMRegisteredPhase20JobRunTransportV1 {
			t.Fatalf("fresh role %d gate was not startable: %+v / %v",
				index, gate, err)
		}
		formalGLMRegisteredPhase20JobControlTestAssertPrivateV1(t, gate)
		gates[index] = gate
		controllers[index], err =
			startFormalGLMRegisteredPhase20JobWorkerControllerV1(
				fixture.attempts[index], fixture.jobKeys[index],
				gate.proposal, gate.accept, gate.epoch)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = controllers[index].Close() })
	}

	refs := [2]formalGLMRegisteredPhase20JobRefV1{}
	claims := [2][]byte{}
	for index := range 2 {
		var err error
		refs[index], claims[index], err = fixture.controls[index].JobRefV1(
			controllers[index])
		if err != nil || refs[index].ProductionReady {
			t.Fatalf("live role %d did not emit JobRef: %+v / %v", index, refs[index], err)
		}
		formalGLMRegisteredPhase20JobControlTestAssertFrameV1(t, claims[index])
	}
	if !reflect.DeepEqual(refs[0], refs[1]) || bytes.Equal(claims[0], claims[1]) {
		t.Fatal("live controllers derived different refs or unauthenticated claims")
	}
	if _, _, err := fixture.controls[0].JobRefV1(controllers[1]); err == nil {
		t.Fatal("control signed a foreign controller JobRef")
	}
	for index := range 2 {
		if err := fixture.controls[index].BindPeerJobRefV1(
			controllers[index], claims[1-index]); err != nil {
			t.Fatalf("exact peer claim did not bind role %d: %v", index, err)
		}
		if !controllers[index].transport.peerEpochBound {
			t.Fatalf("role %d RAM transport was not bound", index)
		}
		if !formalGLMRegisteredPhase20JobControlTestPeerBoundV1(
			controllers[index]) {
			t.Fatalf("role %d durable relay was not bound first", index)
		}
		if err := fixture.controls[index].BindPeerJobRefV1(
			controllers[index], claims[1-index]); err != nil {
			t.Fatalf("role %d exact bind replay failed: %v", index, err)
		}
		burned, err := fixture.controls[index].ResolveV1(fixture.start)
		if err != nil || burned.startAllowed || !burned.inspectOnly {
			t.Fatalf("burned role %d gate was not inspect-only: %+v / %v",
				index, burned, err)
		}
	}
	for index := range 2 {
		if err := controllers[index].Close(); err != nil {
			t.Fatal(err)
		}
		if _, _, err := fixture.controls[index].JobRefV1(
			controllers[index]); err == nil {
			t.Fatal("closed controller emitted a JobRef claim")
		}
		if _, err := startFormalGLMRegisteredPhase20JobWorkerControllerV1(
			fixture.attempts[index], fixture.jobKeys[index], gates[index].proposal,
			gates[index].accept, gates[index].epoch); err == nil {
			t.Fatal("inspect-only epoch reopened")
		}
	}
}

func TestFormalGLMRegisteredPhase20JobControlJobRefFencesConcurrentClose(
	t *testing.T,
) {
	fixture := newFormalGLMRegisteredPhase20JobControlTestFixtureV1(t)
	fixture.negotiate(t)
	gate, err := fixture.controls[0].ResolveV1(fixture.start)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := startFormalGLMRegisteredPhase20JobWorkerControllerV1(
		fixture.attempts[0], fixture.jobKeys[0],
		gate.proposal, gate.accept, gate.epoch)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Close() })

	type resultV1 struct {
		ref   formalGLMRegisteredPhase20JobRefV1
		frame []byte
		err   error
	}
	result := make(chan resultV1, 1)
	started := make(chan struct{})
	controller.mu.Lock()
	fixture.jobKeys[0].mu.Lock()
	go func() {
		close(started)
		ref, frame, err := fixture.controls[0].JobRefV1(controller)
		result <- resultV1{ref: ref, frame: frame, err: err}
	}()
	<-started
	controlLocked := false
	for attempt := 0; attempt < 10_000; attempt++ {
		if !fixture.controls[0].mu.TryLock() {
			controlLocked = true
			break
		}
		fixture.controls[0].mu.Unlock()
		runtime.Gosched()
	}
	if !controlLocked {
		fixture.jobKeys[0].mu.Unlock()
		controller.mu.Unlock()
		t.Fatal("JobRef did not enter control ownership")
	}
	// JobRef now owns control.mu; let it reach the held JobKey lock, then
	// release that stage so it queues behind the held controller lock.
	runtime.Gosched()
	controller.transport.mu.Lock()
	fixture.jobKeys[0].mu.Unlock()
	controller.mu.Unlock()
	controllerOwned := false
	for attempt := 0; attempt < 10_000; attempt++ {
		if !controller.mu.TryLock() {
			controllerOwned = true
			break
		}
		controller.mu.Unlock()
		runtime.Gosched()
	}
	if !controllerOwned {
		controller.transport.mu.Unlock()
		t.Fatal("JobRef did not acquire controller ownership")
	}
	fixture.attempts[0].mu.Lock()
	controller.transport.mu.Unlock()
	heldThroughSign := true
	for attempt := 0; attempt < 10_000; attempt++ {
		if controller.mu.TryLock() {
			heldThroughSign = false
			controller.mu.Unlock()
			break
		}
		runtime.Gosched()
	}

	closeStarted := make(chan struct{})
	closeDone := make(chan error, 1)
	go func() {
		close(closeStarted)
		closeDone <- controller.Close()
	}()
	<-closeStarted
	runtime.Gosched()
	fixture.attempts[0].mu.Unlock()
	got, closeErr := <-result, <-closeDone
	if !heldThroughSign {
		t.Fatal("controller ownership was released before JobRef signing")
	}
	if got.err != nil || len(got.frame) == 0 || got.ref.ProductionReady {
		t.Fatalf("JobRef failed before concurrent Close: %+v", got)
	}
	if closeErr != nil {
		t.Fatalf("concurrent Close failed after JobRef: %v", closeErr)
	}
}

func TestFormalGLMRegisteredPhase20JobControlPeerRefRejectsBeforeIO(
	t *testing.T,
) {
	fixture := newFormalGLMRegisteredPhase20JobControlTestFixtureV1(t)
	proposalBytes, _ := fixture.negotiate(t)
	controllers := [2]*formalGLMRegisteredPhase20JobWorkerControllerV1{}
	claims := [2][]byte{}
	for index := range 2 {
		gate, err := fixture.controls[index].ResolveV1(fixture.start)
		if err != nil {
			t.Fatal(err)
		}
		controllers[index], err = startFormalGLMRegisteredPhase20JobWorkerControllerV1(
			fixture.attempts[index], fixture.jobKeys[index],
			gate.proposal, gate.accept, gate.epoch)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = controllers[index].Close() })
		_, claims[index], err = fixture.controls[index].JobRefV1(controllers[index])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := controllers[index].transport.Write([]byte("before-bind")); err == nil {
			t.Fatal("worker bytes were accepted before peer JobRef bind")
		}
	}
	if err := fixture.controls[0].BindPeerJobRefV1(
		controllers[0], claims[0]); err == nil {
		t.Fatal("local JobRef claim was accepted as peer claim")
	}
	if formalGLMRegisteredPhase20JobControlTestPeerBoundV1(controllers[0]) {
		t.Fatal("rejected local claim wrote durable peer bind")
	}
	if err := fixture.controls[0].BindPeerJobRefV1(
		controllers[0], proposalBytes); err == nil {
		t.Fatal("proposal frame was mixed into peer JobRef phase")
	}
	claim, err := formalGLMRegisteredPhase20JobControlDecodePeerJobRefClaimV1(
		fixture.attempts[0], claims[1])
	if err != nil {
		t.Fatal(err)
	}
	claim.Signature[0] ^= 1
	tampered, err := json.Marshal(claim)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.controls[0].BindPeerJobRefV1(
		controllers[0], tampered); err == nil {
		t.Fatal("tampered peer JobRef claim was accepted")
	}
	mixedClaim, err := formalGLMRegisteredPhase20JobControlDecodePeerJobRefClaimV1(
		fixture.attempts[0], claims[1])
	if err != nil {
		t.Fatal(err)
	}
	mixedClaim.ClaimAcceptSHA256 = strings.Repeat("c", 64)
	mixed := formalGLMRegisteredPhase20JobControlTestSignClaimV1(
		t, fixture.controls[1], mixedClaim)
	if err := fixture.controls[0].BindPeerJobRefV1(
		controllers[0], mixed); err == nil {
		t.Fatal("validly signed mixed accept/JobRef claim was accepted")
	}
	mixedRef, err := formalGLMRegisteredPhase20JobControlDecodePeerJobRefClaimV1(
		fixture.attempts[0], claims[1])
	if err != nil {
		t.Fatal(err)
	}
	mixedRef.JobRef.JobSHA256 = strings.Repeat("d", 64)
	if mixedRef.JobRef.JobSHA256 == controllers[0].transport.ref.JobSHA256 {
		mixedRef.JobRef.JobSHA256 = strings.Repeat("e", 64)
	}
	mixedRefFrame := formalGLMRegisteredPhase20JobControlTestSignClaimV1(
		t, fixture.controls[1], mixedRef)
	if err := fixture.controls[0].BindPeerJobRefV1(
		controllers[0], mixedRefFrame); err == nil {
		t.Fatal("validly signed foreign full JobRef was accepted")
	}
	if _, err := formalGLMRegisteredPhase20JobControlDecodePeerJobRefClaimV1(
		fixture.attempts[0], append(append([]byte(nil), claims[1]...), ' ')); err == nil {
		t.Fatal("non-canonical peer JobRef claim was accepted")
	}
	if controllers[0].transport.peerEpochBound {
		t.Fatal("invalid control frame performed worker I/O binding")
	}
	if formalGLMRegisteredPhase20JobControlTestPeerBoundV1(controllers[0]) {
		t.Fatal("invalid control frame wrote durable peer bind")
	}
	if err := formalGLMRegisteredPhase20JobTransportWriteInitialV1(
		controllers[1].metadata.scratch,
		formalGLMRegisteredPhase20JobPeerBindFileV1,
		[]byte("invalid-peer-bind")); err != nil {
		t.Fatal(err)
	}
	if err := fixture.controls[1].BindPeerJobRefV1(
		controllers[1], claims[0]); err == nil {
		t.Fatal("invalid durable peer bind anchor was overwritten")
	}
	if controllers[1].transport.peerEpochBound {
		t.Fatal("RAM peer bind preceded durable peer bind")
	}
	if err := fixture.controls[0].BindPeerJobRefV1(
		controllers[0], claims[1]); err != nil ||
		!controllers[0].transport.peerEpochBound {
		t.Fatalf("exact peer claim failed after pre-I/O rejects: %v", err)
	}
}
