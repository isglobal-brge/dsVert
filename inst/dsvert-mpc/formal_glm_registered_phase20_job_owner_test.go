package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type formalGLMRegisteredPhase20JobOwnerTestFixtureV1 struct {
	control *formalGLMRegisteredPhase20JobControlTestFixtureV1
	owners  [2]*formalGLMRegisteredPhase20JobOwnerV1
}

func newFormalGLMRegisteredPhase20JobOwnerTestFixtureV1(
	t testing.TB,
) *formalGLMRegisteredPhase20JobOwnerTestFixtureV1 {
	t.Helper()
	fixture := &formalGLMRegisteredPhase20JobOwnerTestFixtureV1{
		control: newFormalGLMRegisteredPhase20JobControlTestFixtureV1(t),
	}
	for index := range 2 {
		fixture.openOwner(t, index)
	}
	return fixture
}

func (fixture *formalGLMRegisteredPhase20JobOwnerTestFixtureV1) openOwner(
	t testing.TB, index int,
) {
	t.Helper()
	owner, err := newFormalGLMRegisteredPhase20JobOwnerV1(
		fixture.control.attempts[index], fixture.control.jobKeys[index],
		fixture.control.start)
	if err != nil {
		t.Fatal(err)
	}
	fixture.owners[index] = owner
	t.Cleanup(func() { _ = owner.Close() })
}

func (fixture *formalGLMRegisteredPhase20JobOwnerTestFixtureV1) negotiate(
	t testing.TB,
) (proposalFrame, acceptFrame []byte) {
	t.Helper()
	waiting, err := fixture.owners[1].NegotiateV1(nil)
	if err != nil || waiting.state !=
		formalGLMRegisteredPhase20JobControlWaitingProposalStateV1 ||
		len(waiting.outbound) != 0 || waiting.productionReady {
		t.Fatalf("evaluator did not wait: %+v / %v", waiting, err)
	}
	proposal, err := fixture.owners[0].NegotiateV1(nil)
	if err != nil || proposal.state !=
		formalGLMRegisteredPhase20JobControlProposalStateV1 ||
		len(proposal.outbound) == 0 || proposal.productionReady {
		t.Fatalf("garbler did not propose: %+v / %v", proposal, err)
	}
	accepted, err := fixture.owners[1].NegotiateV1(proposal.outbound)
	if err != nil || accepted.state !=
		formalGLMRegisteredPhase20JobControlAcceptedStateV1 ||
		len(accepted.outbound) == 0 || accepted.productionReady {
		t.Fatalf("evaluator did not accept: %+v / %v", accepted, err)
	}
	adopted, err := fixture.owners[0].NegotiateV1(accepted.outbound)
	if err != nil || adopted.state !=
		formalGLMRegisteredPhase20JobControlAcceptedStateV1 ||
		len(adopted.outbound) != 0 || adopted.productionReady {
		t.Fatalf("garbler did not adopt: %+v / %v", adopted, err)
	}
	return proposal.outbound, accepted.outbound
}

func (fixture *formalGLMRegisteredPhase20JobOwnerTestFixtureV1) reopenOwner(
	t testing.TB, index int,
) {
	t.Helper()
	if fixture.owners[index] != nil {
		if err := fixture.owners[index].Close(); err != nil {
			t.Fatal(err)
		}
	}
	fixture.control.reopen(t, index)
	fixture.openOwner(t, index)
}

func formalGLMRegisteredPhase20JobOwnerTestAssertPrivateV1(
	t testing.TB, value any,
) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("JobOwner private state serialized: %s / %v", encoded, err)
	}
}

func formalGLMRegisteredPhase20JobOwnerTestAttemptRootV1(
	t testing.TB, owner *formalGLMRegisteredPhase20JobOwnerV1, rockPath string,
) (*os.Root, string) {
	t.Helper()
	owner.attempts.mu.Lock()
	relative := owner.attempts.attemptRelativeDirV1(
		owner.proposal.Binding.AttemptID)
	root := owner.attempts.root
	owner.attempts.mu.Unlock()
	opened, err := root.OpenRoot(relative)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	return opened, filepath.Join(rockPath, relative)
}

func formalGLMRegisteredPhase20JobOwnerTestSubprocessV1(
	t testing.TB, path, mode string,
) {
	t.Helper()
	command := exec.Command(os.Args[0],
		"-test.run=^TestFormalGLMRegisteredPhase20JobOwnerFlockProcess$")
	command.Env = append(os.Environ(),
		"DSVERT_JOB_OWNER_TEST_ROOT="+path,
		"DSVERT_JOB_OWNER_TEST_MODE="+mode)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("flock subprocess %s failed: %v\n%s", mode, err, output)
	}
}

func TestFormalGLMRegisteredPhase20JobOwnerFlockProcess(t *testing.T) {
	path := os.Getenv("DSVERT_JOB_OWNER_TEST_ROOT")
	if path == "" {
		t.Skip("subprocess helper")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	lock, err := formalGLMRegisteredPhase20JobOwnerAcquireFlockV1(root)
	if os.Getenv("DSVERT_JOB_OWNER_TEST_MODE") == "busy" {
		if !errors.Is(err, errFormalGLMRegisteredPhase20JobOwnerBusyV1) {
			t.Fatalf("held process flock was not busy: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	formalGLMRegisteredPhase20JobOwnerReleaseFlockV1(lock)
}

func TestFormalGLMRegisteredPhase20JobOwnerNegotiatesRunsAndInspectsRestart(
	t *testing.T,
) {
	fixture := newFormalGLMRegisteredPhase20JobOwnerTestFixtureV1(t)
	fixture.negotiate(t)
	formalGLMRegisteredPhase20JobOwnerTestAssertPrivateV1(t, fixture.owners[0])
	results := [2]formalGLMRegisteredPhase20JobOwnerResultV1{}
	claims := [2][]byte{}
	refs := [2]formalGLMRegisteredPhase20JobRefV1{}
	for index := range 2 {
		var err error
		results[index], err = fixture.owners[index].StartOrInspectV1()
		if err != nil || results[index].state !=
			formalGLMRegisteredPhase20JobOwnerRunningStateV1 ||
			results[index].inspectOnly || results[index].productionReady {
			t.Fatalf("role %d did not start: %+v / %v", index, results[index], err)
		}
		formalGLMRegisteredPhase20JobOwnerTestAssertPrivateV1(t, results[index])
		refs[index], claims[index], err = fixture.owners[index].JobRefV1()
		if err != nil || refs[index].ProductionReady || len(claims[index]) == 0 {
			t.Fatalf("role %d did not claim JobRef: %+v / %v", index, refs[index], err)
		}
		formalGLMRegisteredPhase20JobControlTestAssertFrameV1(t, claims[index])
	}
	if !reflect.DeepEqual(refs[0], refs[1]) {
		t.Fatal("sole owners derived different JobRefs")
	}
	for index := range 2 {
		if err := fixture.owners[index].BindPeerJobRefV1(
			claims[1-index]); err != nil {
			t.Fatal(err)
		}
		if err := fixture.owners[index].HeartbeatV1(); err != nil {
			t.Fatal(err)
		}
		if replay, err := fixture.owners[index].StartOrInspectV1(); err != nil ||
			replay.state != formalGLMRegisteredPhase20JobOwnerRunningStateV1 {
			t.Fatalf("live start replay failed: %+v / %v", replay, err)
		}
	}
	for index := range 2 {
		fixture.reopenOwner(t, index)
		inspected, err := fixture.owners[index].StartOrInspectV1()
		if err != nil || !inspected.inspectOnly || inspected.productionReady ||
			inspected.state == formalGLMRegisteredPhase20JobOwnerRunningStateV1 {
			t.Fatalf("burned role %d reopened: %+v / %v", index, inspected, err)
		}
		if fixture.owners[index].controller != nil {
			t.Fatal("restart exposed a controller for a burned epoch")
		}
	}
}

func TestFormalGLMRegisteredPhase20JobOwnerFixedProcessFlock(t *testing.T) {
	fixture := newFormalGLMRegisteredPhase20JobOwnerTestFixtureV1(t)
	fixture.negotiate(t)
	root, path := formalGLMRegisteredPhase20JobOwnerTestAttemptRootV1(
		t, fixture.owners[0], fixture.control.roots[0])
	lock, err := formalGLMRegisteredPhase20JobOwnerAcquireFlockV1(root)
	if err != nil {
		t.Fatal(err)
	}
	info, err := root.Lstat(formalGLMRegisteredPhase20JobOwnerLockFileV1)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		info.Size() != 0 || !exactGCPrivateOwnedRegular(info) {
		t.Fatalf("unsafe fixed JobOwner flock: %+v / %v", info, err)
	}
	formalGLMRegisteredPhase20JobOwnerTestSubprocessV1(t, path, "busy")
	formalGLMRegisteredPhase20JobOwnerReleaseFlockV1(lock)
	formalGLMRegisteredPhase20JobOwnerTestSubprocessV1(t, path, "free")
	directory, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := directory.ReadDir(-1)
	closeErr := directory.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("read fixed flock directory: %v / %v", err, closeErr)
	}
	locks := 0
	for _, entry := range entries {
		if entry.Name() == formalGLMRegisteredPhase20JobOwnerLockFileV1 {
			locks++
		}
		if strings.Contains(entry.Name(), ".next") ||
			strings.Contains(entry.Name(), ".tmp") {
			t.Fatalf("JobOwner created a random/temp artifact: %s", entry.Name())
		}
	}
	if locks != 1 {
		t.Fatalf("fixed JobOwner flock count = %d", locks)
	}
}

func TestFormalGLMRegisteredPhase20JobOwnerStartVersusAbandonHasOneWinner(
	t *testing.T,
) {
	fixture := newFormalGLMRegisteredPhase20JobOwnerTestFixtureV1(t)
	fixture.negotiate(t)
	owner := fixture.owners[1]
	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(2)
	var started, abandoned formalGLMRegisteredPhase20JobOwnerResultV1
	var startErr, abandonErr error
	go func() {
		defer wait.Done()
		<-start
		started, startErr = owner.StartOrInspectV1()
	}()
	go func() {
		defer wait.Done()
		<-start
		abandoned, abandonErr = owner.InitiateAbandonV1()
	}()
	close(start)
	wait.Wait()
	startWon := startErr == nil &&
		started.state == formalGLMRegisteredPhase20JobOwnerRunningStateV1
	abandonWon := abandonErr == nil &&
		abandoned.state == formalGLMRegisteredPhase20JobOwnerVotedStateV1
	if startWon == abandonWon {
		t.Fatalf("start/abandon did not choose exactly one branch: %+v/%v %+v/%v",
			started, startErr, abandoned, abandonErr)
	}
	status, err := owner.attempts.LoadStatus(nil)
	if err != nil {
		t.Fatal(err)
	}
	burned, burnErr := owner.burnedV1()
	if startWon {
		if abandonErr != nil || abandoned.state !=
			formalGLMRegisteredPhase20JobOwnerPendingStateV1 ||
			status.votes[1] != nil || burnErr != nil || !burned {
			t.Fatalf("started branch also voted: %+v / %v / %v", status, abandoned, burnErr)
		}
	} else if status.votes[1] == nil || burnErr != nil || burned {
		t.Fatalf("abandon branch burned transport: %+v / %v", status, burnErr)
	}
}

func TestFormalGLMRegisteredPhase20JobOwnerLiveAbortThenQuiescentVote(
	t *testing.T,
) {
	fixture := newFormalGLMRegisteredPhase20JobOwnerTestFixtureV1(t)
	fixture.negotiate(t)
	live := fixture.owners[1]
	if _, err := live.StartOrInspectV1(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := live.JobRefV1(); err != nil {
		t.Fatal(err)
	}
	peer := fixture.control.core.source.plan.DesignatedComputePeers[1]
	observerAttempts := formalGLMRegisteredPhase20JobRelayTestOpenAttemptV1(
		t, fixture.control.roots[1], peer, fixture.control.core)
	observerKeys := formalGLMRegisteredPhase20JobRelayTestOpenJobKeyV1(
		t, fixture.control.roots[1], peer, fixture.control.core)
	observer, err := newFormalGLMRegisteredPhase20JobOwnerV1(
		observerAttempts, observerKeys, fixture.control.start)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = observer.Close() })
	pending, err := observer.InitiateAbandonV1()
	if err != nil || pending.state !=
		formalGLMRegisteredPhase20JobOwnerPendingStateV1 ||
		len(pending.outbound) != 0 || pending.productionReady {
		t.Fatalf("live owner was not abort-pending: %+v / %v", pending, err)
	}
	status, err := observer.attempts.LoadStatus(nil)
	if err != nil || status.votes[0] != nil || status.votes[1] != nil {
		t.Fatalf("live abort persisted a vote: %+v / %v", status, err)
	}
	if _, _, err := live.JobRefV1(); err == nil {
		t.Fatal("run-control survived durable abort intent")
	}
	if err := live.Close(); err != nil {
		t.Fatal(err)
	}
	voted, err := observer.InitiateAbandonV1()
	if err != nil || voted.state != formalGLMRegisteredPhase20JobOwnerVotedStateV1 ||
		len(voted.outbound) == 0 || voted.productionReady {
		t.Fatalf("owner-lost attempt did not vote: %+v / %v", voted, err)
	}
	formalGLMRegisteredPhase20JobControlTestAssertFrameV1(t, voted.outbound)
	if _, err := observer.StartOrInspectV1(); err == nil {
		t.Fatal("voted burned attempt returned to run-control")
	}
}

func TestFormalGLMRegisteredPhase20JobOwnerRoleOrderRestartAndCommit(
	t *testing.T,
) {
	fixture := newFormalGLMRegisteredPhase20JobOwnerTestFixtureV1(t)
	fixture.negotiate(t)
	if _, err := fixture.owners[0].InitiateAbandonV1(); err == nil {
		t.Fatal("garbler initiated abandonment")
	}
	if _, err := fixture.owners[1].AcceptEvaluatorAbandonV1(nil); err == nil {
		t.Fatal("evaluator accepted its own abandonment")
	}
	if _, err := fixture.owners[0].AcceptEvaluatorAbandonV1(nil); err == nil {
		t.Fatal("garbler voted before evaluator")
	}
	evaluator, err := fixture.owners[1].InitiateAbandonV1()
	if err != nil || evaluator.state !=
		formalGLMRegisteredPhase20JobOwnerVotedStateV1 ||
		len(evaluator.outbound) == 0 || evaluator.productionReady {
		t.Fatalf("evaluator vote unavailable: %+v / %v", evaluator, err)
	}
	formalGLMRegisteredPhase20JobControlTestAssertFrameV1(t, evaluator.outbound)
	var evaluatorVote formalGLMRegisteredPhase19DecisionVoteV1
	if err := formalGLMPhase21RockStrictDecode(
		evaluator.outbound, &evaluatorVote); err != nil {
		t.Fatal(err)
	}
	garbler := fixture.owners[0]
	tamperedVote := evaluatorVote
	tamperedVote.Signature = append([]byte(nil), evaluatorVote.Signature...)
	tamperedVote.Signature[0] ^= 1
	tampered, err := json.Marshal(tamperedVote)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := garbler.AcceptEvaluatorAbandonV1(tampered); err == nil {
		t.Fatal("garbler accepted a tampered evaluator vote")
	}
	if _, err := garbler.AcceptEvaluatorAbandonV1(
		append(append([]byte(nil), evaluator.outbound...), ' ')); err == nil {
		t.Fatal("garbler accepted a non-canonical evaluator vote")
	}
	status, err := garbler.attempts.LoadStatus(nil)
	if err != nil || status.votes[0] != nil || status.votes[1] != nil {
		t.Fatalf("rejected evaluator vote changed durable state: %+v / %v", status, err)
	}
	garbler.attempts.mu.Lock()
	_, err = garbler.attempts.commitVoteV1(
		garbler.proposal, garbler.accept, evaluatorVote)
	garbler.attempts.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	fixture.reopenOwner(t, 0)
	garbler = fixture.owners[0]
	accepted, err := garbler.AcceptEvaluatorAbandonV1(evaluator.outbound)
	if err != nil || accepted.state !=
		formalGLMRegisteredPhase20JobOwnerVotedStateV1 ||
		len(accepted.outbound) == 0 || accepted.productionReady {
		t.Fatalf("garbler did not resume imported vote1: %+v / %v", accepted, err)
	}
	formalGLMRegisteredPhase20JobControlTestAssertFrameV1(t, accepted.outbound)
	garblerAggregate, err := garbler.CommitAbandonedV1(nil)
	if err != nil || garblerAggregate.state !=
		formalGLMRegisteredPhase20JobOwnerAbandonedStateV1 ||
		len(garblerAggregate.outbound) == 0 || garblerAggregate.productionReady {
		t.Fatalf("garbler did not commit abandonment: %+v / %v", garblerAggregate, err)
	}
	evaluatorAggregate, err := fixture.owners[1].CommitAbandonedV1(
		accepted.outbound)
	if err != nil || !bytes.Equal(
		evaluatorAggregate.outbound, garblerAggregate.outbound) {
		t.Fatalf("evaluator aggregate differs: %+v / %v", evaluatorAggregate, err)
	}
	formalGLMRegisteredPhase20JobControlTestAssertFrameV1(
		t, evaluatorAggregate.outbound)
	replay, err := fixture.owners[1].CommitAbandonedV1(accepted.outbound)
	if err != nil || !bytes.Equal(replay.outbound, evaluatorAggregate.outbound) {
		t.Fatalf("abandonment replay changed: %+v / %v", replay, err)
	}
	for index := range 2 {
		status, err := fixture.owners[index].attempts.LoadStatus(nil)
		if err != nil || status.abandoned == nil || status.votes[0] == nil ||
			status.votes[1] == nil {
			t.Fatalf("role %d did not persist exact K2 abandonment: %+v / %v",
				index, status, err)
		}
	}
}
