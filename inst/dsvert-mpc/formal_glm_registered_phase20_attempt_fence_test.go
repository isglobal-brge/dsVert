package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

// This RED names every lower-level primitive which must join the same
// attempt fence. Holding job-owner.lock must stop raw Start and Vote in a
// different process, not merely callers which honor JobOwner by convention.
type formalGLMRegisteredPhase20AttemptFenceProcessConfigV1 struct {
	RockRoot string                                        `json:"rock_root"`
	Record   formalGLMRegisteredPhase19BindingRecordV1     `json:"record"`
	Contract formalGLMSourceContractV1                     `json:"contract"`
	Pins     map[string]ed25519.PublicKey                  `json:"pins"`
	Peer     string                                        `json:"peer"`
	Signing  ed25519.PrivateKey                            `json:"signing"`
	Proposal formalGLMRegisteredPhase19ClaimProposalV1     `json:"proposal"`
	Accept   formalGLMRegisteredPhase19ClaimAcceptV1       `json:"accept"`
	Epoch    formalGLMRegisteredPhase20JobTransportEpochV1 `json:"epoch"`
}

func formalGLMRegisteredPhase20AttemptFenceTestAcceptedV1(
	t testing.TB,
) (*formalGLMRegisteredPhase20JobControlTestFixtureV1,
	formalGLMRegisteredPhase19ClaimProposalV1,
	formalGLMRegisteredPhase19ClaimAcceptV1,
	formalGLMRegisteredPhase20JobTransportEpochV1,
) {
	t.Helper()
	fixture := newFormalGLMRegisteredPhase20JobControlTestFixtureV1(t)
	fixture.negotiate(t)
	proposal, accept := fixture.pair(t, 1)
	acceptSHA256, err := formalGLMRegisteredPhase19ClaimAcceptSHA256V1(accept)
	if err != nil {
		t.Fatal(err)
	}
	return fixture, proposal, accept,
		formalGLMRegisteredPhase20JobTransportEpochV1{
			Mode:        formalGLMRegisteredPhase20JobRunTransportV1,
			BasisSHA256: acceptSHA256,
		}
}

func formalGLMRegisteredPhase20AttemptFenceTestAliasV1(
	t testing.TB, fixture *formalGLMRegisteredPhase20JobControlTestFixtureV1,
	index int,
) (*formalGLMRegisteredPhase19AttemptStoreV1,
	*formalGLMRegisteredPhase20JobKeyProviderV1,
) {
	t.Helper()
	peer := fixture.core.source.plan.DesignatedComputePeers[index]
	return formalGLMRegisteredPhase20JobRelayTestOpenAttemptV1(
			t, fixture.roots[index], peer, fixture.core),
		formalGLMRegisteredPhase20JobRelayTestOpenJobKeyV1(
			t, fixture.roots[index], peer, fixture.core)
}

func formalGLMRegisteredPhase20AttemptFenceTestRootV1(
	t testing.TB, store *formalGLMRegisteredPhase19AttemptStoreV1,
	attemptID string,
) (*os.Root, string) {
	t.Helper()
	store.mu.Lock()
	root := store.root
	relative := store.attemptRelativeDirV1(attemptID)
	store.mu.Unlock()
	opened, err := root.OpenRoot(relative)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	return opened, relative
}

func formalGLMRegisteredPhase20AttemptFenceTestWriteConfigV1(
	t testing.TB, fixture *formalGLMRegisteredPhase20JobControlTestFixtureV1,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	epoch formalGLMRegisteredPhase20JobTransportEpochV1,
	index int,
) string {
	t.Helper()
	peer := fixture.core.source.plan.DesignatedComputePeers[index]
	config := formalGLMRegisteredPhase20AttemptFenceProcessConfigV1{
		RockRoot: fixture.roots[index], Record: fixture.core.record,
		Contract: fixture.core.source.contract,
		Pins:     fixture.core.source.inputs.identities.public,
		Peer:     peer,
		Signing:  fixture.core.source.inputs.identities.private[peer],
		Proposal: proposal, Accept: accept, Epoch: epoch,
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fence-process.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func formalGLMRegisteredPhase20AttemptFenceTestProcessV1(
	t testing.TB, configPath, mode string,
) {
	t.Helper()
	command := exec.Command(os.Args[0],
		"-test.run=^TestFormalGLMRegisteredPhase20AttemptFenceProcess$")
	command.Env = append(os.Environ(),
		"DSVERT_ATTEMPT_FENCE_CONFIG="+configPath,
		"DSVERT_ATTEMPT_FENCE_MODE="+mode)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("raw %s bypassed the process fence: %v\n%s", mode, err, output)
	}
}

func TestFormalGLMRegisteredPhase20AttemptFenceProcess(t *testing.T) {
	path := os.Getenv("DSVERT_ATTEMPT_FENCE_CONFIG")
	if path == "" {
		t.Skip("subprocess helper")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var config formalGLMRegisteredPhase20AttemptFenceProcessConfigV1
	if err := json.Unmarshal(encoded, &config); err != nil {
		t.Fatal(err)
	}
	attempts, err := newFormalGLMRegisteredPhase19AttemptStoreV1(
		config.RockRoot, config.Record, config.Contract,
		config.Pins, config.Peer, config.Signing)
	if err != nil {
		t.Fatal(err)
	}
	defer attempts.Close()
	keys, err := newFormalGLMRegisteredPhase20JobKeyProviderV1(
		config.RockRoot, config.Contract, config.Pins, config.Record, config.Peer)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Close()
	switch os.Getenv("DSVERT_ATTEMPT_FENCE_MODE") {
	case "start":
		controller, startErr := startFormalGLMRegisteredPhase20JobWorkerControllerV1(
			attempts, keys, config.Proposal, config.Accept, config.Epoch)
		if controller != nil {
			_ = controller.Close()
		}
		if !errors.Is(startErr, errFormalGLMRegisteredPhase20JobOwnerBusyV1) {
			t.Fatalf("raw Start ignored held attempt lease: %v", startErr)
		}
	case "vote":
		_, _, voteErr := attempts.VoteAbandon(config.Proposal, config.Accept)
		if !errors.Is(voteErr, errFormalGLMRegisteredPhase20JobOwnerBusyV1) {
			t.Fatalf("raw Vote ignored held attempt lease: %v", voteErr)
		}
		status, loadErr := attempts.LoadStatus(nil)
		if loadErr != nil || status.votes[0] != nil || status.votes[1] != nil {
			t.Fatalf("busy Vote changed durable state: %+v / %v", status, loadErr)
		}
	default:
		t.Fatal("unknown subprocess mode")
	}
}

func TestFormalGLMRegisteredPhase20AttemptFenceRawStartAndVoteUseProcessLease(
	t *testing.T,
) {
	for _, mode := range []string{"start", "vote"} {
		t.Run(mode, func(t *testing.T) {
			fixture, proposal, accept, epoch :=
				formalGLMRegisteredPhase20AttemptFenceTestAcceptedV1(t)
			index := 1
			root, _ := formalGLMRegisteredPhase20AttemptFenceTestRootV1(
				t, fixture.attempts[index], proposal.Binding.AttemptID)
			lock, err := formalGLMRegisteredPhase20JobOwnerAcquireFlockV1(root)
			if err != nil {
				t.Fatal(err)
			}
			defer formalGLMRegisteredPhase20JobOwnerReleaseFlockV1(lock)
			config := formalGLMRegisteredPhase20AttemptFenceTestWriteConfigV1(
				t, fixture, proposal, accept, epoch, index)
			formalGLMRegisteredPhase20AttemptFenceTestProcessV1(t, config, mode)
		})
	}
}

func TestFormalGLMRegisteredPhase20AttemptFenceLiveOwnerAbortsBeforeVote(
	t *testing.T,
) {
	fixture, proposal, accept, epoch :=
		formalGLMRegisteredPhase20AttemptFenceTestAcceptedV1(t)
	controllers := [2]*formalGLMRegisteredPhase20JobWorkerControllerV1{}
	claims := [2][]byte{}
	for index := range 2 {
		var err error
		controllers[index], err = startFormalGLMRegisteredPhase20JobWorkerControllerV1(
			fixture.attempts[index], fixture.jobKeys[index], proposal, accept, epoch)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = controllers[index].Close() })
		_, claims[index], err = fixture.controls[index].JobRefV1(controllers[index])
		if err != nil {
			t.Fatal(err)
		}
	}
	alias, aliasKeys := formalGLMRegisteredPhase20AttemptFenceTestAliasV1(
		t, fixture, 1)
	_ = aliasKeys
	if _, _, err := alias.VoteAbandon(proposal, accept); err == nil {
		t.Fatal("raw Vote raced a live lifetime owner")
	}
	status, err := alias.LoadStatus(nil)
	if err != nil || status.votes[0] != nil || status.votes[1] != nil {
		t.Fatalf("live owner race persisted a vote: %+v / %v", status, err)
	}
	if !formalGLMRegisteredPhase20JobTransportAbortValidV1(
		controllers[1].transport.scratch) {
		t.Fatal("live owner race did not fsync abort before pending")
	}
	if _, _, err := fixture.controls[1].JobRefV1(controllers[1]); err == nil {
		t.Fatal("raw JobRef survived abandon intent")
	}
	if err := fixture.controls[1].BindPeerJobRefV1(
		controllers[1], claims[0]); err == nil {
		t.Fatal("raw Bind survived abandon intent")
	}
	if err := controllers[1].Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := alias.VoteAbandon(proposal, accept); err != nil {
		t.Fatalf("quiescent retry did not vote: %v", err)
	}
}

func TestFormalGLMRegisteredPhase20AttemptFencePreLifetimeCrashCanVote(
	t *testing.T,
) {
	fixture, proposal, accept, epoch :=
		formalGLMRegisteredPhase20AttemptFenceTestAcceptedV1(t)
	root, relative, binding, err := formalGLMRegisteredPhase20JobWorkerStartBindingV1(
		fixture.attempts[1], fixture.jobKeys[1], proposal, accept, epoch)
	if err != nil {
		t.Fatal(err)
	}
	attemptRoot, _ := formalGLMRegisteredPhase20AttemptFenceTestRootV1(
		t, fixture.attempts[1], proposal.Binding.AttemptID)
	lock, err := formalGLMRegisteredPhase20JobOwnerAcquireFlockV1(attemptRoot)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := newFormalGLMRegisteredPhase20JobTransportV1(
		root, relative, binding, epoch)
	formalGLMRegisteredPhase20JobOwnerReleaseFlockV1(lock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = transport.Close() })
	alias, _ := formalGLMRegisteredPhase20AttemptFenceTestAliasV1(t, fixture, 1)
	if _, _, err := alias.VoteAbandon(proposal, accept); err != nil {
		t.Fatalf("pre-lifetime burned crash could not vote: %v", err)
	}
	if !formalGLMRegisteredPhase20JobTransportAbortValidV1(transport.scratch) {
		t.Fatal("pre-lifetime recovery voted before fsynced abort")
	}
	status, err := alias.LoadStatus(nil)
	if err != nil || status.votes[1] == nil {
		t.Fatalf("pre-lifetime recovery lost evaluator vote: %+v / %v", status, err)
	}
}

func TestFormalGLMRegisteredPhase20AttemptFenceRawRunControlUsesLease(
	t *testing.T,
) {
	fixture, proposal, accept, epoch :=
		formalGLMRegisteredPhase20AttemptFenceTestAcceptedV1(t)
	controllers := [2]*formalGLMRegisteredPhase20JobWorkerControllerV1{}
	claims := [2][]byte{}
	for index := range 2 {
		var err error
		controllers[index], err = startFormalGLMRegisteredPhase20JobWorkerControllerV1(
			fixture.attempts[index], fixture.jobKeys[index], proposal, accept, epoch)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = controllers[index].Close() })
		_, claims[index], err = fixture.controls[index].JobRefV1(controllers[index])
		if err != nil {
			t.Fatal(err)
		}
	}
	root, _ := formalGLMRegisteredPhase20AttemptFenceTestRootV1(
		t, fixture.attempts[1], proposal.Binding.AttemptID)
	lock, err := formalGLMRegisteredPhase20JobOwnerAcquireFlockV1(root)
	if err != nil {
		t.Fatal(err)
	}
	defer formalGLMRegisteredPhase20JobOwnerReleaseFlockV1(lock)
	if _, _, err := fixture.controls[1].JobRefV1(controllers[1]); !errors.Is(err, errFormalGLMRegisteredPhase20JobOwnerBusyV1) {
		t.Fatalf("raw JobRef ignored held abandon lease: %v", err)
	}
	if err := fixture.controls[1].BindPeerJobRefV1(
		controllers[1], claims[0]); !errors.Is(err, errFormalGLMRegisteredPhase20JobOwnerBusyV1) {
		t.Fatalf("raw Bind ignored held abandon lease: %v", err)
	}
}

func TestFormalGLMRegisteredPhase20AttemptFenceInternalVoteCannotBypassLease(
	t *testing.T,
) {
	fixture, proposal, accept, _ :=
		formalGLMRegisteredPhase20AttemptFenceTestAcceptedV1(t)
	garbler, _ := formalGLMRegisteredPhase20AttemptFenceTestAliasV1(t, fixture, 0)
	evaluator, _, err := fixture.attempts[1].VoteAbandon(proposal, accept)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := formalGLMRegisteredPhase20AttemptFenceTestRootV1(
		t, garbler, proposal.Binding.AttemptID)
	lock, err := formalGLMRegisteredPhase20JobOwnerAcquireFlockV1(root)
	if err != nil {
		t.Fatal(err)
	}
	defer formalGLMRegisteredPhase20JobOwnerReleaseFlockV1(lock)
	garbler.mu.Lock()
	_, err = garbler.commitVoteV1(nil, proposal, accept, evaluator)
	garbler.mu.Unlock()
	if err == nil {
		t.Fatalf("internal commitVote bypassed held attempt lease: %v", err)
	}
	status, loadErr := garbler.LoadStatus(nil)
	if loadErr != nil || status.votes[1] != nil ||
		!reflect.DeepEqual(status.proposal, &proposal) {
		t.Fatalf("internal lease bypass changed durable vote: %+v / %v", status, loadErr)
	}
}

func TestFormalGLMRegisteredPhase20AttemptFenceTerminalLiveOwnerDefersChoice(
	t *testing.T,
) {
	fixture, proposal, accept, epoch :=
		formalGLMRegisteredPhase20AttemptFenceTestAcceptedV1(t)
	backend := sha256.Sum256([]byte(
		"formal-glm/registered-phase20/attempt-fence/terminal-live-owner"))
	runtime, err := newFormalGLMRegisteredPhase19EphemeralRuntimeV1(
		fixture.core.record, fixture.core.source.contract,
		fixture.core.source.inputs.identities.public, backend)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	owner, err := newFormalGLMRegisteredPhase20TerminalOwnerV1(
		fixture.attempts[1], fixture.jobKeys[1], runtime, proposal, accept)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	controller, err := startFormalGLMRegisteredPhase20JobWorkerControllerV1(
		fixture.attempts[1], fixture.jobKeys[1], proposal, accept, epoch)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	if _, _, err := owner.VoteAbandonBeforePrepareV1(); !errors.Is(err, errFormalGLMRegisteredPhase20JobWorkerOwnerLockBusyV1) {
		t.Fatalf("live owner did not leave terminal abandonment pending: %v", err)
	}
	terminalStatus, terminalErr := owner.LoadStatusV1()
	attemptStatus, attemptErr := fixture.attempts[1].LoadStatus(nil)
	if terminalErr != nil || attemptErr != nil || terminalStatus.abandonChosen ||
		attemptStatus.votes[0] != nil || attemptStatus.votes[1] != nil {
		t.Fatalf("pending terminal abandonment chose or voted: %+v / %+v / %v / %v",
			terminalStatus, attemptStatus, terminalErr, attemptErr)
	}
	if err := controller.Close(); err != nil {
		t.Fatal(err)
	}
	vote, replayed, err := owner.VoteAbandonBeforePrepareV1()
	if err != nil || replayed {
		t.Fatalf("quiescent terminal abandonment retry failed: replay=%v err=%v",
			replayed, err)
	}
	replayedVote, replayed, err := owner.VoteAbandonBeforePrepareV1()
	if err != nil || !replayed || !reflect.DeepEqual(replayedVote, vote) {
		t.Fatalf("quiescent terminal abandonment replay changed: replay=%v err=%v",
			replayed, err)
	}
}
