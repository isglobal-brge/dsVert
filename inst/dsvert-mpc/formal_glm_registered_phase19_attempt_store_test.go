package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type formalGLMRegisteredPhase19AttemptTestCoreV1 struct {
	source formalGLMSourceContractTestFixtureV1
	record formalGLMRegisteredPhase19BindingRecordV1
}

var (
	formalGLMRegisteredPhase19AttemptK2Once sync.Once
	formalGLMRegisteredPhase19AttemptK2     formalGLMRegisteredPhase19AttemptTestCoreV1
)

func formalGLMRegisteredPhase19AttemptTestCoreK2(
	t testing.TB,
) formalGLMRegisteredPhase19AttemptTestCoreV1 {
	t.Helper()
	formalGLMRegisteredPhase19AttemptK2Once.Do(func() {
		fixture := formalGLMRegisteredPhase19PairKeyTestBuild(t, 2)
		formalGLMRegisteredPhase19AttemptK2 =
			formalGLMRegisteredPhase19AttemptTestCoreV1{
				source: fixture.source, record: fixture.record,
			}
	})
	return formalGLMRegisteredPhase19AttemptK2
}

func formalGLMRegisteredPhase19AttemptTestOpen(t testing.TB,
	root, peer string,
	core formalGLMRegisteredPhase19AttemptTestCoreV1,
) *formalGLMRegisteredPhase19AttemptStoreV1 {
	t.Helper()
	store, err := newFormalGLMRegisteredPhase19AttemptStoreV1(
		root, core.record, core.source.contract,
		core.source.inputs.identities.public, peer,
		core.source.inputs.identities.private[peer])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return store
}

func formalGLMRegisteredPhase19AttemptTestPair(t testing.TB,
	stores map[string]*formalGLMRegisteredPhase19AttemptStoreV1,
	core formalGLMRegisteredPhase19AttemptTestCoreV1,
	previous *formalGLMRegisteredPhase19AbandonedV1,
) (formalGLMRegisteredPhase19ClaimProposalV1,
	formalGLMRegisteredPhase19ClaimAcceptV1,
	[]formalGLMRegisteredPhase19DecisionVoteV1,
	formalGLMRegisteredPhase19AbandonedV1,
) {
	t.Helper()
	peers := core.source.plan.DesignatedComputePeers
	proposal, _, err := stores[peers[0]].Begin(previous)
	if err != nil {
		t.Fatal(err)
	}
	accept, _, err := stores[peers[1]].Accept(proposal)
	if err != nil {
		t.Fatal(err)
	}
	votes := make([]formalGLMRegisteredPhase19DecisionVoteV1, 2)
	for index, peer := range peers {
		votes[index], _, err = stores[peer].VoteAbandon(proposal, accept)
		if err != nil {
			t.Fatal(err)
		}
	}
	left, _, err := stores[peers[0]].CommitAbandoned(
		proposal, accept,
		[]formalGLMRegisteredPhase19DecisionVoteV1{votes[1], votes[0]})
	if err != nil {
		t.Fatal(err)
	}
	right, _, err := stores[peers[1]].CommitAbandoned(
		proposal, accept, votes)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(left, right) {
		t.Fatal("compute peers committed different abandoned attempts")
	}
	return proposal, accept, votes, left
}

func formalGLMRegisteredPhase19AttemptTestAssertStatus(t testing.TB,
	status formalGLMRegisteredPhase19AttemptStatusV1,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	votes []formalGLMRegisteredPhase19DecisionVoteV1,
	abandoned formalGLMRegisteredPhase19AbandonedV1,
) {
	t.Helper()
	if status.proposal == nil || status.accept == nil ||
		status.votes[0] == nil || status.votes[1] == nil ||
		status.abandoned == nil ||
		!reflect.DeepEqual(*status.proposal, proposal) ||
		!reflect.DeepEqual(*status.accept, accept) ||
		!reflect.DeepEqual(*status.votes[0], votes[0]) ||
		!reflect.DeepEqual(*status.votes[1], votes[1]) ||
		!reflect.DeepEqual(*status.abandoned, abandoned) {
		t.Fatal("registered Phase19 attempt status is incomplete")
	}
}

func formalGLMRegisteredPhase19AttemptTestPublicJSON(t testing.TB,
	values ...any,
) {
	t.Helper()
	for _, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(string(encoded))
		for _, forbidden := range []string{
			"capsule", "run_id", "pre_execution", "preexecution",
			"path", "key", "secret", "backend", "private_key",
		} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("attempt DTO exposed %q: %s", forbidden, encoded)
			}
		}
	}
}

func TestFormalGLMRegisteredPhase19AttemptK2RestartAndTwoAttempts(
	t *testing.T,
) {
	core := formalGLMRegisteredPhase19AttemptTestCoreK2(t)
	peers := core.source.plan.DesignatedComputePeers
	roots := map[string]string{
		peers[0]: filepath.Join(t.TempDir(), "garbler-rock"),
		peers[1]: filepath.Join(t.TempDir(), "evaluator-rock"),
	}
	stores := make(map[string]*formalGLMRegisteredPhase19AttemptStoreV1, 2)
	for _, peer := range peers {
		stores[peer] = formalGLMRegisteredPhase19AttemptTestOpen(
			t, roots[peer], peer, core)
	}
	proposal1, accept1, votes1, abandoned1 :=
		formalGLMRegisteredPhase19AttemptTestPair(t, stores, core, nil)
	if proposal1.Binding.PreviousAbandonSHA256 !=
		formalGLMRegisteredPhase19AttemptZeroPreviousV1 ||
		proposal1.Binding.PreviousAttemptID !=
			formalGLMRegisteredPhase19AttemptZeroPreviousV1 {
		t.Fatal("first attempt did not use the canonical zero predecessor")
	}
	wantAttempt1, err := formalGLMRegisteredPhase19AttemptIDV1(
		core.record.Binding.SemanticRootSHA256,
		formalGLMRegisteredPhase19AttemptZeroPreviousV1)
	if err != nil {
		t.Fatal(err)
	}
	wantSchedule1, err := formalGLMRegisteredPhase19AttemptScheduleRootV1(
		core.record.Binding.SemanticRootSHA256, wantAttempt1)
	if err != nil || proposal1.Binding.AttemptID != wantAttempt1 ||
		proposal1.Binding.ScheduleRootSHA256 != wantSchedule1 {
		t.Fatal("first attempt identity or schedule root is not canonical")
	}
	replay, replayed, err := stores[peers[0]].Begin(nil)
	if err != nil || !replayed || !reflect.DeepEqual(replay, proposal1) {
		t.Fatalf("first claim did not replay exactly: %v %v", replayed, err)
	}
	for _, peer := range peers {
		status, err := stores[peer].LoadStatus(nil)
		if err != nil {
			t.Fatal(err)
		}
		formalGLMRegisteredPhase19AttemptTestAssertStatus(
			t, status, proposal1, accept1, votes1, abandoned1)
		stores[peer].Close()
		stores[peer] = formalGLMRegisteredPhase19AttemptTestOpen(
			t, roots[peer], peer, core)
		status, err = stores[peer].LoadStatus(nil)
		if err != nil {
			t.Fatal(err)
		}
		formalGLMRegisteredPhase19AttemptTestAssertStatus(
			t, status, proposal1, accept1, votes1, abandoned1)
	}

	proposal2, accept2, votes2, abandoned2 :=
		formalGLMRegisteredPhase19AttemptTestPair(
			t, stores, core, &abandoned1)
	if proposal2.Binding.PreviousAbandonSHA256 !=
		abandoned1.AbandonedSHA256 ||
		proposal2.Binding.PreviousAttemptID != proposal1.Binding.AttemptID ||
		proposal2.Binding.AttemptID == proposal1.Binding.AttemptID ||
		abandoned2.AbandonedSHA256 == abandoned1.AbandonedSHA256 {
		t.Fatal("second attempt did not advance the exact abandoned chain")
	}
	for _, peer := range peers {
		status, err := stores[peer].LoadStatus(&abandoned1)
		if err != nil {
			t.Fatal(err)
		}
		formalGLMRegisteredPhase19AttemptTestAssertStatus(
			t, status, proposal2, accept2, votes2, abandoned2)
	}
	formalGLMRegisteredPhase19AttemptTestPublicJSON(
		t, proposal1, accept1, votes1[0], votes1[1], abandoned1,
		proposal2, accept2, abandoned2)
	for rootIndex, root := range roots {
		if err := filepath.WalkDir(root,
			func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				info, err := entry.Info()
				if err != nil {
					return err
				}
				if entry.IsDir() && info.Mode().Perm() != 0o700 {
					return fmt.Errorf("directory mode %o at %s",
						info.Mode().Perm(), path)
				}
				if !entry.IsDir() && info.Mode().Perm() != 0o600 {
					return fmt.Errorf("record mode %o at %s",
						info.Mode().Perm(), path)
				}
				return nil
			}); err != nil {
			t.Fatalf("%s filesystem: %v", rootIndex, err)
		}
	}
}

func TestFormalGLMRegisteredPhase19AttemptConcurrentExactCAS(t *testing.T) {
	core := formalGLMRegisteredPhase19AttemptTestCoreK2(t)
	peer := core.source.plan.DesignatedComputePeers[0]
	root := filepath.Join(t.TempDir(), "shared-garbler-rock")
	stores := []*formalGLMRegisteredPhase19AttemptStoreV1{
		formalGLMRegisteredPhase19AttemptTestOpen(t, root, peer, core),
		formalGLMRegisteredPhase19AttemptTestOpen(t, root, peer, core),
	}
	type result struct {
		proposal formalGLMRegisteredPhase19ClaimProposalV1
		replayed bool
		err      error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for _, store := range stores {
		go func(store *formalGLMRegisteredPhase19AttemptStoreV1) {
			<-start
			proposal, replayed, err := store.Begin(nil)
			results <- result{proposal: proposal, replayed: replayed, err: err}
		}(store)
	}
	close(start)
	left, right := <-results, <-results
	if left.err != nil || right.err != nil ||
		!reflect.DeepEqual(left.proposal, right.proposal) ||
		left.replayed == right.replayed {
		t.Fatalf("concurrent attempt CAS differed: %+v %+v", left, right)
	}
}

func TestFormalGLMRegisteredPhase19AttemptRejectsTamperRolesAndForks(
	t *testing.T,
) {
	core := formalGLMRegisteredPhase19AttemptTestCoreK2(t)
	peers := core.source.plan.DesignatedComputePeers
	stores := map[string]*formalGLMRegisteredPhase19AttemptStoreV1{
		peers[0]: formalGLMRegisteredPhase19AttemptTestOpen(
			t, filepath.Join(t.TempDir(), "garbler-rock"), peers[0], core),
		peers[1]: formalGLMRegisteredPhase19AttemptTestOpen(
			t, filepath.Join(t.TempDir(), "evaluator-rock"), peers[1], core),
	}
	proposal, _, err := stores[peers[0]].Begin(nil)
	if err != nil {
		t.Fatal(err)
	}
	accept, _, err := stores[peers[1]].Accept(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := stores[peers[1]].Begin(nil); err == nil {
		t.Fatal("evaluator issued a garbler claim")
	}
	if _, _, err := stores[peers[0]].Accept(proposal); err == nil {
		t.Fatal("garbler issued an evaluator accept")
	}
	if wrong, err := newFormalGLMRegisteredPhase19AttemptStoreV1(
		filepath.Join(t.TempDir(), "wrong-signer"), core.record,
		core.source.contract, core.source.inputs.identities.public, peers[0],
		core.source.inputs.identities.private[peers[1]]); err == nil {
		wrong.Close()
		t.Fatal("constructor accepted the other role's signing key")
	}

	tamperedSemantic := formalGLMRegisteredPhase18ProvenanceTestClone(
		t, proposal)
	tamperedSemantic.Binding.SemanticRootSHA256 =
		formalGLMRegisteredPhase19BindingTestDifferentSHA(
			tamperedSemantic.Binding.SemanticRootSHA256)
	tamperedSemantic.Signature = nil
	message, err := formalGLMRegisteredPhase19AttemptSignatureMessageV1(
		formalGLMRegisteredPhase19ClaimProposalDomainV1, tamperedSemantic)
	if err != nil {
		t.Fatal(err)
	}
	tamperedSemantic.Signature = ed25519.Sign(
		core.source.inputs.identities.private[peers[0]], message)
	if _, _, err := stores[peers[1]].Accept(tamperedSemantic); err == nil {
		t.Fatal("validly signed claim with another SemanticRoot was accepted")
	}

	tamperedPrevious := formalGLMRegisteredPhase18ProvenanceTestClone(
		t, proposal)
	tamperedPrevious.Binding.PreviousAbandonSHA256 = sha256Hex(
		[]byte("registered-phase19/unknown-previous-abandon"))
	tamperedPrevious.Binding.PreviousAttemptID = sha256Hex(
		[]byte("registered-phase19/unknown-previous-attempt"))
	tamperedPrevious.Binding.AttemptID, err =
		formalGLMRegisteredPhase19AttemptIDV1(
			tamperedPrevious.Binding.SemanticRootSHA256,
			tamperedPrevious.Binding.PreviousAbandonSHA256)
	if err != nil {
		t.Fatal(err)
	}
	tamperedPrevious.Binding.ScheduleRootSHA256, err =
		formalGLMRegisteredPhase19AttemptScheduleRootV1(
			tamperedPrevious.Binding.SemanticRootSHA256,
			tamperedPrevious.Binding.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	tamperedPrevious.Signature = nil
	message, err = formalGLMRegisteredPhase19AttemptSignatureMessageV1(
		formalGLMRegisteredPhase19ClaimProposalDomainV1, tamperedPrevious)
	if err != nil {
		t.Fatal(err)
	}
	tamperedPrevious.Signature = ed25519.Sign(
		core.source.inputs.identities.private[peers[0]], message)
	if _, _, err := stores[peers[1]].Accept(tamperedPrevious); err == nil {
		t.Fatal("claim with an unavailable previous abandonment was accepted")
	}

	vote, _, err := stores[peers[0]].VoteAbandon(proposal, accept)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := stores[peers[0]].CommitAbandoned(
		proposal, accept,
		[]formalGLMRegisteredPhase19DecisionVoteV1{vote}); err == nil {
		t.Fatal("one abandonment vote committed a terminal abandonment")
	}
	tamperedVote := formalGLMRegisteredPhase18ProvenanceTestClone(t, vote)
	tamperedVote.VoterRole = "evaluator"
	tamperedVote.Signature = nil
	message, err = formalGLMRegisteredPhase19AttemptSignatureMessageV1(
		formalGLMRegisteredPhase19DecisionVoteDomainV1, tamperedVote)
	if err != nil {
		t.Fatal(err)
	}
	tamperedVote.Signature = ed25519.Sign(
		core.source.inputs.identities.private[peers[0]], message)
	if _, _, err := stores[peers[0]].CommitAbandoned(
		proposal, accept,
		[]formalGLMRegisteredPhase19DecisionVoteV1{tamperedVote, vote}); err == nil {
		t.Fatal("wrong-role abandonment vote was accepted")
	}
}

func TestFormalGLMRegisteredPhase19AttemptForkAndHardlinkFailClosed(
	t *testing.T,
) {
	core := formalGLMRegisteredPhase19AttemptTestCoreK2(t)
	peer := core.source.plan.DesignatedComputePeers[0]

	t.Run("unsafe-root-mode", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "unsafe-rock")
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatal(err)
		}
		store, err := newFormalGLMRegisteredPhase19AttemptStoreV1(
			root, core.record, core.source.contract,
			core.source.inputs.identities.public, peer,
			core.source.inputs.identities.private[peer])
		if err == nil {
			store.Close()
			t.Fatal("attempt store accepted a non-private Rock root")
		}
	})

	t.Run("fork", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "fork-rock")
		store := formalGLMRegisteredPhase19AttemptTestOpen(t, root, peer, core)
		proposal, _, err := store.Begin(nil)
		if err != nil {
			t.Fatal(err)
		}
		fork := formalGLMRegisteredPhase18ProvenanceTestClone(t, proposal)
		fork.Binding.ScheduleRootSHA256 = sha256Hex(
			[]byte("registered-phase19/forked-schedule"))
		fork.Signature = nil
		message, err := formalGLMRegisteredPhase19AttemptSignatureMessageV1(
			formalGLMRegisteredPhase19ClaimProposalDomainV1, fork)
		if err != nil {
			t.Fatal(err)
		}
		fork.Signature = ed25519.Sign(
			core.source.inputs.identities.private[peer], message)
		encoded, err := json.Marshal(fork)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, store.attemptRelativePathV1(
			proposal.Binding.AttemptID,
			formalGLMRegisteredPhase19ClaimProposalFileV1))
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.Begin(nil); err == nil {
			t.Fatal("same predecessor accepted different claim bytes")
		}
	})

	t.Run("hardlink", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "hardlink-rock")
		store := formalGLMRegisteredPhase19AttemptTestOpen(t, root, peer, core)
		proposal, _, err := store.Begin(nil)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, store.attemptRelativePathV1(
			proposal.Binding.AttemptID,
			formalGLMRegisteredPhase19ClaimProposalFileV1))
		if err := os.Link(path, path+".hardlink"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.LoadStatus(nil); err == nil {
			t.Fatal("hard-linked attempt record was accepted")
		}
	})
}

func TestFormalGLMRegisteredPhase19AttemptK5Shape(t *testing.T) {
	fixture := formalGLMSourceContractTestFixture(t, 5)
	if len(fixture.plan.NoiseAuthorities) != 2 ||
		fixture.plan.NoiseAuthorities[0].Role != "garbler" ||
		fixture.plan.NoiseAuthorities[1].Role != "evaluator" {
		t.Fatal("K5 registered plan does not expose the ordered compute pair")
	}
	semantic := sha256Hex([]byte("registered-phase19/K5/semantic"))
	attempt, err := formalGLMRegisteredPhase19AttemptIDV1(
		semantic, formalGLMRegisteredPhase19AttemptZeroPreviousV1)
	if err != nil {
		t.Fatal(err)
	}
	schedule, err := formalGLMRegisteredPhase19AttemptScheduleRootV1(
		semantic, attempt)
	if err != nil || !formalGLMIsSHA256(attempt) ||
		!formalGLMIsSHA256(schedule) || attempt == schedule {
		t.Fatalf("invalid K5 attempt shape: %s %s %v", attempt, schedule, err)
	}
}

func TestFormalGLMRegisteredPhase19AttemptProviderDoesNotSerializeSigner(
	t *testing.T,
) {
	core := formalGLMRegisteredPhase19AttemptTestCoreK2(t)
	peer := core.source.plan.DesignatedComputePeers[0]
	store := formalGLMRegisteredPhase19AttemptTestOpen(
		t, filepath.Join(t.TempDir(), "private-store"), peer, core)
	encoded, err := json.Marshal(store)
	if err != nil || !bytes.Equal(encoded, []byte("{}")) {
		t.Fatalf("attempt store serialized private state: %s %v", encoded, err)
	}
}
