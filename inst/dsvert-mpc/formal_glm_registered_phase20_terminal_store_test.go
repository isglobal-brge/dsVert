package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func formalGLMRegisteredPhase20TerminalTestCopyRockV1(
	t testing.TB, source string,
) string {
	t.Helper()
	target := filepath.Join(t.TempDir(), "rock-copy")
	if err := filepath.WalkDir(source,
		func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			relative, err := filepath.Rel(source, path)
			if err != nil {
				return err
			}
			destination := filepath.Join(target, relative)
			if entry.IsDir() {
				return os.MkdirAll(destination, 0o700)
			}
			encoded, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(destination, encoded, 0o600)
		}); err != nil {
		t.Fatal(err)
	}
	return target
}

func formalGLMRegisteredPhase20TerminalTestOpenV1(
	t testing.TB,
	root string,
	index int,
	fixture formalGLMRegisteredPhase20DPShareReceiptTestFixtureV1,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
) *formalGLMRegisteredPhase20TerminalOwnerV1 {
	t.Helper()
	base := fixture.evidence
	peer := base.source.plan.DesignatedComputePeers[index]
	attempts, err := newFormalGLMRegisteredPhase19AttemptStoreV1(
		root, base.record, base.source.contract,
		base.source.inputs.identities.public, peer,
		base.source.inputs.identities.private[peer])
	if err != nil {
		t.Fatal(err)
	}
	keys, err := newFormalGLMRegisteredPhase20JobKeyProviderV1(
		root, base.source.contract, base.source.inputs.identities.public,
		base.record, peer)
	if err != nil {
		attempts.Close()
		t.Fatal(err)
	}
	owner, err := newFormalGLMRegisteredPhase20TerminalOwnerV1(
		attempts, keys, base.runtime, proposal, accept)
	if err != nil {
		attempts.Close()
		_ = keys.Close()
		t.Fatal(err)
	}
	return owner
}

func formalGLMRegisteredPhase20TerminalTestPrivateJSONV1(
	t testing.TB, value any,
) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("terminal trust object became serializable: %s / %v",
			encoded, err)
	}
}

func formalGLMRegisteredPhase20TerminalTestPublicJSONV1(
	t testing.TB,
	shares [2]string,
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
			"canonical_dp_share", "evidence_seal_sha256", "post_execution_token",
			"capsule", "run_id", "pre_execution", "path", "key", "secret",
		} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("terminal DTO exposed %q: %s", forbidden, encoded)
			}
		}
		for _, share := range shares {
			if share != "" && bytes.Contains(encoded, []byte(share)) {
				t.Fatal("terminal DTO exposed a canonical DP share")
			}
		}
	}
}

func formalGLMRegisteredPhase20TerminalTestAssertFilesV1(
	t testing.TB,
	root string,
	relative [4]string,
	shares [2]string,
) {
	t.Helper()
	for _, item := range relative {
		path := filepath.Join(root, item)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() ||
			info.Mode().Perm() != 0o600 ||
			!exactGCPrivateOwnedRegular(info) {
			t.Fatalf("unsafe terminal file %s: %v", path, err)
		}
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, share := range shares {
			if share != "" && bytes.Contains(encoded, []byte(share)) {
				t.Fatalf("terminal file %s exposed a raw DP share", path)
			}
		}
		lower := strings.ToLower(string(encoded))
		if strings.Contains(lower, "canonical_dp_share") ||
			strings.Contains(lower, "evidence_seal_sha256") {
			t.Fatalf("terminal file %s exposed a private evidence field", path)
		}
	}
}

func formalGLMRegisteredPhase20TerminalTestFlipCiphertextV1(
	t testing.TB, path string,
) {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	marker := []byte(`"ciphertext":"`)
	index := bytes.Index(encoded, marker)
	if index < 0 || index+len(marker) >= len(encoded) {
		t.Fatal("encrypted prepare has no ciphertext")
	}
	index += len(marker)
	if encoded[index] == 'A' {
		encoded[index] = 'B'
	} else {
		encoded[index] = 'A'
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFormalGLMRegisteredPhase20TerminalStoreK2PrepareSelectRestartAndFailClosed(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase20DPShareReceiptTestBuildV1(t)
	base := fixture.evidence
	record, contract := base.record, base.source.contract
	pins := base.source.inputs.identities.public
	private := base.source.inputs.identities.private
	peers := base.source.plan.DesignatedComputePeers
	evidence := [2]formalGLMRegisteredPhase20PreparedEvidenceV1{
		fixture.garbler, fixture.evaluator,
	}
	shares := [2]string{
		evidence[0].CanonicalDPShare, evidence[1].CanonicalDPShare,
	}
	roots := [2]string{
		filepath.Join(t.TempDir(), "garbler-rock"),
		filepath.Join(t.TempDir(), "evaluator-rock"),
	}

	var attempts [2]*formalGLMRegisteredPhase19AttemptStoreV1
	for index, peer := range peers {
		var err error
		attempts[index], err = newFormalGLMRegisteredPhase19AttemptStoreV1(
			roots[index], record, contract, pins, peer, private[peer])
		if err != nil {
			t.Fatal(err)
		}
	}
	proposal, _, err := attempts[0].Begin(nil)
	if err != nil {
		t.Fatal(err)
	}
	accept, _, err := attempts[1].Accept(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(proposal, base.proposal) ||
		!reflect.DeepEqual(accept, fixture.accept) {
		t.Fatal("terminal fixture did not reproduce the accepted claim")
	}
	for index, peer := range peers {
		if err := formalGLMRegisteredPhase19ScheduleTailPersistClaimV1(
			attempts[index], record, contract, pins, peer,
			proposal, accept); err != nil {
			t.Fatal(err)
		}
	}
	var keys [2]*formalGLMRegisteredPhase20JobKeyProviderV1
	var owners [2]*formalGLMRegisteredPhase20TerminalOwnerV1
	for index, peer := range peers {
		keys[index], err = newFormalGLMRegisteredPhase20JobKeyProviderV1(
			roots[index], contract, pins, record, peer)
		if err != nil {
			t.Fatal(err)
		}
		owners[index], err = newFormalGLMRegisteredPhase20TerminalOwnerV1(
			attempts[index], keys[index], base.runtime, proposal, accept)
		if err != nil {
			t.Fatal(err)
		}
		formalGLMRegisteredPhase20TerminalTestPrivateJSONV1(t, owners[index])
	}
	abandonRoots := [2]string{
		formalGLMRegisteredPhase20TerminalTestCopyRockV1(t, roots[0]),
		formalGLMRegisteredPhase20TerminalTestCopyRockV1(t, roots[1]),
	}
	choiceRaceRoot := formalGLMRegisteredPhase20TerminalTestCopyRockV1(
		t, roots[1])

	if _, _, err := owners[0].VoteSelectV1(
		formalGLMRegisteredPhase20PrepareReceiptV1{}); err == nil {
		t.Fatal("select vote was accepted before local prepare")
	}
	if _, _, err := owners[0].CommitSelectedV1(
		formalGLMRegisteredPhase20SelectVoteV1{}); err == nil {
		t.Fatal("Selected was accepted before local vote")
	}
	for index := range owners {
		replayed, err := owners[index].SealLocalEvidenceV1(evidence[index])
		if err != nil || replayed {
			t.Fatalf("seal local evidence %d: replay=%v err=%v",
				index, replayed, err)
		}
	}
	if replayed, err := owners[0].SealLocalEvidenceV1(evidence[0]); err != nil || !replayed {
		t.Fatalf("sealed evidence replay failed: replay=%v err=%v", replayed, err)
	}
	conflictingEvidence := evidence[0]
	conflictingEvidence.EvidenceSealSHA256 = strings.Repeat("f", 64)
	if _, err := owners[0].SealLocalEvidenceV1(conflictingEvidence); err == nil {
		t.Fatal("conflicting evidence replaced the durable draft")
	}
	if err := owners[0].Close(); err != nil {
		t.Fatal(err)
	}
	owners[0] = formalGLMRegisteredPhase20TerminalTestOpenV1(
		t, roots[0], 0, fixture, proposal, accept)
	status, err := owners[0].LoadStatusV1()
	if err != nil || !status.draftSealed || status.prepareReceipt != nil {
		t.Fatalf("draft crash recovery failed: %v", err)
	}

	garblerReceipt, err := owners[0].PublishDPShareReceiptV1()
	if err != nil {
		t.Fatal(err)
	}
	garblerReceiptReplay, err := owners[0].PublishDPShareReceiptV1()
	if err != nil || !reflect.DeepEqual(garblerReceiptReplay, garblerReceipt) {
		t.Fatalf("garbler receipt replay changed before restart: %v", err)
	}
	if err := owners[0].Close(); err != nil {
		t.Fatal(err)
	}
	owners[0] = formalGLMRegisteredPhase20TerminalTestOpenV1(
		t, roots[0], 0, fixture, proposal, accept)
	garblerReceiptReplay, err = owners[0].PublishDPShareReceiptV1()
	if err != nil || !reflect.DeepEqual(garblerReceiptReplay, garblerReceipt) {
		t.Fatalf("garbler receipt replay changed after restart: %v", err)
	}
	garblerReceiptReplay.Signature[0] ^= 1
	garblerReceiptReplay, err = owners[0].PublishDPShareReceiptV1()
	if err != nil || !reflect.DeepEqual(garblerReceiptReplay, garblerReceipt) {
		t.Fatalf("garbler receipt cache aliased its caller: %v", err)
	}
	choiceRaceOwners := [2]*formalGLMRegisteredPhase20TerminalOwnerV1{
		formalGLMRegisteredPhase20TerminalTestOpenV1(
			t, choiceRaceRoot, 1, fixture, proposal, accept),
		formalGLMRegisteredPhase20TerminalTestOpenV1(
			t, choiceRaceRoot, 1, fixture, proposal, accept),
	}
	if replayed, err := choiceRaceOwners[0].SealLocalEvidenceV1(
		evidence[1]); err != nil || replayed {
		t.Fatalf("choice race draft: replay=%v err=%v", replayed, err)
	}
	choiceRaceOwners[0].mu.Lock()
	racedDraft, err := choiceRaceOwners[0].readDraftLockedV1()
	if err != nil {
		choiceRaceOwners[0].mu.Unlock()
		t.Fatal(err)
	}
	racePair, err := choiceRaceOwners[0].pairLocalReceiptsV1(
		racedDraft, garblerReceipt)
	if err != nil {
		racedDraft.clear()
		choiceRaceOwners[0].mu.Unlock()
		t.Fatal(err)
	}
	racePrepared, err := choiceRaceOwners[0].preparedRecordV1(
		racedDraft, racePair)
	racedDraft.clear()
	if err != nil {
		choiceRaceOwners[0].mu.Unlock()
		t.Fatal(err)
	}
	prepareChoice, err := choiceRaceOwners[0].choiceV1(
		formalGLMRegisteredPhase20TerminalPrepareChoiceV1, &racePrepared)
	choiceRaceOwners[0].mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	choiceRaceOwners[1].mu.Lock()
	abandonChoice, err := choiceRaceOwners[1].choiceV1(
		formalGLMRegisteredPhase20TerminalAbandonChoiceV1, nil)
	choiceRaceOwners[1].mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	startChoiceRace := make(chan struct{})
	var choiceRaceWait sync.WaitGroup
	var prepareRaceErr, abandonRaceErr error
	choiceRaceWait.Add(2)
	go func() {
		defer choiceRaceWait.Done()
		<-startChoiceRace
		choiceRaceOwners[0].mu.Lock()
		_, prepareRaceErr = choiceRaceOwners[0].chooseV1(prepareChoice)
		choiceRaceOwners[0].mu.Unlock()
	}()
	go func() {
		defer choiceRaceWait.Done()
		<-startChoiceRace
		choiceRaceOwners[1].mu.Lock()
		_, abandonRaceErr = choiceRaceOwners[1].chooseV1(abandonChoice)
		choiceRaceOwners[1].mu.Unlock()
	}()
	close(startChoiceRace)
	choiceRaceWait.Wait()
	prepareWon, abandonWon := prepareRaceErr == nil, abandonRaceErr == nil
	if prepareWon == abandonWon {
		t.Fatalf("prepare/abandon choice race was not exclusive: prepare=%v abandon=%v",
			prepareRaceErr, abandonRaceErr)
	}
	choiceRaceOwners[0].mu.Lock()
	persistedChoice, found, err := choiceRaceOwners[0].readChoiceV1()
	choiceRaceOwners[0].mu.Unlock()
	wantChoice := abandonChoice
	if prepareWon {
		wantChoice = prepareChoice
	}
	if err != nil || !found || !reflect.DeepEqual(persistedChoice, wantChoice) {
		t.Fatalf("prepare/abandon CAS persisted the wrong winner: %v", err)
	}
	for _, owner := range choiceRaceOwners {
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
	}
	choiceRaceRestart := formalGLMRegisteredPhase20TerminalTestOpenV1(
		t, choiceRaceRoot, 1, fixture, proposal, accept)
	choiceRaceStatus, err := choiceRaceRestart.LoadStatusV1()
	if err != nil || choiceRaceStatus.abandonChosen != abandonWon ||
		(choiceRaceStatus.prepareReceipt != nil) != prepareWon ||
		choiceRaceStatus.selectVote != nil || choiceRaceStatus.selected != nil {
		t.Fatalf("prepare/abandon choice race restart invalid: %v", err)
	}
	if err := choiceRaceRestart.Close(); err != nil {
		t.Fatal(err)
	}
	tamperedGarblerReceipt := garblerReceipt
	tamperedGarblerReceipt.Signature = append(
		[]byte(nil), tamperedGarblerReceipt.Signature...)
	tamperedGarblerReceipt.Signature[0] ^= 1
	if _, _, err := owners[1].PrepareFromGarblerReceiptV1(
		tamperedGarblerReceipt); err == nil {
		t.Fatal("tampered garbler receipt created a prepare marker")
	}
	status, err = owners[1].LoadStatusV1()
	if err != nil || !status.draftSealed || status.prepareReceipt != nil {
		t.Fatalf("failed evaluator prepare changed durable state: %v", err)
	}

	bundle, replayed, err := owners[1].PrepareFromGarblerReceiptV1(
		garblerReceipt)
	if err != nil || replayed {
		t.Fatalf("evaluator prepare: replay=%v err=%v", replayed, err)
	}
	if err := owners[1].Close(); err != nil {
		t.Fatal(err)
	}
	owners[1] = formalGLMRegisteredPhase20TerminalTestOpenV1(
		t, roots[1], 1, fixture, proposal, accept)
	replayedBundle, replayed, err := owners[1].PrepareFromGarblerReceiptV1(
		garblerReceipt)
	if err != nil || !replayed || !reflect.DeepEqual(replayedBundle, bundle) {
		t.Fatalf("evaluator prepare restart changed: replay=%v err=%v",
			replayed, err)
	}
	if _, _, err := owners[1].PrepareFromGarblerReceiptV1(
		tamperedGarblerReceipt); err == nil {
		t.Fatal("durable evaluator prepare accepted a receipt fork")
	}
	if _, _, err := owners[0].VoteSelectV1(
		bundle.EvaluatorPrepare); err == nil {
		t.Fatal("garbler voted before persisting its prepare")
	}
	tamperedBundle := bundle
	tamperedBundle.Pair.PairSHA256 = strings.Repeat("0", 64)
	if tamperedBundle.Pair.PairSHA256 == bundle.Pair.PairSHA256 {
		tamperedBundle.Pair.PairSHA256 = strings.Repeat("1", 64)
	}
	if _, _, err := owners[0].PrepareFromEvaluatorBundleV1(
		tamperedBundle); err == nil {
		t.Fatal("tampered evaluator bundle created a garbler prepare marker")
	}
	garblerPrepare, replayed, err := owners[0].PrepareFromEvaluatorBundleV1(
		bundle)
	if err != nil || replayed {
		t.Fatalf("garbler prepare: replay=%v err=%v", replayed, err)
	}
	prepare := [2]formalGLMRegisteredPhase20PrepareReceiptV1{
		garblerPrepare, bundle.EvaluatorPrepare,
	}
	pair := bundle.Pair
	for index := range owners {
		if _, _, err := owners[index].VoteAbandonBeforePrepareV1(); err == nil {
			t.Fatal("irreversible prepare marker allowed abandonment")
		}
		if _, _, err := owners[index].CommitAbandonedBeforePrepareV1(nil); err == nil {
			t.Fatal("irreversible prepare marker allowed abandoned aggregate")
		}
	}
	if prepare[0].CommonEvidenceSHA256 != prepare[1].CommonEvidenceSHA256 ||
		prepare[0].DPShareReceiptPairSHA256 != pair.PairSHA256 ||
		prepare[1].DPShareReceiptPairSHA256 != pair.PairSHA256 ||
		prepare[0].DraftRecordSHA256 == prepare[1].DraftRecordSHA256 {
		t.Fatal("prepare receipts did not bind common evidence and distinct local records")
	}
	formalGLMRegisteredPhase20TerminalTestPublicJSONV1(
		t, shares, pair, bundle, prepare[0], prepare[1])
	for _, mode := range []os.FileMode{0o400, 0o700} {
		modeRoot := formalGLMRegisteredPhase20TerminalTestCopyRockV1(
			t, roots[1])
		modeOwner := formalGLMRegisteredPhase20TerminalTestOpenV1(
			t, modeRoot, 1, fixture, proposal, accept)
		modeOwner.mu.Lock()
		choice, found, err := modeOwner.readChoiceV1()
		modeOwner.mu.Unlock()
		if err != nil || !found {
			t.Fatalf("read choice before mode tamper: %v", err)
		}
		if err := os.Chmod(
			filepath.Join(modeRoot, modeOwner.choiceRelativePath), mode); err != nil {
			t.Fatal(err)
		}
		modeOwner.mu.Lock()
		_, replayErr := modeOwner.chooseV1(choice)
		modeOwner.mu.Unlock()
		if replayErr == nil {
			t.Fatalf("open owner replayed choice with mode %#o", mode)
		}
		if err := modeOwner.Close(); err != nil {
			t.Fatal(err)
		}
	}
	tamperedChoiceRoot := formalGLMRegisteredPhase20TerminalTestCopyRockV1(
		t, roots[1])
	tamperedChoicePath := filepath.Join(
		tamperedChoiceRoot, owners[1].choiceRelativePath)
	encodedChoice, err := os.ReadFile(tamperedChoicePath)
	if err != nil {
		t.Fatal(err)
	}
	var tamperedChoice formalGLMRegisteredPhase20TerminalChoiceV1
	if err := json.Unmarshal(encodedChoice, &tamperedChoice); err != nil {
		t.Fatal(err)
	}
	tamperedChoice.Decision = formalGLMRegisteredPhase20TerminalAbandonChoiceV1
	tamperedChoice.Prepared = nil
	encodedChoice, err = json.Marshal(tamperedChoice)
	if err != nil || os.WriteFile(tamperedChoicePath, encodedChoice, 0o600) != nil {
		t.Fatal("could not tamper prepare-only choice")
	}
	tamperedAttempts, err := newFormalGLMRegisteredPhase19AttemptStoreV1(
		tamperedChoiceRoot, record, contract, pins, peers[1], private[peers[1]])
	if err != nil {
		t.Fatal(err)
	}
	tamperedKeys, err := newFormalGLMRegisteredPhase20JobKeyProviderV1(
		tamperedChoiceRoot, contract, pins, record, peers[1])
	if err != nil {
		tamperedAttempts.Close()
		t.Fatal(err)
	}
	if tamperedOwner, err := newFormalGLMRegisteredPhase20TerminalOwnerV1(
		tamperedAttempts, tamperedKeys, base.runtime, proposal, accept); err == nil {
		_ = tamperedOwner.Close()
		t.Fatal("unsigned prepare-to-abandon choice rewrite reopened")
	} else {
		tamperedAttempts.Close()
		_ = tamperedKeys.Close()
	}

	paths := [2][4]string{}
	for index := range owners {
		paths[index] = [4]string{
			owners[index].draftRelativePath,
			owners[index].choiceRelativePath,
			owners[index].voteRelativePath,
			owners[index].selectedRelativePath,
		}
		if err := owners[index].Close(); err != nil {
			t.Fatal(err)
		}
		owners[index] = formalGLMRegisteredPhase20TerminalTestOpenV1(
			t, roots[index], index, fixture, proposal, accept)
		status, err := owners[index].LoadStatusV1()
		if err != nil || !status.draftSealed || status.prepareReceipt == nil ||
			!reflect.DeepEqual(*status.prepareReceipt, prepare[index]) ||
			status.selectVote != nil || status.selected != nil {
			t.Fatalf("prepare crash recovery %d failed: %v", index, err)
		}
	}

	tamperedPrepare := prepare[1]
	tamperedPrepare.CommonEvidenceSHA256 = strings.Repeat("f", 64)
	if _, _, err := owners[0].VoteSelectV1(tamperedPrepare); err == nil {
		t.Fatal("relay of a forked prepare receipt was accepted")
	}
	var votes [2]formalGLMRegisteredPhase20SelectVoteV1
	votes[0], _, err = owners[0].VoteSelectV1(prepare[1])
	if err != nil {
		t.Fatal(err)
	}
	votes[1], _, err = owners[1].VoteSelectV1(prepare[0])
	if err != nil {
		t.Fatal(err)
	}
	if votes[0].PrepareReceiptSetSHA256 != votes[1].PrepareReceiptSetSHA256 {
		t.Fatal("K2 peers voted over different prepare receipt sets")
	}
	if replay, replayed, err := owners[0].VoteSelectV1(prepare[1]); err != nil || !replayed || !reflect.DeepEqual(replay, votes[0]) {
		t.Fatalf("select-vote replay changed: replay=%v err=%v", replayed, err)
	}
	if _, _, err := owners[0].VoteSelectV1(tamperedPrepare); err == nil {
		t.Fatal("durable select vote accepted a fork")
	}
	formalGLMRegisteredPhase20TerminalTestPublicJSONV1(
		t, shares, votes[0], votes[1])

	for index := range owners {
		if err := owners[index].Close(); err != nil {
			t.Fatal(err)
		}
		owners[index] = formalGLMRegisteredPhase20TerminalTestOpenV1(
			t, roots[index], index, fixture, proposal, accept)
		status, err := owners[index].LoadStatusV1()
		if err != nil || status.prepareReceipt == nil || status.selectVote == nil ||
			!reflect.DeepEqual(*status.selectVote, votes[index]) ||
			status.selected != nil {
			t.Fatalf("vote crash recovery %d failed: %v", index, err)
		}
	}
	if _, _, err := owners[0].CommitSelectedV1(
		formalGLMRegisteredPhase20SelectVoteV1{}); err == nil {
		t.Fatal("reordered empty remote vote was accepted")
	}
	tamperedVote := votes[1]
	tamperedVote.Signature = append([]byte(nil), tamperedVote.Signature...)
	tamperedVote.Signature[0] ^= 1
	if _, _, err := owners[0].CommitSelectedV1(tamperedVote); err == nil {
		t.Fatal("forked remote select vote was accepted")
	}

	var selected [2]formalGLMRegisteredPhase20SelectedV1
	selected[0], _, err = owners[0].CommitSelectedV1(votes[1])
	if err != nil {
		t.Fatal(err)
	}
	selected[1], _, err = owners[1].CommitSelectedV1(votes[0])
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(selected[0], selected[1]) ||
		selected[0].CommonEvidenceSHA256 != pair.Garbler.CommonEvidenceSHA256 ||
		selected[0].DPShareReceiptPair.PairSHA256 != pair.PairSHA256 {
		t.Fatal("K2 peers committed different Selected records")
	}
	if replay, replayed, err := owners[0].CommitSelectedV1(votes[1]); err != nil || !replayed || !reflect.DeepEqual(replay, selected[0]) {
		t.Fatalf("Selected replay changed: replay=%v err=%v", replayed, err)
	}
	formalGLMRegisteredPhase20TerminalTestPublicJSONV1(
		t, shares, selected[0])

	for index := range owners {
		if err := owners[index].Close(); err != nil {
			t.Fatal(err)
		}
		owners[index] = formalGLMRegisteredPhase20TerminalTestOpenV1(
			t, roots[index], index, fixture, proposal, accept)
		status, err := owners[index].LoadStatusV1()
		if err != nil || status.selected == nil ||
			!reflect.DeepEqual(*status.selected, selected[index]) {
			t.Fatalf("Selected restart %d failed: %v", index, err)
		}
		formalGLMRegisteredPhase20TerminalTestPrivateJSONV1(t, status)
		loadedSelected, trusted, err := owners[index].LoadSelectedSourceV1()
		if err != nil || !reflect.DeepEqual(loadedSelected, selected[index]) ||
			trusted.source.Result.Peer != peers[index] ||
			trusted.source.Result.DPShare != evidence[index].CanonicalDPShare {
			trusted.clear()
			t.Fatalf("Selected source %d did not rehydrate: %v", index, err)
		}
		formalGLMRegisteredPhase20TerminalTestPrivateJSONV1(t, trusted)
		trusted.clear()
		formalGLMRegisteredPhase20TerminalTestAssertFilesV1(
			t, roots[index], paths[index], shares)
	}

	garblerAbandon := formalGLMRegisteredPhase20TerminalTestOpenV1(
		t, abandonRoots[0], 0, fixture, proposal, accept)
	evaluatorAbandon := formalGLMRegisteredPhase20TerminalTestOpenV1(
		t, abandonRoots[1], 1, fixture, proposal, accept)
	if replayed, err := garblerAbandon.SealLocalEvidenceV1(
		evidence[0]); err != nil || replayed {
		t.Fatalf("garbler abandonment draft: %v", err)
	}
	publishedBeforeAbandon, err := garblerAbandon.PublishDPShareReceiptV1()
	if err != nil || !reflect.DeepEqual(publishedBeforeAbandon, garblerReceipt) {
		t.Fatalf("garbler receipt before abandonment changed: %v", err)
	}
	if _, _, err := garblerAbandon.VoteAbandonBeforePrepareV1(); err == nil {
		t.Fatal("garbler initiated role-ordered abandonment")
	}
	if replayed, err := evaluatorAbandon.SealLocalEvidenceV1(
		evidence[1]); err != nil || replayed {
		t.Fatalf("evaluator abandonment draft: %v", err)
	}
	evaluatorVote, replayed, err := evaluatorAbandon.VoteAbandonBeforePrepareV1()
	if err != nil || replayed {
		t.Fatalf("evaluator abandonment vote: replay=%v err=%v", replayed, err)
	}
	garblerAbandon.mu.Lock()
	choiceReplayed, err := garblerAbandon.chooseAbandonV1()
	garblerAbandon.mu.Unlock()
	if err != nil || choiceReplayed {
		t.Fatalf("persist garbler abandon choice: replay=%v err=%v",
			choiceReplayed, err)
	}
	if err := garblerAbandon.Close(); err != nil {
		t.Fatal(err)
	}
	garblerAbandon = formalGLMRegisteredPhase20TerminalTestOpenV1(
		t, abandonRoots[0], 0, fixture, proposal, accept)
	if status, err := garblerAbandon.LoadStatusV1(); err != nil ||
		!status.abandonChosen || status.prepareReceipt != nil {
		t.Fatalf("abandon-choice-only prefix did not restart: %v", err)
	}
	fence, err := formalGLMRegisteredPhase20AcquireAttemptFenceV1(
		garblerAbandon.attempts, proposal.Binding.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	if err := formalGLMRegisteredPhase20AttemptVoteQuiescenceV1(
		garblerAbandon.attempts, fence, proposal, accept); err != nil {
		t.Fatal(err)
	}
	garblerAbandon.attempts.mu.Lock()
	remoteReplayed, err := garblerAbandon.attempts.commitVoteV1(
		fence, proposal, accept, evaluatorVote)
	garblerAbandon.attempts.mu.Unlock()
	fence.Close()
	if err != nil || remoteReplayed {
		t.Fatalf("persist evaluator-only crash prefix: replay=%v err=%v",
			remoteReplayed, err)
	}
	if err := garblerAbandon.Close(); err != nil {
		t.Fatal(err)
	}
	garblerAbandon = formalGLMRegisteredPhase20TerminalTestOpenV1(
		t, abandonRoots[0], 0, fixture, proposal, accept)
	if status, err := garblerAbandon.LoadStatusV1(); err != nil ||
		!status.draftSealed || !status.abandonChosen ||
		status.prepareReceipt != nil {
		t.Fatalf("evaluator-only abandonment prefix did not restart: %v", err)
	}
	garblerVote, replayed, err := garblerAbandon.AcceptEvaluatorAbandonV1(
		evaluatorVote)
	if err != nil || replayed {
		t.Fatalf("garbler abandonment co-sign: replay=%v err=%v", replayed, err)
	}
	abandonVotes := []formalGLMRegisteredPhase19DecisionVoteV1{
		garblerVote, evaluatorVote,
	}
	for _, owner := range []*formalGLMRegisteredPhase20TerminalOwnerV1{
		garblerAbandon, evaluatorAbandon,
	} {
		if _, _, err := owner.CommitAbandonedBeforePrepareV1(
			abandonVotes); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := evaluatorAbandon.PrepareFromGarblerReceiptV1(
		garblerReceipt); err == nil {
		t.Fatal("abandoned evaluator created a prepare marker")
	}
	if err := garblerAbandon.Close(); err != nil {
		t.Fatal(err)
	}
	if err := evaluatorAbandon.Close(); err != nil {
		t.Fatal(err)
	}

	warmDraftPath := filepath.Join(roots[1], paths[1][0])
	warmDraft, err := os.ReadFile(warmDraftPath)
	if err != nil {
		t.Fatal(err)
	}
	warmDraft = append(warmDraft, ' ')
	if err := os.WriteFile(warmDraftPath, warmDraft, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(warmDraft)
	if _, err := owners[1].LoadStatusV1(); err == nil {
		t.Fatal("warm draft cache accepted changed durable bytes")
	}
	if err := os.Remove(warmDraftPath); err != nil {
		t.Fatal(err)
	}
	if _, err := owners[1].LoadStatusV1(); err == nil {
		t.Fatal("warm draft cache accepted missing durable draft")
	}
	if _, err := owners[1].SealLocalEvidenceV1(evidence[1]); err == nil {
		t.Fatal("warm draft cache resealed a missing durable draft")
	}
	if _, err := os.Stat(warmDraftPath); !os.IsNotExist(err) {
		t.Fatal("failed reseal recreated a missing durable draft")
	}

	for index := range owners {
		cached := owners[index].draftCache
		if err := owners[index].Close(); err != nil {
			t.Fatal(err)
		}
		if cached == nil || owners[index].draftCache != nil ||
			!reflect.DeepEqual(*cached,
				formalGLMRegisteredPhase20TerminalDraftLoadedV1{}) {
			t.Fatal("terminal close retained validated draft cache")
		}
		owners[index] = nil
	}

	for _, scenario := range []string{
		"missing-draft", "missing-choice", "missing-vote",
		"tamper-ciphertext", "draft-hardlink", "draft-symlink",
		"draft-mode-0400", "choice-mode-0700", "selected-mode",
		"terminal-directory-mode", "fork-vote", "tamper-choice",
	} {
		t.Run("durable-"+scenario, func(t *testing.T) {
			root := formalGLMRegisteredPhase20TerminalTestCopyRockV1(t, roots[0])
			draft := filepath.Join(root, paths[0][0])
			choice := filepath.Join(root, paths[0][1])
			vote := filepath.Join(root, paths[0][2])
			selectedPath := filepath.Join(root, paths[0][3])
			switch scenario {
			case "missing-draft":
				if err := os.Remove(draft); err != nil {
					t.Fatal(err)
				}
			case "missing-choice":
				if err := os.Remove(choice); err != nil {
					t.Fatal(err)
				}
			case "missing-vote":
				if err := os.Remove(vote); err != nil {
					t.Fatal(err)
				}
			case "tamper-ciphertext":
				formalGLMRegisteredPhase20TerminalTestFlipCiphertextV1(t, draft)
			case "draft-hardlink":
				if err := os.Link(draft, draft+".alias"); err != nil {
					t.Fatal(err)
				}
			case "draft-symlink":
				outside := filepath.Join(t.TempDir(), "outside")
				encoded, err := os.ReadFile(draft)
				if err != nil || os.WriteFile(outside, encoded, 0o600) != nil {
					t.Fatal("could not create symlink target")
				}
				if err := os.Remove(draft); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, draft); err != nil {
					t.Fatal(err)
				}
			case "draft-mode-0400":
				if err := os.Chmod(draft, 0o400); err != nil {
					t.Fatal(err)
				}
			case "choice-mode-0700":
				if err := os.Chmod(choice, 0o700); err != nil {
					t.Fatal(err)
				}
			case "selected-mode":
				if err := os.Chmod(selectedPath, 0o640); err != nil {
					t.Fatal(err)
				}
			case "terminal-directory-mode":
				if err := os.Chmod(filepath.Dir(draft), 0o750); err != nil {
					t.Fatal(err)
				}
			case "fork-vote":
				encoded, err := os.ReadFile(vote)
				if err != nil {
					t.Fatal(err)
				}
				var fork formalGLMRegisteredPhase20SelectVoteRecordV1
				if err := json.Unmarshal(encoded, &fork); err != nil {
					t.Fatal(err)
				}
				fork.Vote.PrepareReceiptSetSHA256 = strings.Repeat("a", 64)
				encoded, err = json.Marshal(fork)
				if err != nil || os.WriteFile(vote, encoded, 0o600) != nil {
					t.Fatal("could not write forked vote")
				}
			case "tamper-choice":
				encoded, err := os.ReadFile(choice)
				if err != nil {
					t.Fatal(err)
				}
				var fork formalGLMRegisteredPhase20TerminalChoiceV1
				if err := json.Unmarshal(encoded, &fork); err != nil {
					t.Fatal(err)
				}
				fork.Decision = formalGLMRegisteredPhase20TerminalAbandonChoiceV1
				fork.Prepared = nil
				encoded, err = json.Marshal(fork)
				if err != nil || os.WriteFile(choice, encoded, 0o600) != nil {
					t.Fatal("could not write forked choice")
				}
			}
			attemptStore, err := newFormalGLMRegisteredPhase19AttemptStoreV1(
				root, record, contract, pins, peers[0], private[peers[0]])
			if err != nil {
				t.Fatal(err)
			}
			jobKeys, err := newFormalGLMRegisteredPhase20JobKeyProviderV1(
				root, contract, pins, record, peers[0])
			if err != nil {
				attemptStore.Close()
				t.Fatal(err)
			}
			owner, openErr := newFormalGLMRegisteredPhase20TerminalOwnerV1(
				attemptStore, jobKeys, base.runtime, proposal, accept)
			if openErr == nil {
				_, openErr = owner.LoadStatusV1()
				_ = owner.Close()
			} else {
				attemptStore.Close()
				_ = jobKeys.Close()
			}
			if openErr == nil {
				t.Fatal("unsafe terminal state reopened")
			}
		})
	}
}
