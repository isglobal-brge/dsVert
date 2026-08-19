package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func formalGLMRegisteredPhase18LocalReceiptTestNoBuildHooks(
	builds *atomic.Int32,
) formalGLMRegisteredPhase18SourceOutboxHooksV3 {
	return formalGLMRegisteredPhase18SourceOutboxHooksV3{
		BuildPair: func(contract formalGLMSourceContractV1,
			authorization formalGLMRegisteredPhase18AuthorizationV1,
			tickets []formalGLMRegisteredPhase18RecipientTicketV1,
			blockIndex int, values []string, validity []bool,
			consensus []byte, key []byte,
			pins map[string]ed25519.PublicKey,
		) (formalGLMRegisteredPhase18BlockPairV1, error) {
			builds.Add(1)
			return formalGLMRegisteredPhase18BuildMaterializedBlockPairV3(
				contract, authorization, tickets, blockIndex, values,
				validity, consensus, key, pins)
		},
	}
}

func formalGLMRegisteredPhase18LocalReceiptTestOpenWithHooks(
	t testing.TB, root string,
	fixture formalGLMRegisteredPhase18SourceOutboxTestFixtureV3,
	hooks formalGLMRegisteredPhase18SourceOutboxHooksV3,
) *formalGLMRegisteredPhase18SourceOutboxV3 {
	t.Helper()
	outbox, err := newFormalGLMRegisteredPhase18SourceOutboxWithHooksV3(
		root, fixture.provenance.source.contract, fixture.source,
		fixture.provenance.source.inputs.identities.private[fixture.source],
		fixture.localKey, fixture.provenance.source.inputs.identities.public,
		hooks)
	if err != nil {
		t.Fatal(err)
	}
	return outbox
}

func formalGLMRegisteredPhase18LocalReceiptTestCommitAllPairs(
	t testing.TB,
	outbox *formalGLMRegisteredPhase18SourceOutboxV3,
	fixture formalGLMRegisteredPhase18SourceOutboxTestFixtureV3,
) [][]byte {
	t.Helper()
	pairs := make([][]byte, fixture.authorization.Geometry.TotalBlocks)
	for blockIndex := range pairs {
		values, validity :=
			formalGLMRegisteredPhase18MaterializedPairTestValues(
				fixture.authorization, blockIndex)
		consensus := sha256.Sum256([]byte(fmt.Sprintf(
			"registered-phase18/local-receipt/%s/%d",
			fixture.source, blockIndex)))
		_, pairJSON, replayed, err := outbox.CommitBlock(
			fixture.authorization, fixture.tickets, blockIndex,
			values, validity, consensus[:])
		if err != nil || replayed {
			t.Fatalf("commit block %d: replay=%v err=%v",
				blockIndex, replayed, err)
		}
		pairs[blockIndex] = pairJSON
	}
	return pairs
}

func formalGLMRegisteredPhase18LocalReceiptTestPaths(
	t testing.TB, root string,
	outbox *formalGLMRegisteredPhase18SourceOutboxV3,
	fixture formalGLMRegisteredPhase18SourceOutboxTestFixtureV3,
) ([]string, []string, string) {
	t.Helper()
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	intents := make([]string, fixture.authorization.Geometry.TotalBlocks)
	pairs := make([]string, len(intents))
	for blockIndex := range intents {
		_, intent, pair, err := outbox.slotLocked(
			fixture.authorization, blockIndex, false)
		if err != nil {
			t.Fatal(err)
		}
		intents[blockIndex] = filepath.Join(root, intent)
		pairs[blockIndex] = filepath.Join(root, pair)
	}
	_, receipt, err := outbox.localReceiptRelativeLocked(
		fixture.authorization, false)
	if err != nil {
		t.Fatal(err)
	}
	return intents, pairs, filepath.Join(root, receipt)
}

func formalGLMRegisteredPhase18LocalReceiptTestForbiddenKeys(
	t testing.TB, encoded []byte,
) {
	t.Helper()
	var value any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	var walk func(any)
	walk = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				lower := strings.ToLower(key)
				for _, forbidden := range []string{
					"path", "input_commitment", "input_mac", "payload", "key",
				} {
					if strings.Contains(lower, forbidden) {
						t.Fatalf("local receipt response exposes %q", key)
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(value)
}

func TestFormalGLMRegisteredPhase18CommitLocalReceiptK2K5RestartReplay(
	t *testing.T,
) {
	for _, custodians := range []int{2, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMRegisteredPhase18SourceOutboxTestBuild(
				t, custodians)
			if custodians == 5 && len(fixture.authorization.LocalColumns) != 0 {
				t.Fatal("K5 source is not the alignment-only witness")
			}
			root := formalGLMRegisteredPhase18SourceOutboxTestRoot(
				t, "local-receipt")
			outbox := formalGLMRegisteredPhase18SourceOutboxTestNew(
				t, root, fixture)
			pairJSON := formalGLMRegisteredPhase18LocalReceiptTestCommitAllPairs(
				t, outbox, fixture)
			outbox.Close()

			var builds atomic.Int32
			outbox = formalGLMRegisteredPhase18LocalReceiptTestOpenWithHooks(
				t, root, fixture,
				formalGLMRegisteredPhase18LocalReceiptTestNoBuildHooks(&builds))
			receiptJSON, replayed, err := outbox.CommitLocalReceipt(
				fixture.authorization, fixture.tickets)
			if err != nil || replayed || builds.Load() != 0 {
				outbox.Close()
				t.Fatalf("first local receipt: replay=%v builds=%d err=%v",
					replayed, builds.Load(), err)
			}
			receipt, err := formalGLMDecodeRegisteredPhase18LocalReceiptV1(
				receiptJSON, fixture.provenance.source.contract,
				fixture.provenance.source.inputs.identities.public)
			if err != nil || receipt.SourceName != fixture.source ||
				len(receipt.BlockCommitments) != len(pairJSON) {
				outbox.Close()
				t.Fatalf("invalid committed local receipt: %v", err)
			}
			for blockIndex, encodedPair := range pairJSON {
				pair, err := formalGLMDecodeRegisteredPhase18BlockPairV1(
					encodedPair, fixture.provenance.source.contract,
					fixture.authorization, fixture.tickets,
					fixture.provenance.source.inputs.identities.public)
				if err != nil ||
					receipt.BlockCommitments[blockIndex].PairCommitmentSHA256 !=
						pair.PairCommitmentSHA256 ||
					receipt.BlockCommitments[blockIndex].BlockCommitmentSHA256 !=
						pair.BlockCommitmentSHA256 {
					outbox.Close()
					t.Fatalf("receipt lost block %d commitment: %v", blockIndex, err)
				}
			}
			formalGLMRegisteredPhase18LocalReceiptTestForbiddenKeys(
				t, receiptJSON)
			outbox.Close()

			outbox = formalGLMRegisteredPhase18LocalReceiptTestOpenWithHooks(
				t, root, fixture,
				formalGLMRegisteredPhase18LocalReceiptTestNoBuildHooks(&builds))
			replayedJSON, wasReplay, err := outbox.CommitLocalReceipt(
				fixture.authorization, fixture.tickets)
			outbox.Close()
			if err != nil || !wasReplay || builds.Load() != 0 ||
				!bytes.Equal(receiptJSON, replayedJSON) {
				t.Fatalf("receipt restart replay: replay=%v builds=%d bytes=%v err=%v",
					wasReplay, builds.Load(), bytes.Equal(receiptJSON, replayedJSON), err)
			}
			records := formalGLMRegisteredPhase18SourceOutboxTestRecords(t, root)
			wantRecords := 2*fixture.authorization.Geometry.TotalBlocks + 1
			if len(records) != wantRecords {
				t.Fatalf("got %d records, want %d complete outbox+receipt",
					len(records), wantRecords)
			}
		})
	}
}

func TestFormalGLMRegisteredPhase18CommitLocalReceiptRejectsDurableDamage(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase18SourceOutboxTestBuild(t, 2)
	root := formalGLMRegisteredPhase18SourceOutboxTestRoot(t, "damage")
	outbox := formalGLMRegisteredPhase18SourceOutboxTestNew(t, root, fixture)
	formalGLMRegisteredPhase18LocalReceiptTestCommitAllPairs(t, outbox, fixture)
	outbox.Close()
	var builds atomic.Int32
	outbox = formalGLMRegisteredPhase18LocalReceiptTestOpenWithHooks(
		t, root, fixture,
		formalGLMRegisteredPhase18LocalReceiptTestNoBuildHooks(&builds))
	receiptJSON, replayed, err := outbox.CommitLocalReceipt(
		fixture.authorization, fixture.tickets)
	if err != nil || replayed {
		t.Fatalf("first local receipt: replay=%v err=%v", replayed, err)
	}
	intents, pairs, receiptPath :=
		formalGLMRegisteredPhase18LocalReceiptTestPaths(
			t, root, outbox, fixture)

	requireReject := func(label string) {
		t.Helper()
		if _, _, err := outbox.CommitLocalReceipt(
			fixture.authorization, fixture.tickets); err == nil {
			t.Fatalf("%s was accepted", label)
		}
	}
	removeAndRestore := func(label, path string) {
		t.Helper()
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		requireReject("missing " + label)
		if err := os.WriteFile(path, original, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tamperAndRestore := func(label, path string) {
		t.Helper()
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		tampered := append([]byte(nil), original...)
		tampered[len(tampered)/2] ^= 1
		if err := os.WriteFile(path, tampered, 0o600); err != nil {
			t.Fatal(err)
		}
		requireReject("tampered " + label)
		if err := os.WriteFile(path, original, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	removeAndRestore("intent", intents[0])
	removeAndRestore("pair", pairs[0])
	tamperAndRestore("intent", intents[0])
	tamperAndRestore("pair", pairs[0])
	tamperAndRestore("receipt", receiptPath)

	firstPair, err := os.ReadFile(pairs[0])
	if err != nil {
		t.Fatal(err)
	}
	secondPair, err := os.ReadFile(pairs[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pairs[0], secondPair, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pairs[1], firstPair, 0o600); err != nil {
		t.Fatal(err)
	}
	requireReject("reordered durable pairs")
	if err := os.WriteFile(pairs[0], firstPair, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pairs[1], secondPair, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(receiptPath, 0o640); err != nil {
		t.Fatal(err)
	}
	requireReject("unsafe receipt mode")
	if err := os.Chmod(receiptPath, 0o600); err != nil {
		t.Fatal(err)
	}
	hardlink := pairs[0] + ".hardlink"
	if err := os.Link(pairs[0], hardlink); err != nil {
		t.Fatal(err)
	}
	requireReject("hard-linked pair")
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	backup := intents[0] + ".backup"
	if err := os.Rename(intents[0], backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(backup, intents[0]); err != nil {
		t.Fatal(err)
	}
	requireReject("symlinked intent")
	if err := os.Remove(intents[0]); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, intents[0]); err != nil {
		t.Fatal(err)
	}

	replayedJSON, wasReplay, err := outbox.CommitLocalReceipt(
		fixture.authorization, fixture.tickets)
	outbox.Close()
	if err != nil || !wasReplay || !bytes.Equal(receiptJSON, replayedJSON) ||
		builds.Load() != 0 {
		t.Fatalf("damage recovery changed receipt: replay=%v builds=%d bytes=%v err=%v",
			wasReplay, builds.Load(), bytes.Equal(receiptJSON, replayedJSON), err)
	}
}
