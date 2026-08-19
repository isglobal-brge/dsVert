package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	formalGLMRegisteredPhase18ReceiptSetAssemblerK2Once    sync.Once
	formalGLMRegisteredPhase18ReceiptSetAssemblerK2Fixture formalGLMRegisteredPhase18ProvenanceTestFixtureV1
)

func formalGLMRegisteredPhase18ReceiptSetAssemblerTestK2(
	t testing.TB,
) formalGLMRegisteredPhase18ProvenanceTestFixtureV1 {
	t.Helper()
	formalGLMRegisteredPhase18ReceiptSetAssemblerK2Once.Do(func() {
		formalGLMRegisteredPhase18ReceiptSetAssemblerK2Fixture =
			formalGLMRegisteredPhase18ProvenanceTestBuild(t, 2)
	})
	return formalGLMRegisteredPhase18ReceiptSetAssemblerK2Fixture
}

func formalGLMRegisteredPhase18ReceiptSetAssemblerTestRoot(
	t testing.TB, label string,
) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "rock-"+label)
}

func formalGLMRegisteredPhase18ReceiptSetAssemblerTestOpen(
	t testing.TB,
	root string,
	fixture formalGLMRegisteredPhase18ProvenanceTestFixtureV1,
) *formalGLMRegisteredPhase18ReceiptSetAssemblerV1 {
	t.Helper()
	assembler, err := newFormalGLMRegisteredPhase18ReceiptSetAssemblerV1(
		root, fixture.source.contract,
		fixture.source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(assembler.Close)
	return assembler
}

func formalGLMRegisteredPhase18ReceiptSetAssemblerTestReceiptJSON(
	t testing.TB,
	receipt formalGLMRegisteredPhase18LocalReceiptV1,
) []byte {
	t.Helper()
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func formalGLMRegisteredPhase18ReceiptSetAssemblerTestPaths(
	t testing.TB,
	root string,
	assembler *formalGLMRegisteredPhase18ReceiptSetAssemblerV1,
) ([]string, string, string) {
	t.Helper()
	assembler.mu.Lock()
	defer assembler.mu.Unlock()
	peers := assembler.contract.Core.RegisteredExecutionPlan.CustodianPeers
	receipts := make([]string, len(peers))
	artifactDir := ""
	for index, peer := range peers {
		relative, err := assembler.localReceiptRelativeLocked(peer, false)
		if err != nil {
			t.Fatal(err)
		}
		receipts[index] = filepath.Join(root, relative)
		artifactDir = filepath.Join(root, filepath.Dir(relative))
	}
	setRelative, err := assembler.receiptSetRelativeLocked(false)
	if err != nil {
		t.Fatal(err)
	}
	return receipts, filepath.Join(root, setRelative), artifactDir
}

func formalGLMRegisteredPhase18ReceiptSetAssemblerTestConflict(
	t testing.TB,
	fixture formalGLMRegisteredPhase18ProvenanceTestFixtureV1,
	source string,
) []byte {
	t.Helper()
	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		fixture.source.contract, fixture.source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	blocks := formalGLMRegisteredPhase18ProvenanceTestClone(
		t, fixture.pairs[source])
	ciphertexts := make(map[string][]byte, 2)
	for index, recipient := range fixture.source.plan.DesignatedComputePeers {
		ciphertexts[recipient] =
			formalGLMRegisteredPhase18ProvenanceTestCiphertext(
				source, recipient, 0, index)
		ciphertexts[recipient][0] ^= 0x80
	}
	blocks[0], err = formalGLMRegisteredPhase18BuildBlockPairWithContextV1(
		context, fixture.authorizations[source], fixture.tickets, 0,
		ciphertexts, fixture.source.inputs.identities.private[source])
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := formalGLMRegisteredPhase18BuildLocalReceiptWithContextV1(
		context, fixture.authorizations[source], fixture.tickets, blocks,
		fixture.source.inputs.identities.private[source])
	if err != nil {
		t.Fatal(err)
	}
	return formalGLMRegisteredPhase18ReceiptSetAssemblerTestReceiptJSON(
		t, receipt)
}

func formalGLMRegisteredPhase18ReceiptSetAssemblerTestCrossContractClaim(
	t testing.TB,
	fixture formalGLMRegisteredPhase18ProvenanceTestFixtureV1,
) []byte {
	t.Helper()
	receipt := formalGLMRegisteredPhase18ProvenanceTestClone(
		t, fixture.receipts[0])
	receipt.SourceContractSHA256 = strings.Repeat("a", 64)
	if receipt.SourceContractSHA256 == fixture.receipts[0].SourceContractSHA256 {
		receipt.SourceContractSHA256 = strings.Repeat("b", 64)
	}
	receipt.Signature = nil
	message, err := formalGLMRegisteredPhase18SignatureMessageV1(
		formalGLMRegisteredPhase18LocalReceiptDomain, receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Signature = ed25519.Sign(
		fixture.source.inputs.identities.private[receipt.SourceName], message)
	return formalGLMRegisteredPhase18ReceiptSetAssemblerTestReceiptJSON(
		t, receipt)
}

func formalGLMRegisteredPhase18ReceiptSetAssemblerTestPublic(
	t testing.TB, encoded []byte,
) {
	t.Helper()
	text := strings.ToLower(string(encoded))
	for _, forbidden := range []string{
		`"path"`, `"payload"`, `"ciphertext"`, `"private_consensus"`,
		`"input_commitment"`, `"input_mac"`, `"local_key"`,
		`"private_key"`,
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("receipt-set response exposes %s", forbidden)
		}
	}
}

func TestFormalGLMRegisteredPhase18ReceiptSetAssemblerK2K5(
	t *testing.T,
) {
	for _, custodians := range []int{2, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			var fixture formalGLMRegisteredPhase18ProvenanceTestFixtureV1
			if custodians == 2 {
				fixture = formalGLMRegisteredPhase18ReceiptSetAssemblerTestK2(t)
			} else {
				fixture = formalGLMRegisteredPhase18ProvenanceTestBuild(t, 5)
			}
			leftRoot := formalGLMRegisteredPhase18ReceiptSetAssemblerTestRoot(
				t, "left")
			left := formalGLMRegisteredPhase18ReceiptSetAssemblerTestOpen(
				t, leftRoot, fixture)
			right := formalGLMRegisteredPhase18ReceiptSetAssemblerTestOpen(
				t, formalGLMRegisteredPhase18ReceiptSetAssemblerTestRoot(
					t, "right"), fixture)
			if _, _, err := left.SealReceiptSet(); err == nil {
				t.Fatal("empty receipt set sealed")
			}
			for offset := range fixture.receipts {
				leftIndex := len(fixture.receipts) - 1 - offset
				rightIndex := (offset + 1) % len(fixture.receipts)
				leftInput := formalGLMRegisteredPhase18ReceiptSetAssemblerTestReceiptJSON(
					t, fixture.receipts[leftIndex])
				persisted, replayed, err := left.CommitLocalReceipt(leftInput)
				if err != nil || replayed || !bytes.Equal(persisted, leftInput) {
					t.Fatalf("left commit %d: replay=%v err=%v",
						leftIndex, replayed, err)
				}
				rightInput := formalGLMRegisteredPhase18ReceiptSetAssemblerTestReceiptJSON(
					t, fixture.receipts[rightIndex])
				if _, replayed, err := right.CommitLocalReceipt(rightInput); err != nil || replayed {
					t.Fatalf("right commit %d: replay=%v err=%v",
						rightIndex, replayed, err)
				}
				if offset == 0 {
					replayedJSON, wasReplay, err := left.CommitLocalReceipt(leftInput)
					if err != nil || !wasReplay ||
						!bytes.Equal(replayedJSON, leftInput) {
						t.Fatalf("exact receipt replay changed: replay=%v err=%v",
							wasReplay, err)
					}
				}
			}
			leftSet, leftReplay, err := left.SealReceiptSet()
			if err != nil || leftReplay {
				t.Fatalf("left seal: replay=%v err=%v", leftReplay, err)
			}
			rightSet, rightReplay, err := right.SealReceiptSet()
			if err != nil || rightReplay || !bytes.Equal(leftSet, rightSet) {
				t.Fatalf("authority-independent seal: replay=%v equal=%v err=%v",
					rightReplay, bytes.Equal(leftSet, rightSet), err)
			}
			expected, err := json.Marshal(fixture.receiptSet)
			if err != nil || !bytes.Equal(leftSet, expected) {
				t.Fatal("assembler differs from canonical receipt-set builder")
			}
			decoded, err := formalGLMDecodeRegisteredPhase18ReceiptSetV1(
				leftSet, fixture.source.contract,
				fixture.source.inputs.identities.public)
			if err != nil || len(decoded.Receipts) != custodians {
				t.Fatalf("sealed receipt set is invalid: %v", err)
			}
			for index, peer := range fixture.source.plan.CustodianPeers {
				if decoded.Receipts[index].SourceName != peer {
					t.Fatal("sealed receipts are not in registered plan order")
				}
			}
			formalGLMRegisteredPhase18ReceiptSetAssemblerTestPublic(t, leftSet)

			left.Close()
			left = formalGLMRegisteredPhase18ReceiptSetAssemblerTestOpen(
				t, leftRoot, fixture)
			loaded, err := left.LoadReceiptSet()
			if err != nil || !bytes.Equal(loaded, leftSet) {
				t.Fatalf("restart load changed receipt set: %v", err)
			}
			replayedSet, replayed, err := left.SealReceiptSet()
			if err != nil || !replayed || !bytes.Equal(replayedSet, leftSet) {
				t.Fatalf("restart seal replay changed: replay=%v err=%v",
					replayed, err)
			}
		})
	}
}

func TestFormalGLMRegisteredPhase18ReceiptSetAssemblerRejectsDamage(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase18ReceiptSetAssemblerTestK2(t)
	root := formalGLMRegisteredPhase18ReceiptSetAssemblerTestRoot(t, "damage")
	assembler := formalGLMRegisteredPhase18ReceiptSetAssemblerTestOpen(
		t, root, fixture)
	first := formalGLMRegisteredPhase18ReceiptSetAssemblerTestReceiptJSON(
		t, fixture.receipts[0])
	second := formalGLMRegisteredPhase18ReceiptSetAssemblerTestReceiptJSON(
		t, fixture.receipts[1])
	tamperedInput := append([]byte(nil), first...)
	tamperedInput[len(tamperedInput)/2] ^= 1
	if _, _, err := assembler.CommitLocalReceipt(tamperedInput); err == nil {
		t.Fatal("tampered receipt input committed")
	}
	if _, _, err := assembler.CommitLocalReceipt(
		append(first, ' ')); err == nil {
		t.Fatal("non-canonical receipt input committed")
	}
	crossJSON := formalGLMRegisteredPhase18ReceiptSetAssemblerTestCrossContractClaim(
		t, fixture)
	if _, _, err := assembler.CommitLocalReceipt(crossJSON); err == nil {
		t.Fatal("cross-contract receipt committed")
	}
	if _, replayed, err := assembler.CommitLocalReceipt(first); err != nil || replayed {
		t.Fatalf("first receipt commit: replay=%v err=%v", replayed, err)
	}
	if _, _, err := assembler.SealReceiptSet(); err == nil {
		t.Fatal("incomplete K receipt set sealed")
	}
	if replayedJSON, replayed, err := assembler.CommitLocalReceipt(first); err != nil || !replayed || !bytes.Equal(replayedJSON, first) {
		t.Fatalf("exact duplicate was not replayed: replay=%v err=%v",
			replayed, err)
	}
	conflict := formalGLMRegisteredPhase18ReceiptSetAssemblerTestConflict(
		t, fixture, fixture.receipts[0].SourceName)
	if bytes.Equal(conflict, first) {
		t.Fatal("valid conflict fixture did not diverge")
	}
	if _, _, err := assembler.CommitLocalReceipt(conflict); err == nil {
		t.Fatal("valid different receipt for one source replaced CAS")
	}
	if _, replayed, err := assembler.CommitLocalReceipt(second); err != nil || replayed {
		t.Fatalf("second receipt commit: replay=%v err=%v", replayed, err)
	}
	sealed, replayed, err := assembler.SealReceiptSet()
	if err != nil || replayed {
		t.Fatalf("initial seal: replay=%v err=%v", replayed, err)
	}
	receiptPaths, setPath, artifactDir :=
		formalGLMRegisteredPhase18ReceiptSetAssemblerTestPaths(
			t, root, assembler)
	requireLoadReject := func(label string) {
		t.Helper()
		if _, err := assembler.LoadReceiptSet(); err == nil {
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
		requireLoadReject("missing " + label)
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
		requireLoadReject("tampered " + label)
		if err := os.WriteFile(path, original, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	removeAndRestore("receipt", receiptPaths[0])
	removeAndRestore("receipt-set", setPath)
	tamperAndRestore("receipt", receiptPaths[0])
	tamperAndRestore("receipt-set", setPath)

	firstRecord, err := os.ReadFile(receiptPaths[0])
	if err != nil {
		t.Fatal(err)
	}
	secondRecord, err := os.ReadFile(receiptPaths[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receiptPaths[0], secondRecord, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receiptPaths[1], firstRecord, 0o600); err != nil {
		t.Fatal(err)
	}
	requireLoadReject("reordered receipt records")
	if err := os.WriteFile(receiptPaths[0], firstRecord, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receiptPaths[1], secondRecord, 0o600); err != nil {
		t.Fatal(err)
	}

	set, err := formalGLMDecodeRegisteredPhase18ReceiptSetV1(
		sealed, fixture.source.contract,
		fixture.source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	set.Receipts[0], set.Receipts[1] = set.Receipts[1], set.Receipts[0]
	reorderedSet, err := json.Marshal(set)
	if err != nil || os.WriteFile(setPath, reorderedSet, 0o600) != nil {
		t.Fatal("failed to install reordered receipt set")
	}
	requireLoadReject("reordered receipt set")
	if err := os.WriteFile(setPath, sealed, 0o600); err != nil {
		t.Fatal(err)
	}

	duplicate := filepath.Join(artifactDir, "duplicate-receipt.json")
	if err := os.WriteFile(duplicate, firstRecord, 0o600); err != nil {
		t.Fatal(err)
	}
	requireLoadReject("unexpected duplicate receipt record")
	if err := os.Remove(duplicate); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(receiptPaths[0], 0o640); err != nil {
		t.Fatal(err)
	}
	requireLoadReject("unsafe receipt mode")
	if err := os.Chmod(receiptPaths[0], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(setPath, 0o640); err != nil {
		t.Fatal(err)
	}
	requireLoadReject("unsafe receipt-set mode")
	if err := os.Chmod(setPath, 0o600); err != nil {
		t.Fatal(err)
	}
	hardlink := receiptPaths[0] + ".hardlink"
	if err := os.Link(receiptPaths[0], hardlink); err != nil {
		t.Fatal(err)
	}
	requireLoadReject("hard-linked receipt")
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	backup := setPath + ".backup"
	if err := os.Rename(setPath, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(backup, setPath); err != nil {
		t.Fatal(err)
	}
	requireLoadReject("symlinked receipt set")
	if err := os.Remove(setPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, setPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(artifactDir, 0o750); err != nil {
		t.Fatal(err)
	}
	requireLoadReject("unsafe artifact directory mode")
	if err := os.Chmod(artifactDir, 0o700); err != nil {
		t.Fatal(err)
	}
	loaded, err := assembler.LoadReceiptSet()
	if err != nil || !bytes.Equal(loaded, sealed) {
		t.Fatalf("damage recovery changed receipt set: %v", err)
	}

	otherArtifact := strings.Repeat("f", 64)
	if otherArtifact == fixture.source.contract.Core.ArtifactID {
		otherArtifact = strings.Repeat("e", 64)
	}
	otherArtifactDir := filepath.Join(root,
		formalGLMRegisteredPhase18ReceiptSetAssemblerDirV1,
		otherArtifact[:2], otherArtifact[2:4], otherArtifact)
	if err := os.MkdirAll(otherArtifactDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(otherArtifactDir, "foreign.json"),
		[]byte(strings.Repeat("x", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	if loaded, err := assembler.LoadReceiptSet(); err != nil ||
		!bytes.Equal(loaded, sealed) {
		t.Fatalf("another artifact interfered with receipt set: %v", err)
	}

	unsafeRoot := filepath.Join(t.TempDir(), "unsafe-root")
	if err := os.Mkdir(unsafeRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	if store, err := newFormalGLMRegisteredPhase18ReceiptSetAssemblerV1(
		unsafeRoot, fixture.source.contract,
		fixture.source.inputs.identities.public); err == nil {
		store.Close()
		t.Fatal("unsafe Rock root mode accepted")
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	redirected := filepath.Join(t.TempDir(), "redirected")
	if err := os.Symlink(target, redirected); err != nil {
		t.Fatal(err)
	}
	if store, err := newFormalGLMRegisteredPhase18ReceiptSetAssemblerV1(
		redirected, fixture.source.contract,
		fixture.source.inputs.identities.public); err == nil {
		store.Close()
		t.Fatal("symlinked Rock root accepted")
	}
}

func TestFormalGLMRegisteredPhase18ReceiptSetAssemblerConcurrentCAS(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase18ReceiptSetAssemblerTestK2(t)
	root := formalGLMRegisteredPhase18ReceiptSetAssemblerTestRoot(
		t, "concurrent")
	const workers = 4
	assemblers := make([]*formalGLMRegisteredPhase18ReceiptSetAssemblerV1,
		workers)
	for index := range assemblers {
		assemblers[index] =
			formalGLMRegisteredPhase18ReceiptSetAssemblerTestOpen(
				t, root, fixture)
	}
	type result struct {
		encoded []byte
		created bool
		err     error
	}
	commits := make(chan result, workers*len(fixture.receipts))
	var wait sync.WaitGroup
	for worker, assembler := range assemblers {
		for offset := range fixture.receipts {
			receipt := fixture.receipts[(worker+offset)%len(fixture.receipts)]
			input := formalGLMRegisteredPhase18ReceiptSetAssemblerTestReceiptJSON(
				t, receipt)
			wait.Add(1)
			go func(store *formalGLMRegisteredPhase18ReceiptSetAssemblerV1,
				candidate []byte,
			) {
				defer wait.Done()
				encoded, replayed, err := store.CommitLocalReceipt(candidate)
				commits <- result{encoded: encoded, created: !replayed, err: err}
			}(assembler, input)
		}
	}
	wait.Wait()
	close(commits)
	createdReceipts := 0
	for commit := range commits {
		if commit.err != nil || len(commit.encoded) == 0 {
			t.Fatalf("concurrent receipt commit: %v", commit.err)
		}
		if commit.created {
			createdReceipts++
		}
	}
	if createdReceipts != len(fixture.receipts) {
		t.Fatalf("created %d receipt records, want %d",
			createdReceipts, len(fixture.receipts))
	}

	seals := make(chan result, workers)
	for _, assembler := range assemblers {
		wait.Add(1)
		go func(store *formalGLMRegisteredPhase18ReceiptSetAssemblerV1) {
			defer wait.Done()
			encoded, replayed, err := store.SealReceiptSet()
			seals <- result{encoded: encoded, created: !replayed, err: err}
		}(assembler)
	}
	wait.Wait()
	close(seals)
	createdSets := 0
	var canonical []byte
	for seal := range seals {
		if seal.err != nil || len(seal.encoded) == 0 {
			t.Fatalf("concurrent receipt-set seal: %v", seal.err)
		}
		if canonical == nil {
			canonical = seal.encoded
		} else if !bytes.Equal(canonical, seal.encoded) {
			t.Fatal("concurrent authorities derived different receipt sets")
		}
		if seal.created {
			createdSets++
		}
	}
	if createdSets != 1 {
		t.Fatalf("created %d durable receipt sets, want 1", createdSets)
	}
	for _, assembler := range assemblers {
		loaded, err := assembler.LoadReceiptSet()
		if err != nil || !bytes.Equal(loaded, canonical) {
			t.Fatalf("concurrent load mismatch: %v", err)
		}
	}
}
