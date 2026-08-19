package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

var (
	formalGLMRegisteredPhase18PendingPairK5Once    sync.Once
	formalGLMRegisteredPhase18PendingPairK5Fixture formalGLMRegisteredPhase18ProvenanceTestFixtureV1
)

func formalGLMRegisteredPhase18PendingPairTestFixture(
	t testing.TB,
	custodians int,
) formalGLMRegisteredPhase18ProvenanceTestFixtureV1 {
	t.Helper()
	if custodians == 2 {
		return formalGLMRegisteredPhase18ReceiptSetAssemblerTestK2(t)
	}
	formalGLMRegisteredPhase18PendingPairK5Once.Do(func() {
		formalGLMRegisteredPhase18PendingPairK5Fixture =
			formalGLMRegisteredPhase18ProvenanceTestBuild(t, 5)
	})
	return formalGLMRegisteredPhase18PendingPairK5Fixture
}

func formalGLMRegisteredPhase18PendingPairTestJSON(t testing.TB,
	value any,
) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func formalGLMRegisteredPhase18PendingPairTestRoot(t testing.TB,
	label string,
) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(base, "rock-"+label)
}

type formalGLMRegisteredPhase18PendingPairTestStoresV1 struct {
	tickets *formalGLMRegisteredPhase18RecipientTicketStoreV1
	pending *formalGLMRegisteredPhase18PendingPairStoreV1
}

func formalGLMRegisteredPhase18PendingPairTestOpen(
	t testing.TB,
	root string,
	fixture formalGLMRegisteredPhase18ProvenanceTestFixtureV1,
	recipient string,
) formalGLMRegisteredPhase18PendingPairTestStoresV1 {
	t.Helper()
	tickets, err := newFormalGLMRegisteredPhase18RecipientTicketStoreV1(
		root, fixture.source.contract,
		fixture.source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	for _, ticket := range fixture.tickets {
		if _, _, err := tickets.Commit(ticket); err != nil {
			tickets.Close()
			t.Fatal(err)
		}
	}
	pending, err := newFormalGLMRegisteredPhase18PendingPairStoreV1(
		root, recipient, fixture.source.contract,
		fixture.source.inputs.identities.public, tickets)
	if err != nil {
		tickets.Close()
		t.Fatal(err)
	}
	return formalGLMRegisteredPhase18PendingPairTestStoresV1{
		tickets: tickets, pending: pending,
	}
}

func (stores formalGLMRegisteredPhase18PendingPairTestStoresV1) Close() {
	if stores.pending != nil {
		stores.pending.Close()
	}
	if stores.tickets != nil {
		stores.tickets.Close()
	}
}

func formalGLMRegisteredPhase18PendingPairTestCommitAll(
	t testing.TB,
	stores formalGLMRegisteredPhase18PendingPairTestStoresV1,
	fixture formalGLMRegisteredPhase18ProvenanceTestFixtureV1,
	skipSource string,
	skipBlock int,
) []formalGLMRegisteredPhase18PendingPairReceiptV1 {
	t.Helper()
	var receipts []formalGLMRegisteredPhase18PendingPairReceiptV1
	for _, source := range fixture.source.plan.CustodianPeers {
		for blockIndex, pair := range fixture.pairs[source] {
			if source == skipSource && blockIndex == skipBlock {
				continue
			}
			receipt, replayed, err := stores.pending.CommitPair(
				formalGLMRegisteredPhase18PendingPairTestJSON(t, pair))
			if err != nil || replayed {
				t.Fatalf("commit %s/%d: replay=%v err=%v",
					source, blockIndex, replayed, err)
			}
			receipts = append(receipts, receipt)
		}
	}
	return receipts
}

func formalGLMRegisteredPhase18PendingPairTestIngress(
	t testing.TB,
	root string,
	fixture formalGLMRegisteredPhase18ProvenanceTestFixtureV1,
	recipient string,
	globalRoot string,
	localKey [32]byte,
) *formalGLMRegisteredPhase18IngressStoreV3 {
	t.Helper()
	store, err := newFormalGLMRegisteredPhase18IngressStoreV3(
		root, recipient, localKey, fixture.source.contract, globalRoot,
		fixture.source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func formalGLMRegisteredPhase18PendingPairTestRegularFiles(
	t testing.TB,
	root string,
	relative string,
) int {
	t.Helper()
	directory := filepath.Join(root, relative)
	count := 0
	err := filepath.WalkDir(directory, func(_ string, entry fs.DirEntry,
		err error,
	) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			count++
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return count
}

func formalGLMRegisteredPhase18PendingPairTestModes(
	t testing.TB,
	root string,
) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry,
		err error,
	) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() && info.Mode().Perm() != 0o700 {
			return fmt.Errorf("directory %s mode is %o", path, info.Mode().Perm())
		}
		if info.Mode().IsRegular() && info.Mode().Perm() != 0o600 {
			return fmt.Errorf("record %s mode is %o", path, info.Mode().Perm())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func formalGLMRegisteredPhase18PendingPairTestForeignArtifact(
	t testing.TB,
	root string,
	fixture formalGLMRegisteredPhase18ProvenanceTestFixtureV1,
) {
	t.Helper()
	foreign := strings.Repeat("f", 64)
	if foreign == fixture.source.contract.Core.ArtifactID {
		foreign = strings.Repeat("e", 64)
	}
	directory := filepath.Join(root,
		formalGLMRegisteredPhase18PendingPairDirV1,
		foreign[:2], foreign[2:4], foreign, "recipient-0", "source-0")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "pair-block-00000000.json"),
		[]byte(strings.Repeat("x", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFormalGLMRegisteredPhase18PendingPairsK2K5FinalizeRestartReplay(
	t *testing.T,
) {
	for _, custodians := range []int{2, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMRegisteredPhase18PendingPairTestFixture(
				t, custodians)
			recipient := fixture.source.plan.DesignatedComputePeers[0]
			root := formalGLMRegisteredPhase18PendingPairTestRoot(
				t, fmt.Sprintf("happy-k%d", custodians))
			stores := formalGLMRegisteredPhase18PendingPairTestOpen(
				t, root, fixture, recipient)
			receipts := formalGLMRegisteredPhase18PendingPairTestCommitAll(
				t, stores, fixture, "", -1)
			wantCount := custodians * fixture.source.plan.TotalBlocks
			if len(receipts) != wantCount {
				t.Fatalf("pending receipts=%d want=%d", len(receipts), wantCount)
			}
			lastSource := fixture.source.plan.CustodianPeers[custodians-1]
			lastBlock := fixture.pairs[lastSource][fixture.source.plan.TotalBlocks-1]
			if lastBlock.GlobalSlotOffset != 8 || lastBlock.SlotsInBlock != 4 ||
				fixture.source.plan.TotalCapacity != 9 {
				t.Fatal("fixture is not the fixed-shape padded final block")
			}
			replayedReceipt, replayed, err := stores.pending.CommitPair(
				formalGLMRegisteredPhase18PendingPairTestJSON(t, lastBlock))
			if err != nil || !replayed ||
				!reflect.DeepEqual(replayedReceipt, receipts[len(receipts)-1]) {
				t.Fatalf("pending replay: replay=%v equal=%v err=%v", replayed,
					reflect.DeepEqual(replayedReceipt, receipts[len(receipts)-1]), err)
			}
			stores.Close()
			stores = formalGLMRegisteredPhase18PendingPairTestOpen(
				t, root, fixture, recipient)
			defer stores.Close()
			if _, replayed, err := stores.pending.CommitPair(
				formalGLMRegisteredPhase18PendingPairTestJSON(t, lastBlock)); err != nil || !replayed {
				t.Fatalf("restart replay: replay=%v err=%v", replayed, err)
			}

			if custodians == 2 {
				formalGLMRegisteredPhase18PendingPairTestForeignArtifact(
					t, root, fixture)
			}
			localKey := sha256.Sum256([]byte(fmt.Sprintf(
				"registered-phase18/pending/K%d", custodians)))
			ingress := formalGLMRegisteredPhase18PendingPairTestIngress(
				t, root, fixture, recipient,
				fixture.receiptSet.GlobalMaterializationRootSHA256, localKey)
			defer ingress.Close()
			receiptSetJSON := formalGLMRegisteredPhase18PendingPairTestJSON(
				t, fixture.receiptSet)
			ingressReceipts, allReplayed, err := stores.pending.Finalize(
				receiptSetJSON, ingress)
			if err != nil || allReplayed || len(ingressReceipts) != wantCount {
				t.Fatalf("first finalize: receipts=%d replay=%v err=%v",
					len(ingressReceipts), allReplayed, err)
			}
			replayedIngress, allReplayed, err := stores.pending.Finalize(
				receiptSetJSON, ingress)
			if err != nil || !allReplayed ||
				!reflect.DeepEqual(replayedIngress, ingressReceipts) {
				t.Fatalf("finalize replay: equal=%v replay=%v err=%v",
					reflect.DeepEqual(replayedIngress, ingressReceipts), allReplayed, err)
			}
			for sourceIndex, source := range fixture.source.plan.CustodianPeers {
				authorization := fixture.authorizations[source]
				for blockIndex := 0; blockIndex < fixture.source.plan.TotalBlocks; blockIndex++ {
					loaded, err := ingress.Load(authorization, blockIndex)
					want := ingressReceipts[sourceIndex*fixture.source.plan.TotalBlocks+blockIndex]
					if err != nil || !reflect.DeepEqual(loaded, want) {
						t.Fatalf("load %s/%d: equal=%v err=%v", source,
							blockIndex, reflect.DeepEqual(loaded, want), err)
					}
				}
			}
			formalGLMRegisteredPhase18PendingPairTestModes(t, root)
			ingress.Close()
			ingress = formalGLMRegisteredPhase18PendingPairTestIngress(
				t, root, fixture, recipient,
				fixture.receiptSet.GlobalMaterializationRootSHA256, localKey)
			loaded, err := ingress.Load(
				fixture.authorizations[lastSource], lastBlock.BlockIndex)
			if err != nil || !reflect.DeepEqual(loaded, ingressReceipts[len(ingressReceipts)-1]) {
				t.Fatalf("ingress restart: equal=%v err=%v",
					reflect.DeepEqual(loaded, ingressReceipts[len(ingressReceipts)-1]), err)
			}
		})
	}

	for _, field := range reflect.VisibleFields(
		reflect.TypeOf(formalGLMRegisteredPhase18PendingPairReceiptV1{})) {
		lower := strings.ToLower(field.Name)
		for _, forbidden := range []string{
			"path", "payload", "ciphertext", "encoded", "pairjson", "key",
		} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("pending receipt exposes %q", field.Name)
			}
		}
	}
}

func TestFormalGLMRegisteredPhase18PendingPairsRejectBeforeCASAndConflict(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase18PendingPairTestFixture(t, 2)
	recipient := fixture.source.plan.DesignatedComputePeers[0]
	root := formalGLMRegisteredPhase18PendingPairTestRoot(t, "reject-pair")
	stores := formalGLMRegisteredPhase18PendingPairTestOpen(
		t, root, fixture, recipient)
	defer stores.Close()
	source := fixture.source.plan.CustodianPeers[0]
	pair := fixture.pairs[source][0]
	tampered := formalGLMRegisteredPhase18ProvenanceTestClone(t, pair)
	tampered.Envelopes[0].Signature[0] ^= 1
	reordered := formalGLMRegisteredPhase18ProvenanceTestClone(t, pair)
	reordered.Envelopes[0], reordered.Envelopes[1] =
		reordered.Envelopes[1], reordered.Envelopes[0]
	wrongArtifact := formalGLMRegisteredPhase18ProvenanceTestClone(t, pair)
	wrongArtifact.ArtifactID = strings.Repeat("a", 64)
	canonical := formalGLMRegisteredPhase18PendingPairTestJSON(t, pair)
	for name, encoded := range map[string][]byte{
		"tampered-signature": formalGLMRegisteredPhase18PendingPairTestJSON(
			t, tampered),
		"reordered-envelopes": formalGLMRegisteredPhase18PendingPairTestJSON(
			t, reordered),
		"wrong-artifact": formalGLMRegisteredPhase18PendingPairTestJSON(
			t, wrongArtifact),
		"non-canonical": append(append([]byte(nil), canonical...), ' '),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := stores.pending.CommitPair(encoded); err == nil {
				t.Fatal("invalid pair reached pending CAS")
			}
			if got := formalGLMRegisteredPhase18PendingPairTestRegularFiles(
				t, root, formalGLMRegisteredPhase18PendingPairDirV1); got != 0 {
				t.Fatalf("invalid pair created %d pending records", got)
			}
		})
	}
	want, replayed, err := stores.pending.CommitPair(canonical)
	if err != nil || replayed {
		t.Fatalf("valid pair commit: replay=%v err=%v", replayed, err)
	}

	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		fixture.source.contract, fixture.source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	ciphertexts := make(map[string][]byte, 2)
	for _, envelope := range pair.Envelopes {
		changed := append([]byte(nil), envelope.Ciphertext...)
		changed[len(changed)-1] ^= 1
		ciphertexts[envelope.RecipientName] = changed
	}
	alternate, err := formalGLMRegisteredPhase18BuildBlockPairWithContextV1(
		context, fixture.authorizations[source], fixture.tickets, pair.BlockIndex,
		ciphertexts, fixture.source.inputs.identities.private[source])
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := stores.pending.CommitPair(
		formalGLMRegisteredPhase18PendingPairTestJSON(t, alternate)); err == nil {
		t.Fatal("different valid pair replaced the pending CAS slot")
	}
	got, replayed, err := stores.pending.CommitPair(canonical)
	if err != nil || !replayed || !reflect.DeepEqual(got, want) {
		t.Fatalf("conflict changed slot: equal=%v replay=%v err=%v",
			reflect.DeepEqual(got, want), replayed, err)
	}
}

func TestFormalGLMRegisteredPhase18PendingPairsFinalizeFailsClosed(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase18PendingPairTestFixture(t, 2)
	recipient := fixture.source.plan.DesignatedComputePeers[0]
	otherRecipient := fixture.source.plan.DesignatedComputePeers[1]
	localKey := sha256.Sum256([]byte("registered-phase18/pending/fail-closed"))
	receiptSetJSON := formalGLMRegisteredPhase18PendingPairTestJSON(
		t, fixture.receiptSet)

	t.Run("missing-pair", func(t *testing.T) {
		root := formalGLMRegisteredPhase18PendingPairTestRoot(t, "missing")
		stores := formalGLMRegisteredPhase18PendingPairTestOpen(
			t, root, fixture, recipient)
		defer stores.Close()
		lastSource := fixture.source.plan.CustodianPeers[1]
		lastBlock := fixture.source.plan.TotalBlocks - 1
		formalGLMRegisteredPhase18PendingPairTestCommitAll(
			t, stores, fixture, lastSource, lastBlock)
		ingress := formalGLMRegisteredPhase18PendingPairTestIngress(
			t, root, fixture, recipient,
			fixture.receiptSet.GlobalMaterializationRootSHA256, localKey)
		defer ingress.Close()
		if _, _, err := stores.pending.Finalize(
			receiptSetJSON, ingress); err == nil {
			t.Fatal("incomplete pending matrix reached ingress")
		}
		if got := formalGLMRegisteredPhase18PendingPairTestRegularFiles(
			t, root, formalGLMRegisteredPhase18RecordsDirectoryV3); got != 0 {
			t.Fatalf("missing pair created %d ingress records", got)
		}
	})

	t.Run("root-recipient-order-tamper", func(t *testing.T) {
		root := formalGLMRegisteredPhase18PendingPairTestRoot(t, "bindings")
		stores := formalGLMRegisteredPhase18PendingPairTestOpen(
			t, root, fixture, recipient)
		defer stores.Close()
		formalGLMRegisteredPhase18PendingPairTestCommitAll(
			t, stores, fixture, "", -1)
		reordered := formalGLMRegisteredPhase18ProvenanceTestClone(
			t, fixture.receiptSet)
		reordered.Receipts[0], reordered.Receipts[1] =
			reordered.Receipts[1], reordered.Receipts[0]
		ingress := formalGLMRegisteredPhase18PendingPairTestIngress(
			t, root, fixture, recipient,
			fixture.receiptSet.GlobalMaterializationRootSHA256, localKey)
		if _, _, err := stores.pending.Finalize(
			formalGLMRegisteredPhase18PendingPairTestJSON(t, reordered), ingress); err == nil {
			ingress.Close()
			t.Fatal("reordered K receipts reached ingress")
		}
		ingress.Close()

		wrongRoot := strings.Repeat("a", 64)
		if wrongRoot == fixture.receiptSet.GlobalMaterializationRootSHA256 {
			wrongRoot = strings.Repeat("b", 64)
		}
		ingress = formalGLMRegisteredPhase18PendingPairTestIngress(
			t, root, fixture, recipient, wrongRoot, localKey)
		if _, _, err := stores.pending.Finalize(receiptSetJSON, ingress); err == nil {
			ingress.Close()
			t.Fatal("wrong global root reached ingress")
		}
		ingress.Close()

		ingress = formalGLMRegisteredPhase18PendingPairTestIngress(
			t, root, fixture, otherRecipient,
			fixture.receiptSet.GlobalMaterializationRootSHA256, localKey)
		if _, _, err := stores.pending.Finalize(receiptSetJSON, ingress); err == nil {
			ingress.Close()
			t.Fatal("wrong recipient reached ingress")
		}
		ingress.Close()
		if got := formalGLMRegisteredPhase18PendingPairTestRegularFiles(
			t, root, formalGLMRegisteredPhase18RecordsDirectoryV3); got != 0 {
			t.Fatalf("binding rejection created %d ingress records", got)
		}

		stores.pending.mu.Lock()
		relative, err := stores.pending.recordRelativeLocked(
			fixture.source.plan.CustodianPeers[0], 0, false)
		stores.pending.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(root, relative), 0o644); err != nil {
			t.Fatal(err)
		}
		ingress = formalGLMRegisteredPhase18PendingPairTestIngress(
			t, root, fixture, recipient,
			fixture.receiptSet.GlobalMaterializationRootSHA256, localKey)
		defer ingress.Close()
		if _, _, err := stores.pending.Finalize(receiptSetJSON, ingress); err == nil {
			t.Fatal("tampered pending mode reached ingress")
		}
		if got := formalGLMRegisteredPhase18PendingPairTestRegularFiles(
			t, root, formalGLMRegisteredPhase18RecordsDirectoryV3); got != 0 {
			t.Fatalf("tamper rejection created %d ingress records", got)
		}
	})

	t.Run("different-valid-pair", func(t *testing.T) {
		root := formalGLMRegisteredPhase18PendingPairTestRoot(t, "different")
		stores := formalGLMRegisteredPhase18PendingPairTestOpen(
			t, root, fixture, recipient)
		defer stores.Close()
		targetSource := fixture.source.plan.CustodianPeers[0]
		target := fixture.pairs[targetSource][0]
		context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
			fixture.source.contract, fixture.source.inputs.identities.public)
		if err != nil {
			t.Fatal(err)
		}
		ciphertexts := make(map[string][]byte, 2)
		for _, envelope := range target.Envelopes {
			changed := append([]byte(nil), envelope.Ciphertext...)
			changed[0] ^= 1
			ciphertexts[envelope.RecipientName] = changed
		}
		alternate, err := formalGLMRegisteredPhase18BuildBlockPairWithContextV1(
			context, fixture.authorizations[targetSource], fixture.tickets, 0,
			ciphertexts, fixture.source.inputs.identities.private[targetSource])
		if err != nil {
			t.Fatal(err)
		}
		for _, source := range fixture.source.plan.CustodianPeers {
			for blockIndex, pair := range fixture.pairs[source] {
				if source == targetSource && blockIndex == 0 {
					pair = alternate
				}
				if _, replayed, err := stores.pending.CommitPair(
					formalGLMRegisteredPhase18PendingPairTestJSON(t, pair)); err != nil || replayed {
					t.Fatalf("alternate matrix commit: replay=%v err=%v", replayed, err)
				}
			}
		}
		ingress := formalGLMRegisteredPhase18PendingPairTestIngress(
			t, root, fixture, recipient,
			fixture.receiptSet.GlobalMaterializationRootSHA256, localKey)
		defer ingress.Close()
		if _, _, err := stores.pending.Finalize(receiptSetJSON, ingress); err == nil {
			t.Fatal("different valid pair was accepted under the K root")
		}
		if got := formalGLMRegisteredPhase18PendingPairTestRegularFiles(
			t, root, formalGLMRegisteredPhase18RecordsDirectoryV3); got != 0 {
			t.Fatalf("root mismatch created %d ingress records", got)
		}
	})
}

func TestFormalGLMRegisteredPhase18TypedIngressSeamsExcludePolicyAndContextCopies(
	t *testing.T,
) {
	contractType := reflect.TypeOf(formalGLMSourceContractV1{})
	pinsType := reflect.TypeOf(map[string]ed25519.PublicKey{})
	for name, functionType := range map[string]reflect.Type{
		"compose": reflect.TypeOf(
			formalGLMRegisteredPhase18ComposeValidatedIngressFrameWithContextV3),
		"commit": reflect.TypeOf(
			(*formalGLMRegisteredPhase18IngressStoreV3).CommitWithContextV3),
	} {
		for index := 0; index < functionType.NumIn(); index++ {
			if functionType.In(index) == contractType ||
				functionType.In(index) == pinsType {
				t.Fatalf("typed %s seam accepts public policy input", name)
			}
		}
	}

	fixture := formalGLMRegisteredPhase18PendingPairTestFixture(t, 2)
	recipient := fixture.source.plan.DesignatedComputePeers[0]
	source := fixture.source.plan.CustodianPeers[0]
	pair := fixture.pairs[source][fixture.source.plan.TotalBlocks-1]
	localKey := sha256.Sum256([]byte("registered-phase18/context-identity"))
	root := formalGLMRegisteredPhase18PendingPairTestRoot(t, "context")
	ingress := formalGLMRegisteredPhase18PendingPairTestIngress(
		t, root, fixture, recipient,
		fixture.receiptSet.GlobalMaterializationRootSHA256, localKey)
	defer ingress.Close()
	provenance, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		fixture.source.contract, fixture.source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	separate, err :=
		formalGLMRegisteredPhase18ValidationContextFromProvenanceV3(provenance)
	if err != nil || reflect.ValueOf(separate).Pointer() ==
		reflect.ValueOf(ingress.context).Pointer() {
		t.Fatal("test did not create a separate equivalent context")
	}
	encoded, err := formalGLMRegisteredPhase18ComposeIngressFrameWithContextV3(
		provenance, ingress.context, fixture.authorizations[source],
		fixture.tickets, pair, fixture.receiptSet, recipient, localKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ingress.CommitWithContextV3(encoded, separate); err == nil {
		t.Fatal("typed ingress CAS accepted an equivalent context copy")
	}
	if got := formalGLMRegisteredPhase18PendingPairTestRegularFiles(
		t, root, formalGLMRegisteredPhase18RecordsDirectoryV3); got != 0 {
		t.Fatalf("context copy rejection created %d ingress records", got)
	}
	if _, replayed, err := ingress.CommitWithContextV3(
		encoded, ingress.context); err != nil || replayed {
		t.Fatalf("fixed context commit: replay=%v err=%v", replayed, err)
	}
	if !bytes.Equal(encoded, append([]byte(nil), encoded...)) {
		t.Fatal("typed ingress commit changed caller bytes")
	}
}
