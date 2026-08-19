package main

import (
	"bytes"
	"crypto/ecdh"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type formalGLMRegisteredPhase19LoaderTestFixtureV1 struct {
	provenance  formalGLMRegisteredPhase18ProvenanceTestFixtureV1
	tickets     []formalGLMRegisteredPhase18RecipientTicketV1
	recipientSK map[string][]byte
	pairs       map[string][]formalGLMRegisteredPhase18BlockPairV1
	receiptSet  formalGLMRegisteredPhase18ReceiptSetV1
	record      formalGLMRegisteredPhase19BindingRecordV1
	values      map[string][][]string
	validity    map[string][][]bool
	consensus   [][32]byte
	localKeys   map[string][32]byte
	frames      map[string]map[string][][]byte
}

var (
	formalGLMRegisteredPhase19LoaderK2Once sync.Once
	formalGLMRegisteredPhase19LoaderK2     formalGLMRegisteredPhase19LoaderTestFixtureV1
	formalGLMRegisteredPhase19LoaderK3Once sync.Once
	formalGLMRegisteredPhase19LoaderK3     formalGLMRegisteredPhase19LoaderTestFixtureV1
	formalGLMRegisteredPhase19LoaderK5Once sync.Once
	formalGLMRegisteredPhase19LoaderK5     formalGLMRegisteredPhase19LoaderTestFixtureV1
)

func formalGLMRegisteredPhase19LoaderTestCached(t testing.TB,
	custodians int,
) formalGLMRegisteredPhase19LoaderTestFixtureV1 {
	t.Helper()
	var once *sync.Once
	var fixture *formalGLMRegisteredPhase19LoaderTestFixtureV1
	switch custodians {
	case 2:
		once = &formalGLMRegisteredPhase19LoaderK2Once
		fixture = &formalGLMRegisteredPhase19LoaderK2
	case 3:
		once = &formalGLMRegisteredPhase19LoaderK3Once
		fixture = &formalGLMRegisteredPhase19LoaderK3
	case 5:
		once = &formalGLMRegisteredPhase19LoaderK5Once
		fixture = &formalGLMRegisteredPhase19LoaderK5
	default:
		t.Fatalf("unsupported registered Phase19 loader fixture K%d", custodians)
	}
	once.Do(func() {
		*fixture = formalGLMRegisteredPhase19LoaderTestBuild(t, custodians)
	})
	return *fixture
}

func TestFormalGLMRegisteredPhase19PrivateBlockSetK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMRegisteredPhase19LoaderTestCached(t, custodians)
			plan := fixture.provenance.source.plan
			for _, recipient := range plan.DesignatedComputePeers {
				store := formalGLMRegisteredPhase19LoaderTestStore(
					t, fixture, formalGLMRegisteredPhase19LoaderTestRoot(
						t, fmt.Sprintf("block-set-K%d-%s", custodians, recipient)),
					recipient, fixture.receiptSet.GlobalMaterializationRootSHA256,
					fixture.localKeys[recipient])
				formalGLMRegisteredPhase19LoaderTestCommit(
					t, fixture, store, recipient, "", -1, nil)
				for blockIndex := 0; blockIndex < plan.TotalBlocks; blockIndex++ {
					blocks, err := formalGLMLoadRegisteredPhase19PrivateBlockSetV1(
						fixture.record, store, fixture.recipientSK[recipient], blockIndex)
					if err != nil {
						t.Fatal(err)
					}
					if len(blocks) != custodians {
						formalGLMRegisteredPhase19ClearPrivateBlocksV1(blocks)
						t.Fatalf("loaded %d private blocks, want exactly K=%d", len(blocks), custodians)
					}
					for sourceIndex, source := range plan.CustodianPeers {
						block := blocks[sourceIndex]
						if !block.verified || block.source != source ||
							block.sourceSlot != sourceIndex ||
							block.recipient != recipient || block.blockIndex != blockIndex ||
							block.totalBlocks != plan.TotalBlocks {
							formalGLMRegisteredPhase19ClearPrivateBlocksV1(blocks)
							t.Fatal("private block set is not source-complete and canonical")
						}
					}
					encoded, err := json.Marshal(blocks)
					if err != nil || strings.Contains(strings.ToLower(string(encoded)), "coordinate") {
						formalGLMRegisteredPhase19ClearPrivateBlocksV1(blocks)
						t.Fatalf("private block set became serializable: %s / %v", encoded, err)
					}
					formalGLMRegisteredPhase19ClearPrivateBlocksV1(blocks)
				}
				for _, invalid := range []int{-1, plan.TotalBlocks} {
					if blocks, err := formalGLMLoadRegisteredPhase19PrivateBlockSetV1(
						fixture.record, store, fixture.recipientSK[recipient], invalid); err == nil || blocks != nil {
						formalGLMRegisteredPhase19ClearPrivateBlocksV1(blocks)
						t.Fatal("out-of-range private block load was accepted")
					}
				}
				store.Close()
			}
		})
	}
}

func formalGLMRegisteredPhase19LoaderTestTickets(t testing.TB,
	provenance formalGLMRegisteredPhase18ProvenanceTestFixtureV1,
) ([]formalGLMRegisteredPhase18RecipientTicketV1, map[string][]byte) {
	t.Helper()
	contract := provenance.source.contract
	pins := provenance.source.inputs.identities.public
	tickets := make([]formalGLMRegisteredPhase18RecipientTicketV1, 0, 2)
	privateKeys := make(map[string][]byte, 2)
	for _, recipient := range provenance.source.plan.DesignatedComputePeers {
		transportKey, err := ecdh.X25519().GenerateKey(crand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		unsigned, err := formalGLMRegisteredPhase18BuildRecipientTicketV1(
			contract, recipient, transportKey.PublicKey().Bytes(), pins)
		if err != nil {
			t.Fatal(err)
		}
		ticket, err := formalGLMRegisteredPhase18SignRecipientTicketV1(
			unsigned, contract,
			provenance.source.inputs.identities.private[recipient], pins)
		if err != nil {
			t.Fatal(err)
		}
		tickets = append(tickets, ticket)
		privateKeys[recipient] = append([]byte(nil), transportKey.Bytes()...)
	}
	return tickets, privateKeys
}

func formalGLMRegisteredPhase19LoaderTestRecord(t testing.TB,
	provenance formalGLMRegisteredPhase18ProvenanceTestFixtureV1,
	receiptSet formalGLMRegisteredPhase18ReceiptSetV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
) formalGLMRegisteredPhase19BindingRecordV1 {
	t.Helper()
	contract := provenance.source.contract
	pins := provenance.source.inputs.identities.public
	binding, err := formalGLMBuildRegisteredPhase19BindingV1(
		contract, receiptSet, tickets, pins)
	if err != nil {
		t.Fatal(err)
	}
	ordered, err := formalGLMRegisteredPhase18CanonicalTicketsV1(
		tickets, contract, pins)
	if err != nil {
		t.Fatal(err)
	}
	record := formalGLMRegisteredPhase19BindingRecordV1{
		Version: formalGLMRegisteredPhase19BindingRecordVersion,
		Purpose: formalGLMRegisteredPhase19BindingRecordPurpose,
		Binding: binding, ReceiptSet: receiptSet,
		RecipientTickets: ordered,
	}
	if err := formalGLMValidateRegisteredPhase19BindingRecordV1(
		record, contract, pins); err != nil {
		t.Fatal(err)
	}
	return record
}

func formalGLMRegisteredPhase19LoaderTestBuild(t testing.TB,
	custodians int,
) formalGLMRegisteredPhase19LoaderTestFixtureV1 {
	t.Helper()
	provenance := formalGLMRegisteredPhase18ProvenanceTestBuild(t, custodians)
	contract := provenance.source.contract
	pins := provenance.source.inputs.identities.public
	tickets, recipientSK := formalGLMRegisteredPhase19LoaderTestTickets(
		t, provenance)
	plan := provenance.source.plan
	pairs := make(map[string][]formalGLMRegisteredPhase18BlockPairV1,
		custodians)
	values := make(map[string][][]string, custodians)
	validity := make(map[string][][]bool, custodians)
	consensus := make([][32]byte, plan.TotalBlocks)
	for blockIndex := range consensus {
		consensus[blockIndex] = sha256.Sum256([]byte(fmt.Sprintf(
			"registered-phase19-loader/K%d/block/%d", custodians, blockIndex)))
	}
	receipts := make([]formalGLMRegisteredPhase18LocalReceiptV1, 0,
		custodians)
	for _, source := range plan.CustodianPeers {
		authorization := provenance.authorizations[source]
		pairs[source] = make([]formalGLMRegisteredPhase18BlockPairV1,
			plan.TotalBlocks)
		values[source] = make([][]string, plan.TotalBlocks)
		validity[source] = make([][]bool, plan.TotalBlocks)
		for blockIndex := 0; blockIndex < plan.TotalBlocks; blockIndex++ {
			values[source][blockIndex], validity[source][blockIndex] =
				formalGLMRegisteredPhase18MaterializedPairTestValues(
					authorization, blockIndex)
			var err error
			pairs[source][blockIndex], err =
				formalGLMRegisteredPhase18BuildMaterializedBlockPairV3(
					contract, authorization, tickets, blockIndex,
					values[source][blockIndex], validity[source][blockIndex],
					consensus[blockIndex][:],
					provenance.source.inputs.identities.private[source], pins)
			if err != nil {
				t.Fatal(err)
			}
		}
		receipt, err := formalGLMRegisteredPhase18BuildLocalReceiptV1(
			contract, authorization, tickets, pairs[source],
			provenance.source.inputs.identities.private[source], pins)
		if err != nil {
			t.Fatal(err)
		}
		receipts = append(receipts, receipt)
	}
	receiptSet, err := formalGLMRegisteredPhase18BuildReceiptSetV1(
		contract, receipts, pins)
	if err != nil {
		t.Fatal(err)
	}
	record := formalGLMRegisteredPhase19LoaderTestRecord(
		t, provenance, receiptSet, tickets)

	ticketJSON := make([][]byte, len(tickets))
	for index := range tickets {
		ticketJSON[index], err = json.Marshal(tickets[index])
		if err != nil {
			t.Fatal(err)
		}
	}
	receiptJSON, err := json.Marshal(receiptSet)
	if err != nil {
		t.Fatal(err)
	}
	localKeys := make(map[string][32]byte, 2)
	frames := make(map[string]map[string][][]byte, 2)
	for _, recipient := range plan.DesignatedComputePeers {
		localKeys[recipient] = sha256.Sum256([]byte(
			"registered-phase19-loader/local-key/" + recipient))
		frames[recipient] = make(map[string][][]byte, custodians)
		for _, source := range plan.CustodianPeers {
			frames[recipient][source] = make([][]byte, plan.TotalBlocks)
			for blockIndex, pair := range pairs[source] {
				pairJSON, marshalErr := json.Marshal(pair)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				frames[recipient][source][blockIndex], err =
					formalGLMRegisteredPhase18ComposeIngressFrameV3(
						contract, provenance.authorizations[source], ticketJSON,
						pairJSON, receiptJSON, recipient, pins,
						localKeys[recipient])
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	return formalGLMRegisteredPhase19LoaderTestFixtureV1{
		provenance: provenance, tickets: tickets, recipientSK: recipientSK,
		pairs: pairs, receiptSet: receiptSet, record: record,
		values: values, validity: validity, consensus: consensus,
		localKeys: localKeys, frames: frames,
	}
}

func formalGLMRegisteredPhase19LoaderTestRoot(t testing.TB,
	name string,
) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(resolved, name)
}

func formalGLMRegisteredPhase19LoaderTestStore(t testing.TB,
	fixture formalGLMRegisteredPhase19LoaderTestFixtureV1,
	root, recipient, expectedRoot string, localKey [32]byte,
) *formalGLMRegisteredPhase18IngressStoreV3 {
	t.Helper()
	store, err := newFormalGLMRegisteredPhase18IngressStoreV3(
		root, recipient, localKey, fixture.provenance.source.contract,
		expectedRoot, fixture.provenance.source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func formalGLMRegisteredPhase19LoaderTestCommit(t testing.TB,
	fixture formalGLMRegisteredPhase19LoaderTestFixtureV1,
	store *formalGLMRegisteredPhase18IngressStoreV3,
	recipient, skipSource string, skipBlock int,
	mutate func(string, int, []byte) []byte,
) {
	t.Helper()
	for _, source := range fixture.provenance.source.plan.CustodianPeers {
		for blockIndex, original := range fixture.frames[recipient][source] {
			if source == skipSource && blockIndex == skipBlock {
				continue
			}
			encoded := append([]byte(nil), original...)
			if mutate != nil {
				encoded = mutate(source, blockIndex, encoded)
			}
			if _, replayed, err := store.Commit(
				encoded, fixture.provenance.authorizations[source]); err != nil || replayed {
				t.Fatalf("commit %s/%d: replay=%v err=%v",
					source, blockIndex, replayed, err)
			}
		}
	}
}

func formalGLMRegisteredPhase19LoaderTestSigned(left, right *big.Int,
	ringBits int,
) *big.Int {
	modulus := exactGCModulus(ringBits)
	half := new(big.Int).Rsh(new(big.Int).Set(modulus), 1)
	result := new(big.Int).Add(left, right)
	result.Mod(result, modulus)
	if result.Cmp(half) >= 0 {
		result.Sub(result, modulus)
	}
	return result
}

func TestFormalGLMRegisteredPhase19LoaderK2K5FinalBlockAndNoOpenings(
	t *testing.T,
) {
	for _, custodians := range []int{2, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMRegisteredPhase19LoaderTestCached(t, custodians)
			plan := fixture.provenance.source.plan
			byRecipient := make(
				map[string][]formalGLMRegisteredPhase19PrivateBlockV1, 2)
			for _, recipient := range plan.DesignatedComputePeers {
				root := formalGLMRegisteredPhase19LoaderTestRoot(
					t, "ingress-"+recipient)
				store := formalGLMRegisteredPhase19LoaderTestStore(
					t, fixture, root, recipient,
					fixture.receiptSet.GlobalMaterializationRootSHA256,
					fixture.localKeys[recipient])
				formalGLMRegisteredPhase19LoaderTestCommit(
					t, fixture, store, recipient, "", -1, nil)
				blocks, err := formalGLMLoadRegisteredPhase19PrivateBlocksV1(
					fixture.record, store, fixture.recipientSK[recipient])
				store.Close()
				if err != nil {
					t.Fatal(err)
				}
				if len(blocks) != custodians*plan.TotalBlocks {
					t.Fatalf("loaded %d blocks, want %d",
						len(blocks), custodians*plan.TotalBlocks)
				}
				for sourceIndex, source := range plan.CustodianPeers {
					for blockIndex := 0; blockIndex < plan.TotalBlocks; blockIndex++ {
						block := blocks[sourceIndex*plan.TotalBlocks+blockIndex]
						if !block.verified || block.source != source ||
							block.sourceSlot != sourceIndex ||
							block.recipient != recipient ||
							block.blockIndex != blockIndex ||
							block.semanticRootSHA256 !=
								fixture.record.Binding.SemanticRootSHA256 ||
							block.openingsPerformed != 0 {
							t.Fatalf("non-canonical private block %s/%d", source, blockIndex)
						}
					}
				}
				last := blocks[len(blocks)-1]
				if last.blockIndex != plan.TotalBlocks-1 ||
					last.globalSlotOffset != 8 || last.slotsInBlock != 4 {
					t.Fatal("loader did not preserve the fixed padded final block")
				}
				encoded, err := json.Marshal(blocks)
				if err != nil {
					t.Fatal(err)
				}
				lower := strings.ToLower(string(encoded))
				for _, forbidden := range []string{
					"ciphertext", "path", "key", "capsule", "run_id",
					"pre_execution", "coordinate", "validity", "consensus",
				} {
					if strings.Contains(lower, forbidden) {
						t.Fatalf("private in-memory result serialized %q", forbidden)
					}
				}
				byRecipient[recipient] = blocks
			}

			left := byRecipient[plan.DesignatedComputePeers[0]]
			right := byRecipient[plan.DesignatedComputePeers[1]]
			alignmentOnly := false
			for sourceIndex, source := range plan.CustodianPeers {
				if len(fixture.provenance.authorizations[source].LocalColumns) == 0 {
					alignmentOnly = true
				}
				for blockIndex := 0; blockIndex < plan.TotalBlocks; blockIndex++ {
					index := sourceIndex*plan.TotalBlocks + blockIndex
					for coordinate, want := range fixture.values[source][blockIndex] {
						got := formalGLMRegisteredPhase19LoaderTestSigned(
							left[index].coordinateShares[coordinate],
							right[index].coordinateShares[coordinate], plan.RingBits)
						if got.String() != want {
							t.Fatalf("%s block %d coordinate %d got %s want %s",
								source, blockIndex, coordinate, got, want)
						}
					}
					for row, want := range fixture.validity[source][blockIndex] {
						got := left[index].validityShares[row] ^
							right[index].validityShares[row]
						if (got == 1) != want {
							t.Fatalf("%s block %d validity %d got %d want %v",
								source, blockIndex, row, got, want)
						}
					}
					var consensus [32]byte
					for byteIndex := range consensus {
						consensus[byteIndex] =
							left[index].alignmentConsensusShare[byteIndex] ^
								right[index].alignmentConsensusShare[byteIndex]
					}
					if consensus != fixture.consensus[blockIndex] ||
						left[index].alignmentGateShare^
							right[index].alignmentGateShare != 1 {
						t.Fatalf("%s block %d alignment shares differ",
							source, blockIndex)
					}
				}
			}
			if custodians == 5 && !alignmentOnly {
				t.Fatal("K5 fixture lacks an alignment-only witness")
			}
		})
	}
}

func TestFormalGLMRegisteredPhase19LoaderRestart(t *testing.T) {
	fixture := formalGLMRegisteredPhase19LoaderTestCached(t, 2)
	recipient := fixture.provenance.source.plan.DesignatedComputePeers[0]
	ingressRoot := formalGLMRegisteredPhase19LoaderTestRoot(t, "ingress")
	bindingRoot := formalGLMRegisteredPhase19LoaderTestRoot(t, "binding")
	ingress := formalGLMRegisteredPhase19LoaderTestStore(
		t, fixture, ingressRoot, recipient,
		fixture.receiptSet.GlobalMaterializationRootSHA256,
		fixture.localKeys[recipient])
	formalGLMRegisteredPhase19LoaderTestCommit(
		t, fixture, ingress, recipient, "", -1, nil)
	before, err := formalGLMLoadRegisteredPhase19PrivateBlocksV1(
		fixture.record, ingress, fixture.recipientSK[recipient])
	if err != nil {
		t.Fatal(err)
	}
	bindingStore, err := newFormalGLMRegisteredPhase19BindingStoreV1(
		bindingRoot, fixture.provenance.source.contract,
		fixture.provenance.source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	persisted, replayed, err := bindingStore.Commit(
		fixture.receiptSet, fixture.tickets)
	if err != nil || replayed || !reflect.DeepEqual(persisted, fixture.record) {
		t.Fatalf("persist binding: replay=%v equal=%v err=%v",
			replayed, reflect.DeepEqual(persisted, fixture.record), err)
	}
	ingress.Close()
	bindingStore.Close()

	restartedIngress := formalGLMRegisteredPhase19LoaderTestStore(
		t, fixture, ingressRoot, recipient,
		fixture.receiptSet.GlobalMaterializationRootSHA256,
		fixture.localKeys[recipient])
	restartedBinding, err := newFormalGLMRegisteredPhase19BindingStoreV1(
		bindingRoot, fixture.provenance.source.contract,
		fixture.provenance.source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	record, err := restartedBinding.Load(
		fixture.record.Binding.ArtifactID,
		fixture.record.Binding.ReceiptSetSHA256)
	if err != nil {
		t.Fatal(err)
	}
	after, err := formalGLMLoadRegisteredPhase19PrivateBlocksV1(
		record, restartedIngress, fixture.recipientSK[recipient])
	restartedIngress.Close()
	restartedBinding.Close()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("restart blocks: equal=%v err=%v",
			reflect.DeepEqual(before, after), err)
	}
}

func TestFormalGLMRegisteredPhase19LoaderRejectsInvalidInputs(t *testing.T) {
	fixture := formalGLMRegisteredPhase19LoaderTestCached(t, 2)
	plan := fixture.provenance.source.plan
	recipient := plan.DesignatedComputePeers[0]
	otherRecipient := plan.DesignatedComputePeers[1]
	open := func(t *testing.T, name string) (
		*formalGLMRegisteredPhase18IngressStoreV3, string,
	) {
		root := formalGLMRegisteredPhase19LoaderTestRoot(t, name)
		store := formalGLMRegisteredPhase19LoaderTestStore(
			t, fixture, root, recipient,
			fixture.receiptSet.GlobalMaterializationRootSHA256,
			fixture.localKeys[recipient])
		return store, root
	}

	t.Run("missing", func(t *testing.T) {
		store, _ := open(t, "missing")
		defer store.Close()
		formalGLMRegisteredPhase19LoaderTestCommit(
			t, fixture, store, recipient, plan.CustodianPeers[0],
			plan.TotalBlocks-1, nil)
		blocks, err := formalGLMLoadRegisteredPhase19PrivateBlocksV1(
			fixture.record, store, fixture.recipientSK[recipient])
		if err == nil || blocks != nil {
			t.Fatal("missing slot returned a partial private fan-in")
		}
	})

	t.Run("reordered-receipts", func(t *testing.T) {
		store, _ := open(t, "reordered")
		defer store.Close()
		formalGLMRegisteredPhase19LoaderTestCommit(
			t, fixture, store, recipient, "", -1, nil)
		record := formalGLMRegisteredPhase18ProvenanceTestClone(
			t, fixture.record)
		record.ReceiptSet.Receipts[0], record.ReceiptSet.Receipts[1] =
			record.ReceiptSet.Receipts[1], record.ReceiptSet.Receipts[0]
		if blocks, err := formalGLMLoadRegisteredPhase19PrivateBlocksV1(
			record, store, fixture.recipientSK[recipient]); err == nil || blocks != nil {
			t.Fatal("reordered receipt set reached private output")
		}
	})

	t.Run("tampered-rooted-record", func(t *testing.T) {
		store, root := open(t, "tamper")
		defer store.Close()
		formalGLMRegisteredPhase19LoaderTestCommit(
			t, fixture, store, recipient, "", -1, nil)
		source := plan.CustodianPeers[0]
		store.mu.Lock()
		_, relative, err := store.recordRelativePathLocked(
			fixture.provenance.authorizations[source], 0, false)
		store.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, relative)
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		encoded[len(encoded)/2] ^= 1
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		if blocks, err := formalGLMLoadRegisteredPhase19PrivateBlocksV1(
			fixture.record, store, fixture.recipientSK[recipient]); err == nil || blocks != nil {
			t.Fatal("tampered rooted frame reached private output")
		}
	})

	t.Run("wrong-secret", func(t *testing.T) {
		store, _ := open(t, "wrong-secret")
		defer store.Close()
		formalGLMRegisteredPhase19LoaderTestCommit(
			t, fixture, store, recipient, "", -1, nil)
		if blocks, err := formalGLMLoadRegisteredPhase19PrivateBlocksV1(
			fixture.record, store,
			fixture.recipientSK[otherRecipient]); err == nil || blocks != nil {
			t.Fatal("wrong X25519 secret reached private output")
		}
	})

	t.Run("valid-but-wrong-ticket", func(t *testing.T) {
		store, _ := open(t, "wrong-ticket")
		defer store.Close()
		formalGLMRegisteredPhase19LoaderTestCommit(
			t, fixture, store, recipient, "", -1, nil)
		otherTickets, otherKeys := formalGLMRegisteredPhase19LoaderTestTickets(
			t, fixture.provenance)
		otherRecord := formalGLMRegisteredPhase19LoaderTestRecord(
			t, fixture.provenance, fixture.receiptSet, otherTickets)
		if blocks, err := formalGLMLoadRegisteredPhase19PrivateBlocksV1(
			otherRecord, store, otherKeys[recipient]); err == nil || blocks != nil {
			t.Fatal("valid but causally different ticket reached private output")
		}
	})

	t.Run("receipt-link", func(t *testing.T) {
		store, _ := open(t, "receipt-link")
		defer store.Close()
		targetSource := plan.CustodianPeers[0]
		targetBlock := plan.TotalBlocks - 1
		mutate := func(source string, blockIndex int, encoded []byte) []byte {
			if source != targetSource || blockIndex != targetBlock {
				return encoded
			}
			authorization := fixture.provenance.authorizations[source]
			frame, err := formalGLMRegisteredPhase18DecodeIngressFrameV3(
				encoded, fixture.provenance.source.contract, authorization,
				fixture.receiptSet.GlobalMaterializationRootSHA256,
				fixture.provenance.source.inputs.identities.public,
				fixture.localKeys[recipient])
			if err != nil {
				t.Fatal(err)
			}
			frame.PairCommitment = sha256Hex([]byte("causally-different-pair"))
			changed, err := formalGLMRegisteredPhase18EncodeIngressFrameV3(
				frame, fixture.provenance.source.contract, authorization,
				fixture.receiptSet.GlobalMaterializationRootSHA256,
				fixture.provenance.source.inputs.identities.public,
				fixture.localKeys[recipient])
			if err != nil {
				t.Fatal(err)
			}
			return changed
		}
		formalGLMRegisteredPhase19LoaderTestCommit(
			t, fixture, store, recipient, "", -1, mutate)
		if blocks, err := formalGLMLoadRegisteredPhase19PrivateBlocksV1(
			fixture.record, store, fixture.recipientSK[recipient]); err == nil || blocks != nil {
			t.Fatal("frame outside its receipt commitment reached private output")
		}
	})

	t.Run("wrong-root", func(t *testing.T) {
		store, root := open(t, "wrong-root")
		formalGLMRegisteredPhase19LoaderTestCommit(
			t, fixture, store, recipient, "", -1, nil)
		store.Close()
		wrongRoot := sha256Hex([]byte("another-global-root"))
		wrongStore := formalGLMRegisteredPhase19LoaderTestStore(
			t, fixture, root, recipient, wrongRoot,
			fixture.localKeys[recipient])
		defer wrongStore.Close()
		if blocks, err := formalGLMLoadRegisteredPhase19PrivateBlocksV1(
			fixture.record, wrongStore,
			fixture.recipientSK[recipient]); err == nil || blocks != nil {
			t.Fatal("store bound to another global root reached private output")
		}
	})

	t.Run("wrong-store-route", func(t *testing.T) {
		store, root := open(t, "wrong-route")
		formalGLMRegisteredPhase19LoaderTestCommit(
			t, fixture, store, recipient, "", -1, nil)
		store.Close()
		wrongStore := formalGLMRegisteredPhase19LoaderTestStore(
			t, fixture, root, otherRecipient,
			fixture.receiptSet.GlobalMaterializationRootSHA256,
			fixture.localKeys[recipient])
		defer wrongStore.Close()
		if blocks, err := formalGLMLoadRegisteredPhase19PrivateBlocksV1(
			fixture.record, wrongStore,
			fixture.recipientSK[otherRecipient]); err == nil || blocks != nil {
			t.Fatal("recipient-mismatched store route reached private output")
		}
	})
}

func TestFormalGLMRegisteredPhase19LoaderTypeHasNoForbiddenCarrier(t *testing.T) {
	typeOf := reflect.TypeOf(formalGLMRegisteredPhase19PrivateBlockV1{})
	for index := 0; index < typeOf.NumField(); index++ {
		name := strings.ToLower(typeOf.Field(index).Name)
		for _, forbidden := range []string{
			"ciphertext", "path", "key", "capsule", "run", "preexecution",
		} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("private block type exposes forbidden field %q", name)
			}
		}
	}
	encoded, err := json.Marshal(formalGLMRegisteredPhase19PrivateBlockV1{})
	if err != nil || !bytes.Equal(encoded, []byte("{}")) {
		t.Fatalf("private block acquired a serialized surface: %q %v", encoded, err)
	}
}

func TestFormalGLMRegisteredPhase19LoaderHotLoopUsesValidationContextV3(
	t *testing.T,
) {
	source, err := os.ReadFile("formal_glm_registered_phase19_loader.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"recordRelativePathLocked(",
		"slotIDLocked(",
		"formalGLMValidateRegisteredPhase18AuthorizationV1(",
	} {
		if bytes.Contains(source, []byte(forbidden)) {
			t.Fatalf("loader hot path retains deep validation seam %q", forbidden)
		}
	}
	for _, required := range []string{
		"recordRelativePathWithContextLocked(",
		"formalGLMRegisteredPhase18IngressSlotIDWithContextV3(",
	} {
		if !bytes.Contains(source, []byte(required)) {
			t.Fatalf("loader is missing prevalidated seam %q", required)
		}
	}
	loopStart := bytes.Index(source,
		[]byte("for sourceSlot, source := range plan.CustodianPeers"))
	if loopStart < 0 {
		t.Fatal("loader source-major loop is absent")
	}
	hotLoop := source[loopStart:]
	for _, forbidden := range []string{
		"store.contract", "store.pins", "reflect.DeepEqual(",
	} {
		if bytes.Contains(hotLoop, []byte(forbidden)) {
			t.Fatalf("loader KxB loop accepts deep validation input %q", forbidden)
		}
	}

	storeSource, err := os.ReadFile("formal_glm_registered_phase18_store.go")
	if err != nil {
		t.Fatal(err)
	}
	seamStart := bytes.Index(storeSource,
		[]byte("func (store *formalGLMRegisteredPhase18IngressStoreV3) slotIDWithContextLocked("))
	seamEnd := bytes.Index(storeSource,
		[]byte("func (store *formalGLMRegisteredPhase18IngressStoreV3) recordRelativePathLocked("))
	if seamStart < 0 || seamEnd <= seamStart {
		t.Fatal("registered ingress WithContext slot seam is absent")
	}
	seam := storeSource[seamStart:seamEnd]
	for _, forbidden := range []string{
		"store.contract", "store.pins", "reflect.DeepEqual(",
		"formalGLMValidateRegisteredPhase18AuthorizationV1(",
	} {
		if bytes.Contains(seam, []byte(forbidden)) {
			t.Fatalf("registered ingress slot seam retains deep validation %q", forbidden)
		}
	}
}
