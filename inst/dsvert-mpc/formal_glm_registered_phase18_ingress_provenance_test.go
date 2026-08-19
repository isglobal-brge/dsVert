package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type formalGLMRegisteredPhase18IngressProvenanceTestInputV3 struct {
	fixture       formalGLMRegisteredPhase18ProvenanceTestFixtureV1
	authorization formalGLMRegisteredPhase18AuthorizationV1
	source        string
	recipient     string
	tickets       [][]byte
	pair          formalGLMRegisteredPhase18BlockPairV1
	pairJSON      []byte
	receiptSet    formalGLMRegisteredPhase18ReceiptSetV1
	receiptJSON   []byte
	localKey      [32]byte
}

func formalGLMRegisteredPhase18IngressProvenanceTestJSON(t testing.TB,
	value any,
) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func formalGLMRegisteredPhase18IngressProvenanceTestBuild(t testing.TB,
	custodians int,
) formalGLMRegisteredPhase18IngressProvenanceTestInputV3 {
	t.Helper()
	fixture := formalGLMRegisteredPhase18ProvenanceTestBuild(t, custodians)
	source := fixture.source.plan.CustodianPeers[0]
	if custodians == 5 {
		for _, candidate := range fixture.source.plan.CustodianPeers {
			if len(fixture.authorizations[candidate].LocalColumns) == 0 {
				source = candidate
				break
			}
		}
	}
	authorization := fixture.authorizations[source]
	recipient := authorization.DesignatedComputePeers[0]
	pair := fixture.pairs[source][authorization.Geometry.TotalBlocks-1]
	tickets := make([][]byte, len(fixture.tickets))
	for index := range fixture.tickets {
		tickets[index] = formalGLMRegisteredPhase18IngressProvenanceTestJSON(
			t, fixture.tickets[index])
	}
	return formalGLMRegisteredPhase18IngressProvenanceTestInputV3{
		fixture: fixture, authorization: authorization, source: source,
		recipient: recipient, tickets: tickets, pair: pair,
		pairJSON:   formalGLMRegisteredPhase18IngressProvenanceTestJSON(t, pair),
		receiptSet: fixture.receiptSet,
		receiptJSON: formalGLMRegisteredPhase18IngressProvenanceTestJSON(
			t, fixture.receiptSet),
		localKey: sha256.Sum256([]byte(fmt.Sprintf(
			"registered-phase18/provenance-ingress/K%d", custodians))),
	}
}

func formalGLMRegisteredPhase18IngressProvenanceTestCompose(t testing.TB,
	input formalGLMRegisteredPhase18IngressProvenanceTestInputV3,
) []byte {
	t.Helper()
	encoded, err := formalGLMRegisteredPhase18ComposeIngressFrameV3(
		input.fixture.source.contract, input.authorization, input.tickets,
		input.pairJSON, input.receiptJSON, input.recipient,
		input.fixture.source.inputs.identities.public, input.localKey)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func formalGLMRegisteredPhase18IngressProvenanceTestRegularFiles(
	t testing.TB, root string,
) int {
	t.Helper()
	count := 0
	err := filepath.WalkDir(root, func(_ string, entry fs.DirEntry,
		err error,
	) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			count++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return count
}

func TestFormalGLMRegisteredPhase18ComposeIngressFrameV3K2K5(
	t *testing.T,
) {
	for _, custodians := range []int{2, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			input := formalGLMRegisteredPhase18IngressProvenanceTestBuild(
				t, custodians)
			if input.pair.GlobalSlotOffset != 8 ||
				input.pair.SlotsInBlock != 4 ||
				input.authorization.Geometry.TotalCapacity != 9 {
				t.Fatal("fixture is not the fixed padded final block")
			}
			if custodians == 5 && len(input.authorization.LocalColumns) != 0 {
				t.Fatal("K5 fixture is not the alignment-only witness")
			}
			encoded := formalGLMRegisteredPhase18IngressProvenanceTestCompose(
				t, input)
			replayed := formalGLMRegisteredPhase18IngressProvenanceTestCompose(
				t, input)
			if !bytes.Equal(encoded, replayed) {
				t.Fatal("canonical provenance composition changed replay bytes")
			}
			frame, err := formalGLMRegisteredPhase18DecodeIngressFrameV3(
				encoded, input.fixture.source.contract, input.authorization,
				input.receiptSet.GlobalMaterializationRootSHA256,
				input.fixture.source.inputs.identities.public, input.localKey)
			if err != nil {
				t.Fatal(err)
			}
			envelope := input.pair.Envelopes[0]
			wantEnvelopeSHA, err :=
				formalGLMRegisteredPhase18SourceEnvelopeSHA256V1(envelope)
			if err != nil {
				t.Fatal(err)
			}
			if frame.Source != input.source || frame.Recipient != input.recipient ||
				frame.SourceSlot < 0 || frame.RecipientSlot != 0 ||
				frame.PairCommitment != input.pair.PairCommitmentSHA256 ||
				frame.BlockCommitment != input.pair.BlockCommitmentSHA256 ||
				frame.EnvelopeSHA256 != wantEnvelopeSHA ||
				frame.GlobalMaterializationRoot !=
					input.receiptSet.GlobalMaterializationRootSHA256 ||
				!bytes.Equal(frame.Ciphertext, envelope.Ciphertext) {
				t.Fatal("composed ingress frame lost signed provenance")
			}

			root := formalGLMRegisteredPhase18StoreTestRoot(t)
			store, err := newFormalGLMRegisteredPhase18IngressStoreV3(
				root, input.recipient, input.localKey,
				input.fixture.source.contract,
				input.receiptSet.GlobalMaterializationRootSHA256,
				input.fixture.source.inputs.identities.public)
			if err != nil {
				t.Fatal(err)
			}
			receipt, wasReplay, err := store.Commit(encoded, input.authorization)
			if err != nil || wasReplay {
				store.Close()
				t.Fatalf("first provenance commit: replay=%v err=%v", wasReplay, err)
			}
			replayedReceipt, wasReplay, err := store.Commit(
				encoded, input.authorization)
			if err != nil || !wasReplay || !reflect.DeepEqual(receipt, replayedReceipt) {
				store.Close()
				t.Fatalf("provenance replay: replay=%v equal=%v err=%v",
					wasReplay, reflect.DeepEqual(receipt, replayedReceipt), err)
			}
			store.Close()
			restarted, err := newFormalGLMRegisteredPhase18IngressStoreV3(
				root, input.recipient, input.localKey,
				input.fixture.source.contract,
				input.receiptSet.GlobalMaterializationRootSHA256,
				input.fixture.source.inputs.identities.public)
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := restarted.Load(input.authorization, input.pair.BlockIndex)
			restarted.Close()
			if err != nil || !reflect.DeepEqual(receipt, loaded) {
				t.Fatalf("provenance restart load: equal=%v err=%v",
					reflect.DeepEqual(receipt, loaded), err)
			}
			for index := 0; index < reflect.TypeOf(receipt).NumField(); index++ {
				name := strings.ToLower(reflect.TypeOf(receipt).Field(index).Name)
				for _, forbidden := range []string{
					"path", "payload", "ciphertext", "encoded",
				} {
					if strings.Contains(name, forbidden) {
						t.Fatalf("safe receipt exposes %q", name)
					}
				}
			}
		})
	}
}

func TestFormalGLMRegisteredPhase18ComposeIngressFrameV3RejectsBeforeCAS(
	t *testing.T,
) {
	input := formalGLMRegisteredPhase18IngressProvenanceTestBuild(t, 2)
	root := formalGLMRegisteredPhase18StoreTestRoot(t)
	store, err := newFormalGLMRegisteredPhase18IngressStoreV3(
		root, input.recipient, input.localKey, input.fixture.source.contract,
		input.receiptSet.GlobalMaterializationRootSHA256,
		input.fixture.source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	tamperedTicket := formalGLMRegisteredPhase18ProvenanceTestClone(
		t, input.fixture.tickets[0])
	tamperedTicket.Signature[0] ^= 1
	tamperedTickets := append([][]byte(nil), input.tickets...)
	tamperedTickets[0] =
		formalGLMRegisteredPhase18IngressProvenanceTestJSON(t, tamperedTicket)

	tamperedPair := formalGLMRegisteredPhase18ProvenanceTestClone(t, input.pair)
	tamperedPair.Envelopes[0].Ciphertext[0] ^= 1

	tamperedRoot := formalGLMRegisteredPhase18ProvenanceTestClone(
		t, input.receiptSet)
	tamperedRoot.GlobalMaterializationRootSHA256 = strings.Repeat("f", 64)

	tamperedReceipt := formalGLMRegisteredPhase18ProvenanceTestClone(
		t, input.receiptSet)
	tamperedReceipt.Receipts[0].Signature[0] ^= 1

	missingReceipt := formalGLMRegisteredPhase18ProvenanceTestClone(
		t, input.receiptSet)
	missingReceipt.Receipts = missingReceipt.Receipts[:1]

	reorderedReceipts := formalGLMRegisteredPhase18ProvenanceTestClone(
		t, input.receiptSet)
	reorderedReceipts.Receipts[0], reorderedReceipts.Receipts[1] =
		reorderedReceipts.Receipts[1], reorderedReceipts.Receipts[0]

	tests := []struct {
		name        string
		tickets     [][]byte
		pairJSON    []byte
		receiptJSON []byte
		recipient   string
	}{
		{"missing-ticket", input.tickets[:1], input.pairJSON,
			input.receiptJSON, input.recipient},
		{"reordered-tickets", [][]byte{input.tickets[1], input.tickets[0]},
			input.pairJSON, input.receiptJSON, input.recipient},
		{"tampered-ticket", tamperedTickets, input.pairJSON,
			input.receiptJSON, input.recipient},
		{"tampered-pair", input.tickets,
			formalGLMRegisteredPhase18IngressProvenanceTestJSON(t, tamperedPair),
			input.receiptJSON, input.recipient},
		{"wrong-recipient", input.tickets, input.pairJSON,
			input.receiptJSON, "not-a-designated-recipient"},
		{"tampered-root", input.tickets, input.pairJSON,
			formalGLMRegisteredPhase18IngressProvenanceTestJSON(t, tamperedRoot),
			input.recipient},
		{"tampered-receipt", input.tickets, input.pairJSON,
			formalGLMRegisteredPhase18IngressProvenanceTestJSON(t, tamperedReceipt),
			input.recipient},
		{"missing-receipt", input.tickets, input.pairJSON,
			formalGLMRegisteredPhase18IngressProvenanceTestJSON(t, missingReceipt),
			input.recipient},
		{"reordered-receipts", input.tickets, input.pairJSON,
			formalGLMRegisteredPhase18IngressProvenanceTestJSON(t, reorderedReceipts),
			input.recipient},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := formalGLMRegisteredPhase18ComposeIngressFrameV3(
				input.fixture.source.contract, input.authorization, test.tickets,
				test.pairJSON, test.receiptJSON, test.recipient,
				input.fixture.source.inputs.identities.public,
				input.localKey); err == nil {
				t.Fatal("invalid provenance composed an ingress frame")
			}
		})
	}
	if got := formalGLMRegisteredPhase18IngressProvenanceTestRegularFiles(
		t, root); got != 0 {
		t.Fatalf("provenance rejection reached durable CAS: files=%d", got)
	}
}

func TestFormalGLMRegisteredPhase18ComposeIngressFrameV3RequiresPairInKRoot(
	t *testing.T,
) {
	input := formalGLMRegisteredPhase18IngressProvenanceTestBuild(t, 2)
	ciphertexts := make(map[string][]byte, len(input.pair.Envelopes))
	for _, envelope := range input.pair.Envelopes {
		changed := append([]byte(nil), envelope.Ciphertext...)
		changed[len(changed)-1] ^= 1
		ciphertexts[envelope.RecipientName] = changed
	}
	alternate, err := formalGLMRegisteredPhase18BuildBlockPairV1(
		input.fixture.source.contract, input.authorization, input.fixture.tickets,
		input.pair.BlockIndex, ciphertexts,
		input.fixture.source.inputs.identities.private[input.source],
		input.fixture.source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	alternateJSON := formalGLMRegisteredPhase18IngressProvenanceTestJSON(
		t, alternate)
	if _, err := formalGLMDecodeRegisteredPhase18BlockPairV1(
		alternateJSON, input.fixture.source.contract, input.authorization,
		input.fixture.tickets,
		input.fixture.source.inputs.identities.public); err != nil {
		t.Fatalf("alternate pair is not independently valid: %v", err)
	}
	if _, err := formalGLMDecodeRegisteredPhase18ReceiptSetV1(
		input.receiptJSON, input.fixture.source.contract,
		input.fixture.source.inputs.identities.public); err != nil {
		t.Fatalf("receipt set is not independently valid: %v", err)
	}
	if _, err := formalGLMRegisteredPhase18ComposeIngressFrameV3(
		input.fixture.source.contract, input.authorization, input.tickets,
		alternateJSON, input.receiptJSON, input.recipient,
		input.fixture.source.inputs.identities.public,
		input.localKey); err == nil {
		t.Fatal("valid but causally different pair was accepted under the K root")
	}
}
