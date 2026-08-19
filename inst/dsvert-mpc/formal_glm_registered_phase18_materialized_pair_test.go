package main

import (
	"bytes"
	"crypto/ecdh"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

type formalGLMRegisteredPhase18MaterializedPairTestFixtureV3 struct {
	provenance    formalGLMRegisteredPhase18ProvenanceTestFixtureV1
	authorization formalGLMRegisteredPhase18AuthorizationV1
	source        string
	tickets       []formalGLMRegisteredPhase18RecipientTicketV1
	recipientSK   map[string][]byte
	pairs         []formalGLMRegisteredPhase18BlockPairV1
	receiptSet    formalGLMRegisteredPhase18ReceiptSetV1
	values        [][]string
	validity      [][]bool
	consensus     [][32]byte
}

func formalGLMRegisteredPhase18MaterializedPairTestValues(
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	blockIndex int,
) ([]string, []bool) {
	geometry := authorization.Geometry
	values := make([]string, geometry.BlockCapacity*geometry.CoordinateCount)
	for index := range values {
		values[index] = "0"
	}
	validity := make([]bool, geometry.BlockCapacity)
	offset := blockIndex * geometry.BlockCapacity
	for row := 0; row < geometry.BlockCapacity; row++ {
		if offset+row >= geometry.TotalCapacity {
			continue
		}
		validity[row] = true
		for coordinate, owner := range geometry.CoordinateOwners {
			if owner == authorization.LocalSource.SignerPeerName {
				values[row*geometry.CoordinateCount+coordinate] =
					fmt.Sprintf("%d", (offset+row+1)*(coordinate+2))
			}
		}
	}
	if blockIndex == geometry.TotalBlocks-1 {
		owned := make([]int, 0, geometry.CoordinateCount)
		for coordinate, owner := range geometry.CoordinateOwners {
			if owner == authorization.LocalSource.SignerPeerName {
				owned = append(owned, coordinate)
			}
		}
		if len(owned) > 0 {
			values[owned[0]] = "9007199254740993"
		}
		if len(owned) > 1 {
			values[owned[1]] = "-9007199254740995"
		}
	}
	return values, validity
}

func formalGLMRegisteredPhase18MaterializedPairTestBuild(t testing.TB,
	custodians int,
) formalGLMRegisteredPhase18MaterializedPairTestFixtureV3 {
	t.Helper()
	provenance := formalGLMRegisteredPhase18ProvenanceTestBuild(t, custodians)
	source := provenance.source.plan.CustodianPeers[0]
	if custodians == 5 {
		for _, peer := range provenance.source.plan.CustodianPeers {
			if len(provenance.authorizations[peer].LocalColumns) == 0 {
				source = peer
				break
			}
		}
	}
	authorization := provenance.authorizations[source]
	pins := provenance.source.inputs.identities.public
	tickets := make([]formalGLMRegisteredPhase18RecipientTicketV1, 0, 2)
	recipientSK := make(map[string][]byte, 2)
	for _, recipient := range authorization.DesignatedComputePeers {
		transportKey, err := ecdh.X25519().GenerateKey(crand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		unsigned, err := formalGLMRegisteredPhase18BuildRecipientTicketV1(
			provenance.source.contract, recipient,
			transportKey.PublicKey().Bytes(), pins)
		if err != nil {
			t.Fatal(err)
		}
		ticket, err := formalGLMRegisteredPhase18SignRecipientTicketV1(
			unsigned, provenance.source.contract,
			provenance.source.inputs.identities.private[recipient], pins)
		if err != nil {
			t.Fatal(err)
		}
		tickets = append(tickets, ticket)
		recipientSK[recipient] = append([]byte(nil), transportKey.Bytes()...)
	}
	pairs := make([]formalGLMRegisteredPhase18BlockPairV1,
		authorization.Geometry.TotalBlocks)
	values := make([][]string, len(pairs))
	validity := make([][]bool, len(pairs))
	consensus := make([][32]byte, len(pairs))
	for blockIndex := range pairs {
		values[blockIndex], validity[blockIndex] =
			formalGLMRegisteredPhase18MaterializedPairTestValues(
				authorization, blockIndex)
		consensus[blockIndex] = sha256.Sum256([]byte(fmt.Sprintf(
			"registered-materialized-pair/K%d/block/%d", custodians, blockIndex)))
		var err error
		pairs[blockIndex], err =
			formalGLMRegisteredPhase18BuildMaterializedBlockPairV3(
				provenance.source.contract, authorization, tickets, blockIndex,
				values[blockIndex], validity[blockIndex], consensus[blockIndex][:],
				provenance.source.inputs.identities.private[source], pins)
		if err != nil {
			t.Fatal(err)
		}
	}
	localReceipt, err := formalGLMRegisteredPhase18BuildLocalReceiptV1(
		provenance.source.contract, authorization, tickets, pairs,
		provenance.source.inputs.identities.private[source], pins)
	if err != nil {
		t.Fatal(err)
	}
	receipts := formalGLMRegisteredPhase18ProvenanceTestClone(
		t, provenance.receiptSet.Receipts)
	replaced := false
	for index := range receipts {
		if receipts[index].SourceName == source {
			receipts[index] = localReceipt
			replaced = true
		}
	}
	if !replaced {
		t.Fatal("source receipt was not present in the K set")
	}
	receiptSet, err := formalGLMRegisteredPhase18BuildReceiptSetV1(
		provenance.source.contract, receipts, pins)
	if err != nil {
		t.Fatal(err)
	}
	return formalGLMRegisteredPhase18MaterializedPairTestFixtureV3{
		provenance: provenance, authorization: authorization, source: source,
		tickets: tickets, recipientSK: recipientSK, pairs: pairs,
		receiptSet: receiptSet, values: values, validity: validity,
		consensus: consensus,
	}
}

func formalGLMRegisteredPhase18MaterializedPairTestJSON(t testing.TB,
	value any,
) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestFormalGLMRegisteredPhase18MaterializedBlockPairV3K2K5(
	t *testing.T,
) {
	for _, custodians := range []int{2, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMRegisteredPhase18MaterializedPairTestBuild(
				t, custodians)
			blockIndex := fixture.authorization.Geometry.TotalBlocks - 1
			pair := fixture.pairs[blockIndex]
			if pair.GlobalSlotOffset != 8 || pair.SlotsInBlock != 4 ||
				fixture.authorization.Geometry.TotalCapacity != 9 ||
				fixture.validity[blockIndex][0] != true ||
				fixture.validity[blockIndex][1] ||
				fixture.validity[blockIndex][2] ||
				fixture.validity[blockIndex][3] {
				t.Fatal("fixture is not the 9/4 fixed padded final block")
			}
			if custodians == 5 && len(fixture.authorization.LocalColumns) != 0 {
				t.Fatal("K5 source is not an alignment-only witness")
			}
			ticketJSON := make([][]byte, len(fixture.tickets))
			for index := range fixture.tickets {
				ticketJSON[index] =
					formalGLMRegisteredPhase18MaterializedPairTestJSON(
						t, fixture.tickets[index])
			}
			pairJSON := formalGLMRegisteredPhase18MaterializedPairTestJSON(t, pair)
			receiptJSON := formalGLMRegisteredPhase18MaterializedPairTestJSON(
				t, fixture.receiptSet)
			coordinateShares := make([][]*big.Int, 2)
			validityShares := make([][]byte, 2)
			consensusShares := make([][]byte, 2)
			gateShares := make([]byte, 2)
			for recipientIndex, recipient := range fixture.authorization.DesignatedComputePeers {
				localKey := sha256.Sum256([]byte(
					"materialized-pair/local-key/" + recipient))
				encoded, err := formalGLMRegisteredPhase18ComposeIngressFrameV3(
					fixture.provenance.source.contract, fixture.authorization,
					ticketJSON, pairJSON, receiptJSON, recipient,
					fixture.provenance.source.inputs.identities.public, localKey)
				if err != nil {
					t.Fatal(err)
				}
				frame, err := formalGLMRegisteredPhase18DecodeIngressFrameV3(
					encoded, fixture.provenance.source.contract,
					fixture.authorization,
					fixture.receiptSet.GlobalMaterializationRootSHA256,
					fixture.provenance.source.inputs.identities.public, localKey)
				if err != nil {
					t.Fatal(err)
				}
				plaintext, err := transportDecryptBytes(
					frame.Ciphertext, fixture.recipientSK[recipient])
				if err != nil {
					t.Fatal(err)
				}
				header, coordinates, validity, err :=
					formalGLMRegisteredPhase18DecodePrivateBlockV3(
						plaintext, frame, fixture.provenance.source.contract,
						fixture.authorization,
						fixture.receiptSet.GlobalMaterializationRootSHA256,
						fixture.provenance.source.inputs.identities.public)
				if err != nil {
					t.Fatal(err)
				}
				coordinateShares[recipientIndex] = coordinates
				validityShares[recipientIndex] = validity
				consensusShares[recipientIndex], err =
					base64.RawURLEncoding.Strict().DecodeString(
						header.PrivateAlignmentConsensusShare)
				if err != nil {
					t.Fatal(err)
				}
				gateShares[recipientIndex] =
					byte(header.PrivateAlignmentGateShare)
			}
			modulus := exactGCModulus(fixture.authorization.Geometry.RingBits)
			half := new(big.Int).Rsh(new(big.Int).Set(modulus), 1)
			for index, want := range fixture.values[blockIndex] {
				got := new(big.Int).Add(
					coordinateShares[0][index], coordinateShares[1][index])
				got.Mod(got, modulus)
				if got.Cmp(half) >= 0 {
					got.Sub(got, modulus)
				}
				if got.String() != want {
					t.Fatalf("coordinate %d reconstructed %s, want %s",
						index, got, want)
				}
			}
			for index, want := range fixture.validity[blockIndex] {
				got := validityShares[0][index] ^ validityShares[1][index]
				if (got == 1) != want {
					t.Fatalf("validity %d reconstructed %d, want %v",
						index, got, want)
				}
			}
			consensus := make([]byte, 32)
			for index := range consensus {
				consensus[index] =
					consensusShares[0][index] ^ consensusShares[1][index]
			}
			if !bytes.Equal(consensus, fixture.consensus[blockIndex][:]) ||
				gateShares[0]^gateShares[1] != 1 {
				t.Fatal("private consensus or accepted gate did not reconstruct")
			}
			if custodians == 2 &&
				!strings.Contains(strings.Join(fixture.values[blockIndex], ","),
					"9007199254740993") {
				t.Fatal("K2 fixture did not preserve a value above 2^53")
			}
		})
	}
}

func TestFormalGLMRegisteredPhase18MaterializedBlockPairV3RejectsInvalid(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase18MaterializedPairTestBuild(t, 2)
	blockIndex := fixture.authorization.Geometry.TotalBlocks - 1
	values := fixture.values[blockIndex]
	validity := fixture.validity[blockIndex]
	consensus := fixture.consensus[blockIndex][:]
	pins := fixture.provenance.source.inputs.identities.public
	sourceKey := fixture.provenance.source.inputs.identities.private[fixture.source]

	call := func(changedValues []string, changedValidity []bool,
		changedConsensus []byte,
		changedTickets []formalGLMRegisteredPhase18RecipientTicketV1,
		changedKey []byte,
	) error {
		_, err := formalGLMRegisteredPhase18BuildMaterializedBlockPairV3(
			fixture.provenance.source.contract, fixture.authorization,
			changedTickets, blockIndex, changedValues, changedValidity,
			changedConsensus, changedKey, pins)
		return err
	}
	clonedValues := func() []string { return append([]string(nil), values...) }
	clonedValidity := func() []bool { return append([]bool(nil), validity...) }
	clonedTickets := func() []formalGLMRegisteredPhase18RecipientTicketV1 {
		return formalGLMRegisteredPhase18ProvenanceTestClone(t, fixture.tickets)
	}

	if err := call(values[:len(values)-1], validity, consensus,
		fixture.tickets, sourceKey); err == nil {
		t.Fatal("short fixed-shape values were accepted")
	}
	if err := call(values, validity[:len(validity)-1], consensus,
		fixture.tickets, sourceKey); err == nil {
		t.Fatal("short fixed-shape validity was accepted")
	}
	if err := call(values, validity, consensus[:31],
		fixture.tickets, sourceKey); err == nil {
		t.Fatal("non-32-byte private consensus was accepted")
	}
	changed := clonedValues()
	changed[0] = new(big.Int).Lsh(
		big.NewInt(1), uint(fixture.authorization.Geometry.RingBits-1)).String()
	if err := call(changed, validity, consensus, fixture.tickets,
		sourceKey); err == nil {
		t.Fatal("value outside signed Ring was accepted")
	}
	changed = clonedValues()
	changed[0] = "01"
	if err := call(changed, validity, consensus, fixture.tickets,
		sourceKey); err == nil {
		t.Fatal("non-canonical signed decimal was accepted")
	}
	unowned := -1
	for index, owner := range fixture.authorization.Geometry.CoordinateOwners {
		if owner != fixture.source {
			unowned = index
			break
		}
	}
	if unowned < 0 {
		t.Fatal("fixture has no unowned coordinate")
	}
	changed = clonedValues()
	changed[unowned] = "1"
	if err := call(changed, validity, consensus, fixture.tickets,
		sourceKey); err == nil {
		t.Fatal("nonzero unowned coordinate was accepted")
	}
	changed = clonedValues()
	changed[fixture.authorization.Geometry.CoordinateCount] = "1"
	if err := call(changed, validity, consensus, fixture.tickets,
		sourceKey); err == nil {
		t.Fatal("nonzero final padding was accepted")
	}
	changedValidity := clonedValidity()
	changedValidity[1] = true
	if err := call(values, changedValidity, consensus, fixture.tickets,
		sourceKey); err == nil {
		t.Fatal("valid final padding was accepted")
	}
	tamperedTickets := clonedTickets()
	tamperedTickets[0].Signature[0] ^= 1
	if err := call(values, validity, consensus, tamperedTickets,
		sourceKey); err == nil {
		t.Fatal("tampered recipient ticket was accepted")
	}
	if err := call(values, validity, consensus, fixture.tickets[:1],
		sourceKey); err == nil {
		t.Fatal("missing recipient ticket was accepted")
	}
	other := fixture.provenance.source.plan.CustodianPeers[1]
	if err := call(values, validity, consensus, fixture.tickets,
		fixture.provenance.source.inputs.identities.private[other]); err == nil {
		t.Fatal("wrong source signing key was accepted")
	}
	if reflect.DeepEqual(fixture.pairs[blockIndex].Envelopes[0].Ciphertext,
		fixture.pairs[blockIndex].Envelopes[1].Ciphertext) {
		t.Fatal("recipient ciphertexts unexpectedly coincide")
	}
}
