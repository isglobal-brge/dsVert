package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type formalGLMRegisteredPhase18ProvenanceTestFixtureV1 struct {
	source         formalGLMSourceContractTestFixtureV1
	authorizations map[string]formalGLMRegisteredPhase18AuthorizationV1
	tickets        []formalGLMRegisteredPhase18RecipientTicketV1
	pairs          map[string][]formalGLMRegisteredPhase18BlockPairV1
	receipts       []formalGLMRegisteredPhase18LocalReceiptV1
	receiptSet     formalGLMRegisteredPhase18ReceiptSetV1
}

func formalGLMRegisteredPhase18ProvenanceTestClone[T any](t testing.TB,
	value T,
) T {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var cloned T
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func formalGLMRegisteredPhase18ProvenanceTestCiphertext(source,
	recipient string, blockIndex, recipientIndex int,
) []byte {
	prefix := []byte(fmt.Sprintf("registered-phase18/%s/%s/%d|",
		source, recipient, blockIndex))
	result := make([]byte, 512)
	copy(result, prefix)
	for index := len(prefix); index < len(result)-8; index++ {
		result[index] = byte((index + blockIndex + recipientIndex) % 251)
	}
	var exact [8]byte
	binary.BigEndian.PutUint64(exact[:],
		uint64(1)<<53+uint64(blockIndex*2+recipientIndex+1))
	copy(result[len(result)-8:], exact[:])
	return result
}

func formalGLMRegisteredPhase18ProvenanceTestCanonicalDecoder(t testing.TB,
	encoded []byte, decode func([]byte) error,
) {
	t.Helper()
	if err := decode(encoded); err != nil {
		t.Fatal(err)
	}
	unknown := append([]byte(nil), encoded[:len(encoded)-1]...)
	unknown = append(unknown, []byte(",\"unknown\":0}")...)
	for label, changed := range map[string][]byte{
		"unknown":             unknown,
		"trailing":            append(append([]byte(nil), encoded...), []byte("{}")...),
		"leading-whitespace":  append([]byte(" "), encoded...),
		"trailing-whitespace": append(append([]byte(nil), encoded...), ' '),
	} {
		if err := decode(changed); err == nil {
			t.Fatalf("canonical decoder accepted %s input", label)
		}
	}
}

func TestFormalGLMRegisteredPhase18CanonicalDecoderClosed(t *testing.T) {
	type probe struct {
		Version string `json:"version"`
	}
	decode := func(encoded []byte) error {
		decoded, err := formalGLMDecodeRegisteredPhase18CanonicalV1[probe](
			encoded, 64)
		if err == nil && decoded.Version != "v1" {
			t.Fatal("canonical provenance decoder changed its value")
		}
		return err
	}
	formalGLMRegisteredPhase18ProvenanceTestCanonicalDecoder(
		t, []byte(`{"version":"v1"}`), decode)
	if decode([]byte(`{"version":"`+strings.Repeat("x", 60)+`"}`)) == nil {
		t.Fatal("canonical provenance decoder ignored its physical bound")
	}
}

func formalGLMRegisteredPhase18ProvenanceTestBuild(t testing.TB,
	custodians int,
) formalGLMRegisteredPhase18ProvenanceTestFixtureV1 {
	return formalGLMRegisteredPhase18ProvenanceTestBuildWithCapacity(t, custodians, 9)
}

func formalGLMRegisteredPhase18ProvenanceTestBuildWithCapacity(t testing.TB,
	custodians, totalCapacity int,
) formalGLMRegisteredPhase18ProvenanceTestFixtureV1 {
	t.Helper()
	source := formalGLMRegisteredPhase18IngressTestSourceWithCapacity(
		t, custodians, totalCapacity)
	pins := source.inputs.identities.public
	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		source.contract, pins)
	if err != nil {
		t.Fatal(err)
	}
	tickets := make([]formalGLMRegisteredPhase18RecipientTicketV1, 0, 2)
	for _, recipient := range source.plan.DesignatedComputePeers {
		transportKey, err := ecdh.X25519().GenerateKey(crand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		unsigned, err := formalGLMRegisteredPhase18BuildRecipientTicketV1(
			source.contract, recipient, transportKey.PublicKey().Bytes(), pins)
		if err != nil {
			t.Fatal(err)
		}
		ticket, err := formalGLMRegisteredPhase18SignRecipientTicketV1(
			unsigned, source.contract,
			source.inputs.identities.private[recipient], pins)
		if err != nil {
			t.Fatal(err)
		}
		tickets = append(tickets, ticket)
	}

	authorizations := make(
		map[string]formalGLMRegisteredPhase18AuthorizationV1, custodians)
	pairs := make(
		map[string][]formalGLMRegisteredPhase18BlockPairV1, custodians)
	receipts := make([]formalGLMRegisteredPhase18LocalReceiptV1, 0, custodians)
	for sourceIndex, sourceName := range source.plan.CustodianPeers {
		authorization, err := formalGLMProjectRegisteredPhase18AuthorizationV1(
			source.contract, sourceName, pins)
		if err != nil {
			t.Fatal(err)
		}
		authorization.AuthorizationSHA256, err =
			formalGLMRegisteredPhase18AuthorizationSHA256V1(authorization)
		if err != nil ||
			formalGLMRegisteredPhase18ValidateAuthorizationWithContextV1(
				context, authorization) != nil {
			t.Fatal("registered Phase18 authorization fixture is invalid")
		}
		authorizations[sourceName] = authorization
		blocks := make([]formalGLMRegisteredPhase18BlockPairV1, 0,
			authorization.Geometry.TotalBlocks)
		for blockIndex := 0; blockIndex < authorization.Geometry.TotalBlocks; blockIndex++ {
			ciphertexts := make(map[string][]byte, 2)
			for recipientIndex, recipient := range authorization.DesignatedComputePeers {
				ciphertexts[recipient] =
					formalGLMRegisteredPhase18ProvenanceTestCiphertext(
						sourceName, recipient, blockIndex, recipientIndex)
			}
			ticketInput := tickets
			if (sourceIndex+blockIndex)%2 == 1 {
				ticketInput = []formalGLMRegisteredPhase18RecipientTicketV1{
					tickets[1], tickets[0],
				}
			}
			pair, err := formalGLMRegisteredPhase18BuildBlockPairWithContextV1(
				context, authorization, ticketInput, blockIndex, ciphertexts,
				source.inputs.identities.private[sourceName])
			if err != nil {
				t.Fatal(err)
			}
			if err := formalGLMRegisteredPhase18ValidateBlockPairV1(
				pair, source.contract, authorization, tickets, pins); err != nil {
				t.Fatal(err)
			}
			blocks = append(blocks, pair)
		}
		pairs[sourceName] = blocks
		blockInput := append([]formalGLMRegisteredPhase18BlockPairV1(nil),
			blocks...)
		for left, right := 0, len(blockInput)-1; left < right; left, right = left+1, right-1 {
			blockInput[left], blockInput[right] = blockInput[right], blockInput[left]
		}
		receipt, err := formalGLMRegisteredPhase18BuildLocalReceiptWithContextV1(
			context, authorization, tickets, blockInput,
			source.inputs.identities.private[sourceName])
		if err != nil {
			t.Fatal(err)
		}
		receipts = append(receipts, receipt)
	}
	receiptInput := append([]formalGLMRegisteredPhase18LocalReceiptV1(nil),
		receipts...)
	for left, right := 0, len(receiptInput)-1; left < right; left, right = left+1, right-1 {
		receiptInput[left], receiptInput[right] =
			receiptInput[right], receiptInput[left]
	}
	receiptSet, err := formalGLMRegisteredPhase18BuildReceiptSetV1(
		source.contract, receiptInput, pins)
	if err != nil {
		t.Fatal(err)
	}
	return formalGLMRegisteredPhase18ProvenanceTestFixtureV1{
		source: source, authorizations: authorizations, tickets: tickets,
		pairs: pairs, receipts: receipts, receiptSet: receiptSet,
	}
}

func TestFormalGLMRegisteredPhase18ProvenanceK2K5(t *testing.T) {
	for _, custodians := range []int{2, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMRegisteredPhase18ProvenanceTestBuild(t, custodians)
			contract := fixture.source.contract
			pins := fixture.source.inputs.identities.public
			if len(fixture.tickets) != 2 ||
				len(fixture.receiptSet.Receipts) != custodians ||
				!formalGLMIsSHA256(fixture.receiptSet.ReceiptSetSHA256) ||
				!formalGLMIsSHA256(
					fixture.receiptSet.GlobalMaterializationRootSHA256) ||
				fixture.receiptSet.OpeningsPerformed != 0 ||
				fixture.receiptSet.ProductionReady {
				t.Fatal("registered Phase18 provenance set is incomplete")
			}
			for _, ticket := range fixture.tickets {
				raw := sha256.Sum256(ticket.TransportPK)
				if ticket.TransportPKSHA256 == hex.EncodeToString(raw[:]) {
					t.Fatal("transport public key hash is not domain-separated")
				}
			}
			for _, sourceName := range fixture.source.plan.CustodianPeers {
				authorization := fixture.authorizations[sourceName]
				blocks := fixture.pairs[sourceName]
				if authorization.Geometry.TotalCapacity != 9 ||
					authorization.Geometry.BlockCapacity != 4 || len(blocks) != 3 {
					t.Fatal("registered Phase18 fixed geometry changed")
				}
				for blockIndex, pair := range blocks {
					if pair.BlockIndex != blockIndex || pair.SlotsInBlock != 4 ||
						pair.GlobalSlotOffset != blockIndex*4 ||
						len(pair.Envelopes) != 2 ||
						!reflect.DeepEqual(pair.Recipients,
							authorization.DesignatedComputePeers) ||
						pair.OpeningsPerformed != 0 || pair.ProductionReady {
						t.Fatal("registered Phase18 block pair is not canonical")
					}
					for recipientIndex, envelope := range pair.Envelopes {
						wantCiphertext :=
							formalGLMRegisteredPhase18ProvenanceTestCiphertext(
								sourceName, pair.Recipients[recipientIndex],
								blockIndex, recipientIndex)
						if !reflect.DeepEqual(envelope.Ciphertext, wantCiphertext) ||
							envelope.OpeningsPerformed != 0 ||
							envelope.ProductionReady {
							t.Fatal("opaque ciphertext changed before the global root")
						}
					}
				}
			}
			for _, value := range []any{
				fixture.tickets, fixture.pairs, fixture.receipts,
			} {
				encoded, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				text := string(encoded)
				for _, forbidden := range []string{
					`"capsule_id":`, `"run_id":`, `"analysis_id":`,
					`"path":`, `"ttl":`,
					`"global_materialization_root_sha256":`,
				} {
					if strings.Contains(text, forbidden) {
						t.Fatalf("pre-root provenance leaked %q", forbidden)
					}
				}
			}
			encoded, err := json.Marshal(fixture.receiptSet)
			if err != nil {
				t.Fatal(err)
			}
			formalGLMRegisteredPhase18ProvenanceTestCanonicalDecoder(
				t, encoded, func(value []byte) error {
					decoded, decodeErr :=
						formalGLMDecodeRegisteredPhase18ReceiptSetV1(
							value, contract, pins)
					if decodeErr == nil && !reflect.DeepEqual(
						decoded, fixture.receiptSet) {
						t.Fatal("decoded receipt set changed")
					}
					return decodeErr
				})
			firstSource := fixture.source.plan.CustodianPeers[0]
			for _, decoder := range []struct {
				value any
				call  func([]byte) error
			}{
				{fixture.tickets[0], func(value []byte) error {
					_, decodeErr := formalGLMDecodeRegisteredPhase18RecipientTicketV1(
						value, contract, pins)
					return decodeErr
				}},
				{fixture.pairs[firstSource][0], func(value []byte) error {
					_, decodeErr := formalGLMDecodeRegisteredPhase18BlockPairV1(
						value, contract, fixture.authorizations[firstSource],
						fixture.tickets, pins)
					return decodeErr
				}},
				{fixture.receipts[0], func(value []byte) error {
					_, decodeErr := formalGLMDecodeRegisteredPhase18LocalReceiptV1(
						value, contract, pins)
					return decodeErr
				}},
			} {
				value, marshalErr := json.Marshal(decoder.value)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				formalGLMRegisteredPhase18ProvenanceTestCanonicalDecoder(
					t, value, decoder.call)
			}
		})
	}
}

func TestFormalGLMRegisteredPhase18ProvenanceRejectsTamperAndMix(t *testing.T) {
	for _, custodians := range []int{2, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMRegisteredPhase18ProvenanceTestBuild(t, custodians)
			contract := fixture.source.contract
			pins := fixture.source.inputs.identities.public
			context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
				contract, pins)
			if err != nil {
				t.Fatal(err)
			}
			peers := fixture.source.plan.CustodianPeers
			designated := fixture.source.plan.DesignatedComputePeers

			unsigned, err := formalGLMRegisteredPhase18BuildRecipientTicketV1(
				contract, designated[0], make([]byte, 32), pins)
			if err == nil || !reflect.DeepEqual(
				unsigned, formalGLMRegisteredPhase18RecipientTicketV1{}) {
				t.Fatal("invalid X25519 transport public key was accepted")
			}
			unsigned = formalGLMRegisteredPhase18ProvenanceTestClone(
				t, fixture.tickets[0])
			unsigned.Signature = nil
			if _, err := formalGLMRegisteredPhase18SignRecipientTicketV1(
				unsigned, contract,
				fixture.source.inputs.identities.private[designated[1]], pins); err == nil {
				t.Fatal("recipient ticket accepted the wrong pinned signer")
			}
			ticket := formalGLMRegisteredPhase18ProvenanceTestClone(
				t, fixture.tickets[0])
			ticket.TransportPK[0] ^= 1
			if formalGLMRegisteredPhase18ValidateRecipientTicketWithContextV1(
				context, ticket) == nil {
				t.Fatal("tampered recipient transport key was accepted")
			}
			ticket = formalGLMRegisteredPhase18ProvenanceTestClone(
				t, fixture.tickets[0])
			ticket.Signature[0] ^= 1
			if formalGLMRegisteredPhase18ValidateRecipientTicketWithContextV1(
				context, ticket) == nil {
				t.Fatal("tampered recipient ticket signature was accepted")
			}

			sourceName := peers[0]
			authorization := fixture.authorizations[sourceName]
			pair := formalGLMRegisteredPhase18ProvenanceTestClone(
				t, fixture.pairs[sourceName][0])
			pair.Envelopes[0], pair.Envelopes[1] =
				pair.Envelopes[1], pair.Envelopes[0]
			if formalGLMRegisteredPhase18ValidateBlockPairWithContextV1(
				context, pair, authorization, fixture.tickets) == nil {
				t.Fatal("reordered source envelopes were accepted")
			}
			pair = formalGLMRegisteredPhase18ProvenanceTestClone(
				t, fixture.pairs[sourceName][0])
			pair.Envelopes = pair.Envelopes[:1]
			if formalGLMRegisteredPhase18ValidateBlockPairWithContextV1(
				context, pair, authorization, fixture.tickets) == nil {
				t.Fatal("missing source envelope was accepted")
			}
			pair = formalGLMRegisteredPhase18ProvenanceTestClone(
				t, fixture.pairs[sourceName][0])
			pair.Envelopes[0].Ciphertext[0] ^= 1
			if formalGLMRegisteredPhase18ValidateBlockPairWithContextV1(
				context, pair, authorization, fixture.tickets) == nil {
				t.Fatal("tampered source ciphertext was accepted")
			}
			pair = formalGLMRegisteredPhase18ProvenanceTestClone(
				t, fixture.pairs[sourceName][0])
			pair.BlockCommitmentSHA256 = strings.Repeat("a", 64)
			if formalGLMRegisteredPhase18ValidateBlockPairWithContextV1(
				context, pair, authorization, fixture.tickets) == nil {
				t.Fatal("tampered block commitment was accepted")
			}
			pair = formalGLMRegisteredPhase18ProvenanceTestClone(
				t, fixture.pairs[sourceName][0])
			pair.Envelopes[0].Signature[0] ^= 1
			if formalGLMRegisteredPhase18ValidateBlockPairWithContextV1(
				context, pair, authorization, fixture.tickets) == nil {
				t.Fatal("tampered source envelope signature was accepted")
			}
			if formalGLMRegisteredPhase18ValidateBlockPairWithContextV1(
				context, fixture.pairs[sourceName][0], authorization,
				fixture.tickets[:1]) == nil {
				t.Fatal("missing recipient ticket was accepted")
			}
			pair = formalGLMRegisteredPhase18ProvenanceTestClone(
				t, fixture.pairs[sourceName][0])
			pair.ArtifactID = strings.Repeat("0", 64)
			if formalGLMRegisteredPhase18ValidateBlockPairWithContextV1(
				context, pair, authorization, fixture.tickets) == nil {
				t.Fatal("cross-artifact source pair was accepted")
			}
			if len(peers) > 1 {
				otherAuthorization := fixture.authorizations[peers[1]]
				if formalGLMRegisteredPhase18ValidateBlockPairWithContextV1(
					context, fixture.pairs[sourceName][0], otherAuthorization,
					fixture.tickets) == nil {
					t.Fatal("mixed source authorization was accepted")
				}
			}

			receipt := formalGLMRegisteredPhase18ProvenanceTestClone(
				t, fixture.receipts[0])
			receipt.BlockCommitments[0], receipt.BlockCommitments[1] =
				receipt.BlockCommitments[1], receipt.BlockCommitments[0]
			if formalGLMRegisteredPhase18ValidateLocalReceiptWithContextV1(
				context, receipt) == nil {
				t.Fatal("reordered local block commitments were accepted")
			}
			receipt = formalGLMRegisteredPhase18ProvenanceTestClone(
				t, fixture.receipts[0])
			receipt.BlockCommitments = receipt.BlockCommitments[:2]
			if formalGLMRegisteredPhase18ValidateLocalReceiptWithContextV1(
				context, receipt) == nil {
				t.Fatal("incomplete local receipt was accepted")
			}
			receipt = formalGLMRegisteredPhase18ProvenanceTestClone(
				t, fixture.receipts[0])
			receipt.Signature[0] ^= 1
			if formalGLMRegisteredPhase18ValidateLocalReceiptWithContextV1(
				context, receipt) == nil {
				t.Fatal("tampered local receipt signature was accepted")
			}

			set := formalGLMRegisteredPhase18ProvenanceTestClone(
				t, fixture.receiptSet)
			set.Receipts[0], set.Receipts[1] = set.Receipts[1], set.Receipts[0]
			if formalGLMRegisteredPhase18ValidateReceiptSetWithContextV1(
				context, set) == nil {
				t.Fatal("reordered K receipt set was accepted")
			}
			set = formalGLMRegisteredPhase18ProvenanceTestClone(
				t, fixture.receiptSet)
			set.Receipts = set.Receipts[:len(set.Receipts)-1]
			if formalGLMRegisteredPhase18ValidateReceiptSetWithContextV1(
				context, set) == nil {
				t.Fatal("missing K receipt was accepted")
			}
			set = formalGLMRegisteredPhase18ProvenanceTestClone(
				t, fixture.receiptSet)
			set.GlobalMaterializationRootSHA256 = strings.Repeat("f", 64)
			if formalGLMRegisteredPhase18ValidateReceiptSetWithContextV1(
				context, set) == nil {
				t.Fatal("tampered global materialization root was accepted")
			}
			wrongPins := make(map[string]ed25519.PublicKey, len(pins))
			for name, pin := range pins {
				wrongPins[name] = append([]byte(nil), pin...)
			}
			wrongPins[sourceName][0] ^= 1
			if formalGLMRegisteredPhase18ValidateReceiptSetV1(
				fixture.receiptSet, contract, wrongPins) == nil {
				t.Fatal("receipt set accepted a mismatched pinset")
			}
		})
	}
}
