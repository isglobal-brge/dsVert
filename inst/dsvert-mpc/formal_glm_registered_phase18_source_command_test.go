package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

func formalGLMRegisteredPhase18SourceCommandTestPinsV1(
	t testing.TB, pins map[string]ed25519.PublicKey,
) map[string]string {
	t.Helper()
	encoded := make(map[string]string, len(pins))
	for peer, pin := range pins {
		encoded[peer] = base64.StdEncoding.EncodeToString(pin)
	}
	return encoded
}

func formalGLMRegisteredPhase18SourceProjectTestPinsV1(
	t testing.TB, pins map[string]ed25519.PublicKey,
) map[string]string {
	t.Helper()
	encoded := make(map[string]string, len(pins))
	for peer, pin := range pins {
		encoded[peer] = base64.RawURLEncoding.EncodeToString(pin)
	}
	return encoded
}

func formalGLMRegisteredPhase18SourceCommandTestKeyV1(
	t testing.TB, key ed25519.PrivateKey,
) string {
	t.Helper()
	if len(key) != ed25519.PrivateKeySize {
		t.Fatal("invalid test signing key")
	}
	return base64.StdEncoding.EncodeToString(key)
}

func formalGLMRegisteredPhase18SourceCommandTestRunV1(
	t testing.TB, root string,
	request formalGLMRegisteredPhase18SourceCommandV1,
) formalGLMRegisteredPhase18SourceCommandResponseV1 {
	t.Helper()
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	response, err := formalGLMRegisteredPhase18SourceCommandRunAtRootV1(
		encoded, root)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func formalGLMRegisteredPhase18SourceCommandTestRequestV1(
	t testing.TB, action, peer string,
	fixture formalGLMRegisteredPhase18SourceOutboxTestFixtureV3,
) formalGLMRegisteredPhase18SourceCommandV1 {
	t.Helper()
	contractJSON, err := json.Marshal(fixture.provenance.source.contract)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(contractJSON)
	return formalGLMRegisteredPhase18SourceCommandV1{
		Version:            formalGLMRegisteredPhase18SourceCommandVersionV1,
		Action:             action,
		SourceContractJSON: string(contractJSON),
		Pins: formalGLMRegisteredPhase18SourceCommandTestPinsV1(
			t, fixture.provenance.source.inputs.identities.public),
		LocalPeerName: peer,
		LocalSigningKey: formalGLMRegisteredPhase18SourceCommandTestKeyV1(
			t, fixture.provenance.source.inputs.identities.private[peer]),
	}
}

func TestFormalGLMRegisteredPhase18SourceCommandK2K3K5(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		for _, custodians := range []int{2, 3, 5} {
			t.Run(fmt.Sprintf("%s/K%d", family, custodians), func(t *testing.T) {
				fixture := formalGLMRegisteredPhase18SourceOutboxTestBuildFamily(
					t, custodians, family)
				plan := fixture.provenance.source.contract.Core.RegisteredExecutionPlan
				roots := make(map[string]string, len(plan.DesignatedComputePeers))
				tickets := make([]formalGLMRegisteredPhase18RecipientTicketV1,
					len(plan.DesignatedComputePeers))
				for index, peer := range plan.DesignatedComputePeers {
					roots[peer] = formalGLMRegisteredPhase18SourceOutboxTestRoot(
						t, fmt.Sprintf("recipient-%d", index))
					response := formalGLMRegisteredPhase18SourceCommandTestRunV1(
						t, roots[peer],
						formalGLMRegisteredPhase18SourceCommandTestRequestV1(
							t, formalGLMRegisteredPhase18SourceCommandActionTicketV1,
							peer, fixture))
					if response.Ticket == nil || response.Replayed ||
						response.Ticket.RecipientName != peer {
						t.Fatal("recipient ticket command returned an invalid first response")
					}
					tickets[index] = *response.Ticket
				}
				for _, peer := range plan.DesignatedComputePeers {
					request := formalGLMRegisteredPhase18SourceCommandTestRequestV1(
						t, formalGLMRegisteredPhase18SourceCommandActionTicketSetV1,
						peer, fixture)
					request.RecipientTickets = append(
						[]formalGLMRegisteredPhase18RecipientTicketV1(nil), tickets...)
					response := formalGLMRegisteredPhase18SourceCommandTestRunV1(
						t, roots[peer], request)
					if len(response.TicketReceipts) != 2 || response.Replayed {
						t.Fatal("recipient ticket set was not committed")
					}
				}

				sourceRoot := formalGLMRegisteredPhase18SourceOutboxTestRoot(
					t, "source")
				request := formalGLMRegisteredPhase18SourceCommandTestRequestV1(
					t, formalGLMRegisteredPhase18SourceCommandActionProduceV1,
					fixture.source, fixture)
				contractJSON, err := json.Marshal(fixture.provenance.source.contract)
				if err != nil {
					t.Fatal(err)
				}
				projectRequest, err := json.Marshal(
					formalGLMPhase18SourceProjectRequestV1{
						SourceContractJSON: string(contractJSON),
						Pins: formalGLMRegisteredPhase18SourceProjectTestPinsV1(
							t, fixture.provenance.source.inputs.identities.public),
						LocalPeerName: fixture.source,
					})
				clear(contractJSON)
				if err != nil {
					t.Fatal(err)
				}
				projected, err := formalGLMRunPhase18SourceProjectV1(projectRequest)
				clear(projectRequest)
				if err != nil ||
					projected.AuthorizationSHA256 != fixture.authorization.AuthorizationSHA256 {
					t.Fatalf("source authorization projection: %#v / %v", projected, err)
				}
				request.AuthorizationJSON = projected.AuthorizationJSON
				request.RecipientTickets = append(
					[]formalGLMRegisteredPhase18RecipientTicketV1(nil), tickets...)
				request.BlockIndex = fixture.blockIndex
				request.Values = append([]string(nil), fixture.values...)
				request.Validity = append([]bool(nil), fixture.validity...)
				request.PrivateConsensus = base64.StdEncoding.EncodeToString(
					fixture.consensus[:])
				produced := formalGLMRegisteredPhase18SourceCommandTestRunV1(
					t, sourceRoot, request)
				if produced.SourceReceipt == nil || produced.Replayed ||
					produced.PairJSON == "" {
					t.Fatal("source command did not produce a durable encrypted pair")
				}
				pair, err := formalGLMDecodeRegisteredPhase18BlockPairV1(
					[]byte(produced.PairJSON), fixture.provenance.source.contract,
					fixture.authorization, tickets,
					fixture.provenance.source.inputs.identities.public)
				if err != nil || pair.SourceName != fixture.source ||
					pair.BlockIndex != fixture.blockIndex {
					t.Fatal("source command returned an invalid encrypted pair")
				}
				replayed := formalGLMRegisteredPhase18SourceCommandTestRunV1(
					t, sourceRoot, request)
				if !replayed.Replayed || replayed.PairJSON != produced.PairJSON ||
					replayed.SourceReceipt.PairCommitment !=
						produced.SourceReceipt.PairCommitment {
					t.Fatal("source command did not replay its exact durable pair")
				}

				for _, peer := range plan.DesignatedComputePeers {
					importRequest := formalGLMRegisteredPhase18SourceCommandTestRequestV1(
						t, formalGLMRegisteredPhase18SourceCommandActionImportV1,
						peer, fixture)
					importRequest.RecipientTickets = append(
						[]formalGLMRegisteredPhase18RecipientTicketV1(nil), tickets...)
					importRequest.PairJSON = produced.PairJSON
					imported := formalGLMRegisteredPhase18SourceCommandTestRunV1(
						t, roots[peer], importRequest)
					if imported.PendingReceipt == nil || imported.Replayed ||
						imported.PendingReceipt.Recipient != peer ||
						imported.PendingReceipt.PairSHA256 == "" {
						t.Fatal("recipient did not commit the encrypted pair")
					}
					if peer == plan.DesignatedComputePeers[0] {
						tampered := importRequest
						pairBytes := []byte(tampered.PairJSON)
						pairBytes[len(pairBytes)-2] ^= 1
						tampered.PairJSON = string(pairBytes)
						clear(pairBytes)
						encoded, err := json.Marshal(tampered)
						if err != nil {
							t.Fatal(err)
						}
						if _, err := formalGLMRegisteredPhase18SourceCommandRunAtRootV1(
							encoded, roots[peer]); err == nil {
							t.Fatal("tampered encrypted pair was accepted")
						}
						clear(encoded)
					}
					replayImport := formalGLMRegisteredPhase18SourceCommandTestRunV1(
						t, roots[peer], importRequest)
					if !replayImport.Replayed ||
						*replayImport.PendingReceipt != *imported.PendingReceipt {
						t.Fatal("recipient import did not replay exactly")
					}
				}
			})
		}
	}
}

func TestFormalGLMRegisteredPhase18SourceCommandSealsLocalReceiptK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMRegisteredPhase18SourceOutboxTestBuild(t, custodians)
			root := formalGLMRegisteredPhase18SourceOutboxTestRoot(t, "local-receipt")
			authorizationJSON, err := json.Marshal(fixture.authorization)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(authorizationJSON)
			for blockIndex := 0; blockIndex < fixture.authorization.Geometry.TotalBlocks; blockIndex++ {
				request := formalGLMRegisteredPhase18SourceCommandTestRequestV1(
					t, formalGLMRegisteredPhase18SourceCommandActionProduceV1,
					fixture.source, fixture)
				values, validity := formalGLMRegisteredPhase18MaterializedPairTestValues(
					fixture.authorization, blockIndex)
				consensus := sha256.Sum256([]byte(fmt.Sprintf(
					"registered-phase18/source-command/local-receipt/K%d/block/%d",
					custodians, blockIndex)))
				request.AuthorizationJSON = string(authorizationJSON)
				request.RecipientTickets = append(
					[]formalGLMRegisteredPhase18RecipientTicketV1(nil), fixture.tickets...)
				request.BlockIndex = blockIndex
				request.Values = values
				request.Validity = validity
				request.PrivateConsensus = base64.StdEncoding.EncodeToString(consensus[:])
				produced := formalGLMRegisteredPhase18SourceCommandTestRunV1(t, root, request)
				if produced.SourceReceipt == nil || produced.Replayed || produced.PairJSON == "" {
					t.Fatal("source block was not durably produced")
				}
			}
			request := formalGLMRegisteredPhase18SourceCommandTestRequestV1(
				t, formalGLMRegisteredPhase18SourceCommandActionLocalReceiptV1,
				fixture.source, fixture)
			request.AuthorizationJSON = string(authorizationJSON)
			request.RecipientTickets = append(
				[]formalGLMRegisteredPhase18RecipientTicketV1(nil), fixture.tickets...)
			sealed := formalGLMRegisteredPhase18SourceCommandTestRunV1(t, root, request)
			if sealed.LocalReceiptJSON == "" || sealed.Replayed {
				t.Fatal("local receipt was not sealed")
			}
			receipt, err := formalGLMDecodeRegisteredPhase18LocalReceiptV1(
				[]byte(sealed.LocalReceiptJSON), fixture.provenance.source.contract,
				fixture.provenance.source.inputs.identities.public)
			if err != nil || receipt.SourceName != fixture.source ||
				len(receipt.BlockCommitments) != fixture.authorization.Geometry.TotalBlocks {
				t.Fatal("sealed local receipt is invalid")
			}
			replayed := formalGLMRegisteredPhase18SourceCommandTestRunV1(t, root, request)
			if !replayed.Replayed || replayed.LocalReceiptJSON != sealed.LocalReceiptJSON {
				t.Fatal("local receipt replay changed durable evidence")
			}
		})
	}
}
