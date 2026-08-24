package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

func TestFormalGLMRegisteredPhase18SourceCommandSamplerAuthorityRootCanonical(t *testing.T) {
	root := sha256.Sum256([]byte("formal-glm registered sampler authority root"))
	encoded := base64.StdEncoding.EncodeToString(root[:])
	decoded, err := formalGLMRegisteredPhase18SourceCommandDecodeSamplerAuthorityRootV1(encoded)
	if err != nil || decoded != root {
		t.Fatalf("canonical sampler authority root changed: %x / %v", decoded, err)
	}
	if _, err := formalGLMRegisteredPhase18SourceCommandDecodeSamplerAuthorityRootV1(
		"not-canonical-base64"); err == nil {
		t.Fatal("source command accepted a malformed sampler authority root")
	}
}

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

func TestFormalGLMRegisteredPhase18SourceCommandReadsBoundedChunk(t *testing.T) {
	fixture := formalGLMRegisteredPhase18SourceOutboxTestBuild(t, 2)
	root := formalGLMRegisteredPhase18SourceOutboxTestRoot(t, "source-command-chunk")
	authorizationJSON, err := json.Marshal(fixture.authorization)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(authorizationJSON)
	produce := formalGLMRegisteredPhase18SourceCommandTestRequestV1(
		t, formalGLMRegisteredPhase18SourceCommandActionProduceV1, fixture.source, fixture)
	produce.AuthorizationJSON = string(authorizationJSON)
	produce.RecipientTickets = append([]formalGLMRegisteredPhase18RecipientTicketV1(nil), fixture.tickets...)
	produce.BlockIndex = fixture.blockIndex
	produce.Values = append([]string(nil), fixture.values...)
	produce.Validity = append([]bool(nil), fixture.validity...)
	produce.PrivateConsensus = base64.StdEncoding.EncodeToString(fixture.consensus[:])
	produced := formalGLMRegisteredPhase18SourceCommandTestRunV1(t, root, produce)
	if produced.SourceReceipt == nil || produced.PairJSON == "" {
		t.Fatal("source did not produce a durable pair")
	}

	chunk := formalGLMRegisteredPhase18SourceCommandTestRequestV1(
		t, formalGLMRegisteredPhase18SourceCommandActionChunkV1, fixture.source, fixture)
	chunk.AuthorizationJSON = string(authorizationJSON)
	chunk.RecipientTickets = append([]formalGLMRegisteredPhase18RecipientTicketV1(nil), fixture.tickets...)
	chunk.BlockIndex = fixture.blockIndex
	response := formalGLMRegisteredPhase18SourceCommandTestRunV1(t, root, chunk)
	if response.ChunkReceipt == nil || response.PairChunkBase64 == "" ||
		response.PairJSON != "" || response.Replayed ||
		response.ChunkReceipt.PairBytes != len(produced.PairJSON) ||
		response.ChunkReceipt.Offset != 0 || response.ChunkReceipt.ChunkBytes >
		formalGLMRegisteredPhase18SourceOutboxChunkMaxV3 {
		t.Fatalf("invalid bounded source chunk response: %#v", response)
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(response.PairChunkBase64)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != response.PairChunkBase64 ||
		!bytes.Equal(decoded, []byte(produced.PairJSON)) {
		clear(decoded)
		t.Fatal("source command chunk differs from durable pair")
	}
	clear(decoded)
	chunk.ChunkOffset = int64(len(produced.PairJSON))
	encoded, err := json.Marshal(chunk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := formalGLMRegisteredPhase18SourceCommandRunAtRootV1(encoded, root); err == nil {
		clear(encoded)
		t.Fatal("source command accepted an out-of-range chunk")
	}
	clear(encoded)
}

func TestFormalGLMRegisteredPhase18SourceCommandSealsBlockWithoutPairReply(t *testing.T) {
	fixture := formalGLMRegisteredPhase18SourceOutboxTestBuild(t, 2)
	root := formalGLMRegisteredPhase18SourceOutboxTestRoot(t, "source-command-seal")
	authorizationJSON, err := json.Marshal(fixture.authorization)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(authorizationJSON)
	request := formalGLMRegisteredPhase18SourceCommandTestRequestV1(
		t, formalGLMRegisteredPhase18SourceCommandActionSealBlockV1, fixture.source, fixture)
	request.AuthorizationJSON = string(authorizationJSON)
	request.RecipientTickets = append([]formalGLMRegisteredPhase18RecipientTicketV1(nil), fixture.tickets...)
	request.BlockIndex = fixture.blockIndex
	request.Values = append([]string(nil), fixture.values...)
	request.Validity = append([]bool(nil), fixture.validity...)
	request.PrivateConsensus = base64.StdEncoding.EncodeToString(fixture.consensus[:])
	sealed := formalGLMRegisteredPhase18SourceCommandTestRunV1(t, root, request)
	if sealed.SourceReceipt == nil || sealed.PairJSON != "" || sealed.Replayed {
		t.Fatalf("seal response exposed a pair or omitted durable evidence: %#v", sealed)
	}
	chunk := formalGLMRegisteredPhase18SourceCommandTestRequestV1(
		t, formalGLMRegisteredPhase18SourceCommandActionChunkV1, fixture.source, fixture)
	chunk.AuthorizationJSON = string(authorizationJSON)
	chunk.RecipientTickets = append([]formalGLMRegisteredPhase18RecipientTicketV1(nil), fixture.tickets...)
	chunk.BlockIndex = fixture.blockIndex
	read := formalGLMRegisteredPhase18SourceCommandTestRunV1(t, root, chunk)
	if read.ChunkReceipt == nil || read.PairChunkBase64 == "" ||
		read.ChunkReceipt.PairSHA256 == "" {
		t.Fatalf("sealed pair was not available only as a bounded chunk: %#v", read)
	}
}

func TestFormalGLMRegisteredPhase18SourceCommandImportsBoundedChunk(t *testing.T) {
	fixture := formalGLMRegisteredPhase18SourceOutboxTestBuild(t, 2)
	authorizationJSON, err := json.Marshal(fixture.authorization)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(authorizationJSON)
	sourceRoot := formalGLMRegisteredPhase18SourceOutboxTestRoot(t, "source-command-chunk-import-source")
	produce := formalGLMRegisteredPhase18SourceCommandTestRequestV1(
		t, formalGLMRegisteredPhase18SourceCommandActionProduceV1, fixture.source, fixture)
	produce.AuthorizationJSON = string(authorizationJSON)
	produce.RecipientTickets = append([]formalGLMRegisteredPhase18RecipientTicketV1(nil), fixture.tickets...)
	produce.BlockIndex = fixture.blockIndex
	produce.Values = append([]string(nil), fixture.values...)
	produce.Validity = append([]bool(nil), fixture.validity...)
	produce.PrivateConsensus = base64.StdEncoding.EncodeToString(fixture.consensus[:])
	_ = formalGLMRegisteredPhase18SourceCommandTestRunV1(t, sourceRoot, produce)
	chunkRequest := formalGLMRegisteredPhase18SourceCommandTestRequestV1(
		t, formalGLMRegisteredPhase18SourceCommandActionChunkV1, fixture.source, fixture)
	chunkRequest.AuthorizationJSON = string(authorizationJSON)
	chunkRequest.RecipientTickets = append([]formalGLMRegisteredPhase18RecipientTicketV1(nil), fixture.tickets...)
	chunkRequest.BlockIndex = fixture.blockIndex
	chunk := formalGLMRegisteredPhase18SourceCommandTestRunV1(t, sourceRoot, chunkRequest)
	if chunk.ChunkReceipt == nil || chunk.PairChunkBase64 == "" {
		t.Fatal("source did not return a bounded pair frame")
	}

	recipient := fixture.provenance.source.plan.DesignatedComputePeers[0]
	recipientRoot := formalGLMRegisteredPhase18SourceOutboxTestRoot(t, "source-command-chunk-import-recipient")
	tickets, err := newFormalGLMRegisteredPhase18RecipientTicketStoreV1(
		recipientRoot, fixture.provenance.source.contract, fixture.provenance.source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	for _, ticket := range fixture.tickets {
		if _, _, err := tickets.Commit(ticket); err != nil {
			tickets.Close()
			t.Fatal(err)
		}
	}
	tickets.Close()
	importRequest := formalGLMRegisteredPhase18SourceCommandTestRequestV1(
		t, formalGLMRegisteredPhase18SourceCommandActionImportChunkV1, recipient, fixture)
	importRequest.RecipientTickets = append([]formalGLMRegisteredPhase18RecipientTicketV1(nil), fixture.tickets...)
	importRequest.ChunkReceipt = chunk.ChunkReceipt
	importRequest.PairChunkBase64 = chunk.PairChunkBase64
	imported := formalGLMRegisteredPhase18SourceCommandTestRunV1(t, recipientRoot, importRequest)
	if imported.ChunkDelivery == nil || !imported.ChunkDelivery.Complete ||
		imported.ChunkDelivery.PendingReceipt == nil || imported.Replayed {
		t.Fatalf("recipient did not complete bounded pair import: %#v", imported)
	}
	replayed := formalGLMRegisteredPhase18SourceCommandTestRunV1(t, recipientRoot, importRequest)
	if replayed.ChunkDelivery == nil || !replayed.ChunkDelivery.Complete ||
		!replayed.Replayed || !replayed.ChunkDelivery.Replayed {
		t.Fatalf("recipient did not replay bounded pair import: %#v", replayed)
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

func TestFormalGLMRegisteredPhase18SourceCommandAssemblesReceiptSetK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMRegisteredPhase18ProvenanceTestBuild(t, custodians)
			peer := fixture.source.plan.DesignatedComputePeers[0]
			root := formalGLMRegisteredPhase18SourceOutboxTestRoot(t, "receipt-set")
			contractJSON, err := json.Marshal(fixture.source.contract)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(contractJSON)
			request := formalGLMRegisteredPhase18SourceCommandV1{
				Version:            formalGLMRegisteredPhase18SourceCommandVersionV1,
				Action:             formalGLMRegisteredPhase18SourceCommandActionReceiptCommitV1,
				SourceContractJSON: string(contractJSON),
				Pins: formalGLMRegisteredPhase18SourceCommandTestPinsV1(
					t, fixture.source.inputs.identities.public),
				LocalPeerName: peer,
				LocalSigningKey: formalGLMRegisteredPhase18SourceCommandTestKeyV1(
					t, fixture.source.inputs.identities.private[peer]),
			}
			for _, receipt := range fixture.receipts {
				receiptJSON, marshalErr := json.Marshal(receipt)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				request.LocalReceiptJSON = string(receiptJSON)
				clear(receiptJSON)
				committed := formalGLMRegisteredPhase18SourceCommandTestRunV1(t, root, request)
				if committed.LocalReceiptJSON != request.LocalReceiptJSON || committed.Replayed {
					t.Fatal("local receipt command did not persist exact evidence")
				}
			}
			request.Action = formalGLMRegisteredPhase18SourceCommandActionReceiptSetV1
			request.LocalReceiptJSON = ""
			sealed := formalGLMRegisteredPhase18SourceCommandTestRunV1(t, root, request)
			if sealed.ReceiptSetJSON == "" || sealed.Replayed {
				t.Fatal("receipt-set command did not seal K evidence")
			}
			set, err := formalGLMDecodeRegisteredPhase18ReceiptSetV1(
				[]byte(sealed.ReceiptSetJSON), fixture.source.contract,
				fixture.source.inputs.identities.public)
			if err != nil || set.ReceiptSetSHA256 != fixture.receiptSet.ReceiptSetSHA256 ||
				len(set.Receipts) != custodians {
				t.Fatal("receipt-set command returned invalid canonical evidence")
			}
			replayed := formalGLMRegisteredPhase18SourceCommandTestRunV1(t, root, request)
			if !replayed.Replayed || replayed.ReceiptSetJSON != sealed.ReceiptSetJSON {
				t.Fatal("receipt-set replay changed durable evidence")
			}
		})
	}
}

func TestFormalGLMRegisteredPhase18SourceCommandCommitsBindingK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMRegisteredPhase18SourceOutboxTestBuild(t, custodians)
			plan := fixture.provenance.source.contract.Core.RegisteredExecutionPlan
			peer := plan.DesignatedComputePeers[0]
			root := formalGLMRegisteredPhase18SourceOutboxTestRoot(t, "binding")
			tickets := make([]formalGLMRegisteredPhase18RecipientTicketV1, len(plan.DesignatedComputePeers))
			for index, recipient := range plan.DesignatedComputePeers {
				ticketRoot := root
				if index != 0 {
					ticketRoot = formalGLMRegisteredPhase18SourceOutboxTestRoot(
						t, fmt.Sprintf("binding-ticket-%d", index))
				}
				issued := formalGLMRegisteredPhase18SourceCommandTestRunV1(
					t, ticketRoot,
					formalGLMRegisteredPhase18SourceCommandTestRequestV1(
						t, formalGLMRegisteredPhase18SourceCommandActionTicketV1,
						recipient, fixture))
				if issued.Ticket == nil || issued.Replayed {
					t.Fatal("recipient ticket was not issued")
				}
				tickets[index] = *issued.Ticket
			}
			request := formalGLMRegisteredPhase18SourceCommandTestRequestV1(
				t, formalGLMRegisteredPhase18SourceCommandActionTicketSetV1, peer, fixture)
			request.RecipientTickets = append(
				[]formalGLMRegisteredPhase18RecipientTicketV1(nil), tickets...)
			if committed := formalGLMRegisteredPhase18SourceCommandTestRunV1(t, root, request); committed.Replayed {
				t.Fatal("ticket set was unexpectedly replayed")
			}
			request.Action = formalGLMRegisteredPhase18SourceCommandActionReceiptCommitV1
			request.RecipientTickets = nil
			for _, receipt := range fixture.provenance.receipts {
				receiptJSON, marshalErr := json.Marshal(receipt)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				request.LocalReceiptJSON = string(receiptJSON)
				clear(receiptJSON)
				if committed := formalGLMRegisteredPhase18SourceCommandTestRunV1(t, root, request); committed.Replayed {
					t.Fatal("local receipt was unexpectedly replayed")
				}
			}
			request.Action = formalGLMRegisteredPhase18SourceCommandActionReceiptSetV1
			request.LocalReceiptJSON = ""
			if sealed := formalGLMRegisteredPhase18SourceCommandTestRunV1(t, root, request); sealed.Replayed {
				t.Fatal("receipt set was unexpectedly replayed")
			}
			request.Action = formalGLMRegisteredPhase18SourceCommandActionBindingV1
			request.RecipientTickets = append(
				[]formalGLMRegisteredPhase18RecipientTicketV1(nil), tickets...)
			committed := formalGLMRegisteredPhase18SourceCommandTestRunV1(t, root, request)
			if committed.BindingRecordJSON == "" || committed.Replayed {
				t.Fatal("binding command did not persist registered evidence")
			}
			var record formalGLMRegisteredPhase19BindingRecordV1
			if formalGLMPhase21RockStrictDecode(
				[]byte(committed.BindingRecordJSON), &record) != nil ||
				formalGLMValidateRegisteredPhase19BindingRecordV1(
					record, fixture.provenance.source.contract,
					fixture.provenance.source.inputs.identities.public) != nil ||
				record.Binding.ReceiptSetSHA256 != fixture.provenance.receiptSet.ReceiptSetSHA256 {
				t.Fatal("binding command returned invalid registered evidence")
			}
			replayed := formalGLMRegisteredPhase18SourceCommandTestRunV1(t, root, request)
			if !replayed.Replayed || replayed.BindingRecordJSON != committed.BindingRecordJSON {
				t.Fatal("binding replay changed durable evidence")
			}
			request.Action = formalGLMRegisteredPhase18SourceCommandActionHostProvisionV1
			request.RecipientTickets = nil
			provisioned := formalGLMRegisteredPhase18SourceCommandTestRunV1(t, root, request)
			if provisioned.JobHostReceipt == nil || provisioned.Replayed ||
				provisioned.JobHostReceipt.Peer != peer ||
				provisioned.JobHostReceipt.ArtifactID != record.Binding.ArtifactID ||
				provisioned.JobHostReceipt.ReceiptSetSHA256 != record.Binding.ReceiptSetSHA256 ||
				provisioned.JobHostReceipt.ProductionReady {
				t.Fatal("host bootstrap was not derived from the registered binding")
			}
			host, hostErr := formalGLMRegisteredPhase20JobControlHostOpenProvisionedV1(
				root, *provisioned.JobHostReceipt)
			if hostErr != nil {
				t.Fatal(hostErr)
			}
			if encodedHost, marshalErr := json.Marshal(host); marshalErr != nil || string(encodedHost) != "{}" {
				_ = host.Close()
				t.Fatalf("provisioned host exposed private state: %q / %v", encodedHost, marshalErr)
			}
			if err := host.Close(); err != nil {
				t.Fatal(err)
			}
			replayedProvision := formalGLMRegisteredPhase18SourceCommandTestRunV1(t, root, request)
			if replayedProvision.JobHostReceipt == nil || !replayedProvision.Replayed ||
				replayedProvision.JobHostReceipt.Version != provisioned.JobHostReceipt.Version ||
				replayedProvision.JobHostReceipt.Peer != provisioned.JobHostReceipt.Peer ||
				replayedProvision.JobHostReceipt.ArtifactID != provisioned.JobHostReceipt.ArtifactID ||
				replayedProvision.JobHostReceipt.ReceiptSetSHA256 != provisioned.JobHostReceipt.ReceiptSetSHA256 ||
				replayedProvision.JobHostReceipt.ConfigSHA256 != provisioned.JobHostReceipt.ConfigSHA256 ||
				replayedProvision.JobHostReceipt.ProductionReady {
				t.Fatal("host bootstrap replay changed durable evidence")
			}
		})
	}
}
