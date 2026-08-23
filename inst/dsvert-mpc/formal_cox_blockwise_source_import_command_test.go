package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func formalCoxBlockwiseSourceImportCommandTestRequest(
	t testing.TB, source formalCoxBlockwiseSourceProducerCommand,
	delivery formalCoxBlockwiseSourceDelivery, recipient string,
	signer ed25519.PrivateKey,
) formalCoxBlockwiseSourceImportCommand {
	t.Helper()
	return formalCoxBlockwiseSourceImportCommand{
		Version:       formalCoxBlockwiseSourceImportCommandVersion,
		Schema:        append(json.RawMessage(nil), source.Schema...),
		BlockCapacity: source.BlockCapacity,
		RunID:         source.RunID,
		Pins:          source.Pins,
		RecipientTickets: append(
			[]formalCoxBlockwiseSourceRecipientTicket(nil),
			source.RecipientTickets...),
		RecipientPeerName:   recipient,
		RecipientSigningKey: base64.StdEncoding.EncodeToString(signer),
		Delivery:            delivery,
	}
}

func formalCoxBlockwiseSourceImportCommandTestSource(
	t testing.TB, custodians int, root string,
) (formalCoxBlockwiseSourceProducerCommand, *formalCoxBlockwiseSourceSession,
	map[string]ed25519.PrivateKey) {
	t.Helper()
	source, session, _, _, signers :=
		formalCoxBlockwiseSourceProducerCommandTestRequest(t, custodians)
	tickets := make([]formalCoxBlockwiseSourceRecipientTicket, 2)
	for index, recipient := range session.context.plan.Policy.ComputePeers {
		request := formalCoxBlockwiseSourceRecipientKeyCommandTestRequest(
			t, source, recipient, signers[recipient])
		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		ticket, err := formalCoxBlockwiseSourceRecipientKeyCommandRunAtRoot(
			encoded, root, false)
		if err != nil {
			t.Fatal(err)
		}
		tickets[index] = ticket
	}
	bound, err := session.context.bindRecipientManifest(tickets)
	if err != nil {
		t.Fatal(err)
	}
	source.RecipientTickets = tickets
	return source, bound, signers
}

func TestFormalCoxBlockwiseSourceImportCommandK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			root := formalCoxBlockwiseSourceProducerCommandTestRoot(t)
			source, session, signers :=
				formalCoxBlockwiseSourceImportCommandTestSource(t, custodians, root)
			formalCoxBlockwiseSourceProducerCommandTestRun(t, source, root)

			for _, recipient := range session.context.plan.Policy.ComputePeers {
				deliveryCommand := formalCoxBlockwiseSourceDeliveryCommandTestRequest(
					t, source, recipient)
				deliveryInput, err := json.Marshal(deliveryCommand)
				if err != nil {
					t.Fatal(err)
				}
				delivery, err := formalCoxBlockwiseSourceDeliveryRunAtRoot(
					deliveryInput, root, false)
				if err != nil {
					t.Fatal(err)
				}
				command := formalCoxBlockwiseSourceImportCommandTestRequest(
					t, source, delivery, recipient, signers[recipient])
				encoded, err := json.Marshal(command)
				if err != nil {
					t.Fatal(err)
				}
				first, err := formalCoxBlockwiseSourceImportRunAtRoot(
					encoded, root, false)
				if err != nil || first.Replayed ||
					first.Version != formalCoxBlockwiseSourceImportReceiptVersion ||
					first.Purpose != formalCoxBlockwiseSourceDeliveryPurpose ||
					first.RecipientPeerName != recipient ||
					first.ReceiptSHA256 != delivery.ReceiptSHA256 {
					t.Fatalf("first import %s: %+v / %v", recipient, first, err)
				}
				replayed, err := formalCoxBlockwiseSourceImportRunAtRoot(
					encoded, root, false)
				if err != nil || !replayed.Replayed ||
					replayed.ReceiptSHA256 != first.ReceiptSHA256 ||
					replayed.RecipientPeerName != first.RecipientPeerName {
					t.Fatalf("replayed import %s: %+v / %v", recipient, replayed, err)
				}
				public, err := json.Marshal(first)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(public, signers[recipient]) ||
					bytes.Contains(public, delivery.Envelope) ||
					bytes.Contains(public, []byte(root)) {
					t.Fatal("source import receipt exposed private material")
				}
			}
		})
	}
}

// TestFormalCoxBlockwiseSourceCommandsStageAllBlocksK2K3K5 exercises the
// closed producer, delivery and recipient-import commands over the complete
// static block prefix.  The update/noise slots are supplied by the separate
// guarded sampler route; this test deliberately does not pretend otherwise.
func TestFormalCoxBlockwiseSourceCommandsStageAllBlocksK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			root := formalCoxBlockwiseSourceProducerCommandTestRoot(t)
			source, session, signers :=
				formalCoxBlockwiseSourceImportCommandTestSource(t, custodians, root)
			fixture := formalCoxRSourceBridgeFixtureFor(t, custodians)
			plan := session.context.plan
			if len(fixture.Blocks) != len(plan.Policy.CustodianPeers) ||
				plan.TotalBlocks < 2 {
				t.Fatal("all-block command fixture is incomplete")
			}

			for block := 0; block < plan.TotalBlocks; block++ {
				for _, peer := range plan.Policy.CustodianPeers {
					lines, ok := fixture.Blocks[peer]
					if !ok || len(lines) != plan.TotalBlocks {
						t.Fatalf("source %s has incomplete blocks", peer)
					}
					command := source
					command.SourcePeerName = peer
					command.SourceSigningKey = base64.StdEncoding.EncodeToString(signers[peer])
					command.BlockIndex = block
					command.CanonicalInputBase64 = base64.StdEncoding.EncodeToString(
						[]byte(strings.Join(lines[block], "\n") + "\n"))
					formalCoxBlockwiseSourceProducerCommandTestRun(t, command, root)

					for _, recipient := range plan.Policy.ComputePeers {
						deliveryCommand := formalCoxBlockwiseSourceDeliveryCommandTestRequest(
							t, command, recipient)
						deliveryJSON, err := json.Marshal(deliveryCommand)
						if err != nil {
							t.Fatal(err)
						}
						delivery, err := formalCoxBlockwiseSourceDeliveryRunAtRoot(
							deliveryJSON, root, false)
						if err != nil || delivery.RecipientPeerName != recipient {
							t.Fatalf("delivery %s/%d to %s: %+v / %v",
								peer, block, recipient, delivery, err)
						}
						importCommand := formalCoxBlockwiseSourceImportCommandTestRequest(
							t, command, delivery, recipient, signers[recipient])
						importJSON, err := json.Marshal(importCommand)
						if err != nil {
							t.Fatal(err)
						}
						imported, err := formalCoxBlockwiseSourceImportRunAtRoot(
							importJSON, root, false)
						if err != nil || imported.Replayed ||
							imported.ReceiptSHA256 != delivery.ReceiptSHA256 {
							t.Fatalf("import %s/%d to %s: %+v / %v",
								peer, block, recipient, imported, err)
						}
					}
				}
			}

			stores := make(map[string]*formalCoxBlockwiseSourceStore, 2)
			for _, recipient := range plan.Policy.ComputePeers {
				last := source
				last.SourcePeerName = plan.Policy.CustodianPeers[len(plan.Policy.CustodianPeers)-1]
				last.SourceSigningKey = base64.StdEncoding.EncodeToString(
					signers[last.SourcePeerName])
				last.BlockIndex = plan.TotalBlocks - 1
				last.CanonicalInputBase64 = base64.StdEncoding.EncodeToString([]byte(
					strings.Join(fixture.Blocks[last.SourcePeerName][last.BlockIndex], "\n") + "\n"))
				deliveryCommand := formalCoxBlockwiseSourceDeliveryCommandTestRequest(
					t, last, recipient)
				deliveryJSON, err := json.Marshal(deliveryCommand)
				if err != nil {
					t.Fatal(err)
				}
				delivery, err := formalCoxBlockwiseSourceDeliveryRunAtRoot(
					deliveryJSON, root, false)
				if err != nil {
					t.Fatal(err)
				}
				importCommand := formalCoxBlockwiseSourceImportCommandTestRequest(
					t, last, delivery, recipient, signers[recipient])
				store, closeStore, err := formalCoxBlockwiseSourceImportOpen(
					importCommand, root, false)
				if err != nil {
					t.Fatal(err)
				}
				defer closeStore()
				stores[recipient] = store
				state, err := store.readState()
				if err != nil || state.NextSlot !=
					plan.TotalBlocks*len(plan.Policy.CustodianPeers) {
					t.Fatalf("recipient %s static source state: %+v / %v",
						recipient, state, err)
				}
			}
			modulus := exactGCModulus(plan.RingBits)
			for block := 0; block < plan.TotalBlocks; block++ {
				step := formalCoxBlockwiseSourceTestStep(
					t, plan, formalCoxBlockwiseStepBlock, block)
				want := make([]*big.Int, plan.BlockCapacity*plan.RowWidth)
				got := make([]*big.Int, len(want))
				for index := range want {
					want[index], got[index] = new(big.Int), new(big.Int)
				}
				for _, sourcePeer := range plan.Policy.CustodianPeers {
					values := formalCoxRSourceBridgeExpected(t,
						fixture.Blocks[sourcePeer][block], len(want), plan.RingBits)
					for index := range want {
						want[index].Add(want[index], values[index])
						want[index].Mod(want[index], modulus)
					}
					exactGCZeroBigInts(values)
				}
				for _, recipient := range plan.Policy.ComputePeers {
					input, err := stores[recipient].Load(step)
					if err != nil || len(input.Shares) != len(got) ||
						!formalCoxIsSHA256(input.PairedInputRootSHA256) {
						exactGCZeroBigInts(input.Shares)
						exactGCZeroBigInts(want)
						exactGCZeroBigInts(got)
						t.Fatalf("recipient %s block %d source load: %+v / %v",
							recipient, block, input, err)
					}
					for index := range got {
						got[index].Add(got[index], input.Shares[index])
						got[index].Mod(got[index], modulus)
					}
					exactGCZeroBigInts(input.Shares)
				}
				for index := range want {
					if got[index].Cmp(want[index]) != 0 {
						actual, expected := got[index].String(), want[index].String()
						exactGCZeroBigInts(want)
						exactGCZeroBigInts(got)
						t.Fatalf("block %d coordinate %d: got %s want %s",
							block, index, actual, expected)
					}
				}
				exactGCZeroBigInts(want)
				exactGCZeroBigInts(got)
			}
		})
	}
}

func TestFormalCoxBlockwiseSourceImportCommandRejectsTamperAndOpenInput(t *testing.T) {
	root := formalCoxBlockwiseSourceProducerCommandTestRoot(t)
	source, session, signers :=
		formalCoxBlockwiseSourceImportCommandTestSource(t, 2, root)
	formalCoxBlockwiseSourceProducerCommandTestRun(t, source, root)
	recipient := session.context.plan.Policy.ComputePeers[0]
	deliveryInput, err := json.Marshal(
		formalCoxBlockwiseSourceDeliveryCommandTestRequest(t, source, recipient))
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := formalCoxBlockwiseSourceDeliveryRunAtRoot(
		deliveryInput, root, false)
	if err != nil {
		t.Fatal(err)
	}
	command := formalCoxBlockwiseSourceImportCommandTestRequest(
		t, source, delivery, recipient, signers[recipient])
	planSHA, err := formalCoxBlockwisePlanSHA256(session.context.plan)
	if err != nil {
		t.Fatal(err)
	}
	recipientRoot := filepath.Join(root,
		"formal-cox-blockwise-source-recipient-v1", recipient, planSHA)

	for name, mutate := range map[string]func(*formalCoxBlockwiseSourceImportCommand){
		"recipient": func(value *formalCoxBlockwiseSourceImportCommand) {
			value.RecipientPeerName = "outsider"
		},
		"signer": func(value *formalCoxBlockwiseSourceImportCommand) {
			value.RecipientSigningKey = base64.StdEncoding.EncodeToString(
				make([]byte, ed25519.PrivateKeySize))
		},
		"delivery": func(value *formalCoxBlockwiseSourceImportCommand) {
			value.Delivery.ReceiptSHA256 =
				"0000000000000000000000000000000000000000000000000000000000000000"
		},
		"recipient ticket": func(value *formalCoxBlockwiseSourceImportCommand) {
			value.RecipientTickets[0] = formalCoxBlockwiseSourceCloneTicket(
				value.RecipientTickets[0])
			value.RecipientTickets[0].Signature[0] ^= 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := command
			candidate.Schema = append(json.RawMessage(nil), command.Schema...)
			candidate.RecipientTickets = append(
				[]formalCoxBlockwiseSourceRecipientTicket(nil), command.RecipientTickets...)
			mutate(&candidate)
			encoded, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := formalCoxBlockwiseSourceImportRunAtRoot(
				encoded, root, false); err == nil {
				t.Fatal("source import accepted tampered command")
			}
			if _, err := os.Lstat(recipientRoot); !os.IsNotExist(err) {
				t.Fatalf("tampered command created recipient state: %v", err)
			}
		})
	}

	encoded, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	object["path"] = "/caller-selected"
	open, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := formalCoxBlockwiseSourceImportDecodeCommand(open); err == nil {
		t.Fatal("source import accepted a caller-selected path")
	}
}
