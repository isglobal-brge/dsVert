package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func formalCoxBlockwiseSourceDeliveryCommandTestRequest(
	t testing.TB, source formalCoxBlockwiseSourceProducerCommand,
	recipient string,
) formalCoxBlockwiseSourceDeliveryCommand {
	t.Helper()
	return formalCoxBlockwiseSourceDeliveryCommand{
		Version:       formalCoxBlockwiseSourceDeliveryCommandVersion,
		Schema:        append(json.RawMessage(nil), source.Schema...),
		BlockCapacity: source.BlockCapacity,
		RunID:         source.RunID,
		Pins:          source.Pins,
		RecipientTickets: append(
			[]formalCoxBlockwiseSourceRecipientTicket(nil),
			source.RecipientTickets...),
		SourcePeerName:    source.SourcePeerName,
		SourceSigningKey:  source.SourceSigningKey,
		BlockIndex:        source.BlockIndex,
		RecipientPeerName: recipient,
	}
}

func TestFormalCoxBlockwiseSourceDeliveryCommandK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			source, session, transportSecret, _ :=
				formalCoxBlockwiseSourceProducerCommandTestRequest(t, custodians)
			root := formalCoxBlockwiseSourceProducerCommandTestRoot(t)
			produced, _ := formalCoxBlockwiseSourceProducerCommandTestRun(
				t, source, root)

			for _, recipient := range session.context.plan.Policy.ComputePeers {
				command := formalCoxBlockwiseSourceDeliveryCommandTestRequest(
					t, source, recipient)
				encoded, err := json.Marshal(command)
				if err != nil {
					t.Fatal(err)
				}
				delivery, err := formalCoxBlockwiseSourceDeliveryRunAtRoot(
					encoded, root, false)
				if err != nil || delivery.ReceiptSHA256 != produced.ReceiptSHA256 ||
					delivery.RecipientPeerName != recipient {
					t.Fatalf("delivery %s: %+v / %v", recipient, delivery, err)
				}
				canonical, err := delivery.Encode(session)
				if err != nil {
					t.Fatal(err)
				}
				replayed, err := formalCoxBlockwiseSourceDeliveryRunAtRoot(
					encoded, root, false)
				if err != nil {
					t.Fatal(err)
				}
				replayedJSON, err := replayed.Encode(session)
				if err != nil || !bytes.Equal(replayedJSON, canonical) {
					t.Fatalf("delivery replay %s: %v", recipient, err)
				}

				storeKey := sha256.Sum256([]byte(
					"formal-cox-source-delivery-command/store/" + recipient))
				if err := os.MkdirAll(filepath.Join(root, "recipient"), 0o700); err != nil {
					t.Fatal(err)
				}
				store, err := newFormalCoxBlockwiseSourceStore(
					filepath.Join(root, "recipient", recipient), storeKey, session,
					recipient, transportSecret[recipient])
				if err != nil {
					t.Fatal(err)
				}
				accepted, err := store.AcceptDelivery(canonical)
				if err != nil || accepted {
					_ = store.Close()
					t.Fatalf("accept %s: replay=%v err=%v", recipient, accepted, err)
				}
				accepted, err = store.AcceptDelivery(canonical)
				if err != nil || !accepted {
					_ = store.Close()
					t.Fatalf("accept replay %s: replay=%v err=%v", recipient, accepted, err)
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}

				private, err := base64.StdEncoding.Strict().DecodeString(
					source.SourceSigningKey)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(canonical, private) ||
					bytes.Contains(canonical, transportSecret[recipient]) ||
					bytes.Contains(canonical, []byte(root)) {
					clear(private)
					t.Fatal("delivery exposed local private material")
				}
				clear(private)
			}
		})
	}
}

func TestFormalCoxBlockwiseSourceDeliveryCommandRejectsTamperAndOpenInput(t *testing.T) {
	source, session, _, _ := formalCoxBlockwiseSourceProducerCommandTestRequest(t, 2)
	root := formalCoxBlockwiseSourceProducerCommandTestRoot(t)
	formalCoxBlockwiseSourceProducerCommandTestRun(t, source, root)
	command := formalCoxBlockwiseSourceDeliveryCommandTestRequest(
		t, source, session.context.plan.Policy.ComputePeers[0])

	for name, mutate := range map[string]func(*formalCoxBlockwiseSourceDeliveryCommand){
		"recipient": func(value *formalCoxBlockwiseSourceDeliveryCommand) {
			value.RecipientPeerName = "outsider"
		},
		"block": func(value *formalCoxBlockwiseSourceDeliveryCommand) {
			value.BlockIndex++
		},
		"source key": func(value *formalCoxBlockwiseSourceDeliveryCommand) {
			value.SourceSigningKey = base64.StdEncoding.EncodeToString(make([]byte, 64))
		},
		"recipient ticket": func(value *formalCoxBlockwiseSourceDeliveryCommand) {
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
			if _, err := formalCoxBlockwiseSourceDeliveryRunAtRoot(
				encoded, root, false); err == nil {
				t.Fatal("source delivery accepted tampered command")
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
	if _, err := formalCoxBlockwiseSourceDeliveryDecodeCommand(open); err == nil {
		t.Fatal("source delivery accepted a caller-selected path")
	}
}
