package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func formalCoxBlockwiseSourceRecipientKeyCommandTestRequest(
	t testing.TB, source formalCoxBlockwiseSourceProducerCommand,
	recipient string, signer ed25519.PrivateKey,
) formalCoxBlockwiseSourceRecipientKeyCommand {
	t.Helper()
	return formalCoxBlockwiseSourceRecipientKeyCommand{
		Version:             formalCoxBlockwiseSourceRecipientKeyCommandVersion,
		Schema:              append(json.RawMessage(nil), source.Schema...),
		BlockCapacity:       source.BlockCapacity,
		RunID:               source.RunID,
		Pins:                source.Pins,
		RecipientPeerName:   recipient,
		RecipientSigningKey: base64.StdEncoding.EncodeToString(signer),
	}
}

func TestFormalCoxBlockwiseSourceRecipientKeyCommandK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			source, session, _, _, signers :=
				formalCoxBlockwiseSourceProducerCommandTestRequest(t, custodians)
			root := formalCoxBlockwiseSourceProducerCommandTestRoot(t)
			tickets := make([]formalCoxBlockwiseSourceRecipientTicket, 2)

			for index, recipient := range session.context.plan.Policy.ComputePeers {
				command := formalCoxBlockwiseSourceRecipientKeyCommandTestRequest(
					t, source, recipient, signers[recipient])
				encoded, err := json.Marshal(command)
				if err != nil {
					t.Fatal(err)
				}
				first, err := formalCoxBlockwiseSourceRecipientKeyCommandRunAtRoot(
					encoded, root, false)
				if err != nil || first.RecipientPeerName != recipient ||
					first.RecipientRole != session.context.roles[recipient] ||
					len(first.TransportPublicKey) != 32 ||
					len(first.Signature) != ed25519.SignatureSize {
					t.Fatalf("first ticket for %s: %+v / %v", recipient, first, err)
				}
				replayed, err := formalCoxBlockwiseSourceRecipientKeyCommandRunAtRoot(
					encoded, root, false)
				if err != nil || !reflect.DeepEqual(replayed, first) {
					t.Fatalf("replayed ticket for %s: %+v / %v", recipient, replayed, err)
				}
				public, err := json.Marshal(first)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(public, signers[recipient]) ||
					bytes.Contains(public, []byte(root)) {
					t.Fatal("recipient ticket exposed local private material")
				}
				tickets[index] = first
			}
			if _, err := session.context.bindRecipientManifest(tickets); err != nil {
				t.Fatalf("issued tickets did not bind: %v", err)
			}
		})
	}
}

func TestFormalCoxBlockwiseSourceRecipientKeyCommandRejectsTamperAndUnsafeKey(t *testing.T) {
	source, session, _, _, signers := formalCoxBlockwiseSourceProducerCommandTestRequest(t, 2)
	recipient := session.context.plan.Policy.ComputePeers[0]
	root := formalCoxBlockwiseSourceProducerCommandTestRoot(t)
	command := formalCoxBlockwiseSourceRecipientKeyCommandTestRequest(
		t, source, recipient, signers[recipient])
	encoded, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := formalCoxBlockwiseSourceRecipientKeyCommandRunAtRoot(
		encoded, root, false); err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*formalCoxBlockwiseSourceRecipientKeyCommand){
		"recipient": func(value *formalCoxBlockwiseSourceRecipientKeyCommand) {
			value.RecipientPeerName = "outsider"
		},
		"signer": func(value *formalCoxBlockwiseSourceRecipientKeyCommand) {
			value.RecipientSigningKey = base64.StdEncoding.EncodeToString(
				make([]byte, ed25519.PrivateKeySize))
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := command
			candidate.Schema = append(json.RawMessage(nil), command.Schema...)
			mutate(&candidate)
			candidateJSON, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := formalCoxBlockwiseSourceRecipientKeyCommandRunAtRoot(
				candidateJSON, root, false); err == nil {
				t.Fatal("recipient key command accepted invalid local authority")
			}
		})
	}

	planSHA, err := formalCoxBlockwisePlanSHA256(session.context.plan)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, formalCoxBlockwiseSourceRecipientKeyDir,
		recipient, planSHA, formalCoxBlockwiseSourceRecipientKeyFile)
	if err := os.Chmod(keyPath, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := formalCoxBlockwiseSourceRecipientKeyCommandRunAtRoot(
		encoded, root, false); err == nil {
		t.Fatal("recipient key command accepted unsafe key mode")
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	linked := keyPath + ".link"
	if err := os.Link(keyPath, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := formalCoxBlockwiseSourceRecipientKeyCommandRunAtRoot(
		encoded, root, false); err == nil {
		t.Fatal("recipient key command accepted hard-linked key")
	}
	if err := os.Remove(linked); err != nil {
		t.Fatal(err)
	}
	backup := keyPath + ".backup"
	if err := os.Rename(keyPath, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(backup, keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := formalCoxBlockwiseSourceRecipientKeyCommandRunAtRoot(
		encoded, root, false); err == nil {
		t.Fatal("recipient key command accepted symlinked key")
	}
}
