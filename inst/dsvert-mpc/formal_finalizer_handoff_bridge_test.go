package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFormalFinalizerHandoffBridgeDescribeAndImport(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(string(rune('0'+custodians)), func(t *testing.T) {
			fixture := formalFinalizerHandoffTestFixtureForK(
				t, custodians, formalFinalizerHandoffFamilyGLM)
			garbler := fixture.binding.Authorities[0]
			evaluator := fixture.binding.Authorities[1]
			garblerDir := filepath.Join(t.TempDir(), garbler.PeerName)
			evaluatorDir := filepath.Join(t.TempDir(), evaluator.PeerName)
			garblerStorageRoot := sha256.Sum256([]byte(t.Name() + "/garbler"))
			evaluatorStorageRoot := sha256.Sum256([]byte(t.Name() + "/evaluator"))
			garblerStore, err := newFormalFinalizerHandoffAuthorityStoreForTest(
				garblerDir, fixture.binding, garbler, garblerStorageRoot,
				fixture.public)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { garblerStore.Close() }()
			evaluatorStore, err := newFormalFinalizerHandoffAuthorityStoreForTest(
				evaluatorDir, fixture.binding, evaluator, evaluatorStorageRoot,
				fixture.public)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { evaluatorStore.Close() }()

			ticket, secret, _, err := garblerStore.IssueTicketOnce(
				fixture.private[garbler.PeerName])
			clear(secret)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := evaluatorStore.CommitTicket(ticket); err != nil {
				t.Fatal(err)
			}
			payload := formalFinalizerHandoffTestPayload(
				t, fixture, ticket, evaluator.PeerName,
				formalFinalizerHandoffGLMOneDrawKind, custodians)
			envelope, err := formalFinalizerHandoffSealCanonical(
				fixture.binding, ticket, evaluator.PeerName,
				formalFinalizerHandoffGLMOneDrawKind, payload,
				fixture.private[evaluator.PeerName], fixture.public)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := evaluatorStore.CommitOutbox(envelope); err != nil {
				t.Fatal(err)
			}

			descriptor, err := evaluatorStore.DescribeOutboxCanonical("evaluator")
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := os.ReadFile(descriptor.SourcePath)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(encoded)
			ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
			if err != nil {
				t.Fatal(err)
			}
			expectedContext := formalFinalizerHandoffBridgeContext{
				Version:             formalFinalizerHandoffBridgeContextVersion,
				Family:              fixture.binding.Family,
				Purpose:             fixture.binding.Purpose,
				ArtifactID:          fixture.binding.ArtifactID,
				FinalPairRootSHA256: fixture.binding.FinalPairRootSHA256,
				PlanSHA256:          fixture.binding.PlanSHA256,
				PinsetSHA256:        fixture.binding.PinsetSHA256,
				TicketSHA256:        ticketSHA,
				SenderPeerName:      evaluator.PeerName,
				SenderRole:          "evaluator",
				FinalizerPeerName:   garbler.PeerName,
				PayloadKind:         formalFinalizerHandoffGLMOneDrawKind,
				EnvelopeSHA256:      hex.EncodeToString(digest[:]),
				EnvelopeBytes:       int64(len(encoded)),
			}
			if descriptor.Version != formalFinalizerHandoffBridgeDescriptorVersion ||
				descriptor.EnvelopeBytes != int64(len(encoded)) ||
				descriptor.EnvelopeSHA256 != hex.EncodeToString(digest[:]) ||
				descriptor.PayloadChars != int64(
					base64.RawURLEncoding.EncodedLen(len(encoded))) ||
				descriptor.Context != expectedContext {
				t.Fatalf("invalid source descriptor: %#v", descriptor)
			}
			evaluatorStore.Close()
			evaluatorStore, err = newFormalFinalizerHandoffAuthorityStoreForTest(
				evaluatorDir, fixture.binding, evaluator, evaluatorStorageRoot,
				fixture.public)
			if err != nil {
				t.Fatal(err)
			}
			restartedDescriptor, err := evaluatorStore.DescribeOutboxCanonical(
				"evaluator")
			if err != nil || restartedDescriptor != descriptor {
				t.Fatalf("outbox descriptor changed across restart: %#v / %v",
					restartedDescriptor, err)
			}
			certificateSHA := formalFinalizerHandoffTestSHA(
				t.Name() + "/certificate")
			proof, err := formalFinalizerHandoffBuildCommitProof(
				fixture.binding, ticketSHA, certificateSHA,
				fixture.private[garbler.PeerName], fixture.public)
			if err != nil {
				t.Fatal(err)
			}
			publication := formalFinalizerHandoffTestPublicationGuard{
				wantArtifact:    fixture.binding.ArtifactID,
				wantCertificate: certificateSHA,
			}
			if _, _, err := evaluatorStore.AckAfterCommit(
				proof, publication); err != nil {
				t.Fatal(err)
			}
			evaluatorStore.Close()
			evaluatorStore, err = newFormalFinalizerHandoffAuthorityStoreForTest(
				evaluatorDir, fixture.binding, evaluator, evaluatorStorageRoot,
				fixture.public)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := evaluatorStore.DescribeOutboxCanonical(
				"evaluator"); err == nil {
				t.Fatal("terminal ACK allowed a post-restart source remint")
			}

			receipt, err := garblerStore.ImportIngressCanonical("evaluator", encoded)
			if err != nil || receipt.Replayed ||
				receipt.EnvelopeSHA256 != descriptor.EnvelopeSHA256 ||
				receipt.ArtifactID != fixture.binding.ArtifactID ||
				receipt.SenderRole != "evaluator" {
				t.Fatalf("invalid ingress receipt: %#v / %v", receipt, err)
			}
			encodedReceipt, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			var receiptFields map[string]any
			if err := json.Unmarshal(encodedReceipt, &receiptFields); err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{
				"ciphertext", "payload", "source_path", "ingress_path",
			} {
				if _, found := receiptFields[forbidden]; found {
					t.Fatalf("ingress receipt leaked %s", forbidden)
				}
			}
			garblerStore.Close()
			garblerStore, err = newFormalFinalizerHandoffAuthorityStoreForTest(
				garblerDir, fixture.binding, garbler, garblerStorageRoot,
				fixture.public)
			if err != nil {
				t.Fatal(err)
			}
			replay, err := garblerStore.ImportIngressCanonical("evaluator", encoded)
			if err != nil || !replay.Replayed || replay != (formalFinalizerHandoffIngressReceipt{
				Version: formalFinalizerHandoffBridgeIngressVersion,
				State:   "ingress_committed", ArtifactID: fixture.binding.ArtifactID,
				SenderRole: "evaluator", EnvelopeSHA256: descriptor.EnvelopeSHA256,
				Replayed: true,
			}) {
				t.Fatalf("invalid ingress replay: %#v / %v", replay, err)
			}
		})
	}
}

func TestFormalFinalizerHandoffBridgeFailsClosed(t *testing.T) {
	fixture := formalFinalizerHandoffTestFixtureForK(
		t, 3, formalFinalizerHandoffFamilyCox)
	garbler := fixture.binding.Authorities[0]
	evaluator := fixture.binding.Authorities[1]
	garblerStore, err := newFormalFinalizerHandoffAuthorityStoreForTest(
		filepath.Join(t.TempDir(), garbler.PeerName), fixture.binding,
		garbler, sha256.Sum256([]byte(t.Name()+"/garbler")), fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	defer garblerStore.Close()
	evaluatorStore, err := newFormalFinalizerHandoffAuthorityStoreForTest(
		filepath.Join(t.TempDir(), evaluator.PeerName), fixture.binding,
		evaluator, sha256.Sum256([]byte(t.Name()+"/evaluator")), fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	defer evaluatorStore.Close()
	ticket, secret, _, err := garblerStore.IssueTicketOnce(
		fixture.private[garbler.PeerName])
	clear(secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := evaluatorStore.CommitTicket(ticket); err != nil {
		t.Fatal(err)
	}
	payload := formalFinalizerHandoffTestPayload(
		t, fixture, ticket, evaluator.PeerName,
		formalFinalizerHandoffCoxOpeningKind, 1)
	envelope, err := formalFinalizerHandoffSealCanonical(
		fixture.binding, ticket, evaluator.PeerName,
		formalFinalizerHandoffCoxOpeningKind, payload,
		fixture.private[evaluator.PeerName], fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := evaluatorStore.CommitOutbox(envelope); err != nil {
		t.Fatal(err)
	}
	descriptor, err := evaluatorStore.DescribeOutboxCanonical("evaluator")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(descriptor.SourcePath)
	if err != nil {
		t.Fatal(err)
	}

	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)/2] ^= 1
	if _, err := garblerStore.ImportIngressCanonical("evaluator", tampered); err == nil {
		t.Fatal("tampered ingress was accepted")
	}
	if _, err := garblerStore.ImportIngressCanonical("garbler", encoded); err == nil {
		t.Fatal("misrouted ingress was accepted")
	}
	if _, err := garblerStore.ImportIngressCanonical("evaluator", nil); err == nil {
		t.Fatal("empty ingress was accepted")
	}
	if _, err := garblerStore.DescribeOutboxCanonical("garbler"); err == nil {
		t.Fatal("garbler outbox was exposed through the crossing bridge")
	}
	oversized := make([]byte, formalFinalizerHandoffMaxRecord+1)
	if _, err := garblerStore.ImportIngressCanonical("evaluator", oversized); err == nil {
		t.Fatal("oversized ingress was accepted")
	}

	if err := os.Chmod(descriptor.SourcePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := evaluatorStore.DescribeOutboxCanonical("evaluator"); err == nil {
		t.Fatal("world-readable outbox was described")
	}
	if err := os.Chmod(descriptor.SourcePath, 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(filepath.Dir(descriptor.SourcePath), "linked-envelope.json")
	if err := os.Link(descriptor.SourcePath, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := evaluatorStore.DescribeOutboxCanonical("evaluator"); err == nil {
		t.Fatal("multiply-linked outbox was described")
	}
	if err := os.Remove(linked); err != nil {
		t.Fatal(err)
	}
	tamperedOutbox := append([]byte(nil), encoded...)
	tamperedOutbox[len(tamperedOutbox)/2] ^= 1
	if err := os.WriteFile(descriptor.SourcePath, tamperedOutbox, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := evaluatorStore.DescribeOutboxCanonical("evaluator"); err == nil {
		t.Fatal("tampered durable outbox was described")
	}
	if err := os.WriteFile(descriptor.SourcePath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, found := decoded["source_path"]; found {
		t.Fatal("canonical envelope unexpectedly contains a filesystem path")
	}
}

func TestFormalFinalizerHandoffBridgeBase64URLBound(t *testing.T) {
	for _, size := range []int64{1, 2, 3, formalFinalizerHandoffMaxRecord} {
		got, err := formalFinalizerHandoffBase64URLChars(size)
		want := int64(base64.RawURLEncoding.EncodedLen(int(size)))
		if err != nil || got != want {
			t.Fatalf("size %d: got %d, want %d / %v", size, got, want, err)
		}
	}
	if formalFinalizerHandoffMaxOuterPayloadChars != 11_184_811 {
		t.Fatalf("unexpected outer bound: %d",
			formalFinalizerHandoffMaxOuterPayloadChars)
	}
	for _, invalid := range []int64{0, -1, formalFinalizerHandoffMaxRecord + 1} {
		if _, err := formalFinalizerHandoffBase64URLChars(invalid); err == nil {
			t.Fatalf("invalid size %d was accepted", invalid)
		}
	}
}
