package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func formalFinalizerHandoffBridgeCommandJSON(t *testing.T,
	fixture formalFinalizerHandoffTestFixture,
	local formalFinalizerHandoffAuthority, storageRoot [32]byte,
	envelope string, mutate func(map[string]any),
) []byte {
	t.Helper()
	pins := make(map[string]string, len(fixture.public))
	for peer, pin := range fixture.public {
		pins[peer] = base64.StdEncoding.EncodeToString(pin)
	}
	request := map[string]any{
		"version":                "dsvert-formal-finalizer-handoff-bridge-command-v1",
		"binding":                fixture.binding,
		"local_authority":        local,
		"pins":                   pins,
		"transport_storage_root": base64.StdEncoding.EncodeToString(storageRoot[:]),
	}
	if envelope != "" {
		request["envelope_base64url"] = envelope
	}
	if mutate != nil {
		mutate(request)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func formalFinalizerHandoffBridgeCommandFixture(t *testing.T, custodians int) (
	formalFinalizerHandoffTestFixture, string,
	formalFinalizerHandoffAuthority, [32]byte,
	formalFinalizerHandoffAuthority, [32]byte,
) {
	t.Helper()
	fixture := formalFinalizerHandoffTestFixtureForK(
		t, custodians, formalFinalizerHandoffFamilyGLM)
	garbler := fixture.binding.Authorities[0]
	evaluator := fixture.binding.Authorities[1]
	garblerRoot := sha256.Sum256([]byte(t.Name() + "/garbler"))
	evaluatorRoot := sha256.Sum256([]byte(t.Name() + "/evaluator"))
	stateRoot := t.TempDir()
	garblerStore, err := newFormalFinalizerHandoffAuthorityStoreForTest(
		filepath.Join(stateRoot, garbler.PeerName), fixture.binding,
		garbler, garblerRoot, fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	ticket, secret, _, err := garblerStore.IssueTicketOnce(
		fixture.private[garbler.PeerName])
	clear(secret)
	garblerStore.Close()
	if err != nil {
		t.Fatal(err)
	}
	evaluatorStore, err := newFormalFinalizerHandoffAuthorityStoreForTest(
		filepath.Join(stateRoot, evaluator.PeerName), fixture.binding,
		evaluator, evaluatorRoot, fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	defer evaluatorStore.Close()
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
	return fixture, stateRoot, garbler, garblerRoot, evaluator, evaluatorRoot
}

func TestFormalFinalizerHandoffBridgeCommandsK2K3K5Restart(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(string(rune('0'+custodians)), func(t *testing.T) {
			fixture, stateRoot, garbler, garblerRoot, evaluator, evaluatorRoot :=
				formalFinalizerHandoffBridgeCommandFixture(t, custodians)
			sourceRequest := formalFinalizerHandoffBridgeCommandJSON(
				t, fixture, evaluator, evaluatorRoot, "", nil)
			if strings.Contains(string(sourceRequest), "path") {
				t.Fatal("source command accepted a filesystem path")
			}
			descriptor, err := formalFinalizerHandoffRunSourceDescriptorAtRoot(
				sourceRequest, stateRoot, false)
			if err != nil || descriptor.Context.SenderRole != "evaluator" ||
				descriptor.Context.FinalizerPeerName != garbler.PeerName {
				t.Fatalf("invalid command descriptor: %#v / %v", descriptor, err)
			}
			envelope, err := os.ReadFile(descriptor.SourcePath)
			if err != nil {
				t.Fatal(err)
			}
			outer := base64.RawURLEncoding.EncodeToString(envelope)
			importRequest := formalFinalizerHandoffBridgeCommandJSON(
				t, fixture, garbler, garblerRoot, outer, nil)
			receipt, err := formalFinalizerHandoffRunImportIngressAtRoot(
				importRequest, stateRoot, false)
			if err != nil || receipt.Replayed ||
				receipt.EnvelopeSHA256 != descriptor.EnvelopeSHA256 {
				t.Fatalf("invalid command import: %#v / %v", receipt, err)
			}
			replay, err := formalFinalizerHandoffRunImportIngressAtRoot(
				importRequest, stateRoot, false)
			if err != nil || !replay.Replayed ||
				replay.EnvelopeSHA256 != descriptor.EnvelopeSHA256 {
				t.Fatalf("invalid restart replay: %#v / %v", replay, err)
			}
			encodedReceipt, err := json.Marshal(replay)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"ciphertext", "payload", "path"} {
				if strings.Contains(string(encodedReceipt), forbidden) {
					t.Fatalf("command receipt leaked %s", forbidden)
				}
			}
		})
	}
}

func TestFormalFinalizerHandoffBridgeCommandsFailClosed(t *testing.T) {
	fixture, stateRoot, garbler, garblerRoot, evaluator, evaluatorRoot :=
		formalFinalizerHandoffBridgeCommandFixture(t, 3)
	source := formalFinalizerHandoffBridgeCommandJSON(
		t, fixture, evaluator, evaluatorRoot, "", nil)
	descriptor, err := formalFinalizerHandoffRunSourceDescriptorAtRoot(
		source, stateRoot, false)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := os.ReadFile(descriptor.SourcePath)
	if err != nil {
		t.Fatal(err)
	}
	outer := base64.RawURLEncoding.EncodeToString(envelope)

	badPin := formalFinalizerHandoffBridgeCommandJSON(
		t, fixture, evaluator, evaluatorRoot, "", func(value map[string]any) {
			pins := value["pins"].(map[string]string)
			pins[evaluator.PeerName] = base64.StdEncoding.EncodeToString(
				make([]byte, ed25519.PublicKeySize))
		})
	if _, err := formalFinalizerHandoffRunSourceDescriptorAtRoot(
		badPin, stateRoot, false); err == nil {
		t.Fatal("tampered pinset was accepted")
	}
	extra := formalFinalizerHandoffBridgeCommandJSON(
		t, fixture, evaluator, evaluatorRoot, "", func(value map[string]any) {
			value["source_path"] = descriptor.SourcePath
		})
	if _, err := formalFinalizerHandoffRunSourceDescriptorAtRoot(
		extra, stateRoot, false); err == nil {
		t.Fatal("caller-selected source path was accepted")
	}
	if _, err := formalFinalizerHandoffRunImportIngressAtRoot(
		formalFinalizerHandoffBridgeCommandJSON(
			t, fixture, garbler, garblerRoot, "", nil), stateRoot, false); err == nil {
		t.Fatal("empty ingress was accepted")
	}
	tampered := []byte(outer)
	tampered[len(tampered)/2] = 'A'
	if string(tampered) == outer {
		tampered[len(tampered)/2] = 'B'
	}
	if _, err := formalFinalizerHandoffRunImportIngressAtRoot(
		formalFinalizerHandoffBridgeCommandJSON(
			t, fixture, garbler, garblerRoot, string(tampered), nil),
		stateRoot, false); err == nil {
		t.Fatal("tampered ingress was accepted")
	}
	if _, err := formalFinalizerHandoffRunSourceDescriptorAtRoot(
		formalFinalizerHandoffBridgeCommandJSON(
			t, fixture, garbler, garblerRoot, "", nil),
		stateRoot, false); err == nil {
		t.Fatal("garbler was accepted as bridge source")
	}
}
