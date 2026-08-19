package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type formalCoxControlStoreTestSide struct {
	root      string
	authority formalFinalizerHandoffAuthority
	transport *ecdh.PrivateKey
	signature []byte
}

func TestFormalCoxBlockwiseControlStoreRejectsReorderTamperAndMix(t *testing.T) {
	values := newFormalCoxControlTestRecords(t, 3)
	sides := formalCoxControlStoreTestSides(t, values)
	stores := [2]*formalCoxBlockwiseControlStore{}
	for index := range stores {
		var err error
		stores[index], err = newFormalCoxBlockwiseControlStore(
			sides[index].root, values.context, sides[index].authority, false)
		if err != nil {
			t.Fatal(err)
		}
		defer stores[index].Close()
	}
	now := time.Unix(1_900_000_000, 0)
	candidate := values.records[formalCoxControlTestRecordKey(
		formalCoxControlRecordCandidate, "garbler")]
	candidateEnvelope, err := formalCoxBlockwiseControlSeal(
		values.context, values.fixture.binding,
		formalCoxControlRecordCandidate, "garbler", candidate,
		values.fixture.ticket, sides[1].transport.PublicKey().Bytes(),
		sides[1].signature, values.related)
	if err != nil {
		t.Fatal(err)
	}
	encodedCandidate, err := formalCoxControlMarshalEnvelope(candidateEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stores[1].ImportCanonical(
		encodedCandidate, sides[1].transport.Bytes(), now); err == nil {
		t.Fatal("candidate import skipped preflight/header/ticket/envelope state")
	}

	preflightPath, err := formalCoxControlLifecyclePath(
		sides[0].root, values.context, formalCoxControlRecordPreflight,
		"garbler")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(preflightPath), 0o700); err != nil ||
		os.Chmod(filepath.Dir(preflightPath), 0o700) != nil ||
		os.WriteFile(preflightPath, values.records[formalCoxControlTestRecordKey(
			formalCoxControlRecordPreflight, "garbler")], 0o600) != nil {
		t.Fatal("write preflight source")
	}
	descriptor, err := stores[0].DescribeNextSource(
		sides[1].transport.PublicKey().Bytes(), sides[1].signature, now)
	if err != nil {
		t.Fatal(err)
	}
	encoded := formalCoxControlStoreTestRead(t, descriptor)
	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)/2] ^= 1
	if _, err := stores[1].ImportCanonical(
		tampered, sides[1].transport.Bytes(), now); err == nil {
		t.Fatal("tampered envelope was imported")
	}
	envelope, err := formalCoxControlDecodeEnvelope(encoded)
	if err != nil {
		t.Fatal(err)
	}
	envelope.AAD.Family = formalFinalizerHandoffFamilyGLM
	crossFamily := formalCoxControlTestMarshal(t, envelope)
	if _, err := stores[1].ImportCanonical(
		crossFamily, sides[1].transport.Bytes(), now); err == nil {
		t.Fatal("cross-family envelope was imported")
	}
	envelope, err = formalCoxControlDecodeEnvelope(encoded)
	if err != nil {
		t.Fatal(err)
	}
	envelope.AAD.RecipientRole = "garbler"
	wrongRole := formalCoxControlTestMarshal(t, envelope)
	if _, err := stores[1].ImportCanonical(
		wrongRole, sides[1].transport.Bytes(), now); err == nil {
		t.Fatal("role-substituted envelope was imported")
	}
	if err := os.Chmod(descriptor.SourcePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := stores[0].DescribeNextSource(
		sides[1].transport.PublicKey().Bytes(), sides[1].signature, now); err == nil {
		t.Fatal("world-readable durable outbox was reused")
	}
}

func TestFormalCoxBlockwiseControlPublishedRepairNewRunNoReroll(t *testing.T) {
	values := newFormalCoxControlTestRecords(t, 2)
	context := values.context
	authority := context.Authorities[0]
	publication := values.publication.Publication
	receipt := formalCoxBlockwiseRockPreflightReceipt{
		Version:    formalCoxBlockwiseRockRecordVersion,
		Purpose:    formalCoxBlockwiseRockPreflightPurpose,
		ArtifactID: context.ArtifactID, PinsetSHA256: context.PinsetSHA256,
		PeerName: authority.PeerName, PeerID: authority.PeerID,
		Role: authority.Role, State: formalCoxBlockwiseRockStatePublished,
		CertificateSHA256: publication.CertificateSHA256,
		ProductionReady:   false,
	}
	message, err := formalCoxBlockwiseRockPreflightMessage(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Signature = ed25519.Sign(
		values.fixture.private[authority.PeerName], message)
	record := formalCoxControlTestMarshal(t,
		formalCoxBlockwiseRockPreflightRecord{
			Version: formalCoxBlockwiseRockRecordVersion,
			Family:  formalFinalizerHandoffFamilyCox,
			Purpose: formalCoxBlockwiseRockPreflightPurpose,
			Receipt: receipt, Publication: &publication, ProductionReady: false,
		})
	alternatePlan := values.fixture.plan
	alternatePlan.RunID = formalFinalizerHandoffTestSHA("control-repair-new-run")
	alternate, err := formalCoxControlContextFor(alternatePlan, values.fixture.pins)
	if err != nil || alternate.ArtifactID != context.ArtifactID ||
		alternate.ExecutionSHA256 == context.ExecutionSHA256 {
		t.Fatalf("invalid same-artifact alternate run: %#v/%v", alternate, err)
	}
	transport, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipient := alternate.Authorities[1]
	signature := ed25519.Sign(
		values.fixture.private[recipient.PeerName], transport.PublicKey().Bytes())
	envelope, err := formalCoxBlockwiseControlSeal(
		alternate, formalFinalizerHandoffBinding{},
		formalCoxControlRecordPreflight, "garbler", record,
		formalFinalizerHandoffTicket{}, transport.PublicKey().Bytes(), signature,
		formalCoxBlockwiseControlRelated{})
	if err != nil {
		t.Fatalf("new-run published preflight seal: %v", err)
	}
	opened, err := formalCoxBlockwiseControlOpen(
		alternate, formalFinalizerHandoffBinding{}, envelope,
		formalFinalizerHandoffTicket{}, transport.Bytes(),
		formalCoxBlockwiseControlRelated{})
	if err != nil || !bytes.Equal(opened, record) {
		t.Fatalf("new-run published preflight open: %v", err)
	}
	if _, err := formalCoxBlockwiseControlOpen(
		context, formalFinalizerHandoffBinding{}, envelope,
		formalFinalizerHandoffTicket{}, transport.Bytes(),
		formalCoxBlockwiseControlRelated{}); err == nil {
		t.Fatal("new-run repair envelope mixed into prior execution")
	}
}

func formalCoxControlStoreTestSides(t *testing.T,
	values *formalCoxControlTestRecords,
) [2]formalCoxControlStoreTestSide {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var sides [2]formalCoxControlStoreTestSide
	for index, authority := range values.context.Authorities {
		root := filepath.Join(base, authority.PeerName)
		if err := os.MkdirAll(root, 0o700); err != nil ||
			os.Chmod(root, 0o700) != nil {
			t.Fatal("private control test root")
		}
		transport, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		sides[index] = formalCoxControlStoreTestSide{
			root: root, authority: authority, transport: transport,
			signature: ed25519.Sign(
				values.fixture.private[authority.PeerName],
				transport.PublicKey().Bytes()),
		}
	}
	return sides
}

func formalCoxControlStoreTestPopulate(t *testing.T,
	values *formalCoxControlTestRecords,
	sides [2]formalCoxControlStoreTestSide,
) {
	t.Helper()
	for key, encoded := range values.records {
		recordType, senderRole, found := stringsCutControlKey(key)
		if !found {
			t.Fatalf("invalid control record key %q", key)
		}
		position := 0
		if senderRole == "evaluator" {
			position = 1
		}
		path, err := formalCoxControlLifecyclePath(
			sides[position].root, values.context, recordType, senderRole)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil ||
			os.Chmod(filepath.Dir(path), 0o700) != nil ||
			os.WriteFile(path, encoded, 0o600) != nil {
			t.Fatalf("write lifecycle source %s", key)
		}
	}
}

func stringsCutControlKey(value string) (string, string, bool) {
	for index := range value {
		if value[index] == '/' {
			return value[:index], value[index+1:], true
		}
	}
	return "", "", false
}

func formalCoxControlStoreTestRead(t *testing.T,
	descriptor formalCoxBlockwiseControlSourceDescriptor,
) []byte {
	t.Helper()
	encoded, err := os.ReadFile(descriptor.SourcePath)
	if err != nil || int64(len(encoded)) != descriptor.EnvelopeBytes {
		t.Fatalf("read source descriptor: %d/%v", len(encoded), err)
	}
	return encoded
}

func TestFormalCoxBlockwiseControlStoreK2K3K5BothDirections(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			values := newFormalCoxControlTestRecords(t, custodians)
			sides := formalCoxControlStoreTestSides(t, values)
			formalCoxControlStoreTestPopulate(t, values, sides)
			var stores [2]*formalCoxBlockwiseControlStore
			for index := range stores {
				var err error
				stores[index], err = newFormalCoxBlockwiseControlStore(
					sides[index].root, values.context,
					sides[index].authority, false)
				if err != nil {
					t.Fatal(err)
				}
				defer stores[index].Close()
			}
			now := time.Unix(1_900_000_000, 0)
			steps := []struct {
				producer int
				consumer int
				record   string
			}{
				{0, 1, formalCoxControlRecordPreflight},
				{1, 0, formalCoxControlRecordPreflight},
				{0, 1, formalCoxControlRecordHeader},
				{1, 0, formalCoxControlRecordHeader},
				{0, 1, formalCoxControlRecordTicket},
				{1, 0, formalCoxControlRecordEnvelope},
				{0, 1, formalCoxControlRecordCandidate},
				{0, 1, formalCoxControlRecordAuthorization},
				{1, 0, formalCoxControlRecordAuthorization},
				{0, 1, formalCoxControlRecordPublication},
				{1, 0, formalCoxControlRecordCommit},
				{0, 1, formalCoxControlRecordAck},
			}
			for index, step := range steps {
				descriptor, err := stores[step.producer].DescribeNextSource(
					sides[step.consumer].transport.PublicKey().Bytes(),
					sides[step.consumer].signature, now)
				if err != nil || descriptor.Context.AAD.RecordType != step.record {
					t.Fatalf("step %d source: %+v/%v", index, descriptor, err)
				}
				encoded := formalCoxControlStoreTestRead(t, descriptor)
				ingress, err := stores[step.consumer].ImportCanonical(
					encoded, sides[step.consumer].transport.Bytes(), now)
				if err != nil || ingress.RecordType != step.record || ingress.Replayed {
					t.Fatalf("step %d ingress: %+v/%v", index, ingress, err)
				}
				replay, err := stores[step.consumer].ImportCanonical(
					encoded, sides[step.consumer].transport.Bytes(), now)
				if err != nil || !replay.Replayed {
					t.Fatalf("step %d ingress replay: %+v/%v", index, replay, err)
				}
				receiptSHA := formalCoxControlSHA(
					formalCoxControlAADDomain+"typed-receipt|",
					[]byte(fmt.Sprintf("%d", index)))
				delivery, err := stores[step.producer].MarkNextDelivered(
					descriptor.EnvelopeSHA256, receiptSHA, now)
				if err != nil || delivery.RecordType != step.record || delivery.Replayed {
					t.Fatalf("step %d delivery: %+v/%v", index, delivery, err)
				}
				now = now.Add(time.Second)
			}
			for index, store := range stores {
				if _, err := store.DescribeNextSource(
					sides[1-index].transport.PublicKey().Bytes(),
					sides[1-index].signature, now); !errors.Is(
					err, errFormalCoxControlNoSource) {
					t.Fatalf("authority %d was not terminal: %v", index, err)
				}
				retained, err := store.RetainedBytes(now)
				if err != nil || retained != 0 {
					t.Fatalf("authority %d retained %d: %v", index, retained, err)
				}
			}
		})
	}
}

func TestFormalCoxBlockwiseControlStoreRestartTTLRemint(t *testing.T) {
	values := newFormalCoxControlTestRecords(t, 3)
	sides := formalCoxControlStoreTestSides(t, values)
	path, err := formalCoxControlLifecyclePath(
		sides[0].root, values.context, formalCoxControlRecordPreflight,
		"garbler")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil ||
		os.Chmod(filepath.Dir(path), 0o700) != nil ||
		os.WriteFile(path, values.records[formalCoxControlTestRecordKey(
			formalCoxControlRecordPreflight, "garbler")], 0o600) != nil {
		t.Fatal("write preflight source")
	}
	open := func() *formalCoxBlockwiseControlStore {
		store, err := newFormalCoxBlockwiseControlStore(
			sides[0].root, values.context, sides[0].authority, false)
		if err != nil {
			t.Fatal(err)
		}
		return store
	}
	now := time.Unix(1_900_000_000, 0)
	store := open()
	first, err := store.DescribeNextSource(
		sides[1].transport.PublicKey().Bytes(), sides[1].signature, now)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := store.RetainedBytes(now)
	if err != nil || retained < first.EnvelopeBytes {
		t.Fatalf("invalid retained accounting %d/%v", retained, err)
	}
	store.Close()
	store = open()
	restarted, err := store.DescribeNextSource(
		sides[1].transport.PublicKey().Bytes(), sides[1].signature, now)
	if err != nil || restarted.EnvelopeSHA256 != first.EnvelopeSHA256 {
		t.Fatalf("restart changed outbox: %+v/%v", restarted, err)
	}
	rotated, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rotatedSignature := ed25519.Sign(
		values.fixture.private[sides[1].authority.PeerName],
		rotated.PublicKey().Bytes())
	if _, err := store.DescribeNextSource(
		rotated.PublicKey().Bytes(), rotatedSignature,
		now.Add(formalCoxControlOutboxTTL-time.Second)); !errors.Is(
		err, errFormalCoxControlOutboxLease) {
		t.Fatalf("active lease was rotated: %v", err)
	}
	reminted, err := store.DescribeNextSource(
		rotated.PublicKey().Bytes(), rotatedSignature,
		now.Add(formalCoxControlOutboxTTL+time.Second))
	if err != nil || reminted.EnvelopeSHA256 == first.EnvelopeSHA256 ||
		reminted.Context.RecordSHA256 != first.Context.RecordSHA256 {
		t.Fatalf("post-TTL remint failed: %+v/%v", reminted, err)
	}
	if _, err := os.Lstat(first.SourcePath); !os.IsNotExist(err) {
		t.Fatal("expired outbox was not swept")
	}
	store.Close()
}
