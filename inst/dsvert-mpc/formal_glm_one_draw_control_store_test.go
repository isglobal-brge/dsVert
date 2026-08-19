package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type formalGLMControlStoreTestSide struct {
	root      string
	authority formalFinalizerHandoffAuthority
	transport *ecdh.PrivateKey
	signature []byte
}

func formalGLMControlStoreTestSides(t *testing.T,
	fixture formalFinalizerHandoffTestFixture,
) [2]formalGLMControlStoreTestSide {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var result [2]formalGLMControlStoreTestSide
	for index, authority := range fixture.binding.Authorities {
		root := filepath.Join(base, authority.PeerName)
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal(err)
		}
		transport, signature := formalGLMControlTestTransport(
			t, fixture.private[authority.PeerName])
		result[index] = formalGLMControlStoreTestSide{
			root: root, authority: authority,
			transport: transport, signature: signature,
		}
	}
	return result
}

func formalGLMControlStoreTestTicket(t *testing.T,
	fixture formalFinalizerHandoffTestFixture,
) formalFinalizerHandoffTicket {
	t.Helper()
	transport, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := formalFinalizerHandoffIssueTicket(
		fixture.binding, transport.PublicKey().Bytes(),
		fixture.private[fixture.binding.Finalizer.PeerName], fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	return ticket
}

func formalGLMControlStoreTestLifecyclePath(t *testing.T, root, artifactID,
	recordType, senderRole string,
) string {
	t.Helper()
	var path string
	var err error
	switch recordType {
	case formalGLMControlRecordStage:
		path, err = formalGLMPhase21RockStageRecordPath(
			root, artifactID, senderRole)
	case formalGLMControlRecordTicket:
		path, err = formalGLMPhase21RockTicketRecordPath(root, artifactID)
	case formalGLMControlRecordSealReceipt:
		path, err = formalGLMPhase21RockSealRecordPath(
			root, artifactID, senderRole)
	case formalGLMControlRecordCandidate:
		path, err = formalGLMPhase21RockCandidateRecordPath(root, artifactID)
	case formalGLMControlRecordLocalRelease:
		path, err = formalGLMPhase21RockLocalReleaseRecordPath(
			root, artifactID, senderRole)
	case formalGLMControlRecordBaseCertificate:
		path, err = formalGLMPhase21RockBaseCertificateRecordPath(
			root, artifactID)
	case formalGLMControlRecordAuthorization:
		path, err = formalGLMPhase21RockAuthorizationRecordPath(
			root, artifactID, senderRole)
	case formalGLMControlRecordAck:
		path, err = formalGLMPhase21RockAckRecordPath(root, artifactID)
	default:
		t.Fatalf("unknown control record %q", recordType)
	}
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func formalGLMControlStoreTestWriteRecord(t *testing.T, root string,
	fixture formalFinalizerHandoffTestFixture,
	ticket formalFinalizerHandoffTicket, recordType, senderRole string,
) []byte {
	t.Helper()
	record := formalGLMControlTestRecord(
		t, recordType, senderRole, fixture, ticket)
	path := formalGLMControlStoreTestLifecyclePath(
		t, root, fixture.binding.ArtifactID, recordType, senderRole)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, record, 0o600); err != nil {
		t.Fatal(err)
	}
	return record
}

func formalGLMControlStoreTestPopulateSources(t *testing.T,
	fixture formalFinalizerHandoffTestFixture,
	ticket formalFinalizerHandoffTicket,
	sides [2]formalGLMControlStoreTestSide,
) {
	t.Helper()
	for _, item := range []struct {
		rootIndex int
		record    string
		role      string
	}{
		{0, formalGLMControlRecordStage, "garbler"},
		{1, formalGLMControlRecordStage, "evaluator"},
		{0, formalGLMControlRecordTicket, "garbler"},
		{1, formalGLMControlRecordSealReceipt, "evaluator"},
		{0, formalGLMControlRecordCandidate, "garbler"},
		{1, formalGLMControlRecordLocalRelease, "evaluator"},
		{0, formalGLMControlRecordBaseCertificate, "garbler"},
		{0, formalGLMControlRecordAuthorization, "garbler"},
		{1, formalGLMControlRecordAuthorization, "evaluator"},
		{0, formalGLMControlRecordAck, "garbler"},
	} {
		formalGLMControlStoreTestWriteRecord(
			t, sides[item.rootIndex].root, fixture, ticket,
			item.record, item.role)
	}
}

func formalGLMControlStoreTestReadSource(t *testing.T,
	descriptor formalGLMOneDrawControlSourceDescriptor,
) []byte {
	t.Helper()
	encoded, err := os.ReadFile(descriptor.SourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(encoded)) != descriptor.EnvelopeBytes {
		t.Fatalf("source size %d != %d", len(encoded), descriptor.EnvelopeBytes)
	}
	return encoded
}

func TestFormalGLMOneDrawControlStoreK2K3K5BothDirections(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalFinalizerHandoffTestFixtureForK(
				t, custodians, formalFinalizerHandoffFamilyGLM)
			ticket := formalGLMControlStoreTestTicket(t, fixture)
			sides := formalGLMControlStoreTestSides(t, fixture)
			formalGLMControlStoreTestPopulateSources(
				t, fixture, ticket, sides)
			stores := [2]*formalGLMOneDrawControlStore{}
			for index := range stores {
				var err error
				stores[index], err = newFormalGLMOneDrawControlStore(
					sides[index].root, fixture.binding,
					sides[index].authority, fixture.public, false)
				if err != nil {
					t.Fatal(err)
				}
				defer stores[index].Close()
			}
			now := time.Unix(1_800_000_000, 0)
			steps := []struct {
				producer, consumer int
				record             string
			}{
				{0, 1, formalGLMControlRecordStage},
				{1, 0, formalGLMControlRecordStage},
				{0, 1, formalGLMControlRecordTicket},
				{1, 0, formalGLMControlRecordSealReceipt},
				{0, 1, formalGLMControlRecordCandidate},
				{1, 0, formalGLMControlRecordLocalRelease},
				{0, 1, formalGLMControlRecordBaseCertificate},
				{0, 1, formalGLMControlRecordAuthorization},
				{1, 0, formalGLMControlRecordAuthorization},
				{0, 1, formalGLMControlRecordAck},
			}
			for index, step := range steps {
				descriptor, err := stores[step.producer].DescribeNextSource(
					sides[step.consumer].transport.PublicKey().Bytes(),
					sides[step.consumer].signature, now)
				if err != nil {
					t.Fatalf("step %d source: %v", index, err)
				}
				if descriptor.Context.AAD.RecordType != step.record ||
					descriptor.Context.AAD.SenderRole !=
						sides[step.producer].authority.Role {
					t.Fatalf("step %d wrong descriptor: %+v", index, descriptor)
				}
				encoded := formalGLMControlStoreTestReadSource(t, descriptor)
				ingress, err := stores[step.consumer].ImportCanonical(
					encoded, sides[step.consumer].transport.Bytes(), now)
				if err != nil || ingress.RecordType != step.record || ingress.Replayed {
					t.Fatalf("step %d import: %+v %v", index, ingress, err)
				}
				replayedIngress, err := stores[step.consumer].ImportCanonical(
					encoded, sides[step.consumer].transport.Bytes(), now)
				if err != nil || !replayedIngress.Replayed {
					t.Fatalf("step %d ingress replay: %+v %v",
						index, replayedIngress, err)
				}
				receiptSHA := formalGLMControlSHA(
					formalGLMControlAADDomain+"typed-receipt|",
					[]byte(fmt.Sprintf("%d", index)))
				delivered, err := stores[step.producer].MarkNextDelivered(
					descriptor.EnvelopeSHA256, receiptSHA, now)
				if err != nil || delivered.RecordType != step.record ||
					delivered.Replayed {
					t.Fatalf("step %d delivery: %+v %v", index, delivered, err)
				}
				replayedDelivery, err := stores[step.producer].MarkNextDelivered(
					descriptor.EnvelopeSHA256, receiptSHA, now)
				if err != nil || !replayedDelivery.Replayed {
					t.Fatalf("step %d delivery replay: %+v %v",
						index, replayedDelivery, err)
				}
				now = now.Add(time.Second)
			}
			for index, store := range stores {
				if _, err := store.DescribeNextSource(
					sides[1-index].transport.PublicKey().Bytes(),
					sides[1-index].signature, now); !errors.Is(
					err, errFormalGLMControlNoSource) {
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

func TestFormalGLMOneDrawControlStoreRestartTTLRemintAndAccounting(t *testing.T) {
	fixture := formalFinalizerHandoffTestFixtureForK(
		t, 3, formalFinalizerHandoffFamilyGLM)
	ticket := formalGLMControlStoreTestTicket(t, fixture)
	sides := formalGLMControlStoreTestSides(t, fixture)
	formalGLMControlStoreTestWriteRecord(
		t, sides[0].root, fixture, ticket,
		formalGLMControlRecordStage, "garbler")
	now := time.Unix(1_800_000_000, 0)
	open := func() *formalGLMOneDrawControlStore {
		store, err := newFormalGLMOneDrawControlStore(
			sides[0].root, fixture.binding, sides[0].authority,
			fixture.public, false)
		if err != nil {
			t.Fatal(err)
		}
		return store
	}
	store := open()
	first, err := store.DescribeNextSource(
		sides[1].transport.PublicKey().Bytes(), sides[1].signature, now)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := store.RetainedBytes(now)
	if err != nil || retained < first.EnvelopeBytes ||
		retained > formalGLMControlMaxEnvelope+4096 {
		t.Fatalf("unexpected retained bytes %d: %v", retained, err)
	}
	store.Close()
	store = open()
	restarted, err := store.DescribeNextSource(
		sides[1].transport.PublicKey().Bytes(), sides[1].signature, now)
	if err != nil || restarted.EnvelopeSHA256 != first.EnvelopeSHA256 ||
		restarted.SourcePath != first.SourcePath {
		t.Fatalf("restart changed outbox: %+v %v", restarted, err)
	}
	rotated, rotatedSignature := formalGLMControlTestTransport(
		t, fixture.private[sides[1].authority.PeerName])
	if _, err := store.DescribeNextSource(
		rotated.PublicKey().Bytes(), rotatedSignature,
		now.Add(formalGLMControlOutboxTTL-time.Second)); err == nil {
		t.Fatal("recipient key rotated before the outbox lease expired")
	}
	reminted, err := store.DescribeNextSource(
		rotated.PublicKey().Bytes(), rotatedSignature,
		now.Add(formalGLMControlOutboxTTL+time.Second))
	if err != nil || reminted.EnvelopeSHA256 == first.EnvelopeSHA256 ||
		reminted.Context.RecordSHA256 != first.Context.RecordSHA256 {
		t.Fatalf("post-TTL remint failed: %+v %v", reminted, err)
	}
	if _, err := os.Lstat(first.SourcePath); !os.IsNotExist(err) {
		t.Fatal("expired outbox was not swept")
	}
	receiptSHA := formalGLMControlSHA(
		formalGLMControlAADDomain+"typed-receipt|", []byte("remint"))
	if _, err := store.MarkNextDelivered(
		reminted.EnvelopeSHA256, receiptSHA,
		now.Add(formalGLMControlOutboxTTL+time.Second)); err != nil {
		t.Fatal(err)
	}
	retained, err = store.RetainedBytes(
		now.Add(formalGLMControlOutboxTTL + time.Second))
	if err != nil || retained != 0 {
		t.Fatalf("delivered outbox retained %d bytes: %v", retained, err)
	}
	store.Close()
}

func TestFormalGLMOneDrawControlStoreRejectsReorderTamperAndUnsafeOutbox(t *testing.T) {
	fixture := formalFinalizerHandoffTestFixtureForK(
		t, 3, formalFinalizerHandoffFamilyGLM)
	ticket := formalGLMControlStoreTestTicket(t, fixture)
	sides := formalGLMControlStoreTestSides(t, fixture)
	stores := [2]*formalGLMOneDrawControlStore{}
	for index := range stores {
		var err error
		stores[index], err = newFormalGLMOneDrawControlStore(
			sides[index].root, fixture.binding, sides[index].authority,
			fixture.public, false)
		if err != nil {
			t.Fatal(err)
		}
		defer stores[index].Close()
	}
	now := time.Unix(1_800_000_000, 0)
	candidate := formalGLMControlTestRecord(
		t, formalGLMControlRecordCandidate, "garbler", fixture, ticket)
	candidateEnvelope, err := formalGLMOneDrawControlSeal(
		fixture.binding, formalGLMControlRecordCandidate, "garbler",
		candidate, ticket, sides[1].transport.PublicKey().Bytes(),
		sides[1].signature, fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	encodedCandidate, err := formalGLMControlMarshalEnvelope(candidateEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stores[1].ImportCanonical(
		encodedCandidate, sides[1].transport.Bytes(), now); err == nil {
		t.Fatal("candidate import skipped the stage and ticket sequence")
	}
	formalGLMControlStoreTestWriteRecord(
		t, sides[0].root, fixture, ticket,
		formalGLMControlRecordStage, "garbler")
	descriptor, err := stores[0].DescribeNextSource(
		sides[1].transport.PublicKey().Bytes(), sides[1].signature, now)
	if err != nil {
		t.Fatal(err)
	}
	encoded := formalGLMControlStoreTestReadSource(t, descriptor)
	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)/2] ^= 1
	if _, err := stores[1].ImportCanonical(
		tampered, sides[1].transport.Bytes(), now); err == nil {
		t.Fatal("tampered outbox was imported")
	}
	if err := os.Chmod(descriptor.SourcePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := stores[0].DescribeNextSource(
		sides[1].transport.PublicKey().Bytes(), sides[1].signature, now); err == nil {
		t.Fatal("world-readable outbox was replayed")
	}
	if err := os.Chmod(descriptor.SourcePath, 0o600); err != nil {
		t.Fatal(err)
	}
	oversized := make([]byte, formalGLMControlMaxRecord+1)
	if _, err := formalGLMOneDrawControlSeal(
		fixture.binding, formalGLMControlRecordStage, "garbler", oversized,
		formalFinalizerHandoffTicket{},
		sides[1].transport.PublicKey().Bytes(), sides[1].signature,
		fixture.public); err == nil {
		t.Fatal("oversized control record was sealed")
	}
}

func TestFormalGLMOneDrawControlStoreRestartReplay(t *testing.T) {
	fixture := formalFinalizerHandoffTestFixtureForK(
		t, 2, formalFinalizerHandoffFamilyGLM)
	ticket := formalGLMControlStoreTestTicket(t, fixture)
	sides := formalGLMControlStoreTestSides(t, fixture)
	formalGLMControlStoreTestWriteRecord(
		t, sides[0].root, fixture, ticket,
		formalGLMControlRecordStage, "garbler")
	producer, err := newFormalGLMOneDrawControlStore(
		sides[0].root, fixture.binding, sides[0].authority,
		fixture.public, false)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	descriptor, err := producer.DescribeNextSource(
		sides[1].transport.PublicKey().Bytes(), sides[1].signature, now)
	if err != nil {
		t.Fatal(err)
	}
	encoded := formalGLMControlStoreTestReadSource(t, descriptor)
	producer.Close()
	consumer, err := newFormalGLMOneDrawControlStore(
		sides[1].root, fixture.binding, sides[1].authority,
		fixture.public, false)
	if err != nil {
		t.Fatal(err)
	}
	first, err := consumer.ImportCanonical(
		encoded, sides[1].transport.Bytes(), now)
	if err != nil || first.Replayed {
		t.Fatalf("first ingress: %+v %v", first, err)
	}
	consumer.Close()
	consumer, err = newFormalGLMOneDrawControlStore(
		sides[1].root, fixture.binding, sides[1].authority,
		fixture.public, false)
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	replay, err := consumer.ImportCanonical(
		encoded, sides[1].transport.Bytes(), now.Add(time.Second))
	if err != nil || !replay.Replayed || replay.RecordSHA256 != first.RecordSHA256 {
		t.Fatalf("restart ingress replay: %+v %v", replay, err)
	}
}

func TestFormalGLMOneDrawControlStoreRecordHashUsesExactBytes(t *testing.T) {
	value := []byte("control-record")
	want := sha256.Sum256(append(
		[]byte(formalGLMControlRecordDomain), value...))
	if got := formalGLMControlSHA(formalGLMControlRecordDomain, value); got != fmt.Sprintf("%x", want[:]) {
		t.Fatal("record hash domain changed")
	}
}
