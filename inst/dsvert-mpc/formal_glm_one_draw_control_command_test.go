package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func formalGLMControlCommandTestBase(
	fixture formalFinalizerHandoffTestFixture,
	local formalFinalizerHandoffAuthority,
) formalGLMOneDrawControlCommand {
	pins := make(map[string]string, len(fixture.public))
	for peer, pin := range fixture.public {
		pins[peer] = base64.StdEncoding.EncodeToString(pin)
	}
	return formalGLMOneDrawControlCommand{
		Version: formalGLMControlCommandVersion,
		Binding: fixture.binding, LocalAuthority: local, Pins: pins,
	}
}

func formalGLMControlCommandTestEncode(t *testing.T,
	command formalGLMOneDrawControlCommand,
) []byte {
	t.Helper()
	encoded, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestFormalGLMOneDrawControlCommandSourceImportDelivery(t *testing.T) {
	fixture := formalFinalizerHandoffTestFixtureForK(
		t, 3, formalFinalizerHandoffFamilyGLM)
	ticket := formalGLMControlStoreTestTicket(t, fixture)
	sides := formalGLMControlStoreTestSides(t, fixture)
	formalGLMControlStoreTestWriteRecord(
		t, sides[0].root, fixture, ticket,
		formalGLMControlRecordStage, "garbler")
	stateRoot := filepath.Dir(sides[0].root)
	now := time.Unix(1_800_000_000, 0)
	source := formalGLMControlCommandTestBase(fixture, sides[0].authority)
	source.RecipientTransportPublic = base64.StdEncoding.EncodeToString(
		sides[1].transport.PublicKey().Bytes())
	source.RecipientTransportSignature = base64.StdEncoding.EncodeToString(
		sides[1].signature)
	descriptor, err := formalGLMOneDrawControlRunSourceAtRoot(
		formalGLMControlCommandTestEncode(t, source), stateRoot, false, now)
	if err != nil || descriptor.Context.AAD.RecordType !=
		formalGLMControlRecordStage {
		t.Fatalf("source command: %+v %v", descriptor, err)
	}
	envelope := formalGLMControlStoreTestReadSource(t, descriptor)
	consumer := formalGLMControlCommandTestBase(fixture, sides[1].authority)
	consumer.RecipientTransportSecret = base64.StdEncoding.EncodeToString(
		sides[1].transport.Bytes())
	consumer.EnvelopeBase64URL = base64.RawURLEncoding.EncodeToString(envelope)
	ingress, err := formalGLMOneDrawControlRunImportAtRoot(
		formalGLMControlCommandTestEncode(t, consumer), stateRoot, false, now)
	if err != nil || ingress.RecordType != formalGLMControlRecordStage ||
		ingress.Replayed {
		t.Fatalf("import command: %+v %v", ingress, err)
	}
	delivery := formalGLMControlCommandTestBase(fixture, sides[0].authority)
	delivery.EnvelopeSHA256 = descriptor.EnvelopeSHA256
	delivery.ReceiptSHA256 = formalGLMControlSHA(
		formalGLMControlAADDomain+"typed-receipt|", []byte("command"))
	marked, err := formalGLMOneDrawControlRunDeliveryAtRoot(
		formalGLMControlCommandTestEncode(t, delivery), stateRoot, false, now)
	if err != nil || marked.RecordType != formalGLMControlRecordStage ||
		marked.Replayed {
		t.Fatalf("delivery command: %+v %v", marked, err)
	}
}

func TestFormalGLMOneDrawControlCommandRejectsOpenFieldsAndEmpty(t *testing.T) {
	fixture := formalFinalizerHandoffTestFixtureForK(
		t, 2, formalFinalizerHandoffFamilyGLM)
	sides := formalGLMControlStoreTestSides(t, fixture)
	stateRoot := filepath.Dir(sides[0].root)
	base := formalGLMControlCommandTestBase(fixture, sides[0].authority)
	if _, err := formalGLMOneDrawControlRunSourceAtRoot(
		formalGLMControlCommandTestEncode(t, base), stateRoot, false,
		time.Unix(1_800_000_000, 0)); err == nil {
		t.Fatal("source accepted empty recipient binding")
	}
	base.RecipientTransportPublic = base64.StdEncoding.EncodeToString(
		make([]byte, 32))
	base.RecipientTransportSignature = base64.StdEncoding.EncodeToString(
		make([]byte, ed25519.SignatureSize))
	base.EnvelopeBase64URL = "AA"
	if _, err := formalGLMOneDrawControlRunSourceAtRoot(
		formalGLMControlCommandTestEncode(t, base), stateRoot, false,
		time.Unix(1_800_000_000, 0)); err == nil {
		t.Fatal("source accepted an import field")
	}
	encoded := formalGLMControlCommandTestEncode(t,
		formalGLMControlCommandTestBase(fixture, sides[0].authority))
	encoded = append(encoded[:len(encoded)-1], []byte(",\"record_type\":\"stage\"}")...)
	if _, _, err := formalGLMOneDrawControlDecodeCommand(encoded); err == nil {
		t.Fatal("command accepted analyst-chosen record_type")
	}
}
