package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func formalCoxControlCommandTestBase(
	values *formalCoxControlTestRecords,
	local formalFinalizerHandoffAuthority,
) formalCoxBlockwiseControlCommand {
	pins := make(map[string]string, len(values.fixture.pins))
	for peer, pin := range values.fixture.pins {
		pins[peer] = base64.StdEncoding.EncodeToString(pin)
	}
	return formalCoxBlockwiseControlCommand{
		Version: formalCoxControlCommandVersion,
		Plan:    values.fixture.plan, Binding: values.fixture.binding,
		LocalAuthority: local, Pins: pins,
	}
}

func formalCoxControlCommandTestEncode(t *testing.T,
	command formalCoxBlockwiseControlCommand,
) []byte {
	t.Helper()
	encoded, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestFormalCoxBlockwiseControlCommandSourceImportDeliveryK2K3K5(
	t *testing.T,
) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			values := newFormalCoxControlTestRecords(t, custodians)
			sides := formalCoxControlStoreTestSides(t, values)
			formalCoxControlStoreTestPopulate(t, values, sides)
			stateRoot := filepath.Dir(sides[0].root)
			now := time.Unix(1_900_100_000, 0)

			source := formalCoxControlCommandTestBase(
				values, sides[0].authority)
			source.RecipientTransportPublic = base64.StdEncoding.EncodeToString(
				sides[1].transport.PublicKey().Bytes())
			source.RecipientTransportSignature = base64.StdEncoding.EncodeToString(
				sides[1].signature)
			descriptor, err := formalCoxBlockwiseControlRunSourceAtRoot(
				formalCoxControlCommandTestEncode(t, source), stateRoot, false, now)
			if err != nil || descriptor.Context.AAD.RecordType !=
				formalCoxControlRecordPreflight {
				t.Fatalf("source command: %+v/%v", descriptor, err)
			}
			descriptorJSON, err := json.Marshal(descriptor)
			if err != nil || strings.Contains(string(descriptorJSON), "ciphertext") ||
				strings.Contains(string(descriptorJSON), "record_json") {
				t.Fatalf("source descriptor leaked payload: %v", err)
			}
			envelope := formalCoxControlStoreTestRead(t, descriptor)

			consumer := formalCoxControlCommandTestBase(
				values, sides[1].authority)
			consumer.RecipientTransportSecret = base64.StdEncoding.EncodeToString(
				sides[1].transport.Bytes())
			consumer.EnvelopeBase64URL = base64.RawURLEncoding.EncodeToString(
				envelope)
			ingress, err := formalCoxBlockwiseControlRunImportAtRoot(
				formalCoxControlCommandTestEncode(t, consumer), stateRoot, false, now)
			if err != nil || ingress.RecordType !=
				formalCoxControlRecordPreflight || ingress.Replayed {
				t.Fatalf("import command: %+v/%v", ingress, err)
			}

			delivery := formalCoxControlCommandTestBase(
				values, sides[0].authority)
			delivery.EnvelopeSHA256 = descriptor.EnvelopeSHA256
			delivery.ReceiptSHA256 = formalCoxControlSHA(
				formalCoxControlAADDomain+"typed-receipt|", []byte("command"))
			marked, err := formalCoxBlockwiseControlRunDeliveryAtRoot(
				formalCoxControlCommandTestEncode(t, delivery), stateRoot, false, now)
			if err != nil || marked.RecordType !=
				formalCoxControlRecordPreflight || marked.Replayed {
				t.Fatalf("delivery command: %+v/%v", marked, err)
			}

			store, err := newFormalCoxBlockwiseControlStore(
				sides[0].root, values.context, sides[0].authority, false)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			retained, err := store.RetainedBytes(now)
			if err != nil || retained != 0 {
				t.Fatalf("delivery retained %d bytes: %v", retained, err)
			}
		})
	}
}

func TestFormalCoxBlockwiseControlCommandRejectsOpenFieldsAndTamper(
	t *testing.T,
) {
	values := newFormalCoxControlTestRecords(t, 2)
	sides := formalCoxControlStoreTestSides(t, values)
	stateRoot := filepath.Dir(sides[0].root)
	now := time.Unix(1_900_100_000, 0)
	base := formalCoxControlCommandTestBase(values, sides[0].authority)
	if _, err := formalCoxBlockwiseControlRunSourceAtRoot(
		formalCoxControlCommandTestEncode(t, base), stateRoot, false, now); err == nil {
		t.Fatal("source accepted empty recipient binding")
	}
	base.RecipientTransportPublic = base64.StdEncoding.EncodeToString(
		make([]byte, 32))
	base.RecipientTransportSignature = base64.StdEncoding.EncodeToString(
		make([]byte, ed25519.SignatureSize))
	base.EnvelopeBase64URL = "AA"
	if _, err := formalCoxBlockwiseControlRunSourceAtRoot(
		formalCoxControlCommandTestEncode(t, base), stateRoot, false, now); err == nil {
		t.Fatal("source accepted an import field")
	}

	encoded := formalCoxControlCommandTestEncode(t,
		formalCoxControlCommandTestBase(values, sides[0].authority))
	encoded = append(encoded[:len(encoded)-1],
		[]byte(",\"record_type\":\"ticket\"}")...)
	if _, _, err := formalCoxBlockwiseControlDecodeCommand(encoded); err == nil {
		t.Fatal("command accepted caller-selected record type")
	}

	tampered := formalCoxControlCommandTestBase(values, sides[0].authority)
	for peer := range tampered.Pins {
		tampered.Pins[peer] = base64.StdEncoding.EncodeToString(
			make([]byte, ed25519.PublicKeySize))
		break
	}
	if _, _, err := formalCoxBlockwiseControlDecodeCommand(
		formalCoxControlCommandTestEncode(t, tampered)); err == nil {
		t.Fatal("command accepted a pinset/plan substitution")
	}
	tampered = formalCoxControlCommandTestBase(values, sides[0].authority)
	tampered.Binding.PlanSHA256 = formalFinalizerHandoffTestSHA(
		"substitute-control-plan")
	if _, _, err := formalCoxBlockwiseControlDecodeCommand(
		formalCoxControlCommandTestEncode(t, tampered)); err == nil {
		t.Fatal("command accepted a substituted signed binding")
	}
	tampered = formalCoxControlCommandTestBase(values, sides[0].authority)
	tampered.Plan.RunID = formalFinalizerHandoffTestSHA(
		"substitute-control-run")
	if _, _, err := formalCoxBlockwiseControlDecodeCommand(
		formalCoxControlCommandTestEncode(t, tampered)); err == nil {
		t.Fatal("command accepted a substituted execution plan")
	}
}
