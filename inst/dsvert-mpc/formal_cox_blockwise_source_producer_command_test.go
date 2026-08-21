package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func formalCoxBlockwiseSourceProducerCommandTestRoot(t testing.TB) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "rock")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func formalCoxBlockwiseSourceProducerCommandTestRequest(t testing.TB,
	custodians int,
) (formalCoxBlockwiseSourceProducerCommand, *formalCoxBlockwiseSourceSession,
	map[string][]byte, []*big.Int) {
	t.Helper()
	fixture := formalCoxRSourceBridgeFixtureFor(t, custodians)
	compiled, err := formalCoxCompileSignedRSchema(
		json.RawMessage(fixture.SchemaJSON))
	if err != nil {
		t.Fatal(err)
	}
	runID := sha256.Sum256([]byte("formal-cox-source-command/" +
		fmt.Sprint(custodians)))
	plan, err := buildFormalCoxBlockwisePlan(
		compiled.Policy, 2, hex.EncodeToString(runID[:]))
	if err != nil {
		t.Fatal(err)
	}
	pins := formalCoxRSourceBridgePins(t, json.RawMessage(fixture.SchemaJSON))
	signing := formalCoxRSourceBridgePrivateKeys(t, fixture.Seeds)
	session, _, transportSecret := formalCoxBlockwiseSourceTestSession(
		t, plan, pins, signing)
	source := plan.Policy.CustodianPeers[0]
	lines := fixture.Blocks[source][0]
	values := formalCoxRSourceBridgeExpected(t, lines,
		plan.BlockCapacity*plan.RowWidth, plan.RingBits)
	input := []byte(strings.Join(lines, "\n") + "\n")
	encodedPins := make(map[string]string, len(pins))
	for peer, pin := range pins {
		encodedPins[peer] = base64.StdEncoding.EncodeToString(pin)
	}
	tickets := make([]formalCoxBlockwiseSourceRecipientTicket,
		len(session.manifest.Tickets))
	for index := range tickets {
		tickets[index] = formalCoxBlockwiseSourceCloneTicket(
			session.manifest.Tickets[index])
	}
	return formalCoxBlockwiseSourceProducerCommand{
		Version:       formalCoxBlockwiseSourceProducerCommandVersion,
		Schema:        json.RawMessage(append([]byte(nil), fixture.SchemaJSON...)),
		BlockCapacity: plan.BlockCapacity, RunID: plan.RunID,
		Pins: encodedPins, RecipientTickets: tickets,
		SourcePeerName:       source,
		SourceSigningKey:     base64.StdEncoding.EncodeToString(signing[source]),
		BlockIndex:           0,
		CanonicalInputBase64: base64.StdEncoding.EncodeToString(input),
	}, session, transportSecret, values
}

func formalCoxBlockwiseSourceProducerCommandTestRun(t testing.TB,
	command formalCoxBlockwiseSourceProducerCommand, root string,
) (formalCoxBlockwiseSourceProductionResult, []byte) {
	t.Helper()
	encoded, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	result, err := formalCoxBlockwiseSourceProducerRunAtRoot(encoded, root, false)
	if err != nil {
		t.Fatal(err)
	}
	return result, encoded
}

func TestFormalCoxBlockwiseSourceProducerCommandK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			command, session, transportSecret, values :=
				formalCoxBlockwiseSourceProducerCommandTestRequest(t, custodians)
			defer exactGCZeroBigInts(values)
			root := formalCoxBlockwiseSourceProducerCommandTestRoot(t)
			result, encoded := formalCoxBlockwiseSourceProducerCommandTestRun(
				t, command, root)
			if result.Replayed || result.ReceiptSHA256 == "" ||
				result.Receipt.Binding.SourcePeerName != command.SourcePeerName ||
				result.Receipt.Binding.BlockIndex != command.BlockIndex {
				t.Fatalf("invalid command result: %+v", result)
			}
			replayed, err := formalCoxBlockwiseSourceProducerRunAtRoot(
				encoded, root, false)
			if err != nil || !replayed.Replayed ||
				replayed.ReceiptSHA256 != result.ReceiptSHA256 {
				t.Fatalf("command replay: %+v / %v", replayed, err)
			}

			producerRoot, key, err := formalCoxBlockwiseSourceProducerCommandRoot(
				root, false, session.context.plan, command.SourcePeerName,
				command.SourceSigningKey)
			if err != nil {
				t.Fatal(err)
			}
			private := mustFormalCoxBlockwiseSourceProducerCommandTestKey(t,
				command.SourceSigningKey)
			producer, err := newFormalCoxBlockwiseSourceProducer(
				producerRoot, key, session, command.SourcePeerName, private)
			clear(private)
			if err != nil {
				t.Fatal(err)
			}
			defer producer.Close()
			opened := formalCoxBlockwiseSourceProducerTestOpen(
				t, producer, session, transportSecret, command.BlockIndex)
			modulus := exactGCModulus(session.context.plan.RingBits)
			for index, want := range values {
				got := new(big.Int).Add(
					opened[session.context.plan.Policy.ComputePeers[0]][index],
					opened[session.context.plan.Policy.ComputePeers[1]][index])
				got.Mod(got, modulus)
				if got.Cmp(formalCoxResidue(want, session.context.plan.RingBits)) != 0 {
					t.Fatalf("coordinate %d: got %s want %s", index, got, want)
				}
			}
			exactGCZeroBigInts(opened[session.context.plan.Policy.ComputePeers[0]])
			exactGCZeroBigInts(opened[session.context.plan.Policy.ComputePeers[1]])
		})
	}
}

func mustFormalCoxBlockwiseSourceProducerCommandTestKey(t testing.TB,
	encoded string,
) ed25519.PrivateKey {
	t.Helper()
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != ed25519.PrivateKeySize ||
		base64.StdEncoding.EncodeToString(decoded) != encoded {
		t.Fatal("invalid test source signing key")
	}
	return ed25519.PrivateKey(decoded)
}

func TestFormalCoxBlockwiseSourceProducerCommandRejectsOpenAndTamperedInput(t *testing.T) {
	command, _, _, _ := formalCoxBlockwiseSourceProducerCommandTestRequest(t, 2)
	canonical, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(canonical, &object); err != nil {
		t.Fatal(err)
	}
	object["path"] = "/caller-selected"
	unknown, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	delete(object, "path")
	object["source_peer_name"] = "outsider"
	wrongSource, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	delete(object, "source_peer_name")
	object["canonical_input_base64"] = base64.StdEncoding.EncodeToString(
		[]byte("not-a-complete-canonical-block\n"))
	wrongInput, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	badSchema := command
	var schema map[string]any
	if err := json.Unmarshal(badSchema.Schema, &schema); err != nil {
		t.Fatal(err)
	}
	schema["schema_sha256"] = strings.Repeat("0", 64)
	badSchema.Schema, err = json.Marshal(schema)
	if err != nil {
		t.Fatal(err)
	}
	tamperedSchema, err := json.Marshal(badSchema)
	if err != nil {
		t.Fatal(err)
	}
	badTicket := command
	badTicket.RecipientTickets = append(
		[]formalCoxBlockwiseSourceRecipientTicket(nil), command.RecipientTickets...)
	badTicket.RecipientTickets[0] = formalCoxBlockwiseSourceCloneTicket(
		badTicket.RecipientTickets[0])
	badTicket.RecipientTickets[0].Signature[0] ^= 1
	tamperedTicket, err := json.Marshal(badTicket)
	if err != nil {
		t.Fatal(err)
	}
	for name, encoded := range map[string][]byte{
		"unknown": unknown, "wrong source": wrongSource,
		"wrong input":               wrongInput,
		"tampered schema":           tamperedSchema,
		"tampered recipient ticket": tamperedTicket,
		"trailing":                  append(append([]byte(nil), canonical...), []byte("{}")...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := formalCoxBlockwiseSourceProducerRunAtRoot(
				encoded, formalCoxBlockwiseSourceProducerCommandTestRoot(t), false); err == nil {
				t.Fatal("source producer command accepted open or invalid input")
			}
		})
	}
}

func TestFormalCoxBlockwiseSourceProducerCommandAllowsOuterJSONFormatting(t *testing.T) {
	command, _, _, _ := formalCoxBlockwiseSourceProducerCommandTestRequest(t, 2)
	canonical, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	var formatted bytes.Buffer
	if err := json.Indent(&formatted, canonical, "", "  "); err != nil {
		t.Fatal(err)
	}
	root := formalCoxBlockwiseSourceProducerCommandTestRoot(t)
	first, err := formalCoxBlockwiseSourceProducerRunAtRoot(canonical, root, false)
	if err != nil || first.Replayed {
		t.Fatalf("canonical source command: %+v / %v", first, err)
	}
	replayed, err := formalCoxBlockwiseSourceProducerRunAtRoot(
		formatted.Bytes(), root, false)
	if err != nil || !replayed.Replayed ||
		replayed.ReceiptSHA256 != first.ReceiptSHA256 {
		t.Fatalf("formatted source command replay: %+v / %v", replayed, err)
	}
}

func TestFormalCoxBlockwiseSourceProducerCommandResponseDoesNotExposeInput(t *testing.T) {
	command, _, _, _ := formalCoxBlockwiseSourceProducerCommandTestRequest(t, 2)
	result, _ := formalCoxBlockwiseSourceProducerCommandTestRun(
		t, command, formalCoxBlockwiseSourceProducerCommandTestRoot(t))
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		command.SourceSigningKey, command.CanonicalInputBase64,
		"private_key", "canonical_input", "source_root", "path",
	} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("source producer response exposes %q", forbidden)
		}
	}
}
