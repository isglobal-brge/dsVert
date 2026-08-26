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

func formalCoxBlockwiseLiveControlRelayRecordV1(
	t *testing.T, controllers [2]*formalCoxBlockwiseExchangeController,
	headers [2]formalCoxBlockwiseOpeningHandoffHeader, stateRoot string,
	producer, consumer int, record string,
) {
	t.Helper()
	recipient, err := controllers[consumer].FinalizerControlRecipientAtRootV1(
		headers, stateRoot, false)
	if err != nil || recipient.ProductionReady {
		t.Fatalf("relay %s recipient: %+v / %v", record, recipient, err)
	}
	recipientJSON, err := json.Marshal(recipient)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private", "secret", "path"} {
		if bytes.Contains(bytes.ToLower(recipientJSON), []byte(`"`+forbidden+`"`)) {
			clear(recipientJSON)
			t.Fatalf("relay %s recipient exposed %q", record, forbidden)
		}
	}
	clear(recipientJSON)
	public, err := base64.StdEncoding.Strict().DecodeString(recipient.TransportPublic)
	if err != nil {
		t.Fatalf("relay %s public key: %v", record, err)
	}
	defer clear(public)
	signature, err := base64.StdEncoding.Strict().DecodeString(recipient.TransportSignature)
	if err != nil {
		t.Fatalf("relay %s signature: %v", record, err)
	}
	defer clear(signature)
	source, err := controllers[producer].FinalizerControlSourceAtRootV1(
		headers, public, signature, stateRoot, false)
	if err != nil || !source.Available || source.ProductionReady ||
		!formalCoxIsSHA256(source.EnvelopeSHA256) {
		t.Fatalf("relay %s source: %+v / %v", record, source, err)
	}
	sourceJSON, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"candidate", "private", "secret", "path"} {
		if bytes.Contains(bytes.ToLower(sourceJSON), []byte(`"`+forbidden+`"`)) {
			clear(sourceJSON)
			t.Fatalf("relay %s source exposed %q", record, forbidden)
		}
	}
	clear(sourceJSON)
	encoded, err := base64.RawURLEncoding.Strict().DecodeString(source.EnvelopeBase64URL)
	if err != nil {
		t.Fatalf("relay %s envelope: %v", record, err)
	}
	receipt, err := controllers[consumer].FinalizerControlImportAtRootV1(
		headers, encoded, stateRoot, false)
	clear(encoded)
	if err != nil || receipt.RecordType != record || receipt.ProductionReady {
		t.Fatalf("relay %s import: %+v / %v", record, receipt, err)
	}
	tampered := receipt
	tampered.EnvelopeSHA256 = formalCoxControlSHA("tampered-relay-receipt|", []byte(record))
	if _, err := controllers[producer].FinalizerControlDeliveredAtRootV1(
		headers, tampered, stateRoot, false); err == nil {
		t.Fatalf("relay %s accepted a receipt not covering its envelope", record)
	}
	delivery, err := controllers[producer].FinalizerControlDeliveredAtRootV1(
		headers, receipt, stateRoot, false)
	if err != nil || delivery.RecordType != record || delivery.Replayed {
		t.Fatalf("relay %s delivery: %+v / %v", record, delivery, err)
	}
	replayed, err := controllers[producer].FinalizerControlDeliveredAtRootV1(
		headers, receipt, stateRoot, false)
	if err != nil || replayed.RecordType != record || !replayed.Replayed {
		t.Fatalf("relay %s delivery replay: %+v / %v", record, replayed, err)
	}
}

func formalCoxBlockwiseLiveControlStagesFreshFinalizerV1(
	t *testing.T, custodians int,
) {
	fixture := newFormalCoxBlockwiseSourceBridgeTestFixture(
		t, custodians, map[string]bool{"peer-a": true, "peer-b": true})
	formalCoxBlockwiseSourceBridgeTestRunFullSchedule(t, fixture)
	bridges, err := formalCoxBlockwiseSourceBridgeTestOpen(t, fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer formalCoxBlockwiseSourceBridgeTestClose(bridges)

	var openings [2]*formalCoxBlockwiseOpeningStore
	var headers [2]formalCoxBlockwiseOpeningHandoffHeader
	for index, peer := range fixture.plan.Policy.ComputePeers {
		key := sha256.Sum256([]byte(t.Name() + "/opening/" + peer))
		openings[index], err = newFormalCoxBlockwiseOpeningStore(
			filepath.Join(t.TempDir(), "opening-"+peer), key, fixture.plan, fixture.pins)
		if err != nil {
			t.Fatal(err)
		}
		defer openings[index].Close()
		headers[index], _, err = bridges[index].SubmitStickyOpening(openings[index])
		if err != nil {
			t.Fatalf("submit %s: %v", peer, err)
		}
	}
	stateRoot := t.TempDir()
	ticket, _, err := bridges[0].IssueFinalizerTicketAtRootV1(
		openings[0], headers, stateRoot, false)
	if err != nil {
		t.Fatal(err)
	}
	var envelopes [2]formalFinalizerHandoffEnvelope
	for index := range bridges {
		envelopes[index], _, err = bridges[index].SealStickyOpeningToFinalizerAtRootV1(
			openings[index], ticket, headers, stateRoot, false)
		if err != nil {
			t.Fatalf("seal %d: %v", index, err)
		}
	}
	controllers := [2]*formalCoxBlockwiseExchangeController{}
	for index := range controllers {
		controllers[index] = &formalCoxBlockwiseExchangeController{
			bridge: bridges[index], opening: openings[index], plan: fixture.plan,
			peer: fixture.plan.Policy.ComputePeers[index], committed: true,
		}
	}
	evaluator, err := controllers[1].StageFinalizerControlAtRootV1(
		ticket, headers, envelopes, stateRoot, false)
	if err != nil || evaluator.LocalRole != "evaluator" || evaluator.ArtifactID == "" ||
		evaluator.CandidateSHA256 != "" || evaluator.ProductionReady {
		t.Fatalf("evaluator stage: %+v / %v", evaluator, err)
	}
	garbler, err := controllers[0].StageFinalizerControlAtRootV1(
		ticket, headers, envelopes, stateRoot, false)
	if err != nil || garbler.LocalRole != "garbler" ||
		!formalCoxIsSHA256(garbler.ArtifactID) ||
		!formalCoxIsSHA256(garbler.CandidateSHA256) || garbler.ProductionReady {
		t.Fatalf("garbler stage: %+v / %v", garbler, err)
	}
	encoded, err := json.Marshal(garbler)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	if !bytes.Contains(encoded, []byte(`"production_ready":false`)) {
		t.Fatalf("stage response omitted non-production marker: %s", encoded)
	}
	for _, forbidden := range [][]byte{
		[]byte("coefficient"), []byte("share"), []byte("secret"), []byte("storage"),
	} {
		if bytes.Contains(bytes.ToLower(encoded), forbidden) {
			t.Fatalf("stage response exposed %q: %s", forbidden, encoded)
		}
	}

	context, err := formalCoxControlContextFor(fixture.plan, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	defer formalCoxBlockwiseClearPinsV1(context.pins)
	for index, authority := range context.Authorities {
		store, openErr := newFormalCoxBlockwiseControlStore(
			filepath.Join(stateRoot, authority.PeerName), context, authority, false)
		if openErr != nil {
			t.Fatal(openErr)
		}
		if index == 0 {
			if !mustFormalCoxLiveControlRecord(t, store,
				formalCoxControlRecordTicket, "garbler") ||
				!mustFormalCoxLiveControlRecord(t, store,
					formalCoxControlRecordCandidate, "garbler") {
				store.Close()
				t.Fatal("garbler did not stage ticket and candidate")
			}
		} else if !mustFormalCoxLiveControlRecord(t, store,
			formalCoxControlRecordEnvelope, "evaluator") {
			store.Close()
			t.Fatal("evaluator did not stage its envelope")
		}
		if mustFormalCoxLiveControlRecord(t, store,
			formalCoxControlRecordCandidate, "garbler") && index == 1 {
			store.Close()
			t.Fatal("evaluator received a candidate without encrypted relay")
		}
		store.Close()
	}

	// Replay is byte-identical and does not create a second candidate or ticket.
	replayed, err := controllers[0].StageFinalizerControlAtRootV1(
		ticket, headers, envelopes, stateRoot, false)
	if err != nil || !formalCoxBlockwiseOpeningEqual(replayed, garbler) {
		t.Fatalf("garbler stage replay: %+v / %v", replayed, err)
	}
}

func TestFormalCoxBlockwiseLiveControlStagesFreshFinalizerK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			formalCoxBlockwiseLiveControlStagesFreshFinalizerV1(t, custodians)
		})
	}
}

func formalCoxBlockwiseLiveControlAdvancesFinalizerV1(t *testing.T, custodians int) {
	fixture := newFormalCoxBlockwiseSourceBridgeTestFixture(
		t, custodians, map[string]bool{"peer-a": true, "peer-b": true})
	formalCoxBlockwiseSourceBridgeTestRunFullSchedule(t, fixture)
	bridges, err := formalCoxBlockwiseSourceBridgeTestOpen(t, fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer formalCoxBlockwiseSourceBridgeTestClose(bridges)
	var openings [2]*formalCoxBlockwiseOpeningStore
	var headers [2]formalCoxBlockwiseOpeningHandoffHeader
	for index, peer := range fixture.plan.Policy.ComputePeers {
		key := sha256.Sum256([]byte(t.Name() + "/advance-opening/" + peer))
		openings[index], err = newFormalCoxBlockwiseOpeningStore(
			filepath.Join(t.TempDir(), "advance-opening-"+peer), key,
			fixture.plan, fixture.pins)
		if err != nil {
			t.Fatal(err)
		}
		defer openings[index].Close()
		headers[index], _, err = bridges[index].SubmitStickyOpening(openings[index])
		if err != nil {
			t.Fatal(err)
		}
	}
	stateRoot := t.TempDir()
	ticket, _, err := bridges[0].IssueFinalizerTicketAtRootV1(
		openings[0], headers, stateRoot, false)
	if err != nil {
		t.Fatal(err)
	}
	var envelopes [2]formalFinalizerHandoffEnvelope
	for index := range bridges {
		envelopes[index], _, err = bridges[index].SealStickyOpeningToFinalizerAtRootV1(
			openings[index], ticket, headers, stateRoot, false)
		if err != nil {
			t.Fatal(err)
		}
	}
	controllers := [2]*formalCoxBlockwiseExchangeController{}
	for index, peer := range fixture.plan.Policy.ComputePeers {
		controllers[index] = &formalCoxBlockwiseExchangeController{
			bridge: bridges[index], opening: openings[index], plan: fixture.plan,
			peer: peer, committed: true,
		}
	}
	if _, err := controllers[1].StageFinalizerControlAtRootV1(
		ticket, headers, envelopes, stateRoot, false); err != nil {
		t.Fatal(err)
	}
	if _, err := controllers[0].StageFinalizerControlAtRootV1(
		ticket, headers, envelopes, stateRoot, false); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		producer, consumer int
		record             string
	}{
		{0, 1, formalCoxControlRecordPreflight},
		{1, 0, formalCoxControlRecordPreflight},
		{0, 1, formalCoxControlRecordHeader},
		{1, 0, formalCoxControlRecordHeader},
		{0, 1, formalCoxControlRecordTicket},
		{1, 0, formalCoxControlRecordEnvelope},
		{0, 1, formalCoxControlRecordCandidate},
	} {
		formalCoxBlockwiseLiveControlRelayRecordV1(
			t, controllers, headers, stateRoot, step.producer, step.consumer,
			step.record)
	}
	garbler, err := controllers[0].AdvanceFinalizerControlAtRootV1(
		headers, stateRoot, false)
	if err != nil || garbler.State != "awaiting_evaluator_authorization" ||
		garbler.ArtifactID == "" || garbler.ProductionReady {
		t.Fatalf("garbler authorization advance: %+v / %v", garbler, err)
	}
	formalCoxBlockwiseLiveControlRelayRecordV1(
		t, controllers, headers, stateRoot, 0, 1,
		formalCoxControlRecordAuthorization)
	evaluator, err := controllers[1].AdvanceFinalizerControlAtRootV1(
		headers, stateRoot, false)
	if err != nil || evaluator.State != "awaiting_publication" ||
		evaluator.ArtifactID != garbler.ArtifactID || evaluator.ProductionReady {
		t.Fatalf("evaluator authorization advance: %+v / %v", evaluator, err)
	}
	formalCoxBlockwiseLiveControlRelayRecordV1(
		t, controllers, headers, stateRoot, 1, 0,
		formalCoxControlRecordAuthorization)
	garbler, err = controllers[0].AdvanceFinalizerControlAtRootV1(headers, stateRoot, false)
	if err != nil || garbler.State != "publication_ready" ||
		!formalCoxIsSHA256(garbler.CertificateSHA256) || garbler.ProductionReady {
		t.Fatalf("garbler publication advance: %+v / %v", garbler, err)
	}
	encoded, err := json.Marshal(garbler)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{
		[]byte("candidate"), []byte("share"), []byte("secret"), []byte("storage"),
		[]byte("path"),
	} {
		if bytes.Contains(bytes.ToLower(encoded), forbidden) {
			clear(encoded)
			t.Fatalf("advance response exposed %q: %s", forbidden, encoded)
		}
	}
	clear(encoded)
	formalCoxBlockwiseLiveControlRelayRecordV1(
		t, controllers, headers, stateRoot, 0, 1,
		formalCoxControlRecordPublication)
	evaluator, err = controllers[1].AdvanceFinalizerControlAtRootV1(headers, stateRoot, false)
	if err != nil || evaluator.State != "commit_ready" ||
		evaluator.CertificateSHA256 != garbler.CertificateSHA256 || evaluator.ProductionReady {
		t.Fatalf("evaluator commit advance: %+v / %v", evaluator, err)
	}
	formalCoxBlockwiseLiveControlRelayRecordV1(
		t, controllers, headers, stateRoot, 1, 0,
		formalCoxControlRecordCommit)
	formalCoxBlockwiseLiveControlRelayRecordV1(
		t, controllers, headers, stateRoot, 0, 1,
		formalCoxControlRecordAck)
	for index := range controllers {
		recipient, err := controllers[1-index].FinalizerControlRecipientAtRootV1(
			headers, stateRoot, false)
		if err != nil {
			t.Fatal(err)
		}
		public, err := base64.StdEncoding.Strict().DecodeString(recipient.TransportPublic)
		if err != nil {
			t.Fatal(err)
		}
		signature, err := base64.StdEncoding.Strict().DecodeString(recipient.TransportSignature)
		if err != nil {
			clear(public)
			t.Fatal(err)
		}
		source, sourceErr := controllers[index].FinalizerControlSourceAtRootV1(
			headers, public, signature, stateRoot, false)
		clear(public)
		clear(signature)
		if sourceErr != nil || source.Available {
			t.Fatalf("authority %d did not reach terminal control state: %+v / %v",
				index, source, sourceErr)
		}
	}
}

func TestFormalCoxBlockwiseLiveControlAdvancesFinalizerK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			formalCoxBlockwiseLiveControlAdvancesFinalizerV1(t, custodians)
		})
	}
}

func mustFormalCoxLiveControlRecord(t *testing.T,
	store *formalCoxBlockwiseControlStore, recordType, role string,
) bool {
	t.Helper()
	encoded, err := store.readLifecycleRaw(recordType, role)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		t.Fatalf("record %s/%s: %v", recordType, role, err)
	}
	clear(encoded)
	return true
}
