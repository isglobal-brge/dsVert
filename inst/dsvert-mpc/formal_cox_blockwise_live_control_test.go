package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func formalCoxBlockwiseLiveControlRelayRecord(
	t *testing.T, stores [2]*formalCoxBlockwiseControlStore,
	transports [2]*ecdh.PrivateKey, signatures [2][]byte,
	producer, consumer int, record string, now time.Time,
) time.Time {
	t.Helper()
	descriptor, err := stores[producer].DescribeNextSource(
		transports[consumer].PublicKey().Bytes(), signatures[consumer], now)
	if err != nil || descriptor.Context.AAD.RecordType != record {
		t.Fatalf("relay %s source: %+v / %v", record, descriptor, err)
	}
	encoded, err := os.ReadFile(descriptor.SourcePath)
	if err != nil || int64(len(encoded)) != descriptor.EnvelopeBytes {
		clear(encoded)
		t.Fatalf("relay %s read: %d / %v", record, len(encoded), err)
	}
	ingress, err := stores[consumer].ImportCanonical(
		encoded, transports[consumer].Bytes(), now)
	clear(encoded)
	if err != nil || ingress.RecordType != record || ingress.Replayed {
		t.Fatalf("relay %s import: %+v / %v", record, ingress, err)
	}
	receiptSHA := formalCoxControlSHA(
		formalCoxControlAADDomain+"live-control-receipt|",
		[]byte(record+"|"+fmt.Sprint(now.UnixNano())))
	delivery, err := stores[producer].MarkNextDelivered(
		descriptor.EnvelopeSHA256, receiptSHA, now)
	if err != nil || delivery.RecordType != record || delivery.Replayed {
		t.Fatalf("relay %s delivery: %+v / %v", record, delivery, err)
	}
	return now.Add(time.Second)
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
	context, err := formalCoxControlContextFor(fixture.plan, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	defer formalCoxBlockwiseClearPinsV1(context.pins)
	var stores [2]*formalCoxBlockwiseControlStore
	var transports [2]*ecdh.PrivateKey
	var signatures [2][]byte
	for index, authority := range context.Authorities {
		seed := sha256.Sum256([]byte(t.Name() + "/advance-transport/" + authority.PeerName))
		transports[index], err = ecdh.X25519().NewPrivateKey(seed[:])
		if err != nil {
			t.Fatal(err)
		}
		signatures[index] = ed25519.Sign(
			fixture.signing[authority.PeerName], transports[index].PublicKey().Bytes())
	}
	openStores := func() {
		for index, authority := range context.Authorities {
			stores[index], err = newFormalCoxBlockwiseControlStore(
				filepath.Join(stateRoot, authority.PeerName), context, authority, false)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	closeStores := func() {
		for index := range stores {
			stores[index].Close()
			stores[index] = nil
		}
	}
	openStores()
	now := time.Unix(1_900_000_000, 0)
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
		now = formalCoxBlockwiseLiveControlRelayRecord(
			t, stores, transports, signatures, step.producer, step.consumer,
			step.record, now)
	}
	closeStores()
	garbler, err := controllers[0].AdvanceFinalizerControlAtRootV1(
		headers, stateRoot, false)
	if err != nil || garbler.State != "awaiting_evaluator_authorization" ||
		garbler.ArtifactID == "" || garbler.ProductionReady {
		t.Fatalf("garbler authorization advance: %+v / %v", garbler, err)
	}
	openStores()
	now = formalCoxBlockwiseLiveControlRelayRecord(
		t, stores, transports, signatures, 0, 1,
		formalCoxControlRecordAuthorization, now)
	closeStores()
	evaluator, err := controllers[1].AdvanceFinalizerControlAtRootV1(
		headers, stateRoot, false)
	if err != nil || evaluator.State != "awaiting_publication" ||
		evaluator.ArtifactID != garbler.ArtifactID || evaluator.ProductionReady {
		t.Fatalf("evaluator authorization advance: %+v / %v", evaluator, err)
	}
	openStores()
	now = formalCoxBlockwiseLiveControlRelayRecord(
		t, stores, transports, signatures, 1, 0,
		formalCoxControlRecordAuthorization, now)
	closeStores()
	garbler, err = controllers[0].AdvanceFinalizerControlAtRootV1(headers, stateRoot, false)
	if err != nil || garbler.State != "publication_ready" ||
		!formalCoxIsSHA256(garbler.CertificateSHA256) || garbler.ProductionReady {
		t.Fatalf("garbler publication advance: %+v / %v", garbler, err)
	}
	openStores()
	now = formalCoxBlockwiseLiveControlRelayRecord(
		t, stores, transports, signatures, 0, 1,
		formalCoxControlRecordPublication, now)
	closeStores()
	evaluator, err = controllers[1].AdvanceFinalizerControlAtRootV1(headers, stateRoot, false)
	if err != nil || evaluator.State != "commit_ready" ||
		evaluator.CertificateSHA256 != garbler.CertificateSHA256 || evaluator.ProductionReady {
		t.Fatalf("evaluator commit advance: %+v / %v", evaluator, err)
	}
	openStores()
	now = formalCoxBlockwiseLiveControlRelayRecord(
		t, stores, transports, signatures, 1, 0,
		formalCoxControlRecordCommit, now)
	now = formalCoxBlockwiseLiveControlRelayRecord(
		t, stores, transports, signatures, 0, 1,
		formalCoxControlRecordAck, now)
	for index, store := range stores {
		if _, err := store.DescribeNextSource(
			transports[1-index].PublicKey().Bytes(), signatures[1-index], now); !errors.Is(
			err, errFormalCoxControlNoSource) {
			t.Fatalf("authority %d did not reach terminal control state: %v", index, err)
		}
	}
	closeStores()
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
