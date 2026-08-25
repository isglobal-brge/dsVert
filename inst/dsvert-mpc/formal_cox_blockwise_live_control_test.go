package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

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
