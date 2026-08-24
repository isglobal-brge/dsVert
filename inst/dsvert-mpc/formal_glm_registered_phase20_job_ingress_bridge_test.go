package main

import (
	"encoding/json"
	"fmt"
	"testing"
)

func formalGLMRegisteredPhase20JobIngressBridgeTestPersistPendingV1(
	t testing.TB,
	fixture *formalGLMRegisteredPhase20JobComputeTestFixtureV1,
	index int,
) {
	t.Helper()
	contract := fixture.provenance.source.contract
	pins := fixture.provenance.source.inputs.identities.public
	peer := fixture.provenance.source.plan.DesignatedComputePeers[index]
	tickets, err := newFormalGLMRegisteredPhase18RecipientTicketStoreV1(
		fixture.roots[index], contract, pins)
	if err != nil {
		t.Fatal(err)
	}
	defer tickets.Close()
	for _, ticket := range fixture.record.RecipientTickets {
		if _, replayed, commitErr := tickets.Commit(ticket); commitErr != nil || replayed {
			t.Fatalf("ticket %s: replay=%v err=%v", ticket.RecipientName, replayed, commitErr)
		}
	}
	pending, err := newFormalGLMRegisteredPhase18PendingPairStoreV1(
		fixture.roots[index], peer, contract, pins, tickets)
	if err != nil {
		t.Fatal(err)
	}
	defer pending.Close()
	for _, source := range fixture.provenance.source.plan.CustodianPeers {
		for blockIndex, pair := range fixture.pairs[source] {
			encoded, marshalErr := json.Marshal(pair)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			_, replayed, commitErr := pending.CommitPair(encoded)
			clear(encoded)
			if commitErr != nil || replayed {
				t.Fatalf("pending %s/%d: replay=%v err=%v", source, blockIndex, replayed, commitErr)
			}
		}
	}
}

func TestFormalGLMRegisteredPhase20JobIngressBridgeK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMRegisteredPhase20JobComputeTestBuild(t, custodians, 4)
			for index, peer := range fixture.provenance.source.plan.DesignatedComputePeers {
				formalGLMRegisteredPhase20JobIngressBridgeTestPersistPendingV1(t, fixture, index)
				bridge, err := newFormalGLMRegisteredPhase20JobIngressBridgeV1(
					fixture.roots[index], peer, fixture.record,
					fixture.provenance.source.contract,
					fixture.provenance.source.inputs.identities.public)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(bridge.Close)
				receipts, replayed, finalizeErr := bridge.FinalizeV1()
				want := custodians * fixture.provenance.source.plan.TotalBlocks
				if finalizeErr != nil || !replayed || len(receipts) != want {
					t.Fatalf("recipient %d finalize: receipts=%d replay=%v err=%v",
						index, len(receipts), replayed, finalizeErr)
				}
			}
		})
	}
}
