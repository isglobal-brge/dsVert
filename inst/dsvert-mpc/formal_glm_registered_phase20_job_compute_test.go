package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFormalGLMRegisteredPhase20JobComputeHeartbeatRetriesOnlyRelayLockBusy(t *testing.T) {
	if !formalGLMRegisteredPhase20JobComputeHeartbeatRetryableV1(
		fmt.Errorf("wrapped: %w", errFormalGLMRegisteredPhase20JobRelayLockBusyV1),
	) {
		t.Fatal("relay lock contention was not retryable")
	}
	if formalGLMRegisteredPhase20JobComputeHeartbeatRetryableV1(
		errFormalGLMRegisteredPhase20JobWorkerOwnerLockBusyV1,
	) {
		t.Fatal("worker ownership contention must not be treated as relay contention")
	}
	if formalGLMRegisteredPhase20JobComputeHeartbeatRetryableV1(errors.New("disk failure")) {
		t.Fatal("storage failure must not be retryable")
	}
}

type formalGLMRegisteredPhase20JobComputeTestFixtureV1 struct {
	provenance formalGLMRegisteredPhase18ProvenanceTestFixtureV1
	record     formalGLMRegisteredPhase19BindingRecordV1
	roots      [2]string
	pairs      map[string][]formalGLMRegisteredPhase18BlockPairV1
	providers  [2]*formalGLMRegisteredPhase19PairKeyProviderV1
	ingress    [2]*formalGLMRegisteredPhase18IngressStoreV3
	owners     [2]*formalGLMRegisteredPhase20JobOwnerV1
}

func formalGLMRegisteredPhase20JobComputeTestBuild(
	t *testing.T, custodians, totalCapacity int,
) *formalGLMRegisteredPhase20JobComputeTestFixtureV1 {
	return formalGLMRegisteredPhase20JobComputeTestBuildWithFamily(
		t, "binomial", custodians, totalCapacity)
}

func formalGLMRegisteredPhase20JobComputeTestBuildWithFamily(
	t *testing.T, family string, custodians, totalCapacity int,
) *formalGLMRegisteredPhase20JobComputeTestFixtureV1 {
	return formalGLMRegisteredPhase20JobComputeTestBuildWithValuesV1(
		t, family, custodians, totalCapacity,
		formalGLMRegisteredPhase18MaterializedPairTestValues, false)
}

func formalGLMRegisteredPhase20JobComputeTestBuildWithValuesV1(
	t *testing.T, family string, custodians, totalCapacity int,
	valuesForBlock func(formalGLMRegisteredPhase18AuthorizationV1, int) ([]string, []bool),
	sharedConsensus bool,
) *formalGLMRegisteredPhase20JobComputeTestFixtureV1 {
	t.Helper()
	if valuesForBlock == nil {
		t.Fatal("registered job compute fixture has no block values")
	}
	fixture := &formalGLMRegisteredPhase20JobComputeTestFixtureV1{
		provenance: formalGLMRegisteredPhase18ProvenanceTestBuildWithCapacityAndFamily(
			t, family, custodians, totalCapacity),
	}
	source := fixture.provenance.source
	plan, contract := source.plan, source.contract
	pins, private := source.inputs.identities.public,
		source.inputs.identities.private
	tickets := make([]formalGLMRegisteredPhase18RecipientTicketV1, 0, 2)
	for index, peer := range plan.DesignatedComputePeers {
		parent, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		fixture.roots[index] = filepath.Join(parent, "rock")
		if err := os.Mkdir(fixture.roots[index], 0o700); err != nil {
			t.Fatal(err)
		}
		provider, err := newFormalGLMRegisteredPhase19PairKeyProviderV1(
			fixture.roots[index], peer, contract, pins)
		if err != nil {
			t.Fatal(err)
		}
		fixture.providers[index] = provider
		public, err := provider.PublicKeyV1()
		if err != nil {
			t.Fatal(err)
		}
		unsigned, err := formalGLMRegisteredPhase18BuildRecipientTicketV1(
			contract, peer, public, pins)
		if err != nil {
			t.Fatal(err)
		}
		ticket, err := formalGLMRegisteredPhase18SignRecipientTicketV1(
			unsigned, contract, private[peer], pins)
		if err != nil {
			t.Fatal(err)
		}
		tickets = append(tickets, ticket)
	}

	fixture.pairs = make(map[string][]formalGLMRegisteredPhase18BlockPairV1,
		plan.CustodianCount)
	receipts := make([]formalGLMRegisteredPhase18LocalReceiptV1, 0,
		plan.CustodianCount)
	for _, source := range plan.CustodianPeers {
		authorization := fixture.provenance.authorizations[source]
		fixture.pairs[source] = make([]formalGLMRegisteredPhase18BlockPairV1,
			plan.TotalBlocks)
		for blockIndex := 0; blockIndex < plan.TotalBlocks; blockIndex++ {
			values, validity := valuesForBlock(authorization, blockIndex)
			consensusLabel := fmt.Sprintf(
				"registered-job-compute/K%d/%s/%d", custodians, source, blockIndex)
			if sharedConsensus {
				consensusLabel = fmt.Sprintf(
					"registered-job-compute/K%d/shared/%d", custodians, blockIndex)
			}
			consensus := sha256.Sum256([]byte(consensusLabel))
			pair, err := formalGLMRegisteredPhase18BuildMaterializedBlockPairV3(
				contract, authorization, tickets, blockIndex, values, validity,
				consensus[:], private[source], pins)
			if err != nil {
				t.Fatal(err)
			}
			fixture.pairs[source][blockIndex] = pair
		}
		receipt, err := formalGLMRegisteredPhase18BuildLocalReceiptV1(
			contract, authorization, tickets, fixture.pairs[source], private[source], pins)
		if err != nil {
			t.Fatal(err)
		}
		receipts = append(receipts, receipt)
	}
	receiptSet, err := formalGLMRegisteredPhase18BuildReceiptSetV1(
		contract, receipts, pins)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := formalGLMBuildRegisteredPhase19BindingV1(
		contract, receiptSet, tickets, pins)
	if err != nil {
		t.Fatal(err)
	}
	orderedTickets, err := formalGLMRegisteredPhase18CanonicalTicketsV1(
		tickets, contract, pins)
	if err != nil {
		t.Fatal(err)
	}
	fixture.record = formalGLMRegisteredPhase19BindingRecordV1{
		Version: formalGLMRegisteredPhase19BindingRecordVersion,
		Purpose: formalGLMRegisteredPhase19BindingRecordPurpose,
		Binding: binding, ReceiptSet: receiptSet, RecipientTickets: orderedTickets,
	}
	if err := formalGLMValidateRegisteredPhase19BindingRecordV1(
		fixture.record, contract, pins); err != nil {
		t.Fatal(err)
	}
	ticketJSON := make([][]byte, len(orderedTickets))
	for index := range orderedTickets {
		ticketJSON[index], err = json.Marshal(orderedTickets[index])
		if err != nil {
			t.Fatal(err)
		}
	}
	receiptJSON, err := json.Marshal(receiptSet)
	if err != nil {
		t.Fatal(err)
	}
	for index, peer := range plan.DesignatedComputePeers {
		backend, backendErr := fixture.providers[index].DeriveBackendV1(fixture.record)
		if backendErr != nil {
			t.Fatal(backendErr)
		}
		localKey, keyErr := formalGLMRegisteredPhase20JobIngressKeyV1(
			backend, fixture.record, peer)
		clear(backend[:])
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		ingress, ingressErr := newFormalGLMRegisteredPhase18IngressStoreV3(
			fixture.roots[index], peer, localKey, contract,
			receiptSet.GlobalMaterializationRootSHA256, pins)
		if ingressErr != nil {
			t.Fatal(ingressErr)
		}
		for _, source := range plan.CustodianPeers {
			for blockIndex, pair := range fixture.pairs[source] {
				pairJSON, marshalErr := json.Marshal(pair)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				frame, frameErr := formalGLMRegisteredPhase18ComposeIngressFrameV3(
					contract, fixture.provenance.authorizations[source], ticketJSON, pairJSON,
					receiptJSON, peer, pins, localKey)
				if frameErr != nil {
					t.Fatal(frameErr)
				}
				if _, replayed, commitErr := ingress.Commit(
					frame, fixture.provenance.authorizations[source]); commitErr != nil || replayed {
					t.Fatalf("commit %s/%d: replay=%v err=%v",
						source, blockIndex, replayed, commitErr)
				}
			}
		}
		fixture.ingress[index] = ingress
		attempts, attemptErr := newFormalGLMRegisteredPhase19AttemptStoreV1(
			fixture.roots[index], fixture.record, contract, pins, peer, private[peer])
		if attemptErr != nil {
			t.Fatal(attemptErr)
		}
		jobKeys, keyErr := newFormalGLMRegisteredPhase20JobKeyProviderV1(
			fixture.roots[index], contract, pins, fixture.record, peer)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		owner, ownerErr := newFormalGLMRegisteredPhase20JobOwnerV1(
			attempts, jobKeys, formalGLMRegisteredPhase20JobStartV1{
				ArtifactID:       fixture.record.Binding.ArtifactID,
				ReceiptSetSHA256: fixture.record.Binding.ReceiptSetSHA256,
			})
		if ownerErr != nil {
			t.Fatal(ownerErr)
		}
		fixture.owners[index] = owner
	}
	t.Cleanup(func() {
		for index := range fixture.owners {
			if fixture.owners[index] != nil {
				_ = fixture.owners[index].Close()
			}
			if fixture.providers[index] != nil {
				fixture.providers[index].Close()
			}
			if fixture.ingress[index] != nil {
				fixture.ingress[index].Close()
			}
		}
	})
	return fixture
}

func (fixture *formalGLMRegisteredPhase20JobComputeTestFixtureV1) bind(
	t *testing.T,
) {
	t.Helper()
	proposal, err := fixture.owners[0].NegotiateV1(nil)
	if err != nil || len(proposal.outbound) == 0 {
		t.Fatalf("garbler proposal: %+v / %v", proposal, err)
	}
	accept, err := fixture.owners[1].NegotiateV1(proposal.outbound)
	if err != nil || len(accept.outbound) == 0 {
		t.Fatalf("evaluator accept: %+v / %v", accept, err)
	}
	if _, err := fixture.owners[0].NegotiateV1(accept.outbound); err != nil {
		t.Fatal(err)
	}
	var refs [2]formalGLMRegisteredPhase20JobRefV1
	var claims [2][]byte
	for index := range fixture.owners {
		if result, startErr := fixture.owners[index].StartOrInspectV1(); startErr != nil ||
			result.state != formalGLMRegisteredPhase20JobOwnerRunningStateV1 {
			t.Fatalf("worker %d start: %+v / %v", index, result, startErr)
		}
		refs[index], claims[index], err = fixture.owners[index].JobRefV1()
		if err != nil {
			t.Fatal(err)
		}
	}
	if refs[0] != refs[1] {
		t.Fatal("paired workers derived different job refs")
	}
	for index := range fixture.owners {
		if err := fixture.owners[index].BindPeerJobRefV1(claims[1-index]); err != nil {
			t.Fatal(err)
		}
	}
}

func formalGLMRegisteredPhase20JobComputeTestRelayV1(
	stop <-chan struct{}, from, to *formalGLMRegisteredPhase20JobOwnerV1,
	errCh chan<- error,
) {
	ack := int64(0)
	for {
		select {
		case <-stop:
			return
		default:
		}
		from.controller.mu.Lock()
		transport := from.controller.transport
		from.controller.mu.Unlock()
		result, err := transport.Poll(ack)
		if err != nil {
			errCh <- err
			return
		}
		if result.RelayChunk == nil {
			time.Sleep(time.Millisecond)
			continue
		}
		to.controller.mu.Lock()
		peer := to.controller.transport
		to.controller.mu.Unlock()
		ack, err = peer.Relay(*result.RelayChunk)
		if err != nil {
			errCh <- err
			return
		}
	}
}

func TestFormalGLMRegisteredPhase20JobComputeK2SealsWithoutRawOutput(
	t *testing.T,
) {
	formalGLMRegisteredPhase20JobComputeSealsWithoutRawOutput(t, 2, 9)
}

func TestFormalGLMRegisteredPhase20JobComputeK3K5SealsWithoutRawOutput(
	t *testing.T,
) {
	for _, custodians := range []int{3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			formalGLMRegisteredPhase20JobComputeSealsWithoutRawOutput(t, custodians, 4)
		})
	}
}

func TestFormalGLMRegisteredPhase20JobComputePoissonK2K3K5SealsWithoutRawOutput(
	t *testing.T,
) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			formalGLMRegisteredPhase20JobComputeSealsWithoutRawOutputFamily(
				t, "poisson", custodians, 4)
		})
	}
}

func formalGLMRegisteredPhase20JobComputeSealsWithoutRawOutput(
	t *testing.T, custodians, totalCapacity int,
) {
	formalGLMRegisteredPhase20JobComputeSealsWithoutRawOutputFamily(
		t, "binomial", custodians, totalCapacity)
}

func formalGLMRegisteredPhase20JobComputeSealsWithoutRawOutputFamily(
	t *testing.T, family string, custodians, totalCapacity int,
) {
	t.Helper()
	fixture := formalGLMRegisteredPhase20JobComputeTestBuildWithFamily(
		t, family, custodians, totalCapacity)
	plan := fixture.provenance.source.plan
	backend, err := fixture.providers[0].DeriveBackendV1(fixture.record)
	if err != nil {
		t.Fatal(err)
	}
	ingressKey, err := formalGLMRegisteredPhase20JobIngressKeyV1(
		backend, fixture.record, plan.DesignatedComputePeers[0])
	clear(backend[:])
	if err != nil || ingressKey != fixture.ingress[0].localKey {
		clear(ingressKey[:])
		t.Fatalf("recipient ingress key did not bind the pair backend: %v", err)
	}
	otherBackend, err := fixture.providers[1].DeriveBackendV1(fixture.record)
	if err != nil {
		clear(ingressKey[:])
		t.Fatal(err)
	}
	otherKey, err := formalGLMRegisteredPhase20JobIngressKeyV1(
		otherBackend, fixture.record, plan.DesignatedComputePeers[1])
	clear(otherBackend[:])
	if err != nil || otherKey != fixture.ingress[1].localKey || otherKey == ingressKey {
		clear(ingressKey[:])
		clear(otherKey[:])
		t.Fatalf("recipient ingress keys are not distinct and reproducible: %v", err)
	}
	snapshot := formalGLMRegisteredPhase20JobComputeSnapshotV1{
		attempts: fixture.owners[0].attempts,
		record:   fixture.record,
		contract: fixture.provenance.source.contract,
		pins:     fixture.provenance.source.inputs.identities.public,
		peer:     plan.DesignatedComputePeers[0],
	}
	if err := formalGLMRegisteredPhase20JobComputeValidateIngressV1(
		fixture.ingress[0], snapshot, ingressKey); err != nil {
		clear(ingressKey[:])
		clear(otherKey[:])
		t.Fatal(err)
	}
	fixture.ingress[0].mu.Lock()
	fixture.ingress[0].localKey[0] ^= 1
	fixture.ingress[0].mu.Unlock()
	if err := formalGLMRegisteredPhase20JobComputeValidateIngressV1(
		fixture.ingress[0], snapshot, ingressKey); err == nil {
		clear(ingressKey[:])
		clear(otherKey[:])
		t.Fatal("job compute accepted an ingress store with an arbitrary MAC key")
	}
	fixture.ingress[0].mu.Lock()
	fixture.ingress[0].localKey[0] ^= 1
	fixture.ingress[0].mu.Unlock()
	clear(ingressKey[:])
	clear(otherKey[:])
	if plan.TotalCapacity != totalCapacity ||
		plan.TotalBlocks != (totalCapacity+plan.BlockCapacity-1)/plan.BlockCapacity {
		t.Fatal("registered job compute changed its public block geometry")
	}
	if err := fixture.owners[0].RunComputeV1(
		fixture.providers[0], fixture.ingress[0]); err == nil {
		t.Fatal("job compute ran before the peer epoch was bound")
	}
	fixture.bind(t)
	stop := make(chan struct{})
	errs := make(chan error, 2)
	go formalGLMRegisteredPhase20JobComputeTestRelayV1(
		stop, fixture.owners[0], fixture.owners[1], errs)
	go formalGLMRegisteredPhase20JobComputeTestRelayV1(
		stop, fixture.owners[1], fixture.owners[0], errs)
	var run [2]error
	finished := make(chan int, 2)
	for index := range fixture.owners {
		go func(index int) {
			run[index] = fixture.owners[index].RunComputeV1(
				fixture.providers[index], fixture.ingress[index])
			finished <- index
		}(index)
	}
	abort := func() {
		close(stop)
		for _, owner := range fixture.owners {
			owner.mu.Lock()
			controller := owner.controller
			owner.mu.Unlock()
			if controller != nil {
				go func() { _ = controller.Close() }()
			}
		}
	}
	var first int
	select {
	case first = <-finished:
	case relayErr := <-errs:
		abort()
		select {
		case <-finished:
		case <-time.After(30 * time.Second):
		}
		t.Fatalf("relay failed before compute completed: %v", relayErr)
	}
	if run[first] != nil {
		abort()
		select {
		case second := <-finished:
			t.Fatalf("registered job compute failed: %v / %v", run[first], run[second])
		case <-time.After(30 * time.Second):
			t.Fatalf("registered job compute left peer blocked after: %v", run[first])
		}
	}
	<-finished
	close(stop)
	select {
	case relayErr := <-errs:
		t.Fatalf("relay failed: %v", relayErr)
	default:
	}
	if run[0] != nil || run[1] != nil {
		t.Fatalf("registered job compute failed: %v / %v", run[0], run[1])
	}
	for index, owner := range fixture.owners {
		owner.mu.Lock()
		terminal := owner.terminal
		attempts, jobKeys := owner.attempts, owner.jobKeys
		owner.mu.Unlock()
		if terminal == nil || attempts != nil || jobKeys != nil {
			t.Fatalf("role %d did not transfer only the terminal owner", index)
		}
		status, err := terminal.LoadStatusV1()
		if err != nil || !status.draftSealed || status.selected != nil ||
			status.prepareReceipt != nil || status.selectVote != nil {
			t.Fatalf("role %d terminal status: %+v / %v", index, status, err)
		}
		encoded, err := json.Marshal(owner)
		if err != nil || string(encoded) != "{}" {
			t.Fatalf("job compute owner exposed private state: %s / %v", encoded, err)
		}
	}
}
