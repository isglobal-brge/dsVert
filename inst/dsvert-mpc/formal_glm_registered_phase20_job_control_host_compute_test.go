package main

import (
	"encoding/json"
	"testing"
	"time"
)

func formalGLMRegisteredPhase20JobControlHostComputeConfigV1(
	t testing.TB,
	fixture *formalGLMRegisteredPhase20JobComputeTestFixtureV1,
	index int,
) formalGLMRegisteredPhase20JobControlHostConfigV1 {
	t.Helper()
	peer := fixture.provenance.source.plan.DesignatedComputePeers[index]
	pins := formalGLMRegisteredPhase19ScheduleTailClonePinsV1(
		fixture.provenance.source.inputs.identities.public)
	return formalGLMRegisteredPhase20JobControlHostConfigV1{
		Version:  formalGLMRegisteredPhase20JobControlHostVersionV1,
		Contract: fixture.provenance.source.contract,
		Record:   fixture.record,
		Pins:     pins,
		Peer:     peer,
		Signing:  append([]byte(nil), fixture.provenance.source.inputs.identities.private[peer]...),
		Start: formalGLMRegisteredPhase20JobStartV1{
			ArtifactID:       fixture.record.Binding.ArtifactID,
			ReceiptSetSHA256: fixture.record.Binding.ReceiptSetSHA256,
		},
	}
}

func formalGLMRegisteredPhase20JobControlHostComputeRelayV1(
	stop <-chan struct{}, from, to *formalGLMRegisteredPhase20JobControlHostV1,
	fromRef, toRef formalGLMRegisteredPhase20JobRefV1,
	errs chan<- error, done chan<- struct{},
) {
	defer func() { done <- struct{}{} }()
	ack := int64(0)
	for {
		select {
		case <-stop:
			return
		default:
		}
		result, err := from.PollV1(fromRef, ack)
		if err != nil {
			errs <- err
			return
		}
		if result.RelayChunk == nil {
			time.Sleep(time.Millisecond)
			continue
		}
		ack, err = to.RelayV1(toRef, *result.RelayChunk)
		if err != nil {
			errs <- err
			return
		}
	}
}

func TestFormalGLMRegisteredPhase20JobControlHostRunsK2FromPendingIngress(t *testing.T) {
	fixture := formalGLMRegisteredPhase20JobComputeTestBuild(t, 2, 9)
	for index := range fixture.roots {
		formalGLMRegisteredPhase20JobIngressBridgeTestPersistPendingV1(t, fixture, index)
		if err := fixture.owners[index].Close(); err != nil {
			t.Fatal(err)
		}
		fixture.owners[index] = nil
	}
	hosts := [2]*formalGLMRegisteredPhase20JobControlHostV1{}
	for index := range hosts {
		config := formalGLMRegisteredPhase20JobControlHostComputeConfigV1(t, fixture, index)
		host, err := newFormalGLMRegisteredPhase20JobControlHostV1(
			fixture.roots[index], config)
		if err != nil {
			t.Fatal(err)
		}
		hosts[index] = host
		t.Cleanup(func() { _ = host.Close() })
		encoded, marshalErr := json.Marshal(host)
		if marshalErr != nil || string(encoded) != "{}" {
			t.Fatalf("host %d exposed private compute state: %q / %v", index, encoded, marshalErr)
		}
	}
	waiting, err := hosts[1].NegotiateV1(nil)
	if err != nil || waiting.state != formalGLMRegisteredPhase20JobControlWaitingProposalStateV1 {
		t.Fatalf("evaluator waiting: %+v / %v", waiting, err)
	}
	proposal, err := hosts[0].NegotiateV1(nil)
	if err != nil || len(proposal.outbound) == 0 {
		t.Fatalf("garbler proposal: %+v / %v", proposal, err)
	}
	accept, err := hosts[1].NegotiateV1(proposal.outbound)
	if err != nil || len(accept.outbound) == 0 {
		t.Fatalf("evaluator accept: %+v / %v", accept, err)
	}
	if _, err := hosts[0].NegotiateV1(accept.outbound); err != nil {
		t.Fatal(err)
	}
	refs := [2]formalGLMRegisteredPhase20JobRefV1{}
	claims := [2][]byte{}
	for index := range hosts {
		started, startErr := hosts[index].StartOrInspectV1()
		if startErr != nil || started.state != formalGLMRegisteredPhase20JobOwnerRunningStateV1 ||
			started.inspectOnly || started.productionReady {
			t.Fatalf("host %d start: %+v / %v", index, started, startErr)
		}
		refs[index], claims[index], err = hosts[index].JobRefV1()
		if err != nil || refs[index].ProductionReady || len(claims[index]) == 0 {
			t.Fatalf("host %d ref: %+v / %v", index, refs[index], err)
		}
	}
	if refs[0] != refs[1] {
		t.Fatal("hosts derived different job refs")
	}
	for index := range hosts {
		if err := hosts[index].BindPeerJobRefV1(claims[1-index]); err != nil {
			t.Fatal(err)
		}
	}
	stop := make(chan struct{})
	relayErrs := make(chan error, 2)
	relayDone := make(chan struct{}, 2)
	for index := range hosts {
		go formalGLMRegisteredPhase20JobControlHostComputeRelayV1(
			stop, hosts[index], hosts[1-index], refs[index], refs[1-index],
			relayErrs, relayDone)
	}
	completed := make(chan error, 2)
	for index := range hosts {
		go func(index int) { completed <- hosts[index].RunComputeV1() }(index)
	}
	for range hosts {
		select {
		case runErr := <-completed:
			if runErr != nil {
				close(stop)
				<-relayDone
				<-relayDone
				t.Fatal(runErr)
			}
		case relayErr := <-relayErrs:
			close(stop)
			<-relayDone
			<-relayDone
			t.Fatal(relayErr)
		case <-time.After(90 * time.Second):
			close(stop)
			<-relayDone
			<-relayDone
			t.Fatal("host compute did not complete")
		}
	}
	close(stop)
	<-relayDone
	<-relayDone
	select {
	case relayErr := <-relayErrs:
		t.Fatal(relayErr)
	default:
	}
	for index, host := range hosts {
		host.mu.Lock()
		owner := host.owner
		host.mu.Unlock()
		owner.mu.Lock()
		sealed := owner.terminal != nil && owner.attempts == nil && owner.jobKeys == nil
		owner.mu.Unlock()
		if !sealed {
			t.Fatalf("host %d did not retain only the sealed terminal owner", index)
		}
	}
}
