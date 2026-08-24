package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"runtime"
	"testing"
)

func formalGLMRegisteredPhase20JobControlHostTestConfigV1(
	t testing.TB,
	fixture *formalGLMRegisteredPhase20JobControlTestFixtureV1,
	index int,
) formalGLMRegisteredPhase20JobControlHostConfigV1 {
	t.Helper()
	peer := fixture.core.source.plan.DesignatedComputePeers[index]
	pins := make(map[string]ed25519.PublicKey, len(fixture.core.source.inputs.identities.public))
	for name, pin := range fixture.core.source.inputs.identities.public {
		pins[name] = append(ed25519.PublicKey(nil), pin...)
	}
	return formalGLMRegisteredPhase20JobControlHostConfigV1{
		Version:  formalGLMRegisteredPhase20JobControlHostVersionV1,
		Contract: fixture.core.source.contract,
		Record:   fixture.core.record,
		Pins:     pins,
		Peer:     peer,
		Signing:  append(ed25519.PrivateKey(nil), fixture.core.source.inputs.identities.private[peer]...),
		Start:    fixture.start,
	}
}

func formalGLMRegisteredPhase20JobControlHostTestReleaseFixtureV1(
	t testing.TB,
	fixture *formalGLMRegisteredPhase20JobControlTestFixtureV1,
) {
	t.Helper()
	for index := range 2 {
		if fixture.attempts[index] != nil {
			fixture.attempts[index].Close()
			fixture.attempts[index] = nil
		}
		if fixture.jobKeys[index] != nil {
			if err := fixture.jobKeys[index].Close(); err != nil {
				t.Fatal(err)
			}
			fixture.jobKeys[index] = nil
		}
		fixture.controls[index] = nil
	}
}

func TestFormalGLMRegisteredPhase20JobControlHostK2(t *testing.T) {
	fixture := newFormalGLMRegisteredPhase20JobControlTestFixtureV1(t)
	configs := [2]formalGLMRegisteredPhase20JobControlHostConfigV1{
		formalGLMRegisteredPhase20JobControlHostTestConfigV1(t, fixture, 0),
		formalGLMRegisteredPhase20JobControlHostTestConfigV1(t, fixture, 1),
	}
	formalGLMRegisteredPhase20JobControlHostTestReleaseFixtureV1(t, fixture)

	hosts := [2]*formalGLMRegisteredPhase20JobControlHostV1{}
	for index := range hosts {
		var err error
		hosts[index], err = newFormalGLMRegisteredPhase20JobControlHostV1(
			fixture.roots[index], configs[index])
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = hosts[index].Close() })
		encoded, err := json.Marshal(hosts[index])
		if err != nil || !bytes.Equal(encoded, []byte(`{}`)) {
			t.Fatalf("host %d exposed private state: %q / %v", index, encoded, err)
		}
	}

	waiting, err := hosts[1].NegotiateV1(nil)
	if err != nil || waiting.state != formalGLMRegisteredPhase20JobControlWaitingProposalStateV1 ||
		len(waiting.outbound) != 0 || waiting.productionReady {
		t.Fatalf("evaluator did not wait: %+v / %v", waiting, err)
	}
	proposal, err := hosts[0].NegotiateV1(nil)
	if err != nil || proposal.state != formalGLMRegisteredPhase20JobControlProposalStateV1 ||
		len(proposal.outbound) == 0 || proposal.productionReady {
		t.Fatalf("garbler did not issue a proposal: %+v / %v", proposal, err)
	}
	accepted, err := hosts[1].NegotiateV1(proposal.outbound)
	if err != nil || accepted.state != formalGLMRegisteredPhase20JobControlAcceptedStateV1 ||
		len(accepted.outbound) == 0 || accepted.productionReady {
		t.Fatalf("evaluator did not accept: %+v / %v", accepted, err)
	}
	if adopted, err := hosts[0].NegotiateV1(accepted.outbound); err != nil ||
		adopted.state != formalGLMRegisteredPhase20JobControlAcceptedStateV1 ||
		len(adopted.outbound) != 0 || adopted.productionReady {
		t.Fatalf("garbler did not adopt the acceptance: %+v / %v", adopted, err)
	}

	for index := range hosts {
		started, startErr := hosts[index].StartOrInspectV1()
		if startErr != nil || started.state != formalGLMRegisteredPhase20JobOwnerRunningStateV1 ||
			started.inspectOnly || started.productionReady {
			t.Fatalf("host %d did not own a running controller: %+v / %v", index, started, startErr)
		}
	}
	refs := [2]formalGLMRegisteredPhase20JobRefV1{}
	frames := [2][]byte{}
	for index := range hosts {
		var refErr error
		refs[index], frames[index], refErr = hosts[index].JobRefV1()
		if refErr != nil || refs[index].ProductionReady || len(frames[index]) == 0 {
			t.Fatalf("host %d did not issue a private JobRef: %+v / %v", index, refs[index], refErr)
		}
	}
	for index := range hosts {
		if err := hosts[index].BindPeerJobRefV1(frames[1-index]); err != nil {
			t.Fatalf("host %d did not persist the peer binding: %v", index, err)
		}
		if err := hosts[index].HeartbeatV1(); err != nil {
			t.Fatalf("host %d heartbeat failed after binding: %v", index, err)
		}
		result, pollErr := hosts[index].PollV1(refs[index], 0)
		if pollErr != nil || result.ProductionReady || result.State != formalGLMRegisteredPhase20JobRunningV1 ||
			result.RelayChunk != nil {
			t.Fatalf("host %d leaked or changed an idle relay: %+v / %v", index, result, pollErr)
		}
	}
}

func TestFormalGLMRegisteredPhase20JobControlHostRejectsCrossedAuthority(t *testing.T) {
	fixture := newFormalGLMRegisteredPhase20JobControlTestFixtureV1(t)
	config := formalGLMRegisteredPhase20JobControlHostTestConfigV1(t, fixture, 0)
	formalGLMRegisteredPhase20JobControlHostTestReleaseFixtureV1(t, fixture)

	config.Signing = append(ed25519.PrivateKey(nil), fixture.core.source.inputs.identities.private[fixture.core.source.plan.DesignatedComputePeers[1]]...)
	if host, err := newFormalGLMRegisteredPhase20JobControlHostV1(fixture.roots[0], config); err == nil || host != nil {
		if host != nil {
			_ = host.Close()
		}
		t.Fatal("host accepted a signing key from the other compute authority")
	}
}

func TestFormalGLMRegisteredPhase20JobControlHostRetainsPublicationContextPrivately(t *testing.T) {
	fixture := newFormalGLMRegisteredPhase20JobControlTestFixtureV1(t)
	config := formalGLMRegisteredPhase20JobControlHostTestConfigV1(t, fixture, 0)
	publication := formalGLMRegisteredPhase21PublicationContextTestBuildV1(t, fixture.core.source)
	config.Publication = &publication
	formalGLMRegisteredPhase20JobControlHostTestReleaseFixtureV1(t, fixture)

	host, err := newFormalGLMRegisteredPhase20JobControlHostV1(fixture.roots[0], config)
	if err != nil {
		t.Fatal(err)
	}
	config.Publication.RegistryResolution.ArtifactID = ""
	host.mu.Lock()
	retained := host.publication
	valid := retained != nil &&
		formalGLMRegisteredPhase21PublicationContextValidateV1(
			*retained, fixture.core.source.contract,
			fixture.core.source.inputs.identities.public) == nil
	host.mu.Unlock()
	if !valid {
		_ = host.Close()
		t.Fatal("host did not retain an independent signed publication context")
	}
	encoded, marshalErr := json.Marshal(host)
	if marshalErr != nil || !bytes.Equal(encoded, []byte(`{}`)) {
		_ = host.Close()
		t.Fatalf("host exposed publication context: %q / %v", encoded, marshalErr)
	}
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
	host.mu.Lock()
	cleared := host.publication == nil
	host.mu.Unlock()
	if !cleared {
		t.Fatal("host retained publication context after close")
	}
}

func TestFormalGLMRegisteredPhase20JobControlHostCloseWaitsForOperation(t *testing.T) {
	fixture := newFormalGLMRegisteredPhase20JobControlTestFixtureV1(t)
	config := formalGLMRegisteredPhase20JobControlHostTestConfigV1(t, fixture, 0)
	formalGLMRegisteredPhase20JobControlHostTestReleaseFixtureV1(t, fixture)
	host, err := newFormalGLMRegisteredPhase20JobControlHostV1(fixture.roots[0], config)
	if err != nil {
		t.Fatal(err)
	}
	owner, release, err := host.beginOpV1()
	if err != nil || owner == nil || release == nil {
		t.Fatalf("host did not issue an operation lease: %v", err)
	}
	closed := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		closed <- host.Close()
	}()
	<-started
	closing := false
	for range 10000 {
		host.mu.Lock()
		closing = host.closed
		host.mu.Unlock()
		if closing {
			break
		}
		runtime.Gosched()
	}
	if !closing {
		t.Fatal("host close did not begin")
	}
	select {
	case closeErr := <-closed:
		t.Fatalf("host close raced an active operation: %v", closeErr)
	default:
	}
	release()
	if closeErr := <-closed; closeErr != nil {
		t.Fatal(closeErr)
	}
	if _, release, beginErr := host.beginOpV1(); beginErr == nil || release != nil {
		t.Fatal("closed host issued another operation lease")
	}
}
