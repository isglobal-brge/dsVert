package main

import (
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFormalGLMRegisteredPhase20ComputeReadyK2Binding(t *testing.T) {
	fixture := formalGLMRegisteredPhase20DPShareReceiptTestBuildV1(t)
	runtime := fixture.evidence.runtime
	record := fixture.evidence.record
	contract := fixture.evidence.source.contract
	pins := fixture.evidence.source.inputs.identities.public
	accept := fixture.accept

	garbler, err := formalGLMRegisteredPhase20BuildComputeReadyV1(
		runtime, record, contract, pins, accept, fixture.garbler)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := formalGLMRegisteredPhase20BuildComputeReadyV1(
		runtime, record, contract, pins, accept, fixture.evaluator)
	if err != nil {
		t.Fatal(err)
	}
	if err := formalGLMRegisteredPhase20ValidateComputeReadyPairV1(
		runtime, record, contract, pins, accept, fixture.garbler, garbler, evaluator); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(garbler)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"canonical_dp_share", "evidence_seal", "signature", "path", "key",
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("compute-ready exposed %q: %s", forbidden, encoded)
		}
	}

	mutations := []struct {
		name   string
		mutate func(*formalGLMRegisteredPhase20ComputeReadyV1)
	}{
		{"attempt", func(value *formalGLMRegisteredPhase20ComputeReadyV1) {
			value.AttemptID = formalGLMRegisteredPhase20EvidenceTestDigestV1("attempt")
		}},
		{"accept", func(value *formalGLMRegisteredPhase20ComputeReadyV1) {
			value.ClaimAcceptSHA256 = formalGLMRegisteredPhase20EvidenceTestDigestV1("accept")
		}},
		{"post", func(value *formalGLMRegisteredPhase20ComputeReadyV1) {
			value.PostExecutionRootSHA256 = formalGLMRegisteredPhase20EvidenceTestDigestV1("post")
		}},
		{"pair", func(value *formalGLMRegisteredPhase20ComputeReadyV1) {
			value.ExecutionReceiptPairSHA256 = formalGLMRegisteredPhase20EvidenceTestDigestV1("pair")
		}},
		{"seal", func(value *formalGLMRegisteredPhase20ComputeReadyV1) {
			value.FinalReceiptSetSeal = formalGLMRegisteredPhase20EvidenceTestDigestV1("seal")
		}},
		{"peer", func(value *formalGLMRegisteredPhase20ComputeReadyV1) { value.Peer = garbler.Peer }},
		{"role", func(value *formalGLMRegisteredPhase20ComputeReadyV1) { value.Role = garbler.Role }},
		{"openings", func(value *formalGLMRegisteredPhase20ComputeReadyV1) { value.OpeningsPerformed = 1 }},
		{"production", func(value *formalGLMRegisteredPhase20ComputeReadyV1) { value.ProductionReady = true }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := evaluator
			mutation.mutate(&changed)
			if err := formalGLMRegisteredPhase20ValidateComputeReadyPairV1(
				runtime, record, contract, pins, accept, fixture.garbler, garbler, changed); err == nil {
				t.Fatal("accepted a modified remote compute-ready receipt")
			}
		})
	}
}

func TestFormalGLMRegisteredPhase20ComputeReadyK2Exchange(t *testing.T) {
	fixture := formalGLMRegisteredPhase20DPShareReceiptTestBuildV1(t)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	deadline := time.Now().Add(30 * time.Second)
	_ = left.SetDeadline(deadline)
	_ = right.SetDeadline(deadline)
	var errs [2]error
	var group sync.WaitGroup
	group.Add(2)
	go func() {
		defer group.Done()
		errs[0] = formalGLMRegisteredPhase20ExchangeComputeReadyV1(
			left, fixture.evidence.runtime, fixture.evidence.record,
			fixture.evidence.source.contract, fixture.evidence.source.inputs.identities.public,
			fixture.accept, fixture.garbler)
	}()
	go func() {
		defer group.Done()
		errs[1] = formalGLMRegisteredPhase20ExchangeComputeReadyV1(
			right, fixture.evidence.runtime, fixture.evidence.record,
			fixture.evidence.source.contract, fixture.evidence.source.inputs.identities.public,
			fixture.accept, fixture.evaluator)
	}()
	group.Wait()
	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("compute-ready exchange garbler=%v evaluator=%v", errs[0], errs[1])
	}
}
