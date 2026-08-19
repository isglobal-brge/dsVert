package main

import (
	"crypto/sha256"
	"encoding/json"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func TestFormalGLMRegisteredPhase19ComputePipelineK2SealsTerminal(
	t *testing.T,
) {
	formalGLMRegisteredPhase19ComputePipelineSealsTerminalV1(t, 2)
}

func TestFormalGLMRegisteredPhase19ComputePipelineK3SealsTerminal(
	t *testing.T,
) {
	formalGLMRegisteredPhase19ComputePipelineSealsTerminalV1(t, 3)
}

func TestFormalGLMRegisteredPhase19ComputePipelineK5SealsTerminal(
	t *testing.T,
) {
	formalGLMRegisteredPhase19ComputePipelineSealsTerminalV1(t, 5)
}

func formalGLMRegisteredPhase19ComputePipelineSealsTerminalV1(
	t *testing.T,
	custodians int,
) {
	t.Helper()
	fixture := formalGLMRegisteredPhase19FanInTestCached(t, custodians)
	source := fixture.loader.provenance.source
	plan := source.plan
	peers := plan.DesignatedComputePeers
	contract := source.contract
	pins := source.inputs.identities.public
	private := source.inputs.identities.private
	record := fixture.loader.record

	var attempts [2]*formalGLMRegisteredPhase19AttemptStoreV1
	var roots [2]string
	for index, peer := range peers {
		roots[index] = formalGLMRegisteredPhase19LoaderTestRoot(
			t, "compute-pipeline-attempt-"+peer)
		if err := os.Mkdir(roots[index], 0o700); err != nil {
			t.Fatal(err)
		}
		store, err := newFormalGLMRegisteredPhase19AttemptStoreV1(
			roots[index], record, contract, pins, peer, private[peer])
		if err != nil {
			t.Fatal(err)
		}
		attempts[index] = store
	}
	proposal, _, err := attempts[0].Begin(nil)
	if err != nil {
		t.Fatal(err)
	}
	accept, _, err := attempts[1].Accept(proposal)
	if err != nil {
		t.Fatal(err)
	}

	legacy := formalGLMRegisteredExecutionLegacyPlanMustForTest(t, plan)
	_, requiredBytes, err := formalGLMPhase19StreamStoreRequiredBytes(legacy)
	if err != nil {
		t.Fatal(err)
	}
	backend := sha256.Sum256([]byte(t.Name() + "/backend"))
	var runtimes [2]*formalGLMRegisteredPhase19EphemeralRuntimeV1
	var ingress [2]*formalGLMRegisteredPhase18IngressStoreV3
	var streams [2]*formalGLMRegisteredPhase19BlockStreamV1
	var jobKeys [2]*formalGLMRegisteredPhase20JobKeyProviderV1
	var pipelines [2]*formalGLMRegisteredPhase19ComputePipelineV1
	for index, peer := range peers {
		runtimes[index], err = newFormalGLMRegisteredPhase19EphemeralRuntimeV1(
			record, contract, pins, backend)
		if err != nil {
			t.Fatal(err)
		}
		ingress[index] = formalGLMRegisteredPhase19LoaderTestStore(t,
			fixture.loader, formalGLMRegisteredPhase19LoaderTestRoot(
				t, "compute-pipeline-ingress-"+peer), peer,
			fixture.loader.receiptSet.GlobalMaterializationRootSHA256,
			fixture.loader.localKeys[peer])
		formalGLMRegisteredPhase19LoaderTestCommit(
			t, fixture.loader, ingress[index], peer, "", -1, nil)
		accumulator, accumulatorErr := newFormalGLMRegisteredPhase19AccumulatorStoreV1(
			runtimes[index], peer, t.TempDir(), requiredBytes)
		if accumulatorErr != nil {
			t.Fatal(accumulatorErr)
		}
		streams[index], err = newFormalGLMRegisteredPhase19BlockStreamV1(
			runtimes[index], record, contract, pins, attempts[index], proposal, accept,
			ingress[index], fixture.loader.recipientSK[peer], accumulator)
		if err != nil {
			t.Fatal(err)
		}
		jobKeys[index], err = newFormalGLMRegisteredPhase20JobKeyProviderV1(
			roots[index], contract, pins, record, peer)
		if err != nil {
			t.Fatal(err)
		}
		pipelines[index], err = newFormalGLMRegisteredPhase19ComputePipelineV1(
			roots[index], streams[index], runtimes[index], record, contract, pins,
			attempts[index], proposal, accept, jobKeys[index], private[peer])
		if err != nil {
			t.Fatal(err)
		}
		encoded, marshalErr := json.Marshal(pipelines[index])
		if marshalErr != nil || string(encoded) != "{}" {
			t.Fatalf("compute pipeline became serializable: %s / %v", encoded, marshalErr)
		}
	}
	for index := range pipelines {
		t.Cleanup(func() {
			_ = pipelines[index].Close()
			ingress[index].Close()
			runtimes[index].Close()
		})
	}
	if terminal, err := pipelines[0].RunV1(nil); err == nil || terminal != nil {
		t.Fatal("compute pipeline accepted a nil peer channel")
	}

	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	deadline := time.Now().Add(12 * time.Minute)
	_ = left.SetDeadline(deadline)
	_ = right.SetDeadline(deadline)
	var terminals [2]*formalGLMRegisteredPhase20TerminalOwnerV1
	var runErr [2]error
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		terminals[0], runErr[0] = pipelines[0].RunV1(left)
	}()
	go func() {
		defer workers.Done()
		terminals[1], runErr[1] = pipelines[1].RunV1(right)
	}()
	workers.Wait()
	if runErr[0] != nil || runErr[1] != nil {
		t.Fatalf("compute pipeline garbler=%v evaluator=%v", runErr[0], runErr[1])
	}
	for index := range terminals {
		if terminals[index] == nil {
			t.Fatal("compute pipeline returned no terminal owner")
		}
		t.Cleanup(func() { _ = terminals[index].Close() })
		encoded, marshalErr := json.Marshal(terminals[index])
		if marshalErr != nil || string(encoded) != "{}" {
			t.Fatalf("terminal owner exposed pipeline output: %s / %v", encoded, marshalErr)
		}
		status, statusErr := terminals[index].LoadStatusV1()
		if statusErr != nil || !status.draftSealed || status.prepareReceipt != nil ||
			status.selectVote != nil || status.selected != nil {
			t.Fatalf("terminal %d did not retain only the sealed draft: %v", index, statusErr)
		}
		probe := &formalGLMRegisteredPhase19BlockStreamNoIOV1{}
		if terminal, replayErr := pipelines[index].RunV1(probe); replayErr == nil ||
			terminal != nil || probe.touched {
			t.Fatal("completed compute pipeline reused peer I/O")
		}
	}
	receipt, receiptErr := terminals[0].PublishDPShareReceiptV1()
	if receiptErr != nil || receipt.OutputShareSHA256 == "" ||
		receipt.ProtectedPayloadExposed || receipt.MaliciousSecurityClaim {
		t.Fatalf("garbler did not publish a sealed DP receipt: %v", receiptErr)
	}
	if _, receiptErr := terminals[1].PublishDPShareReceiptV1(); receiptErr == nil {
		t.Fatal("evaluator published a DP receipt before the garbler")
	}
}
