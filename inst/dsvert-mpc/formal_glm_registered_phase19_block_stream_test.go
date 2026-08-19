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

type formalGLMRegisteredPhase19BlockStreamNoIOV1 struct{ touched bool }

func (rw *formalGLMRegisteredPhase19BlockStreamNoIOV1) Read([]byte) (int, error) {
	rw.touched = true
	return 0, net.ErrClosed
}

func (rw *formalGLMRegisteredPhase19BlockStreamNoIOV1) Write([]byte) (int, error) {
	rw.touched = true
	return 0, net.ErrClosed
}

func TestFormalGLMRegisteredPhase19BlockStreamK2Accumulator(t *testing.T) {
	fixture := formalGLMRegisteredPhase19FanInTestCached(t, 2)
	source := fixture.loader.provenance.source
	plan := source.plan
	var attempts [2]*formalGLMRegisteredPhase19AttemptStoreV1
	var err error
	for index, peer := range plan.DesignatedComputePeers {
		root := formalGLMRegisteredPhase19LoaderTestRoot(t, "block-stream-attempt-"+peer)
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		attempts[index], err = newFormalGLMRegisteredPhase19AttemptStoreV1(
			root, fixture.loader.record, source.contract,
			source.inputs.identities.public, peer,
			source.inputs.identities.private[peer])
		if err != nil {
			t.Fatal(err)
		}
	}
	proposal, _, err := attempts[0].Begin(nil)
	if err != nil {
		t.Fatal(err)
	}
	accept, _, err := attempts[1].Accept(proposal)
	if err != nil {
		t.Fatal(err)
	}
	defer attempts[0].Close()
	defer attempts[1].Close()
	backend := sha256.Sum256([]byte(t.Name() + "/backend"))
	var runtimes [2]*formalGLMRegisteredPhase19EphemeralRuntimeV1
	var ingress [2]*formalGLMRegisteredPhase18IngressStoreV3
	var accumulators [2]*formalGLMRegisteredPhase19AccumulatorStoreV1
	var streams [2]*formalGLMRegisteredPhase19BlockStreamV1
	legacy := formalGLMRegisteredExecutionLegacyPlanMustForTest(t, plan)
	_, requiredBytes, err := formalGLMPhase19StreamStoreRequiredBytes(legacy)
	if err != nil {
		t.Fatal(err)
	}
	for index, peer := range plan.DesignatedComputePeers {
		runtimes[index], err = newFormalGLMRegisteredPhase19EphemeralRuntimeV1(
			fixture.loader.record, source.contract, source.inputs.identities.public, backend)
		if err != nil {
			t.Fatal(err)
		}
		defer runtimes[index].Close()
		ingress[index] = formalGLMRegisteredPhase19LoaderTestStore(t,
			fixture.loader, formalGLMRegisteredPhase19LoaderTestRoot(t, "block-stream-"+peer),
			peer, fixture.loader.receiptSet.GlobalMaterializationRootSHA256,
			fixture.loader.localKeys[peer])
		defer ingress[index].Close()
		formalGLMRegisteredPhase19LoaderTestCommit(
			t, fixture.loader, ingress[index], peer, "", -1, nil)
		accumulators[index], err = newFormalGLMRegisteredPhase19AccumulatorStoreV1(
			runtimes[index], peer, t.TempDir(), requiredBytes)
		if err != nil {
			t.Fatal(err)
		}
		streams[index], err = newFormalGLMRegisteredPhase19BlockStreamV1(
			runtimes[index], fixture.loader.record, source.contract,
			source.inputs.identities.public, attempts[index], proposal, accept, ingress[index],
			fixture.loader.recipientSK[peer], accumulators[index])
		if err != nil {
			t.Fatal(err)
		}
		defer streams[index].Close()
		encoded, marshalErr := json.Marshal(streams[index])
		if marshalErr != nil || string(encoded) != "{}" {
			t.Fatalf("block stream became serializable: %s / %v", encoded, marshalErr)
		}
	}

	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	deadline := time.Now().Add(8 * time.Minute)
	_ = left.SetDeadline(deadline)
	_ = right.SetDeadline(deadline)
	var runErr [2]error
	var workers sync.WaitGroup
	workers.Add(2)
	go func() { defer workers.Done(); runErr[0] = streams[0].RunV1(left) }()
	go func() { defer workers.Done(); runErr[1] = streams[1].RunV1(right) }()
	workers.Wait()
	if runErr[0] != nil || runErr[1] != nil {
		t.Fatalf("block stream garbler=%v evaluator=%v", runErr[0], runErr[1])
	}
	for index := range streams {
		probe := &formalGLMRegisteredPhase19BlockStreamNoIOV1{}
		if err := streams[index].RunV1(probe); err == nil || probe.touched {
			t.Fatal("completed block stream was reusable or touched I/O")
		}
	}

	root, err := formalGLMPhase19ScheduleDecodeHex32(
		proposal.Binding.ScheduleRootSHA256, "root")
	if err != nil {
		t.Fatal(err)
	}
	accumulatorAttempt := formalGLMPhase19RuntimeAttempt(
		root, "phase19-accumulator", 0, -1)
	clear(root[:])
	var executions [2]*formalGLMRegisteredPhase19AccumulatorExecutionV1
	for index := range executions {
		executions[index], _, err = formalGLMRegisteredPhase19PrepareAccumulatorV1(
			runtimes[index], accumulators[index], accumulatorAttempt)
		if err != nil {
			t.Fatal(err)
		}
		defer executions[index].Close()
	}
	clear(accumulatorAttempt[:])
	leftAccumulator, rightAccumulator := net.Pipe()
	defer leftAccumulator.Close()
	defer rightAccumulator.Close()
	_ = leftAccumulator.SetDeadline(time.Now().Add(3 * time.Minute))
	_ = rightAccumulator.SetDeadline(time.Now().Add(3 * time.Minute))
	var seals [2]formalGLMRegisteredPhase19AccumulatorSealV1
	workers.Add(2)
	go func() {
		defer workers.Done()
		seals[0], runErr[0] = formalGLMRegisteredPhase19RunAccumulatorPeerV1(leftAccumulator, executions[0])
	}()
	go func() {
		defer workers.Done()
		seals[1], runErr[1] = formalGLMRegisteredPhase19RunAccumulatorPeerV1(rightAccumulator, executions[1])
	}()
	workers.Wait()
	if runErr[0] != nil || runErr[1] != nil {
		t.Fatalf("block stream accumulator garbler=%v evaluator=%v", runErr[0], runErr[1])
	}
	defer seals[0].Close()
	defer seals[1].Close()
	for index := range executions {
		pair, pairErr := formalGLMRegisteredPhase19PairAccumulatorReceiptsV1(
			executions[index], seals[0].Receipt, seals[1].Receipt)
		if pairErr != nil || !pair.ExecutionValidSealed ||
			pair.ExecutionValidityOpened || pair.ProductionReady {
			t.Fatalf("invalid accumulated registered execution %d: %v", index, pairErr)
		}
		pair.Close()
	}
}
