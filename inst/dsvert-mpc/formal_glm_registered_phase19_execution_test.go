package main

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type formalGLMRegisteredPhase19ExecutionNoIOV1 struct {
	touched bool
}

func (rw *formalGLMRegisteredPhase19ExecutionNoIOV1) Read([]byte) (int, error) {
	rw.touched = true
	return 0, io.ErrUnexpectedEOF
}

func (rw *formalGLMRegisteredPhase19ExecutionNoIOV1) Write([]byte) (int, error) {
	rw.touched = true
	return 0, io.ErrClosedPipe
}

func formalGLMRegisteredPhase19ExecutionTestFanIn(
	t testing.TB,
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	fixture formalGLMRegisteredPhase19FanInTestFixtureV1,
	recipient string,
	blockIndex int,
) formalGLMRegisteredPhase19FanInResultV1 {
	t.Helper()
	blocks := formalGLMRegisteredPhase19FanInTestCloneBlocks(
		t, fixture.blocks[recipient])
	defer formalGLMRegisteredPhase19ClearPrivateBlocksV1(blocks)
	result, err := formalGLMRegisteredPhase19FanInBlockV1(
		runtime, blocks, recipient, blockIndex)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func formalGLMRegisteredPhase19ExecutionTestRoundTrip[T any](
	t testing.TB,
	value T,
) T {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(encoded))
	for _, forbidden := range []string{
		"capsule", "run_id", "pre_execution", "preexecution", "path",
		"secret", "backend", "master_key", "tuple_shares",
		"coordinate_shares", "validity_shares", "execution_share",
	} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("registered Phase19 execution JSON exposed %q: %s",
				forbidden, encoded)
		}
	}
	var decoded T
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestFormalGLMRegisteredPhase19ExecutionK2PublicDuplexAndPair(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase19FanInTestCached(t, 2)
	plan := fixture.loader.provenance.source.plan
	blockIndex := 0
	garblerName := plan.DesignatedComputePeers[0]
	evaluatorName := plan.DesignatedComputePeers[1]
	garblerRuntime := formalGLMRegisteredPhase19FanInTestRuntime(t, fixture)
	evaluatorRuntime := formalGLMRegisteredPhase19FanInTestRuntime(t, fixture)
	garblerFanIn := formalGLMRegisteredPhase19ExecutionTestFanIn(
		t, garblerRuntime, fixture, garblerName, blockIndex)
	defer formalGLMRegisteredPhase19ClearFanInResultV1(&garblerFanIn)
	evaluatorFanIn := formalGLMRegisteredPhase19ExecutionTestFanIn(
		t, evaluatorRuntime, fixture, evaluatorName, blockIndex)
	defer formalGLMRegisteredPhase19ClearFanInResultV1(&evaluatorFanIn)

	garblerReceipt, err := formalGLMRegisteredPhase19ExportFanInReceiptV1(
		garblerRuntime, garblerFanIn)
	if err != nil {
		t.Fatal(err)
	}
	evaluatorReceipt, err := formalGLMRegisteredPhase19ExportFanInReceiptV1(
		evaluatorRuntime, evaluatorFanIn)
	if err != nil {
		t.Fatal(err)
	}
	garblerReceipt = formalGLMRegisteredPhase19ExecutionTestRoundTrip(
		t, garblerReceipt)
	evaluatorReceipt = formalGLMRegisteredPhase19ExecutionTestRoundTrip(
		t, evaluatorReceipt)

	attempt := sha256.Sum256([]byte(t.Name() + "/attempt"))
	garblerExecution, err := formalGLMRegisteredPhase19PrepareBlockExecutionV1(
		garblerRuntime, garblerFanIn, evaluatorReceipt, attempt)
	if err != nil {
		t.Fatal(err)
	}
	defer garblerExecution.Close()
	evaluatorExecution, err := formalGLMRegisteredPhase19PrepareBlockExecutionV1(
		evaluatorRuntime, evaluatorFanIn, garblerReceipt, attempt)
	if err != nil {
		t.Fatal(err)
	}
	defer evaluatorExecution.Close()
	for name, execution := range map[string]any{
		"garbler":   garblerExecution,
		"evaluator": evaluatorExecution,
	} {
		encoded, marshalErr := json.Marshal(execution)
		if marshalErr != nil || string(encoded) != "{}" {
			t.Fatalf("%s execution trust type became serializable: %s / %v",
				name, encoded, marshalErr)
		}
	}

	garblerConn, evaluatorConn := net.Pipe()
	defer garblerConn.Close()
	defer evaluatorConn.Close()
	deadline := time.Now().Add(60 * time.Second)
	_ = garblerConn.SetDeadline(deadline)
	_ = evaluatorConn.SetDeadline(deadline)

	// Preparation must snapshot all private state. Holding both registered
	// runtime mutexes proves that the blocking exact-GC transport does not.
	garblerRuntime.mu.Lock()
	evaluatorRuntime.mu.Lock()
	var garblerMasked, evaluatorMasked formalGLMRegisteredPhase19MaskedBlockV1
	var garblerErr, evaluatorErr error
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		garblerMasked, garblerErr = formalGLMRegisteredPhase19RunBlockPeerV1(
			garblerConn, garblerExecution)
	}()
	go func() {
		defer workers.Done()
		evaluatorMasked, evaluatorErr = formalGLMRegisteredPhase19RunBlockPeerV1(
			evaluatorConn, evaluatorExecution)
	}()
	workers.Wait()
	evaluatorRuntime.mu.Unlock()
	garblerRuntime.mu.Unlock()
	if garblerErr != nil || evaluatorErr != nil {
		t.Fatalf("registered Phase19 duplex garbler=%v evaluator=%v",
			garblerErr, evaluatorErr)
	}
	defer garblerMasked.Close()
	defer evaluatorMasked.Close()
	probe := &formalGLMRegisteredPhase19ExecutionNoIOV1{}
	if _, err := formalGLMRegisteredPhase19RunBlockPeerV1(
		probe, garblerExecution); err == nil || probe.touched {
		t.Fatal("claimed registered Phase19 session was reused or touched I/O")
	}

	garblerPublic := formalGLMRegisteredPhase19ExecutionTestRoundTrip(
		t, garblerMasked.Receipt)
	evaluatorPublic := formalGLMRegisteredPhase19ExecutionTestRoundTrip(
		t, evaluatorMasked.Receipt)
	garblerPair, err := formalGLMRegisteredPhase19PairMaskedReceiptsV1(
		garblerExecution, garblerPublic, evaluatorPublic)
	if err != nil {
		t.Fatal(err)
	}
	defer garblerPair.Close()
	evaluatorPair, err := formalGLMRegisteredPhase19PairMaskedReceiptsV1(
		evaluatorExecution, garblerPublic, evaluatorPublic)
	if err != nil {
		t.Fatal(err)
	}
	defer evaluatorPair.Close()
	formalGLMRegisteredPhase19ExecutionTestRoundTrip(t, garblerPair)
	if !reflect.DeepEqual(garblerPair.Public(), evaluatorPair.Public()) ||
		garblerPair.ReceiptPairSHA256 == "" ||
		!garblerPair.ExecutionValidSealed ||
		garblerPair.ExecutionValidityOpened ||
		garblerPair.OpeningsPerformed != 0 || garblerPair.ProductionReady {
		t.Fatal("registered Phase19 peers derived different public receipt pairs")
	}
	if err := formalGLMPhase19VerifyMaskedBlock(
		garblerExecution.plan, garblerExecution.context,
		garblerExecution.pair, garblerMasked.block,
		garblerExecution.backendKey); err != nil {
		t.Fatal(err)
	}
	if err := formalGLMPhase19VerifyMaskedBlock(
		evaluatorExecution.plan, evaluatorExecution.context,
		evaluatorExecution.pair, evaluatorMasked.block,
		evaluatorExecution.backendKey); err != nil {
		t.Fatal(err)
	}
	tampered := evaluatorPublic
	tampered.Receipt.ReceiptMAC = strings.Repeat("0", 64)
	if _, err := formalGLMRegisteredPhase19PairMaskedReceiptsV1(
		garblerExecution, garblerPublic, tampered); err == nil {
		t.Fatal("tampered registered masked receipt was paired")
	}
	if _, err := formalGLMRegisteredPhase19PairMaskedReceiptsV1(
		garblerExecution, evaluatorPublic, garblerPublic); err == nil {
		t.Fatal("swapped registered masked receipt roles were paired")
	}
}

func TestFormalGLMRegisteredPhase19ExecutionRejectsBindingAndBackend(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase19FanInTestCached(t, 2)
	plan := fixture.loader.provenance.source.plan
	blockIndex := 0
	garblerName := plan.DesignatedComputePeers[0]
	evaluatorName := plan.DesignatedComputePeers[1]
	garblerRuntime := formalGLMRegisteredPhase19FanInTestRuntime(t, fixture)
	evaluatorRuntime := formalGLMRegisteredPhase19FanInTestRuntime(t, fixture)
	garblerFanIn := formalGLMRegisteredPhase19ExecutionTestFanIn(
		t, garblerRuntime, fixture, garblerName, blockIndex)
	defer formalGLMRegisteredPhase19ClearFanInResultV1(&garblerFanIn)
	evaluatorFanIn := formalGLMRegisteredPhase19ExecutionTestFanIn(
		t, evaluatorRuntime, fixture, evaluatorName, blockIndex)
	defer formalGLMRegisteredPhase19ClearFanInResultV1(&evaluatorFanIn)
	garblerReceipt, err := formalGLMRegisteredPhase19ExportFanInReceiptV1(
		garblerRuntime, garblerFanIn)
	if err != nil {
		t.Fatal(err)
	}
	evaluatorReceipt, err := formalGLMRegisteredPhase19ExportFanInReceiptV1(
		evaluatorRuntime, evaluatorFanIn)
	if err != nil {
		t.Fatal(err)
	}
	attempt := sha256.Sum256([]byte(t.Name() + "/attempt"))

	for _, test := range []struct {
		name   string
		mutate func(formalGLMRegisteredPhase19FanInReceiptV1) formalGLMRegisteredPhase19FanInReceiptV1
	}{
		{
			name: "semantic-root",
			mutate: func(value formalGLMRegisteredPhase19FanInReceiptV1) formalGLMRegisteredPhase19FanInReceiptV1 {
				value.SemanticRootSHA256 = strings.Repeat("a", 64)
				return value
			},
		},
		{
			name: "receipt-mac",
			mutate: func(value formalGLMRegisteredPhase19FanInReceiptV1) formalGLMRegisteredPhase19FanInReceiptV1 {
				value.Receipt.ReceiptMAC = strings.Repeat("0", 64)
				return value
			},
		},
		{
			name: "recipient",
			mutate: func(value formalGLMRegisteredPhase19FanInReceiptV1) formalGLMRegisteredPhase19FanInReceiptV1 {
				value.Recipient = garblerName
				return value
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			peer := formalGLMRegisteredPhase19ExecutionTestRoundTrip(
				t, evaluatorReceipt)
			peer = test.mutate(peer)
			if execution, prepareErr :=
				formalGLMRegisteredPhase19PrepareBlockExecutionV1(
					garblerRuntime, garblerFanIn, peer, attempt); prepareErr == nil {
				execution.Close()
				t.Fatal("modified registered fan-in receipt was prepared")
			}
		})
	}
	if execution, err := formalGLMRegisteredPhase19PrepareBlockExecutionV1(
		garblerRuntime, garblerFanIn, evaluatorReceipt, [32]byte{}); err == nil {
		execution.Close()
		t.Fatal("zero registered Phase19 attempt was prepared")
	}
	if execution, err := formalGLMRegisteredPhase19PrepareBlockExecutionV1(
		garblerRuntime, garblerFanIn, garblerReceipt, attempt); err == nil {
		execution.Close()
		t.Fatal("same-role registered fan-in pair was prepared")
	}

	otherBackend := sha256.Sum256([]byte(t.Name() + "/other-backend"))
	otherRuntime, err := newFormalGLMRegisteredPhase19EphemeralRuntimeV1(
		fixture.loader.record, fixture.loader.provenance.source.contract,
		fixture.loader.provenance.source.inputs.identities.public,
		otherBackend)
	if err != nil {
		t.Fatal(err)
	}
	defer otherRuntime.Close()
	otherLocal := formalGLMRegisteredPhase19ExecutionTestFanIn(
		t, otherRuntime, fixture, garblerName, blockIndex)
	defer formalGLMRegisteredPhase19ClearFanInResultV1(&otherLocal)
	if execution, err := formalGLMRegisteredPhase19PrepareBlockExecutionV1(
		otherRuntime, otherLocal, evaluatorReceipt, attempt); err == nil {
		execution.Close()
		t.Fatal("fan-in receipt authenticated under another backend was prepared")
	}
}
