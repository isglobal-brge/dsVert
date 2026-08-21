package main

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type formalGLMRegisteredPhase19AccumulatorSignalRWV1 struct {
	net.Conn
	once    sync.Once
	started chan struct{}
}

func (rw *formalGLMRegisteredPhase19AccumulatorSignalRWV1) notify() {
	rw.once.Do(func() { close(rw.started) })
}

func (rw *formalGLMRegisteredPhase19AccumulatorSignalRWV1) Read(
	buffer []byte,
) (int, error) {
	rw.notify()
	return rw.Conn.Read(buffer)
}

func (rw *formalGLMRegisteredPhase19AccumulatorSignalRWV1) Write(
	buffer []byte,
) (int, error) {
	rw.notify()
	return rw.Conn.Write(buffer)
}

type formalGLMRegisteredPhase19AccumulatorNoIOV1 struct {
	touched bool
}

func (rw *formalGLMRegisteredPhase19AccumulatorNoIOV1) Read([]byte) (int, error) {
	rw.touched = true
	return 0, io.ErrUnexpectedEOF
}

func (rw *formalGLMRegisteredPhase19AccumulatorNoIOV1) Write([]byte) (int, error) {
	rw.touched = true
	return 0, io.ErrClosedPipe
}

func formalGLMRegisteredPhase19AccumulatorTestRoundTrip[T any](
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
		"capsule", "run_id", "pre_execution", "preexecution", "attempt",
		"path", "secret", "backend", "master_key", "tuple_share",
		"coordinate_share", "validity_share", "execution_share\"",
	} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("registered accumulator JSON exposed %q: %s",
				forbidden, encoded)
		}
	}
	var decoded T
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func formalGLMRegisteredPhase19AccumulatorTestMaskedBlock(
	execution *formalGLMRegisteredPhase19BlockExecutionV1,
	block formalGLMPhase19MaskedBlock,
) formalGLMRegisteredPhase19MaskedBlockV1 {
	return formalGLMRegisteredPhase19MaskedBlockV1{
		Receipt: formalGLMRegisteredPhase19MaskedReceiptV1{
			Version:                       formalGLMRegisteredPhase19MaskedReceiptVersionV1,
			Purpose:                       formalGLMRegisteredPhase19MaskedReceiptPurposeV1,
			SemanticRootSHA256:            execution.semanticRootSHA256,
			ReceiptSetSHA256:              execution.receiptSetSHA256,
			RegisteredExecutionPlanSHA256: execution.registeredExecutionPlanSHA256,
			Peer:                          execution.peer, BlockIndex: execution.blockIndex,
			RowsInBlock: execution.rowsInBlock, PairRoot: execution.pair.PairRoot,
			Receipt: block.Receipt, OpeningsPerformed: 0, ProductionReady: false,
		},
		block: block,
	}
}

type formalGLMRegisteredPhase19AccumulatorTestFixtureV1 struct {
	base     formalGLMRegisteredPhase19FanInTestFixtureV1
	runtimes [2]*formalGLMRegisteredPhase19EphemeralRuntimeV1
	owners   [2]*formalGLMRegisteredPhase19AccumulatorStoreV1
}

func formalGLMRegisteredPhase19AccumulatorTestBuild(
	t *testing.T,
) formalGLMRegisteredPhase19AccumulatorTestFixtureV1 {
	t.Helper()
	base := formalGLMRegisteredPhase19FanInTestCached(t, 2)
	plan := base.loader.provenance.source.plan
	fixture := formalGLMRegisteredPhase19AccumulatorTestFixtureV1{base: base}
	_, required, err := formalGLMPhase19StreamStoreRequiredBytes(
		formalGLMRegisteredExecutionLegacyPlanMustForTest(t, plan))
	if err != nil {
		t.Fatal(err)
	}
	for peerIndex, peer := range plan.DesignatedComputePeers {
		fixture.runtimes[peerIndex] =
			formalGLMRegisteredPhase19FanInTestRuntime(t, base)
		owner, ownerErr := newFormalGLMRegisteredPhase19AccumulatorStoreV1(
			fixture.runtimes[peerIndex], peer, t.TempDir(), required)
		if ownerErr != nil {
			t.Fatal(ownerErr)
		}
		fixture.owners[peerIndex] = owner
		t.Cleanup(func() { _ = owner.Destroy() })
	}
	for blockIndex := 0; blockIndex < plan.TotalBlocks; blockIndex++ {
		var fanIn [2]formalGLMRegisteredPhase19FanInResultV1
		var receipt [2]formalGLMRegisteredPhase19FanInReceiptV1
		for peerIndex, peer := range plan.DesignatedComputePeers {
			fanIn[peerIndex] = formalGLMRegisteredPhase19ExecutionTestFanIn(
				t, fixture.runtimes[peerIndex], base, peer, blockIndex)
			receipt[peerIndex], err = formalGLMRegisteredPhase19ExportFanInReceiptV1(
				fixture.runtimes[peerIndex], fanIn[peerIndex])
			if err != nil {
				t.Fatal(err)
			}
		}
		blockAttempt := sha256.Sum256([]byte(t.Name() + "/block/" +
			string(rune(blockIndex+'0'))))
		garblerExecution, err := formalGLMRegisteredPhase19PrepareBlockExecutionV1(
			fixture.runtimes[0], fanIn[0], receipt[1], blockAttempt)
		if err != nil {
			t.Fatal(err)
		}
		evaluatorExecution, err := formalGLMRegisteredPhase19PrepareBlockExecutionV1(
			fixture.runtimes[1], fanIn[1], receipt[0], blockAttempt)
		if err != nil {
			garblerExecution.Close()
			t.Fatal(err)
		}
		layout, err := formalGLMPhase19Layout(
			garblerExecution.plan, garblerExecution.context)
		if err != nil {
			t.Fatal(err)
		}
		leftShares := make([]*big.Int, layout.CoordinateCount)
		rightShares := make([]*big.Int, layout.CoordinateCount)
		for index := range leftShares {
			leftShares[index], rightShares[index] = new(big.Int), new(big.Int)
		}
		left, err := formalGLMPhase19BuildMaskedBlock(
			garblerExecution.plan, garblerExecution.context,
			garblerExecution.pair, garblerExecution.session,
			garblerExecution.peer, leftShares, 0, garblerExecution.backendKey)
		if err != nil {
			t.Fatal(err)
		}
		right, err := formalGLMPhase19BuildMaskedBlock(
			evaluatorExecution.plan, evaluatorExecution.context,
			evaluatorExecution.pair, evaluatorExecution.session,
			evaluatorExecution.peer, rightShares, 1,
			evaluatorExecution.backendKey)
		exactGCZeroBigInts(leftShares)
		exactGCZeroBigInts(rightShares)
		if err != nil {
			t.Fatal(err)
		}
		registeredLeft := formalGLMRegisteredPhase19AccumulatorTestMaskedBlock(
			garblerExecution, left)
		registeredRight := formalGLMRegisteredPhase19AccumulatorTestMaskedBlock(
			evaluatorExecution, right)
		pair, err := formalGLMRegisteredPhase19PairMaskedReceiptsV1(
			garblerExecution, registeredLeft.Receipt, registeredRight.Receipt)
		if err != nil {
			t.Fatal(err)
		}
		if blockIndex == 0 {
			tamperedPair := pair
			tamperedPair.PairRoot = strings.Repeat("a", 64)
			if err := fixture.owners[0].AppendRegisteredV1(
				registeredLeft, tamperedPair); err == nil {
				t.Fatal("registered accumulator accepted a modified pair root")
			}
			tamperedBlock := registeredLeft
			tamperedBlock.Receipt.Peer = plan.DesignatedComputePeers[1]
			if err := fixture.owners[0].AppendRegisteredV1(
				tamperedBlock, pair); err == nil {
				t.Fatal("registered accumulator accepted a modified block role")
			}
		}
		if err := fixture.owners[0].AppendRegisteredV1(
			registeredLeft, pair); err != nil {
			t.Fatal(err)
		}
		if err := fixture.owners[1].AppendRegisteredV1(
			registeredRight, pair); err != nil {
			t.Fatal(err)
		}
		pair.Close()
		registeredLeft.Close()
		registeredRight.Close()
		garblerExecution.Close()
		evaluatorExecution.Close()
		formalGLMRegisteredPhase19ClearFanInResultV1(&fanIn[0])
		formalGLMRegisteredPhase19ClearFanInResultV1(&fanIn[1])
	}
	for _, owner := range fixture.owners {
		if err := owner.CompleteV1(); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func formalGLMRegisteredExecutionLegacyPlanMustForTest(
	t testing.TB,
	plan formalGLMRegisteredExecutionPlanV1,
) formalGLMPhase15Plan {
	t.Helper()
	legacy, err := formalGLMRegisteredExecutionLegacyPlanV1(plan)
	if err != nil {
		t.Fatal(err)
	}
	return legacy
}

func TestFormalGLMRegisteredPhase19AccumulatorRootedStorePinsRockDirectory(
	t *testing.T,
) {
	base := formalGLMRegisteredPhase19FanInTestCached(t, 2)
	runtime := formalGLMRegisteredPhase19FanInTestRuntime(t, base)
	plan := base.loader.provenance.source.plan
	legacy := formalGLMRegisteredExecutionLegacyPlanMustForTest(t, plan)
	_, required, err := formalGLMPhase19StreamStoreRequiredBytes(legacy)
	if err != nil {
		t.Fatal(err)
	}

	parent := t.TempDir()
	rock := filepath.Join(parent, "rock")
	if err := os.Mkdir(rock, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rock)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	anchored := filepath.Join(parent, "anchored")
	if err := os.Rename(rock, anchored); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(rock, 0o700); err != nil {
		t.Fatal(err)
	}

	owner, err := newFormalGLMRegisteredPhase19AccumulatorStoreRootedV1(
		runtime, plan.DesignatedComputePeers[0], root, "accumulator", required)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Destroy()
	path := filepath.Join(anchored, "accumulator", formalGLMPhase19StreamStoreName)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || !exactGCPrivateOwnedRegular(info) {
		t.Fatalf("rooted accumulator store escaped its opened Rock root: %+v / %v", info, err)
	}
	if _, err := os.Stat(filepath.Join(rock, "accumulator", formalGLMPhase19StreamStoreName)); !os.IsNotExist(err) {
		t.Fatalf("rooted accumulator store followed replacement Rock path: %v", err)
	}
}

func TestFormalGLMRegisteredPhase19AccumulatorK2DuplexAndFailClosed(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase19AccumulatorTestBuild(t)
	plan := fixture.base.loader.provenance.source.plan

	if owner, err := newFormalGLMRegisteredPhase19AccumulatorStoreV1(
		fixture.runtimes[0], "not-a-compute-peer", t.TempDir(), 1); err == nil {
		_ = owner.Destroy()
		t.Fatal("registered accumulator accepted an invalid peer role")
	}
	_, required, err := formalGLMPhase19StreamStoreRequiredBytes(
		formalGLMRegisteredExecutionLegacyPlanMustForTest(t, plan))
	if err != nil {
		t.Fatal(err)
	}
	incomplete, err := newFormalGLMRegisteredPhase19AccumulatorStoreV1(
		fixture.runtimes[0], plan.DesignatedComputePeers[0], t.TempDir(), required)
	if err != nil {
		t.Fatal(err)
	}
	defer incomplete.Destroy()
	if execution, _, err := formalGLMRegisteredPhase19PrepareAccumulatorV1(
		fixture.runtimes[0], incomplete,
		sha256.Sum256([]byte(t.Name()+"/incomplete"))); err == nil {
		_ = execution.Close()
		t.Fatal("registered accumulator prepared an incomplete store")
	}
	closeProbe := &formalGLMRegisteredPhase19AccumulatorExecutionV1{
		owner: incomplete, running: true,
	}
	incomplete.mu.Lock()
	incomplete.state = formalGLMRegisteredPhase19AccumulatorStoreClaimedV1
	incomplete.holder = closeProbe
	rawCloseProbe := incomplete.store
	incomplete.mu.Unlock()
	if err := closeProbe.Close(); err != nil {
		t.Fatal(err)
	}
	incomplete.mu.Lock()
	if incomplete.store == nil {
		incomplete.mu.Unlock()
		t.Fatal("concurrent Close destroyed scratch while Run was active")
	}
	incomplete.mu.Unlock()
	if err := closeProbe.finish(false); err == nil {
		t.Fatal("concurrent Close did not fail the accumulator Run")
	}
	if rawCloseProbe.file != nil || !closeProbe.closed {
		t.Fatal("concurrent Close did not destroy scratch after Run finished")
	}
	if execution, _, err := formalGLMRegisteredPhase19PrepareAccumulatorV1(
		fixture.runtimes[0], fixture.owners[0], [32]byte{}); err == nil {
		_ = execution.Close()
		t.Fatal("registered accumulator accepted a zero attempt")
	}
	otherBackend := sha256.Sum256([]byte(t.Name() + "/other-backend"))
	otherRuntime, err := newFormalGLMRegisteredPhase19EphemeralRuntimeV1(
		fixture.base.loader.record,
		fixture.base.loader.provenance.source.contract,
		fixture.base.loader.provenance.source.inputs.identities.public,
		otherBackend)
	if err != nil {
		t.Fatal(err)
	}
	defer otherRuntime.Close()
	if execution, _, err := formalGLMRegisteredPhase19PrepareAccumulatorV1(
		otherRuntime, fixture.owners[0],
		sha256.Sum256([]byte(t.Name()+"/wrong-backend"))); err == nil {
		_ = execution.Close()
		t.Fatal("registered accumulator accepted another runtime backend")
	}

	attempt := sha256.Sum256([]byte(t.Name() + "/accumulator-attempt"))
	garbler, garblerPlan, err := formalGLMRegisteredPhase19PrepareAccumulatorV1(
		fixture.runtimes[0], fixture.owners[0], attempt)
	if err != nil {
		t.Fatal(err)
	}
	defer garbler.Close()
	evaluator, evaluatorPlan, err := formalGLMRegisteredPhase19PrepareAccumulatorV1(
		fixture.runtimes[1], fixture.owners[1], attempt)
	if err != nil {
		t.Fatal(err)
	}
	defer evaluator.Close()
	if err := fixture.owners[0].Destroy(); err == nil {
		t.Fatal("claimed registered accumulator store was destroyable")
	}
	garblerPlan = formalGLMRegisteredPhase19AccumulatorTestRoundTrip(
		t, garblerPlan)
	evaluatorPlan = formalGLMRegisteredPhase19AccumulatorTestRoundTrip(
		t, evaluatorPlan)
	if !reflect.DeepEqual(garblerPlan, evaluatorPlan) ||
		!formalGLMIsSHA256(garblerPlan.AccumulatorRoot) ||
		garblerPlan.BlockCount != plan.TotalBlocks ||
		!garblerPlan.ExecutionValidSealed ||
		garblerPlan.ExecutionValidityOpened || garblerPlan.OpeningsPerformed != 0 {
		t.Fatal("registered accumulator authorities derived different plans")
	}
	for name, execution := range map[string]any{
		"garbler": garbler, "evaluator": evaluator,
	} {
		encoded, marshalErr := json.Marshal(execution)
		if marshalErr != nil || string(encoded) != "{}" {
			t.Fatalf("%s accumulator trust type became serializable: %s / %v",
				name, encoded, marshalErr)
		}
	}

	leftConn, rightConn := net.Pipe()
	defer leftConn.Close()
	defer rightConn.Close()
	deadline := time.Now().Add(90 * time.Second)
	_ = leftConn.SetDeadline(deadline)
	_ = rightConn.SetDeadline(deadline)
	leftRW := &formalGLMRegisteredPhase19AccumulatorSignalRWV1{
		Conn: leftConn, started: make(chan struct{}),
	}
	rightRW := &formalGLMRegisteredPhase19AccumulatorSignalRWV1{
		Conn: rightConn, started: make(chan struct{}),
	}
	var leftSeal, rightSeal formalGLMRegisteredPhase19AccumulatorSealV1
	var leftErr, rightErr error
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		leftSeal, leftErr = formalGLMRegisteredPhase19RunAccumulatorPeerV1(
			leftRW, garbler)
	}()
	go func() {
		defer workers.Done()
		rightSeal, rightErr = formalGLMRegisteredPhase19RunAccumulatorPeerV1(
			rightRW, evaluator)
	}()
	for _, check := range []struct {
		started <-chan struct{}
		owner   *formalGLMRegisteredPhase19AccumulatorStoreV1
	}{
		{leftRW.started, fixture.owners[0]},
		{rightRW.started, fixture.owners[1]},
	} {
		select {
		case <-check.started:
		case <-time.After(30 * time.Second):
			t.Fatal("registered accumulator did not reach peer I/O")
		}
		if !check.owner.mu.TryLock() {
			t.Fatal("registered accumulator held owner mutex during peer I/O")
		}
		check.owner.mu.Unlock()
	}
	concurrentProbe := &formalGLMRegisteredPhase19AccumulatorNoIOV1{}
	if _, err := formalGLMRegisteredPhase19RunAccumulatorPeerV1(
		concurrentProbe, garbler); err == nil || concurrentProbe.touched {
		t.Fatal("concurrent registered accumulator run touched peer I/O")
	}
	workers.Wait()
	if leftErr != nil || rightErr != nil {
		t.Fatalf("registered accumulator garbler=%v evaluator=%v",
			leftErr, rightErr)
	}
	defer leftSeal.Close()
	defer rightSeal.Close()
	probe := &formalGLMRegisteredPhase19AccumulatorNoIOV1{}
	if _, err := formalGLMRegisteredPhase19RunAccumulatorPeerV1(
		probe, garbler); err == nil || probe.touched {
		t.Fatal("registered accumulator reused a session or touched peer I/O")
	}
	leftPublic := formalGLMRegisteredPhase19AccumulatorTestRoundTrip(
		t, leftSeal.Receipt)
	rightPublic := formalGLMRegisteredPhase19AccumulatorTestRoundTrip(
		t, rightSeal.Receipt)
	leftPair, err := formalGLMRegisteredPhase19PairAccumulatorReceiptsV1(
		garbler, leftPublic, rightPublic)
	if err != nil {
		t.Fatal(err)
	}
	defer leftPair.Close()
	rightPair, err := formalGLMRegisteredPhase19PairAccumulatorReceiptsV1(
		evaluator, leftPublic, rightPublic)
	if err != nil {
		t.Fatal(err)
	}
	defer rightPair.Close()
	formalGLMRegisteredPhase19AccumulatorTestRoundTrip(t, leftPair)
	if !reflect.DeepEqual(leftPair.Public(), rightPair.Public()) ||
		!leftPair.ExecutionValidSealed || leftPair.ExecutionValidityOpened ||
		leftPair.OpeningsPerformed != 0 || leftPair.ProductionReady ||
		!formalGLMIsSHA256(leftPair.ExecutionReceiptPairSHA256) {
		t.Fatal("registered accumulator receipt pairing diverged or opened validity")
	}
	if err := formalGLMPhase19VerifyExecutionSeal(
		garbler.context, garbler.accumulator, leftSeal.seal,
		garbler.backendKey); err != nil {
		t.Fatal(err)
	}
	if err := formalGLMPhase19VerifyExecutionSeal(
		evaluator.context, evaluator.accumulator, rightSeal.seal,
		evaluator.backendKey); err != nil {
		t.Fatal(err)
	}

	tamperedMAC := rightPublic
	tamperedMAC.Receipt.ReceiptMAC = strings.Repeat("0", 64)
	if _, err := formalGLMRegisteredPhase19PairAccumulatorReceiptsV1(
		garbler, leftPublic, tamperedMAC); err == nil {
		t.Fatal("registered accumulator paired a modified receipt MAC")
	}
	tamperedRoot := rightPublic
	tamperedRoot.AccumulatorRoot = strings.Repeat("b", 64)
	if _, err := formalGLMRegisteredPhase19PairAccumulatorReceiptsV1(
		garbler, leftPublic, tamperedRoot); err == nil {
		t.Fatal("registered accumulator paired another accumulator root")
	}
	if _, err := formalGLMRegisteredPhase19PairAccumulatorReceiptsV1(
		garbler, rightPublic, leftPublic); err == nil {
		t.Fatal("registered accumulator paired swapped peer roles")
	}
}
