package main

import (
	"encoding/hex"
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

type formalGLMRegisteredPhase19ScheduleTailNoIOV1 struct {
	touched bool
}

func (rw *formalGLMRegisteredPhase19ScheduleTailNoIOV1) Read(
	[]byte,
) (int, error) {
	rw.touched = true
	return 0, io.ErrUnexpectedEOF
}

func (rw *formalGLMRegisteredPhase19ScheduleTailNoIOV1) Write(
	[]byte,
) (int, error) {
	rw.touched = true
	return 0, io.ErrClosedPipe
}

func formalGLMRegisteredPhase19ScheduleTailTestAttemptV1(
	t *testing.T,
	fixture formalGLMRegisteredPhase19AccumulatorTestFixtureV1,
	roots [2]string,
) ([2]*formalGLMRegisteredPhase19AttemptStoreV1,
	formalGLMRegisteredPhase19ClaimProposalV1,
	formalGLMRegisteredPhase19ClaimAcceptV1) {
	t.Helper()
	source := fixture.base.loader.provenance.source
	peers := source.plan.DesignatedComputePeers
	var stores [2]*formalGLMRegisteredPhase19AttemptStoreV1
	for index, peer := range peers {
		stores[index] = formalGLMRegisteredPhase19AttemptTestOpen(
			t, roots[index], peer,
			formalGLMRegisteredPhase19AttemptTestCoreV1{
				source: source, record: fixture.base.loader.record,
			})
	}
	proposal, _, err := stores[0].Begin(nil)
	if err != nil {
		t.Fatal(err)
	}
	accept, _, err := stores[1].Accept(proposal)
	if err != nil {
		t.Fatal(err)
	}
	return stores, proposal, accept
}

func formalGLMRegisteredPhase19ScheduleTailTestAccumulatorV1(
	t *testing.T,
	fixture formalGLMRegisteredPhase19AccumulatorTestFixtureV1,
	binding formalGLMRegisteredPhase19AttemptBindingV1,
) ([2]*formalGLMRegisteredPhase19AccumulatorExecutionV1,
	[2]formalGLMRegisteredPhase19AccumulatorSealV1,
	[2]formalGLMRegisteredPhase19AccumulatorReceiptPairV1) {
	t.Helper()
	root, err := formalGLMPhase19ScheduleDecodeHex32(
		binding.ScheduleRootSHA256, "root")
	if err != nil {
		t.Fatal(err)
	}
	attempt := formalGLMPhase19RuntimeAttempt(
		root, "phase19-accumulator", 0, -1)
	clear(root[:])
	var executions [2]*formalGLMRegisteredPhase19AccumulatorExecutionV1
	for index := range executions {
		executions[index], _, err =
			formalGLMRegisteredPhase19PrepareAccumulatorV1(
				fixture.runtimes[index], fixture.owners[index], attempt)
		if err != nil {
			t.Fatal(err)
		}
	}
	left, right := net.Pipe()
	deadline := time.Now().Add(3 * time.Minute)
	_ = left.SetDeadline(deadline)
	_ = right.SetDeadline(deadline)
	defer left.Close()
	defer right.Close()
	var seals [2]formalGLMRegisteredPhase19AccumulatorSealV1
	var errs [2]error
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		seals[0], errs[0] = formalGLMRegisteredPhase19RunAccumulatorPeerV1(
			left, executions[0])
	}()
	go func() {
		defer workers.Done()
		seals[1], errs[1] = formalGLMRegisteredPhase19RunAccumulatorPeerV1(
			right, executions[1])
	}()
	workers.Wait()
	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("accumulator garbler=%v evaluator=%v", errs[0], errs[1])
	}
	var pairs [2]formalGLMRegisteredPhase19AccumulatorReceiptPairV1
	for index := range pairs {
		pairs[index], err = formalGLMRegisteredPhase19PairAccumulatorReceiptsV1(
			executions[index], seals[0].Receipt, seals[1].Receipt)
		if err != nil {
			t.Fatal(err)
		}
	}
	return executions, seals, pairs
}

func formalGLMRegisteredPhase19ScheduleTailTestRootV1(
	t *testing.T, label string,
) string {
	t.Helper()
	return filepath.Join(t.TempDir(), label)
}

func formalGLMRegisteredPhase19ScheduleTailTestPrivateJSONV1(
	t *testing.T, value any,
) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("schedule-tail trust object became serializable: %s / %v",
			encoded, err)
	}
}

func formalGLMRegisteredPhase19ScheduleTailTestFilesystemV1(
	t *testing.T, roots [2]string,
) {
	t.Helper()
	for _, root := range roots {
		if err := filepath.WalkDir(root,
			func(path string, entry os.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				info, err := entry.Info()
				if err != nil {
					return err
				}
				if entry.IsDir() {
					if info.Mode().Perm() != 0o700 ||
						!formalFinalizerHandoffPrivateOwnedDirectory(info) {
						t.Fatalf("unsafe schedule-tail directory %s: %o",
							path, info.Mode().Perm())
					}
					return nil
				}
				if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
					!exactGCPrivateOwnedRegular(info) {
					t.Fatalf("unsafe schedule-tail file %s: %o",
						path, info.Mode().Perm())
				}
				encoded, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				lower := strings.ToLower(string(encoded))
				if strings.Contains(lower, "post_execution_token") ||
					strings.Contains(lower, "canonical_dp_share") {
					t.Fatalf("raw schedule result reached durable storage: %s", path)
				}
				return nil
			}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFormalGLMRegisteredPhase19ScheduleTailEvidenceIsolationWithoutGC(
	t *testing.T,
) {
	peers := [2]string{"diagnostic-garbler", "diagnostic-evaluator"}
	context := formalGLMPhase19Context{
		ComputePeers: []string{peers[0], peers[1]},
	}
	accumulator := formalGLMPhase19AccumulatorPlan{
		AccumulatorRoot: strings.Repeat("a", 64),
	}
	semanticRoot := strings.Repeat("b", 64)
	attempt := [32]byte{1}
	expectedSessionID := [32]byte{3}
	backendKey := [32]byte{2}
	session := exactGCSession{SessionID: expectedSessionID}
	var seals [2]formalGLMRegisteredPhase19AccumulatorSealV1
	for index, peer := range peers {
		legacy, err := formalGLMPhase19BuildExecutionSeal(
			context, accumulator, session, peer, byte(index), backendKey)
		if err != nil {
			t.Fatal(err)
		}
		seals[index] = formalGLMRegisteredPhase19AccumulatorSealV1{
			Receipt: formalGLMRegisteredPhase19AccumulatorReceiptV1{
				Version:                 formalGLMRegisteredPhase19AccumulatorReceiptVersionV1,
				Purpose:                 formalGLMRegisteredPhase19AccumulatorReceiptPurposeV1,
				SemanticRootSHA256:      semanticRoot,
				Peer:                    peer,
				AccumulatorRoot:         accumulator.AccumulatorRoot,
				Receipt:                 legacy.Receipt,
				ExecutionValidSealed:    legacy.Receipt.ExecutionValidSealed,
				ExecutionValidityOpened: legacy.Receipt.ExecutionValidityOpened,
				OpeningsPerformed:       legacy.Receipt.OpeningsPerformed,
				ProductionReady:         legacy.Receipt.ProductionReady,
			},
			seal: legacy,
		}
	}
	legacyPair, err := formalGLMPhase19PairExecutionReceipts(
		context, accumulator, seals[0].seal.Receipt, seals[1].seal.Receipt,
		backendKey)
	if err != nil {
		t.Fatal(err)
	}
	privatePair := formalGLMRegisteredPhase19ScheduleTailPublicPairV1(
		legacyPair, semanticRoot)
	privatePair.pair = legacyPair
	pairs := [2]formalGLMRegisteredPhase19AccumulatorReceiptPairV1{
		privatePair, privatePair,
	}
	snapshots := [2]formalGLMRegisteredPhase19AccumulatorSnapshotV1{
		{semanticRootSHA256: semanticRoot, peer: peers[0], context: context,
			accumulator: accumulator, backendKey: backendKey},
		{semanticRootSHA256: semanticRoot, peer: peers[1], context: context,
			accumulator: accumulator, backendKey: backendKey},
	}
	validate := func(label string, index int,
		seal *formalGLMRegisteredPhase19AccumulatorSealV1,
		pair *formalGLMRegisteredPhase19AccumulatorReceiptPairV1,
		wantError string) {
		t.Helper()
		validationErr := formalGLMRegisteredPhase19ScheduleTailValidateEvidenceV1(
			snapshots[index], seal, pair, expectedSessionID)
		if wantError == "" && validationErr != nil {
			t.Fatalf("%s: %v", label, validationErr)
		}
		if wantError != "" && (validationErr == nil ||
			!strings.Contains(validationErr.Error(), wantError)) {
			t.Fatalf("%s: got %v, want error containing %q",
				label, validationErr, wantError)
		}
	}
	for index := range snapshots {
		validate("initial peer evidence", index, &seals[index], &pairs[index], "")
	}
	if err := formalGLMRegisteredPhase19ScheduleTailValidateEvidenceV1(
		snapshots[0], &seals[0], &pairs[0], attempt); err == nil ||
		!strings.Contains(err.Error(), "accumulator seal binding mismatch") {
		t.Fatalf("raw attempt was accepted as the final bounded session: %v", err)
	}
	pristineSeal := seals[0]
	pristinePair := pairs[0]
	publicOnly := pairs[0].Public()
	validate("public-only pair", 0, &seals[0], &publicOnly,
		"invalid private accumulator pair")
	validate("after public-only pair", 0, &seals[0], &pairs[0], "")
	tamperedSeal := seals[0]
	tamperedSeal.seal.share ^= 1
	validate("tampered hidden seal", 0, &tamperedSeal, &pairs[0],
		"invalid hidden accumulator seal")
	validate("after tampered hidden seal", 0, &seals[0], &pairs[0], "")
	if !reflect.DeepEqual(seals[0], pristineSeal) ||
		!reflect.DeepEqual(pairs[0], pristinePair) {
		t.Fatal("evidence negatives mutated their source fixture")
	}
	seals[0].Close()
	pairs[0].Close()
	validate("peer evidence after other peer consumption", 1,
		&seals[1], &pairs[1], "")
	orderedReceipts := []formalGLMPhase15StepReceipt{
		{Peer: peers[0]}, {Peer: peers[1]},
	}
	reversedReceipts := []formalGLMPhase15StepReceipt{
		orderedReceipts[1], orderedReceipts[0],
	}
	orderedDigest, err := formalGLMPhase15FinalReceiptPairDigest(orderedReceipts)
	if err != nil {
		t.Fatal(err)
	}
	reversedDigest, err := formalGLMPhase15FinalReceiptPairDigest(reversedReceipts)
	if err != nil || orderedDigest != reversedDigest {
		t.Fatalf("receipt-pair digest is not order independent: %v", err)
	}
	clear(orderedDigest[:])
	clear(reversedDigest[:])
	clear(attempt[:])
	clear(expectedSessionID[:])
	clear(backendKey[:])
}

func TestFormalGLMRegisteredPhase19ScheduleTailK2(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase19AccumulatorTestBuild(t)
	source := fixture.base.loader.provenance.source
	record := fixture.base.loader.record
	contract := source.contract
	pins := source.inputs.identities.public
	private := source.inputs.identities.private
	peers := source.plan.DesignatedComputePeers
	roots := [2]string{
		formalGLMRegisteredPhase19ScheduleTailTestRootV1(t, "garbler-rock"),
		formalGLMRegisteredPhase19ScheduleTailTestRootV1(t, "evaluator-rock"),
	}
	stores, proposal, accept :=
		formalGLMRegisteredPhase19ScheduleTailTestAttemptV1(t, fixture, roots)
	executions, seals, pairs :=
		formalGLMRegisteredPhase19ScheduleTailTestAccumulatorV1(
			t, fixture, proposal.Binding)
	for index := range executions {
		t.Cleanup(func() { _ = executions[index].Close() })
	}
	var providers [2]*formalGLMRegisteredPhase20JobKeyProviderV1
	for index, peer := range peers {
		var err error
		providers[index], err = newFormalGLMRegisteredPhase20JobKeyProviderV1(
			roots[index], contract, pins, record, peer)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = providers[index].Close() })
	}
	pristineSeal := seals[0]
	pristinePair := pairs[0]

	barePair := pairs[0].Public()
	if tail, err := newFormalGLMRegisteredPhase19ScheduleTailV1(
		roots[0], fixture.runtimes[0], record, contract, pins, stores[0],
		proposal, accept, providers[0], executions[0], &seals[0], &barePair,
		private[peers[0]]); err == nil {
		_ = tail.Close()
		t.Fatal("schedule tail accepted a public-only accumulator pair")
	}
	unsignedAccept := accept
	unsignedAccept.Signature = nil
	if tail, err := newFormalGLMRegisteredPhase19ScheduleTailV1(
		roots[0], fixture.runtimes[0], record, contract, pins, stores[0],
		proposal, unsignedAccept, providers[0], executions[0], &seals[0], &pairs[0],
		private[peers[0]]); err == nil {
		_ = tail.Close()
		t.Fatal("schedule tail accepted a claim without evaluator signature")
	}
	if tail, err := newFormalGLMRegisteredPhase19ScheduleTailV1(
		roots[1], fixture.runtimes[0], record, contract, pins, stores[0],
		proposal, accept, providers[0], executions[0], &seals[0], &pairs[0],
		private[peers[0]]); err == nil {
		_ = tail.Close()
		t.Fatal("schedule tail accepted a different Rock owner")
	}
	if tail, err := newFormalGLMRegisteredPhase19ScheduleTailV1(
		roots[0], fixture.runtimes[0], record, contract, pins, stores[0],
		proposal, accept, providers[1], executions[0], &seals[0], &pairs[0],
		private[peers[0]]); err == nil {
		_ = tail.Close()
		t.Fatal("schedule tail accepted another peer job-key provider")
	}
	if tail, err := newFormalGLMRegisteredPhase19ScheduleTailV1(
		roots[0], fixture.runtimes[0], record, contract, pins, stores[0],
		proposal, accept, providers[0], executions[0], &seals[0], &pairs[0],
		private[peers[1]]); err == nil {
		_ = tail.Close()
		t.Fatal("schedule tail accepted the wrong pinned signer")
	}
	tamperedSeal := seals[0]
	tamperedSeal.seal.share ^= 1
	if tail, err := newFormalGLMRegisteredPhase19ScheduleTailV1(
		roots[0], fixture.runtimes[0], record, contract, pins, stores[0],
		proposal, accept, providers[0], executions[0], &tamperedSeal, &pairs[0],
		private[peers[0]]); err == nil {
		_ = tail.Close()
		t.Fatal("schedule tail accepted a modified hidden execution share")
	}
	if !reflect.DeepEqual(seals[0], pristineSeal) ||
		!reflect.DeepEqual(pairs[0], pristinePair) {
		t.Fatal("schedule tail negative preparation mutated accumulator evidence")
	}
	executions[0].mu.Lock()
	negativeStateOK := executions[0].claimed && !executions[0].running &&
		executions[0].succeeded && !executions[0].closeRequested &&
		!executions[0].closed
	executions[0].mu.Unlock()
	if !negativeStateOK {
		t.Fatal("schedule tail negative preparation mutated accumulator ownership")
	}

	var tails [2]*formalGLMRegisteredPhase19ScheduleTailV1
	for index := range tails {
		var err error
		tails[index], err = newFormalGLMRegisteredPhase19ScheduleTailV1(
			roots[index], fixture.runtimes[index], record, contract, pins,
			stores[index], proposal, accept, providers[index], executions[index],
			&seals[index], &pairs[index], private[peers[index]])
		if err != nil {
			t.Fatalf("prepare schedule tail peer %d: %v", index, err)
		}
		t.Cleanup(func() { _ = tails[index].Close() })
		formalGLMRegisteredPhase19ScheduleTailTestPrivateJSONV1(t, tails[index])
		if seals[index].seal.verified || pairs[index].pair.verified {
			t.Fatal("schedule tail did not consume private accumulator state")
		}
		status, err := stores[index].LoadStatus(nil)
		if err != nil || status.proposal == nil || status.accept == nil ||
			!reflect.DeepEqual(*status.proposal, proposal) ||
			!reflect.DeepEqual(*status.accept, accept) {
			t.Fatalf("accepted claim was not durable on peer %d: %v", index, err)
		}
	}
	if result, err := formalGLMRegisteredPhase19RunScheduleTailPeerV1(
		nil, tails[0]); err == nil || result != nil {
		t.Fatal("schedule tail accepted a nil peer channel")
	}

	left, right := net.Pipe()
	deadline := time.Now().Add(5 * time.Minute)
	_ = left.SetDeadline(deadline)
	_ = right.SetDeadline(deadline)
	defer left.Close()
	defer right.Close()
	var results [2]*formalGLMRegisteredPhase19ScheduleTailResultV1
	var runErrs [2]error
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		results[0], runErrs[0] = formalGLMRegisteredPhase19RunScheduleTailPeerV1(
			left, tails[0])
	}()
	go func() {
		defer workers.Done()
		results[1], runErrs[1] = formalGLMRegisteredPhase19RunScheduleTailPeerV1(
			right, tails[1])
	}()
	workers.Wait()
	if runErrs[0] != nil || runErrs[1] != nil {
		t.Fatalf("schedule tail garbler=%v evaluator=%v",
			runErrs[0], runErrs[1])
	}
	for index := range results {
		if results[index] == nil {
			t.Fatal("schedule tail returned no RAM result")
		}
		t.Cleanup(func() { _ = results[index].Close() })
		formalGLMRegisteredPhase19ScheduleTailTestPrivateJSONV1(t, results[index])
	}
	leftReceiptDigest, err := formalGLMPhase15FinalReceiptPairDigest(
		results[0].raw.FinalReceipts)
	if err != nil {
		t.Fatal(err)
	}
	rightReceiptDigest, err := formalGLMPhase15FinalReceiptPairDigest(
		results[1].raw.FinalReceipts)
	if err != nil {
		t.Fatal(err)
	}
	if leftReceiptDigest != rightReceiptDigest ||
		!reflect.DeepEqual(results[0].raw.DPBridge, results[1].raw.DPBridge) ||
		results[0].raw.PostExecutionToken.TokenSHA256 !=
			results[1].raw.PostExecutionToken.TokenSHA256 {
		t.Fatal("schedule tail peers derived different bound evidence")
	}
	clear(leftReceiptDigest[:])
	clear(rightReceiptDigest[:])
	root, err := formalGLMPhase19ScheduleDecodeHex32(
		proposal.Binding.ScheduleRootSHA256, "root")
	if err != nil {
		t.Fatal(err)
	}
	finalAttempt := formalGLMPhase19RuntimeAttempt(
		root, "phase15-checkpoint", source.plan.Iterations-1, -1)
	clear(root[:])
	finalStep := source.plan.Iterations*(source.plan.TotalBlocks+1) - 1
	for _, receipt := range results[0].raw.FinalReceipts {
		if receipt.StepIndex != finalStep ||
			receipt.AttemptID != hex.EncodeToString(finalAttempt[:]) {
			t.Fatalf("wrong final schedule receipt: %+v", receipt)
		}
	}
	clear(finalAttempt[:])

	spec := exactGCCircuitSpec{
		Operation: exactGCFormalGLMDPBridge, RingBits: 128, FracBits: 0,
		VectorLen: source.plan.ExecutionKernel.CoefficientCount,
	}
	shares := [2][]*big.Int{}
	for index := range shares {
		shares[index], err = exactGCDecodeWorkerCanonicalShares(
			results[index].raw.DPShare, spec)
		if err != nil {
			t.Fatal(err)
		}
		defer exactGCZeroBigInts(shares[index])
	}
	modulus := new(big.Int).Lsh(big.NewInt(1), 128)
	for coordinate, encodedUpper := range results[0].raw.DPBridge.ShiftedUpperBounds {
		got := new(big.Int).Add(shares[0][coordinate], shares[1][coordinate])
		got.Mod(got, modulus)
		want, ok := new(big.Int).SetString(encodedUpper, 10)
		if !ok || got.Cmp(want) != 0 {
			t.Fatalf("coordinate %d reconstructed %s, want %s",
				coordinate, got, encodedUpper)
		}
	}

	var evidence [2]formalGLMRegisteredPhase20PreparedEvidenceV1
	for index := range evidence {
		evidence[index], err = results[index].BuildPreparedEvidenceV1(
			fixture.runtimes[index], record, contract, pins)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(evidence[index])
		if err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(string(encoded))
		for _, forbidden := range []string{
			"capsule", "run_id", "pre_execution", "path", "secret", "backend",
		} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("prepared evidence exposed %q: %s", forbidden, encoded)
			}
		}
	}
	probe := &formalGLMRegisteredPhase19ScheduleTailNoIOV1{}
	if result, err := formalGLMRegisteredPhase19RunScheduleTailPeerV1(
		probe, tails[0]); err == nil || result != nil || probe.touched {
		t.Fatal("completed schedule tail replay touched peer I/O")
	}
	formalGLMRegisteredPhase19ScheduleTailTestFilesystemV1(t, roots)

	failureFixture := formalGLMRegisteredPhase19AccumulatorTestBuild(t)
	failureRoots := [2]string{
		formalGLMRegisteredPhase19ScheduleTailTestRootV1(t, "failure-garbler-rock"),
		formalGLMRegisteredPhase19ScheduleTailTestRootV1(t, "failure-evaluator-rock"),
	}
	failureStores, failureProposal, failureAccept :=
		formalGLMRegisteredPhase19ScheduleTailTestAttemptV1(
			t, failureFixture, failureRoots)
	failureExecutions, failureSeals, failurePairs :=
		formalGLMRegisteredPhase19ScheduleTailTestAccumulatorV1(
			t, failureFixture, failureProposal.Binding)
	var failureProviders [2]*formalGLMRegisteredPhase20JobKeyProviderV1
	var failureTails [2]*formalGLMRegisteredPhase19ScheduleTailV1
	var scratchPaths [2]string
	for index, peer := range peers {
		failureProviders[index], err =
			newFormalGLMRegisteredPhase20JobKeyProviderV1(
				failureRoots[index], contract, pins, record, peer)
		if err != nil {
			t.Fatal(err)
		}
		defer failureProviders[index].Close()
		failureTails[index], err = newFormalGLMRegisteredPhase19ScheduleTailV1(
			failureRoots[index], failureFixture.runtimes[index], record,
			contract, pins, failureStores[index], failureProposal, failureAccept,
			failureProviders[index], failureExecutions[index], &failureSeals[index],
			&failurePairs[index], private[peer])
		if err != nil {
			t.Fatal(err)
		}
		scratchPaths[index] = failureTails[index].store.path
	}
	for index := range failureTails {
		broken := &formalGLMRegisteredPhase19ScheduleTailNoIOV1{}
		if result, err := formalGLMRegisteredPhase19RunScheduleTailPeerV1(
			broken, failureTails[index]); err == nil || result != nil || !broken.touched {
			t.Fatal("broken peer channel did not fail the schedule tail")
		}
		replayProbe := &formalGLMRegisteredPhase19ScheduleTailNoIOV1{}
		if result, err := formalGLMRegisteredPhase19RunScheduleTailPeerV1(
			replayProbe, failureTails[index]); err == nil || result != nil ||
			replayProbe.touched {
			t.Fatal("failed schedule tail reused a protocol session")
		}
		if err := failureTails[index].Close(); err != nil {
			t.Fatal(err)
		}
		failureFixture.owners[index].mu.Lock()
		closed := failureFixture.owners[index].state ==
			formalGLMRegisteredPhase19AccumulatorStoreClosedV1 &&
			failureFixture.owners[index].store == nil &&
			failureFixture.owners[index].holder == nil
		failureFixture.owners[index].mu.Unlock()
		if !closed || !failureExecutions[index].closed {
			t.Fatal("failed schedule tail Close left accumulator scratch claimed")
		}
		if _, err := os.Lstat(scratchPaths[index]); !os.IsNotExist(err) {
			t.Fatalf("failed schedule tail retained scratch: %v", err)
		}
	}
}
