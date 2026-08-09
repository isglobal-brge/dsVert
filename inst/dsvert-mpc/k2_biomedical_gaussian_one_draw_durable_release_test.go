package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func jointDPBiomedicalGaussianOneDrawTestEnvelopes(
	t testing.TB, fixture jointDPBiomedicalGaussianWorkerTestFixture,
	geometry [][2]int,
) []jointDPBiomedicalGaussianSignedWorkerEnvelope {
	t.Helper()
	result := make([]jointDPBiomedicalGaussianSignedWorkerEnvelope, 0,
		len(geometry))
	for _, chunkGeometry := range geometry {
		chunk, err := compileJointDPBiomedicalGaussianChunk(
			fixture.base.admission, chunkGeometry[0], chunkGeometry[1])
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := jointDPBiomedicalGaussianBuildWorkerEnvelope(
			fixture.base.admission, chunk, fixture.request)
		if err != nil {
			t.Fatal(err)
		}
		jointDPBiomedicalGaussianTestSignWorkerEnvelope(t, &envelope,
			fixture.base.manifest.Contract.CustodianPeers,
			fixture.base.private)
		result = append(result, envelope)
	}
	return result
}

func jointDPBiomedicalGaussianOneDrawTestHandoffs(
	t testing.TB, fixture jointDPBiomedicalGaussianWorkerTestFixture,
	geometry [][2]int, values []*big.Int, valid bool,
) []jointDPBiomedicalGaussianOneDrawChunkHandoff {
	t.Helper()
	envelopes := jointDPBiomedicalGaussianOneDrawTestEnvelopes(
		t, fixture, geometry)
	ringMask := exactGCMask(128)
	result := make([]jointDPBiomedicalGaussianOneDrawChunkHandoff, 0,
		len(envelopes))
	for index, envelope := range envelopes {
		start, count := envelope.Preimage.ChunkStart,
			envelope.Preimage.CoordinateCount
		garbler := make([]*big.Int, 0, count+1)
		evaluator := make([]*big.Int, 0, count+1)
		for local := 0; local < count; local++ {
			absolute := start + local
			mask := new(big.Int).SetUint64(uint64(1000 + absolute*17))
			right := new(big.Int).Sub(values[absolute], mask)
			right.And(right, ringMask)
			garbler = append(garbler, mask)
			evaluator = append(evaluator, right)
		}
		garblerValidity := byte((start + count) & 1)
		evaluatorValidity := garblerValidity ^ 1
		if !valid && index == len(envelopes)-1 {
			evaluatorValidity = garblerValidity
		}
		garbler = append(garbler, new(big.Int).SetUint64(
			uint64(garblerValidity)))
		evaluator = append(evaluator, new(big.Int).SetUint64(
			uint64(evaluatorValidity)))
		garblerReceipt, err :=
			jointDPBiomedicalGaussianBuildOneDrawChunkReceipt(
				envelope, fixture.trust, "garbler", garbler,
				fixture.base.private[envelope.Preimage.GarblerPeerName])
		if err != nil {
			t.Fatal(err)
		}
		evaluatorReceipt, err :=
			jointDPBiomedicalGaussianBuildOneDrawChunkReceipt(
				envelope, fixture.trust, "evaluator", evaluator,
				fixture.base.private[envelope.Preimage.EvaluatorPeerName])
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, jointDPBiomedicalGaussianOneDrawChunkHandoff{
			Envelope: envelope, Garbler: garblerReceipt,
			Evaluator:     evaluatorReceipt,
			GarblerShares: garbler, EvaluatorShares: evaluator,
		})
	}
	return result
}

func jointDPBiomedicalGaussianOneDrawTestStores(
	t testing.TB, fixture jointDPBiomedicalGaussianWorkerTestFixture,
	dir string, key [32]byte,
) (*jointDPBiomedicalGaussianOneDrawDurableReleaseStore,
	*jointDPBiomedicalGaussianOneDrawDurableReleaseStore) {
	t.Helper()
	leftName := fixture.envelope.Preimage.GarblerPeerName
	rightName := fixture.envelope.Preimage.EvaluatorPeerName
	left, err := newJointDPBiomedicalGaussianOneDrawDurableReleaseStore(
		filepath.Join(dir, leftName), leftName, key,
		fixture.base.private[leftName])
	if err != nil {
		t.Fatal(err)
	}
	right, err := newJointDPBiomedicalGaussianOneDrawDurableReleaseStore(
		filepath.Join(dir, rightName), rightName, key,
		fixture.base.private[rightName])
	if err != nil {
		t.Fatal(err)
	}
	return left, right
}

func jointDPBiomedicalGaussianOneDrawTestValues(count int) []*big.Int {
	result := make([]*big.Int, count)
	for index := range result {
		result[index] = big.NewInt(int64(index + 1))
	}
	return result
}

func TestJointDPBiomedicalGaussianOneDrawDurableCommonK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(string(rune('0'+custodians)), func(t *testing.T) {
			fixture := jointDPBiomedicalGaussianTestWorkerFixture(
				t, custodians, 3, t.Name())
			handoffs := jointDPBiomedicalGaussianOneDrawTestHandoffs(
				t, fixture, [][2]int{{0, 1}, {1, 2}},
				jointDPBiomedicalGaussianOneDrawTestValues(3), true)
			key := sha256.Sum256([]byte(t.Name() + "/backend-key"))
			leftStore, rightStore :=
				jointDPBiomedicalGaussianOneDrawTestStores(
					t, fixture, t.TempDir(), key)
			left, err := leftStore.FinalizeVector(handoffs, fixture.trust, nil)
			if err != nil {
				t.Fatal(err)
			}
			right, err := rightStore.FinalizeVector(handoffs, fixture.trust, nil)
			if err != nil {
				t.Fatal(err)
			}
			envelopes := []jointDPBiomedicalGaussianSignedWorkerEnvelope{
				handoffs[0].Envelope, handoffs[1].Envelope}
			common, err := jointDPBiomedicalGaussianPairOneDrawLocalReleases(
				envelopes, fixture.trust, left.Receipt, right.Receipt)
			if err != nil {
				t.Fatal(err)
			}
			if err := jointDPBiomedicalGaussianValidateOneDrawCommonRelease(
				envelopes, fixture.trust, common); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(common.ClampedScaledValues,
				[]string{"1", "2", "3"}) || !common.TargetVarianceOptimal ||
				common.NominalVarianceMultiplier != 1 ||
				common.NominalStandardDeviationFactor !=
					"1_relative_to_one_full_draw" || common.ProductionReady ||
				common.OperationLimit || common.RequestLimit ||
				common.HistoryCanDenyOperation || !common.SingleCommonDPVector ||
				!common.LedgerAppendBeforeValidityOrRelease ||
				common.PrivacyClaimScope !=
					jointDPBiomedicalGaussianOneDrawPrivacyScope ||
				!reflectStringSlicesEqual(common.Blockers,
					jointDPBiomedicalGaussianOneDrawReleaseBlockers) {
				t.Fatalf("invalid K=%d one-draw common release", custodians)
			}
			plan := handoffs[0].Envelope.WorkerPolicy.Plan
			if common.CoreDeltaNumerator != plan.CoreDeltaNumerator ||
				common.CoreDeltaDenominator != plan.CoreDeltaDenominator ||
				common.ImplementationDeltaNumerator !=
					plan.ImplementationDeltaNumerator ||
				common.ImplementationDeltaDenominator !=
					plan.ImplementationDeltaDenominator ||
				common.VectorTotalTVUpperNumerator !=
					plan.VectorTotalTVUpperNumerator ||
				common.VectorTotalTVUpperDenominator !=
					plan.VectorTotalTVUpperDenominator {
				t.Fatal("common release lost the exact finite-transfer certificate")
			}
			encoded, err := json.Marshal(handoffs[0])
			if err != nil {
				t.Fatal(err)
			}
			if bytesContainsAny(encoded, []string{
				"garbler_shares", "evaluator_shares", "worker_policy",
				"release_binding_canonical_json"}) {
				t.Fatal("handoff JSON exposed private shares or local worker state")
			}
		})
	}
}

func TestJointDPBiomedicalGaussianOneDrawRealGCToDurableCommon(t *testing.T) {
	if testing.Short() {
		t.Skip("real KOS/GC protocol")
	}
	fixture := jointDPBiomedicalGaussianTestWorkerFixture(t, 2, 1, t.Name())
	evaluatorSource, err := exactGCEncodeWorkerCanonicalShares(
		[]*big.Int{big.NewInt(6)}, fixture.session.Spec)
	if err != nil {
		t.Fatal(err)
	}
	evaluatorLocal, err := jointDPBiomedicalGaussianBuildLocalSourceBinding(
		fixture.envelope.Preimage,
		fixture.base.candidate.preimage.LogicalSnapshotSHA256,
		fixture.base.candidate.preimage.SourceContractSHA256,
		fixture.envelope.Preimage.EvaluatorPeerName,
		"evaluator", evaluatorSource)
	if err != nil {
		t.Fatal(err)
	}
	garblerConn, evaluatorConn := net.Pipe()
	defer garblerConn.Close()
	defer evaluatorConn.Close()
	type outcome struct {
		shares []*big.Int
		err    error
	}
	garblerDone, evaluatorDone := make(chan outcome, 1), make(chan outcome, 1)
	go func() {
		shares, runErr := jointDPBiomedicalGaussianRunProductiveGarbler(
			garblerConn, fixture.envelope, fixture.trust, fixture.local,
			fixture.session, fixture.source, fixture.privateB64)
		garblerDone <- outcome{shares, runErr}
	}()
	go func() {
		shares, runErr := jointDPBiomedicalGaussianRunProductiveEvaluator(
			evaluatorConn, fixture.envelope, fixture.trust, evaluatorLocal,
			fixture.session, evaluatorSource,
			base64.StdEncoding.EncodeToString(fixture.base.evaluatorSeed[:]))
		evaluatorDone <- outcome{shares, runErr}
	}()
	garbler, evaluator := <-garblerDone, <-evaluatorDone
	if garbler.err != nil || evaluator.err != nil {
		t.Fatalf("productive GC failed: garbler=%v evaluator=%v",
			garbler.err, evaluator.err)
	}
	defer exactGCZeroBigInts(garbler.shares)
	defer exactGCZeroBigInts(evaluator.shares)
	garblerReceipt, err := jointDPBiomedicalGaussianBuildOneDrawChunkReceipt(
		fixture.envelope, fixture.trust, "garbler", garbler.shares,
		fixture.base.private[fixture.envelope.Preimage.GarblerPeerName])
	if err != nil {
		t.Fatal(err)
	}
	evaluatorReceipt, err := jointDPBiomedicalGaussianBuildOneDrawChunkReceipt(
		fixture.envelope, fixture.trust, "evaluator", evaluator.shares,
		fixture.base.private[fixture.envelope.Preimage.EvaluatorPeerName])
	if err != nil {
		t.Fatal(err)
	}
	handoff := jointDPBiomedicalGaussianOneDrawChunkHandoff{
		Envelope: fixture.envelope, Garbler: garblerReceipt,
		Evaluator:     evaluatorReceipt,
		GarblerShares: garbler.shares, EvaluatorShares: evaluator.shares,
	}
	key := sha256.Sum256([]byte(t.Name() + "/backend-key"))
	leftStore, rightStore := jointDPBiomedicalGaussianOneDrawTestStores(
		t, fixture, t.TempDir(), key)
	left, err := leftStore.FinalizeVector(
		[]jointDPBiomedicalGaussianOneDrawChunkHandoff{handoff},
		fixture.trust, nil)
	if err != nil {
		t.Fatal(err)
	}
	right, err := rightStore.FinalizeVector(
		[]jointDPBiomedicalGaussianOneDrawChunkHandoff{handoff},
		fixture.trust, nil)
	if err != nil {
		t.Fatal(err)
	}
	common, err := jointDPBiomedicalGaussianPairOneDrawLocalReleases(
		[]jointDPBiomedicalGaussianSignedWorkerEnvelope{fixture.envelope},
		fixture.trust, left.Receipt, right.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	want := exactGCReferenceReconstruct(
		garbler.shares[0], evaluator.shares[0], 128).String()
	if !reflect.DeepEqual(common.ClampedScaledValues, []string{want}) {
		t.Fatalf("durable common=%v raw GC=%s",
			common.ClampedScaledValues, want)
	}
}

func bytesContainsAny(value []byte, needles []string) bool {
	for _, needle := range needles {
		if bytes.Contains(value, []byte(needle)) {
			return true
		}
	}
	return false
}

func TestJointDPBiomedicalGaussianOneDrawRestartRechunkAndReorderAreByteIdentical(t *testing.T) {
	fixture := jointDPBiomedicalGaussianTestWorkerFixture(t, 5, 3, t.Name())
	values := jointDPBiomedicalGaussianOneDrawTestValues(3)
	full := jointDPBiomedicalGaussianOneDrawTestHandoffs(
		t, fixture, [][2]int{{0, 3}}, values, true)
	split := jointDPBiomedicalGaussianOneDrawTestHandoffs(
		t, fixture, [][2]int{{0, 1}, {1, 2}}, values, true)
	key := sha256.Sum256([]byte(t.Name() + "/backend-key"))
	dir := t.TempDir()
	leftStore, rightStore := jointDPBiomedicalGaussianOneDrawTestStores(
		t, fixture, dir, key)
	left, err := leftStore.FinalizeVector(full, fixture.trust, nil)
	if err != nil {
		t.Fatal(err)
	}
	right, err := rightStore.FinalizeVector(full, fixture.trust, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstCommon, err := jointDPBiomedicalGaussianPairOneDrawLocalReleases(
		[]jointDPBiomedicalGaussianSignedWorkerEnvelope{full[0].Envelope},
		fixture.trust, left.Receipt, right.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(firstCommon)

	// Restart with fresh store instances and deliver a different chunking in
	// reverse transport order. Canonical coverage and absolute-coordinate
	// masks make the durable record and common opening invariant.
	leftStore, rightStore = jointDPBiomedicalGaussianOneDrawTestStores(
		t, fixture, dir, key)
	split[0], split[1] = split[1], split[0]
	leftReplay, err := leftStore.FinalizeVector(split, fixture.trust, nil)
	if err != nil {
		t.Fatal(err)
	}
	rightReplay, err := rightStore.FinalizeVector(split, fixture.trust, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !leftReplay.Replayed || !rightReplay.Replayed {
		t.Fatal("restart/rechunk did not use the durable release")
	}
	secondCommon, err := jointDPBiomedicalGaussianPairOneDrawLocalReleases(
		[]jointDPBiomedicalGaussianSignedWorkerEnvelope{
			split[0].Envelope, split[1].Envelope}, fixture.trust,
		leftReplay.Receipt, rightReplay.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, _ := json.Marshal(secondCommon)
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatal("restart/rechunk changed the signed common DP release")
	}
}

func TestJointDPBiomedicalGaussianOneDrawCrashAfterLedgerRecoversWithoutReroll(t *testing.T) {
	fixture := jointDPBiomedicalGaussianTestWorkerFixture(t, 3, 2, t.Name())
	handoffs := jointDPBiomedicalGaussianOneDrawTestHandoffs(
		t, fixture, [][2]int{{0, 1}, {1, 1}},
		jointDPBiomedicalGaussianOneDrawTestValues(2), true)
	key := sha256.Sum256([]byte(t.Name() + "/backend-key"))
	dir := t.TempDir()
	left, _ := jointDPBiomedicalGaussianOneDrawTestStores(t, fixture, dir, key)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("crash hook did not fire")
			}
		}()
		_, _ = left.FinalizeVector(handoffs, fixture.trust, func(phase string) {
			if phase == "after_ledger_append_before_validity_or_release" {
				panic("simulated crash")
			}
		})
	}()
	left, _ = jointDPBiomedicalGaussianOneDrawTestStores(t, fixture, dir, key)
	recovered, err := left.FinalizeVector(handoffs, fixture.trust, nil)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Replayed ||
		!reflect.DeepEqual(recovered.Receipt.ClampedScaledValues,
			[]string{"1", "2"}) {
		t.Fatal("ledger-committed crash did not recover the same release")
	}
	replay, err := left.FinalizeVector(handoffs, fixture.trust, nil)
	if err != nil || !replay.Replayed ||
		!reflect.DeepEqual(replay.Receipt, recovered.Receipt) {
		t.Fatal("recovered release was not sticky")
	}
}

func TestJointDPBiomedicalGaussianOneDrawLedgerCASCommitsValidityShares(t *testing.T) {
	fixture := jointDPBiomedicalGaussianTestWorkerFixture(t, 3, 1, t.Name())
	values := jointDPBiomedicalGaussianOneDrawTestValues(1)
	invalid := jointDPBiomedicalGaussianOneDrawTestHandoffs(
		t, fixture, [][2]int{{0, 1}}, values, false)
	valid := jointDPBiomedicalGaussianOneDrawTestHandoffs(
		t, fixture, [][2]int{{0, 1}}, values, true)
	key := sha256.Sum256([]byte(t.Name() + "/backend-key"))
	dir := t.TempDir()
	left, _ := jointDPBiomedicalGaussianOneDrawTestStores(t, fixture, dir, key)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("crash hook did not fire")
			}
		}()
		_, _ = left.FinalizeVector(invalid, fixture.trust, func(phase string) {
			if phase == "after_ledger_append_before_validity_or_release" {
				panic("simulated crash")
			}
		})
	}()
	left, _ = jointDPBiomedicalGaussianOneDrawTestStores(t, fixture, dir, key)
	if _, err := left.FinalizeVector(valid, fixture.trust, nil); err == nil ||
		!strings.Contains(err.Error(), "conflicting durable release replay") {
		t.Fatalf("post-ledger validity substitution escaped CAS: %v", err)
	}
}

func TestJointDPBiomedicalGaussianOneDrawInvalidChunkNeverPartiallyReleases(t *testing.T) {
	fixture := jointDPBiomedicalGaussianTestWorkerFixture(t, 3, 3, t.Name())
	handoffs := jointDPBiomedicalGaussianOneDrawTestHandoffs(
		t, fixture, [][2]int{{0, 1}, {1, 2}},
		jointDPBiomedicalGaussianOneDrawTestValues(3), false)
	key := sha256.Sum256([]byte(t.Name() + "/backend-key"))
	store, _ := jointDPBiomedicalGaussianOneDrawTestStores(
		t, fixture, t.TempDir(), key)
	phases := []string{}
	_, err := store.FinalizeVector(handoffs, fixture.trust, func(phase string) {
		phases = append(phases, phase)
	})
	var invalid *jointDPBiomedicalGaussianOneDrawInvalidSource
	if !errors.As(err, &invalid) || !reflect.DeepEqual(phases, []string{
		"after_ledger_append_before_validity_or_release",
		"after_invalid_source_durable_no_release"}) {
		t.Fatalf("invalid source was not append-first and fail-closed: %v %v",
			err, phases)
	}
	_, replayErr := store.FinalizeVector(handoffs, fixture.trust, nil)
	if !errors.As(replayErr, &invalid) {
		t.Fatalf("invalid release was not durably terminal: %v", replayErr)
	}
	path, pathErr := store.recordPath(
		fixture.envelope.Preimage.ReleaseInstanceID, false)
	if pathErr != nil {
		t.Fatal(pathErr)
	}
	encoded, readErr := jointDPBiomedicalGaussianFullReadDurableRecord(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	record, decodeErr := jointDPBiomedicalGaussianOneDrawDecodeRecord(key, encoded)
	if decodeErr != nil || record.State != "invalid_source" ||
		record.ReleaseReceiptJSON != "" || !record.ValidityChecked ||
		record.AllChunksValid {
		t.Fatal("invalid source persisted a public vector")
	}
}

func TestJointDPBiomedicalGaussianOneDrawRejectsTamperCoverageAndOutOfBounds(t *testing.T) {
	fixture := jointDPBiomedicalGaussianTestWorkerFixture(t, 3, 3, t.Name())
	values := jointDPBiomedicalGaussianOneDrawTestValues(3)
	handoffs := jointDPBiomedicalGaussianOneDrawTestHandoffs(
		t, fixture, [][2]int{{0, 1}, {1, 2}}, values, true)
	tampered := append([]jointDPBiomedicalGaussianOneDrawChunkHandoff(nil),
		handoffs...)
	tampered[0].Garbler.Signature = append([]byte(nil),
		tampered[0].Garbler.Signature...)
	tampered[0].Garbler.Signature[0] ^= 1
	if _, err := jointDPBiomedicalGaussianOneDrawNormalizeHandoffs(
		tampered, fixture.trust); err == nil {
		t.Fatal("tampered private chunk receipt was accepted")
	}
	if _, err := jointDPBiomedicalGaussianOneDrawNormalizeHandoffs(
		handoffs[:1], fixture.trust); err == nil {
		t.Fatal("missing chunk was accepted")
	}
	duplicate := []jointDPBiomedicalGaussianOneDrawChunkHandoff{
		handoffs[0], handoffs[0], handoffs[1]}
	if _, err := jointDPBiomedicalGaussianOneDrawNormalizeHandoffs(
		duplicate, fixture.trust); err == nil {
		t.Fatal("duplicate chunk was accepted")
	}

	upper, ok := new(big.Int).SetString(
		fixture.envelope.Preimage.CommonLatticeUpperBounds[0], 10)
	if !ok {
		t.Fatal("invalid fixture upper bound")
	}
	badValues := jointDPBiomedicalGaussianOneDrawTestValues(3)
	badValues[0] = new(big.Int).Add(upper, big.NewInt(1))
	boundHandoffs := jointDPBiomedicalGaussianOneDrawTestHandoffs(
		t, fixture, [][2]int{{0, 3}}, badValues, true)
	key := sha256.Sum256([]byte(t.Name() + "/bound-key"))
	store, _ := jointDPBiomedicalGaussianOneDrawTestStores(
		t, fixture, t.TempDir(), key)
	if _, err := store.FinalizeVector(boundHandoffs, fixture.trust, nil); err == nil || !strings.Contains(err.Error(), "exceeds its certified bound") {
		t.Fatalf("correctly signed out-of-bound output was released: %v", err)
	}
}

func TestJointDPBiomedicalGaussianOneDrawCommonRejectsWrongSignatureAndCertificate(t *testing.T) {
	fixture := jointDPBiomedicalGaussianTestWorkerFixture(t, 3, 2, t.Name())
	handoffs := jointDPBiomedicalGaussianOneDrawTestHandoffs(
		t, fixture, [][2]int{{0, 2}},
		jointDPBiomedicalGaussianOneDrawTestValues(2), true)
	key := sha256.Sum256([]byte(t.Name() + "/backend-key"))
	leftStore, rightStore := jointDPBiomedicalGaussianOneDrawTestStores(
		t, fixture, t.TempDir(), key)
	left, err := leftStore.FinalizeVector(handoffs, fixture.trust, nil)
	if err != nil {
		t.Fatal(err)
	}
	right, err := rightStore.FinalizeVector(handoffs, fixture.trust, nil)
	if err != nil {
		t.Fatal(err)
	}
	envelopes := []jointDPBiomedicalGaussianSignedWorkerEnvelope{
		handoffs[0].Envelope}
	common, err := jointDPBiomedicalGaussianPairOneDrawLocalReleases(
		envelopes, fixture.trust, left.Receipt, right.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	localAsCommon := common
	localAsCommon.Signatures = []jointDPBiomedicalGaussianSignature{
		{Signer: common.DesignatedComputePeers[0],
			Signature: append([]byte(nil), left.Receipt.Signature...)},
		{Signer: common.DesignatedComputePeers[1],
			Signature: append([]byte(nil), right.Receipt.Signature...)},
	}
	if err := jointDPBiomedicalGaussianValidateOneDrawCommonRelease(
		envelopes, fixture.trust, localAsCommon); err == nil {
		t.Fatal("local-domain signatures were accepted as common signatures")
	}
	tampered := common
	tampered.ImplementationDeltaNumerator = "0"
	if err := jointDPBiomedicalGaussianValidateOneDrawCommonRelease(
		envelopes, fixture.trust, tampered); err == nil {
		t.Fatal("tampered implementation delta was accepted")
	}
	tampered = common
	tampered.Cost.LogarithmicCircuitSizeClaim = true
	if err := jointDPBiomedicalGaussianValidateOneDrawCommonRelease(
		envelopes, fixture.trust, tampered); err == nil {
		t.Fatal("false logarithmic cost claim was accepted")
	}
}

func TestJointDPBiomedicalGaussianOneDrawConcurrentCASIsExactlyOnce(t *testing.T) {
	fixture := jointDPBiomedicalGaussianTestWorkerFixture(t, 2, 2, t.Name())
	handoffs := jointDPBiomedicalGaussianOneDrawTestHandoffs(
		t, fixture, [][2]int{{0, 1}, {1, 1}},
		jointDPBiomedicalGaussianOneDrawTestValues(2), true)
	key := sha256.Sum256([]byte(t.Name() + "/backend-key"))
	dir := t.TempDir()
	peer := fixture.envelope.Preimage.GarblerPeerName
	const workers = 8
	results := make(chan jointDPBiomedicalGaussianOneDrawLocalRelease, workers)
	errorsCh := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			store, err := newJointDPBiomedicalGaussianOneDrawDurableReleaseStore(
				filepath.Join(dir, peer), peer, key,
				fixture.base.private[peer])
			if err != nil {
				errorsCh <- err
				return
			}
			result, err := store.FinalizeVector(handoffs, fixture.trust, nil)
			if err != nil {
				errorsCh <- err
				return
			}
			results <- result
		}()
	}
	wait.Wait()
	close(results)
	close(errorsCh)
	for err := range errorsCh {
		t.Fatal(err)
	}
	var first *jointDPBiomedicalGaussianOneDrawLocalReleaseReceipt
	count, fresh := 0, 0
	for result := range results {
		count++
		if !result.Replayed {
			fresh++
		}
		if first == nil {
			copy := result.Receipt
			first = &copy
		} else if !reflect.DeepEqual(*first, result.Receipt) {
			t.Fatal("concurrent stores returned different signed releases")
		}
	}
	if count != workers || fresh < 1 {
		t.Fatalf("concurrent CAS count=%d fresh=%d", count, fresh)
	}
}

func TestJointDPBiomedicalGaussianOneDrawCostCertificateBlocksFalsePromotion(t *testing.T) {
	plan, err := jointDPPlanGaussianOneDraw(jointDPGaussianOneDrawPlanInput{
		Epsilon: "1", Delta: "0.000001",
		L2SensitivitySteps: "363", TotalCoordinateCount: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.CapabilityAvailable || plan.LogarithmicCircuitSizeClaim ||
		plan.SecretIndexedPublicRAMAvailable ||
		plan.CDFComparisonsPerCoordinate != plan.SamplerMagnitudeCount-1 {
		t.Fatal("one-draw plan made a false logarithmic/secret-RAM claim")
	}
	planSHA256, err := jointDPBiomedicalGaussianHash(plan)
	if err != nil {
		t.Fatal(err)
	}
	cost, err := jointDPBiomedicalGaussianOneDrawCost(plan, planSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if cost.PeakProjectedCompilerAllocationBytesUpper < 5_000_000_000 ||
		cost.AggregateProjectedGarbledTableBytesUpper <=
			cost.IndependentFullProtectedSharePayloadBytes ||
		cost.GarbledToIndependentPayloadRatioNumerator == "0" ||
		!cost.ResourcePolicySatisfied || cost.FallbackAutomatic ||
		cost.FallbackNominalVarianceMultiplier != 2 {
		t.Fatalf("cost comparison did not quantify the one-draw blocker: %+v",
			cost)
	}
	unavailable, err := jointDPPlanGaussianOneDraw(
		jointDPGaussianOneDrawPlanInput{
			Epsilon:            "1",
			Delta:              "0.000001",
			L2SensitivitySteps: "810", TotalCoordinateCount: 10})
	if err != nil {
		t.Fatal(err)
	}
	if unavailable.CapabilityAvailable || !unavailable.FallbackAvailable ||
		unavailable.FallbackAutomatic ||
		unavailable.FallbackNominalVarianceMultiplier != 2 ||
		unavailable.UnavailableReason == "" {
		t.Fatal("impractical one-draw shape could be silently promoted/fallback")
	}
}
