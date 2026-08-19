package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type formalCoxBlockwiseSourceBridgeTestFixture struct {
	plan        formalCoxBlockwisePlan
	pins        map[string]ed25519.PublicKey
	signing     map[string]ed25519.PrivateKey
	session     *formalCoxBlockwiseSourceSession
	transportSK map[string][]byte
	sourceDir   map[string]string
	workerDir   map[string]string
	sourceKey   map[string][32]byte
	workerKey   map[string][32]byte
}

func newFormalCoxBlockwiseSourceBridgeTestFixture(t testing.TB, custodians int,
	complete map[string]bool) *formalCoxBlockwiseSourceBridgeTestFixture {
	t.Helper()
	plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, custodians)
	session, _, transportSK := formalCoxBlockwiseSourceTestSession(
		t, plan, pins, signing)
	root := t.TempDir()
	sourceRoot, workerRoot := filepath.Join(root, "source"), filepath.Join(root, "worker")
	if err := os.Mkdir(sourceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(workerRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture := &formalCoxBlockwiseSourceBridgeTestFixture{
		plan: plan, pins: pins, signing: signing, session: session,
		transportSK: transportSK, sourceDir: make(map[string]string, 2),
		workerDir: make(map[string]string, 2), sourceKey: make(map[string][32]byte, 2),
		workerKey: make(map[string][32]byte, 2),
	}
	stores := make(map[string]*formalCoxBlockwiseSourceStore, 2)
	for _, peer := range plan.Policy.ComputePeers {
		fixture.sourceDir[peer] = filepath.Join(sourceRoot, peer)
		fixture.workerDir[peer] = filepath.Join(workerRoot, peer)
		fixture.sourceKey[peer] = sha256.Sum256(
			[]byte("formal-cox-source-bridge/source/" + peer))
		fixture.workerKey[peer] = sha256.Sum256(
			[]byte("formal-cox-source-bridge/worker/" + peer))
		var err error
		stores[peer], err = newFormalCoxBlockwiseSourceStore(
			fixture.sourceDir[peer], fixture.sourceKey[peer], session, peer,
			transportSK[peer])
		if err != nil {
			t.Fatal(err)
		}
	}
	closeStores := func() {
		for _, store := range stores {
			_ = store.Close()
		}
	}
	defer closeStores()
	for block := 0; block < plan.TotalBlocks; block++ {
		step := formalCoxBlockwiseSourceTestStep(
			t, plan, formalCoxBlockwiseStepBlock, block)
		for sourceIndex, source := range plan.Policy.CustodianPeers {
			values := make(map[string][]*big.Int, 2)
			for recipientIndex, recipient := range plan.Policy.ComputePeers {
				values[recipient], _ = formalCoxBlockwiseSourceTestShares(
					plan, step, sourceIndex, recipientIndex)
			}
			envelopes, binding := formalCoxBlockwiseSourceTestSealBlockPair(
				t, session, signing, source, step, values)
			for _, recipient := range plan.Policy.ComputePeers {
				if complete[recipient] {
					if _, err := stores[recipient].Accept(
						envelopes[recipient], binding); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}
	for iteration := 0; iteration < plan.Iterations; iteration++ {
		step := formalCoxBlockwiseSourceTestStep(
			t, plan, formalCoxBlockwiseStepUpdate, iteration)
		values := make(map[string][]*big.Int, 2)
		validity := make(map[string]bool, 2)
		for recipientIndex, recipient := range plan.Policy.ComputePeers {
			var valid *bool
			values[recipient], valid = formalCoxBlockwiseSourceTestShares(
				plan, step, recipientIndex, recipientIndex)
			validity[recipient] = *valid
		}
		envelopes, binding := formalCoxBlockwiseSourceTestSealNoisePair(
			t, session, signing, step, values, validity)
		for _, recipient := range plan.Policy.ComputePeers {
			if complete[recipient] {
				if _, err := stores[recipient].Accept(
					envelopes[recipient], binding); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	return fixture
}

func formalCoxBlockwiseSourceBridgeTestOpen(t testing.TB,
	fixture *formalCoxBlockwiseSourceBridgeTestFixture) (
	[]*formalCoxBlockwiseSourceBridge, error) {
	t.Helper()
	bridges := make([]*formalCoxBlockwiseSourceBridge, 0, 2)
	for _, peer := range fixture.plan.Policy.ComputePeers {
		bridge, err := newFormalCoxBlockwiseSourceBridge(
			fixture.sourceDir[peer], fixture.sourceKey[peer], fixture.session, peer,
			fixture.transportSK[peer], fixture.workerDir[peer],
			fixture.workerKey[peer], fixture.signing[peer])
		if err != nil {
			for _, opened := range bridges {
				_ = opened.Close()
			}
			return nil, err
		}
		bridges = append(bridges, bridge)
	}
	return bridges, nil
}

func formalCoxBlockwiseSourceBridgeTestClose(
	bridges []*formalCoxBlockwiseSourceBridge) {
	for _, bridge := range bridges {
		_ = bridge.Close()
	}
}

func formalCoxBlockwiseSourceBridgeTestStep(plan formalCoxBlockwisePlan,
	kind string) formalCoxBlockwiseWorkerStep {
	index := 0
	switch kind {
	case formalCoxBlockwiseStepGrid:
		index = plan.TotalBlocks
	case formalCoxBlockwiseStepUpdate:
		index = plan.TotalBlocks + plan.Policy.GridTickCount*plan.Policy.CovariateCount
	case formalCoxBlockwiseStepProjection:
		index = plan.TotalBlocks + plan.Policy.GridTickCount*plan.Policy.CovariateCount + 1
	}
	step, err := formalCoxBlockwiseWorkerStepAt(plan, index)
	if err != nil || step.Kind != kind {
		panic("invalid bridge test step")
	}
	return step
}

func formalCoxBlockwiseSourceBridgeTestStageWorkers(t testing.TB,
	fixture *formalCoxBlockwiseSourceBridgeTestFixture, target int) {
	t.Helper()
	stores := make([]*formalCoxBlockwiseCheckpointStore, 2)
	for index, peer := range fixture.plan.Policy.ComputePeers {
		var err error
		stores[index], err = newFormalCoxBlockwiseCheckpointStore(
			fixture.workerDir[peer], fixture.workerKey[peer], fixture.plan, peer)
		if err != nil {
			t.Fatal(err)
		}
		if err := stores[index].Bootstrap(); err != nil {
			t.Fatal(err)
		}
	}
	for scheduleIndex := 0; scheduleIndex < target; scheduleIndex++ {
		step, err := formalCoxBlockwiseWorkerStepAt(fixture.plan, scheduleIndex)
		if err != nil {
			t.Fatal(err)
		}
		if formalCoxBlockwiseWorkerStepNeedsInput(step) {
			step.InputRoot = formalCoxBlockwiseWorkerTestRoot(
				t.Name()+"/staged", scheduleIndex)
		}
		attempt := sha256.Sum256([]byte(fmt.Sprintf(
			"%s/staged-attempt/%d", t.Name(), scheduleIndex)))
		master := sha256.Sum256([]byte(fmt.Sprintf(
			"%s/staged-master/%d", t.Name(), scheduleIndex)))
		session, err := formalCoxBlockwiseWorkerSession(
			fixture.plan, step, attempt, master)
		if err != nil {
			t.Fatal(err)
		}
		receipts := make([]formalCoxBlockwiseStepReceipt, 2)
		for index, peer := range fixture.plan.Policy.ComputePeers {
			if _, err := stores[index].BeginAttempt(step, attempt); err != nil {
				t.Fatal(err)
			}
			if err := stores[index].RecordPendingOutput(step, session,
				formalCoxBlockwiseWorkerTestOutput(
					fixture.plan, step, index)); err != nil {
				t.Fatal(err)
			}
			receipts[index], err = stores[index].PendingReceipt(
				fixture.signing[peer])
			if err != nil {
				t.Fatal(err)
			}
		}
		for _, store := range stores {
			if err := store.CommitPending(receipts, fixture.pins); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestFormalCoxBlockwiseSourceBridgePublicRootsK2K3K5AreShareFree(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			complete := map[string]bool{"peer-a": true, "peer-b": true}
			fixture := newFormalCoxBlockwiseSourceBridgeTestFixture(
				t, custodians, complete)
			bridges, err := formalCoxBlockwiseSourceBridgeTestOpen(t, fixture)
			if err != nil {
				t.Fatal(err)
			}
			defer formalCoxBlockwiseSourceBridgeTestClose(bridges)
			for _, kind := range []string{
				formalCoxBlockwiseStepBlock, formalCoxBlockwiseStepGrid,
				formalCoxBlockwiseStepUpdate, formalCoxBlockwiseStepProjection,
			} {
				step := formalCoxBlockwiseSourceBridgeTestStep(fixture.plan, kind)
				roots := make([]string, 2)
				for index, bridge := range bridges {
					// The public gate must not require or attempt X25519 decryption.
					saved := append([]byte(nil), bridge.source.recipientSK...)
					clear(bridge.source.recipientSK)
					roots[index], err = bridge.PublicInputRoot(step)
					bridge.source.recipientSK = saved
					if err != nil {
						t.Fatalf("%s peer=%d: %v", kind, index, err)
					}
				}
				matched, err := formalCoxBlockwiseMatchPublicInputRoots(
					fixture.plan, step, roots)
				if err != nil {
					t.Fatalf("%s: %v", kind, err)
				}
				if formalCoxBlockwiseWorkerStepNeedsInput(step) {
					if !formalCoxIsSHA256(matched) || roots[0] != roots[1] {
						t.Fatalf("%s roles derived different roots: %v", kind, roots)
					}
				} else if matched != "" || roots[0] != "" || roots[1] != "" {
					t.Fatalf("%s unexpectedly touched a source asset", kind)
				}
			}
		})
	}
}

func formalCoxBlockwiseSourceBridgeTestRunPair(t testing.TB,
	fixture *formalCoxBlockwiseSourceBridgeTestFixture,
	step formalCoxBlockwiseWorkerStep) {
	t.Helper()
	formalCoxBlockwiseSourceBridgeTestStageWorkers(
		t, fixture, step.ScheduleIndex)
	bridges, err := formalCoxBlockwiseSourceBridgeTestOpen(t, fixture)
	if err != nil {
		t.Fatal(err)
	}
	roots := make([]string, 2)
	for index := range bridges {
		roots[index], err = bridges[index].PublicInputRoot(step)
		if err != nil {
			formalCoxBlockwiseSourceBridgeTestClose(bridges)
			t.Fatal(err)
		}
	}
	pairedRoot, err := formalCoxBlockwiseMatchPublicInputRoots(
		fixture.plan, step, roots)
	if err != nil {
		formalCoxBlockwiseSourceBridgeTestClose(bridges)
		t.Fatal(err)
	}
	attempt := sha256.Sum256([]byte(t.Name() + "/attempt"))
	master := sha256.Sum256([]byte(t.Name() + "/master"))
	bound := make([]formalCoxBlockwiseWorkerStep, 2)
	for index := range bridges {
		bound[index], err = bridges[index].BeginAttempt(step, attempt, pairedRoot)
		if err != nil {
			formalCoxBlockwiseSourceBridgeTestClose(bridges)
			t.Fatal(err)
		}
	}
	if bound[0] != bound[1] ||
		(formalCoxBlockwiseWorkerStepNeedsInput(step) &&
			bound[0].InputRoot != pairedRoot) {
		formalCoxBlockwiseSourceBridgeTestClose(bridges)
		t.Fatal("compute roles began different source-bound steps")
	}
	session, err := formalCoxBlockwiseWorkerSession(
		fixture.plan, bound[0], attempt, master)
	if err != nil {
		formalCoxBlockwiseSourceBridgeTestClose(bridges)
		t.Fatal(err)
	}
	if !formalCoxBlockwiseWorkerStepNeedsInput(step) {
		// Internal steps must not consult or decrypt the source spool.
		for _, bridge := range bridges {
			if err := bridge.source.Close(); err != nil {
				formalCoxBlockwiseSourceBridgeTestClose(bridges)
				t.Fatal(err)
			}
		}
	}
	left, right := net.Pipe()
	_ = left.SetDeadline(time.Now().Add(180 * time.Second))
	_ = right.SetDeadline(time.Now().Add(180 * time.Second))
	type outcome struct {
		receipt formalCoxBlockwiseStepReceipt
		err     error
	}
	leftDone := make(chan outcome, 1)
	go func() {
		receipt, runErr := bridges[0].RunPendingWorkerStep(left, session)
		leftDone <- outcome{receipt: receipt, err: runErr}
	}()
	rightReceipt, rightErr := bridges[1].RunPendingWorkerStep(right, session)
	leftResult := <-leftDone
	_ = left.Close()
	_ = right.Close()
	if leftResult.err != nil || rightErr != nil {
		formalCoxBlockwiseSourceBridgeTestClose(bridges)
		t.Fatalf("bridge GC %s: left=%v right=%v",
			step.Kind, leftResult.err, rightErr)
	}
	receipts := []formalCoxBlockwiseStepReceipt{
		leftResult.receipt, rightReceipt,
	}
	if err := formalCoxBlockwiseValidateReceiptPair(
		fixture.plan, receipts, fixture.pins); err != nil {
		formalCoxBlockwiseSourceBridgeTestClose(bridges)
		t.Fatal(err)
	}
	before := make([][]byte, 2)
	for index := range receipts {
		before[index], err = json.Marshal(receipts[index])
		if err != nil {
			formalCoxBlockwiseSourceBridgeTestClose(bridges)
			t.Fatal(err)
		}
	}
	formalCoxBlockwiseSourceBridgeTestClose(bridges)

	// Simulate a cold restart after GC recorded the sealed output but before
	// the two-receipt commit barrier. Replay must not need a network stream.
	bridges, err = formalCoxBlockwiseSourceBridgeTestOpen(t, fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer formalCoxBlockwiseSourceBridgeTestClose(bridges)
	for index := range bridges {
		replayed, err := bridges[index].RunPendingWorkerStep(nil, session)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(replayed)
		if err != nil || !bytes.Equal(encoded, before[index]) {
			t.Fatalf("peer %d restart changed the pending receipt: %v", index, err)
		}
		checkpoint, err := os.ReadFile(bridges[index].worker.path)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range [][]byte{[]byte(`"shares"`), []byte(`"plaintext"`)} {
			if bytes.Contains(bytes.ToLower(checkpoint), forbidden) ||
				bytes.Contains(bytes.ToLower(encoded), forbidden) {
				t.Fatalf("peer %d persisted a forbidden bridge field %s",
					index, forbidden)
			}
		}
	}
}

func TestFormalCoxBlockwiseSourceBridgeRunsAllShapesAndReplaysExactly(t *testing.T) {
	cases := []struct {
		name       string
		custodians int
		kind       string
	}{
		{name: "K2_block", custodians: 2, kind: formalCoxBlockwiseStepBlock},
		{name: "K3_grid", custodians: 3, kind: formalCoxBlockwiseStepGrid},
		{name: "K3_update", custodians: 3, kind: formalCoxBlockwiseStepUpdate},
		{name: "K5_projection", custodians: 5, kind: formalCoxBlockwiseStepProjection},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFormalCoxBlockwiseSourceBridgeTestFixture(t,
				test.custodians, map[string]bool{"peer-a": true, "peer-b": true})
			step := formalCoxBlockwiseSourceBridgeTestStep(
				fixture.plan, test.kind)
			formalCoxBlockwiseSourceBridgeTestRunPair(t, fixture, step)
		})
	}
}

func formalCoxBlockwiseSourceBridgeTestRewriteSlot(t testing.TB, path string,
	mutate func(*formalCoxBlockwiseBoundSourceSlot)) {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record formalCoxBlockwiseBoundSourceSlot
	if err := json.Unmarshal(encoded, &record); err != nil {
		t.Fatal(err)
	}
	mutate(&record)
	encoded, err = json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := exactGCAtomicReplace(path, encoded); err != nil {
		t.Fatal(err)
	}
}

func formalCoxBlockwiseSourceBridgeTestRejectsSlot(t testing.TB,
	fixture *formalCoxBlockwiseSourceBridgeTestFixture,
	step formalCoxBlockwiseWorkerStep) {
	t.Helper()
	peer := fixture.plan.Policy.ComputePeers[0]
	bridge, err := newFormalCoxBlockwiseSourceBridge(
		fixture.sourceDir[peer], fixture.sourceKey[peer], fixture.session, peer,
		fixture.transportSK[peer], fixture.workerDir[peer], fixture.workerKey[peer],
		fixture.signing[peer])
	if err == nil {
		_, err = bridge.PublicInputRoot(step)
		_ = bridge.Close()
	}
	if err == nil {
		t.Fatal("tampered source slot crossed the bridge public-root gate")
	}
}

func TestFormalCoxBlockwiseSourceBridgeRejectsBindingAndCiphertextMatrix(t *testing.T) {
	for _, attack := range []string{
		"root", "slot", "schedule", "role", "ticket", "ciphertext",
		"barrier", "run_mix", "reorder", "missing",
	} {
		t.Run(attack, func(t *testing.T) {
			fixture := newFormalCoxBlockwiseSourceBridgeTestFixture(t, 2,
				map[string]bool{"peer-a": true, "peer-b": true})
			peer := fixture.plan.Policy.ComputePeers[0]
			step := formalCoxBlockwiseSourceBridgeTestStep(
				fixture.plan, formalCoxBlockwiseStepBlock)
			slot := 0
			if attack == "barrier" {
				slot = fixture.plan.TotalBlocks *
					len(fixture.plan.Policy.CustodianPeers)
				step = formalCoxBlockwiseSourceBridgeTestStep(
					fixture.plan, formalCoxBlockwiseStepUpdate)
			}
			path := filepath.Join(fixture.sourceDir[peer], "slots-v1",
				fmt.Sprintf("slot-%012d.bin", slot))
			switch attack {
			case "reorder":
				other := filepath.Join(fixture.sourceDir[peer], "slots-v1",
					"slot-000000000001.bin")
				left, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				right, err := os.ReadFile(other)
				if err != nil {
					t.Fatal(err)
				}
				if err := exactGCAtomicReplace(path, right); err != nil {
					t.Fatal(err)
				}
				if err := exactGCAtomicReplace(other, left); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			default:
				formalCoxBlockwiseSourceBridgeTestRewriteSlot(t, path,
					func(record *formalCoxBlockwiseBoundSourceSlot) {
						if attack == "ciphertext" || attack == "slot" {
							var envelope formalCoxBlockwiseSourceEnvelope
							if err := json.Unmarshal(record.Envelope, &envelope); err != nil {
								t.Fatal(err)
							}
							if attack == "ciphertext" {
								envelope.Ciphertext[0] ^= 0x80
							} else {
								envelope.Header.AssetSlot++
							}
							record.Envelope, _ = json.Marshal(envelope)
							return
						}
						if attack == "barrier" {
							var barrier formalCoxBlockwiseGuardedNoiseBarrier
							if err := json.Unmarshal(record.Binding, &barrier); err != nil {
								t.Fatal(err)
							}
							barrier.Barrier.PairedNoiseRootSHA256 = strings.Repeat("0", 64)
							record.Binding, _ = json.Marshal(barrier)
							return
						}
						var manifest formalCoxBlockwiseSourcePairManifest
						if err := json.Unmarshal(record.Binding, &manifest); err != nil {
							t.Fatal(err)
						}
						switch attack {
						case "root":
							manifest.PairedInputRootSHA256 = strings.Repeat("0", 64)
						case "schedule":
							manifest.CanonicalScheduleIndex++
						case "role":
							manifest.Recipients[0].RecipientRole += "-swapped"
						case "ticket":
							manifest.Recipients[0].RecipientTicketSHA256 =
								strings.Repeat("0", 64)
						case "run_mix":
							manifest.RunID = formalCoxBlockwiseWorkerTestRoot(
								"different-run", 0)
						}
						record.Binding, _ = json.Marshal(manifest)
					})
			}
			formalCoxBlockwiseSourceBridgeTestRejectsSlot(t, fixture, step)
		})
	}
}

func TestFormalCoxBlockwiseSourceBridgeRejectsOneSidedAndRootMismatch(t *testing.T) {
	fixture := newFormalCoxBlockwiseSourceBridgeTestFixture(t, 3,
		map[string]bool{"peer-a": true, "peer-b": false})
	bridges, err := formalCoxBlockwiseSourceBridgeTestOpen(t, fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer formalCoxBlockwiseSourceBridgeTestClose(bridges)
	for _, kind := range []string{
		formalCoxBlockwiseStepBlock, formalCoxBlockwiseStepUpdate,
	} {
		step := formalCoxBlockwiseSourceBridgeTestStep(fixture.plan, kind)
		left, err := bridges[0].PublicInputRoot(step)
		if err != nil || !formalCoxIsSHA256(left) {
			t.Fatalf("complete local spool failed %s: %v", kind, err)
		}
		if _, err := bridges[1].PublicInputRoot(step); err == nil {
			t.Fatalf("one-sided %s input crossed the public gate", kind)
		}
	}

	complete := newFormalCoxBlockwiseSourceBridgeTestFixture(t, 3,
		map[string]bool{"peer-a": true, "peer-b": true})
	completeBridges, err := formalCoxBlockwiseSourceBridgeTestOpen(t, complete)
	if err != nil {
		t.Fatal(err)
	}
	defer formalCoxBlockwiseSourceBridgeTestClose(completeBridges)
	step := formalCoxBlockwiseSourceBridgeTestStep(
		complete.plan, formalCoxBlockwiseStepBlock)
	roots := make([]string, 2)
	for index := range completeBridges {
		roots[index], err = completeBridges[index].PublicInputRoot(step)
		if err != nil {
			t.Fatal(err)
		}
	}
	wrong := formalCoxBlockwiseWorkerTestRoot("wrong-paired-root", 0)
	if wrong == roots[0] {
		t.Fatal("invalid test root collision")
	}
	if _, err := formalCoxBlockwiseMatchPublicInputRoots(
		complete.plan, step, []string{roots[0], wrong}); err == nil {
		t.Fatal("different role roots crossed the share-free gate")
	}
	if _, err := completeBridges[0].BeginAttempt(step,
		sha256.Sum256([]byte(t.Name()+"/attempt")), wrong); err == nil {
		t.Fatal("an unrelated paired root reached the worker checkpoint")
	}
}

func TestFormalCoxBlockwiseSourceBridgeCrashRequiresFreshBoundAttempt(t *testing.T) {
	fixture := newFormalCoxBlockwiseSourceBridgeTestFixture(t, 2,
		map[string]bool{"peer-a": true, "peer-b": true})
	peer := fixture.plan.Policy.ComputePeers[0]
	bridge, err := newFormalCoxBlockwiseSourceBridge(
		fixture.sourceDir[peer], fixture.sourceKey[peer], fixture.session, peer,
		fixture.transportSK[peer], fixture.workerDir[peer], fixture.workerKey[peer],
		fixture.signing[peer])
	if err != nil {
		t.Fatal(err)
	}
	step := formalCoxBlockwiseSourceBridgeTestStep(
		fixture.plan, formalCoxBlockwiseStepBlock)
	root, err := bridge.PublicInputRoot(step)
	if err != nil {
		t.Fatal(err)
	}
	oldAttempt := sha256.Sum256([]byte(t.Name() + "/old-attempt"))
	bound, err := bridge.BeginAttempt(step, oldAttempt, root)
	if err != nil {
		t.Fatal(err)
	}
	oldSession, err := formalCoxBlockwiseWorkerSession(fixture.plan, bound,
		oldAttempt, sha256.Sum256([]byte(t.Name()+"/old-master")))
	if err != nil {
		t.Fatal(err)
	}
	if err := bridge.Close(); err != nil {
		t.Fatal(err)
	}
	bridge, err = newFormalCoxBlockwiseSourceBridge(
		fixture.sourceDir[peer], fixture.sourceKey[peer], fixture.session, peer,
		fixture.transportSK[peer], fixture.workerDir[peer], fixture.workerKey[peer],
		fixture.signing[peer])
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	newAttempt := sha256.Sum256([]byte(t.Name() + "/new-attempt"))
	bound, err = bridge.BeginAttempt(step, newAttempt, root)
	if err != nil {
		t.Fatalf("fresh source-bound attempt after crash: %v", err)
	}
	if _, err := bridge.RunPendingWorkerStep(nil, oldSession); err == nil {
		t.Fatal("pre-crash GC session resumed after a fresh attempt")
	}
	state, err := bridge.worker.Load()
	if err != nil || state.Pending == nil ||
		state.Pending.AttemptID != hex.EncodeToString(newAttempt[:]) ||
		state.Pending.Step != bound {
		t.Fatalf("fresh attempt was not durably bound: %+v %v", state.Pending, err)
	}
}

func TestFormalCoxBlockwiseSourceBridgeRejectsWrongKeysModesAndLinks(t *testing.T) {
	t.Run("keys", func(t *testing.T) {
		fixture := newFormalCoxBlockwiseSourceBridgeTestFixture(t, 2,
			map[string]bool{"peer-a": true, "peer-b": true})
		peer := fixture.plan.Policy.ComputePeers[0]
		wrongSK := append([]byte(nil), fixture.transportSK[peer]...)
		wrongSK[0] ^= 0x80
		if bridge, err := newFormalCoxBlockwiseSourceBridge(
			fixture.sourceDir[peer], fixture.sourceKey[peer], fixture.session, peer,
			wrongSK, fixture.workerDir[peer], fixture.workerKey[peer],
			fixture.signing[peer]); err == nil {
			_ = bridge.Close()
			t.Fatal("wrong recipient transport key opened a source bridge")
		}
		if bridge, err := newFormalCoxBlockwiseSourceBridge(
			fixture.sourceDir[peer], fixture.sourceKey[peer], fixture.session, peer,
			fixture.transportSK[peer], fixture.workerDir[peer], fixture.workerKey[peer],
			fixture.signing[fixture.plan.Policy.ComputePeers[1]]); err == nil {
			_ = bridge.Close()
			t.Fatal("wrong compute signer opened a source bridge")
		}
	})
	t.Run("valid_run_mix", func(t *testing.T) {
		fixture := newFormalCoxBlockwiseSourceBridgeTestFixture(t, 2,
			map[string]bool{"peer-a": true, "peer-b": true})
		mixedPlan := fixture.plan
		mixedPlan.RunID = formalCoxBlockwiseWorkerTestRoot("other-valid-run", 0)
		mixedSession, _, mixedSK := formalCoxBlockwiseSourceTestSession(
			t, mixedPlan, fixture.pins, fixture.signing)
		peer := fixture.plan.Policy.ComputePeers[0]
		if bridge, err := newFormalCoxBlockwiseSourceBridge(
			fixture.sourceDir[peer], fixture.sourceKey[peer], mixedSession, peer,
			mixedSK[peer], fixture.workerDir[peer], fixture.workerKey[peer],
			fixture.signing[peer]); err == nil {
			_ = bridge.Close()
			t.Fatal("a valid but different run context opened the source cursor")
		}
	})
	for _, attack := range []string{"mode", "hardlink", "symlink"} {
		t.Run("slot_"+attack, func(t *testing.T) {
			fixture := newFormalCoxBlockwiseSourceBridgeTestFixture(t, 2,
				map[string]bool{"peer-a": true, "peer-b": true})
			peer := fixture.plan.Policy.ComputePeers[0]
			path := filepath.Join(fixture.sourceDir[peer], "slots-v1",
				"slot-000000000000.bin")
			switch attack {
			case "mode":
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".alias"); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".target"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".target", path); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			}
			formalCoxBlockwiseSourceBridgeTestRejectsSlot(t, fixture,
				formalCoxBlockwiseSourceBridgeTestStep(
					fixture.plan, formalCoxBlockwiseStepBlock))
		})
	}
	t.Run("root_symlinks", func(t *testing.T) {
		fixture := newFormalCoxBlockwiseSourceBridgeTestFixture(t, 2,
			map[string]bool{"peer-a": true, "peer-b": true})
		peer := fixture.plan.Policy.ComputePeers[0]
		sourceAlias := filepath.Join(t.TempDir(), "source-link")
		if err := os.Symlink(fixture.sourceDir[peer], sourceAlias); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if bridge, err := newFormalCoxBlockwiseSourceBridge(
			sourceAlias, fixture.sourceKey[peer], fixture.session, peer,
			fixture.transportSK[peer], fixture.workerDir[peer], fixture.workerKey[peer],
			fixture.signing[peer]); err == nil {
			_ = bridge.Close()
			t.Fatal("symlinked source root was followed")
		}
		workerAlias := filepath.Join(t.TempDir(), "worker-link")
		if err := os.Symlink(t.TempDir(), workerAlias); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if bridge, err := newFormalCoxBlockwiseSourceBridge(
			fixture.sourceDir[peer], fixture.sourceKey[peer], fixture.session, peer,
			fixture.transportSK[peer], workerAlias, fixture.workerKey[peer],
			fixture.signing[peer]); err == nil {
			_ = bridge.Close()
			t.Fatal("symlinked worker root was followed")
		}
	})
	t.Run("worker_hardlink", func(t *testing.T) {
		fixture := newFormalCoxBlockwiseSourceBridgeTestFixture(t, 2,
			map[string]bool{"peer-a": true, "peer-b": true})
		peer := fixture.plan.Policy.ComputePeers[0]
		bridge, err := newFormalCoxBlockwiseSourceBridge(
			fixture.sourceDir[peer], fixture.sourceKey[peer], fixture.session, peer,
			fixture.transportSK[peer], fixture.workerDir[peer], fixture.workerKey[peer],
			fixture.signing[peer])
		if err != nil {
			t.Fatal(err)
		}
		checkpoint := bridge.worker.path
		if err := bridge.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(checkpoint, checkpoint+".alias"); err != nil {
			t.Fatal(err)
		}
		if reopened, err := newFormalCoxBlockwiseSourceBridge(
			fixture.sourceDir[peer], fixture.sourceKey[peer], fixture.session, peer,
			fixture.transportSK[peer], fixture.workerDir[peer], fixture.workerKey[peer],
			fixture.signing[peer]); err == nil {
			_ = reopened.Close()
			t.Fatal("hard-linked worker checkpoint was accepted")
		}
	})
}

func TestFormalCoxBlockwiseSourceBridgeOwnershipIsMultiprocess(t *testing.T) {
	if helper := os.Getenv("DSVERT_COX_BRIDGE_LOCK_HELPER"); helper != "" {
		owner, err := formalCoxBlockwiseSourceAcquireOwner(
			filepath.Join(helper, "owner.lock"))
		if err == nil {
			_ = owner.Close()
			t.Fatal("second process acquired a bridge-owned source spool")
		}
		if !strings.Contains(err.Error(), "already has an owner") {
			t.Fatalf("unexpected bridge lock error: %v", err)
		}
		return
	}
	fixture := newFormalCoxBlockwiseSourceBridgeTestFixture(t, 3,
		map[string]bool{"peer-a": true, "peer-b": true})
	peer := fixture.plan.Policy.ComputePeers[0]
	bridge, err := newFormalCoxBlockwiseSourceBridge(
		fixture.sourceDir[peer], fixture.sourceKey[peer], fixture.session, peer,
		fixture.transportSK[peer], fixture.workerDir[peer], fixture.workerKey[peer],
		fixture.signing[peer])
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	if second, err := newFormalCoxBlockwiseSourceBridge(
		fixture.sourceDir[peer], fixture.sourceKey[peer], fixture.session, peer,
		fixture.transportSK[peer], fixture.workerDir[peer], fixture.workerKey[peer],
		fixture.signing[peer]); err == nil {
		_ = second.Close()
		t.Fatal("concurrent bridge acquired the same source spool")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable,
		"-test.run=^TestFormalCoxBlockwiseSourceBridgeOwnershipIsMultiprocess$")
	command.Env = append(os.Environ(),
		"DSVERT_COX_BRIDGE_LOCK_HELPER="+fixture.sourceDir[peer])
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("multiprocess bridge lock: %v\n%s", err, output)
	}
}
