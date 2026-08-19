package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func formalCoxBlockwiseWorkerTestIdentities(t testing.TB, custodians int) (
	map[string]ed25519.PublicKey, map[string]ed25519.PrivateKey) {
	t.Helper()
	public := make(map[string]ed25519.PublicKey, custodians)
	private := make(map[string]ed25519.PrivateKey, custodians)
	for index := 0; index < custodians; index++ {
		peer := "peer-" + string(rune('a'+index))
		seed := sha256.Sum256([]byte("formal-cox-blockwise-worker/" + peer))
		key := ed25519.NewKeyFromSeed(seed[:])
		public[peer] = append(ed25519.PublicKey(nil), key.Public().(ed25519.PublicKey)...)
		private[peer] = append(ed25519.PrivateKey(nil), key...)
	}
	return public, private
}

func formalCoxBlockwiseWorkerTestPlan(t testing.TB, custodians, capacity int) (
	formalCoxBlockwisePlan, map[string]ed25519.PublicKey,
	map[string]ed25519.PrivateKey) {
	t.Helper()
	public, private := formalCoxBlockwiseWorkerTestIdentities(t, custodians)
	policy := formalCoxBlockwiseTestPolicy(t, custodians, capacity)
	pinset, err := formalCoxBlockwisePinsetSHA256(public)
	if err != nil {
		t.Fatal(err)
	}
	policy.PinsetSHA256 = pinset
	runID := sha256.Sum256([]byte(t.Name() + "/plan/" +
		big.NewInt(int64(custodians)).String() + "/" +
		big.NewInt(int64(capacity)).String()))
	plan, err := buildFormalCoxBlockwisePlan(
		policy, 2, hex.EncodeToString(runID[:]))
	if err != nil {
		t.Fatal(err)
	}
	return plan, public, private
}

func formalCoxBlockwiseWorkerTestKey(peer string) [32]byte {
	return sha256.Sum256([]byte("formal-cox-blockwise-checkpoint-key/" + peer))
}

func formalCoxBlockwiseWorkerTestOutput(plan formalCoxBlockwisePlan,
	step formalCoxBlockwiseWorkerStep, peerIndex int) formalCoxBlockwiseStepOutput {
	count := formalCoxBlockwiseWorkerOutputCoordinates(plan, step)
	values := make([]*big.Int, count)
	for index := range values {
		values[index] = big.NewInt(int64(1 + peerIndex*1000 + step.ScheduleIndex*17 + index))
		values[index].Mod(values[index], exactGCModulus(plan.RingBits))
	}
	return formalCoxBlockwiseStepOutput{
		ArithmeticShares: values,
		ValidityShare:    peerIndex == 1,
	}
}

func formalCoxBlockwiseWorkerTestRoot(label string, step int) string {
	digest := sha256.Sum256([]byte(label + "/" + big.NewInt(int64(step)).String()))
	return hex.EncodeToString(digest[:])
}

func formalCoxBlockwiseWorkerTestRun(t testing.TB, plan formalCoxBlockwisePlan,
	pins map[string]ed25519.PublicKey,
	private map[string]ed25519.PrivateKey) ([]byte, string, string) {
	t.Helper()
	root := t.TempDir()
	peers := plan.Policy.ComputePeers
	stores := make([]*formalCoxBlockwiseCheckpointStore, 2)
	for index, peer := range peers {
		var err error
		stores[index], err = newFormalCoxBlockwiseCheckpointStore(
			filepath.Join(root, peer), formalCoxBlockwiseWorkerTestKey(peer),
			plan, peer)
		if err != nil {
			t.Fatal(err)
		}
		if err := stores[index].Bootstrap(); err != nil {
			t.Fatal(err)
		}
	}
	for scheduleIndex := 0; scheduleIndex < plan.ScheduleSteps; scheduleIndex++ {
		step, err := formalCoxBlockwiseWorkerStepAt(plan, scheduleIndex)
		if err != nil {
			t.Fatal(err)
		}
		if formalCoxBlockwiseWorkerStepNeedsInput(step) {
			step.InputRoot = formalCoxBlockwiseWorkerTestRoot(t.Name(), scheduleIndex)
		}
		attempt := sha256.Sum256([]byte(t.Name() + "/attempt/" +
			big.NewInt(int64(scheduleIndex)).String()))
		master := sha256.Sum256([]byte(t.Name() + "/master/" +
			big.NewInt(int64(scheduleIndex)).String()))
		session, err := formalCoxBlockwiseWorkerSession(plan, step, attempt, master)
		if err != nil {
			t.Fatal(err)
		}
		for index := range stores {
			if _, err := stores[index].BeginAttempt(step, attempt); err != nil {
				t.Fatalf("begin K=%d step=%d peer=%d: %v",
					len(plan.Policy.CustodianPeers), scheduleIndex, index, err)
			}
			output := formalCoxBlockwiseWorkerTestOutput(plan, step, index)
			if err := stores[index].RecordPendingOutput(step, session, output); err != nil {
				t.Fatalf("record K=%d step=%d peer=%d: %v",
					len(plan.Policy.CustodianPeers), scheduleIndex, index, err)
			}
		}
		// Exercise the durable boundary while a result is pending: no GC
		// transcript is resumed, but its completed sealed output is recoverable.
		if scheduleIndex%5 == 1 {
			for index, peer := range peers {
				stores[index], err = newFormalCoxBlockwiseCheckpointStore(
					filepath.Join(root, peer), formalCoxBlockwiseWorkerTestKey(peer),
					plan, peer)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		receipts := make([]formalCoxBlockwiseStepReceipt, 2)
		for index, peer := range peers {
			receipts[index], err = stores[index].PendingReceipt(private[peer])
			if err != nil {
				t.Fatal(err)
			}
		}
		receipts[0], receipts[1] = receipts[1], receipts[0]
		for index := range stores {
			if err := stores[index].CommitPending(receipts, pins); err != nil {
				t.Fatalf("commit K=%d step=%d peer=%d: %v",
					len(plan.Policy.CustodianPeers), scheduleIndex, index, err)
			}
		}
	}
	left, leftBytes, err := stores[0].Completion()
	if err != nil {
		t.Fatal(err)
	}
	right, rightBytes, err := stores[1].Completion()
	if err != nil {
		t.Fatal(err)
	}
	if left != right || !bytes.Equal(leftBytes, rightBytes) {
		t.Fatal("compute peers published different opaque completions")
	}
	leftPath := stores[0].completionPath
	rightPath := stores[1].completionPath
	for index, peer := range peers {
		restarted, err := newFormalCoxBlockwiseCheckpointStore(
			filepath.Join(root, peer), formalCoxBlockwiseWorkerTestKey(peer),
			plan, peer)
		if err != nil {
			t.Fatal(err)
		}
		replayed, replayedBytes, err := restarted.Completion()
		if err != nil {
			t.Fatal(err)
		}
		if replayed != left || !bytes.Equal(replayedBytes, leftBytes) {
			t.Fatalf("peer %d restart changed the sticky completion", index)
		}
	}
	return leftBytes, leftPath, rightPath
}

func TestFormalCoxBlockwiseWorkerK2K3K5ColdRestartAndStickyReplay(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+big.NewInt(int64(custodians)).String(), func(t *testing.T) {
			plan, pins, private := formalCoxBlockwiseWorkerTestPlan(t, custodians, 2)
			completion, leftPath, rightPath := formalCoxBlockwiseWorkerTestRun(
				t, plan, pins, private)
			var public formalCoxBlockwiseCompletion
			if err := json.Unmarshal(completion, &public); err != nil {
				t.Fatal(err)
			}
			if public.ProductionReady || !public.FixedScheduleComplete ||
				public.ScheduleSteps != plan.ScheduleSteps ||
				!formalCoxIsSHA256(public.FinalCommitSHA256) ||
				!formalCoxIsSHA256(public.CompletionSHA256) {
				t.Fatalf("dishonest completion: %+v", public)
			}
			lower := bytes.ToLower(completion)
			for _, forbidden := range [][]byte{
				[]byte("share"), []byte("secret"), []byte("checkpoint_key"),
				[]byte("mac"), []byte("peer"), []byte("coefficient"),
			} {
				if bytes.Contains(lower, forbidden) {
					t.Fatalf("completion exposed private worker state: %s", forbidden)
				}
			}
			for _, path := range []string{leftPath, rightPath} {
				info, err := os.Lstat(path)
				if err != nil || !info.Mode().IsRegular() ||
					info.Mode().Perm() != 0o600 || !exactGCPrivateOwnedRegular(info) {
					t.Fatalf("unsafe completion artifact %s: %v %+v", path, err, info)
				}
			}
		})
	}
}

func TestFormalCoxBlockwiseWorkerRejectsMissingReorderedAndTamperedState(t *testing.T) {
	plan, pins, private := formalCoxBlockwiseWorkerTestPlan(t, 3, 2)
	peer := plan.Policy.ComputePeers[0]
	store, err := newFormalCoxBlockwiseCheckpointStore(
		t.TempDir(), formalCoxBlockwiseWorkerTestKey(peer), plan, peer)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	expected, _ := formalCoxBlockwiseWorkerStepAt(plan, 0)
	reordered, _ := formalCoxBlockwiseWorkerStepAt(plan, plan.TotalBlocks)
	attempt := sha256.Sum256([]byte(t.Name() + "/attempt"))
	if _, err := store.BeginAttempt(reordered, attempt); err == nil {
		t.Fatal("a grid step skipped the required block schedule")
	}
	if _, err := store.BeginAttempt(expected, attempt); err == nil {
		t.Fatal("a block without an authenticated input root was accepted")
	}
	expected.InputRoot = formalCoxBlockwiseWorkerTestRoot(t.Name(), 0)
	if _, err := store.BeginAttempt(expected, attempt); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PendingReceipt(private[peer]); err == nil {
		t.Fatal("a missing block output crossed the commit barrier")
	}
	next, _ := formalCoxBlockwiseWorkerStepAt(plan, 1)
	next.InputRoot = formalCoxBlockwiseWorkerTestRoot(t.Name(), 1)
	if _, err := store.BeginAttempt(next, sha256.Sum256([]byte("next"))); err == nil {
		t.Fatal("a later block replaced a missing pending block")
	}
	restarted, err := newFormalCoxBlockwiseCheckpointStore(
		filepath.Dir(store.path), formalCoxBlockwiseWorkerTestKey(peer), plan, peer)
	if err != nil {
		t.Fatal(err)
	}
	replacement := sha256.Sum256([]byte(t.Name() + "/replacement"))
	if _, err := restarted.BeginAttempt(expected, replacement); err != nil {
		t.Fatalf("fresh session could not replace interrupted GC: %v", err)
	}
	oldSession, err := formalCoxBlockwiseWorkerSession(
		plan, expected, attempt, sha256.Sum256([]byte(t.Name()+"/master")))
	if err != nil {
		t.Fatal(err)
	}
	output := formalCoxBlockwiseWorkerTestOutput(plan, expected, 0)
	if err := restarted.RecordPendingOutput(expected, oldSession, output); err == nil {
		t.Fatal("an interrupted GC session resumed after a fresh attempt")
	}
	session, err := formalCoxBlockwiseWorkerSession(
		plan, expected, replacement, sha256.Sum256([]byte(t.Name()+"/new-master")))
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.RecordPendingOutput(expected, session, output); err != nil {
		t.Fatal(err)
	}
	receipt, err := restarted.PendingReceipt(private[peer])
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitPending([]formalCoxBlockwiseStepReceipt{receipt}, pins); err == nil {
		t.Fatal("an incomplete two-compute-peer barrier was accepted")
	}

	encoded, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	var state formalCoxBlockwiseCheckpoint
	if err := json.Unmarshal(encoded, &state); err != nil {
		t.Fatal(err)
	}
	state.MAC = strings.Repeat("0", 64)
	tampered, _ := json.Marshal(state)
	if err := os.WriteFile(store.path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("a MAC-tampered checkpoint was accepted")
	}
}

func TestFormalCoxBlockwiseWorkerAdapterBindsAllFourCircuitShapes(t *testing.T) {
	plan, _, _ := formalCoxBlockwiseWorkerTestPlan(t, 3, 2)
	peer := plan.Policy.ComputePeers[0]
	store, err := newFormalCoxBlockwiseCheckpointStore(
		t.TempDir(), formalCoxBlockwiseWorkerTestKey(peer), plan, peer)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	indices := []int{
		0,
		plan.TotalBlocks,
		plan.TotalBlocks + plan.Policy.GridTickCount*plan.Policy.CovariateCount,
		plan.TotalBlocks + plan.Policy.GridTickCount*plan.Policy.CovariateCount + 1,
	}
	for _, scheduleIndex := range indices {
		step, err := formalCoxBlockwiseWorkerStepAt(plan, scheduleIndex)
		if err != nil {
			t.Fatal(err)
		}
		if formalCoxBlockwiseWorkerStepNeedsInput(step) {
			step.InputRoot = formalCoxBlockwiseWorkerTestRoot(t.Name(), scheduleIndex)
		}
		state.NextStep = scheduleIndex
		var external []*big.Int
		var externalValidity *bool
		switch step.Kind {
		case formalCoxBlockwiseStepBlock:
			external = make([]*big.Int, plan.BlockCapacity*plan.RowWidth)
			for index := range external {
				external[index] = new(big.Int)
			}
		case formalCoxBlockwiseStepUpdate:
			external = make([]*big.Int, plan.Policy.CovariateCount)
			for index := range external {
				external[index] = new(big.Int)
			}
			valid := false
			externalValidity = &valid
		}
		local, err := formalCoxBlockwiseWorkerLocalInput(
			plan, state, step, external, externalValidity)
		if err != nil {
			t.Fatalf("%s input: %v", step.Kind, err)
		}
		circ, err := formalCoxBlockwiseCompileWorkerStep(plan, step)
		if err != nil {
			t.Fatalf("%s circuit: %v", step.Kind, err)
		}
		outputs := formalCoxBlockwiseWorkerOutputCoordinates(plan, step) + 1
		if len(local) != formalCoxBlockwiseWorkerInputCoordinates(plan, step) ||
			int(circ.Inputs[0].Type.Bits) != (len(local)+outputs)*plan.ContainerBits ||
			int(circ.Inputs[1].Type.Bits) != len(local)*plan.ContainerBits ||
			circ.Outputs.Size() != outputs*plan.ContainerBits {
			t.Fatalf("%s adapter/circuit arity mismatch", step.Kind)
		}
		if step.Kind == formalCoxBlockwiseStepBlock {
			if _, err := formalCoxBlockwiseWorkerLocalInput(
				plan, state, step, nil, nil); err == nil {
				t.Fatal("missing padded block reached the circuit adapter")
			}
		}
		if step.Kind == formalCoxBlockwiseStepUpdate {
			if _, err := formalCoxBlockwiseWorkerLocalInput(
				plan, state, step, external, nil); err == nil {
				t.Fatal("missing sealed-noise validity reached the update circuit")
			}
		}
	}
}

func TestFormalCoxBlockwiseWorkerEnforcesCASPrivateModesAndLinks(t *testing.T) {
	plan, _, _ := formalCoxBlockwiseWorkerTestPlan(t, 2, 2)
	peer := plan.Policy.ComputePeers[0]
	root := t.TempDir()
	store, err := newFormalCoxBlockwiseCheckpointStore(
		root, formalCoxBlockwiseWorkerTestKey(peer), plan, peer)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	before, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	step, _ := formalCoxBlockwiseWorkerStepAt(plan, 0)
	step.InputRoot = formalCoxBlockwiseWorkerTestRoot(t.Name(), 0)
	if _, err := store.BeginAttempt(step, sha256.Sum256([]byte("winner"))); err != nil {
		t.Fatal(err)
	}
	stale := before
	stale.Generation++
	if err := store.writeCAS(before.MAC, stale); err == nil {
		t.Fatal("a stale checkpoint compare-and-swap overwrote newer state")
	}
	if err := os.Chmod(store.path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("a world-readable checkpoint was accepted")
	}
	if err := os.Chmod(store.path, 0o600); err != nil {
		t.Fatal(err)
	}
	alias := store.path + ".hardlink"
	if err := os.Link(store.path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("a hard-linked checkpoint was accepted")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}

	symlinkRoot := filepath.Join(t.TempDir(), "worker")
	if err := os.Symlink(root, symlinkRoot); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := newFormalCoxBlockwiseCheckpointStore(
		symlinkRoot, formalCoxBlockwiseWorkerTestKey(peer), plan, peer); err == nil {
		t.Fatal("a symlinked checkpoint directory was accepted")
	}
}

func TestFormalCoxBlockwiseWorkerResidentStateIsIndependentOfN(t *testing.T) {
	small, _, _ := formalCoxBlockwiseWorkerTestPlan(t, 3, 64)
	large, _, _ := formalCoxBlockwiseWorkerTestPlan(t, 3, 100000)
	if formalCoxBlockwiseWorkerResidentCoordinates(small) !=
		formalCoxBlockwiseWorkerResidentCoordinates(large) {
		t.Fatal("worker resident coordinates grew with total N")
	}
	for _, plan := range []formalCoxBlockwisePlan{small, large} {
		peer := plan.Policy.ComputePeers[0]
		store, err := newFormalCoxBlockwiseCheckpointStore(
			t.TempDir(), formalCoxBlockwiseWorkerTestKey(peer), plan, peer)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Bootstrap(); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(store.path)
		if err != nil || info.Size() > formalCoxBlockwiseCheckpointMax {
			t.Fatalf("checkpoint escaped its fixed public bound: %v %+v", err, info)
		}
	}
}
