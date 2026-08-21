package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func formalCoxBlockwiseExchangeTransportTestPump(
	t testing.TB, left, right *formalCoxBlockwiseExchangeTransport,
	leftAck, rightAck *int64,
) bool {
	t.Helper()
	progress := false
	for _, direction := range []struct {
		from *formalCoxBlockwiseExchangeTransport
		to   *formalCoxBlockwiseExchangeTransport
		ack  *int64
	}{
		{left, right, leftAck}, {right, left, rightAck},
	} {
		chunk, _, err := direction.from.Poll(*direction.ack)
		if err != nil {
			t.Fatal(err)
		}
		if chunk == nil {
			continue
		}
		accepted, err := direction.to.Relay(*chunk)
		if err != nil {
			t.Fatal(err)
		}
		if accepted != chunk.Offset+int64(len(chunk.Payload)) {
			t.Fatalf("relay accepted %d, want %d", accepted,
				chunk.Offset+int64(len(chunk.Payload)))
		}
		*direction.ack = accepted
		progress = true
	}
	return progress
}

func TestFormalCoxBlockwiseExchangeTransportRunsOneBoundStepK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := newFormalCoxBlockwiseSourceBridgeTestFixture(t, custodians,
				map[string]bool{"peer-a": true, "peer-b": true})
			step, err := formalCoxBlockwiseWorkerStepAt(fixture.plan, 0)
			if err != nil {
				t.Fatal(err)
			}
			formalCoxBlockwiseSourceBridgeTestStageWorkers(t, fixture, step.ScheduleIndex)
			bridges, err := formalCoxBlockwiseSourceBridgeTestOpen(t, fixture)
			if err != nil {
				t.Fatal(err)
			}
			defer formalCoxBlockwiseSourceBridgeTestClose(bridges)
			roots := make([]string, len(bridges))
			for index, bridge := range bridges {
				roots[index], err = bridge.PublicInputRoot(step)
				if err != nil {
					t.Fatal(err)
				}
			}
			pairedRoot, err := formalCoxBlockwiseMatchPublicInputRoots(
				fixture.plan, step, roots)
			if err != nil {
				t.Fatal(err)
			}
			attempt := sha256.Sum256([]byte(t.Name() + "/attempt"))
			master := sha256.Sum256([]byte(t.Name() + "/master"))
			var bound [2]formalCoxBlockwiseWorkerStep
			for index, bridge := range bridges {
				bound[index], err = bridge.BeginAttempt(step, attempt, pairedRoot)
				if err != nil {
					t.Fatal(err)
				}
			}
			session, err := formalCoxBlockwiseWorkerSession(
				fixture.plan, bound[0], attempt, master)
			if err != nil {
				t.Fatal(err)
			}
			transportRoot := filepath.Join(t.TempDir(), "exchange")
			if err := os.Mkdir(transportRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			transports := make([]*formalCoxBlockwiseExchangeTransport, 2)
			for index, peer := range fixture.plan.Policy.ComputePeers {
				root := filepath.Join(transportRoot, peer)
				if err := os.Mkdir(root, 0o700); err != nil {
					t.Fatal(err)
				}
				lease, err := openFormalCoxBlockwiseExchangeLease(
					root, fixture.plan, peer, attempt)
				if err != nil {
					t.Fatal(err)
				}
				transports[index], err = newFormalCoxBlockwiseExchangeTransport(
					lease, fixture.plan, peer)
				if err != nil {
					_ = lease.Close()
					t.Fatal(err)
				}
				if err := lease.Close(); err == nil {
					t.Fatal("live transport released its exchange lease")
				}
				if _, err := newFormalCoxBlockwiseExchangeTransport(
					lease, fixture.plan, peer); err == nil {
					t.Fatal("second transport claimed one live exchange lease")
				}
				defer transports[index].Close()
				if err := transports[index].BindPeer(
					fixture.plan.Policy.ComputePeers[1-index]); err != nil {
					t.Fatal(err)
				}
			}
			type outcome struct {
				receipt formalCoxBlockwiseStepReceipt
				err     error
			}
			leftDone := make(chan outcome, 1)
			go func() {
				receipt, runErr := bridges[0].RunPendingWorkerStep(transports[0], session)
				leftDone <- outcome{receipt: receipt, err: runErr}
			}()
			rightDone := make(chan outcome, 1)
			go func() {
				receipt, runErr := bridges[1].RunPendingWorkerStep(transports[1], session)
				rightDone <- outcome{receipt: receipt, err: runErr}
			}()
			var leftAck, rightAck int64
			deadline := time.Now().Add(3 * time.Minute)
			for leftDone != nil || rightDone != nil {
				if time.Now().After(deadline) {
					t.Fatal("segmented exchange did not complete")
				}
				_ = formalCoxBlockwiseExchangeTransportTestPump(
					t, transports[0], transports[1], &leftAck, &rightAck)
				select {
				case left := <-leftDone:
					if left.err != nil {
						t.Fatal(left.err)
					}
					leftDone = nil
					if err := bridges[0].worker.CommitPending(
						[]formalCoxBlockwiseStepReceipt{left.receipt}, fixture.pins); err == nil {
						t.Fatal("one-sided receipt commit succeeded")
					}
				case right := <-rightDone:
					if right.err != nil {
						t.Fatal(right.err)
					}
					rightDone = nil
				default:
					time.Sleep(time.Millisecond)
				}
			}
			// Reload the already-recorded receipts after both workers returned; their
			// byte-for-byte signed form is the only commit barrier accepted here.
			receipts := make([]formalCoxBlockwiseStepReceipt, 2)
			for index, bridge := range bridges {
				receipts[index], err = bridge.RunPendingWorkerStep(nil, session)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := formalCoxBlockwiseValidateReceiptPair(
				fixture.plan, receipts, fixture.pins); err != nil {
				t.Fatal(err)
			}
			for _, bridge := range bridges {
				if err := bridge.worker.CommitPending(receipts, fixture.pins); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestFormalCoxBlockwiseExchangeTransportFailsClosedBeforeBinding(t *testing.T) {
	plan, _, _ := formalCoxBlockwiseWorkerTestPlan(t, 2, 2)
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	attempt := formalCoxBlockwiseExchangeLeaseTestAttempt(t.Name())
	lease, err := openFormalCoxBlockwiseExchangeLease(
		root, plan, plan.Policy.ComputePeers[0], attempt)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := newFormalCoxBlockwiseExchangeTransport(
		lease, plan, plan.Policy.ComputePeers[0])
	if err != nil {
		_ = lease.Close()
		t.Fatal(err)
	}
	defer transport.Close()
	if _, _, err := transport.Poll(0); err == nil {
		t.Fatal("unbound exchange transport polled bytes")
	}
	if err := transport.BindPeer(plan.Policy.ComputePeers[0]); err == nil {
		t.Fatal("exchange transport accepted its own peer identity")
	}
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
	freshAttempt := formalCoxBlockwiseExchangeLeaseTestAttempt(t.Name() + "/malformed")
	freshLease, err := openFormalCoxBlockwiseExchangeLease(
		root, plan, plan.Policy.ComputePeers[0], freshAttempt)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := newFormalCoxBlockwiseExchangeTransport(
		freshLease, plan, plan.Policy.ComputePeers[0])
	if err != nil {
		_ = freshLease.Close()
		t.Fatal(err)
	}
	defer fresh.Close()
	if err := fresh.BindPeer(plan.Policy.ComputePeers[1]); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Relay(formalCoxBlockwiseExchangeChunk{
		Sender: "wrong", Offset: 0, Payload: []byte("x"),
		PayloadSHA256: "f00"}); err == nil {
		t.Fatal("exchange transport accepted a malformed peer chunk")
	}
	if err := fresh.Close(); err != nil {
		t.Fatal(err)
	}
	lockAttempt := formalCoxBlockwiseExchangeLeaseTestAttempt(t.Name() + "/lock")
	lockLease, err := openFormalCoxBlockwiseExchangeLease(
		root, plan, plan.Policy.ComputePeers[0], lockAttempt)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := newFormalCoxBlockwiseExchangeTransport(
		lockLease, plan, plan.Policy.ComputePeers[0])
	if err != nil {
		_ = lockLease.Close()
		t.Fatal(err)
	}
	defer locked.Close()
	if err := locked.BindPeer(plan.Policy.ComputePeers[1]); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(locked.rootPath, "owner.lock")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := locked.Poll(0); err == nil {
		t.Fatal("exchange transport continued after its owner lock disappeared")
	}
}
