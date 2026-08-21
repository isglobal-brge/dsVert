package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFormalCoxBlockwiseExchangeControllerRunsBoundStepK2K3K5(t *testing.T) {
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
			root := filepath.Join(t.TempDir(), "exchange")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			attempt := sha256.Sum256([]byte(t.Name() + "/attempt"))
			master := sha256.Sum256([]byte(t.Name() + "/master"))
			controllers := make([]*formalCoxBlockwiseExchangeController, 2)
			for index, peer := range fixture.plan.Policy.ComputePeers {
				peerRoot := filepath.Join(root, peer)
				if err := os.Mkdir(peerRoot, 0o700); err != nil {
					t.Fatal(err)
				}
				lease, err := openFormalCoxBlockwiseExchangeLease(
					peerRoot, fixture.plan, peer, attempt)
				if err != nil {
					t.Fatal(err)
				}
				controllers[index], err = newFormalCoxBlockwiseExchangeController(
					bridges[index], lease)
				if err != nil {
					_ = lease.Close()
					t.Fatal(err)
				}
				defer controllers[index].Close()
				if err := controllers[index].BindPeer(
					fixture.plan.Policy.ComputePeers[1-index]); err != nil {
					t.Fatal(err)
				}
			}
			roots := make([]string, 2)
			for index, controller := range controllers {
				roots[index], err = controller.PublicInputRoot(step)
				if err != nil {
					t.Fatal(err)
				}
			}
			pairedRoot, err := formalCoxBlockwiseMatchPublicInputRoots(
				fixture.plan, step, roots)
			if err != nil {
				t.Fatal(err)
			}
			for _, controller := range controllers {
				if err := controller.Start(step, attempt, master, pairedRoot); err != nil {
					t.Fatal(err)
				}
			}
			var leftAck, rightAck int64
			var receipts [2]formalCoxBlockwiseStepReceipt
			complete := [2]bool{}
			deadline := time.Now().Add(3 * time.Minute)
			for !complete[0] || !complete[1] {
				if time.Now().After(deadline) {
					t.Fatal("controller exchange did not complete")
				}
				for _, direction := range []struct {
					from *formalCoxBlockwiseExchangeController
					to   *formalCoxBlockwiseExchangeController
					ack  *int64
				}{
					{controllers[0], controllers[1], &leftAck},
					{controllers[1], controllers[0], &rightAck},
				} {
					chunk, _, err := direction.from.Poll(*direction.ack)
					if err != nil {
						t.Fatal(err)
					}
					if chunk != nil {
						accepted, err := direction.to.Relay(*chunk)
						if err != nil {
							t.Fatal(err)
						}
						*direction.ack = accepted
					}
				}
				for index, controller := range controllers {
					receipt, done, err := controller.Result()
					if err != nil {
						t.Fatal(err)
					}
					if done {
						receipts[index], complete[index] = receipt, true
					}
				}
				time.Sleep(time.Millisecond)
			}
			if err := formalCoxBlockwiseValidateReceiptPair(
				fixture.plan, receipts[:], fixture.pins); err != nil {
				t.Fatal(err)
			}
			for _, controller := range controllers {
				if err := controller.Commit(receipts[:], fixture.pins); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestFormalCoxBlockwiseExchangeControllerRejectsUnboundOrWrongRoots(t *testing.T) {
	fixture := newFormalCoxBlockwiseSourceBridgeTestFixture(t, 2,
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
	defer bridges[1].Close()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	attempt := sha256.Sum256([]byte(t.Name() + "/attempt"))
	lease, err := openFormalCoxBlockwiseExchangeLease(
		root, fixture.plan, fixture.plan.Policy.ComputePeers[0], attempt)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := newFormalCoxBlockwiseExchangeController(bridges[0], lease)
	if err != nil {
		_ = lease.Close()
		t.Fatal(err)
	}
	defer controller.Close()
	if _, err := controller.PublicInputRoot(step); err == nil {
		t.Fatal("unbound controller exposed a source root")
	}
	if err := controller.BindPeer(fixture.plan.Policy.ComputePeers[1]); err != nil {
		t.Fatal(err)
	}
	master := sha256.Sum256([]byte(t.Name() + "/master"))
	if err := controller.Start(step, attempt, master,
		formalCoxBlockwiseWorkerTestRoot(t.Name(), 0)); err == nil {
		t.Fatal("controller accepted an unrelated paired source root")
	}
	if _, done, err := controller.Result(); err != nil || done {
		t.Fatalf("failed preflight changed worker state: done=%v err=%v", done, err)
	}
}
