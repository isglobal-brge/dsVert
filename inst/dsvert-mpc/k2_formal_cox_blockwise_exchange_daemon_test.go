package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
	"time"
)

// This exercises the only boundary a later DataSHIELD command adapter may
// use: a live controller owns the exact-GC spool, while short-lived local
// callers can exchange authenticated, opaque frames through its private Unix
// socket.  It deliberately does not introduce a public Cox endpoint.
func TestFormalCoxBlockwiseExchangeDaemonK2K3K5(t *testing.T) {
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

			attempt := sha256.Sum256([]byte(t.Name() + "/attempt"))
			master := sha256.Sum256([]byte(t.Name() + "/master"))
			controlKey := sha256.Sum256([]byte(t.Name() + "/control"))
			controllers := make([]*formalCoxBlockwiseExchangeController, 2)
			daemons := make([]*formalCoxBlockwiseExchangeDaemonV1, 2)
			clients := make([]*formalCoxBlockwiseExchangeDaemonClientV1, 2)
			sockets := make([]string, 2)
			for index, peer := range fixture.plan.Policy.ComputePeers {
				peerRoot, err := os.MkdirTemp("/tmp", "dsvert-cox-")
				if err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(peerRoot)
				lease, err := openFormalCoxBlockwiseExchangeLease(peerRoot,
					fixture.plan, peer, attempt)
				if err != nil {
					t.Fatal(err)
				}
				controllers[index], err = newFormalCoxBlockwiseExchangeController(
					bridges[index], lease)
				if err != nil {
					_ = lease.Close()
					t.Fatal(err)
				}
				daemons[index], err = newFormalCoxBlockwiseExchangeDaemonV1(
					controllers[index], controlKey[:])
				if err != nil {
					_ = controllers[index].Close()
					t.Fatal(err)
				}
				daemon := daemons[index]
				t.Cleanup(func() { _ = daemon.Close() })
				sockets[index] = daemons[index].SocketPathV1()
				clients[index], err = newFormalCoxBlockwiseExchangeDaemonClientV1(
					daemons[index].SocketPathV1(), controlKey[:])
				if err != nil {
					t.Fatal(err)
				}
				if err := clients[index].BindPeerV1(fixture.plan.Policy.ComputePeers[1-index]); err != nil {
					t.Fatal(err)
				}
			}

			wrongKey := sha256.Sum256([]byte(t.Name() + "/wrong-control"))
			wrongClient, err := newFormalCoxBlockwiseExchangeDaemonClientV1(
				daemons[0].SocketPathV1(), wrongKey[:])
			if err != nil {
				t.Fatal(err)
			}
			if _, err := wrongClient.RootClaimV1(step, attempt); err == nil {
				t.Fatal("daemon accepted a request with the wrong local control key")
			}

			claims := make([]formalCoxBlockwiseExchangeRootClaim, 2)
			for index := range clients {
				claims[index], err = clients[index].RootClaimV1(step, attempt)
				if err != nil {
					t.Fatal(err)
				}
			}
			for index := range clients {
				if err := clients[index].StartV1(step, attempt, master, claims[1-index]); err != nil {
					t.Fatal(err)
				}
			}

			var acknowledgements [2]int64
			var receipts [2]formalCoxBlockwiseStepReceipt
			var done [2]bool
			deadline := time.Now().Add(3 * time.Minute)
			for !done[0] || !done[1] {
				if time.Now().After(deadline) {
					t.Fatal("daemon relay did not complete the bound worker step")
				}
				for _, direction := range []struct {
					from, to int
				}{
					{0, 1}, {1, 0},
				} {
					chunk, _, err := clients[direction.from].PollV1(acknowledgements[direction.from])
					if err != nil {
						t.Fatal(err)
					}
					if chunk != nil {
						accepted, err := clients[direction.to].RelayV1(*chunk)
						if err != nil {
							t.Fatal(err)
						}
						acknowledgements[direction.from] = accepted
					}
				}
				for index := range clients {
					receipt, complete, err := clients[index].ResultV1()
					if err != nil {
						t.Fatal(err)
					}
					if complete {
						receipts[index], done[index] = receipt, true
					}
				}
				time.Sleep(time.Millisecond)
			}
			if err := formalCoxBlockwiseValidateReceiptPair(fixture.plan, receipts[:], fixture.pins); err != nil {
				t.Fatal(err)
			}
			for _, client := range clients {
				if err := client.CommitV1(receipts[:], fixture.pins); err != nil {
					t.Fatal(err)
				}
			}
			for _, daemon := range daemons {
				info, err := os.Lstat(daemon.SocketPathV1())
				if err != nil || info.Mode()&os.ModeSocket == 0 ||
					info.Mode().Perm() != 0o600 {
					t.Fatalf("daemon socket is not an owner-only Unix socket: %v / %v", info, err)
				}
			}
			for index, daemon := range daemons {
				if err := daemon.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(sockets[index]); !os.IsNotExist(err) {
					t.Fatalf("daemon socket survived close: %v", err)
				}
			}
		})
	}
}
