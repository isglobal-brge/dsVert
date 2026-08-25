package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
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

			attempt := sha256.Sum256([]byte(t.Name() + "/lease-attempt"))
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

			var incomplete formalCoxBlockwiseExchangeDaemonCompletionV1
			if err := clients[0].callV1("completion", struct{}{}, &incomplete); err != nil {
				t.Fatal(err)
			}
			if incomplete.Complete || incomplete.Completion != nil {
				t.Fatal("unstarted worker exposed a completion")
			}

			wrongKey := sha256.Sum256([]byte(t.Name() + "/wrong-control"))
			wrongClient, err := newFormalCoxBlockwiseExchangeDaemonClientV1(
				daemons[0].SocketPathV1(), wrongKey[:])
			if err != nil {
				t.Fatal(err)
			}
			if _, err := wrongClient.OfferV1(); err == nil {
				t.Fatal("daemon accepted a request with the wrong local control key")
			}

			offer, err := clients[0].OfferV1()
			if err != nil {
				t.Fatal(err)
			}
			replayedOffer, err := clients[0].OfferV1()
			if err != nil {
				t.Fatal(err)
			}
			if replayedOffer != offer {
				t.Fatal("initiator root-offer replay was not byte-identical")
			}
			if _, err := clients[1].OfferV1(); err == nil {
				t.Fatal("evaluator emitted a caller-directed root offer")
			}
			injected, err := json.Marshal(struct {
				Frame  string `json:"frame"`
				Master string `json:"master"`
			}{
				Frame: offer, Master: fmt.Sprintf("%064x", 1),
			})
			if err != nil {
				t.Fatal(err)
			}
			var malformed formalCoxBlockwiseExchangeDaemonFrameV1
			if err := formalCoxBlockwiseExchangeDaemonPayload(injected, &malformed); err == nil {
				t.Fatal("daemon accepted a caller-supplied worker master")
			}
			clear(injected)
			accept, err := clients[1].AcceptV1(offer)
			if err != nil {
				t.Fatal(err)
			}
			if err := clients[0].ConfirmV1(accept.Frame); err != nil {
				t.Fatal(err)
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
			injectedPins, err := json.Marshal(struct {
				Receipts []formalCoxBlockwiseStepReceipt `json:"receipts"`
				Pins     map[string][]byte               `json:"pins"`
			}{Receipts: receipts[:], Pins: map[string][]byte{
				"peer-a": make([]byte, 32),
			}})
			if err != nil {
				t.Fatal(err)
			}
			var injectedCommit formalCoxBlockwiseExchangeDaemonCommitV1
			if err := formalCoxBlockwiseExchangeDaemonPayload(
				injectedPins, &injectedCommit); err == nil {
				t.Fatal("daemon accepted a caller-supplied receipt pinset")
			}
			clear(injectedPins)
			for _, client := range clients {
				if err := client.CommitV1(receipts[:]); err != nil {
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

func TestFormalCoxBlockwiseExchangeDaemonCompletionIsShareFree(t *testing.T) {
	fixture := newFormalCoxBlockwiseSourceBridgeTestFixture(
		t, 2, map[string]bool{"peer-a": true, "peer-b": true})
	formalCoxBlockwiseSourceBridgeTestRunFullSchedule(t, fixture)
	bridges, err := formalCoxBlockwiseSourceBridgeTestOpen(t, fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer bridges[1].Close()

	attempt := sha256.Sum256([]byte(t.Name() + "/attempt"))
	exchangeRoot, err := os.MkdirTemp("/tmp", "dsvert-cox-completion-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(exchangeRoot)
	lease, err := openFormalCoxBlockwiseExchangeLease(
		exchangeRoot, fixture.plan, fixture.plan.Policy.ComputePeers[0], attempt)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := newFormalCoxBlockwiseExchangeController(bridges[0], lease)
	if err != nil {
		_ = lease.Close()
		t.Fatal(err)
	}
	openingKey := sha256.Sum256([]byte(t.Name() + "/opening"))
	openingRoot := t.TempDir()
	if err := os.Chmod(openingRoot, 0o700); err != nil {
		_ = controller.Close()
		t.Fatal(err)
	}
	opening, err := newFormalCoxBlockwiseOpeningStore(
		openingRoot, openingKey, fixture.plan, fixture.pins)
	if err != nil {
		_ = controller.Close()
		t.Fatal(err)
	}
	if err := controller.AttachOpeningV1(opening); err != nil {
		_ = opening.Close()
		_ = controller.Close()
		t.Fatal(err)
	}
	controlKey := sha256.Sum256([]byte(t.Name() + "/control"))
	daemon, err := newFormalCoxBlockwiseExchangeDaemonV1(controller, controlKey[:])
	if err != nil {
		_ = controller.Close()
		t.Fatal(err)
	}
	defer daemon.Close()
	client, err := newFormalCoxBlockwiseExchangeDaemonClientV1(
		daemon.SocketPathV1(), controlKey[:])
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.BindPeerV1(fixture.plan.Policy.ComputePeers[1]); err != nil {
		t.Fatal(err)
	}

	var result formalCoxBlockwiseExchangeDaemonCompletionV1
	if err := client.callV1("completion", struct{}{}, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.Completion == nil ||
		result.Completion.PlanSHA256 == "" ||
		result.Completion.ScheduleSteps != fixture.plan.ScheduleSteps ||
		result.Completion.ProductionReady {
		t.Fatalf("invalid completion response: %+v", result)
	}
	if _, err := client.OpeningV1(); err == nil {
		t.Fatal("daemon opened a result before the receipt pair committed")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	for _, forbidden := range []string{
		"coefficient_shares", "validity_share", "transport_secret", "private-v1",
	} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("completion exposed private field %q", forbidden)
		}
	}
}

func TestFormalCoxBlockwiseExchangeDaemonWireOffsetsPreserveInt64(t *testing.T) {
	const offset int64 = 9007199254740993 // 2^53 + 1
	chunk := formalCoxBlockwiseExchangeChunk{
		Sender: "peer-a", Offset: offset,
		PayloadSHA256: fmt.Sprintf("%064x", 1), Payload: []byte{1, 2, 3},
	}
	wire, err := formalCoxBlockwiseExchangeDaemonWireChunkV1FromChunk(chunk)
	if err != nil || wire.Offset != "9007199254740993" {
		t.Fatalf("wire offset lost precision: %+v / %v", wire, err)
	}
	rebuilt, err := wire.ChunkV1()
	if err != nil || rebuilt.Offset != offset || !bytes.Equal(rebuilt.Payload, chunk.Payload) {
		t.Fatalf("wire offset did not round-trip exactly: %+v / %v", rebuilt, err)
	}
	for _, invalid := range []string{"", "00", "01", "-1", "9223372036854775808"} {
		if _, err := formalCoxBlockwiseExchangeDaemonOffsetV1(invalid); err == nil {
			t.Fatalf("accepted non-canonical or out-of-range offset %q", invalid)
		}
	}
	var request formalCoxBlockwiseExchangeDaemonPollV1
	if err := formalCoxBlockwiseExchangeDaemonPayload(
		[]byte(`{"acknowledged":9007199254740993}`), &request); err == nil {
		t.Fatal("accepted a JSON-number acknowledgement above 2^53")
	}
	if err := formalCoxBlockwiseExchangeDaemonPayload(
		[]byte(`{"acknowledged":"9007199254740993"}`), &request); err != nil ||
		request.Acknowledged != "9007199254740993" {
		t.Fatalf("rejected canonical decimal acknowledgement: %+v / %v", request, err)
	}
}
