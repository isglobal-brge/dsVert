package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

func formalCoxBlockwiseWorkerHostTestControl(t testing.TB, root string,
	bootstrap formalCoxBlockwiseWorkerBootstrapCommand, action string,
	payload any, response any,
) {
	t.Helper()
	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encodedPayload)
	encoded, err := json.Marshal(formalCoxBlockwiseWorkerControlCommand{
		Version:   formalCoxBlockwiseWorkerHostControlVersion,
		Bootstrap: bootstrap, Action: action, Payload: encodedPayload,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	result, err := formalCoxBlockwiseWorkerControlRunAtRoot(encoded, root, false)
	if err != nil {
		t.Fatalf("worker control %s: %v", action, err)
	}
	if err := json.Unmarshal(result.Payload, response); err != nil {
		t.Fatalf("worker control %s response: %v", action, err)
	}
}

// This is deliberately an internal, server-local proof.  A worker host owns
// one burned exact-GC attempt; callers can only attach through the signed
// recipient bootstrap and never supply a socket, a storage path or a key.
func TestFormalCoxBlockwiseWorkerHostAttachesLiveK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			root, err := os.MkdirTemp("/tmp", "dsvert-cox-worker-host-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			plan, pins, imports := formalCoxBlockwiseWorkerBootstrapTestStage(t, custodians, root)
			attempt := sha256.Sum256([]byte(t.Name() + "/attempt"))
			configs := make([]formalCoxBlockwiseWorkerHostConfig, len(plan.Policy.ComputePeers))
			paths := make([]string, len(configs))
			stops := make([]chan struct{}, len(configs))
			ready := make([]chan struct{}, len(configs))
			done := make([]chan error, len(configs))
			for index, peer := range plan.Policy.ComputePeers {
				configs[index] = formalCoxBlockwiseWorkerHostConfig{
					Version: formalCoxBlockwiseWorkerHostConfigVersion,
					Bootstrap: formalCoxBlockwiseWorkerBootstrapCommand{
						Version: formalCoxBlockwiseWorkerBootstrapVersion,
						Source:  imports[peer], AttemptID: fmt.Sprintf("%x", attempt),
					},
				}
				var err error
				paths[index], err = formalCoxBlockwiseWorkerHostConfigPath(root, configs[index])
				if err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(formalCoxBlockwiseWorkerHostConfigDir(paths[index]), 0o700); err != nil {
					t.Fatal(err)
				}
				encoded, err := json.Marshal(configs[index])
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(paths[index], encoded, 0o600); err != nil {
					t.Fatal(err)
				}
				stops[index], ready[index], done[index] = make(chan struct{}), make(chan struct{}), make(chan error, 1)
				go func(index int) {
					done[index] <- runFormalCoxBlockwiseWorkerHostAtRoot(
						paths[index], root, false, stops[index], ready[index])
				}(index)
			}
			for index := range configs {
				select {
				case <-ready[index]:
				case err := <-done[index]:
					t.Fatalf("host %d exited before attachment: %v", index, err)
				case <-time.After(10 * time.Second):
					t.Fatalf("host %d did not become ready", index)
				}
				encoded, err := json.Marshal(formalCoxBlockwiseWorkerControlCommand{
					Version:   formalCoxBlockwiseWorkerHostControlVersion,
					Bootstrap: configs[index].Bootstrap,
					Action:    "bind",
					Payload:   json.RawMessage(fmt.Sprintf(`{"peer":%q}`, plan.Policy.ComputePeers[1-index])),
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := formalCoxBlockwiseWorkerControlRunAtRoot(encoded, root, false); err != nil {
					t.Fatalf("attach %d: %v", index, err)
				}
				if _, err := os.Lstat(paths[index]); !os.IsNotExist(err) {
					t.Fatalf("host %d retained sensitive config: %v", index, err)
				}
			}
			step, err := formalCoxBlockwiseWorkerStepAt(plan, 0)
			if err != nil {
				t.Fatal(err)
			}
			claims := make([]formalCoxBlockwiseExchangeRootClaim, len(configs))
			for index := range configs {
				formalCoxBlockwiseWorkerHostTestControl(t, root, configs[index].Bootstrap,
					"root_claim", formalCoxBlockwiseExchangeDaemonRootV1{
						Step: step, Attempt: fmt.Sprintf("%x", attempt),
					}, &claims[index])
			}
			for index := range configs {
				formalCoxBlockwiseWorkerHostTestControl(t, root, configs[index].Bootstrap,
					"start", formalCoxBlockwiseExchangeDaemonStartV1{
						Step: step, Attempt: fmt.Sprintf("%x", attempt), PeerClaim: claims[1-index],
					}, &struct{}{})
			}
			var acknowledgements [2]int64
			var receipts [2]formalCoxBlockwiseStepReceipt
			var completed [2]bool
			deadline := time.Now().Add(3 * time.Minute)
			for !completed[0] || !completed[1] {
				if time.Now().After(deadline) {
					t.Fatal("worker host relay did not complete")
				}
				for _, direction := range []struct{ from, to int }{{0, 1}, {1, 0}} {
					var poll formalCoxBlockwiseExchangeDaemonPollResultV1
					formalCoxBlockwiseWorkerHostTestControl(t, root,
						configs[direction.from].Bootstrap, "poll",
						formalCoxBlockwiseExchangeDaemonPollV1{Acknowledged: acknowledgements[direction.from]}, &poll)
					if poll.Chunk != nil {
						var relayed formalCoxBlockwiseExchangeDaemonRelayResultV1
						formalCoxBlockwiseWorkerHostTestControl(t, root,
							configs[direction.to].Bootstrap, "relay",
							formalCoxBlockwiseExchangeDaemonRelayV1{Chunk: *poll.Chunk}, &relayed)
						acknowledgements[direction.from] = relayed.Accepted
					}
				}
				for index := range configs {
					var result formalCoxBlockwiseExchangeDaemonResultV1
					formalCoxBlockwiseWorkerHostTestControl(t, root, configs[index].Bootstrap,
						"result", struct{}{}, &result)
					if result.Done {
						receipts[index], completed[index] = result.Receipt, true
					}
				}
			}
			if err := formalCoxBlockwiseValidateReceiptPair(plan, receipts[:], pins); err != nil {
				t.Fatal(err)
			}
			encodedPins := make(map[string][]byte, len(pins))
			for peer, pin := range pins {
				encodedPins[peer] = append([]byte(nil), ed25519.PublicKey(pin)...)
			}
			for index := range configs {
				formalCoxBlockwiseWorkerHostTestControl(t, root, configs[index].Bootstrap,
					"commit", formalCoxBlockwiseExchangeDaemonCommitV1{Receipts: receipts[:], Pins: encodedPins}, &struct{}{})
			}
			for peer := range encodedPins {
				clear(encodedPins[peer])
			}
			for index := range stops {
				close(stops[index])
				if err := <-done[index]; err != nil {
					t.Fatalf("host %d close: %v", index, err)
				}
			}
		})
	}
}
