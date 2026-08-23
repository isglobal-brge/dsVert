package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

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
			plan, _, imports := formalCoxBlockwiseWorkerBootstrapTestStage(t, custodians, root)
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
			for index := range stops {
				close(stops[index])
				if err := <-done[index]; err != nil {
					t.Fatalf("host %d close: %v", index, err)
				}
			}
		})
	}
}
