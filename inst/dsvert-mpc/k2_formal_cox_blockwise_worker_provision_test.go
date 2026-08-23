package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestFormalCoxBlockwiseWorkerProvisionK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			root, err := os.MkdirTemp("/tmp", "dsvert-cox-worker-provision-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}

			plan, _, imports := formalCoxBlockwiseWorkerBootstrapTestStage(t, custodians, root)
			attempt := sha256.Sum256([]byte(t.Name() + "/attempt"))
			for _, peer := range plan.Policy.ComputePeers {
				config := formalCoxBlockwiseWorkerHostConfig{
					Version: formalCoxBlockwiseWorkerHostConfigVersion,
					Bootstrap: formalCoxBlockwiseWorkerBootstrapCommand{
						Version:   formalCoxBlockwiseWorkerBootstrapVersion,
						Source:    imports[peer],
						AttemptID: fmt.Sprintf("%x", attempt),
					},
				}
				encoded, err := json.Marshal(formalCoxBlockwiseWorkerProvisionCommand{
					Version: formalCoxBlockwiseWorkerProvisionVersion,
					Config:  config,
				})
				if err != nil {
					t.Fatal(err)
				}
				first, err := formalCoxBlockwiseWorkerProvisionRunAtRoot(encoded, root, false)
				if err != nil {
					t.Fatalf("provision %s: %v", peer, err)
				}
				if first.Version != formalCoxBlockwiseWorkerProvisionVersion ||
					first.PeerName != peer || first.AttemptID != config.Bootstrap.AttemptID ||
					!formalCoxIsSHA256(first.PlanSHA256) || first.Replayed {
					t.Fatalf("first provision %s = %+v", peer, first)
				}
				public, err := json.Marshal(first)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(public, []byte(root)) ||
					bytes.Contains(public, []byte(config.Bootstrap.Source.RecipientSigningKey)) {
					t.Fatalf("provision receipt exposed local material: %q", public)
				}
				path, err := formalCoxBlockwiseWorkerHostConfigPath(root, config)
				if err != nil {
					t.Fatal(err)
				}
				selected, err := formalCoxBlockwiseWorkerHostConfigPathForSelector(
					root, first.PeerName, first.PlanSHA256, first.AttemptID)
				if err != nil || selected != path {
					t.Fatalf("worker selector %s = %q / %v, want %q", peer, selected, err, path)
				}
				if _, err := formalCoxBlockwiseWorkerHostConfigPathForSelector(
					root, first.PeerName, first.PlanSHA256, "not-an-attempt"); err == nil {
					t.Fatal("worker selector accepted a non-canonical attempt")
				}
				if _, err := formalCoxBlockwiseWorkerHostReadConfigAtRoot(path, root, false); err != nil {
					t.Fatalf("provisioned config %s: %v", peer, err)
				}
				replayed, err := formalCoxBlockwiseWorkerProvisionRunAtRoot(encoded, root, false)
				if err != nil || !replayed.Replayed ||
					replayed.Version != first.Version || replayed.PeerName != first.PeerName ||
					replayed.PlanSHA256 != first.PlanSHA256 ||
					replayed.AttemptID != first.AttemptID {
					t.Fatalf("replayed provision %s = %+v / %v", peer, replayed, err)
				}
			}
		})
	}
}
