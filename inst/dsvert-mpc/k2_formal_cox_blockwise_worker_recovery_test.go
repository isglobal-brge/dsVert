package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"
)

func formalCoxBlockwiseWorkerRecoveryTestRunStep(t testing.TB,
	plan formalCoxBlockwisePlan, pins map[string]ed25519.PublicKey,
	clients []*formalCoxBlockwiseExchangeDaemonClientV1,
	step formalCoxBlockwiseWorkerStep, attempt [32]byte,
) [2]formalCoxBlockwiseStepReceipt {
	t.Helper()
	claims := make([]formalCoxBlockwiseExchangeRootClaim, len(clients))
	for index := range clients {
		claim, err := clients[index].RootClaimV1(step, attempt)
		if err != nil {
			t.Fatal(err)
		}
		claims[index] = claim
	}
	for index := range clients {
		if err := clients[index].StartV1(step, attempt, claims[1-index]); err != nil {
			t.Fatal(err)
		}
	}
	var acknowledgements [2]int64
	var receipts [2]formalCoxBlockwiseStepReceipt
	var done [2]bool
	deadline := time.Now().Add(3 * time.Minute)
	for !done[0] || !done[1] {
		if time.Now().After(deadline) {
			t.Fatal("worker recovery test relay did not complete")
		}
		for _, direction := range []struct{ from, to int }{{0, 1}, {1, 0}} {
			chunk, _, err := clients[direction.from].PollV1(
				acknowledgements[direction.from])
			if err != nil {
				t.Fatal(err)
			}
			if chunk == nil {
				continue
			}
			accepted, err := clients[direction.to].RelayV1(*chunk)
			if err != nil {
				t.Fatal(err)
			}
			acknowledgements[direction.from] = accepted
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
	if err := formalCoxBlockwiseValidateReceiptPair(plan, receipts[:], pins); err != nil {
		t.Fatal(err)
	}
	return receipts
}

func TestFormalCoxBlockwiseWorkerRecoveryCommitsSealedK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			root, err := os.MkdirTemp("/tmp", "dsvert-cox-recovery-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			plan, pins, imports := formalCoxBlockwiseWorkerBootstrapTestStage(
				t, custodians, root)
			step, err := formalCoxBlockwiseWorkerStepAt(plan, 0)
			if err != nil {
				t.Fatal(err)
			}
			attempt := sha256.Sum256([]byte(t.Name() + "/attempt"))
			encoded := make([][]byte, len(plan.Policy.ComputePeers))
			bootstraps := make([]*formalCoxBlockwiseWorkerBootstrap, len(encoded))
			clients := make([]*formalCoxBlockwiseExchangeDaemonClientV1, len(encoded))
			for index, peer := range plan.Policy.ComputePeers {
				encoded[index] = formalCoxBlockwiseWorkerBootstrapTestCommand(
					t, imports[peer], attempt)
				bootstrap, openErr := openFormalCoxBlockwiseWorkerBootstrapAtRoot(
					encoded[index], root, false)
				if openErr != nil {
					t.Fatal(openErr)
				}
				bootstraps[index], clients[index] = bootstrap, bootstrap.client
				if err := clients[index].BindPeerV1(plan.Policy.ComputePeers[1-index]); err != nil {
					t.Fatal(err)
				}
			}
			receipts := formalCoxBlockwiseWorkerRecoveryTestRunStep(
				t, plan, pins, clients, step, attempt)
			for index, bootstrap := range bootstraps {
				if err := bootstrap.Close(); err != nil {
					t.Fatal(err)
				}
				if reopened, openErr := openFormalCoxBlockwiseWorkerBootstrapAtRoot(
					encoded[index], root, false); openErr == nil {
					_ = reopened.Close()
					t.Fatal("worker bootstrap reopened a burned sealed attempt")
				}
			}

			recoveries := make([]*formalCoxBlockwiseWorkerRecovery, len(encoded))
			for index := range recoveries {
				recovery, openErr := openFormalCoxBlockwiseWorkerRecoveryAtRoot(
					encoded[index], root, false)
				if openErr != nil {
					t.Fatal(openErr)
				}
				recoveries[index] = recovery
				if public, marshalErr := json.Marshal(recovery); marshalErr != nil ||
					string(public) != "{}" {
					t.Fatalf("recovery exposed private state: %q / %v", public, marshalErr)
				}
				recovered, receiptErr := recovery.PendingReceiptV1()
				if receiptErr != nil || !reflect.DeepEqual(recovered, receipts[index]) {
					t.Fatalf("recovered receipt %d changed: %v", index, receiptErr)
				}
			}
			tampered := receipts
			tampered[1].Signature = append([]byte(nil), tampered[1].Signature...)
			tampered[1].Signature[0] ^= 1
			if err := recoveries[0].CommitV1(tampered[:]); err == nil {
				t.Fatal("recovery committed a tampered peer receipt")
			}
			for _, recovery := range recoveries {
				if err := recovery.CommitV1(receipts[:]); err != nil {
					t.Fatal(err)
				}
				if err := recovery.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if reopened, openErr := openFormalCoxBlockwiseWorkerRecoveryAtRoot(
				encoded[0], root, false); openErr == nil {
				_ = reopened.Close()
				t.Fatal("recovery reopened a committed worker step")
			}
		})
	}
}

func TestFormalCoxBlockwiseWorkerCheckpointKeySurvivesNewAttempts(t *testing.T) {
	secret := sha256.Sum256([]byte(t.Name() + "/recipient-secret"))
	plan := sha256.Sum256([]byte(t.Name() + "/plan"))
	first := sha256.Sum256([]byte(t.Name() + "/first-attempt"))
	second := sha256.Sum256([]byte(t.Name() + "/second-attempt"))
	checkpointFirst, err := formalCoxBlockwiseWorkerCheckpointKey(
		secret[:], fmt.Sprintf("%x", plan), "peer-a")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(checkpointFirst[:])
	checkpointSecond, err := formalCoxBlockwiseWorkerCheckpointKey(
		secret[:], fmt.Sprintf("%x", plan), "peer-a")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(checkpointSecond[:])
	if !bytes.Equal(checkpointFirst[:], checkpointSecond[:]) {
		t.Fatal("checkpoint key changed across worker attempts")
	}
	controlFirst, err := formalCoxBlockwiseWorkerBootstrapKey(
		secret[:], "daemon-control", fmt.Sprintf("%x", plan), "peer-a", first)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(controlFirst[:])
	controlSecond, err := formalCoxBlockwiseWorkerBootstrapKey(
		secret[:], "daemon-control", fmt.Sprintf("%x", plan), "peer-a", second)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(controlSecond[:])
	if bytes.Equal(controlFirst[:], controlSecond[:]) {
		t.Fatal("daemon-control key was reused across worker attempts")
	}
}
