package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// formalCoxBlockwiseWorkerBootstrapTestStage imports all custodian envelopes
// before opening either worker.  It uses the closed producer/delivery/import
// commands rather than an in-memory source fixture, so this test exercises
// the intended Rock-local bootstrap boundary end to end.
func formalCoxBlockwiseWorkerBootstrapTestStage(t testing.TB, custodians int,
	root string,
) (formalCoxBlockwisePlan, map[string]ed25519.PublicKey,
	map[string]formalCoxBlockwiseSourceImportCommand) {
	t.Helper()
	source, session, signers := formalCoxBlockwiseSourceImportCommandTestSource(
		t, custodians, root)
	imports := make(map[string]formalCoxBlockwiseSourceImportCommand, 2)
	for _, sourcePeer := range session.context.plan.Policy.CustodianPeers {
		producer := source
		producer.SourcePeerName = sourcePeer
		producer.SourceSigningKey = base64.StdEncoding.EncodeToString(signers[sourcePeer])
		formalCoxBlockwiseSourceProducerCommandTestRun(t, producer, root)
		for _, recipient := range session.context.plan.Policy.ComputePeers {
			deliveryCommand := formalCoxBlockwiseSourceDeliveryCommandTestRequest(
				t, producer, recipient)
			deliveryJSON, err := json.Marshal(deliveryCommand)
			if err != nil {
				t.Fatal(err)
			}
			delivery, err := formalCoxBlockwiseSourceDeliveryRunAtRoot(
				deliveryJSON, root, false)
			if err != nil {
				t.Fatal(err)
			}
			command := formalCoxBlockwiseSourceImportCommandTestRequest(
				t, producer, delivery, recipient, signers[recipient])
			commandJSON, err := json.Marshal(command)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := formalCoxBlockwiseSourceImportRunAtRoot(
				commandJSON, root, false); err != nil {
				t.Fatal(err)
			}
			imports[recipient] = command
		}
	}
	return session.context.plan, session.context.pins, imports
}

func formalCoxBlockwiseWorkerBootstrapTestCommand(t testing.TB,
	source formalCoxBlockwiseSourceImportCommand, attempt [32]byte,
) []byte {
	t.Helper()
	encoded, err := json.Marshal(formalCoxBlockwiseWorkerBootstrapCommand{
		Version: formalCoxBlockwiseWorkerBootstrapVersion,
		Source:  source, AttemptID: hex.EncodeToString(attempt[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestFormalCoxBlockwiseWorkerBootstrapK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			root, err := os.MkdirTemp("/tmp", "dsvert-cox-bootstrap-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			plan, pins, imports := formalCoxBlockwiseWorkerBootstrapTestStage(
				t, custodians, root)
			attempt := sha256.Sum256([]byte(t.Name() + "/attempt"))
			step, err := formalCoxBlockwiseWorkerStepAt(plan, 0)
			if err != nil {
				t.Fatal(err)
			}

			encoded := make([][]byte, len(plan.Policy.ComputePeers))
			for index, peer := range plan.Policy.ComputePeers {
				encoded[index] = formalCoxBlockwiseWorkerBootstrapTestCommand(
					t, imports[peer], attempt)
			}
			invalid := append([]byte(nil), encoded[0][:len(encoded[0])-1]...)
			invalid = append(invalid, []byte(`,"path":"/not-a-worker-path"}`)...)
			if _, err := openFormalCoxBlockwiseWorkerBootstrapAtRoot(invalid, root, false); err == nil {
				t.Fatal("worker bootstrap accepted a caller-selected path")
			}
			if _, err := os.Lstat(filepath.Join(root,
				formalCoxBlockwiseWorkerBootstrapDir)); !os.IsNotExist(err) {
				t.Fatalf("invalid bootstrap created worker state: %v", err)
			}

			bootstraps := make([]*formalCoxBlockwiseWorkerBootstrap, 2)
			attachments := make([]*formalCoxBlockwiseWorkerBootstrapAttachment, 2)
			clients := make([]*formalCoxBlockwiseExchangeDaemonClientV1, 2)
			sockets := make([]string, 2)
			for index, peer := range plan.Policy.ComputePeers {
				bootstraps[index], err = openFormalCoxBlockwiseWorkerBootstrapAtRoot(
					encoded[index], root, false)
				if err != nil {
					t.Fatal(err)
				}
				clients[index] = bootstraps[index].client
				sockets[index] = bootstraps[index].daemon.SocketPathV1()
				if err := clients[index].BindPeerV1(plan.Policy.ComputePeers[1-index]); err != nil {
					t.Fatal(err)
				}
				if public, marshalErr := json.Marshal(bootstraps[index]); marshalErr != nil ||
					string(public) != "{}" {
					t.Fatalf("bootstrap exposed private state for %s: %q / %v", peer, public, marshalErr)
				}
				attachments[index], err = openFormalCoxBlockwiseWorkerBootstrapAttachmentAtRoot(
					encoded[index], root, false)
				if err != nil {
					t.Fatalf("attach live worker for %s: %v", peer, err)
				}
				if public, marshalErr := json.Marshal(attachments[index]); marshalErr != nil ||
					string(public) != "{}" {
					t.Fatalf("attachment exposed private state for %s: %q / %v", peer, public, marshalErr)
				}
				wrongAttempt := sha256.Sum256([]byte(t.Name() + "/wrong-attachment"))
				wrongCommand := formalCoxBlockwiseWorkerBootstrapTestCommand(
					t, imports[peer], wrongAttempt)
				if attached, attachErr := openFormalCoxBlockwiseWorkerBootstrapAttachmentAtRoot(
					wrongCommand, root, false); attachErr == nil {
					_ = attached.Close()
					t.Fatal("worker attachment accepted a different attempt")
				}
				clients[index] = attachments[index].client
			}

			claims := make([]formalCoxBlockwiseExchangeRootClaim, 2)
			for index := range clients {
				claims[index], err = clients[index].RootClaimV1(step, attempt)
				if err != nil {
					t.Fatal(err)
				}
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
					t.Fatal("bootstrapped worker relay did not complete")
				}
				for _, direction := range []struct{ from, to int }{{0, 1}, {1, 0}} {
					chunk, _, pollErr := clients[direction.from].PollV1(
						acknowledgements[direction.from])
					if pollErr != nil {
						t.Fatal(pollErr)
					}
					if chunk != nil {
						accepted, relayErr := clients[direction.to].RelayV1(*chunk)
						if relayErr != nil {
							t.Fatal(relayErr)
						}
						acknowledgements[direction.from] = accepted
					}
				}
				for index := range clients {
					receipt, complete, resultErr := clients[index].ResultV1()
					if resultErr != nil {
						t.Fatal(resultErr)
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
			for _, client := range clients {
				if err := client.CommitV1(receipts[:], pins); err != nil {
					t.Fatal(err)
				}
			}
			for index, bootstrap := range bootstraps {
				if err := attachments[index].Close(); err != nil {
					t.Fatal(err)
				}
				if err := bootstrap.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(sockets[index]); !os.IsNotExist(err) {
					t.Fatalf("worker daemon socket survived close: %v", err)
				}
			}
			if attached, attachErr := openFormalCoxBlockwiseWorkerBootstrapAttachmentAtRoot(
				encoded[0], root, false); attachErr == nil {
				attached.Close()
				t.Fatal("worker attachment reopened a closed daemon")
			}
			if reopened, reopenErr := openFormalCoxBlockwiseWorkerBootstrapAtRoot(
				encoded[0], root, false); reopenErr == nil {
				_ = reopened.Close()
				t.Fatal("worker bootstrap reopened a burned exact-GC attempt")
			}
		})
	}
}
