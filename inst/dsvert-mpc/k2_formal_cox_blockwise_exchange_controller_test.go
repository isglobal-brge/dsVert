package main

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFormalCoxBlockwiseExchangeControllerRunsBoundStepK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := newFormalCoxBlockwiseSourceBridgeTestFixture(t, custodians,
				map[string]bool{"peer-a": true, "peer-b": true})
			bridges, err := formalCoxBlockwiseSourceBridgeTestOpen(t, fixture)
			if err != nil {
				t.Fatal(err)
			}
			attempt := sha256.Sum256([]byte(t.Name() + "/attempt"))
			step, err := formalCoxBlockwiseWorkerStepAt(fixture.plan, 0)
			if err != nil {
				t.Fatal(err)
			}
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
			bound := step
			bound.InputRoot = pairedRoot
			leftMaster, err := bridges[0].deriveWorkerMasterV1(bound, attempt)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(leftMaster[:])
			rightMaster, err := bridges[1].deriveWorkerMasterV1(bound, attempt)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(rightMaster[:])
			if !hmac.Equal(leftMaster[:], rightMaster[:]) {
				t.Fatal("compute roles derived different bound worker masters")
			}
			otherAttempt := sha256.Sum256([]byte(t.Name() + "/other-attempt"))
			otherMaster, err := bridges[0].deriveWorkerMasterV1(bound, otherAttempt)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(otherMaster[:])
			if hmac.Equal(leftMaster[:], otherMaster[:]) {
				t.Fatal("worker master was reused across attempts")
			}
			otherRoot := bound
			otherRoot.InputRoot = strings.Repeat("0", sha256.Size*2)
			rootMaster, err := bridges[0].deriveWorkerMasterV1(otherRoot, attempt)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(rootMaster[:])
			if hmac.Equal(leftMaster[:], rootMaster[:]) {
				t.Fatal("worker master was reused across authenticated input roots")
			}
			root := filepath.Join(t.TempDir(), "exchange")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
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
			var leftAck, rightAck int64
			for scheduleIndex := 0; scheduleIndex < 2; scheduleIndex++ {
				offer, offerErr := controllers[0].OfferV1()
				if offerErr != nil {
					t.Fatalf("offer step %d: %v", scheduleIndex, offerErr)
				}
				answer, acceptErr := controllers[1].AcceptOfferV1(offer)
				if acceptErr != nil {
					t.Fatalf("accept step %d: %v", scheduleIndex, acceptErr)
				}
				if err := controllers[0].ConfirmOfferV1(answer); err != nil {
					t.Fatalf("confirm step %d: %v", scheduleIndex, err)
				}

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
				if scheduleIndex == 0 {
					for _, controller := range controllers {
						for _, name := range []string{
							formalCoxBlockwiseExchangeLocalRootClaimFile,
							formalCoxBlockwiseExchangePeerRootClaimFile,
						} {
							if _, err := controller.transport.root.Lstat(name); !os.IsNotExist(err) {
								t.Fatalf("committed step retained root claim %s: %v", name, err)
							}
						}
					}
					if err := controllers[0].Commit(receipts[:], fixture.pins); err != nil {
						t.Fatalf("replay commit step %d: %v", scheduleIndex, err)
					}
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
	if err := controller.Start(step, attempt,
		formalCoxBlockwiseExchangeRootClaim{}); err == nil {
		t.Fatal("controller accepted an unsigned peer source root claim")
	}
	for _, name := range []string{
		formalCoxBlockwiseExchangeLocalRootClaimFile,
		formalCoxBlockwiseExchangePeerRootClaimFile,
	} {
		if _, err := os.Lstat(filepath.Join(controller.transport.rootPath, name)); !os.IsNotExist(err) {
			t.Fatalf("rejected peer source root claim persisted %s: %v", name, err)
		}
	}
	if _, done, err := controller.Result(); err != nil || done {
		t.Fatalf("failed preflight changed worker state: done=%v err=%v", done, err)
	}
}

func TestFormalCoxBlockwiseExchangeControllerRootClaimsK2K3K5(t *testing.T) {
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

			claims := make([]formalCoxBlockwiseExchangeRootClaim, 2)
			for index, controller := range controllers {
				claims[index], err = controller.RootClaim(step, attempt)
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := formalCoxBlockwiseExchangeMarshalRootClaim(claims[index])
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := formalCoxBlockwiseExchangeDecodeRootClaim(encoded)
				if err != nil || !reflect.DeepEqual(decoded, claims[index]) {
					t.Fatalf("root claim did not round-trip canonically: %v", err)
				}
				claims[index] = decoded
			}
			for index, controller := range controllers {
				root, err := controller.ValidatePeerRootClaim(
					step, attempt, claims[1-index])
				if err != nil || root != claims[index].InputRootSHA256 {
					t.Fatalf("peer root claim was not accepted: root=%q err=%v", root, err)
				}
			}
			wrongRoot := claims[1]
			wrongRoot.InputRootSHA256 = formalCoxBlockwiseWorkerTestRoot(
				t.Name()+"/wrong-root", step.ScheduleIndex)
			message, err := formalCoxBlockwiseExchangeRootClaimUnsigned(wrongRoot)
			if err != nil {
				t.Fatal(err)
			}
			wrongRoot.Signature = ed25519.Sign(
				fixture.signing[fixture.plan.Policy.ComputePeers[1]], message)
			clear(message)
			if _, err := controllers[0].ValidatePeerRootClaim(step, attempt, wrongRoot); err == nil {
				t.Fatal("signed mismatched peer root claim was accepted")
			}

			for _, mutate := range []func(*formalCoxBlockwiseExchangeRootClaim){
				func(claim *formalCoxBlockwiseExchangeRootClaim) {
					claim.AttemptID = "00" + claim.AttemptID[2:]
				},
				func(claim *formalCoxBlockwiseExchangeRootClaim) { claim.InputRootSHA256 = "" },
				func(claim *formalCoxBlockwiseExchangeRootClaim) { claim.SenderPeerID = "dsv1_bad" },
				func(claim *formalCoxBlockwiseExchangeRootClaim) { claim.Signature[0] ^= 1 },
			} {
				mutated := claims[1]
				mutated.Signature = append([]byte(nil), mutated.Signature...)
				mutate(&mutated)
				if _, err := controllers[0].ValidatePeerRootClaim(step, attempt, mutated); err == nil {
					t.Fatal("tampered peer root claim was accepted")
				}
				if _, done, err := controllers[0].Result(); err != nil || done {
					t.Fatalf("rejected root claim changed controller state: done=%v err=%v", done, err)
				}
			}
		})
	}
}

func TestFormalCoxBlockwiseExchangeControllerPersistsPeerRootClaimK2K3K5(t *testing.T) {
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
			controllers := make([]*formalCoxBlockwiseExchangeController, 2)
			claims := make([]formalCoxBlockwiseExchangeRootClaim, 2)
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
				claims[index], err = controllers[index].RootClaim(step, attempt)
				if err != nil {
					t.Fatal(err)
				}
			}
			for index, controller := range controllers {
				if err := controller.Start(step, attempt, claims[1-index]); err != nil {
					t.Fatal(err)
				}
				for _, want := range []struct {
					name  string
					claim formalCoxBlockwiseExchangeRootClaim
				}{
					{formalCoxBlockwiseExchangePeerRootClaimFile, claims[1-index]},
					{formalCoxBlockwiseExchangeLocalRootClaimFile, claims[index]},
				} {
					encoded, err := os.ReadFile(filepath.Join(
						controller.transport.rootPath, want.name))
					if err != nil {
						t.Fatalf("%s was not persisted: %v", want.name, err)
					}
					info, err := os.Lstat(filepath.Join(
						controller.transport.rootPath, want.name))
					if err != nil || !info.Mode().IsRegular() ||
						info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
						!exactGCPrivateOwnedRegular(info) {
						t.Fatalf("persisted %s is not a private regular record", want.name)
					}
					stored, err := formalCoxBlockwiseExchangeDecodeRootClaim(encoded)
					if err != nil || !reflect.DeepEqual(stored, want.claim) {
						t.Fatalf("persisted %s changed: %v", want.name, err)
					}
				}
			}
		})
	}
}
