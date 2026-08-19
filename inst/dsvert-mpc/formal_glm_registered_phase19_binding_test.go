package main

import (
	"crypto/ecdh"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func formalGLMRegisteredPhase19BindingTestRoot(t testing.TB) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(resolved, "rock-registered-phase19")
}

func formalGLMRegisteredPhase19BindingTestStore(t testing.TB, root string,
	fixture formalGLMRegisteredPhase18ProvenanceTestFixtureV1,
) *formalGLMRegisteredPhase19BindingStoreV1 {
	t.Helper()
	store, err := newFormalGLMRegisteredPhase19BindingStoreV1(
		root, fixture.source.contract,
		fixture.source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func formalGLMRegisteredPhase19BindingTestRecordPath(t testing.TB,
	root string,
) string {
	t.Helper()
	var records []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry,
		err error,
	) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if info.Mode().Perm() != 0o700 {
				return fmt.Errorf("directory %s mode is %o", path,
					info.Mode().Perm())
			}
			return nil
		}
		if info.Mode().IsRegular() {
			if info.Mode().Perm() != 0o600 {
				return fmt.Errorf("record %s mode is %o", path,
					info.Mode().Perm())
			}
			records = append(records, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("found %d registered Phase19 records, want one", len(records))
	}
	return records[0]
}

func formalGLMRegisteredPhase19BindingTestOtherTickets(t testing.TB,
	fixture formalGLMRegisteredPhase18ProvenanceTestFixtureV1,
) []formalGLMRegisteredPhase18RecipientTicketV1 {
	t.Helper()
	contract := fixture.source.contract
	pins := fixture.source.inputs.identities.public
	tickets := make([]formalGLMRegisteredPhase18RecipientTicketV1, 0, 2)
	for _, recipient := range fixture.source.plan.DesignatedComputePeers {
		transportKey, err := ecdh.X25519().GenerateKey(crand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		unsigned, err := formalGLMRegisteredPhase18BuildRecipientTicketV1(
			contract, recipient, transportKey.PublicKey().Bytes(), pins)
		if err != nil {
			t.Fatal(err)
		}
		ticket, err := formalGLMRegisteredPhase18SignRecipientTicketV1(
			unsigned, contract,
			fixture.source.inputs.identities.private[recipient], pins)
		if err != nil {
			t.Fatal(err)
		}
		tickets = append(tickets, ticket)
	}
	return tickets
}

func formalGLMRegisteredPhase19BindingTestDifferentSHA(value string) string {
	if value[0] == '0' {
		return "1" + value[1:]
	}
	return "0" + value[1:]
}

func TestFormalGLMRegisteredPhase19BindingK2K5(t *testing.T) {
	for _, custodians := range []int{2, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMRegisteredPhase18ProvenanceTestBuild(
				t, custodians)
			contract := fixture.source.contract
			pins := fixture.source.inputs.identities.public
			binding, err := formalGLMBuildRegisteredPhase19BindingV1(
				contract, fixture.receiptSet, fixture.tickets, pins)
			if err != nil {
				t.Fatal(err)
			}
			contractSHA256, err := formalGLMSourceContractSHA256V1(contract)
			if err != nil {
				t.Fatal(err)
			}
			plan := fixture.source.plan
			if binding.ArtifactID != contract.Core.ArtifactID ||
				binding.SourceContractCoreSHA256 != contract.CoreSHA256 ||
				binding.SourceContractSHA256 != contractSHA256 ||
				binding.RegisteredExecutionPlanSHA256 != plan.PlanSHA256 ||
				binding.PinsetSHA256 != plan.PinsetSHA256 ||
				binding.ReceiptSetSHA256 != fixture.receiptSet.ReceiptSetSHA256 ||
				binding.GlobalMaterializationRootSHA256 !=
					fixture.receiptSet.GlobalMaterializationRootSHA256 ||
				binding.CustodianCount != custodians ||
				!reflect.DeepEqual(binding.CustodianPeers,
					plan.CustodianPeers) ||
				!reflect.DeepEqual(binding.DesignatedComputePeers,
					plan.DesignatedComputePeers) ||
				len(binding.RecipientBindings) != 2 ||
				!formalGLMIsSHA256(binding.SemanticRootSHA256) {
				t.Fatalf("incomplete registered Phase19 binding: %+v", binding)
			}
			for index, ticket := range fixture.tickets {
				ticketSHA256, hashErr :=
					formalGLMRegisteredPhase18RecipientTicketSHA256V1(ticket)
				if hashErr != nil ||
					binding.RecipientBindings[index].RecipientName !=
						ticket.RecipientName ||
					binding.RecipientBindings[index].RecipientTicketSHA256 !=
						ticketSHA256 {
					t.Fatalf("recipient binding %d differs: %v", index, hashErr)
				}
			}
			if binding.Geometry.TotalCapacity != plan.TotalCapacity ||
				binding.Geometry.BlockCapacity != plan.BlockCapacity ||
				binding.Geometry.TotalBlocks != plan.TotalBlocks ||
				binding.Geometry.CoordinateCount !=
					plan.ExecutionKernel.CoefficientCount+3 ||
				binding.Geometry.RingBits != plan.RingBits ||
				binding.Geometry.ContainerBits != plan.ContainerBits ||
				binding.Geometry.RecordBytes != exactGCRecordBytes(plan.RingBits) ||
				!reflect.DeepEqual(binding.Geometry.CoordinateOwners,
					plan.CoordinateOwners) {
				t.Fatal("registered Phase19 geometry differs from the plan")
			}
			if err := formalGLMValidateRegisteredPhase19BindingV1(
				binding, contract, fixture.receiptSet, fixture.tickets,
				pins); err != nil {
				t.Fatal(err)
			}

			reversed := []formalGLMRegisteredPhase18RecipientTicketV1{
				fixture.tickets[1], fixture.tickets[0],
			}
			reordered, err := formalGLMBuildRegisteredPhase19BindingV1(
				contract, fixture.receiptSet, reversed, pins)
			if err != nil || !reflect.DeepEqual(reordered, binding) {
				t.Fatalf("recipient ticket order changed the binding: %v", err)
			}
			rebuilt, err := formalGLMBuildRegisteredPhase19BindingV1(
				contract, fixture.receiptSet, fixture.tickets, pins)
			if err != nil || rebuilt.SemanticRootSHA256 !=
				binding.SemanticRootSHA256 {
				t.Fatalf("semantic root was not stable: %v", err)
			}
			encoded, err := json.Marshal(binding)
			if err != nil {
				t.Fatal(err)
			}
			lower := strings.ToLower(string(encoded))
			for _, forbidden := range []string{
				"capsule", "run_id", "pre_execution", "legacy", "attempt",
				"secret", `"path"`,
			} {
				if strings.Contains(lower, forbidden) {
					t.Fatalf("registered Phase19 binding contains %q", forbidden)
				}
			}
		})
	}
}

func TestFormalGLMRegisteredPhase19SemanticRootCoversEveryInput(t *testing.T) {
	fixture := formalGLMRegisteredPhase18ProvenanceTestBuild(t, 5)
	binding, err := formalGLMBuildRegisteredPhase19BindingV1(
		fixture.source.contract, fixture.receiptSet, fixture.tickets,
		fixture.source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*formalGLMRegisteredPhase19BindingV1){
		"artifact": func(value *formalGLMRegisteredPhase19BindingV1) {
			value.ArtifactID = formalGLMRegisteredPhase19BindingTestDifferentSHA(
				value.ArtifactID)
		},
		"core": func(value *formalGLMRegisteredPhase19BindingV1) {
			value.SourceContractCoreSHA256 =
				formalGLMRegisteredPhase19BindingTestDifferentSHA(
					value.SourceContractCoreSHA256)
		},
		"sealed": func(value *formalGLMRegisteredPhase19BindingV1) {
			value.SourceContractSHA256 =
				formalGLMRegisteredPhase19BindingTestDifferentSHA(
					value.SourceContractSHA256)
		},
		"plan": func(value *formalGLMRegisteredPhase19BindingV1) {
			value.RegisteredExecutionPlanSHA256 =
				formalGLMRegisteredPhase19BindingTestDifferentSHA(
					value.RegisteredExecutionPlanSHA256)
		},
		"pinset": func(value *formalGLMRegisteredPhase19BindingV1) {
			value.PinsetSHA256 = formalGLMRegisteredPhase19BindingTestDifferentSHA(
				value.PinsetSHA256)
		},
		"receipt-set": func(value *formalGLMRegisteredPhase19BindingV1) {
			value.ReceiptSetSHA256 =
				formalGLMRegisteredPhase19BindingTestDifferentSHA(
					value.ReceiptSetSHA256)
		},
		"global-root": func(value *formalGLMRegisteredPhase19BindingV1) {
			value.GlobalMaterializationRootSHA256 =
				formalGLMRegisteredPhase19BindingTestDifferentSHA(
					value.GlobalMaterializationRootSHA256)
		},
		"ticket": func(value *formalGLMRegisteredPhase19BindingV1) {
			value.RecipientBindings[0].RecipientTicketSHA256 =
				formalGLMRegisteredPhase19BindingTestDifferentSHA(
					value.RecipientBindings[0].RecipientTicketSHA256)
		},
		"custodian-count": func(value *formalGLMRegisteredPhase19BindingV1) {
			value.CustodianCount++
		},
		"custodian-peers": func(value *formalGLMRegisteredPhase19BindingV1) {
			value.CustodianPeers[0], value.CustodianPeers[1] =
				value.CustodianPeers[1], value.CustodianPeers[0]
		},
		"compute-peers": func(value *formalGLMRegisteredPhase19BindingV1) {
			value.DesignatedComputePeers[0], value.DesignatedComputePeers[1] =
				value.DesignatedComputePeers[1], value.DesignatedComputePeers[0]
		},
		"geometry": func(value *formalGLMRegisteredPhase19BindingV1) {
			value.Geometry.TotalCapacity++
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := formalGLMRegisteredPhase18ProvenanceTestClone(t, binding)
			mutate(&changed)
			root, err := formalGLMRegisteredPhase19SemanticRootV1(changed)
			if err != nil {
				t.Fatal(err)
			}
			if root == binding.SemanticRootSHA256 {
				t.Fatal("semantic root omitted a registered input")
			}
		})
	}
}

func TestFormalGLMRegisteredPhase19BindingRejectsInvalidEvidence(t *testing.T) {
	fixture := formalGLMRegisteredPhase18ProvenanceTestBuild(t, 5)
	contract := fixture.source.contract
	pins := fixture.source.inputs.identities.public

	reordered := formalGLMRegisteredPhase18ProvenanceTestClone(
		t, fixture.receiptSet)
	reordered.Receipts[0], reordered.Receipts[1] =
		reordered.Receipts[1], reordered.Receipts[0]
	if _, err := formalGLMBuildRegisteredPhase19BindingV1(
		contract, reordered, fixture.tickets, pins); err == nil {
		t.Fatal("reordered receipt set was accepted")
	}
	missingReceipt := formalGLMRegisteredPhase18ProvenanceTestClone(
		t, fixture.receiptSet)
	missingReceipt.Receipts = missingReceipt.Receipts[:len(missingReceipt.Receipts)-1]
	if _, err := formalGLMBuildRegisteredPhase19BindingV1(
		contract, missingReceipt, fixture.tickets, pins); err == nil {
		t.Fatal("incomplete receipt set was accepted")
	}
	if _, err := formalGLMBuildRegisteredPhase19BindingV1(
		contract, fixture.receiptSet, fixture.tickets[:1], pins); err == nil {
		t.Fatal("missing recipient ticket was accepted")
	}
	tamperedTicket := formalGLMRegisteredPhase18ProvenanceTestClone(
		t, fixture.tickets)
	tamperedTicket[0].Signature[0] ^= 1
	if _, err := formalGLMBuildRegisteredPhase19BindingV1(
		contract, fixture.receiptSet, tamperedTicket, pins); err == nil {
		t.Fatal("tampered recipient ticket was accepted")
	}
	wrongMode := formalGLMRegisteredPhase18ProvenanceTestClone(
		t, fixture.tickets)
	wrongMode[0].Persistent = false
	if _, err := formalGLMBuildRegisteredPhase19BindingV1(
		contract, fixture.receiptSet, wrongMode, pins); err == nil {
		t.Fatal("non-persistent recipient ticket was accepted")
	}
	opened := formalGLMRegisteredPhase18ProvenanceTestClone(
		t, fixture.receiptSet)
	opened.OpeningsPerformed = 1
	if _, err := formalGLMBuildRegisteredPhase19BindingV1(
		contract, opened, fixture.tickets, pins); err == nil {
		t.Fatal("receipt set with an opening was accepted")
	}
	other := formalGLMRegisteredPhase18ProvenanceTestBuild(t, 2)
	if _, err := formalGLMBuildRegisteredPhase19BindingV1(
		contract, other.receiptSet, fixture.tickets, pins); err == nil {
		t.Fatal("cross-contract receipt set was accepted")
	}

	binding, err := formalGLMBuildRegisteredPhase19BindingV1(
		contract, fixture.receiptSet, fixture.tickets, pins)
	if err != nil {
		t.Fatal(err)
	}
	binding.SemanticRootSHA256 =
		formalGLMRegisteredPhase19BindingTestDifferentSHA(
			binding.SemanticRootSHA256)
	if formalGLMValidateRegisteredPhase19BindingV1(
		binding, contract, fixture.receiptSet, fixture.tickets, pins) == nil {
		t.Fatal("tampered semantic root was accepted")
	}
}

func TestFormalGLMRegisteredPhase19BindingStoreRestartReplayK2K5(
	t *testing.T,
) {
	for _, custodians := range []int{2, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMRegisteredPhase18ProvenanceTestBuild(
				t, custodians)
			root := formalGLMRegisteredPhase19BindingTestRoot(t)
			store := formalGLMRegisteredPhase19BindingTestStore(
				t, root, fixture)
			record, replayed, err := store.Commit(
				fixture.receiptSet, fixture.tickets)
			if err != nil || replayed {
				t.Fatalf("first binding commit: replay=%v err=%v", replayed, err)
			}
			if !reflect.DeepEqual(record.ReceiptSet, fixture.receiptSet) ||
				!reflect.DeepEqual(record.RecipientTickets, fixture.tickets) ||
				formalGLMValidateRegisteredPhase19BindingRecordV1(
					record, fixture.source.contract,
					fixture.source.inputs.identities.public) != nil {
				t.Fatal("durable restart record lost canonical evidence")
			}
			encoded, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			lower := strings.ToLower(string(encoded))
			for _, forbidden := range []string{
				"capsule", "run_id", "pre_execution", "legacy", "attempt",
				"secret", `"path"`,
			} {
				if strings.Contains(lower, forbidden) {
					t.Fatalf("restart record contains %q", forbidden)
				}
			}
			path := formalGLMRegisteredPhase19BindingTestRecordPath(t, root)
			base := filepath.Base(path)
			if !strings.Contains(base, record.Binding.ArtifactID) ||
				!strings.Contains(base, record.Binding.ReceiptSetSHA256) {
				t.Fatal("durable key is not artifact plus receipt-set")
			}

			reversed := []formalGLMRegisteredPhase18RecipientTicketV1{
				fixture.tickets[1], fixture.tickets[0],
			}
			replay, replayed, err := store.Commit(fixture.receiptSet, reversed)
			if err != nil || !replayed || !reflect.DeepEqual(replay, record) {
				t.Fatalf("canonical replay: replay=%v equal=%v err=%v",
					replayed, reflect.DeepEqual(replay, record), err)
			}
			store.Close()

			restarted := formalGLMRegisteredPhase19BindingTestStore(
				t, root, fixture)
			loaded, err := restarted.Load(
				record.Binding.ArtifactID, record.Binding.ReceiptSetSHA256)
			if err != nil || !reflect.DeepEqual(loaded, record) {
				t.Fatalf("restart load: equal=%v err=%v",
					reflect.DeepEqual(loaded, record), err)
			}
			if _, err := restarted.Load(record.Binding.ArtifactID,
				formalGLMRegisteredPhase19BindingTestDifferentSHA(
					record.Binding.ReceiptSetSHA256)); err == nil {
				t.Fatal("another receipt-set selected the committed record")
			}
			restarted.Close()
		})
	}
}

func TestFormalGLMRegisteredPhase19BindingStoreCompoundKeyAndConflict(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase18ProvenanceTestBuild(t, 2)
	root := formalGLMRegisteredPhase19BindingTestRoot(t)
	store := formalGLMRegisteredPhase19BindingTestStore(t, root, fixture)
	defer store.Close()
	record, replayed, err := store.Commit(fixture.receiptSet, fixture.tickets)
	if err != nil || replayed {
		t.Fatalf("first binding commit: replay=%v err=%v", replayed, err)
	}

	otherReceiptSet := formalGLMRegisteredPhase19BindingTestDifferentSHA(
		record.Binding.ReceiptSetSHA256)
	store.mu.Lock()
	firstPath, firstErr := store.recordRelativePathLocked(
		record.Binding.ArtifactID, record.Binding.ReceiptSetSHA256, false)
	otherPath, otherErr := store.recordRelativePathLocked(
		record.Binding.ArtifactID, otherReceiptSet, false)
	store.mu.Unlock()
	if firstErr != nil || otherErr != nil || firstPath == otherPath {
		t.Fatalf("compound durable key collapsed: %q %q %v %v",
			firstPath, otherPath, firstErr, otherErr)
	}

	otherTickets := formalGLMRegisteredPhase19BindingTestOtherTickets(
		t, fixture)
	otherBinding, err := formalGLMBuildRegisteredPhase19BindingV1(
		fixture.source.contract, fixture.receiptSet, otherTickets,
		fixture.source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	if otherBinding.SemanticRootSHA256 == record.Binding.SemanticRootSHA256 {
		t.Fatal("different signed tickets did not change the semantic root")
	}
	if _, _, err := store.Commit(
		fixture.receiptSet, otherTickets); err == nil {
		t.Fatal("conflicting ticket set replaced a materialization binding")
	}
	loaded, err := store.Load(
		record.Binding.ArtifactID, record.Binding.ReceiptSetSHA256)
	if err != nil || !reflect.DeepEqual(loaded, record) {
		t.Fatalf("CAS conflict damaged the winner: equal=%v err=%v",
			reflect.DeepEqual(loaded, record), err)
	}
}

func TestFormalGLMRegisteredPhase19BindingStoreRejectsTamperLinksAndMode(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase18ProvenanceTestBuild(t, 2)
	for _, attack := range []string{
		"tamper", "mode", "hardlink", "symlink", "parent-mode",
	} {
		t.Run(attack, func(t *testing.T) {
			root := formalGLMRegisteredPhase19BindingTestRoot(t)
			store := formalGLMRegisteredPhase19BindingTestStore(
				t, root, fixture)
			defer store.Close()
			record, _, err := store.Commit(
				fixture.receiptSet, fixture.tickets)
			if err != nil {
				t.Fatal(err)
			}
			path := formalGLMRegisteredPhase19BindingTestRecordPath(t, root)
			switch attack {
			case "tamper":
				encoded, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				encoded[len(encoded)/2] ^= 1
				if err := os.WriteFile(path, encoded, 0o600); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".alias"); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				attacker := filepath.Join(t.TempDir(), "attacker.json")
				encoded, err := os.ReadFile(path)
				if err != nil || os.WriteFile(attacker, encoded, 0o600) != nil ||
					os.Remove(path) != nil || os.Symlink(attacker, path) != nil {
					t.Fatalf("install symlink attack: %v", err)
				}
			case "parent-mode":
				if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.Load(
				record.Binding.ArtifactID,
				record.Binding.ReceiptSetSHA256); err == nil {
				t.Fatal("unsafe durable binding record was accepted")
			}
		})
	}

	t.Run("unsafe-root-mode", func(t *testing.T) {
		root := formalGLMRegisteredPhase19BindingTestRoot(t)
		if err := os.Mkdir(root, 0o700); err != nil ||
			os.Chmod(root, 0o755) != nil {
			t.Fatal(err)
		}
		if store, err := newFormalGLMRegisteredPhase19BindingStoreV1(
			root, fixture.source.contract,
			fixture.source.inputs.identities.public); err == nil {
			store.Close()
			t.Fatal("unsafe Rock root mode was accepted")
		}
	})

	t.Run("resolved-ancestor", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "rock-with-resolved-ancestor")
		store, err := newFormalGLMRegisteredPhase19BindingStoreV1(
			root, fixture.source.contract,
			fixture.source.inputs.identities.public)
		if err != nil {
			t.Fatalf("resolved ancestor was rejected: %v", err)
		}
		store.Close()
	})

	t.Run("redirected-root", func(t *testing.T) {
		base, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		realRoot := filepath.Join(base, "real-rock")
		linkRoot := filepath.Join(base, "linked-rock")
		if os.Mkdir(realRoot, 0o700) != nil ||
			os.Symlink(realRoot, linkRoot) != nil {
			t.Fatal("could not create redirected root fixture")
		}
		if store, err := newFormalGLMRegisteredPhase19BindingStoreV1(
			linkRoot, fixture.source.contract,
			fixture.source.inputs.identities.public); err == nil {
			store.Close()
			t.Fatal("redirected Rock root was accepted")
		}
	})
}
