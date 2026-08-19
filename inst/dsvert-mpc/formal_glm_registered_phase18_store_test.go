package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func formalGLMRegisteredPhase18StoreTestRoot(t testing.TB) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(resolved, "rock-registered-phase18")
}

func formalGLMRegisteredPhase18StoreTestNew(t testing.TB, root string,
	fixture formalGLMRegisteredPhase18IngressTestFixtureV3,
) *formalGLMRegisteredPhase18IngressStoreV3 {
	t.Helper()
	store, err := newFormalGLMRegisteredPhase18IngressStoreV3(
		root, fixture.frame.Recipient, fixture.localKey,
		fixture.source.contract, fixture.frame.GlobalMaterializationRoot,
		fixture.source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return store
}

func formalGLMRegisteredPhase18StoreTestRecord(t testing.TB,
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
		t.Fatalf("found %d durable ingress records, want one", len(records))
	}
	return records[0]
}

func TestFormalGLMRegisteredPhase18IngressStoreCommitLoadRestartK2K5(
	t *testing.T,
) {
	for _, custodians := range []int{2, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMRegisteredPhase18IngressTestBuild(t, custodians)
			if fixture.frame.GlobalSlotOffset != 8 ||
				fixture.frame.SlotsInBlock != 4 ||
				fixture.authorization.Geometry.TotalCapacity != 9 {
				t.Fatal("fixture is not the fixed padded final block")
			}
			if custodians == 5 && len(fixture.authorization.LocalColumns) != 0 {
				t.Fatal("K5 fixture is not the alignment-only witness")
			}
			root := formalGLMRegisteredPhase18StoreTestRoot(t)
			store := formalGLMRegisteredPhase18StoreTestNew(t, root, fixture)
			receipt, replayed, err := store.Commit(
				fixture.encoded, fixture.authorization)
			if err != nil || replayed {
				t.Fatalf("first commit: replay=%v err=%v", replayed, err)
			}
			if receipt.ArtifactID != fixture.frame.ArtifactID ||
				receipt.AuthorizationSHA256 !=
					fixture.authorization.AuthorizationSHA256 ||
				receipt.Source != fixture.frame.Source ||
				receipt.Recipient != fixture.frame.Recipient ||
				receipt.BlockIndex != fixture.frame.BlockIndex ||
				receipt.GlobalMaterializationRoot !=
					fixture.frame.GlobalMaterializationRoot ||
				!formalGLMIsSHA256(receipt.Handle) ||
				!formalGLMIsSHA256(receipt.FrameSHA256) ||
				receipt.ProductionReady {
				t.Fatalf("incomplete safe store receipt: %+v", receipt)
			}
			replayedReceipt, replayed, err := store.Commit(
				fixture.encoded, fixture.authorization)
			if err != nil || !replayed ||
				!reflect.DeepEqual(replayedReceipt, receipt) {
				t.Fatalf("exact replay differs: equal=%v replay=%v err=%v",
					reflect.DeepEqual(replayedReceipt, receipt), replayed, err)
			}
			loaded, err := store.Load(
				fixture.authorization, fixture.frame.BlockIndex)
			if err != nil || !reflect.DeepEqual(loaded, receipt) {
				t.Fatalf("load differs: equal=%v err=%v",
					reflect.DeepEqual(loaded, receipt), err)
			}

			recordPath := formalGLMRegisteredPhase18StoreTestRecord(t, root)
			persisted, err := os.ReadFile(recordPath)
			if err != nil || !bytes.Equal(persisted, fixture.encoded) {
				t.Fatalf("durable frame is not byte-exact: %v", err)
			}
			if bytes.Contains(persisted, fixture.plaintext) ||
				bytes.Contains(persisted,
					[]byte(formalGLMRegisteredPhase18PrivateBlockPurposeV3)) {
				t.Fatal("store persisted an unprotected private block/header")
			}

			store.Close()
			store = formalGLMRegisteredPhase18StoreTestNew(t, root, fixture)
			restarted, err := store.Load(
				fixture.authorization, fixture.frame.BlockIndex)
			if err != nil || !reflect.DeepEqual(restarted, receipt) {
				t.Fatalf("restart load differs: equal=%v err=%v",
					reflect.DeepEqual(restarted, receipt), err)
			}
			if custodians == 2 {
				store.Close()
				wrongKey := sha256.Sum256([]byte("wrong private ingress MAC key"))
				wrongStore, err := newFormalGLMRegisteredPhase18IngressStoreV3(
					root, fixture.frame.Recipient, wrongKey,
					fixture.source.contract,
					fixture.frame.GlobalMaterializationRoot,
					fixture.source.inputs.identities.public)
				if err != nil {
					t.Fatal(err)
				}
				defer wrongStore.Close()
				if _, err := wrongStore.Load(
					fixture.authorization, fixture.frame.BlockIndex); err == nil {
					t.Fatal("record authenticated under another private MAC key")
				}
			}
		})
	}

	for _, field := range reflect.VisibleFields(
		reflect.TypeOf(formalGLMRegisteredPhase18IngressStoreReceiptV3{})) {
		lower := strings.ToLower(field.Name)
		for _, forbidden := range []string{"path", "payload", "ciphertext", "encoded"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("store receipt exposes %q", field.Name)
			}
		}
	}
}

func TestFormalGLMRegisteredPhase18IngressStoreCASAndRouteConflicts(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase18IngressTestBuild(t, 2)
	root := formalGLMRegisteredPhase18StoreTestRoot(t)
	store := formalGLMRegisteredPhase18StoreTestNew(t, root, fixture)
	want, replayed, err := store.Commit(fixture.encoded, fixture.authorization)
	if err != nil || replayed {
		t.Fatalf("first commit: replay=%v err=%v", replayed, err)
	}

	conflict := fixture.frame
	conflict.Ciphertext = append([]byte(nil), fixture.frame.Ciphertext...)
	conflict.EnvelopeSHA256 = sha256Hex([]byte("different valid envelope"))
	conflictEncoded, err := formalGLMRegisteredPhase18EncodeIngressFrameV3(
		conflict, fixture.source.contract, fixture.authorization,
		fixture.frame.GlobalMaterializationRoot,
		fixture.source.inputs.identities.public, fixture.localKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Commit(
		conflictEncoded, fixture.authorization); err == nil {
		t.Fatal("different canonical bytes replaced a durable slot")
	}
	loaded, err := store.Load(fixture.authorization, fixture.frame.BlockIndex)
	if err != nil || !reflect.DeepEqual(loaded, want) {
		t.Fatalf("conflict changed durable frame: equal=%v err=%v",
			reflect.DeepEqual(loaded, want), err)
	}

	crossRecipient := fixture.frame
	crossRecipient.Ciphertext = append([]byte(nil), fixture.frame.Ciphertext...)
	crossRecipient.Recipient = fixture.authorization.DesignatedComputePeers[1]
	crossRecipient.RecipientSlot = 1
	crossRecipient.RecipientTicketSHA256 = sha256Hex([]byte("other recipient ticket"))
	crossRecipientEncoded, err := formalGLMRegisteredPhase18EncodeIngressFrameV3(
		crossRecipient, fixture.source.contract, fixture.authorization,
		fixture.frame.GlobalMaterializationRoot,
		fixture.source.inputs.identities.public, fixture.localKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Commit(
		crossRecipientEncoded, fixture.authorization); err == nil {
		t.Fatal("frame entered another recipient's local store")
	}

	otherRoot := sha256Hex([]byte("different global materialization root"))
	crossRoot := fixture.frame
	crossRoot.Ciphertext = append([]byte(nil), fixture.frame.Ciphertext...)
	crossRoot.GlobalMaterializationRoot = otherRoot
	crossRootEncoded, err := formalGLMRegisteredPhase18EncodeIngressFrameV3(
		crossRoot, fixture.source.contract, fixture.authorization, otherRoot,
		fixture.source.inputs.identities.public, fixture.localKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Commit(
		crossRootEncoded, fixture.authorization); err == nil {
		t.Fatal("frame entered a store bound to another global root")
	}

	other := formalGLMRegisteredPhase18IngressTestBuild(t, 5)
	otherEncoded, err := formalGLMRegisteredPhase18EncodeIngressFrameV3(
		other.frame, other.source.contract, other.authorization,
		other.frame.GlobalMaterializationRoot,
		other.source.inputs.identities.public, fixture.localKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Commit(otherEncoded, other.authorization); err == nil {
		t.Fatal("cross-artifact frame entered the store")
	}
	if _, err := store.Load(other.authorization, other.frame.BlockIndex); err == nil {
		t.Fatal("cross-artifact authorization selected a local record")
	}
}

func TestFormalGLMRegisteredPhase18IngressStoreRejectsTamperLinksAndMode(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase18IngressTestBuild(t, 2)
	for _, attack := range []string{
		"tamper", "mode", "hardlink", "symlink", "parent-mode",
	} {
		t.Run(attack, func(t *testing.T) {
			root := formalGLMRegisteredPhase18StoreTestRoot(t)
			store := formalGLMRegisteredPhase18StoreTestNew(t, root, fixture)
			if _, _, err := store.Commit(
				fixture.encoded, fixture.authorization); err != nil {
				t.Fatal(err)
			}
			recordPath := formalGLMRegisteredPhase18StoreTestRecord(t, root)
			switch attack {
			case "tamper":
				encoded, err := os.ReadFile(recordPath)
				if err != nil {
					t.Fatal(err)
				}
				encoded[len(encoded)/2] ^= 1
				if err := os.WriteFile(recordPath, encoded, 0o600); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(recordPath, 0o644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(recordPath, recordPath+".alias"); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				attacker := filepath.Join(t.TempDir(), "attacker.bin")
				encoded, err := os.ReadFile(recordPath)
				if err != nil || os.WriteFile(attacker, encoded, 0o600) != nil ||
					os.Remove(recordPath) != nil ||
					os.Symlink(attacker, recordPath) != nil {
					t.Fatalf("install symlink attack: %v", err)
				}
			case "parent-mode":
				if err := os.Chmod(filepath.Dir(recordPath), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.Load(
				fixture.authorization, fixture.frame.BlockIndex); err == nil {
				t.Fatal("unsafe durable ingress record was accepted")
			}
		})
	}

	t.Run("unsafe-root-mode", func(t *testing.T) {
		root := formalGLMRegisteredPhase18StoreTestRoot(t)
		if err := os.Mkdir(root, 0o700); err != nil ||
			os.Chmod(root, 0o755) != nil {
			t.Fatal(err)
		}
		if store, err := newFormalGLMRegisteredPhase18IngressStoreV3(
			root, fixture.frame.Recipient, fixture.localKey,
			fixture.source.contract, fixture.frame.GlobalMaterializationRoot,
			fixture.source.inputs.identities.public); err == nil {
			store.Close()
			t.Fatal("unsafe Rock root mode was accepted")
		}
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
		if store, err := newFormalGLMRegisteredPhase18IngressStoreV3(
			linkRoot, fixture.frame.Recipient, fixture.localKey,
			fixture.source.contract, fixture.frame.GlobalMaterializationRoot,
			fixture.source.inputs.identities.public); err == nil {
			store.Close()
			t.Fatal("redirected Rock root was accepted")
		}
	})

	if store, err := newFormalGLMRegisteredPhase18IngressStoreV3(
		formalGLMRegisteredPhase18StoreTestRoot(t), fixture.frame.Recipient,
		fixture.localKey, fixture.source.contract, "",
		fixture.source.inputs.identities.public); err == nil {
		store.Close()
		t.Fatal("missing expected global root was accepted")
	}
}
