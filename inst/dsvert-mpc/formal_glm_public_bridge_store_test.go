package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

type formalGLMPublicBridgeStoreTestFixture struct {
	pins           map[string]ed25519.PublicKey
	receipts       []formalGLMPSISourceBridgeReceiptV1
	alternate      []formalGLMPSISourceBridgeReceiptV1
	selectorSHA256 string
	artifactID     string
}

func formalGLMPublicBridgeStoreTestSetup(
	t testing.TB, custodians int,
) formalGLMPublicBridgeStoreTestFixture {
	t.Helper()
	plan, identities := formalGLMPreSourceDescriptorTestPlan(
		t, "binomial", custodians)
	context := formalGLMPreSourceDescriptorTestBuild(
		t, plan, identities,
		`{"columns":["outcome","group"],"version":"v1"}`, nil, nil)
	alternate := formalGLMPreSourceDescriptorTestBuild(
		t, plan, identities,
		`{"columns":["outcome","group"],"version":"v2"}`, nil, nil)
	return formalGLMPublicBridgeStoreTestFixture{
		pins: identities.public, receipts: context.receipts,
		alternate: alternate.receipts,
		selectorSHA256: sha256Hex([]byte(fmt.Sprintf(
			"formal-glm-public-bridge-selector-K%d", custodians))),
		artifactID: context.draft.ArtifactID,
	}
}

func formalGLMPublicBridgeStoreTestNew(
	t testing.TB, dir string, pins map[string]ed25519.PublicKey,
) *formalGLMPublicBridgeStoreV1 {
	t.Helper()
	store, err := newFormalGLMPublicBridgeStoreV1(dir, pins)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return store
}

func formalGLMPublicBridgeStoreTestPath(
	t testing.TB, store *formalGLMPublicBridgeStoreV1, selectorSHA256 string,
) string {
	t.Helper()
	relative, err := store.recordRelativePath(selectorSHA256, false)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(store.dir, relative)
}

func TestFormalGLMPublicBridgeStoreCommitLoadRestartK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMPublicBridgeStoreTestSetup(t, custodians)
			dir := filepath.Join(t.TempDir(), "rock-bridge-store")
			store := formalGLMPublicBridgeStoreTestNew(t, dir, fixture.pins)
			replayed, err := store.Commit(fixture.selectorSHA256,
				fixture.artifactID, fixture.receipts)
			if err != nil || replayed {
				t.Fatalf("first bridge commit: replay=%v err=%v", replayed, err)
			}
			record, err := store.Load(fixture.selectorSHA256)
			if err != nil || record.ArtifactID != fixture.artifactID ||
				!reflect.DeepEqual(record.Receipts, fixture.receipts) {
				t.Fatalf("bridge load differs: %+v %v", record, err)
			}
			path := formalGLMPublicBridgeStoreTestPath(
				t, store, fixture.selectorSHA256)
			encoded, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := json.Marshal(record)
			rootInfo, rootErr := os.Lstat(dir)
			recordInfo, recordErr := os.Lstat(path)
			if err != nil || !bytes.Equal(encoded, canonical) || rootErr != nil ||
				recordErr != nil || rootInfo.Mode().Perm() != 0o700 ||
				recordInfo.Mode().Perm() != 0o600 {
				t.Fatalf("bridge store is not canonical owner-only: %v %v %v",
					err, rootErr, recordErr)
			}

			store.Close()
			store = formalGLMPublicBridgeStoreTestNew(t, dir, fixture.pins)
			restarted, err := store.Load(fixture.selectorSHA256)
			if err != nil || !reflect.DeepEqual(restarted, record) {
				t.Fatalf("restart load differs: %+v %v", restarted, err)
			}
			replayed, err = store.Commit(fixture.selectorSHA256,
				fixture.artifactID, fixture.receipts)
			if err != nil || !replayed {
				t.Fatalf("exact bridge replay: replay=%v err=%v", replayed, err)
			}
			if _, err := store.Commit(fixture.selectorSHA256,
				sha256Hex([]byte("conflicting-artifact")), fixture.receipts); err == nil {
				t.Fatal("selector accepted a conflicting ArtifactID")
			}
			if _, err := store.Commit(fixture.selectorSHA256,
				fixture.artifactID, fixture.alternate); err == nil {
				t.Fatal("selector accepted a conflicting bridge set")
			}
			if after, err := store.Load(fixture.selectorSHA256); err != nil ||
				!reflect.DeepEqual(after, record) {
				t.Fatalf("CAS conflict changed durable bridge record: %+v %v", after, err)
			}
			if _, err := store.Load(sha256Hex([]byte("another-selector"))); err == nil {
				t.Fatal("Load crossed selector-owned path")
			}
		})
	}
}

func TestFormalGLMPublicBridgeStoreRejectsMalformedKSetK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMPublicBridgeStoreTestSetup(t, custodians)
			store := formalGLMPublicBridgeStoreTestNew(t,
				filepath.Join(t.TempDir(), "rock-bridge-store"), fixture.pins)
			missing := append([]formalGLMPSISourceBridgeReceiptV1(nil),
				fixture.receipts[:custodians-1]...)
			duplicate := append([]formalGLMPSISourceBridgeReceiptV1(nil),
				fixture.receipts...)
			duplicate[custodians-1] = duplicate[0]
			reordered := append([]formalGLMPSISourceBridgeReceiptV1(nil),
				fixture.receipts...)
			reordered[0], reordered[1] = reordered[1], reordered[0]
			tampered := append([]formalGLMPSISourceBridgeReceiptV1(nil),
				fixture.receipts...)
			signature := []byte(tampered[0].Signature)
			if signature[0] == 'A' {
				signature[0] = 'B'
			} else {
				signature[0] = 'A'
			}
			tampered[0].Signature = string(signature)
			for name, receipts := range map[string][]formalGLMPSISourceBridgeReceiptV1{
				"missing": missing, "duplicate": duplicate,
				"reordered": reordered, "tampered": tampered,
			} {
				t.Run(name, func(t *testing.T) {
					if _, err := store.Commit(fixture.selectorSHA256,
						fixture.artifactID, receipts); err == nil {
						t.Fatal("malformed K bridge set was committed")
					}
					if _, err := store.Load(fixture.selectorSHA256); err == nil {
						t.Fatal("failed commit created a bridge record")
					}
				})
			}
			if _, err := store.Commit("not-a-selector", fixture.artifactID,
				fixture.receipts); err == nil {
				t.Fatal("invalid selector digest was accepted")
			}
			if _, err := store.Commit(fixture.selectorSHA256, "not-an-artifact",
				fixture.receipts); err == nil {
				t.Fatal("invalid ArtifactID was accepted")
			}
			if replayed, err := store.Commit(fixture.selectorSHA256,
				fixture.artifactID, fixture.receipts); err != nil || replayed {
				t.Fatalf("valid retry after malformed set failed: %v %v", replayed, err)
			}
		})
	}
}

func TestFormalGLMPublicBridgeStoreRejectsTamperLinksAndModeK2K3K5(
	t *testing.T,
) {
	for _, custodians := range []int{2, 3, 5} {
		fixture := formalGLMPublicBridgeStoreTestSetup(t, custodians)
		for _, attack := range []string{
			"tamper", "noncanonical", "mode", "hardlink", "symlink", "parent-mode",
		} {
			t.Run(fmt.Sprintf("K%d/%s", custodians, attack), func(t *testing.T) {
				dir := filepath.Join(t.TempDir(), "rock-bridge-store")
				store := formalGLMPublicBridgeStoreTestNew(t, dir, fixture.pins)
				if _, err := store.Commit(fixture.selectorSHA256,
					fixture.artifactID, fixture.receipts); err != nil {
					t.Fatal(err)
				}
				path := formalGLMPublicBridgeStoreTestPath(
					t, store, fixture.selectorSHA256)
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
				case "noncanonical":
					encoded, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
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
				if _, err := store.Load(fixture.selectorSHA256); err == nil {
					t.Fatal("unsafe durable bridge record was accepted")
				}
			})
		}
	}

	t.Run("redirected-root", func(t *testing.T) {
		fixture := formalGLMPublicBridgeStoreTestSetup(t, 2)
		realRoot := filepath.Join(t.TempDir(), "real-rock")
		if err := os.Mkdir(realRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		linkRoot := filepath.Join(t.TempDir(), "linked-rock")
		if err := os.Symlink(realRoot, linkRoot); err != nil {
			t.Fatal(err)
		}
		if store, err := newFormalGLMPublicBridgeStoreV1(
			linkRoot, fixture.pins); err == nil {
			store.Close()
			t.Fatal("symlinked Rock root was accepted")
		}
	})
}

func TestFormalGLMPublicBridgeStoreConcurrentExactCAS(t *testing.T) {
	fixture := formalGLMPublicBridgeStoreTestSetup(t, 5)
	store := formalGLMPublicBridgeStoreTestNew(t,
		filepath.Join(t.TempDir(), "rock-bridge-store"), fixture.pins)
	const workers = 12
	type result struct {
		replayed bool
		err      error
	}
	results := make(chan result, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			replayed, err := store.Commit(fixture.selectorSHA256,
				fixture.artifactID, fixture.receipts)
			results <- result{replayed: replayed, err: err}
		}()
	}
	wait.Wait()
	close(results)
	created, replayed := 0, 0
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.replayed {
			replayed++
		} else {
			created++
		}
	}
	if created != 1 || replayed != workers-1 {
		t.Fatalf("non-exact bridge CAS: created=%d replayed=%d", created, replayed)
	}
}
