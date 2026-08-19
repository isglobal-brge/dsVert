package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

func formalGLMSourceContractStoreTestNew(t testing.TB,
	dir string,
	fixture formalGLMSourceContractTestFixtureV1,
) *formalGLMSourceContractStoreV1 {
	t.Helper()
	store, err := newFormalGLMSourceContractStoreV1(
		dir, fixture.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return store
}

func formalGLMSourceContractStoreTestAlternateCore(t testing.TB,
	fixture formalGLMSourceContractTestFixtureV1,
) formalGLMSourceContractCoreV1 {
	t.Helper()
	core := formalGLMSourceContractTestCloneCore(t, fixture.core)
	core.SourceBindingSet.Sources[0].SourceBindingID =
		"source_ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	var err error
	core.BridgeSetSHA256, err = formalGLMSourceBindingSetSHA256V1(
		core.SourceBindingSet, fixture.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	if err := formalGLMValidateSourceContractCoreV1(
		core, fixture.inputs.identities.public); err != nil {
		t.Fatalf("alternate core is not independently valid: %v", err)
	}
	return core
}

func formalGLMSourceContractStoreTestSeal(t testing.TB,
	fixture formalGLMSourceContractTestFixtureV1,
	core formalGLMSourceContractCoreV1,
) formalGLMSourceContractV1 {
	t.Helper()
	approvals := make([]jointDPBiomedicalGaussianSignature, 0,
		len(core.RegisteredExecutionPlan.CustodianPeers))
	for _, peer := range core.RegisteredExecutionPlan.CustodianPeers {
		approval, err := formalGLMSignSourceContractV1(
			core, peer, fixture.inputs.identities.private[peer],
			fixture.inputs.identities.public)
		if err != nil {
			t.Fatal(err)
		}
		approvals = append(approvals, approval)
	}
	contract, err := formalGLMSealSourceContractV1(
		core, approvals, fixture.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	return contract
}

func TestFormalGLMSourceContractStoreIntentBeforeSignatureK2K3K5(
	t *testing.T,
) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMSourceContractTestFixture(t, custodians)
			dir := filepath.Join(t.TempDir(), "rock-source-contract")
			store := formalGLMSourceContractStoreTestNew(t, dir, fixture)
			if _, err := store.LoadIntent(fixture.core.ArtifactID); err == nil {
				t.Fatal("intent existed before authorization")
			}
			if _, err := store.Commit(fixture.contract); err == nil {
				t.Fatal("sealed contract committed before durable intent")
			}

			approvals := make([]jointDPBiomedicalGaussianSignature, 0, custodians)
			for index, peer := range fixture.plan.CustodianPeers {
				approval, err := store.Sign(
					fixture.core, peer, fixture.inputs.identities.private[peer])
				if err != nil {
					t.Fatal(err)
				}
				intent, err := store.LoadIntent(fixture.core.ArtifactID)
				if err != nil || !reflect.DeepEqual(intent, fixture.core) {
					t.Fatalf("signature %d returned without exact durable intent: %v", index, err)
				}
				if _, err := store.Load(fixture.core.ArtifactID); err == nil {
					t.Fatal("intent was confused with sealed contract")
				}
				approvals = append(approvals, approval)
			}
			contract, err := formalGLMSealSourceContractV1(
				fixture.core, approvals, fixture.inputs.identities.public)
			if err != nil {
				t.Fatal(err)
			}
			replayed, err := store.Commit(contract)
			if err != nil || replayed {
				t.Fatalf("first source commit: replay=%v err=%v", replayed, err)
			}
			loaded, err := store.Load(fixture.core.ArtifactID)
			if err != nil || !reflect.DeepEqual(loaded, contract) {
				t.Fatalf("loaded contract differs: equal=%v err=%v",
					reflect.DeepEqual(loaded, contract), err)
			}

			intentPath, err := store.recordPath(
				fixture.core.ArtifactID, "intent", false)
			if err != nil {
				t.Fatal(err)
			}
			contractPath, err := store.recordPath(
				fixture.core.ArtifactID, "contract", false)
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{intentPath, contractPath} {
				info, err := os.Lstat(path)
				if err != nil || info.Mode().Perm() != 0o600 {
					t.Fatalf("record is not owner-only: %s %v", path, err)
				}
				encoded, err := os.ReadFile(path)
				if err != nil || len(encoded) < 64 || encoded[len(encoded)-1] == '\n' {
					t.Fatalf("record is not canonical: %s %v", path, err)
				}
			}
			rootInfo, err := os.Lstat(dir)
			if err != nil || rootInfo.Mode().Perm() != 0o700 {
				t.Fatalf("Rock root is not owner-only: %v", err)
			}
		})
	}
}

func TestFormalGLMSourceContractStoreReplayRestartAndConflictK2K3K5(
	t *testing.T,
) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMSourceContractTestFixture(t, custodians)
			dir := filepath.Join(t.TempDir(), "rock-source-contract")
			store := formalGLMSourceContractStoreTestNew(t, dir, fixture)
			firstPeer := fixture.plan.CustodianPeers[0]
			firstApproval, err := store.Sign(
				fixture.core, firstPeer,
				fixture.inputs.identities.private[firstPeer])
			if err != nil {
				t.Fatal(err)
			}
			store.Close()
			store = formalGLMSourceContractStoreTestNew(t, dir, fixture)
			intent, err := store.LoadIntent(fixture.core.ArtifactID)
			if err != nil || !reflect.DeepEqual(intent, fixture.core) {
				t.Fatalf("intent did not survive restart: equal=%v err=%v",
					reflect.DeepEqual(intent, fixture.core), err)
			}
			replayedApproval, err := store.Sign(
				fixture.core, firstPeer,
				fixture.inputs.identities.private[firstPeer])
			if err != nil || !reflect.DeepEqual(replayedApproval, firstApproval) {
				t.Fatalf("exact signature replay changed: equal=%v err=%v",
					reflect.DeepEqual(replayedApproval, firstApproval), err)
			}
			if replayed, err := store.Reserve(fixture.core); err != nil || !replayed {
				t.Fatalf("exact intent replay: replay=%v err=%v", replayed, err)
			}

			alternate := formalGLMSourceContractStoreTestAlternateCore(t, fixture)
			if _, err := store.Sign(alternate, firstPeer,
				fixture.inputs.identities.private[firstPeer]); err == nil {
				t.Fatal("divergent core obtained a signature after intent")
			}
			if _, err := store.Reserve(alternate); err == nil {
				t.Fatal("divergent core replaced intent")
			}
			afterConflict, err := store.LoadIntent(fixture.core.ArtifactID)
			if err != nil || !reflect.DeepEqual(afterConflict, fixture.core) {
				t.Fatalf("conflict altered intent: equal=%v err=%v",
					reflect.DeepEqual(afterConflict, fixture.core), err)
			}
			alternateContract := formalGLMSourceContractStoreTestSeal(
				t, fixture, alternate)
			if _, err := store.Commit(alternateContract); err == nil {
				t.Fatal("divergent sealed contract bypassed intent")
			}
			if _, err := store.Load(fixture.core.ArtifactID); err == nil {
				t.Fatal("failed conflicting commit created contract")
			}

			if replayed, err := store.Commit(fixture.contract); err != nil || replayed {
				t.Fatalf("first exact contract commit: replay=%v err=%v", replayed, err)
			}
			if replayed, err := store.Commit(fixture.contract); err != nil || !replayed {
				t.Fatalf("exact contract replay: replay=%v err=%v", replayed, err)
			}
			store.Close()
			store = formalGLMSourceContractStoreTestNew(t, dir, fixture)
			loaded, err := store.Load(fixture.core.ArtifactID)
			if err != nil || !reflect.DeepEqual(loaded, fixture.contract) {
				t.Fatalf("contract did not survive restart: equal=%v err=%v",
					reflect.DeepEqual(loaded, fixture.contract), err)
			}
		})
	}
}

func TestFormalGLMSourceContractStoreRejectsTamperLinksAndMode(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		fixture := formalGLMSourceContractTestFixture(t, custodians)
		for _, kind := range []string{"intent", "contract"} {
			for _, attack := range []string{
				"tamper", "noncanonical", "mode", "hardlink", "symlink", "parent-mode",
			} {
				t.Run(fmt.Sprintf("K%d/%s/%s", custodians, kind, attack),
					func(t *testing.T) {
						dir := filepath.Join(t.TempDir(), "rock-source-contract")
						store := formalGLMSourceContractStoreTestNew(t, dir, fixture)
						if _, err := store.Reserve(fixture.core); err != nil {
							t.Fatal(err)
						}
						if kind == "contract" {
							if _, err := store.Commit(fixture.contract); err != nil {
								t.Fatal(err)
							}
						}
						path, err := store.recordPath(
							fixture.core.ArtifactID, kind, false)
						if err != nil {
							t.Fatal(err)
						}
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
							if err != nil || os.WriteFile(
								path, append(encoded, '\n'), 0o600) != nil {
								t.Fatalf("install noncanonical record: %v", err)
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
								t.Fatalf("install symlink: %v", err)
							}
						case "parent-mode":
							if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
								t.Fatal(err)
							}
						}
						var loadErr error
						if kind == "intent" {
							_, loadErr = store.LoadIntent(fixture.core.ArtifactID)
						} else {
							_, loadErr = store.Load(fixture.core.ArtifactID)
						}
						if loadErr == nil {
							t.Fatal("unsafe source contract record was accepted")
						}
					})
			}
		}
	}

	t.Run("redirected-root", func(t *testing.T) {
		fixture := formalGLMSourceContractTestFixture(t, 2)
		realRoot := filepath.Join(t.TempDir(), "real-rock")
		if err := os.Mkdir(realRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		linkRoot := filepath.Join(t.TempDir(), "linked-rock")
		if err := os.Symlink(realRoot, linkRoot); err != nil {
			t.Fatal(err)
		}
		if store, err := newFormalGLMSourceContractStoreV1(
			linkRoot, fixture.inputs.identities.public); err == nil {
			store.Close()
			t.Fatal("symlinked Rock root was accepted")
		}
	})
}

func TestFormalGLMSourceContractStoreConcurrentExactCAS(t *testing.T) {
	fixture := formalGLMSourceContractTestFixture(t, 5)
	dir := filepath.Join(t.TempDir(), "rock-source-contract")
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
			store, err := newFormalGLMSourceContractStoreV1(
				dir, fixture.inputs.identities.public)
			if err != nil {
				results <- result{err: err}
				return
			}
			defer store.Close()
			replayed, err := store.Reserve(fixture.core)
			results <- result{replayed: replayed, err: err}
		}()
	}
	wait.Wait()
	close(results)
	created := 0
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if !result.replayed {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("exact CAS created %d intents, want 1", created)
	}
	store := formalGLMSourceContractStoreTestNew(t, dir, fixture)
	loaded, err := store.LoadIntent(fixture.core.ArtifactID)
	if err != nil || !reflect.DeepEqual(loaded, fixture.core) {
		t.Fatalf("raced intent differs: equal=%v err=%v",
			reflect.DeepEqual(loaded, fixture.core), err)
	}
	results = make(chan result, workers)
	wait = sync.WaitGroup{}
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			workerStore, err := newFormalGLMSourceContractStoreV1(
				dir, fixture.inputs.identities.public)
			if err != nil {
				results <- result{err: err}
				return
			}
			defer workerStore.Close()
			replayed, err := workerStore.Commit(fixture.contract)
			results <- result{replayed: replayed, err: err}
		}()
	}
	wait.Wait()
	close(results)
	created = 0
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if !result.replayed {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("exact CAS created %d contracts, want 1", created)
	}
	contract, err := store.Load(fixture.core.ArtifactID)
	if err != nil || !reflect.DeepEqual(contract, fixture.contract) {
		t.Fatalf("raced contract differs: equal=%v err=%v",
			reflect.DeepEqual(contract, fixture.contract), err)
	}
}

func TestFormalGLMSourceContractStoreConcurrentDivergentReserve(t *testing.T) {
	fixture := formalGLMSourceContractTestFixture(t, 5)
	alternate := formalGLMSourceContractStoreTestAlternateCore(t, fixture)
	dir := filepath.Join(t.TempDir(), "rock-source-contract")
	const workers = 12
	type result struct {
		core     formalGLMSourceContractCoreV1
		replayed bool
		err      error
	}
	results := make(chan result, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		core := fixture.core
		if index%2 == 1 {
			core = alternate
		}
		wait.Add(1)
		go func(core formalGLMSourceContractCoreV1) {
			defer wait.Done()
			store, err := newFormalGLMSourceContractStoreV1(
				dir, fixture.inputs.identities.public)
			if err != nil {
				results <- result{core: core, err: err}
				return
			}
			defer store.Close()
			replayed, err := store.Reserve(core)
			results <- result{core: core, replayed: replayed, err: err}
		}(core)
	}
	wait.Wait()
	close(results)
	created, failed := 0, 0
	for result := range results {
		if result.err != nil {
			failed++
			continue
		}
		if !result.replayed {
			created++
		}
	}
	if created != 1 || failed == 0 {
		t.Fatalf("divergent race created=%d failed=%d, want one winner and conflicts",
			created, failed)
	}
	store := formalGLMSourceContractStoreTestNew(t, dir, fixture)
	loaded, err := store.LoadIntent(fixture.core.ArtifactID)
	if err != nil || (!reflect.DeepEqual(loaded, fixture.core) &&
		!reflect.DeepEqual(loaded, alternate)) {
		t.Fatalf("divergent race corrupted intent: %+v %v", loaded, err)
	}
}

func TestFormalGLMSourceContractStoreRecordsAreCanonicalJSON(t *testing.T) {
	fixture := formalGLMSourceContractTestFixture(t, 2)
	store := formalGLMSourceContractStoreTestNew(t,
		filepath.Join(t.TempDir(), "rock-source-contract"), fixture)
	if _, err := store.Reserve(fixture.core); err != nil {
		t.Fatal(err)
	}
	path, err := store.recordPath(fixture.core.ArtifactID, "intent", false)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record formalGLMSourceContractIntentRecordV1
	if err := json.Unmarshal(encoded, &record); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(encoded, canonical) {
		t.Fatalf("intent is not canonical JSON: equal=%v err=%v",
			bytes.Equal(encoded, canonical), err)
	}
}
