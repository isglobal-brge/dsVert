package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type formalGLMRegisteredPhase18TicketStoreTestFixtureV1 struct {
	source  formalGLMSourceContractTestFixtureV1
	tickets []formalGLMRegisteredPhase18RecipientTicketV1
}

var formalGLMRegisteredPhase18TicketStoreTestFixturesV1 struct {
	sync.Mutex
	byCustodians map[int]formalGLMRegisteredPhase18TicketStoreTestFixtureV1
}

func formalGLMRegisteredPhase18TicketStoreTestBuild(t testing.TB,
	custodians int,
) formalGLMRegisteredPhase18TicketStoreTestFixtureV1 {
	t.Helper()
	formalGLMRegisteredPhase18TicketStoreTestFixturesV1.Lock()
	defer formalGLMRegisteredPhase18TicketStoreTestFixturesV1.Unlock()
	if fixture, ok := formalGLMRegisteredPhase18TicketStoreTestFixturesV1.byCustodians[custodians]; ok {
		return fixture
	}
	source := formalGLMRegisteredPhase18IngressTestSource(t, custodians)
	tickets := make([]formalGLMRegisteredPhase18RecipientTicketV1, 0, 2)
	for _, recipient := range source.plan.DesignatedComputePeers {
		transportKey, err := ecdh.X25519().GenerateKey(crand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		unsigned, err := formalGLMRegisteredPhase18BuildRecipientTicketV1(
			source.contract, recipient, transportKey.PublicKey().Bytes(),
			source.inputs.identities.public)
		if err != nil {
			t.Fatal(err)
		}
		ticket, err := formalGLMRegisteredPhase18SignRecipientTicketV1(
			unsigned, source.contract,
			source.inputs.identities.private[recipient],
			source.inputs.identities.public)
		if err != nil {
			t.Fatal(err)
		}
		tickets = append(tickets, ticket)
	}
	fixture := formalGLMRegisteredPhase18TicketStoreTestFixtureV1{
		source: source, tickets: tickets,
	}
	if formalGLMRegisteredPhase18TicketStoreTestFixturesV1.byCustodians == nil {
		formalGLMRegisteredPhase18TicketStoreTestFixturesV1.byCustodians =
			make(map[int]formalGLMRegisteredPhase18TicketStoreTestFixtureV1, 2)
	}
	formalGLMRegisteredPhase18TicketStoreTestFixturesV1.byCustodians[custodians] = fixture
	return fixture
}

func formalGLMRegisteredPhase18TicketStoreTestRoot(t testing.TB) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "rock")
}

func formalGLMRegisteredPhase18TicketStoreTestOpen(t testing.TB, root string,
	fixture formalGLMRegisteredPhase18TicketStoreTestFixtureV1,
) *formalGLMRegisteredPhase18RecipientTicketStoreV1 {
	t.Helper()
	store, err := newFormalGLMRegisteredPhase18RecipientTicketStoreV1(
		root, fixture.source.contract, fixture.source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return store
}

func formalGLMRegisteredPhase18TicketStoreTestRekey(t testing.TB,
	fixture formalGLMRegisteredPhase18TicketStoreTestFixtureV1,
	index int,
) formalGLMRegisteredPhase18RecipientTicketV1 {
	t.Helper()
	recipient := fixture.source.plan.DesignatedComputePeers[index]
	transportKey, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := formalGLMRegisteredPhase18BuildRecipientTicketV1(
		fixture.source.contract, recipient, transportKey.PublicKey().Bytes(),
		fixture.source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := formalGLMRegisteredPhase18SignRecipientTicketV1(
		unsigned, fixture.source.contract,
		fixture.source.inputs.identities.private[recipient],
		fixture.source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	return ticket
}

func formalGLMRegisteredPhase18TicketStoreTestResign(t testing.TB,
	fixture formalGLMRegisteredPhase18TicketStoreTestFixtureV1,
	ticket formalGLMRegisteredPhase18RecipientTicketV1,
	signer string,
) formalGLMRegisteredPhase18RecipientTicketV1 {
	t.Helper()
	ticket.Signature = nil
	message, err := formalGLMRegisteredPhase18SignatureMessageV1(
		formalGLMRegisteredPhase18RecipientTicketDomain, ticket)
	if err != nil {
		t.Fatal(err)
	}
	ticket.Signature = ed25519.Sign(
		fixture.source.inputs.identities.private[signer], message)
	return ticket
}

func formalGLMRegisteredPhase18TicketStoreTestRecordPath(t testing.TB,
	root string,
	fixture formalGLMRegisteredPhase18TicketStoreTestFixtureV1,
	recipientIndex int,
) string {
	t.Helper()
	artifactID := fixture.source.contract.Core.ArtifactID
	return filepath.Join(root,
		formalGLMRegisteredPhase18RecipientTicketRecordDirV1,
		artifactID[:2], artifactID[2:4], artifactID,
		fmt.Sprintf("ticket-recipient-%d.json", recipientIndex))
}

func formalGLMRegisteredPhase18TicketStoreTestCommitSet(t testing.TB,
	store *formalGLMRegisteredPhase18RecipientTicketStoreV1,
	fixture formalGLMRegisteredPhase18TicketStoreTestFixtureV1,
) {
	t.Helper()
	for index := len(fixture.tickets) - 1; index >= 0; index-- {
		if _, replayed, err := store.Commit(fixture.tickets[index]); err != nil || replayed {
			t.Fatalf("ticket %d initial commit: replay=%v err=%v",
				index, replayed, err)
		}
	}
}

func TestFormalGLMRegisteredPhase18RecipientTicketStoreK2K5RestartReplay(
	t *testing.T,
) {
	for _, custodians := range []int{2, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMRegisteredPhase18TicketStoreTestBuild(t, custodians)
			root := formalGLMRegisteredPhase18TicketStoreTestRoot(t)
			store := formalGLMRegisteredPhase18TicketStoreTestOpen(
				t, root, fixture)
			if _, err := store.LoadSet(); err == nil {
				t.Fatal("incomplete ticket set loaded")
			}
			receipt, replayed, err := store.Commit(fixture.tickets[1])
			if err != nil || replayed {
				t.Fatalf("first commit: replay=%v err=%v", replayed, err)
			}
			if _, err := store.LoadSet(); err == nil {
				t.Fatal("one-ticket set loaded")
			}
			replayedReceipt, replayed, err := store.Commit(fixture.tickets[1])
			if err != nil || !replayed || !reflect.DeepEqual(receipt, replayedReceipt) {
				t.Fatalf("exact replay changed: replay=%v err=%v", replayed, err)
			}
			if _, replayed, err := store.Commit(fixture.tickets[0]); err != nil || replayed {
				t.Fatalf("second recipient commit: replay=%v err=%v", replayed, err)
			}
			loaded, err := store.LoadSet()
			if err != nil || !reflect.DeepEqual(loaded, fixture.tickets) {
				t.Fatalf("canonical set mismatch: %v", err)
			}
			encodedReceipt, err := json.Marshal(receipt)
			if err != nil || receipt.ArtifactID != fixture.source.contract.Core.ArtifactID ||
				receipt.RecipientName != fixture.tickets[1].RecipientName ||
				receipt.ProductionReady {
				t.Fatal("unsafe or incomplete ticket receipt")
			}
			for _, forbidden := range []string{
				`"path"`, `"key"`, `"ticket"`, `"transport_pk"`, `"signature"`,
			} {
				if strings.Contains(string(encodedReceipt), forbidden) {
					t.Fatalf("receipt exposes forbidden field %s", forbidden)
				}
			}
			if err := filepath.Walk(root, func(path string, info os.FileInfo,
				err error,
			) error {
				if err != nil {
					return err
				}
				if info.IsDir() && info.Mode().Perm() != 0o700 {
					return fmt.Errorf("directory %s mode %o", path, info.Mode().Perm())
				}
				if !info.IsDir() && info.Mode().Perm() != 0o600 {
					return fmt.Errorf("record %s mode %o", path, info.Mode().Perm())
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}

			store.Close()
			restarted := formalGLMRegisteredPhase18TicketStoreTestOpen(
				t, root, fixture)
			loaded, err = restarted.LoadSet()
			if err != nil || !reflect.DeepEqual(loaded, fixture.tickets) {
				t.Fatalf("restart changed ticket set: %v", err)
			}
			if _, replayed, err := restarted.Commit(fixture.tickets[0]); err != nil || !replayed {
				t.Fatalf("restart replay: replay=%v err=%v", replayed, err)
			}
		})
	}
}

func TestFormalGLMRegisteredPhase18RecipientTicketStoreNoRerollAndBindings(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase18TicketStoreTestBuild(t, 2)
	pins := fixture.source.inputs.identities.public
	for _, test := range []struct {
		name   string
		mutate func(formalGLMRegisteredPhase18RecipientTicketV1) formalGLMRegisteredPhase18RecipientTicketV1
	}{
		{
			name: "wrong-signer",
			mutate: func(ticket formalGLMRegisteredPhase18RecipientTicketV1) formalGLMRegisteredPhase18RecipientTicketV1 {
				return formalGLMRegisteredPhase18TicketStoreTestResign(t, fixture,
					ticket, fixture.source.plan.DesignatedComputePeers[1])
			},
		},
		{
			name: "wrong-contract",
			mutate: func(ticket formalGLMRegisteredPhase18RecipientTicketV1) formalGLMRegisteredPhase18RecipientTicketV1 {
				ticket.SourceContractSHA256 = strings.Repeat("a", 64)
				return formalGLMRegisteredPhase18TicketStoreTestResign(t, fixture,
					ticket, ticket.RecipientName)
			},
		},
		{
			name: "wrong-pinset",
			mutate: func(ticket formalGLMRegisteredPhase18RecipientTicketV1) formalGLMRegisteredPhase18RecipientTicketV1 {
				ticket.PinsetSHA256 = strings.Repeat("b", 64)
				return formalGLMRegisteredPhase18TicketStoreTestResign(t, fixture,
					ticket, ticket.RecipientName)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := formalGLMRegisteredPhase18TicketStoreTestOpen(
				t, formalGLMRegisteredPhase18TicketStoreTestRoot(t), fixture)
			if _, _, err := store.Commit(test.mutate(fixture.tickets[0])); err == nil {
				t.Fatal("invalid ticket committed")
			}
			if _, err := store.LoadSet(); err == nil {
				t.Fatal("invalid ticket created a complete set")
			}
		})
	}

	t.Run("constructor-pinset", func(t *testing.T) {
		wrongPins := make(map[string]ed25519.PublicKey, len(pins))
		for peer, pin := range pins {
			wrongPins[peer] = append(ed25519.PublicKey(nil), pin...)
		}
		_, replacement, err := ed25519.GenerateKey(crand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		peer := fixture.source.plan.DesignatedComputePeers[0]
		wrongPins[peer] = replacement.Public().(ed25519.PublicKey)
		if store, err := newFormalGLMRegisteredPhase18RecipientTicketStoreV1(
			formalGLMRegisteredPhase18TicketStoreTestRoot(t),
			fixture.source.contract, wrongPins); err == nil {
			store.Close()
			t.Fatal("store accepted mismatched pins")
		}
	})

	t.Run("transport-key-reroll", func(t *testing.T) {
		root := formalGLMRegisteredPhase18TicketStoreTestRoot(t)
		store := formalGLMRegisteredPhase18TicketStoreTestOpen(t, root, fixture)
		if _, replayed, err := store.Commit(fixture.tickets[0]); err != nil || replayed {
			t.Fatal("initial ticket did not commit")
		}
		alternative := formalGLMRegisteredPhase18TicketStoreTestRekey(t, fixture, 0)
		if _, _, err := store.Commit(alternative); err == nil {
			t.Fatal("second valid transport key rerolled recipient ticket")
		}
		if _, replayed, err := store.Commit(fixture.tickets[0]); err != nil || !replayed {
			t.Fatal("CAS conflict altered original ticket")
		}
		if _, replayed, err := store.Commit(fixture.tickets[1]); err != nil || replayed {
			t.Fatal("other recipient could not commit")
		}
		loaded, err := store.LoadSet()
		if err != nil || !reflect.DeepEqual(loaded, fixture.tickets) {
			t.Fatal("reroll attempt corrupted durable set")
		}
	})

	t.Run("frozen-provenance-context", func(t *testing.T) {
		contract := formalGLMRegisteredPhase18ProvenanceTestClone(
			t, fixture.source.contract)
		callerPins := make(map[string]ed25519.PublicKey, len(pins))
		for peer, pin := range pins {
			callerPins[peer] = append(ed25519.PublicKey(nil), pin...)
		}
		root := formalGLMRegisteredPhase18TicketStoreTestRoot(t)
		store, err := newFormalGLMRegisteredPhase18RecipientTicketStoreV1(
			root, contract, callerPins)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		frozenContext := formalGLMRegisteredPhase18ProvenanceTestClone(
			t, store.context.contract)
		contract.Core.ArtifactID = strings.Repeat("c", 64)
		for peer := range callerPins {
			clear(callerPins[peer])
		}
		formalGLMRegisteredPhase18TicketStoreTestCommitSet(t, store, fixture)
		for attempt := 0; attempt < 4; attempt++ {
			loaded, err := store.LoadSet()
			if err != nil || !reflect.DeepEqual(loaded, fixture.tickets) {
				t.Fatal("Commit/LoadSet rebuilt context from caller inputs")
			}
		}
		if !reflect.DeepEqual(store.context.contract, frozenContext) {
			t.Fatal("Commit/LoadSet mutated the frozen provenance context")
		}
	})
}

func formalGLMRegisteredPhase18TicketStoreTestComplete(t testing.TB,
	fixture formalGLMRegisteredPhase18TicketStoreTestFixtureV1,
) (string,
	*formalGLMRegisteredPhase18RecipientTicketStoreV1, [2]string) {
	t.Helper()
	root := formalGLMRegisteredPhase18TicketStoreTestRoot(t)
	store := formalGLMRegisteredPhase18TicketStoreTestOpen(t, root, fixture)
	formalGLMRegisteredPhase18TicketStoreTestCommitSet(t, store, fixture)
	return root, store, [2]string{
		formalGLMRegisteredPhase18TicketStoreTestRecordPath(t, root, fixture, 0),
		formalGLMRegisteredPhase18TicketStoreTestRecordPath(t, root, fixture, 1),
	}
}

func TestFormalGLMRegisteredPhase18RecipientTicketStoreFilesystemClosed(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase18TicketStoreTestBuild(t, 2)
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, root string, paths [2]string)
	}{
		{
			name: "noncanonical-tamper",
			mutate: func(t *testing.T, _ string, paths [2]string) {
				encoded, err := os.ReadFile(paths[0])
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(paths[0], append(encoded, ' '), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "record-mode",
			mutate: func(t *testing.T, _ string, paths [2]string) {
				if err := os.Chmod(paths[0], 0o640); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hardlink",
			mutate: func(t *testing.T, root string, paths [2]string) {
				if err := os.Link(paths[0], filepath.Join(root, "ticket-alias")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "record-symlink",
			mutate: func(t *testing.T, _ string, paths [2]string) {
				backup := paths[0] + ".backup"
				if err := os.Rename(paths[0], backup); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Base(backup), paths[0]); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "shard-mode",
			mutate: func(t *testing.T, _ string, paths [2]string) {
				if err := os.Chmod(filepath.Dir(paths[0]), 0o750); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "root-mode",
			mutate: func(t *testing.T, root string, _ [2]string) {
				if err := os.Chmod(root, 0o750); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "duplicate-slot",
			mutate: func(t *testing.T, _ string, paths [2]string) {
				encoded, err := os.ReadFile(paths[0])
				if err != nil || os.WriteFile(paths[1], encoded, 0o600) != nil {
					t.Fatal("could not duplicate persisted slot")
				}
			},
		},
		{
			name: "reordered-slots",
			mutate: func(t *testing.T, _ string, paths [2]string) {
				first, err1 := os.ReadFile(paths[0])
				second, err2 := os.ReadFile(paths[1])
				if err1 != nil || err2 != nil ||
					os.WriteFile(paths[0], second, 0o600) != nil ||
					os.WriteFile(paths[1], first, 0o600) != nil {
					t.Fatal("could not reorder persisted slots")
				}
			},
		},
		{
			name: "unexpected-record",
			mutate: func(t *testing.T, _ string, paths [2]string) {
				if err := os.WriteFile(filepath.Join(filepath.Dir(paths[0]),
					"ticket-unexpected.json"), []byte(strings.Repeat("x", 64)),
					0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, store, paths :=
				formalGLMRegisteredPhase18TicketStoreTestComplete(t, fixture)
			test.mutate(t, root, paths)
			if _, err := store.LoadSet(); err == nil {
				t.Fatal("unsafe durable state loaded")
			}
		})
	}

	t.Run("existing-root-mode", func(t *testing.T) {
		root := formalGLMRegisteredPhase18TicketStoreTestRoot(t)
		if err := os.MkdirAll(root, 0o755); err != nil ||
			os.Chmod(root, 0o755) != nil {
			t.Fatal("could not prepare unsafe root")
		}
		if store, err := newFormalGLMRegisteredPhase18RecipientTicketStoreV1(
			root, fixture.source.contract,
			fixture.source.inputs.identities.public); err == nil {
			store.Close()
			t.Fatal("unsafe existing root accepted")
		}
	})
	t.Run("leaf-symlink", func(t *testing.T) {
		base := t.TempDir()
		realRoot := filepath.Join(base, "real")
		if err := os.Mkdir(realRoot, 0o700); err != nil ||
			os.Symlink(realRoot, filepath.Join(base, "rock")) != nil {
			t.Fatal("could not prepare leaf symlink")
		}
		if store, err := newFormalGLMRegisteredPhase18RecipientTicketStoreV1(
			filepath.Join(base, "rock"), fixture.source.contract,
			fixture.source.inputs.identities.public); err == nil {
			store.Close()
			t.Fatal("symlink Rock root accepted")
		}
	})
	t.Run("resolved-ancestor", func(t *testing.T) {
		base := t.TempDir()
		realParent := filepath.Join(base, "real-parent")
		alias := filepath.Join(base, "alias")
		if err := os.Mkdir(realParent, 0o700); err != nil ||
			os.Symlink(realParent, alias) != nil {
			t.Fatal("could not prepare resolved ancestor")
		}
		root := filepath.Join(alias, "rock")
		store := formalGLMRegisteredPhase18TicketStoreTestOpen(t, root, fixture)
		formalGLMRegisteredPhase18TicketStoreTestCommitSet(t, store, fixture)
		if loaded, err := store.LoadSet(); err != nil ||
			!reflect.DeepEqual(loaded, fixture.tickets) {
			t.Fatal("safe resolved ancestor was not supported")
		}
	})
	t.Run("same-shard-foreign-artifact", func(t *testing.T) {
		_, store, paths :=
			formalGLMRegisteredPhase18TicketStoreTestComplete(t, fixture)
		artifactID := fixture.source.contract.Core.ArtifactID
		foreignID := artifactID[:4] + strings.Repeat("f", 60)
		if foreignID == artifactID {
			foreignID = artifactID[:4] + strings.Repeat("e", 60)
		}
		foreignDir := filepath.Join(filepath.Dir(filepath.Dir(paths[0])), foreignID)
		if err := os.Mkdir(foreignDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(foreignDir,
			"ticket-recipient-0.json"), []byte(strings.Repeat("x", 64)),
			0o600); err != nil {
			t.Fatal(err)
		}
		loaded, err := store.LoadSet()
		if err != nil || !reflect.DeepEqual(loaded, fixture.tickets) {
			t.Fatal("same-shard foreign ArtifactID interfered with local set")
		}
		if filepath.Dir(paths[0]) == foreignDir {
			t.Fatal("ArtifactID does not own a distinct durable directory")
		}
	})
}

func TestFormalGLMRegisteredPhase18RecipientTicketStoreConcurrentExactCAS(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase18TicketStoreTestBuild(t, 2)
	root := formalGLMRegisteredPhase18TicketStoreTestRoot(t)
	const workers = 12
	stores := make([]*formalGLMRegisteredPhase18RecipientTicketStoreV1, workers)
	for index := range stores {
		stores[index] = formalGLMRegisteredPhase18TicketStoreTestOpen(
			t, root, fixture)
	}
	var wait sync.WaitGroup
	wait.Add(workers)
	errors := make(chan error, workers)
	replays := make(chan bool, workers)
	for index := range stores {
		go func(index int) {
			defer wait.Done()
			_, replayed, err := stores[index].Commit(fixture.tickets[0])
			errors <- err
			replays <- replayed
		}(index)
	}
	wait.Wait()
	close(errors)
	close(replays)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	fresh := 0
	for replayed := range replays {
		if !replayed {
			fresh++
		}
	}
	if fresh != 1 {
		t.Fatalf("exact concurrent CAS created %d records", fresh)
	}
}

func TestFormalGLMRegisteredPhase18RecipientTicketStoreConcurrentDivergentCAS(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase18TicketStoreTestBuild(t, 2)
	alternative := formalGLMRegisteredPhase18TicketStoreTestRekey(t, fixture, 0)
	root := formalGLMRegisteredPhase18TicketStoreTestRoot(t)
	const workers = 12
	stores := make([]*formalGLMRegisteredPhase18RecipientTicketStoreV1, workers)
	for index := range stores {
		stores[index] = formalGLMRegisteredPhase18TicketStoreTestOpen(
			t, root, fixture)
	}
	var wait sync.WaitGroup
	wait.Add(workers)
	results := make(chan error, workers)
	for index := range stores {
		go func(index int) {
			defer wait.Done()
			candidate := fixture.tickets[0]
			if index%2 == 1 {
				candidate = alternative
			}
			_, _, err := stores[index].Commit(candidate)
			results <- err
		}(index)
	}
	wait.Wait()
	close(results)
	succeeded, failed := 0, 0
	for err := range results {
		if err == nil {
			succeeded++
		} else {
			failed++
		}
	}
	if succeeded != workers/2 || failed != workers/2 {
		t.Fatalf("divergent CAS successes=%d failures=%d", succeeded, failed)
	}
	if _, replayed, err := stores[0].Commit(fixture.tickets[1]); err != nil || replayed {
		t.Fatalf("second slot commit after race: replay=%v err=%v", replayed, err)
	}
	loaded, err := stores[0].LoadSet()
	if err != nil || len(loaded) != 2 ||
		(!reflect.DeepEqual(loaded[0], fixture.tickets[0]) &&
			!reflect.DeepEqual(loaded[0], alternative)) ||
		!reflect.DeepEqual(loaded[1], fixture.tickets[1]) {
		t.Fatal("divergent CAS corrupted the ticket set")
	}
}
