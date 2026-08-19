package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type formalGLMRegisteredPhase18SourceOutboxTestFixtureV3 struct {
	provenance    formalGLMRegisteredPhase18ProvenanceTestFixtureV1
	authorization formalGLMRegisteredPhase18AuthorizationV1
	source        string
	tickets       []formalGLMRegisteredPhase18RecipientTicketV1
	blockIndex    int
	values        []string
	validity      []bool
	consensus     [32]byte
	localKey      [32]byte
}

func formalGLMRegisteredPhase18SourceOutboxTestBuild(t testing.TB,
	custodians int,
) formalGLMRegisteredPhase18SourceOutboxTestFixtureV3 {
	t.Helper()
	provenance := formalGLMRegisteredPhase18ProvenanceTestBuild(t, custodians)
	source := provenance.source.plan.CustodianPeers[0]
	if custodians == 5 {
		for _, peer := range provenance.source.plan.CustodianPeers {
			if len(provenance.authorizations[peer].LocalColumns) == 0 {
				source = peer
				break
			}
		}
	}
	authorization := provenance.authorizations[source]
	blockIndex := authorization.Geometry.TotalBlocks - 1
	values, validity := formalGLMRegisteredPhase18MaterializedPairTestValues(
		authorization, blockIndex)
	return formalGLMRegisteredPhase18SourceOutboxTestFixtureV3{
		provenance: provenance, authorization: authorization, source: source,
		tickets: provenance.tickets, blockIndex: blockIndex,
		values: values, validity: validity,
		consensus: sha256.Sum256([]byte(fmt.Sprintf(
			"registered-phase18/source-outbox/K%d", custodians))),
		localKey: sha256.Sum256([]byte(fmt.Sprintf(
			"registered-phase18/source-outbox/local-key/K%d", custodians))),
	}
}

func formalGLMRegisteredPhase18SourceOutboxTestRoot(t testing.TB,
	name string,
) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(resolved, name)
}

func formalGLMRegisteredPhase18SourceOutboxTestNew(t testing.TB,
	root string,
	fixture formalGLMRegisteredPhase18SourceOutboxTestFixtureV3,
) *formalGLMRegisteredPhase18SourceOutboxV3 {
	t.Helper()
	outbox, err := newFormalGLMRegisteredPhase18SourceOutboxV3(
		root, fixture.provenance.source.contract, fixture.source,
		fixture.provenance.source.inputs.identities.private[fixture.source],
		fixture.localKey, fixture.provenance.source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	return outbox
}

func formalGLMRegisteredPhase18SourceOutboxTestCommit(t testing.TB,
	outbox *formalGLMRegisteredPhase18SourceOutboxV3,
	fixture formalGLMRegisteredPhase18SourceOutboxTestFixtureV3,
) (formalGLMRegisteredPhase18SourceOutboxReceiptV3, []byte, bool) {
	t.Helper()
	receipt, pairJSON, replayed, err := outbox.CommitBlock(
		fixture.authorization, fixture.tickets, fixture.blockIndex,
		fixture.values, fixture.validity, fixture.consensus[:])
	if err != nil {
		t.Fatal(err)
	}
	return receipt, pairJSON, replayed
}

func formalGLMRegisteredPhase18SourceOutboxTestRecords(t testing.TB,
	root string,
) map[string]string {
	t.Helper()
	records := make(map[string]string)
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
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return fmt.Errorf("unsafe outbox record %s", path)
		}
		records[filepath.Base(path)] = path
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return records
}

func formalGLMRegisteredPhase18SourceOutboxTestRecord(
	t testing.TB, records map[string]string, prefix string,
) string {
	t.Helper()
	for name, path := range records {
		if strings.HasPrefix(name, prefix) {
			return path
		}
	}
	t.Fatalf("missing %s outbox record", prefix)
	return ""
}

func TestFormalGLMRegisteredPhase18SourceOutboxV3K2K5RestartReplay(
	t *testing.T,
) {
	for _, custodians := range []int{2, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMRegisteredPhase18SourceOutboxTestBuild(
				t, custodians)
			if fixture.blockIndex != 2 || len(fixture.validity) != 4 ||
				!fixture.validity[0] || fixture.validity[1] ||
				fixture.validity[2] || fixture.validity[3] {
				t.Fatal("fixture is not the fixed padded 9/4 final block")
			}
			if custodians == 5 && len(fixture.authorization.LocalColumns) != 0 {
				t.Fatal("K5 source is not the alignment-only witness")
			}
			root := formalGLMRegisteredPhase18SourceOutboxTestRoot(
				t, "source-outbox")
			outbox := formalGLMRegisteredPhase18SourceOutboxTestNew(
				t, root, fixture)
			receipt, pairJSON, replayed :=
				formalGLMRegisteredPhase18SourceOutboxTestCommit(
					t, outbox, fixture)
			if replayed {
				t.Fatal("first durable source pair was marked replay")
			}
			if _, err := formalGLMDecodeRegisteredPhase18BlockPairV1(
				pairJSON, fixture.provenance.source.contract,
				fixture.authorization, fixture.tickets,
				fixture.provenance.source.inputs.identities.public); err != nil {
				t.Fatal(err)
			}
			outbox.Close()

			var builds atomic.Int32
			restarted, err :=
				newFormalGLMRegisteredPhase18SourceOutboxWithHooksV3(
					root, fixture.provenance.source.contract, fixture.source,
					fixture.provenance.source.inputs.identities.private[fixture.source],
					fixture.localKey,
					fixture.provenance.source.inputs.identities.public,
					formalGLMRegisteredPhase18SourceOutboxHooksV3{
						BuildPair: func(
							contract formalGLMSourceContractV1,
							authorization formalGLMRegisteredPhase18AuthorizationV1,
							tickets []formalGLMRegisteredPhase18RecipientTicketV1,
							blockIndex int, values []string, validity []bool,
							consensus []byte, key []byte,
							pins map[string]ed25519.PublicKey,
						) (formalGLMRegisteredPhase18BlockPairV1, error) {
							builds.Add(1)
							return formalGLMRegisteredPhase18BuildMaterializedBlockPairV3(
								contract, authorization, tickets, blockIndex, values,
								validity, consensus, key, pins)
						},
					})
			if err != nil {
				t.Fatal(err)
			}
			replayedReceipt, replayedJSON, wasReplay, err :=
				restarted.CommitBlock(
					fixture.authorization, fixture.tickets, fixture.blockIndex,
					fixture.values, fixture.validity, fixture.consensus[:])
			restarted.Close()
			if err != nil || !wasReplay || builds.Load() != 0 ||
				!bytes.Equal(pairJSON, replayedJSON) ||
				!reflect.DeepEqual(receipt, replayedReceipt) {
				t.Fatalf("restart replay differs: replay=%v builds=%d bytes=%v receipt=%v err=%v",
					wasReplay, builds.Load(), bytes.Equal(pairJSON, replayedJSON),
					reflect.DeepEqual(receipt, replayedReceipt), err)
			}
			records := formalGLMRegisteredPhase18SourceOutboxTestRecords(t, root)
			if len(records) != 2 {
				t.Fatalf("got %d durable records, want intent+pair", len(records))
			}
			for _, forbidden := range []string{
				"Value", "Validity", "Consensus", "Plaintext", "Key", "Path",
			} {
				for index := 0; index < reflect.TypeOf(receipt).NumField(); index++ {
					if strings.Contains(
						reflect.TypeOf(receipt).Field(index).Name, forbidden) {
						t.Fatalf("safe outbox receipt exposes %s", forbidden)
					}
				}
			}
			intent, err := os.ReadFile(
				formalGLMRegisteredPhase18SourceOutboxTestRecord(
					t, records, "intent-"))
			if err != nil || bytes.Contains(intent, []byte("9007199254740993")) ||
				bytes.Contains(intent, fixture.consensus[:]) {
				t.Fatal("durable intent leaked private materialization input")
			}
		})
	}
}

func TestFormalGLMRegisteredPhase18SourceOutboxV3CrashConflictTamperAndRace(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase18SourceOutboxTestBuild(t, 2)
	contract := fixture.provenance.source.contract
	privateKey := fixture.provenance.source.inputs.identities.private[fixture.source]
	pins := fixture.provenance.source.inputs.identities.public

	t.Run("crash-intent-before-pair", func(t *testing.T) {
		root := formalGLMRegisteredPhase18SourceOutboxTestRoot(t, "crash")
		var builds atomic.Int32
		outbox, err := newFormalGLMRegisteredPhase18SourceOutboxWithHooksV3(
			root, contract, fixture.source, privateKey, fixture.localKey, pins,
			formalGLMRegisteredPhase18SourceOutboxHooksV3{
				AfterIntent: func() error { return errors.New("injected crash") },
				BuildPair: func(contract formalGLMSourceContractV1,
					authorization formalGLMRegisteredPhase18AuthorizationV1,
					tickets []formalGLMRegisteredPhase18RecipientTicketV1,
					blockIndex int, values []string, validity []bool,
					consensus []byte, key []byte,
					pins map[string]ed25519.PublicKey,
				) (formalGLMRegisteredPhase18BlockPairV1, error) {
					builds.Add(1)
					return formalGLMRegisteredPhase18BuildMaterializedBlockPairV3(
						contract, authorization, tickets, blockIndex, values,
						validity, consensus, key, pins)
				},
			})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := outbox.CommitBlock(
			fixture.authorization, fixture.tickets, fixture.blockIndex,
			fixture.values, fixture.validity, fixture.consensus[:]); err == nil {
			t.Fatal("injected pre-pair crash was ignored")
		}
		outbox.Close()
		if builds.Load() != 0 ||
			len(formalGLMRegisteredPhase18SourceOutboxTestRecords(t, root)) != 1 {
			t.Fatal("crash did not stop after the durable intent")
		}
		restarted := formalGLMRegisteredPhase18SourceOutboxTestNew(t, root, fixture)
		_, _, replayed := formalGLMRegisteredPhase18SourceOutboxTestCommit(
			t, restarted, fixture)
		restarted.Close()
		if replayed ||
			len(formalGLMRegisteredPhase18SourceOutboxTestRecords(t, root)) != 2 {
			t.Fatal("intent-only crash did not recover one durable pair")
		}
	})

	t.Run("conflict-and-record-tamper", func(t *testing.T) {
		root := formalGLMRegisteredPhase18SourceOutboxTestRoot(t, "tamper")
		outbox := formalGLMRegisteredPhase18SourceOutboxTestNew(t, root, fixture)
		_, _, _ = formalGLMRegisteredPhase18SourceOutboxTestCommit(
			t, outbox, fixture)
		changedValues := append([]string(nil), fixture.values...)
		for coordinate, owner := range fixture.authorization.Geometry.CoordinateOwners {
			if owner == fixture.source {
				changedValues[coordinate] = "7"
				break
			}
		}
		if _, _, _, err := outbox.CommitBlock(
			fixture.authorization, fixture.tickets, fixture.blockIndex,
			changedValues, fixture.validity, fixture.consensus[:]); err == nil {
			t.Fatal("conflicting materialized values replaced the intent")
		}
		changedTickets := formalGLMRegisteredPhase18ProvenanceTestClone(
			t, fixture.tickets)
		transportKey, err := ecdh.X25519().GenerateKey(crand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		unsigned, err := formalGLMRegisteredPhase18BuildRecipientTicketV1(
			contract, changedTickets[0].RecipientName,
			transportKey.PublicKey().Bytes(), pins)
		if err != nil {
			t.Fatal(err)
		}
		changedTickets[0], err = formalGLMRegisteredPhase18SignRecipientTicketV1(
			unsigned, contract,
			fixture.provenance.source.inputs.identities.private[unsigned.RecipientName], pins)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := outbox.CommitBlock(
			fixture.authorization, changedTickets, fixture.blockIndex,
			fixture.values, fixture.validity, fixture.consensus[:]); err == nil {
			t.Fatal("conflicting recipient ticket replaced the intent")
		}

		records := formalGLMRegisteredPhase18SourceOutboxTestRecords(t, root)
		intentPath := formalGLMRegisteredPhase18SourceOutboxTestRecord(
			t, records, "intent-")
		pairPath := formalGLMRegisteredPhase18SourceOutboxTestRecord(
			t, records, "pair-")
		for _, path := range []string{intentPath, pairPath} {
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			tampered := append([]byte(nil), original...)
			tampered[len(tampered)/2] ^= 1
			if err := os.WriteFile(path, tampered, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := outbox.CommitBlock(
				fixture.authorization, fixture.tickets, fixture.blockIndex,
				fixture.values, fixture.validity,
				fixture.consensus[:]); err == nil {
				t.Fatalf("tampered %s was accepted", filepath.Base(path))
			}
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chmod(pairPath, 0o640); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := outbox.CommitBlock(
			fixture.authorization, fixture.tickets, fixture.blockIndex,
			fixture.values, fixture.validity, fixture.consensus[:]); err == nil {
			t.Fatal("unsafe pair mode was accepted")
		}
		if err := os.Chmod(pairPath, 0o600); err != nil {
			t.Fatal(err)
		}
		hardlink := pairPath + ".hardlink"
		if err := os.Link(pairPath, hardlink); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := outbox.CommitBlock(
			fixture.authorization, fixture.tickets, fixture.blockIndex,
			fixture.values, fixture.validity, fixture.consensus[:]); err == nil {
			t.Fatal("hard-linked pair was accepted")
		}
		if err := os.Remove(hardlink); err != nil {
			t.Fatal(err)
		}
		backup := pairPath + ".backup"
		if err := os.Rename(pairPath, backup); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(backup, pairPath); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := outbox.CommitBlock(
			fixture.authorization, fixture.tickets, fixture.blockIndex,
			fixture.values, fixture.validity, fixture.consensus[:]); err == nil {
			t.Fatal("symlinked pair was accepted")
		}
		if err := os.Remove(pairPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(backup, pairPath); err != nil {
			t.Fatal(err)
		}
		outbox.Close()
	})

	t.Run("concurrent-exact", func(t *testing.T) {
		root := formalGLMRegisteredPhase18SourceOutboxTestRoot(t, "concurrent")
		var builds atomic.Int32
		outbox, err := newFormalGLMRegisteredPhase18SourceOutboxWithHooksV3(
			root, contract, fixture.source, privateKey, fixture.localKey, pins,
			formalGLMRegisteredPhase18SourceOutboxHooksV3{
				BuildPair: func(contract formalGLMSourceContractV1,
					authorization formalGLMRegisteredPhase18AuthorizationV1,
					tickets []formalGLMRegisteredPhase18RecipientTicketV1,
					blockIndex int, values []string, validity []bool,
					consensus []byte, key []byte,
					pins map[string]ed25519.PublicKey,
				) (formalGLMRegisteredPhase18BlockPairV1, error) {
					builds.Add(1)
					return formalGLMRegisteredPhase18BuildMaterializedBlockPairV3(
						contract, authorization, tickets, blockIndex, values,
						validity, consensus, key, pins)
				},
			})
		if err != nil {
			t.Fatal(err)
		}
		defer outbox.Close()
		type result struct {
			pair     []byte
			replayed bool
			err      error
		}
		const callers = 8
		results := make(chan result, callers)
		var wait sync.WaitGroup
		for index := 0; index < callers; index++ {
			wait.Add(1)
			go func() {
				defer wait.Done()
				_, pair, replayed, err := outbox.CommitBlock(
					fixture.authorization, fixture.tickets, fixture.blockIndex,
					fixture.values, fixture.validity, fixture.consensus[:])
				results <- result{pair: pair, replayed: replayed, err: err}
			}()
		}
		wait.Wait()
		close(results)
		var first []byte
		fresh := 0
		for result := range results {
			if result.err != nil {
				t.Fatal(result.err)
			}
			if first == nil {
				first = result.pair
			} else if !bytes.Equal(first, result.pair) {
				t.Fatal("concurrent exact callers observed different durable pairs")
			}
			if !result.replayed {
				fresh++
			}
		}
		if builds.Load() != 1 || fresh != 1 ||
			len(formalGLMRegisteredPhase18SourceOutboxTestRecords(t, root)) != 2 {
			t.Fatalf("concurrent CAS: builds=%d fresh=%d", builds.Load(), fresh)
		}
	})

	t.Run("unsafe-root", func(t *testing.T) {
		parent := formalGLMRegisteredPhase18SourceOutboxTestRoot(t, "roots")
		if err := os.MkdirAll(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(parent, "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(parent, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := newFormalGLMRegisteredPhase18SourceOutboxV3(
			link, contract, fixture.source, privateKey, fixture.localKey,
			pins); err == nil {
			t.Fatal("symlink Rock root was accepted")
		}
		unsafe := filepath.Join(parent, "unsafe-mode")
		if err := os.Mkdir(unsafe, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := newFormalGLMRegisteredPhase18SourceOutboxV3(
			unsafe, contract, fixture.source, privateKey, fixture.localKey,
			pins); err == nil {
			t.Fatal("unsafe Rock root mode was accepted")
		}
	})
}
