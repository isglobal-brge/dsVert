package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func formalGLMSamplerV2StoreTestRoot(
	t testing.TB, dir string, fixture formalGLMPhase21SamplerV2TestFixture,
	authority formalGLMPhase21StickyNoiseAuthority,
) *formalGLMSamplerV2AuthorityRootStoreV1 {
	t.Helper()
	store, err := newFormalGLMSamplerV2AuthorityRootStoreV1(
		dir, authority.PeerName, authority.Role,
		fixture.keys[authority.PeerName], fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return store
}

func formalGLMSamplerV2StoreTestContract(
	t testing.TB, fixture formalGLMPhase21SamplerV2TestFixture,
	mode, rootBase string,
) (formalGLMPhase21SamplerV2Contract,
	map[string]*formalGLMSamplerV2AuthorityRootStoreV1,
) {
	t.Helper()
	commitments := make([]formalGLMPhase21SamplerV2Commitment, 2)
	stores := make(map[string]*formalGLMSamplerV2AuthorityRootStoreV1, 2)
	for index, authority := range fixture.artifact.NoiseAuthorities {
		store := formalGLMSamplerV2StoreTestRoot(t,
			filepath.Join(rootBase, authority.PeerName), fixture, authority)
		commitment, err := store.DeriveCommitment(fixture.artifactID, mode)
		if err != nil {
			t.Fatal(err)
		}
		stores[authority.PeerName] = store
		commitments[index] = commitment
	}
	unsigned, err := formalGLMPhase21BuildSamplerV2Contract(
		fixture.artifact, fixture.artifactID, mode, commitments, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	signatures := make([]jointDPBiomedicalGaussianSignature, 0,
		fixture.artifact.CustodianCount)
	for _, peer := range fixture.artifact.CustodianPeers {
		signature, signErr := formalGLMPhase21SignSamplerV2Contract(
			unsigned, peer, fixture.keys[peer])
		if signErr != nil {
			t.Fatal(signErr)
		}
		signatures = append(signatures, signature)
	}
	sealed, err := formalGLMPhase21SealSamplerV2Contract(
		unsigned, signatures, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	return sealed, stores
}

func TestFormalGLMSamplerV2StoresRestartAndKOfKK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMPhase21SamplerV2TestSetup(
				t, custodians, formalGLMPhase21SamplerV2OneDraw)
			contract, roots := formalGLMSamplerV2StoreTestContract(
				t, fixture, formalGLMPhase21SamplerV2OneDraw,
				filepath.Join(t.TempDir(), "authority-rocks"))

			for _, authority := range fixture.artifact.NoiseAuthorities {
				store := roots[authority.PeerName]
				before, err := store.DeriveCommitment(
					fixture.artifactID, formalGLMPhase21SamplerV2OneDraw)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(store.dir, store.recordRelativePath())
				keyPath := filepath.Join(store.dir, store.keyRelativePath())
				rootInfo, rootErr := os.Lstat(store.dir)
				peerInfo, peerErr := os.Lstat(filepath.Dir(path))
				recordInfo, recordErr := os.Lstat(path)
				keyInfo, keyErr := os.Lstat(keyPath)
				if rootErr != nil || peerErr != nil || recordErr != nil || keyErr != nil ||
					rootInfo.Mode().Perm() != 0o700 ||
					peerInfo.Mode().Perm() != 0o700 ||
					recordInfo.Mode().Perm() != 0o600 ||
					keyInfo.Mode().Perm() != 0o600 || keyInfo.Size() != 32 ||
					!recordInfo.Mode().IsRegular() ||
					!keyInfo.Mode().IsRegular() ||
					!exactGCPrivateOwnedRegular(recordInfo) ||
					!exactGCPrivateOwnedRegular(keyInfo) {
					t.Fatalf("authority root is not owner-only: %v %v %v %v",
						rootErr, peerErr, recordErr, keyErr)
				}
				store.Close()
				restarted := formalGLMSamplerV2StoreTestRoot(
					t, store.dir, fixture, authority)
				after, err := restarted.DeriveCommitment(
					fixture.artifactID, formalGLMPhase21SamplerV2OneDraw)
				if err != nil || !reflect.DeepEqual(after, before) {
					t.Fatalf("authority root changed on restart: %+v %v", after, err)
				}
				roots[authority.PeerName] = restarted
			}

			contractDir := filepath.Join(t.TempDir(), "contract-rock")
			store, err := newFormalGLMSamplerV2ContractStoreV1(
				contractDir, fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			replayed, err := store.Commit(contract)
			if err != nil || replayed {
				t.Fatalf("first sealed-contract commit: replay=%v err=%v", replayed, err)
			}
			loaded, err := store.Load(fixture.artifactID)
			if err != nil || !reflect.DeepEqual(loaded, contract) {
				t.Fatalf("sealed-contract load differs: %+v %v", loaded, err)
			}
			contractPath, err := store.recordPath(fixture.artifactID, false)
			if err != nil {
				t.Fatal(err)
			}
			contractJSON, err := os.ReadFile(contractPath)
			if err != nil {
				t.Fatal(err)
			}
			for _, directory := range []string{
				store.dir,
				filepath.Join(store.dir, formalGLMSamplerV2ContractRecordDir),
				filepath.Dir(filepath.Dir(contractPath)),
				filepath.Dir(contractPath),
			} {
				info, statErr := os.Lstat(directory)
				if statErr != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
					t.Fatalf("contract directory is not owner-only: %s %v",
						directory, statErr)
				}
			}
			contractInfo, err := os.Lstat(contractPath)
			if err != nil || !contractInfo.Mode().IsRegular() ||
				contractInfo.Mode().Perm() != 0o600 ||
				!exactGCPrivateOwnedRegular(contractInfo) {
				t.Fatalf("contract record is not owner-only: %v", err)
			}
			for _, authorityStore := range roots {
				seed, _, err := formalGLMPhase21SamplerV2Derive(
					authorityStore.authorityRoot, fixture.artifactID,
					formalGLMPhase21SamplerV2OneDraw, authorityStore.role,
					authorityStore.peer, authorityStore.peerID)
				if err != nil {
					t.Fatal(err)
				}
				secretForms := [][]byte{
					authorityStore.authorityRoot[:],
					[]byte(base64.RawURLEncoding.EncodeToString(
						authorityStore.authorityRoot[:])),
					[]byte(base64.StdEncoding.EncodeToString(
						authorityStore.authorityRoot[:])),
					[]byte(hex.EncodeToString(authorityStore.authorityRoot[:])),
					seed[:],
					[]byte(base64.RawURLEncoding.EncodeToString(seed[:])),
					[]byte(base64.StdEncoding.EncodeToString(seed[:])),
					[]byte(hex.EncodeToString(seed[:])),
				}
				err = filepath.WalkDir(authorityStore.dir,
					func(path string, entry os.DirEntry, walkErr error) error {
						if walkErr != nil || entry.IsDir() || filepath.Ext(path) != ".json" {
							return walkErr
						}
						encoded, readErr := os.ReadFile(path)
						if readErr != nil {
							return readErr
						}
						for _, secret := range secretForms {
							if bytes.Contains(encoded, secret) {
								return fmt.Errorf("JSON contains authority-root material")
							}
						}
						return nil
					})
				if err != nil {
					clear(seed[:])
					t.Fatal(err)
				}
				for _, secret := range secretForms {
					if bytes.Contains(contractJSON, secret) {
						t.Fatal("sealed public contract record contains an authority root")
					}
				}
				clear(seed[:])
			}
			store.Close()
			store, err = newFormalGLMSamplerV2ContractStoreV1(
				contractDir, fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			restarted, err := store.Load(fixture.artifactID)
			if err != nil || !reflect.DeepEqual(restarted, contract) {
				t.Fatalf("contract changed on restart: %+v %v", restarted, err)
			}
			replayed, err = store.Commit(contract)
			if err != nil || !replayed {
				t.Fatalf("exact contract replay: replay=%v err=%v", replayed, err)
			}
		})
	}
}

func TestFormalGLMSamplerV2AuthorityRootConcurrentExact(t *testing.T) {
	fixture := formalGLMPhase21SamplerV2TestSetup(
		t, 5, formalGLMPhase21SamplerV2OneDraw)
	authority := fixture.artifact.NoiseAuthorities[0]
	dir := filepath.Join(t.TempDir(), "authority-rock")
	const workers = 16
	type result struct {
		commitment formalGLMPhase21SamplerV2Commitment
		err        error
	}
	results := make(chan result, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			store, err := newFormalGLMSamplerV2AuthorityRootStoreV1(
				dir, authority.PeerName, authority.Role,
				fixture.keys[authority.PeerName], fixture.pins)
			if err != nil {
				results <- result{err: err}
				return
			}
			defer store.Close()
			commitment, err := store.DeriveCommitment(
				fixture.artifactID, formalGLMPhase21SamplerV2OneDraw)
			results <- result{commitment: commitment, err: err}
		}()
	}
	wait.Wait()
	close(results)
	var expected formalGLMPhase21SamplerV2Commitment
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if expected.PeerName == "" {
			expected = result.commitment
		} else if !reflect.DeepEqual(result.commitment, expected) {
			t.Fatal("concurrent initialization created more than one authority root")
		}
	}
}

func TestFormalGLMSamplerV2AuthorityRootFailsClosed(t *testing.T) {
	fixture := formalGLMPhase21SamplerV2TestSetup(
		t, 3, formalGLMPhase21SamplerV2OneDraw)
	authority := fixture.artifact.NoiseAuthorities[0]
	for _, attack := range []string{
		"loss", "key-tamper", "metadata-tamper", "mode", "hardlink",
		"symlink", "parent-mode",
	} {
		t.Run(attack, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "authority-rock")
			store := formalGLMSamplerV2StoreTestRoot(t, dir, fixture, authority)
			metadataPath := filepath.Join(store.dir, store.recordRelativePath())
			path := filepath.Join(store.dir, store.keyRelativePath())
			encoded, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			store.Close()
			switch attack {
			case "loss":
				err = os.Remove(path)
			case "key-tamper":
				encoded[len(encoded)/2] ^= 1
				err = os.WriteFile(path, encoded, 0o600)
			case "metadata-tamper":
				metadata, readErr := os.ReadFile(metadataPath)
				if readErr != nil {
					t.Fatal(readErr)
				}
				metadata[len(metadata)/2] ^= 1
				err = os.WriteFile(metadataPath, metadata, 0o600)
			case "mode":
				err = os.Chmod(path, 0o644)
			case "hardlink":
				err = os.Link(path, path+".alias")
			case "symlink":
				attacker := filepath.Join(t.TempDir(), "attacker.json")
				if err = os.WriteFile(attacker, encoded, 0o600); err == nil {
					err = os.Remove(path)
				}
				if err == nil {
					err = os.Symlink(attacker, path)
				}
			case "parent-mode":
				err = os.Chmod(filepath.Dir(path), 0o755)
			}
			if err != nil {
				t.Fatal(err)
			}
			reopened, openErr := newFormalGLMSamplerV2AuthorityRootStoreV1(
				dir, authority.PeerName, authority.Role,
				fixture.keys[authority.PeerName], fixture.pins)
			if openErr == nil {
				reopened.Close()
				t.Fatal("unsafe or lost authority root was accepted")
			}
			for _, secret := range []string{
				base64.RawURLEncoding.EncodeToString(encoded),
				base64.StdEncoding.EncodeToString(encoded),
				hex.EncodeToString(encoded),
			} {
				if strings.Contains(openErr.Error(), secret) {
					t.Fatal("authority-root error disclosed key material")
				}
			}
		})
	}

	t.Run("wrong-role", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "authority-rock")
		store := formalGLMSamplerV2StoreTestRoot(t, dir, fixture, authority)
		store.Close()
		if reopened, err := newFormalGLMSamplerV2AuthorityRootStoreV1(
			dir, authority.PeerName, "evaluator",
			fixture.keys[authority.PeerName], fixture.pins); err == nil {
			reopened.Close()
			t.Fatal("authority root crossed its role binding")
		}
	})

	t.Run("wrong-pinset", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "authority-rock")
		store := formalGLMSamplerV2StoreTestRoot(t, dir, fixture, authority)
		store.Close()
		wrongPins := make(map[string]ed25519.PublicKey, len(fixture.pins))
		for peer, pin := range fixture.pins {
			wrongPins[peer] = append(ed25519.PublicKey(nil), pin...)
		}
		otherPeer := fixture.artifact.CustodianPeers[1]
		wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		wrongPins[otherPeer] = wrongPublic
		if reopened, err := newFormalGLMSamplerV2AuthorityRootStoreV1(
			dir, authority.PeerName, authority.Role,
			fixture.keys[authority.PeerName], wrongPins); err == nil {
			reopened.Close()
			t.Fatal("authority root crossed its pinned consortium")
		}
	})

	t.Run("wrong-rock-root", func(t *testing.T) {
		sourceDir := filepath.Join(t.TempDir(), "source-rock")
		store := formalGLMSamplerV2StoreTestRoot(
			t, sourceDir, fixture, authority)
		sourcePath := filepath.Join(store.dir, store.recordRelativePath())
		sourceKeyPath := filepath.Join(store.dir, store.keyRelativePath())
		encoded, err := os.ReadFile(sourcePath)
		if err != nil {
			t.Fatal(err)
		}
		key, err := os.ReadFile(sourceKeyPath)
		if err != nil {
			t.Fatal(err)
		}
		store.Close()
		targetDir := filepath.Join(t.TempDir(), "target-rock")
		targetPath := filepath.Join(targetDir, store.recordRelativePath())
		targetKeyPath := filepath.Join(targetDir, store.keyRelativePath())
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(targetPath, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(targetKeyPath, key, 0o600); err != nil {
			t.Fatal(err)
		}
		if reopened, err := newFormalGLMSamplerV2AuthorityRootStoreV1(
			targetDir, authority.PeerName, authority.Role,
			fixture.keys[authority.PeerName], fixture.pins); err == nil {
			reopened.Close()
			t.Fatal("authority root copied from a different Rock root was accepted")
		}
	})

	t.Run("key-before-metadata-recovery", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "authority-rock")
		store := formalGLMSamplerV2StoreTestRoot(t, dir, fixture, authority)
		before, err := store.DeriveCommitment(
			fixture.artifactID, formalGLMPhase21SamplerV2OneDraw)
		if err != nil {
			t.Fatal(err)
		}
		metadataPath := filepath.Join(store.dir, store.recordRelativePath())
		store.Close()
		if err := os.Remove(metadataPath); err != nil {
			t.Fatal(err)
		}
		restarted := formalGLMSamplerV2StoreTestRoot(t, dir, fixture, authority)
		after, err := restarted.DeriveCommitment(
			fixture.artifactID, formalGLMPhase21SamplerV2OneDraw)
		if err != nil || !reflect.DeepEqual(after, before) {
			t.Fatalf("metadata recovery rerolled the authority root: %+v %v", after, err)
		}
	})

	for _, boundary := range []string{"mkdir-before-key", "partial-key-write"} {
		t.Run(boundary, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "authority-rock")
			peerDir := filepath.Join(dir, formalGLMSamplerV2AuthorityRootDir,
				authority.PeerName)
			if err := os.MkdirAll(peerDir, 0o700); err != nil {
				t.Fatal(err)
			}
			keyPath := filepath.Join(peerDir, "authority-root.key")
			metadataPath := filepath.Join(peerDir, "authority-root.json")
			partial := []byte("partial-root-key")
			if boundary == "partial-key-write" {
				if err := os.WriteFile(keyPath, partial, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for attempt := 0; attempt < 2; attempt++ {
				if store, err := newFormalGLMSamplerV2AuthorityRootStoreV1(
					dir, authority.PeerName, authority.Role,
					fixture.keys[authority.PeerName], fixture.pins); err == nil {
					store.Close()
					t.Fatal("crash boundary silently generated a replacement root")
				}
			}
			if _, err := os.Lstat(metadataPath); !os.IsNotExist(err) {
				t.Fatalf("crash boundary created metadata: %v", err)
			}
			if boundary == "mkdir-before-key" {
				if _, err := os.Lstat(keyPath); !os.IsNotExist(err) {
					t.Fatalf("orphan peer directory generated a key: %v", err)
				}
			} else if after, err := os.ReadFile(keyPath); err != nil ||
				!bytes.Equal(after, partial) {
				t.Fatalf("partial O_EXCL key was replaced: %x %v", after, err)
			}
		})
	}

	t.Run("wrong-identity", func(t *testing.T) {
		_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if store, err := newFormalGLMSamplerV2AuthorityRootStoreV1(
			filepath.Join(t.TempDir(), "authority-rock"),
			authority.PeerName, authority.Role, wrongKey,
			fixture.pins); err == nil {
			store.Close()
			t.Fatal("authority root accepted an unpinned signing identity")
		}
	})
}

func TestFormalGLMSamplerV2ContractStoreCASAndValidation(t *testing.T) {
	fixture := formalGLMPhase21SamplerV2TestSetup(
		t, 5, formalGLMPhase21SamplerV2OneDraw)
	rootBase := filepath.Join(t.TempDir(), "authority-rocks")
	contract, _ := formalGLMSamplerV2StoreTestContract(
		t, fixture, formalGLMPhase21SamplerV2OneDraw, rootBase)
	alternate, _ := formalGLMSamplerV2StoreTestContract(
		t, fixture, formalGLMPhase21SamplerV2Full, rootBase)
	dir := filepath.Join(t.TempDir(), "contract-rock")
	store, err := newFormalGLMSamplerV2ContractStoreV1(dir, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Commit(contract); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(alternate); err == nil {
		t.Fatal("ArtifactID accepted a different valid sampler contract")
	}
	loaded, err := store.Load(fixture.artifactID)
	if err != nil || !reflect.DeepEqual(loaded, contract) {
		t.Fatalf("contract CAS conflict changed the winner: %+v %v", loaded, err)
	}

	tampered := contract
	tampered.CustodianSignatures = append(
		[]jointDPBiomedicalGaussianSignature(nil), contract.CustodianSignatures...)
	tampered.CustodianSignatures[0].Signature = append(
		[]byte(nil), tampered.CustodianSignatures[0].Signature...)
	tampered.CustodianSignatures[0].Signature[0] ^= 1
	fresh, err := newFormalGLMSamplerV2ContractStoreV1(
		filepath.Join(t.TempDir(), "fresh-contract-rock"), fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if _, err := fresh.Commit(tampered); err == nil {
		t.Fatal("contract store accepted a non-K-of-K signature set")
	}

	wrongPins := make(map[string]ed25519.PublicKey, len(fixture.pins))
	for peer, pin := range fixture.pins {
		wrongPins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongPins[fixture.artifact.CustodianPeers[0]] = wrongPublic
	wrongStore, err := newFormalGLMSamplerV2ContractStoreV1(dir, wrongPins)
	if err != nil {
		t.Fatal(err)
	}
	defer wrongStore.Close()
	if _, err := wrongStore.Load(fixture.artifactID); err == nil {
		t.Fatal("contract record crossed its pinned consortium")
	}
}

func TestFormalGLMSamplerV2ContractStoreConcurrentExactCAS(t *testing.T) {
	fixture := formalGLMPhase21SamplerV2TestSetup(
		t, 5, formalGLMPhase21SamplerV2OneDraw)
	contract, _ := formalGLMSamplerV2StoreTestContract(
		t, fixture, formalGLMPhase21SamplerV2OneDraw,
		filepath.Join(t.TempDir(), "authority-rocks"))
	const workers = 12
	dir := filepath.Join(t.TempDir(), "contract-rock")
	stores := make([]*formalGLMSamplerV2ContractStoreV1, workers)
	for index := range stores {
		var err error
		stores[index], err = newFormalGLMSamplerV2ContractStoreV1(
			dir, fixture.pins)
		if err != nil {
			t.Fatal(err)
		}
		defer stores[index].Close()
	}
	type result struct {
		replayed bool
		err      error
	}
	results := make(chan result, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			replayed, err := stores[index].Commit(contract)
			results <- result{replayed: replayed, err: err}
		}(index)
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
		t.Fatalf("non-exact contract CAS: created=%d replayed=%d", created, replayed)
	}
}

func TestFormalGLMSamplerV2ContractStoreRejectsUnsafeRecord(t *testing.T) {
	fixture := formalGLMPhase21SamplerV2TestSetup(
		t, 2, formalGLMPhase21SamplerV2OneDraw)
	contract, _ := formalGLMSamplerV2StoreTestContract(
		t, fixture, formalGLMPhase21SamplerV2OneDraw,
		filepath.Join(t.TempDir(), "authority-rocks"))
	for _, attack := range []string{
		"tamper", "noncanonical", "mode", "hardlink", "symlink", "parent-mode",
	} {
		t.Run(attack, func(t *testing.T) {
			store, err := newFormalGLMSamplerV2ContractStoreV1(
				filepath.Join(t.TempDir(), "contract-rock"), fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if _, err := store.Commit(contract); err != nil {
				t.Fatal(err)
			}
			path, err := store.recordPath(fixture.artifactID, false)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch attack {
			case "tamper":
				var record formalGLMSamplerV2ContractRecordV1
				if err := json.Unmarshal(encoded, &record); err != nil {
					t.Fatal(err)
				}
				record.ContractSHA256 = fixture.artifact.CanonicalPlanSHA256
				encoded, err = json.Marshal(record)
				if err == nil {
					err = os.WriteFile(path, encoded, 0o600)
				}
			case "noncanonical":
				err = os.WriteFile(path, append(encoded, '\n'), 0o600)
			case "mode":
				err = os.Chmod(path, 0o644)
			case "hardlink":
				err = os.Link(path, path+".alias")
			case "symlink":
				attacker := filepath.Join(t.TempDir(), "attacker.json")
				if err = os.WriteFile(attacker, encoded, 0o600); err == nil {
					err = os.Remove(path)
				}
				if err == nil {
					err = os.Symlink(attacker, path)
				}
			case "parent-mode":
				err = os.Chmod(filepath.Dir(path), 0o755)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Load(fixture.artifactID); err == nil {
				t.Fatal("unsafe sealed-contract record was accepted")
			}
		})
	}
}
