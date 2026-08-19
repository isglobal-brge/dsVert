package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func formalGLMRegisteredPhase20JobKeyTestCloneV1[T any](
	t testing.TB, value T,
) T {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var cloned T
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func formalGLMRegisteredPhase20JobKeyTestPinsV1(
	pins map[string]ed25519.PublicKey,
) map[string]ed25519.PublicKey {
	cloned := make(map[string]ed25519.PublicKey, len(pins))
	for peer, pin := range pins {
		cloned[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	return cloned
}

func formalGLMRegisteredPhase20JobKeyTestBindingV1(
	t testing.TB,
	core formalGLMRegisteredPhase19AttemptTestCoreV1,
	previousAbandon string,
	previousAttempt string,
) formalGLMRegisteredPhase19AttemptBindingV1 {
	t.Helper()
	recordSHA256, err := formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase19AttemptDomainV1+"/binding-record",
		core.record)
	if err != nil {
		t.Fatal(err)
	}
	attemptID, err := formalGLMRegisteredPhase19AttemptIDV1(
		core.record.Binding.SemanticRootSHA256, previousAbandon)
	if err != nil {
		t.Fatal(err)
	}
	scheduleRoot, err := formalGLMRegisteredPhase19AttemptScheduleRootV1(
		core.record.Binding.SemanticRootSHA256, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	return formalGLMRegisteredPhase19AttemptBindingV1{
		ArtifactID:               core.record.Binding.ArtifactID,
		SourceContractCoreSHA256: core.record.Binding.SourceContractCoreSHA256,
		SourceContractSHA256:     core.record.Binding.SourceContractSHA256,
		PinsetSHA256:             core.record.Binding.PinsetSHA256,
		SemanticRootSHA256:       core.record.Binding.SemanticRootSHA256,
		BindingRecordSHA256:      recordSHA256,
		RegisteredExecutionPlanSHA256: core.record.Binding.
			RegisteredExecutionPlanSHA256,
		PreviousAbandonSHA256: previousAbandon,
		PreviousAttemptID:     previousAttempt,
		AttemptID:             attemptID,
		ScheduleRootSHA256:    scheduleRoot,
		OpeningsPerformed:     0,
		ProductionReady:       false,
	}
}

func formalGLMRegisteredPhase20JobKeyTestDifferentSHA256V1(value string) string {
	digest := sha256.Sum256([]byte("different/" + value))
	return hex.EncodeToString(digest[:])
}

func formalGLMRegisteredPhase20JobKeyTestOpenV1(
	t testing.TB,
	root, peer string,
	core formalGLMRegisteredPhase19AttemptTestCoreV1,
) *formalGLMRegisteredPhase20JobKeyProviderV1 {
	t.Helper()
	provider, err := newFormalGLMRegisteredPhase20JobKeyProviderV1(
		root, core.source.contract, core.source.inputs.identities.public,
		core.record, peer)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func formalGLMRegisteredPhase20JobKeyTestAssertFilesystemV1(
	t testing.TB,
	root string,
) {
	t.Helper()
	files := 0
	if err := filepath.WalkDir(root,
		func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if info.Mode().Perm() != 0o700 ||
					!formalFinalizerHandoffPrivateOwnedDirectory(info) {
					t.Fatalf("unsafe job-key directory %s: %o", path,
						info.Mode().Perm())
				}
				return nil
			}
			files++
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
				info.Size() != 32 || !exactGCPrivateOwnedRegular(info) {
				t.Fatalf("unsafe job-key root %s: %o/%d", path,
					info.Mode().Perm(), info.Size())
			}
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	if files != 1 {
		t.Fatalf("job-key provider persisted %d files, want one raw root", files)
	}
}

func TestFormalGLMRegisteredPhase20JobKeysK2RockLocalAndFailClosed(
	t *testing.T,
) {
	core := formalGLMRegisteredPhase19AttemptTestCoreK2(t)
	peers := core.source.plan.DesignatedComputePeers
	binding := formalGLMRegisteredPhase20JobKeyTestBindingV1(
		t, core, formalGLMRegisteredPhase19AttemptZeroPreviousV1,
		formalGLMRegisteredPhase19AttemptZeroPreviousV1)

	root := filepath.Join(t.TempDir(), "garbler-rock")
	provider := formalGLMRegisteredPhase20JobKeyTestOpenV1(
		t, root, peers[0], core)
	encoded, err := json.Marshal(provider)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("job-key provider became serializable: %s / %v", encoded, err)
	}
	providerType := reflect.TypeOf(provider).Elem()
	for index := 0; index < providerType.NumField(); index++ {
		if providerType.Field(index).IsExported() {
			t.Fatal("job-key provider exposes internal state")
		}
	}
	key, err := provider.DeriveAttemptKey(binding)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := provider.DeriveAttemptKey(binding)
	if err != nil || key != replay {
		t.Fatalf("same registered attempt derived another key: %v", err)
	}
	aead, err := formalGLMPhase20HandoffAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	plaintext := []byte("registered-phase20-job-key")
	ciphertext := aead.Seal(nil, nonce, plaintext, []byte(binding.AttemptID))
	opened, err := aead.Open(nil, nonce, ciphertext, []byte(binding.AttemptID))
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("derived key was not an in-memory AEAD key: %v", err)
	}
	rootBytes, err := os.ReadFile(filepath.Join(root, provider.keyRelativePath))
	if err != nil || len(rootBytes) != 32 || bytes.Equal(rootBytes, key[:]) {
		t.Fatalf("persisted root leaked or matched derived key: %v", err)
	}
	formalGLMRegisteredPhase20JobKeyTestAssertFilesystemV1(t, root)
	keyRelativePath := provider.keyRelativePath
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	if provider.storageRoot != [32]byte{} {
		t.Fatal("Close retained the raw storage root")
	}
	if _, err := provider.DeriveAttemptKey(binding); err == nil {
		t.Fatal("closed job-key provider derived an attempt key")
	}
	restarted := formalGLMRegisteredPhase20JobKeyTestOpenV1(
		t, root, peers[0], core)
	restartedKey, err := restarted.DeriveAttemptKey(binding)
	if err != nil || restartedKey != key ||
		restarted.keyRelativePath != keyRelativePath {
		t.Fatalf("restart did not recover the same root-derived key: %v", err)
	}
	defer restarted.Close()

	secondBinding := formalGLMRegisteredPhase20JobKeyTestBindingV1(
		t, core, formalGLMRegisteredPhase20JobKeyTestDifferentSHA256V1(
			binding.PreviousAbandonSHA256),
		formalGLMRegisteredPhase20JobKeyTestDifferentSHA256V1(
			binding.PreviousAttemptID))
	secondKey, err := restarted.DeriveAttemptKey(secondBinding)
	if err != nil || secondKey == key {
		t.Fatalf("another attempt did not derive an independent key: %v", err)
	}
	evaluatorRoot := filepath.Join(t.TempDir(), "evaluator-rock")
	evaluator := formalGLMRegisteredPhase20JobKeyTestOpenV1(
		t, evaluatorRoot, peers[1], core)
	defer evaluator.Close()
	evaluatorKey, err := evaluator.DeriveAttemptKey(binding)
	if err != nil || evaluatorKey == key {
		t.Fatalf("other Rock-local authority reused the key: %v", err)
	}

	runtimeRecordSHA256, err := formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase19EphemeralDomainV1+"/validated-binding-record",
		core.record)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*formalGLMRegisteredPhase19AttemptBindingV1){
		"artifact": func(value *formalGLMRegisteredPhase19AttemptBindingV1) {
			value.ArtifactID =
				formalGLMRegisteredPhase20JobKeyTestDifferentSHA256V1(
					value.ArtifactID)
		},
		"contract-core": func(value *formalGLMRegisteredPhase19AttemptBindingV1) {
			value.SourceContractCoreSHA256 =
				formalGLMRegisteredPhase20JobKeyTestDifferentSHA256V1(
					value.SourceContractCoreSHA256)
		},
		"contract": func(value *formalGLMRegisteredPhase19AttemptBindingV1) {
			value.SourceContractSHA256 =
				formalGLMRegisteredPhase20JobKeyTestDifferentSHA256V1(
					value.SourceContractSHA256)
		},
		"pinset": func(value *formalGLMRegisteredPhase19AttemptBindingV1) {
			value.PinsetSHA256 =
				formalGLMRegisteredPhase20JobKeyTestDifferentSHA256V1(
					value.PinsetSHA256)
		},
		"semantic": func(value *formalGLMRegisteredPhase19AttemptBindingV1) {
			value.SemanticRootSHA256 =
				formalGLMRegisteredPhase20JobKeyTestDifferentSHA256V1(
					value.SemanticRootSHA256)
		},
		"record": func(value *formalGLMRegisteredPhase19AttemptBindingV1) {
			value.BindingRecordSHA256 =
				formalGLMRegisteredPhase20JobKeyTestDifferentSHA256V1(
					value.BindingRecordSHA256)
		},
		"runtime-record-domain": func(
			value *formalGLMRegisteredPhase19AttemptBindingV1,
		) {
			value.BindingRecordSHA256 = runtimeRecordSHA256
		},
		"plan": func(value *formalGLMRegisteredPhase19AttemptBindingV1) {
			value.RegisteredExecutionPlanSHA256 =
				formalGLMRegisteredPhase20JobKeyTestDifferentSHA256V1(
					value.RegisteredExecutionPlanSHA256)
		},
		"predecessor": func(value *formalGLMRegisteredPhase19AttemptBindingV1) {
			value.PreviousAbandonSHA256 =
				formalGLMRegisteredPhase20JobKeyTestDifferentSHA256V1(
					value.PreviousAbandonSHA256)
		},
		"previous-attempt": func(value *formalGLMRegisteredPhase19AttemptBindingV1) {
			value.PreviousAttemptID =
				formalGLMRegisteredPhase20JobKeyTestDifferentSHA256V1(
					value.PreviousAttemptID)
		},
		"attempt": func(value *formalGLMRegisteredPhase19AttemptBindingV1) {
			value.AttemptID = formalGLMRegisteredPhase20JobKeyTestDifferentSHA256V1(
				value.AttemptID)
		},
		"schedule": func(value *formalGLMRegisteredPhase19AttemptBindingV1) {
			value.ScheduleRootSHA256 =
				formalGLMRegisteredPhase20JobKeyTestDifferentSHA256V1(
					value.ScheduleRootSHA256)
		},
		"openings": func(value *formalGLMRegisteredPhase19AttemptBindingV1) {
			value.OpeningsPerformed = 1
		},
		"production": func(value *formalGLMRegisteredPhase19AttemptBindingV1) {
			value.ProductionReady = true
		},
	} {
		t.Run("binding-"+name, func(t *testing.T) {
			tampered := binding
			mutate(&tampered)
			if derived, err := restarted.DeriveAttemptKey(tampered); err == nil ||
				derived != [32]byte{} {
				t.Fatal("tampered attempt binding derived a key")
			}
		})
	}

	for name, invalid := range map[string]func(
		*formalGLMSourceContractV1,
		map[string]ed25519.PublicKey,
		*formalGLMRegisteredPhase19BindingRecordV1,
		*string,
	){
		"contract": func(contract *formalGLMSourceContractV1,
			_ map[string]ed25519.PublicKey,
			_ *formalGLMRegisteredPhase19BindingRecordV1, _ *string) {
			contract.CoreSHA256 =
				formalGLMRegisteredPhase20JobKeyTestDifferentSHA256V1(
					contract.CoreSHA256)
		},
		"pins": func(_ *formalGLMSourceContractV1,
			pins map[string]ed25519.PublicKey,
			_ *formalGLMRegisteredPhase19BindingRecordV1, peer *string) {
			pins[*peer][0] ^= 1
		},
		"record": func(_ *formalGLMSourceContractV1,
			_ map[string]ed25519.PublicKey,
			record *formalGLMRegisteredPhase19BindingRecordV1, _ *string) {
			record.Binding.SemanticRootSHA256 =
				formalGLMRegisteredPhase20JobKeyTestDifferentSHA256V1(
					record.Binding.SemanticRootSHA256)
		},
		"peer": func(_ *formalGLMSourceContractV1,
			_ map[string]ed25519.PublicKey,
			_ *formalGLMRegisteredPhase19BindingRecordV1, peer *string) {
			*peer = "not-an-authority"
		},
	} {
		t.Run("constructor-"+name, func(t *testing.T) {
			contract := formalGLMRegisteredPhase20JobKeyTestCloneV1(
				t, core.source.contract)
			pins := formalGLMRegisteredPhase20JobKeyTestPinsV1(
				core.source.inputs.identities.public)
			record := formalGLMRegisteredPhase20JobKeyTestCloneV1(t, core.record)
			peer := peers[0]
			invalid(&contract, pins, &record, &peer)
			invalidRoot := filepath.Join(t.TempDir(), "invalid-rock")
			if value, err := newFormalGLMRegisteredPhase20JobKeyProviderV1(
				invalidRoot, contract, pins, record, peer); err == nil {
				_ = value.Close()
				t.Fatal("invalid registered evidence created a job-key provider")
			}
			if _, err := os.Lstat(invalidRoot); !os.IsNotExist(err) {
				t.Fatal("invalid evidence touched the Rock filesystem")
			}
		})
	}

	for _, scenario := range []string{
		"missing", "short", "mode", "hardlink", "symlink", "directory-mode",
	} {
		t.Run("filesystem-"+scenario, func(t *testing.T) {
			caseRoot := filepath.Join(t.TempDir(), "rock")
			value := formalGLMRegisteredPhase20JobKeyTestOpenV1(
				t, caseRoot, peers[0], core)
			keyPath := filepath.Join(caseRoot, value.keyRelativePath)
			keyDirectory := filepath.Dir(keyPath)
			if err := value.Close(); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "missing":
				if err := os.Remove(keyPath); err != nil {
					t.Fatal(err)
				}
			case "short":
				if err := os.Truncate(keyPath, 7); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(keyPath, 0o640); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(keyPath, keyPath+".alias"); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				outside := filepath.Join(t.TempDir(), "outside-key")
				if err := os.WriteFile(outside, make([]byte, 32), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(keyPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, keyPath); err != nil {
					t.Fatal(err)
				}
			case "directory-mode":
				if err := os.Chmod(keyDirectory, 0o750); err != nil {
					t.Fatal(err)
				}
			}
			if reopened, err := newFormalGLMRegisteredPhase20JobKeyProviderV1(
				caseRoot, core.source.contract,
				core.source.inputs.identities.public, core.record,
				peers[0]); err == nil {
				_ = reopened.Close()
				t.Fatal("unsafe or burned root was accepted")
			}
			if scenario == "missing" {
				if _, err := os.Lstat(keyPath); !os.IsNotExist(err) {
					t.Fatal("burned marker regenerated a missing storage root")
				}
			}
		})
	}

	clear(key[:])
	clear(replay[:])
	clear(restartedKey[:])
	clear(secondKey[:])
	clear(evaluatorKey[:])
}
