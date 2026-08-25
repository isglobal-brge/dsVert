package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type formalGLMPhase21RockTestAuthority struct {
	root        string
	contract    string
	pinset      string
	secret      string
	storageRoot [32]byte
	operation   formalGLMPhase21RockPreflightOperation
}

func formalGLMPhase21RockTestRoot(t testing.TB, suffix string) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(base, suffix)
}

func formalGLMPhase21RockTestWriteJSON(t testing.TB, path string, value any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

func formalGLMPhase21RockTestPrepareAuthority(t testing.TB,
	fixture formalGLMPhase21SamplerV2TestFixture, index int,
) formalGLMPhase21RockTestAuthority {
	t.Helper()
	authority := fixture.artifact.NoiseAuthorities[index]
	state := formalGLMPhase21RockTestRoot(t, "state")
	root := filepath.Join(state, authority.PeerName)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{state, root} {
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	contractPath := filepath.Join(root, "assets-v1", "contract.json")
	pinsetPath := filepath.Join(root, "assets-v1", "pinset.json")
	secretPath := filepath.Join(root, "commands-v1", "preflight-secret.json")
	pinned := make(map[string]string, len(fixture.pins))
	for peer, pin := range fixture.pins {
		pinned[peer] = base64.StdEncoding.EncodeToString(pin)
	}
	formalGLMPhase21RockTestWriteJSON(t, pinsetPath,
		formalGLMPhase21RockPinset{
			Version:         formalGLMPhase21RockPinsetVersion,
			Family:          formalFinalizerHandoffFamilyGLM,
			Purpose:         formalGLMPhase21RockPurpose,
			PinnedPublicKey: pinned,
		})
	formalGLMPhase21RockTestWriteJSON(t, contractPath, fixture.contract)
	storageRoot := sha256.Sum256([]byte(
		t.Name() + "/sticky/" + authority.PeerName))
	formalGLMPhase21RockTestWriteJSON(t, secretPath,
		formalGLMPhase21RockPreflightSecret{
			Version:           formalGLMPhase21RockSecretVersion,
			Family:            formalFinalizerHandoffFamilyGLM,
			Purpose:           formalGLMPhase21RockPurpose,
			Action:            formalGLMPhase21RockActionPreflight,
			StickyStorageRoot: base64.StdEncoding.EncodeToString(storageRoot[:]),
			SigningPrivateKey: base64.StdEncoding.EncodeToString(
				fixture.keys[authority.PeerName]),
		})
	return formalGLMPhase21RockTestAuthority{
		root: root, contract: contractPath, pinset: pinsetPath,
		secret: secretPath, storageRoot: storageRoot,
		operation: formalGLMPhase21RockPreflightOperation{
			ArtifactContractPath: contractPath, PinsetPath: pinsetPath,
			PeerName: authority.PeerName, SecretBundlePath: secretPath,
		},
	}
}

func formalGLMPhase21RockTestRefreshSecret(t testing.TB,
	fixture formalGLMPhase21SamplerV2TestFixture, index int,
	authority formalGLMPhase21RockTestAuthority,
) {
	t.Helper()
	peer := fixture.artifact.NoiseAuthorities[index].PeerName
	formalGLMPhase21RockTestWriteJSON(t, authority.secret,
		formalGLMPhase21RockPreflightSecret{
			Version: formalGLMPhase21RockSecretVersion,
			Family:  formalFinalizerHandoffFamilyGLM,
			Purpose: formalGLMPhase21RockPurpose,
			Action:  formalGLMPhase21RockActionPreflight,
			StickyStorageRoot: base64.StdEncoding.EncodeToString(
				authority.storageRoot[:]),
			SigningPrivateKey: base64.StdEncoding.EncodeToString(
				fixture.keys[peer]),
		})
}

func formalGLMPhase21RockTestRunPreflight(t testing.TB,
	authority formalGLMPhase21RockTestAuthority,
) formalGLMPhase21RockLifecycleResponse {
	t.Helper()
	operation, err := json.Marshal(authority.operation)
	if err != nil {
		t.Fatal(err)
	}
	response, err := formalGLMPhase21RockRun(
		authority.root, false, formalGLMPhase21RockActionPreflight, operation)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestFormalGLMPhase21RockPreflightK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMPhase21SamplerV2TestSetup(
				t, custodians, formalGLMPhase21SamplerV2OneDraw)
			var authorities [2]formalGLMPhase21RockTestAuthority
			var absent [2]formalGLMPhase21RockPreflightRecord
			for index := range authorities {
				authorities[index] = formalGLMPhase21RockTestPrepareAuthority(
					t, fixture, index)
				response := formalGLMPhase21RockTestRunPreflight(
					t, authorities[index])
				if response.State != formalGLMPhase21RockStateAbsent ||
					response.ArtifactID != fixture.artifactID ||
					response.Preflight == nil || response.Replayed ||
					response.CertificateSHA256 != "" {
					t.Fatalf("unexpected absent preflight: %+v", response)
				}
				if _, err := os.Lstat(authorities[index].secret); !os.IsNotExist(err) {
					t.Fatal("preflight secret survived durable receipt CAS")
				}
				absent[index] = *response.Preflight
			}
			state, publication, err := formalGLMPhase21RockPreflightPair(
				absent, fixture.contract, fixture.pins)
			if err != nil || state != formalGLMPhase21RockStateAbsent ||
				publication != nil {
				t.Fatalf("absent pair: state=%s publication=%v err=%v",
					state, publication, err)
			}

			sealed := formalGLMPhase21PublicV2TestCertificate(t, fixture)
			published := absent
			for index := range authorities {
				if index == 0 {
					store, err := newFormalGLMPhase21StickyReleaseStore(
						filepath.Join(authorities[index].root,
							"formal-glm-sticky-v2"),
						fixture.artifact.NoiseAuthorities[index].PeerName,
						authorities[index].storageRoot, fixture.pins)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := store.CommitPublicV2(sealed); err != nil {
						store.close()
						t.Fatal(err)
					}
					store.close()
				}
				formalGLMPhase21RockTestRefreshSecret(
					t, fixture, index, authorities[index])
				response := formalGLMPhase21RockTestRunPreflight(
					t, authorities[index])
				published[index] = *response.Preflight
			}
			state, repair, err := formalGLMPhase21RockPreflightPair(
				published, fixture.contract, fixture.pins)
			if err != nil || state != formalGLMPhase21RockStateRepairPending ||
				repair == nil || !reflectPublicV2Equal(*repair, sealed) {
				t.Fatalf("repair preflight: state=%s err=%v", state, err)
			}

			store, err := newFormalGLMPhase21StickyReleaseStore(
				filepath.Join(authorities[1].root, "formal-glm-sticky-v2"),
				fixture.artifact.NoiseAuthorities[1].PeerName,
				authorities[1].storageRoot, fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.CommitPublicV2(*repair); err != nil {
				store.close()
				t.Fatal(err)
			}
			store.close()
			formalGLMPhase21RockTestRefreshSecret(t, fixture, 1, authorities[1])
			response := formalGLMPhase21RockTestRunPreflight(t, authorities[1])
			published[1] = *response.Preflight
			state, replay, err := formalGLMPhase21RockPreflightPair(
				published, fixture.contract, fixture.pins)
			if err != nil || state != formalGLMPhase21RockStatePublished ||
				replay == nil || !reflectPublicV2Equal(*replay, sealed) {
				t.Fatalf("published preflight: state=%s err=%v", state, err)
			}

			encoded, err := json.Marshal(replay)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range [][]byte{
				[]byte(`"capsule_id"`), []byte(`"reservation`),
				[]byte(`"ledger`), []byte(`"lifetime`), []byte(`"epoch`),
				[]byte(base64.StdEncoding.EncodeToString(
					fixture.keys[fixture.artifact.NoiseAuthorities[0].PeerName])),
			} {
				if bytes.Contains(encoded, forbidden) {
					t.Fatalf("preflight relay leaked %q", forbidden)
				}
			}
		})
	}
}

func reflectPublicV2Equal(left, right formalGLMPhase21PublicCertificateV2) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func TestFormalGLMPhase21RockPreflightRejectsReorderAndSplitBrain(t *testing.T) {
	fixture := formalGLMPhase21SamplerV2TestSetup(
		t, 2, formalGLMPhase21SamplerV2OneDraw)
	sealed := formalGLMPhase21PublicV2TestCertificate(t, fixture)
	var records [2]formalGLMPhase21RockPreflightRecord
	for index, authority := range fixture.artifact.NoiseAuthorities {
		encoded, err := json.Marshal(sealed)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(append(
			[]byte(formalGLMPhase21PublicV2Domain+"/sealed-certificate|"),
			encoded...))
		receipt := formalGLMPhase21RockPreflightReceipt{
			Version:      formalGLMPhase21RockRecordVersion,
			Purpose:      formalGLMPhase21RockPreflightPurpose,
			ArtifactID:   fixture.artifactID,
			PinsetSHA256: fixture.contract.PinsetSHA256,
			PeerName:     authority.PeerName, PeerID: authority.PeerID,
			Role: authority.Role, State: formalGLMPhase21RockStatePublished,
			CertificateSHA256: hex.EncodeToString(digest[:]),
		}
		message, err := formalGLMPhase21RockPreflightMessage(receipt)
		if err != nil {
			t.Fatal(err)
		}
		receipt.Signature = ed25519.Sign(
			fixture.keys[authority.PeerName], message)
		copy := sealed
		records[index] = formalGLMPhase21RockPreflightRecord{
			Version: formalGLMPhase21RockRecordVersion,
			Family:  formalFinalizerHandoffFamilyGLM,
			Purpose: formalGLMPhase21RockPreflightPurpose,
			Receipt: receipt, Publication: &copy,
		}
	}
	if _, _, err := formalGLMPhase21RockPreflightPair(
		[2]formalGLMPhase21RockPreflightRecord{records[1], records[0]},
		fixture.contract, fixture.pins); err == nil {
		t.Fatal("preflight accepted reordered authorities")
	}

	divergent := sealed
	divergent.AuthorityReceipts = nil
	divergent.ClampedScaledValues = append(
		[]string(nil), sealed.ClampedScaledValues...)
	divergent.ClampedScaledValues[0] = "12"
	var err error
	divergent.VectorSHA256, err = jointDPBiomedicalGaussianOneDrawVectorSHA256(
		divergent.ClampedScaledValues)
	if err != nil {
		t.Fatal(err)
	}
	signatures := make([]jointDPBiomedicalGaussianSignature, 2)
	for index, authority := range fixture.artifact.NoiseAuthorities {
		signatures[index], err = formalGLMPhase21SignPublicCertificateV2(
			divergent, authority.PeerName, fixture.keys[authority.PeerName],
			fixture.pins)
		if err != nil {
			t.Fatal(err)
		}
	}
	divergent, err = formalGLMPhase21SealPublicCertificateV2(
		divergent, signatures, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(divergent)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(append(
		[]byte(formalGLMPhase21PublicV2Domain+"/sealed-certificate|"),
		encoded...))
	records[1].Publication = &divergent
	records[1].Receipt.CertificateSHA256 = hex.EncodeToString(digest[:])
	records[1].Receipt.Signature = nil
	message, err := formalGLMPhase21RockPreflightMessage(records[1].Receipt)
	if err != nil {
		t.Fatal(err)
	}
	records[1].Receipt.Signature = ed25519.Sign(
		fixture.keys[records[1].Receipt.PeerName], message)
	if _, _, err := formalGLMPhase21RockPreflightPair(
		records, fixture.contract, fixture.pins); err == nil {
		t.Fatal("preflight accepted two valid but divergent publications")
	}
}

func TestFormalGLMPhase21RockPreflightFailsClosedAndRedactsErrors(t *testing.T) {
	fixture := formalGLMPhase21SamplerV2TestSetup(
		t, 2, formalGLMPhase21SamplerV2OneDraw)
	authority := formalGLMPhase21RockTestPrepareAuthority(t, fixture, 0)
	wrongRoot := formalGLMPhase21RockTestRoot(t, "other-state")
	wrongAuthorityRoot := filepath.Join(wrongRoot,
		fixture.artifact.NoiseAuthorities[1].PeerName)
	if err := os.MkdirAll(wrongAuthorityRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	operation := authority.operation
	operation.PeerName = fixture.artifact.NoiseAuthorities[1].PeerName
	encodedOperation, err := json.Marshal(operation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := formalGLMPhase21RockRun(authority.root, false,
		formalGLMPhase21RockActionPreflight, encodedOperation); err == nil {
		t.Fatal("preflight accepted peer from another authority root")
	}

	secretToken := "super-secret-token-that-must-not-appear"
	if err := os.WriteFile(authority.secret,
		[]byte(`{"version":"`+secretToken+`","padding":"`+
			`0123456789abcdef0123456789abcdef0123456789abcdef"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	encodedOperation, err = json.Marshal(authority.operation)
	if err != nil {
		t.Fatal(err)
	}
	err = handleFormalGLMPhase21RockLifecycle(
		authority.root, formalGLMPhase21RockActionPreflight, encodedOperation)
	if err == nil || bytes.Contains([]byte(err.Error()), []byte(secretToken)) ||
		bytes.Contains([]byte(err.Error()), []byte(authority.root)) ||
		bytes.Contains([]byte(err.Error()), []byte(authority.secret)) {
		t.Fatalf("handler error was not coarse: %v", err)
	}

	fullFixture := formalGLMPhase21SamplerV2TestSetup(
		t, 2, formalGLMPhase21SamplerV2Full)
	fullAuthority := formalGLMPhase21RockTestPrepareAuthority(t, fullFixture, 0)
	fullOperation, err := json.Marshal(fullAuthority.operation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := formalGLMPhase21RockRun(fullAuthority.root, false,
		formalGLMPhase21RockActionPreflight, fullOperation); err == nil {
		t.Fatal("independent_full_v2 entered productive preflight")
	}
	if _, err := os.Lstat(fullAuthority.secret); err != nil {
		t.Fatal("unsupported backend touched preflight secret")
	}
}

type formalGLMPhase21RockStageTestAuthority struct {
	root          string
	secret        string
	spool         string
	operation     formalGLMPhase21RockStageOperation
	transportRoot [32]byte
	phase20Record string
}

func formalGLMPhase21RockTestAbsentPreflightRecords(t testing.TB,
	contract formalGLMPhase21SamplerV2Contract,
	pins map[string]ed25519.PublicKey,
	keys map[string]ed25519.PrivateKey,
) [2]formalGLMPhase21RockPreflightRecord {
	t.Helper()
	var records [2]formalGLMPhase21RockPreflightRecord
	for index, authority := range contract.Artifact.NoiseAuthorities {
		receipt := formalGLMPhase21RockPreflightReceipt{
			Version:      formalGLMPhase21RockRecordVersion,
			Purpose:      formalGLMPhase21RockPreflightPurpose,
			ArtifactID:   contract.ArtifactID,
			PinsetSHA256: contract.PinsetSHA256,
			PeerName:     authority.PeerName, PeerID: authority.PeerID,
			Role: authority.Role, State: formalGLMPhase21RockStateAbsent,
			ProductionReady: false,
		}
		message, err := formalGLMPhase21RockPreflightMessage(receipt)
		if err != nil {
			t.Fatal(err)
		}
		receipt.Signature = ed25519.Sign(keys[authority.PeerName], message)
		records[index] = formalGLMPhase21RockPreflightRecord{
			Version: formalGLMPhase21RockRecordVersion,
			Family:  formalFinalizerHandoffFamilyGLM,
			Purpose: formalGLMPhase21RockPreflightPurpose,
			Receipt: receipt, ProductionReady: false,
		}
		if err := formalGLMPhase21RockValidatePreflightRecord(
			records[index], contract, pins); err != nil {
			t.Fatal(err)
		}
	}
	return records
}

func formalGLMPhase21RockTestPrepareSpool(t testing.TB, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"inbound.bin", "outbound.bin", "exchange.hb", "worker.hb",
	} {
		value := []byte{}
		if name == "exchange.hb" || name == "worker.hb" {
			value = []byte(".")
		}
		if err := os.WriteFile(filepath.Join(path, name), value, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"inbound.segments", "outbound.segments"} {
		if err := os.Mkdir(filepath.Join(path, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(path, "inbound.state"),
		[]byte(exactGCInboundStateInitial), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"inbound.ack", "outbound.head", "outbound.ack"} {
		if err := os.WriteFile(filepath.Join(path, name), []byte("0"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func formalGLMPhase21RockTestStageAuthorities(t *testing.T,
	fixture formalGLMPhase21TestFixture,
	contract formalGLMPhase21SamplerV2Contract,
	samplerAuthorizations []formalGLMPhase21SamplerV2Authorization,
) [2]formalGLMPhase21RockStageTestAuthority {
	t.Helper()
	pinned := make(map[string]string, len(fixture.formal.identities.public))
	for peer, pin := range fixture.formal.identities.public {
		pinned[peer] = base64.StdEncoding.EncodeToString(pin)
	}
	preflight := formalGLMPhase21RockTestAbsentPreflightRecords(
		t, contract, fixture.formal.identities.public,
		fixture.formal.identities.private)
	state := formalGLMPhase21RockTestRoot(t, "stage-state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0o700); err != nil {
		t.Fatal(err)
	}
	var result [2]formalGLMPhase21RockStageTestAuthority
	for index, authority := range contract.Artifact.NoiseAuthorities {
		root := filepath.Join(state, authority.PeerName)
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal(err)
		}
		asset := func(name string) string {
			return filepath.Join(root, "assets-v1", name+".json")
		}
		contractPath, pinsetPath := asset("contract"), asset("pinset")
		formalGLMPhase21RockTestWriteJSON(t, contractPath, contract)
		formalGLMPhase21RockTestWriteJSON(t, pinsetPath,
			formalGLMPhase21RockPinset{
				Version:         formalGLMPhase21RockPinsetVersion,
				Family:          formalFinalizerHandoffFamilyGLM,
				Purpose:         formalGLMPhase21RockPurpose,
				PinnedPublicKey: pinned,
			})
		capsulePath, requestPath := asset("capsule"), asset("request")
		backendSignaturesPath := asset("backend-signatures")
		workerSignaturesPath := asset("worker-signatures")
		samplerAuthorizationsPath := asset("sampler-authorizations")
		formalGLMPhase21RockTestWriteJSON(t, capsulePath, fixture.capsule)
		formalGLMPhase21RockTestWriteJSON(t, requestPath, fixture.request)
		formalGLMPhase21RockTestWriteJSON(
			t, backendSignaturesPath, fixture.backendSignatures)
		formalGLMPhase21RockTestWriteJSON(
			t, workerSignaturesPath, fixture.workerSignatures)
		formalGLMPhase21RockTestWriteJSON(
			t, samplerAuthorizationsPath, samplerAuthorizations)
		var preflightPaths [2]string
		for receiptIndex, receipt := range preflight {
			preflightPaths[receiptIndex] = filepath.Join(root, "inbox-v1",
				"preflight-"+receipt.Receipt.Role+".json")
			formalGLMPhase21RockTestWriteJSON(
				t, preflightPaths[receiptIndex], receipt)
		}

		source, _, err := fixture.stores[authority.PeerName].Load()
		if err != nil {
			t.Fatal(err)
		}
		backendKey := source.backend
		phase20Root := sha256.Sum256([]byte(
			t.Name() + "/phase20/" + authority.PeerName))
		target, err := newFormalGLMPhase20HandoffStore(
			filepath.Join(root, "formal-glm-phase20-handoff"),
			fixture.stores[authority.PeerName].semanticRoot,
			authority.PeerName, phase20Root, backendKey,
			fixture.formal.identities.public)
		if err != nil {
			source.clear()
			t.Fatal(err)
		}
		if _, err := target.Commit(source.Plan, source.Context, source.Result); err != nil {
			target.close()
			source.clear()
			t.Fatal(err)
		}
		phase20Record := target.recordPath
		target.close()
		source.clear()

		stickyRoot := sha256.Sum256([]byte(
			t.Name() + "/sticky/" + authority.PeerName))
		transportRoot := sha256.Sum256([]byte(
			t.Name() + "/transport/" + authority.PeerName))
		authorityRoot := fixture.seeds[authority.PeerName]
		secretPath := filepath.Join(root, "commands-v1", "stage-secret.json")
		formalGLMPhase21RockTestWriteJSON(t, secretPath,
			formalGLMPhase21RockStageSecret{
				Version:            formalGLMPhase21RockSecretVersion,
				Family:             formalFinalizerHandoffFamilyGLM,
				Purpose:            formalGLMPhase21RockPurpose,
				Action:             formalGLMPhase21RockActionStage,
				StickyStorageRoot:  base64.StdEncoding.EncodeToString(stickyRoot[:]),
				Phase20StorageRoot: base64.StdEncoding.EncodeToString(phase20Root[:]),
				BackendKey:         base64.StdEncoding.EncodeToString(backendKey[:]),
				AuthorityRoot:      base64.StdEncoding.EncodeToString(authorityRoot[:]),
				AuthoritySeed:      base64.StdEncoding.EncodeToString(authorityRoot[:]),
				TransportStorageRoot: base64.StdEncoding.EncodeToString(
					transportRoot[:]),
				SigningPrivateKey: base64.StdEncoding.EncodeToString(
					fixture.formal.identities.private[authority.PeerName]),
			})
		spool := filepath.Join(root, "formal-glm-exact-gc-v2", contract.ArtifactID)
		formalGLMPhase21RockTestPrepareSpool(t, spool)
		result[index] = formalGLMPhase21RockStageTestAuthority{
			root: root, secret: secretPath, spool: spool,
			transportRoot: transportRoot, phase20Record: phase20Record,
			operation: formalGLMPhase21RockStageOperation{
				ArtifactContractPath: contractPath, PinsetPath: pinsetPath,
				PreflightRecordPaths:      preflightPaths,
				PeerName:                  authority.PeerName,
				Phase20SemanticRootSHA256: fixture.stores[authority.PeerName].semanticRoot,
				CapsulePath:               capsulePath, RequestPath: requestPath,
				BackendSignaturesPath:     backendSignaturesPath,
				WorkerSignaturesPath:      workerSignaturesPath,
				SamplerAuthorizationsPath: samplerAuthorizationsPath,
				SpoolDir:                  spool, MaxSpoolBytes: 64 << 20, TTLSeconds: 30,
				SecretBundlePath: secretPath,
			},
		}
		clear(backendKey[:])
	}
	return result
}

func formalGLMPhase21RockTestRefreshStageSecret(t testing.TB,
	fixture formalGLMPhase21TestFixture,
	contract formalGLMPhase21SamplerV2Contract, index int,
	authority formalGLMPhase21RockStageTestAuthority,
) {
	t.Helper()
	peer := contract.Artifact.NoiseAuthorities[index].PeerName
	source, _, err := fixture.stores[peer].Load()
	if err != nil {
		t.Fatal(err)
	}
	backendKey := source.backend
	source.clear()
	phase20Root := sha256.Sum256([]byte(t.Name() + "/phase20/" + peer))
	stickyRoot := sha256.Sum256([]byte(t.Name() + "/sticky/" + peer))
	seed := fixture.seeds[peer]
	formalGLMPhase21RockTestWriteJSON(t, authority.secret,
		formalGLMPhase21RockStageSecret{
			Version:            formalGLMPhase21RockSecretVersion,
			Family:             formalFinalizerHandoffFamilyGLM,
			Purpose:            formalGLMPhase21RockPurpose,
			Action:             formalGLMPhase21RockActionStage,
			StickyStorageRoot:  base64.StdEncoding.EncodeToString(stickyRoot[:]),
			Phase20StorageRoot: base64.StdEncoding.EncodeToString(phase20Root[:]),
			BackendKey:         base64.StdEncoding.EncodeToString(backendKey[:]),
			AuthorityRoot:      base64.StdEncoding.EncodeToString(seed[:]),
			AuthoritySeed:      base64.StdEncoding.EncodeToString(seed[:]),
			TransportStorageRoot: base64.StdEncoding.EncodeToString(
				authority.transportRoot[:]),
			SigningPrivateKey: base64.StdEncoding.EncodeToString(
				fixture.formal.identities.private[peer]),
		})
	clear(backendKey[:])
}

func TestFormalGLMPhase21RockStageLocalK2K3K5(t *testing.T) {
	formalGLMPhase21RockFullLifecycleK2K3K5(t, false)
}

func formalGLMPhase21RockFullLifecycleK2K3K5(t *testing.T, registered bool) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMPhase21TestSetup(t, custodians, "binomial")
			defer fixture.close()
			reference := fixture.formal.ctx.ComputePeers[0]
			runtime, _, err := formalGLMPhase21LoadAndAdmit(
				fixture.stores[reference], fixture.capsule, fixture.request,
				fixture.backendSignatures, fixture.workerSignatures)
			if err != nil {
				t.Fatal(err)
			}
			artifact, artifactID, err := formalGLMPhase21BuildCanonicalArtifact(
				runtime.Admission.Productive.Compiled.Binding,
				runtime.Source.Plan, fixture.formal.identities.public)
			broadArtifact, broadArtifactID := artifact, artifactID
			var registryResolution *formalGLMArtifactRegistryResolutionV1
			if err == nil && registered {
				projected, projectedID, resolution :=
					formalGLMRegisteredLifecycleTestResolution(
						t, fixture, artifact,
						runtime.Admission.Productive.Compiled.Binding)
				artifact, artifactID = projected, projectedID
				registryResolution = &resolution
			}
			runtime.clear()
			if err != nil {
				t.Fatal(err)
			}
			contract := formalGLMPhase21SamplerV2TestContractForArtifact(
				t, artifact, artifactID, formalGLMPhase21SamplerV2OneDraw,
				fixture.formal.identities.public,
				fixture.formal.identities.private, fixture.seeds)
			authorizations := formalGLMPhase21SamplerV2TestAuthorize(
				t, contract, fixture.formal.identities.public,
				fixture.formal.identities.private, fixture.seeds)
			authorities := formalGLMPhase21RockTestStageAuthorities(
				t, fixture, contract, authorizations)
			if registryResolution != nil {
				for index := range authorities {
					path := filepath.Join(authorities[index].root,
						"assets-v1", "registry-resolution.json")
					formalGLMPhase21RockTestWriteJSON(
						t, path, *registryResolution)
					authorities[index].operation.RegistryResolutionPath = path
				}
				missingResolution := authorities[0].operation
				missingResolution.RegistryResolutionPath = ""
				missingJSON, marshalErr := json.Marshal(missingResolution)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				entered := false
				if _, runErr := formalGLMPhase21RockRunWithHook(
					authorities[0].root, false,
					formalGLMPhase21RockActionStage, missingJSON,
					func(string) error { entered = true; return nil }); runErr == nil || entered {
					t.Fatalf("registered lifecycle accepted nil resolution: %v", runErr)
				}
				broadContract := formalGLMRegisteredLifecycleTestContract(
					t, fixture, broadArtifact, broadArtifactID)
				broadPath := filepath.Join(authorities[0].root,
					"assets-v1", "broad-contract.json")
				formalGLMPhase21RockTestWriteJSON(t, broadPath, broadContract)
				broadResolution := authorities[0].operation
				broadResolution.ArtifactContractPath = broadPath
				broadJSON, marshalErr := json.Marshal(broadResolution)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				entered = false
				if _, runErr := formalGLMPhase21RockRunWithHook(
					authorities[0].root, false,
					formalGLMPhase21RockActionStage, broadJSON,
					func(string) error { entered = true; return nil }); runErr == nil || entered {
					t.Fatalf("broad lifecycle accepted a registry resolution: %v", runErr)
				}
			}
			type stageResult struct {
				index    int
				response formalGLMPhase21RockLifecycleResponse
				err      error
			}
			results := make(chan stageResult, 2)
			for index := range authorities {
				operation, err := json.Marshal(authorities[index].operation)
				if err != nil {
					t.Fatal(err)
				}
				go func(index int, operation []byte) {
					response, runErr := formalGLMPhase21RockRun(
						authorities[index].root, false,
						formalGLMPhase21RockActionStage, operation)
					results <- stageResult{index, response, runErr}
				}(index, operation)
			}
			var responses [2]formalGLMPhase21RockLifecycleResponse
			offsets := [2]int64{}
			completed := 0
			deadline := time.Now().Add(90 * time.Second)
			for completed < 2 && time.Now().Before(deadline) {
				select {
				case result := <-results:
					responses[result.index] = result.response
					if result.err != nil {
						for _, authority := range authorities {
							_ = os.WriteFile(filepath.Join(authority.spool, "abort"),
								[]byte("1"), 0o600)
						}
						t.Fatalf("stage authority %d: %v", result.index, result.err)
					}
					completed++
				default:
					offsets[0] = exactGCTestRelaySpool(
						t, authorities[0].spool, authorities[1].spool, offsets[0])
					offsets[1] = exactGCTestRelaySpool(
						t, authorities[1].spool, authorities[0].spool, offsets[1])
					now := time.Now()
					for _, authority := range authorities {
						if err := os.Chtimes(filepath.Join(
							authority.spool, "exchange.hb"), now, now); err != nil {
							t.Fatal(err)
						}
					}
					time.Sleep(time.Millisecond)
				}
			}
			if completed != 2 {
				t.Fatal("stage authorities did not complete")
			}
			var records [2]formalGLMPhase21RockStageRecord
			for index, response := range responses {
				if response.State != formalGLMPhase21RockStateStaged ||
					response.Stage == nil || response.ArtifactID != artifactID ||
					response.Replayed {
					t.Fatalf("unexpected stage response %d: %+v", index, response)
				}
				records[index] = *response.Stage
				if _, err := os.Lstat(authorities[index].secret); !os.IsNotExist(err) {
					t.Fatal("stage secret survived durable spool/header CAS")
				}
				encoded, err := json.Marshal(response)
				if err != nil {
					t.Fatal(err)
				}
				spoolPath, err := formalGLMPhase21RockLocalSpoolPath(
					authorities[index].root, artifactID,
					contract.Artifact.NoiseAuthorities[index].Role)
				if err != nil {
					t.Fatal(err)
				}
				spoolBytes, err := os.ReadFile(spoolPath)
				if err != nil {
					t.Fatal(err)
				}
				for _, forbidden := range [][]byte{
					[]byte(`"shares"`), []byte(`"secret_key"`),
					[]byte(base64.StdEncoding.EncodeToString(
						fixture.formal.identities.private[contract.Artifact.NoiseAuthorities[index].PeerName])),
				} {
					if bytes.Contains(encoded, forbidden) ||
						bytes.Contains(spoolBytes, forbidden) {
						t.Fatalf("stage %d leaked %q", index, forbidden)
					}
				}
			}
			binding, err := formalGLMPhase21RockStagePair(
				records, contract, fixture.formal.identities.public)
			if err != nil || binding.ArtifactID != artifactID {
				t.Fatalf("stage pair: %v", err)
			}
			var stagePaths [2]string
			for index, record := range records {
				stagePaths[index] = filepath.Join(authorities[0].root,
					"inbox-v1", "stage-"+record.Receipt.Role+".json")
				formalGLMPhase21RockTestWriteJSON(t, stagePaths[index], record)
			}
			ticketSecretPath := filepath.Join(
				authorities[0].root, "commands-v1", "ticket-secret.json")
			writeTicketSecret := func() {
				formalGLMPhase21RockTestWriteJSON(t, ticketSecretPath,
					formalGLMPhase21RockTicketSecret{
						Version: formalGLMPhase21RockSecretVersion,
						Family:  formalFinalizerHandoffFamilyGLM,
						Purpose: formalGLMPhase21RockPurpose,
						Action:  formalGLMPhase21RockActionTicket,
						TransportStorageRoot: base64.StdEncoding.EncodeToString(
							authorities[0].transportRoot[:]),
						SigningPrivateKey: base64.StdEncoding.EncodeToString(
							fixture.formal.identities.private[binding.Finalizer.PeerName]),
					})
			}
			writeTicketSecret()
			ticketOperation := formalGLMPhase21RockTicketOperation{
				ArtifactContractPath: authorities[0].operation.ArtifactContractPath,
				PinsetPath:           authorities[0].operation.PinsetPath,
				PreflightRecordPaths: authorities[0].operation.PreflightRecordPaths,
				StageRecordPaths:     stagePaths,
				PeerName:             binding.Finalizer.PeerName,
				SecretBundlePath:     ticketSecretPath,
			}
			ticketOperationJSON, err := json.Marshal(ticketOperation)
			if err != nil {
				t.Fatal(err)
			}
			crashAfterTicket := fmt.Errorf("test crash after durable ticket")
			if _, err := formalGLMPhase21RockRunWithHook(
				authorities[0].root, false,
				formalGLMPhase21RockActionTicket, ticketOperationJSON,
				func(phase string) error {
					if phase == "after_ticket_before_record" {
						return crashAfterTicket
					}
					return nil
				}); err != crashAfterTicket {
				t.Fatalf("ticket crash hook: %v", err)
			}
			ticketRecordPath, err := formalGLMPhase21RockTicketRecordPath(
				authorities[0].root, artifactID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(ticketRecordPath); !os.IsNotExist(err) {
				t.Fatal("ticket crash committed lifecycle record")
			}
			ticketResponse, err := formalGLMPhase21RockRun(
				authorities[0].root, false,
				formalGLMPhase21RockActionTicket, ticketOperationJSON)
			if err != nil || ticketResponse.Ticket == nil ||
				ticketResponse.State != formalGLMPhase21RockStateTicketReady ||
				ticketResponse.ArtifactID != artifactID {
				t.Fatalf("ticket recovery: %+v / %v", ticketResponse, err)
			}
			if _, err := os.Lstat(ticketSecretPath); !os.IsNotExist(err) {
				t.Fatal("ticket secret survived lifecycle record CAS")
			}
			ticketReplay, err := formalGLMPhase21RockRun(
				authorities[0].root, false,
				formalGLMPhase21RockActionTicket, ticketOperationJSON)
			if err != nil || !ticketReplay.Replayed || ticketReplay.Ticket == nil ||
				!reflect.DeepEqual(*ticketReplay.Ticket, *ticketResponse.Ticket) {
				t.Fatalf("ticket replay: %+v / %v", ticketReplay, err)
			}
			ticketJSON, err := json.Marshal(ticketResponse)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range [][]byte{
				[]byte(`"secret_key"`),
				[]byte(base64.StdEncoding.EncodeToString(
					fixture.formal.identities.private[binding.Finalizer.PeerName])),
			} {
				if bytes.Contains(ticketJSON, forbidden) {
					t.Fatalf("ticket response leaked %q", forbidden)
				}
			}

			var sealRecords [2]formalGLMPhase21RockSealRecord
			for index, authority := range authorities {
				var localStagePaths [2]string
				for recordIndex, record := range records {
					localStagePaths[recordIndex] = filepath.Join(
						authority.root, "inbox-v1",
						"stage-"+record.Receipt.Role+".json")
					formalGLMPhase21RockTestWriteJSON(
						t, localStagePaths[recordIndex], record)
				}
				localTicketPath := filepath.Join(
					authority.root, "inbox-v1", "ticket.json")
				formalGLMPhase21RockTestWriteJSON(
					t, localTicketPath, *ticketResponse.Ticket)
				peer := contract.Artifact.NoiseAuthorities[index].PeerName
				source, _, err := fixture.stores[peer].Load()
				if err != nil {
					t.Fatal(err)
				}
				backendKey := source.backend
				source.clear()
				phase20Root := sha256.Sum256([]byte(
					t.Name() + "/phase20/" + peer))
				sealSecretPath := filepath.Join(
					authority.root, "commands-v1", "seal-secret.json")
				formalGLMPhase21RockTestWriteJSON(t, sealSecretPath,
					formalGLMPhase21RockSealSecret{
						Version: formalGLMPhase21RockSecretVersion,
						Family:  formalFinalizerHandoffFamilyGLM,
						Purpose: formalGLMPhase21RockPurpose,
						Action:  formalGLMPhase21RockActionSeal,
						Phase20StorageRoot: base64.StdEncoding.EncodeToString(
							phase20Root[:]),
						BackendKey: base64.StdEncoding.EncodeToString(backendKey[:]),
						TransportStorageRoot: base64.StdEncoding.EncodeToString(
							authority.transportRoot[:]),
						SigningPrivateKey: base64.StdEncoding.EncodeToString(
							fixture.formal.identities.private[peer]),
					})
				clear(backendKey[:])
				sealOperation := formalGLMPhase21RockSealOperation{
					ArtifactContractPath: authority.operation.ArtifactContractPath,
					PinsetPath:           authority.operation.PinsetPath,
					RegistryResolutionPath: authority.operation.
						RegistryResolutionPath,
					PreflightRecordPaths: authority.operation.PreflightRecordPaths,
					StageRecordPaths:     localStagePaths,
					TicketRecordPath:     localTicketPath, PeerName: peer,
					Phase20SemanticRootSHA256: authority.operation.Phase20SemanticRootSHA256,
					CapsulePath:               authority.operation.CapsulePath,
					RequestPath:               authority.operation.RequestPath,
					BackendSignaturesPath:     authority.operation.BackendSignaturesPath,
					WorkerSignaturesPath:      authority.operation.WorkerSignaturesPath,
					SecretBundlePath:          sealSecretPath,
				}
				sealOperationJSON, err := json.Marshal(sealOperation)
				if err != nil {
					t.Fatal(err)
				}
				crashAfterOutbox := fmt.Errorf(
					"test crash after %s outbox", records[index].Receipt.Role)
				if _, err := formalGLMPhase21RockRunWithHook(
					authority.root, false, formalGLMPhase21RockActionSeal,
					sealOperationJSON, func(phase string) error {
						if phase == "after_outbox_before_seal_record" {
							return crashAfterOutbox
						}
						return nil
					}); err != crashAfterOutbox {
					t.Fatalf("seal crash hook %s: %v", peer, err)
				}
				sealResponse, err := formalGLMPhase21RockRun(
					authority.root, false, formalGLMPhase21RockActionSeal,
					sealOperationJSON)
				if err != nil || sealResponse.Seal == nil ||
					sealResponse.State != formalGLMPhase21RockStateSealed ||
					sealResponse.ArtifactID != artifactID {
					t.Fatalf("seal recovery %s: %+v / %v",
						peer, sealResponse, err)
				}
				sealRecords[index] = *sealResponse.Seal
				if _, err := os.Lstat(sealSecretPath); !os.IsNotExist(err) {
					t.Fatalf("%s seal secret survived record CAS", peer)
				}
				sealReplay, err := formalGLMPhase21RockRun(
					authority.root, false, formalGLMPhase21RockActionSeal,
					sealOperationJSON)
				if err != nil || !sealReplay.Replayed || sealReplay.Seal == nil ||
					!reflect.DeepEqual(*sealReplay.Seal, sealRecords[index]) {
					t.Fatalf("seal replay %s: %+v / %v", peer, sealReplay, err)
				}
				responseJSON, err := json.Marshal(sealResponse)
				if err != nil {
					t.Fatal(err)
				}
				for _, forbidden := range [][]byte{
					[]byte(`"envelope"`), []byte(`"nonce"`),
					[]byte(`"ephemeral_public_key"`), []byte(`"secret_key"`),
					[]byte(base64.StdEncoding.EncodeToString(
						fixture.formal.identities.private[peer])),
				} {
					if bytes.Contains(responseJSON, forbidden) {
						t.Fatalf("seal response %s leaked %q", peer, forbidden)
					}
				}
			}
			if sealRecords[0].Receipt.EnvelopeSHA256 ==
				sealRecords[1].Receipt.EnvelopeSHA256 {
				t.Fatal("two authority envelopes shared one digest")
			}

			var sealedEnvelopes [2]formalFinalizerHandoffEnvelope
			for index, authority := range contract.Artifact.NoiseAuthorities {
				store, err := newFormalFinalizerHandoffAuthorityStoreForTest(
					authorities[index].root, binding,
					formalFinalizerHandoffAuthority{
						PeerName: authority.PeerName, PeerID: authority.PeerID,
						Role: authority.Role,
					}, authorities[index].transportRoot,
					fixture.formal.identities.public)
				if err != nil {
					t.Fatal(err)
				}
				sealedEnvelopes[index], err = store.loadEnvelope(
					"outbox-v1", authority.Role)
				store.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			ingress, err := newFormalFinalizerHandoffAuthorityStoreForTest(
				authorities[0].root, binding, binding.Finalizer,
				authorities[0].transportRoot, fixture.formal.identities.public)
			if err != nil {
				t.Fatal(err)
			}
			for _, envelope := range sealedEnvelopes {
				if _, _, err := ingress.CommitIngress(envelope); err != nil {
					ingress.Close()
					t.Fatal(err)
				}
			}
			ingress.Close()
			var sealPaths [2]string
			for index, record := range sealRecords {
				sealPaths[index] = filepath.Join(authorities[0].root,
					"inbox-v1", "seal-"+record.Receipt.Role+".json")
				formalGLMPhase21RockTestWriteJSON(t, sealPaths[index], record)
			}
			finalizerSource, _, err := fixture.stores[binding.Finalizer.PeerName].Load()
			if err != nil {
				t.Fatal(err)
			}
			candidateBackendKey := finalizerSource.backend
			finalizerSource.clear()
			candidatePhase20Root := sha256.Sum256([]byte(
				t.Name() + "/phase20/" + binding.Finalizer.PeerName))
			candidateSecretPath := filepath.Join(
				authorities[0].root, "commands-v1", "candidate-secret.json")
			formalGLMPhase21RockTestWriteJSON(t, candidateSecretPath,
				formalGLMPhase21RockCandidateSecret{
					Version: formalGLMPhase21RockSecretVersion,
					Family:  formalFinalizerHandoffFamilyGLM,
					Purpose: formalGLMPhase21RockPurpose,
					Action:  formalGLMPhase21RockActionPrepareCandidate,
					Phase20StorageRoot: base64.StdEncoding.EncodeToString(
						candidatePhase20Root[:]),
					BackendKey: base64.StdEncoding.EncodeToString(
						candidateBackendKey[:]),
					TransportStorageRoot: base64.StdEncoding.EncodeToString(
						authorities[0].transportRoot[:]),
					SigningPrivateKey: base64.StdEncoding.EncodeToString(
						fixture.formal.identities.private[binding.Finalizer.PeerName]),
				})
			clear(candidateBackendKey[:])
			candidateOperation := formalGLMPhase21RockPrepareCandidateOperation{
				ArtifactContractPath: authorities[0].operation.ArtifactContractPath,
				PinsetPath:           authorities[0].operation.PinsetPath,
				RegistryResolutionPath: authorities[0].operation.
					RegistryResolutionPath,
				PreflightRecordPaths: authorities[0].operation.PreflightRecordPaths,
				StageRecordPaths:     stagePaths, TicketRecordPath: ticketRecordPath,
				SealRecordPaths: sealPaths, PeerName: binding.Finalizer.PeerName,
				Phase20SemanticRootSHA256: authorities[0].operation.Phase20SemanticRootSHA256,
				CapsulePath:               authorities[0].operation.CapsulePath,
				RequestPath:               authorities[0].operation.RequestPath,
				BackendSignaturesPath:     authorities[0].operation.BackendSignaturesPath,
				WorkerSignaturesPath:      authorities[0].operation.WorkerSignaturesPath,
				SecretBundlePath:          candidateSecretPath,
			}
			candidateOperationJSON, err := json.Marshal(candidateOperation)
			if err != nil {
				t.Fatal(err)
			}
			crashAfterCandidate := fmt.Errorf("test crash after durable candidate")
			if _, err := formalGLMPhase21RockRunWithHook(
				authorities[0].root, false,
				formalGLMPhase21RockActionPrepareCandidate,
				candidateOperationJSON, func(phase string) error {
					if phase == "after_candidate_before_record" {
						return crashAfterCandidate
					}
					return nil
				}); err != crashAfterCandidate {
				t.Fatalf("candidate crash hook: %v", err)
			}
			candidateResponse, err := formalGLMPhase21RockRun(
				authorities[0].root, false,
				formalGLMPhase21RockActionPrepareCandidate,
				candidateOperationJSON)
			if err != nil || candidateResponse.Candidate == nil ||
				candidateResponse.State != formalGLMPhase21RockStateCandidateReady ||
				len(candidateResponse.Candidate.Candidate.Signatures) != 0 {
				t.Fatalf("candidate recovery: %+v / %v", candidateResponse, err)
			}
			if _, err := os.Lstat(candidateSecretPath); !os.IsNotExist(err) {
				t.Fatal("candidate secret survived record CAS")
			}
			candidateReplay, err := formalGLMPhase21RockRun(
				authorities[0].root, false,
				formalGLMPhase21RockActionPrepareCandidate,
				candidateOperationJSON)
			if err != nil || !candidateReplay.Replayed ||
				candidateReplay.Candidate == nil ||
				!reflect.DeepEqual(*candidateReplay.Candidate,
					*candidateResponse.Candidate) {
				t.Fatalf("candidate replay: %+v / %v", candidateReplay, err)
			}
			candidateJSON, err := json.Marshal(candidateResponse)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range [][]byte{
				[]byte(`"shares"`), []byte(`"ciphertext"`),
				[]byte(`"secret_key"`), []byte(`"nonce"`),
				[]byte(base64.StdEncoding.EncodeToString(
					fixture.formal.identities.private[binding.Finalizer.PeerName])),
			} {
				if bytes.Contains(candidateJSON, forbidden) {
					t.Fatalf("candidate response leaked %q", forbidden)
				}
			}

			var localReleaseRecords [2]formalGLMPhase21RockLocalReleaseRecord
			for index, authority := range authorities {
				var localStagePaths [2]string
				for recordIndex, record := range records {
					localStagePaths[recordIndex] = filepath.Join(
						authority.root, "inbox-v1",
						"verify-stage-"+record.Receipt.Role+".json")
					formalGLMPhase21RockTestWriteJSON(
						t, localStagePaths[recordIndex], record)
				}
				localTicketPath := filepath.Join(
					authority.root, "inbox-v1", "verify-ticket.json")
				formalGLMPhase21RockTestWriteJSON(
					t, localTicketPath, *ticketResponse.Ticket)
				candidatePath := filepath.Join(
					authority.root, "inbox-v1", "candidate.json")
				formalGLMPhase21RockTestWriteJSON(
					t, candidatePath, *candidateResponse.Candidate)
				peer := contract.Artifact.NoiseAuthorities[index].PeerName
				source, _, err := fixture.stores[peer].Load()
				if err != nil {
					t.Fatal(err)
				}
				backendKey := source.backend
				source.clear()
				phase20Root := sha256.Sum256([]byte(
					t.Name() + "/phase20/" + peer))
				verifySecretPath := filepath.Join(
					authority.root, "commands-v1", "verify-secret.json")
				writeVerifySecret := func() {
					formalGLMPhase21RockTestWriteJSON(t, verifySecretPath,
						formalGLMPhase21RockVerifyCandidateSecret{
							Version: formalGLMPhase21RockSecretVersion,
							Family:  formalFinalizerHandoffFamilyGLM,
							Purpose: formalGLMPhase21RockPurpose,
							Action:  formalGLMPhase21RockActionVerifyCandidate,
							Phase20StorageRoot: base64.StdEncoding.EncodeToString(
								phase20Root[:]),
							BackendKey: base64.StdEncoding.EncodeToString(backendKey[:]),
							TransportStorageRoot: base64.StdEncoding.EncodeToString(
								authority.transportRoot[:]),
							SigningPrivateKey: base64.StdEncoding.EncodeToString(
								fixture.formal.identities.private[peer]),
						})
				}
				writeVerifySecret()
				verifyOperation := formalGLMPhase21RockVerifyCandidateOperation{
					ArtifactContractPath: authority.operation.ArtifactContractPath,
					PinsetPath:           authority.operation.PinsetPath,
					RegistryResolutionPath: authority.operation.
						RegistryResolutionPath,
					PreflightRecordPaths: authority.operation.PreflightRecordPaths,
					StageRecordPaths:     localStagePaths,
					TicketRecordPath:     localTicketPath,
					CandidateRecordPath:  candidatePath, PeerName: peer,
					Phase20SemanticRootSHA256: authority.operation.Phase20SemanticRootSHA256,
					CapsulePath:               authority.operation.CapsulePath,
					RequestPath:               authority.operation.RequestPath,
					BackendSignaturesPath:     authority.operation.BackendSignaturesPath,
					WorkerSignaturesPath:      authority.operation.WorkerSignaturesPath,
					SecretBundlePath:          verifySecretPath,
				}
				if index == 1 {
					malicious := *candidateResponse.Candidate
					malicious.Candidate.ClampedScaledValues = append(
						[]string(nil), malicious.Candidate.ClampedScaledValues...)
					value, ok := new(big.Int).SetString(
						malicious.Candidate.ClampedScaledValues[0], 10)
					if !ok {
						t.Fatal("candidate coordinate was not exact decimal")
					}
					value.Add(value, big.NewInt(1))
					malicious.Candidate.ClampedScaledValues[0] = value.String()
					malicious.Candidate.VectorSHA256, err =
						jointDPBiomedicalGaussianOneDrawVectorSHA256(
							malicious.Candidate.ClampedScaledValues)
					if err != nil {
						t.Fatal(err)
					}
					malicious, err = formalGLMPhase21RockBuildCandidateRecord(
						formalGLMPhase21RockContext{
							contract:   contract,
							pins:       fixture.formal.identities.public,
							artifactID: artifactID,
						}, binding, ticketResponse.Ticket.Ticket,
						malicious.Candidate,
						fixture.formal.identities.private[binding.Finalizer.PeerName])
					if err != nil {
						t.Fatal(err)
					}
					formalGLMPhase21RockTestWriteJSON(t, candidatePath, malicious)
					maliciousJSON, err := json.Marshal(verifyOperation)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := formalGLMPhase21RockRun(
						authority.root, false,
						formalGLMPhase21RockActionVerifyCandidate,
						maliciousJSON); err == nil {
						t.Fatal("authority signed finalizer-authenticated wrong vector")
					}
					formalGLMPhase21RockTestWriteJSON(
						t, candidatePath, *candidateResponse.Candidate)
				}
				verifyOperationJSON, err := json.Marshal(verifyOperation)
				if err != nil {
					t.Fatal(err)
				}
				crashAfterVerify := fmt.Errorf(
					"test crash after %s nonblind verify", records[index].Receipt.Role)
				if _, err := formalGLMPhase21RockRunWithHook(
					authority.root, false,
					formalGLMPhase21RockActionVerifyCandidate,
					verifyOperationJSON, func(phase string) error {
						if phase == "after_nonblind_verification_before_record" {
							return crashAfterVerify
						}
						return nil
					}); err != crashAfterVerify {
					t.Fatalf("verify crash hook %s: %v", peer, err)
				}
				verifyResponse, err := formalGLMPhase21RockRun(
					authority.root, false,
					formalGLMPhase21RockActionVerifyCandidate,
					verifyOperationJSON)
				if err != nil || verifyResponse.LocalRelease == nil ||
					verifyResponse.State !=
						formalGLMPhase21RockStateCandidateVerified {
					t.Fatalf("verify recovery %s: %+v / %v",
						peer, verifyResponse, err)
				}
				localReleaseRecords[index] = *verifyResponse.LocalRelease
				if _, err := os.Lstat(verifySecretPath); !os.IsNotExist(err) {
					t.Fatalf("%s verify secret survived record CAS", peer)
				}
				verifyReplay, err := formalGLMPhase21RockRun(
					authority.root, false,
					formalGLMPhase21RockActionVerifyCandidate,
					verifyOperationJSON)
				if err != nil || !verifyReplay.Replayed ||
					verifyReplay.LocalRelease == nil ||
					!reflect.DeepEqual(*verifyReplay.LocalRelease,
						localReleaseRecords[index]) {
					t.Fatalf("verify replay %s: %+v / %v", peer, verifyReplay, err)
				}
				clear(backendKey[:])
			}
			if localReleaseRecords[0].Binding.Role != "garbler" ||
				localReleaseRecords[1].Binding.Role != "evaluator" {
				t.Fatal("nonblind local releases lost authority order")
			}
			var localReleasePaths [2]string
			for index, record := range localReleaseRecords {
				localReleasePaths[index] = filepath.Join(
					authorities[0].root, "inbox-v1",
					"local-release-"+record.Binding.Role+".json")
				formalGLMPhase21RockTestWriteJSON(
					t, localReleasePaths[index], record)
			}
			candidateRecordPath, err := formalGLMPhase21RockCandidateRecordPath(
				authorities[0].root, artifactID)
			if err != nil {
				t.Fatal(err)
			}
			certificateSource, _, err := fixture.stores[binding.Finalizer.PeerName].Load()
			if err != nil {
				t.Fatal(err)
			}
			certificateBackendKey := certificateSource.backend
			certificateSource.clear()
			certificatePhase20Root := sha256.Sum256([]byte(
				t.Name() + "/phase20/" + binding.Finalizer.PeerName))
			certificateSecretPath := filepath.Join(
				authorities[0].root, "commands-v1", "certificate-secret.json")
			formalGLMPhase21RockTestWriteJSON(t, certificateSecretPath,
				formalGLMPhase21RockPrepareCertificateSecret{
					Version: formalGLMPhase21RockSecretVersion,
					Family:  formalFinalizerHandoffFamilyGLM,
					Purpose: formalGLMPhase21RockPurpose,
					Action:  formalGLMPhase21RockActionPrepareCertificate,
					Phase20StorageRoot: base64.StdEncoding.EncodeToString(
						certificatePhase20Root[:]),
					BackendKey: base64.StdEncoding.EncodeToString(
						certificateBackendKey[:]),
					TransportStorageRoot: base64.StdEncoding.EncodeToString(
						authorities[0].transportRoot[:]),
					SigningPrivateKey: base64.StdEncoding.EncodeToString(
						fixture.formal.identities.private[binding.Finalizer.PeerName]),
				})
			clear(certificateBackendKey[:])
			certificateOperation := formalGLMPhase21RockPrepareCertificateOperation{
				ArtifactContractPath: authorities[0].operation.ArtifactContractPath,
				PinsetPath:           authorities[0].operation.PinsetPath,
				RegistryResolutionPath: authorities[0].operation.
					RegistryResolutionPath,
				PreflightRecordPaths: authorities[0].operation.PreflightRecordPaths,
				StageRecordPaths:     stagePaths, TicketRecordPath: ticketRecordPath,
				CandidateRecordPath:       candidateRecordPath,
				LocalReleaseRecordPaths:   localReleasePaths,
				PeerName:                  binding.Finalizer.PeerName,
				Phase20SemanticRootSHA256: authorities[0].operation.Phase20SemanticRootSHA256,
				CapsulePath:               authorities[0].operation.CapsulePath,
				RequestPath:               authorities[0].operation.RequestPath,
				BackendSignaturesPath:     authorities[0].operation.BackendSignaturesPath,
				WorkerSignaturesPath:      authorities[0].operation.WorkerSignaturesPath,
				SecretBundlePath:          certificateSecretPath,
			}
			reorderedCertificate := certificateOperation
			reorderedCertificate.LocalReleaseRecordPaths = [2]string{
				localReleasePaths[1], localReleasePaths[0],
			}
			reorderedJSON, err := json.Marshal(reorderedCertificate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := formalGLMPhase21RockRun(
				authorities[0].root, false,
				formalGLMPhase21RockActionPrepareCertificate,
				reorderedJSON); err == nil {
				t.Fatal("base certificate accepted reordered local releases")
			}
			certificateOperationJSON, err := json.Marshal(certificateOperation)
			if err != nil {
				t.Fatal(err)
			}
			crashAfterCertificate := fmt.Errorf(
				"test crash after base certificate")
			if _, err := formalGLMPhase21RockRunWithHook(
				authorities[0].root, false,
				formalGLMPhase21RockActionPrepareCertificate,
				certificateOperationJSON, func(phase string) error {
					if phase == "after_base_certificate_before_record" {
						return crashAfterCertificate
					}
					return nil
				}); err != crashAfterCertificate {
				t.Fatalf("base certificate crash hook: %v", err)
			}
			certificateResponse, err := formalGLMPhase21RockRun(
				authorities[0].root, false,
				formalGLMPhase21RockActionPrepareCertificate,
				certificateOperationJSON)
			if err != nil || certificateResponse.BaseCertificate == nil ||
				certificateResponse.State != formalGLMPhase21RockStateCertificateReady ||
				certificateResponse.BaseCertificate.CertifiedRelease.OneDraw == nil ||
				len(certificateResponse.BaseCertificate.
					BaseCertificate.AuthorityReceipts) != 0 {
				t.Fatalf("base certificate recovery: %+v / %v",
					certificateResponse, err)
			}
			if _, err := os.Lstat(certificateSecretPath); !os.IsNotExist(err) {
				t.Fatal("certificate secret survived record CAS")
			}
			certificateReplay, err := formalGLMPhase21RockRun(
				authorities[0].root, false,
				formalGLMPhase21RockActionPrepareCertificate,
				certificateOperationJSON)
			if err != nil || !certificateReplay.Replayed ||
				certificateReplay.BaseCertificate == nil ||
				!reflect.DeepEqual(*certificateReplay.BaseCertificate,
					*certificateResponse.BaseCertificate) {
				t.Fatalf("base certificate replay: %+v / %v",
					certificateReplay, err)
			}
			certificateJSON, err := json.Marshal(certificateResponse)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range [][]byte{
				[]byte(`"shares"`), []byte(`"ciphertext"`),
				[]byte(`"secret_key"`), []byte(`"nonce"`),
				[]byte(base64.StdEncoding.EncodeToString(
					fixture.formal.identities.private[binding.Finalizer.PeerName])),
			} {
				if bytes.Contains(certificateJSON, forbidden) {
					t.Fatalf("base certificate response leaked %q", forbidden)
				}
			}

			var authorizationRecords [2]formalGLMPhase21RockAuthorizationRecord
			for index, authority := range authorities {
				peer := contract.Artifact.NoiseAuthorities[index].PeerName
				var localStagePaths [2]string
				var localReleaseRelayPaths [2]string
				for recordIndex, record := range records {
					localStagePaths[recordIndex] = filepath.Join(
						authority.root, "inbox-v1",
						"sign-stage-"+record.Receipt.Role+".json")
					formalGLMPhase21RockTestWriteJSON(
						t, localStagePaths[recordIndex], record)
					localReleaseRelayPaths[recordIndex] = filepath.Join(
						authority.root, "inbox-v1",
						"sign-local-release-"+
							localReleaseRecords[recordIndex].Binding.Role+".json")
					formalGLMPhase21RockTestWriteJSON(t,
						localReleaseRelayPaths[recordIndex],
						localReleaseRecords[recordIndex])
				}
				localTicketPath := filepath.Join(
					authority.root, "inbox-v1", "sign-ticket.json")
				localCandidatePath := filepath.Join(
					authority.root, "inbox-v1", "sign-candidate.json")
				localBasePath := filepath.Join(
					authority.root, "inbox-v1", "base-certificate.json")
				formalGLMPhase21RockTestWriteJSON(
					t, localTicketPath, *ticketResponse.Ticket)
				formalGLMPhase21RockTestWriteJSON(
					t, localCandidatePath, *candidateResponse.Candidate)
				formalGLMPhase21RockTestWriteJSON(
					t, localBasePath, *certificateResponse.BaseCertificate)
				source, _, err := fixture.stores[peer].Load()
				if err != nil {
					t.Fatal(err)
				}
				backendKey := source.backend
				source.clear()
				phase20Root := sha256.Sum256([]byte(
					t.Name() + "/phase20/" + peer))
				stickyRoot := sha256.Sum256([]byte(
					t.Name() + "/sticky/" + peer))
				signSecretPath := filepath.Join(
					authority.root, "commands-v1", "sign-secret.json")
				formalGLMPhase21RockTestWriteJSON(t, signSecretPath,
					formalGLMPhase21RockSignCertificateSecret{
						Version: formalGLMPhase21RockSecretVersion,
						Family:  formalFinalizerHandoffFamilyGLM,
						Purpose: formalGLMPhase21RockPurpose,
						Action:  formalGLMPhase21RockActionSignCertificate,
						StickyStorageRoot: base64.StdEncoding.EncodeToString(
							stickyRoot[:]),
						Phase20StorageRoot: base64.StdEncoding.EncodeToString(
							phase20Root[:]),
						BackendKey: base64.StdEncoding.EncodeToString(backendKey[:]),
						TransportStorageRoot: base64.StdEncoding.EncodeToString(
							authority.transportRoot[:]),
						SigningPrivateKey: base64.StdEncoding.EncodeToString(
							fixture.formal.identities.private[peer]),
					})
				clear(backendKey[:])
				signOperation := formalGLMPhase21RockSignCertificateOperation{
					ArtifactContractPath:      authority.operation.ArtifactContractPath,
					PinsetPath:                authority.operation.PinsetPath,
					RegistryResolutionPath:    authority.operation.RegistryResolutionPath,
					PreflightRecordPaths:      authority.operation.PreflightRecordPaths,
					StageRecordPaths:          localStagePaths,
					TicketRecordPath:          localTicketPath,
					CandidateRecordPath:       localCandidatePath,
					LocalReleaseRecordPaths:   localReleaseRelayPaths,
					BaseCertificateRecordPath: localBasePath,
					PeerName:                  peer,
					Phase20SemanticRootSHA256: authority.operation.Phase20SemanticRootSHA256,
					CapsulePath:               authority.operation.CapsulePath,
					RequestPath:               authority.operation.RequestPath,
					BackendSignaturesPath:     authority.operation.BackendSignaturesPath,
					WorkerSignaturesPath:      authority.operation.WorkerSignaturesPath,
					SecretBundlePath:          signSecretPath,
				}
				if index == 1 {
					missingPredecessorJSON, err := json.Marshal(signOperation)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := formalGLMPhase21RockRun(
						authority.root, false,
						formalGLMPhase21RockActionSignCertificate,
						missingPredecessorJSON); err == nil {
						t.Fatal("evaluator signed without garbler predecessor")
					}
					predecessorPath := filepath.Join(authority.root,
						"inbox-v1", "garbler-authorization.json")
					formalGLMPhase21RockTestWriteJSON(
						t, predecessorPath, authorizationRecords[0])
					signOperation.PredecessorAuthorizationPath = &predecessorPath
				}
				signOperationJSON, err := json.Marshal(signOperation)
				if err != nil {
					t.Fatal(err)
				}
				crashAfterSignOnce := fmt.Errorf(
					"test crash after %s SignOnce", records[index].Receipt.Role)
				if _, err := formalGLMPhase21RockRunWithHook(
					authority.root, false,
					formalGLMPhase21RockActionSignCertificate,
					signOperationJSON, func(phase string) error {
						if phase == "after_sign_once_before_authorization_record" {
							return crashAfterSignOnce
						}
						return nil
					}); err != crashAfterSignOnce {
					t.Fatalf("SignOnce crash hook %s: %v", peer, err)
				}
				signResponse, err := formalGLMPhase21RockRun(
					authority.root, false,
					formalGLMPhase21RockActionSignCertificate,
					signOperationJSON)
				if err != nil || signResponse.Authorization == nil ||
					signResponse.State != formalGLMPhase21RockStateAuthorized {
					t.Fatalf("SignOnce recovery %s: %+v / %v",
						peer, signResponse, err)
				}
				authorizationRecords[index] = *signResponse.Authorization
				if _, err := os.Lstat(signSecretPath); !os.IsNotExist(err) {
					t.Fatalf("%s SignOnce secret survived record CAS", peer)
				}
				signReplay, err := formalGLMPhase21RockRun(
					authority.root, false,
					formalGLMPhase21RockActionSignCertificate,
					signOperationJSON)
				if err != nil || !signReplay.Replayed ||
					signReplay.Authorization == nil ||
					!reflect.DeepEqual(*signReplay.Authorization,
						authorizationRecords[index]) {
					t.Fatalf("SignOnce replay %s: %+v / %v", peer, signReplay, err)
				}
			}
			if authorizationRecords[0].Role != "garbler" ||
				authorizationRecords[1].Role != "evaluator" ||
				authorizationRecords[1].TransportAuthorization.
					PredecessorReceiptSHA256 == "" {
				t.Fatal("ordered certificate authorizations lost predecessor")
			}
			var authorizationPaths [2]string
			for index, record := range authorizationRecords {
				authorizationPaths[index] = filepath.Join(
					authorities[0].root, "inbox-v1",
					"publication-authorization-"+record.Role+".json")
				formalGLMPhase21RockTestWriteJSON(
					t, authorizationPaths[index], record)
			}
			publicationSecretPath := filepath.Join(
				authorities[0].root, "commands-v1", "publication-secret.json")
			formalGLMPhase21RockTestWriteJSON(t, publicationSecretPath,
				formalGLMPhase21RockPreparePublicationSecret{
					Version: formalGLMPhase21RockSecretVersion,
					Family:  formalFinalizerHandoffFamilyGLM,
					Purpose: formalGLMPhase21RockPurpose,
					Action:  formalGLMPhase21RockActionPreparePublication,
					TransportStorageRoot: base64.StdEncoding.EncodeToString(
						authorities[0].transportRoot[:]),
					SigningPrivateKey: base64.StdEncoding.EncodeToString(
						fixture.formal.identities.private[binding.Finalizer.PeerName]),
				})
			publicationOperation := formalGLMPhase21RockPreparePublicationOperation{
				ArtifactContractPath: authorities[0].operation.ArtifactContractPath,
				PinsetPath:           authorities[0].operation.PinsetPath,
				RegistryResolutionPath: authorities[0].operation.
					RegistryResolutionPath,
				PreflightRecordPaths: authorities[0].operation.PreflightRecordPaths,
				StageRecordPaths:     stagePaths, TicketRecordPath: ticketRecordPath,
				CandidateRecordPath: candidateRecordPath,
				BaseCertificateRecordPath: func() string {
					path, pathErr := formalGLMPhase21RockBaseCertificateRecordPath(
						authorities[0].root, artifactID)
					if pathErr != nil {
						t.Fatal(pathErr)
					}
					return path
				}(),
				AuthorizationRecordPaths: authorizationPaths,
				PeerName:                 binding.Finalizer.PeerName,
				SecretBundlePath:         publicationSecretPath,
			}
			swappedPublication := publicationOperation
			swappedPublication.AuthorizationRecordPaths = [2]string{
				authorizationPaths[1], authorizationPaths[0],
			}
			swappedPublicationJSON, err := json.Marshal(swappedPublication)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := formalGLMPhase21RockRun(
				authorities[0].root, false,
				formalGLMPhase21RockActionPreparePublication,
				swappedPublicationJSON); err == nil {
				t.Fatal("publication accepted swapped ordered authorizations")
			}
			publicationOperationJSON, err := json.Marshal(publicationOperation)
			if err != nil {
				t.Fatal(err)
			}
			crashBeforePublicationRecord := fmt.Errorf(
				"test crash before publication-ready record")
			if _, err := formalGLMPhase21RockRunWithHook(
				authorities[0].root, false,
				formalGLMPhase21RockActionPreparePublication,
				publicationOperationJSON, func(phase string) error {
					if phase == "after_publication_ready_before_record" {
						return crashBeforePublicationRecord
					}
					return nil
				}); err != crashBeforePublicationRecord {
				t.Fatalf("publication-ready crash hook: %v", err)
			}
			publicationResponse, err := formalGLMPhase21RockRun(
				authorities[0].root, false,
				formalGLMPhase21RockActionPreparePublication,
				publicationOperationJSON)
			if err != nil || publicationResponse.Publication == nil ||
				publicationResponse.State != formalGLMPhase21RockStatePublicationReady ||
				formalGLMPhase21ValidatePublicCertificateV2(
					*publicationResponse.Publication,
					fixture.formal.identities.public) != nil {
				t.Fatalf("publication-ready recovery: %+v / %v",
					publicationResponse, err)
			}
			if _, err := os.Lstat(publicationSecretPath); !os.IsNotExist(err) {
				t.Fatal("publication secret survived record CAS")
			}
			publicationReplay, err := formalGLMPhase21RockRun(
				authorities[0].root, false,
				formalGLMPhase21RockActionPreparePublication,
				publicationOperationJSON)
			if err != nil || !publicationReplay.Replayed ||
				publicationReplay.Publication == nil ||
				!reflect.DeepEqual(*publicationReplay.Publication,
					*publicationResponse.Publication) {
				t.Fatalf("publication-ready replay: %+v / %v",
					publicationReplay, err)
			}
			publicResponseJSON, err := json.Marshal(publicationResponse)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range [][]byte{
				[]byte(`"capsule_id"`), []byte(`"reservation`),
				[]byte(`"ledger`), []byte(`"lifetime`), []byte(`"epoch`),
				[]byte(`"shares"`), []byte(`"ciphertext"`),
			} {
				if bytes.Contains(publicResponseJSON, forbidden) {
					t.Fatalf("public-v2 response leaked %q", forbidden)
				}
			}

			// Crash-equivalent window: local AEAD spool is durable but the
			// signed stage header and Phase-2.0 source are unavailable. The
			// retry must reconstruct the same header without rerunning MPC.
			stagePath, err := formalGLMPhase21RockStageRecordPath(
				authorities[0].root, artifactID, "garbler")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(stagePath); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(authorities[0].phase20Record); err != nil {
				t.Fatal(err)
			}
			formalGLMPhase21RockTestRefreshStageSecret(
				t, fixture, contract, 0, authorities[0])
			operation, err := json.Marshal(authorities[0].operation)
			if err != nil {
				t.Fatal(err)
			}
			recovered, err := formalGLMPhase21RockRunWithHook(
				authorities[0].root, false,
				formalGLMPhase21RockActionStage, operation,
				func(phase string) error {
					if phase == "after_sampler_before_local_spool" {
						t.Fatal("recovery reran sampler")
					}
					return nil
				})
			if err != nil || !recovered.Replayed || recovered.Stage == nil ||
				!reflectPublicStageEqual(*recovered.Stage, records[0]) {
				t.Fatalf("stage spool recovery: %+v / %v", recovered, err)
			}
			if _, err := os.Lstat(authorities[0].secret); !os.IsNotExist(err) {
				t.Fatal("recovered stage secret survived header CAS")
			}
			plainReplay, err := formalGLMPhase21RockRun(
				authorities[0].root, false,
				formalGLMPhase21RockActionStage, operation)
			if err != nil || !plainReplay.Replayed || plainReplay.Stage == nil ||
				!reflectPublicStageEqual(*plainReplay.Stage, records[0]) {
				t.Fatalf("stage terminal replay: %+v / %v", plainReplay, err)
			}

			var commitRecords [2]formalGLMPhase21RockCommitRecord
			var commitPaths [2]string
			for index, authority := range contract.Artifact.NoiseAuthorities {
				stickyRoot := sha256.Sum256([]byte(
					t.Name() + "/sticky/" + authority.PeerName))
				secretPath := filepath.Join(authorities[index].root,
					"commands-v1", "commit-publication-secret.json")
				formalGLMPhase21RockTestWriteJSON(t, secretPath,
					formalGLMPhase21RockCommitPublicationSecret{
						Version: formalGLMPhase21RockSecretVersion,
						Family:  formalFinalizerHandoffFamilyGLM,
						Purpose: formalGLMPhase21RockPurpose,
						Action:  formalGLMPhase21RockActionCommitPublication,
						StickyStorageRoot: base64.StdEncoding.EncodeToString(
							stickyRoot[:]),
						SigningPrivateKey: base64.StdEncoding.EncodeToString(
							fixture.formal.identities.private[authority.PeerName]),
					})
				operation := formalGLMPhase21RockCommitPublicationOperation{
					ArtifactContractPath: authorities[index].operation.ArtifactContractPath,
					PinsetPath:           authorities[index].operation.PinsetPath,
					PeerName:             authority.PeerName,
					Publication:          *publicationResponse.Publication,
					SecretBundlePath:     secretPath,
				}
				encodedOperation, err := json.Marshal(operation)
				if err != nil {
					t.Fatal(err)
				}
				crashAfterPublicCAS := fmt.Errorf(
					"test crash after public CAS %s", authority.Role)
				if _, err := formalGLMPhase21RockRunWithHook(
					authorities[index].root, false,
					formalGLMPhase21RockActionCommitPublication,
					encodedOperation, func(phase string) error {
						if phase == "after_publication_commit_before_receipt" {
							return crashAfterPublicCAS
						}
						return nil
					}); err != crashAfterPublicCAS {
					t.Fatalf("publication commit crash %s: %v", authority.Role, err)
				}
				response, err := formalGLMPhase21RockRun(
					authorities[index].root, false,
					formalGLMPhase21RockActionCommitPublication,
					encodedOperation)
				if err != nil || response.Commit == nil || response.Publication == nil ||
					response.State != formalGLMPhase21RockStatePublicationCommit ||
					!reflectPublicV2Equal(*response.Publication,
						*publicationResponse.Publication) {
					t.Fatalf("publication commit %s: %+v / %v",
						authority.Role, response, err)
				}
				commitJSON, err := json.Marshal(response)
				if err != nil {
					t.Fatal(err)
				}
				for _, forbidden := range [][]byte{
					[]byte(`"capsule_id"`), []byte(`"reservation`),
					[]byte(`"ledger`), []byte(`"lifetime`), []byte(`"epoch`),
					[]byte(`"shares"`), []byte(`"ciphertext"`),
					[]byte(`"ticket_sha256"`), []byte(`"final_pair_root_sha256"`),
				} {
					if bytes.Contains(commitJSON, forbidden) {
						t.Fatalf("public commit response %s leaked %q",
							authority.Role, forbidden)
					}
				}
				commitRecords[index] = *response.Commit
				commitPaths[index], err = formalGLMPhase21RockCommitRecordPath(
					authorities[index].root, artifactID, authority.Role)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(secretPath); !os.IsNotExist(err) {
					t.Fatalf("publication commit secret survived %s", authority.Role)
				}
				replayed, err := formalGLMPhase21RockRun(
					authorities[index].root, false,
					formalGLMPhase21RockActionCommitPublication,
					encodedOperation)
				if err != nil || !replayed.Replayed || replayed.Commit == nil ||
					!reflect.DeepEqual(*replayed.Commit, commitRecords[index]) {
					t.Fatalf("publication commit replay %s: %+v / %v",
						authority.Role, replayed, err)
				}

				if index == 0 {
					var repairRecords [2]formalGLMPhase21RockPreflightRecord
					var repairPaths [2]string
					for peerIndex, peer := range contract.Artifact.NoiseAuthorities {
						peerStickyRoot := sha256.Sum256([]byte(
							t.Name() + "/sticky/" + peer.PeerName))
						preflightSecret := filepath.Join(authorities[peerIndex].root,
							"commands-v1", "repair-preflight-secret.json")
						formalGLMPhase21RockTestWriteJSON(t, preflightSecret,
							formalGLMPhase21RockPreflightSecret{
								Version: formalGLMPhase21RockSecretVersion,
								Family:  formalFinalizerHandoffFamilyGLM,
								Purpose: formalGLMPhase21RockPurpose,
								Action:  formalGLMPhase21RockActionPreflight,
								StickyStorageRoot: base64.StdEncoding.EncodeToString(
									peerStickyRoot[:]),
								SigningPrivateKey: base64.StdEncoding.EncodeToString(
									fixture.formal.identities.private[peer.PeerName]),
							})
						preflightOperation, err := json.Marshal(
							formalGLMPhase21RockPreflightOperation{
								ArtifactContractPath: authorities[peerIndex].operation.ArtifactContractPath,
								PinsetPath:           authorities[peerIndex].operation.PinsetPath,
								RegistryResolutionPath: authorities[peerIndex].operation.
									RegistryResolutionPath,
								PeerName: peer.PeerName, SecretBundlePath: preflightSecret,
							})
						if err != nil {
							t.Fatal(err)
						}
						preflightResponse, err := formalGLMPhase21RockRun(
							authorities[peerIndex].root, false,
							formalGLMPhase21RockActionPreflight, preflightOperation)
						if err != nil || preflightResponse.Preflight == nil {
							t.Fatalf("repair preflight %s: %+v / %v",
								peer.Role, preflightResponse, err)
						}
						repairRecords[peerIndex] = *preflightResponse.Preflight
						repairPaths[peerIndex], err = formalGLMPhase21RockPreflightRecordPath(
							authorities[peerIndex].root, artifactID,
							preflightResponse.State, preflightResponse.CertificateSHA256)
						if err != nil {
							t.Fatal(err)
						}
					}
					state, repair, err := formalGLMPhase21RockPreflightPair(
						repairRecords, contract, fixture.formal.identities.public)
					if err != nil || state != formalGLMPhase21RockStateRepairPending ||
						repair == nil || !reflectPublicV2Equal(
						*repair, *publicationResponse.Publication) {
						t.Fatalf("one-of-two repair state: %s / %v", state, err)
					}
					for peerIndex := range repairPaths {
						target := filepath.Join(authorities[1].root, "inbox-v1",
							fmt.Sprintf("repair-preflight-%d.json", peerIndex))
						formalGLMPhase21RockTestWriteJSON(t, target, repairRecords[peerIndex])
						repairPaths[peerIndex] = target
					}
					repairStage := authorities[1].operation
					repairStage.PreflightRecordPaths = repairPaths
					repairStage.SecretBundlePath = filepath.Join(
						authorities[1].root, "commands-v1", "must-not-be-read.json")
					repairStageJSON, err := json.Marshal(repairStage)
					if err != nil {
						t.Fatal(err)
					}
					repairResponse, err := formalGLMPhase21RockRunWithHook(
						authorities[1].root, false,
						formalGLMPhase21RockActionStage, repairStageJSON,
						func(phase string) error {
							t.Fatalf("repair entered source/sampler phase %s", phase)
							return nil
						})
					if err != nil || repairResponse.State !=
						formalGLMPhase21RockStateRepairPending ||
						repairResponse.Publication == nil {
						t.Fatalf("repair stage did not stop early: %+v / %v",
							repairResponse, err)
					}
				}
			}
			if commitRecords[0].Receipt.CertificateSHA256 !=
				commitRecords[1].Receipt.CertificateSHA256 {
				t.Fatal("local publication commit bytes diverged")
			}
			var publishedRecords [2]formalGLMPhase21RockPreflightRecord
			var publishedPaths [2]string
			for index, authority := range contract.Artifact.NoiseAuthorities {
				stickyRoot := sha256.Sum256([]byte(
					t.Name() + "/sticky/" + authority.PeerName))
				secretPath := filepath.Join(authorities[index].root,
					"commands-v1", "published-preflight-secret.json")
				formalGLMPhase21RockTestWriteJSON(t, secretPath,
					formalGLMPhase21RockPreflightSecret{
						Version: formalGLMPhase21RockSecretVersion,
						Family:  formalFinalizerHandoffFamilyGLM,
						Purpose: formalGLMPhase21RockPurpose,
						Action:  formalGLMPhase21RockActionPreflight,
						StickyStorageRoot: base64.StdEncoding.EncodeToString(
							stickyRoot[:]),
						SigningPrivateKey: base64.StdEncoding.EncodeToString(
							fixture.formal.identities.private[authority.PeerName]),
					})
				operation, err := json.Marshal(formalGLMPhase21RockPreflightOperation{
					ArtifactContractPath: authorities[index].operation.ArtifactContractPath,
					PinsetPath:           authorities[index].operation.PinsetPath,
					RegistryResolutionPath: authorities[index].operation.
						RegistryResolutionPath,
					PeerName: authority.PeerName, SecretBundlePath: secretPath,
				})
				if err != nil {
					t.Fatal(err)
				}
				response, err := formalGLMPhase21RockRun(
					authorities[index].root, false,
					formalGLMPhase21RockActionPreflight, operation)
				if err != nil || response.State != formalGLMPhase21RockStatePublished ||
					response.Preflight == nil || response.Preflight.Publication == nil {
					t.Fatalf("published preflight %s: %+v / %v",
						authority.Role, response, err)
				}
				publishedRecords[index] = *response.Preflight
				publishedPaths[index], err = formalGLMPhase21RockPreflightRecordPath(
					authorities[index].root, artifactID, response.State,
					response.CertificateSHA256)
				if err != nil {
					t.Fatal(err)
				}
			}
			state, replayPublication, err := formalGLMPhase21RockPreflightPair(
				publishedRecords, contract, fixture.formal.identities.public)
			if err != nil || state != formalGLMPhase21RockStatePublished ||
				replayPublication == nil || !reflectPublicV2Equal(
				*replayPublication, *publicationResponse.Publication) {
				t.Fatalf("dual published preflight: %s / %v", state, err)
			}
			for index := range publishedPaths {
				target := filepath.Join(authorities[0].root, "inbox-v1",
					fmt.Sprintf("published-preflight-%d.json", index))
				formalGLMPhase21RockTestWriteJSON(t, target, publishedRecords[index])
				publishedPaths[index] = target
			}
			terminalStage := authorities[0].operation
			terminalStage.PreflightRecordPaths = publishedPaths
			terminalStage.SecretBundlePath = filepath.Join(
				authorities[0].root, "commands-v1", "terminal-must-not-read.json")
			terminalStageJSON, err := json.Marshal(terminalStage)
			if err != nil {
				t.Fatal(err)
			}
			terminalResponse, err := formalGLMPhase21RockRunWithHook(
				authorities[0].root, false, formalGLMPhase21RockActionStage,
				terminalStageJSON, func(phase string) error {
					t.Fatalf("published replay entered execution phase %s", phase)
					return nil
				})
			if err != nil || terminalResponse.State !=
				formalGLMPhase21RockStatePublished ||
				terminalResponse.Publication == nil {
				t.Fatalf("published replay did not stop early: %+v / %v",
					terminalResponse, err)
			}

			divergent := *publicationResponse.Publication
			divergent.AuthorityReceipts = nil
			divergent.ClampedScaledValues = append(
				[]string(nil), divergent.ClampedScaledValues...)
			coordinate, ok := new(big.Int).SetString(
				divergent.ClampedScaledValues[0], 10)
			if !ok {
				t.Fatal("invalid public coordinate")
			}
			divergent.ClampedScaledValues[0] = coordinate.Add(
				coordinate, big.NewInt(1)).String()
			divergent.VectorSHA256, err =
				jointDPBiomedicalGaussianOneDrawVectorSHA256(
					divergent.ClampedScaledValues)
			if err != nil {
				t.Fatal(err)
			}
			var divergentSignatures [2]jointDPBiomedicalGaussianSignature
			for index, authority := range contract.Artifact.NoiseAuthorities {
				divergentSignatures[index], err = formalGLMPhase21SignPublicCertificateV2(
					divergent, authority.PeerName,
					fixture.formal.identities.private[authority.PeerName],
					fixture.formal.identities.public)
				if err != nil {
					t.Fatal(err)
				}
			}
			divergent, err = formalGLMPhase21SealPublicCertificateV2(
				divergent, divergentSignatures[:], fixture.formal.identities.public)
			if err != nil {
				t.Fatal(err)
			}
			conflictOperation, err := json.Marshal(
				formalGLMPhase21RockCommitPublicationOperation{
					ArtifactContractPath: authorities[1].operation.ArtifactContractPath,
					PinsetPath:           authorities[1].operation.PinsetPath,
					PeerName:             contract.Artifact.NoiseAuthorities[1].PeerName,
					Publication:          divergent,
					SecretBundlePath: filepath.Join(authorities[1].root,
						"commands-v1", "conflict-must-not-read.json"),
				})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := formalGLMPhase21RockRun(
				authorities[1].root, false,
				formalGLMPhase21RockActionCommitPublication,
				conflictOperation); err == nil {
				t.Fatal("local publication accepted valid divergent split brain")
			}
			var finalizerCommitPaths [2]string
			for index := range commitRecords {
				finalizerCommitPaths[index] = filepath.Join(
					authorities[0].root, "inbox-v1",
					fmt.Sprintf("publication-commit-%d.json", index))
				formalGLMPhase21RockTestWriteJSON(
					t, finalizerCommitPaths[index], commitRecords[index])
			}
			publicationReadyPath, err := formalGLMPhase21RockPublicationReadyRecordPath(
				authorities[0].root, artifactID)
			if err != nil {
				t.Fatal(err)
			}
			ackSecretPath := filepath.Join(
				authorities[0].root, "commands-v1", "finalize-ack-secret.json")
			finalizerStickyRoot := sha256.Sum256([]byte(
				t.Name() + "/sticky/" + binding.Finalizer.PeerName))
			formalGLMPhase21RockTestWriteJSON(t, ackSecretPath,
				formalGLMPhase21RockFinalizeAckSecret{
					Version: formalGLMPhase21RockSecretVersion,
					Family:  formalFinalizerHandoffFamilyGLM,
					Purpose: formalGLMPhase21RockPurpose,
					Action:  formalGLMPhase21RockActionFinalizeAck,
					StickyStorageRoot: base64.StdEncoding.EncodeToString(
						finalizerStickyRoot[:]),
					TransportStorageRoot: base64.StdEncoding.EncodeToString(
						authorities[0].transportRoot[:]),
					SigningPrivateKey: base64.StdEncoding.EncodeToString(
						fixture.formal.identities.private[binding.Finalizer.PeerName]),
				})
			ackOperation := formalGLMPhase21RockFinalizeAckOperation{
				ArtifactContractPath:       authorities[0].operation.ArtifactContractPath,
				PinsetPath:                 authorities[0].operation.PinsetPath,
				StageRecordPaths:           stagePaths,
				TicketRecordPath:           ticketRecordPath,
				PublicationReadyRecordPath: publicationReadyPath,
				CommitRecordPaths:          finalizerCommitPaths,
				PeerName:                   binding.Finalizer.PeerName,
				SecretBundlePath:           ackSecretPath,
			}
			swappedAck := ackOperation
			swappedAck.CommitRecordPaths = [2]string{
				finalizerCommitPaths[1], finalizerCommitPaths[0],
			}
			swappedAckJSON, err := json.Marshal(swappedAck)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := formalGLMPhase21RockRun(
				authorities[0].root, false,
				formalGLMPhase21RockActionFinalizeAck,
				swappedAckJSON); err == nil {
				t.Fatal("final ACK accepted reordered commit receipts")
			}
			ackOperationJSON, err := json.Marshal(ackOperation)
			if err != nil {
				t.Fatal(err)
			}
			crashAfterAck := fmt.Errorf("test crash after finalizer ACK")
			if _, err := formalGLMPhase21RockRunWithHook(
				authorities[0].root, false,
				formalGLMPhase21RockActionFinalizeAck,
				ackOperationJSON, func(phase string) error {
					if phase == "after_finalizer_ack_before_record" {
						return crashAfterAck
					}
					return nil
				}); err != crashAfterAck {
				t.Fatalf("final ACK crash hook: %v", err)
			}
			ackResponse, err := formalGLMPhase21RockRun(
				authorities[0].root, false,
				formalGLMPhase21RockActionFinalizeAck, ackOperationJSON)
			if err != nil || ackResponse.Ack == nil ||
				ackResponse.Publication == nil ||
				ackResponse.State != formalGLMPhase21RockStateAckReady ||
				ackResponse.CertificateSHA256 !=
					commitRecords[0].Receipt.CertificateSHA256 ||
				!reflectPublicV2Equal(*ackResponse.Publication,
					*publicationResponse.Publication) {
				t.Fatalf("final ACK recovery: %+v / %v", ackResponse, err)
			}
			if _, err := os.Lstat(ackSecretPath); !os.IsNotExist(err) {
				t.Fatal("final ACK secret survived durable record")
			}
			for _, path := range finalizerCommitPaths {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			ackReplay, err := formalGLMPhase21RockRun(
				authorities[0].root, false,
				formalGLMPhase21RockActionFinalizeAck, ackOperationJSON)
			if err != nil || !ackReplay.Replayed || ackReplay.Ack == nil ||
				!reflect.DeepEqual(*ackReplay.Ack, *ackResponse.Ack) {
				t.Fatalf("final ACK replay: %+v / %v", ackReplay, err)
			}

			for index, authority := range contract.Artifact.NoiseAuthorities {
				var localStagePaths [2]string
				for stageIndex, stageRecord := range records {
					localStagePaths[stageIndex] = filepath.Join(
						authorities[index].root, "inbox-v1",
						fmt.Sprintf("cleanup-stage-%d.json", stageIndex))
					formalGLMPhase21RockTestWriteJSON(
						t, localStagePaths[stageIndex], stageRecord)
				}
				localTicketPath := filepath.Join(
					authorities[index].root, "inbox-v1", "cleanup-ticket.json")
				localAckPath := filepath.Join(
					authorities[index].root, "inbox-v1", "cleanup-ack.json")
				formalGLMPhase21RockTestWriteJSON(
					t, localTicketPath, *ticketResponse.Ticket)
				formalGLMPhase21RockTestWriteJSON(
					t, localAckPath, *ackResponse.Ack)
				source, _, err := fixture.stores[authority.PeerName].Load()
				if err != nil {
					t.Fatal(err)
				}
				backendKey := source.backend
				source.clear()
				stickyRoot := sha256.Sum256([]byte(
					t.Name() + "/sticky/" + authority.PeerName))
				phase20Root := sha256.Sum256([]byte(
					t.Name() + "/phase20/" + authority.PeerName))
				cleanupSecretPath := filepath.Join(
					authorities[index].root, "commands-v1", "cleanup-secret.json")
				writeCleanupSecret := func() {
					formalGLMPhase21RockTestWriteJSON(t, cleanupSecretPath,
						formalGLMPhase21RockAckSecret{
							Version: formalGLMPhase21RockSecretVersion,
							Family:  formalFinalizerHandoffFamilyGLM,
							Purpose: formalGLMPhase21RockPurpose,
							Action:  formalGLMPhase21RockActionAck,
							StickyStorageRoot: base64.StdEncoding.EncodeToString(
								stickyRoot[:]),
							Phase20StorageRoot: base64.StdEncoding.EncodeToString(
								phase20Root[:]),
							BackendKey: base64.StdEncoding.EncodeToString(backendKey[:]),
							TransportStorageRoot: base64.StdEncoding.EncodeToString(
								authorities[index].transportRoot[:]),
							SigningPrivateKey: base64.StdEncoding.EncodeToString(
								fixture.formal.identities.private[authority.PeerName]),
						})
				}
				writeCleanupSecret()
				cleanupOperation := formalGLMPhase21RockAckOperation{
					ArtifactContractPath: authorities[index].operation.ArtifactContractPath,
					PinsetPath:           authorities[index].operation.PinsetPath,
					RegistryResolutionPath: authorities[index].operation.
						RegistryResolutionPath,
					StageRecordPaths: localStagePaths,
					TicketRecordPath: localTicketPath,
					CommitRecordPath: commitPaths[index],
					AckRecordPath:    localAckPath,
					PeerName:         authority.PeerName,
					Publication:      *publicationResponse.Publication,
					Phase20SemanticRootSHA256: authorities[index].operation.
						Phase20SemanticRootSHA256,
					CapsulePath: authorities[index].operation.CapsulePath,
					RequestPath: authorities[index].operation.RequestPath,
					BackendSignaturesPath: authorities[index].operation.
						BackendSignaturesPath,
					WorkerSignaturesPath: authorities[index].operation.
						WorkerSignaturesPath,
					SecretBundlePath: cleanupSecretPath,
				}
				cleanupOperationJSON, err := json.Marshal(cleanupOperation)
				if err != nil {
					t.Fatal(err)
				}
				crashPhase := "after_source_cleanup"
				if index == 1 {
					crashPhase = "after_transport_cleanup_before_record"
				}
				crashAfterCleanup := fmt.Errorf(
					"test crash during %s cleanup", authority.Role)
				if _, err := formalGLMPhase21RockRunWithHook(
					authorities[index].root, false,
					formalGLMPhase21RockActionAck, cleanupOperationJSON,
					func(phase string) error {
						if phase == crashPhase {
							return crashAfterCleanup
						}
						return nil
					}); err != crashAfterCleanup {
					t.Fatalf("cleanup crash %s: %v", authority.Role, err)
				}
				cleanupResponse, err := formalGLMPhase21RockRun(
					authorities[index].root, false,
					formalGLMPhase21RockActionAck, cleanupOperationJSON)
				if err != nil || cleanupResponse.Cleanup == nil ||
					cleanupResponse.Publication == nil ||
					cleanupResponse.State != formalGLMPhase21RockStateCleaned ||
					!reflectPublicV2Equal(*cleanupResponse.Publication,
						*publicationResponse.Publication) {
					t.Fatalf("cleanup recovery %s: %+v / %v",
						authority.Role, cleanupResponse, err)
				}
				if _, err := os.Lstat(cleanupSecretPath); !os.IsNotExist(err) {
					t.Fatalf("cleanup secret survived %s", authority.Role)
				}
				cleanupReplay, err := formalGLMPhase21RockRun(
					authorities[index].root, false,
					formalGLMPhase21RockActionAck, cleanupOperationJSON)
				if err != nil || !cleanupReplay.Replayed ||
					cleanupReplay.Cleanup == nil ||
					!reflect.DeepEqual(*cleanupReplay.Cleanup,
						*cleanupResponse.Cleanup) {
					t.Fatalf("cleanup replay %s: %+v / %v",
						authority.Role, cleanupReplay, err)
				}
				if _, err := os.Lstat(authorities[index].phase20Record); !os.IsNotExist(err) {
					t.Fatalf("Phase-2.0 source survived %s cleanup", authority.Role)
				}
				lateStore, err := newFormalFinalizerHandoffAuthorityStoreForTest(
					authorities[index].root, binding,
					formalFinalizerHandoffAuthority{
						PeerName: authority.PeerName, PeerID: authority.PeerID,
						Role: authority.Role,
					}, authorities[index].transportRoot,
					fixture.formal.identities.public)
				if err != nil {
					t.Fatal(err)
				}
				_, _, lateErr := lateStore.CommitOutbox(sealedEnvelopes[index])
				var terminalAck *formalFinalizerHandoffTerminalAckError
				if !errors.As(lateErr, &terminalAck) || !reflect.DeepEqual(
					terminalAck.Proof, ackResponse.Ack.Proof) {
					lateStore.Close()
					t.Fatalf("late outbox did not return exact ACK %s: %v",
						authority.Role, lateErr)
				}
				if index == 0 {
					_, secretKey, _, issueErr := lateStore.IssueTicketOnce(
						fixture.formal.identities.private[authority.PeerName])
					clear(secretKey)
					terminalAck = nil
					if !errors.As(issueErr, &terminalAck) || !reflect.DeepEqual(
						terminalAck.Proof, ackResponse.Ack.Proof) {
						lateStore.Close()
						t.Fatalf("late ticket did not return exact ACK: %v", issueErr)
					}
				}
				lateStore.Close()
				err = filepath.WalkDir(authorities[index].root,
					func(path string, entry os.DirEntry, walkErr error) error {
						if walkErr != nil {
							return walkErr
						}
						if entry.Type().IsRegular() &&
							(strings.Contains(path, string(filepath.Separator)+"outbox-v1"+
								string(filepath.Separator)) ||
								strings.Contains(path, string(filepath.Separator)+"ingress-v1"+
									string(filepath.Separator)) ||
								strings.Contains(path, string(filepath.Separator)+"transport-keys-v1"+
									string(filepath.Separator)) ||
								strings.Contains(path, string(filepath.Separator)+"formal-glm-local-v1"+
									string(filepath.Separator))) {
							return fmt.Errorf("transport file survived cleanup")
						}
						return nil
					})
				if err != nil {
					t.Fatalf("cleanup residue %s: %v", authority.Role, err)
				}
				cleanupJSON, err := json.Marshal(cleanupResponse)
				if err != nil {
					t.Fatal(err)
				}
				for _, forbidden := range [][]byte{
					[]byte(`"capsule_id"`), []byte(`"reservation`),
					[]byte(`"ledger`), []byte(`"lifetime`), []byte(`"epoch`),
					[]byte(`"shares"`), []byte(`"ciphertext"`),
					[]byte(`"ticket_sha256"`), []byte(`"final_pair_root_sha256"`),
				} {
					if bytes.Contains(cleanupJSON, forbidden) {
						t.Fatalf("cleanup response %s leaked %q",
							authority.Role, forbidden)
					}
				}
				publicRecordPath := filepath.Join(authorities[index].root,
					"formal-glm-sticky-v2", "public-v2", artifactID[:2],
					artifactID[2:4], "release-"+artifactID+".json")
				if err := os.Chmod(publicRecordPath, 0o644); err != nil {
					t.Fatal(err)
				}
				if _, err := formalGLMPhase21RockRun(
					authorities[index].root, false,
					formalGLMPhase21RockActionAck,
					cleanupOperationJSON); err == nil {
					t.Fatalf("cleanup replay accepted 0644 public CAS %s",
						authority.Role)
				}
				if err := os.Chmod(publicRecordPath, 0o600); err != nil {
					t.Fatal(err)
				}
				clear(backendKey[:])
			}
		})
	}
}

func reflectPublicStageEqual(left, right formalGLMPhase21RockStageRecord) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}
