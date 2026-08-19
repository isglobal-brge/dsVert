package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const formalGLMPhase21TerminalRaceHelperEnv = "DSVERT_FORMAL_GLM_ACK_RACE_HELPER"

type formalGLMPhase21TerminalRaceHelperConfig struct {
	Dir                      string                            `json:"dir"`
	Binding                  formalFinalizerHandoffBinding     `json:"binding"`
	Local                    formalFinalizerHandoffAuthority   `json:"local"`
	StorageRoot              [32]byte                          `json:"storage_root"`
	Pins                     map[string]ed25519.PublicKey      `json:"pins"`
	Proof                    formalFinalizerHandoffCommitProof `json:"proof"`
	Contract                 formalGLMPhase21SamplerV2Contract `json:"contract"`
	ExpectedTransportRemoved int                               `json:"expected_transport_removed"`
}

func TestFormalGLMPhase21TerminalRaceHelperProcess(t *testing.T) {
	configPath := os.Getenv(formalGLMPhase21TerminalRaceHelperEnv)
	if configPath == "" {
		t.Skip("subprocess helper")
	}
	encoded, err := os.ReadFile(configPath)
	if err != nil {
		os.Exit(24)
	}
	var config formalGLMPhase21TerminalRaceHelperConfig
	if err := json.Unmarshal(encoded, &config); err != nil {
		os.Exit(24)
	}
	store, err := newFormalFinalizerHandoffAuthorityStoreForTest(
		config.Dir, config.Binding, config.Local, config.StorageRoot, config.Pins)
	if err != nil {
		os.Exit(23)
	}
	defer store.Close()
	guard := formalFinalizerHandoffTestPublicationGuard{
		wantArtifact:    config.Proof.ArtifactID,
		wantCertificate: config.Proof.CertificateSHA256,
	}
	if _, _, err := store.AckAfterCommit(config.Proof, guard); err != nil {
		os.Exit(24)
	}
	removed, err := store.CleanupTransportAfterAck(config.Proof)
	if err != nil || removed != config.ExpectedTransportRemoved {
		os.Exit(24)
	}
	localRemoved, err := formalGLMPhase21CleanupLocalOneDrawSpoolAfterAck(
		store, config.Contract, config.Proof)
	if err != nil || localRemoved != 1 {
		os.Exit(24)
	}
}

func formalGLMPhase21RunTerminalRaceHelper(t testing.TB,
	config formalGLMPhase21TerminalRaceHelperConfig, wantExit int,
) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ack-race-helper.json")
	formalGLMPhase21RockTestWriteJSON(t, path, config)
	command := exec.Command(os.Args[0],
		"-test.run=^TestFormalGLMPhase21TerminalRaceHelperProcess$")
	command.Env = append(os.Environ(),
		formalGLMPhase21TerminalRaceHelperEnv+"="+path)
	output, err := command.CombinedOutput()
	if wantExit == 0 {
		if err != nil {
			t.Fatalf("ACK subprocess failed: %v / %q", err, output)
		}
		return
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != wantExit {
		t.Fatalf("ACK subprocess exit=%v, want=%d / %q", err, wantExit, output)
	}
}

func formalGLMPhase21AssertTerminalTransportAbsent(t testing.TB,
	store *formalFinalizerHandoffStore, role string,
) {
	t.Helper()
	paths := make([]string, 0, 4)
	if path, err := formalGLMPhase21LocalSpoolOwnerRelativePath(
		store, false); err == nil {
		paths = append(paths, path)
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if path, err := formalGLMPhase21LocalSpoolRelativePath(
		store, role, false); err == nil {
		paths = append(paths, path)
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if path, err := store.relativePath("outbox-v1", role, "", false); err == nil {
		paths = append(paths, path)
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if path, err := store.relativePath(
		"transport-keys-v1", "", "", false); err == nil {
		paths = append(paths, path)
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, path := range paths {
		if _, err := store.root.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("terminal ACK left or recreated %s: %v", path, err)
		}
	}
}

func TestFormalGLMPhase21PersistSealRaceAckAcrossProcessesK2K3K5(t *testing.T) {
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
			outputByPeer := formalGLMPhase21SamplerV2TestRunOneDraw(
				t, fixture, contract, authorizations)
			defer func() {
				for peer := range outputByPeer {
					output := outputByPeer[peer]
					output.clear()
				}
			}()
			binding, err := formalGLMPhase21OneDrawFinalizerBinding(
				fixture.stores[reference], outputByPeer[reference])
			if err != nil {
				t.Fatal(err)
			}
			local := binding.Finalizer
			if local.Role != "garbler" || local.PeerName != reference {
				t.Fatal("test finalizer authority changed")
			}
			source := fixture.stores[local.PeerName]
			output := outputByPeer[local.PeerName]

			for _, scenario := range []struct {
				name             string
				seal             bool
				transportRemoved int
			}{
				{name: "persist-vs-ack", transportRemoved: 1},
				{name: "seal-vs-ack", seal: true, transportRemoved: 2},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					dir := filepath.Join(t.TempDir(), local.PeerName)
					storageRoot := sha256.Sum256([]byte(t.Name() + "/transport"))
					store, err := newFormalFinalizerHandoffAuthorityStoreForTest(
						dir, binding, local, storageRoot,
						fixture.formal.identities.public)
					if err != nil {
						t.Fatal(err)
					}
					ticket, secret, replayed, err := store.IssueTicketOnce(
						fixture.formal.identities.private[local.PeerName])
					clear(secret)
					if err != nil || replayed {
						store.Close()
						t.Fatalf("ticket setup: replay=%v err=%v", replayed, err)
					}
					if scenario.seal {
						_, replayed, err = formalGLMPhase21SealLocalOneDraw(
							source, store, contract, ticket, output,
							fixture.formal.identities.private[local.PeerName],
							nil)
					} else {
						replayed, err = formalGLMPhase21PersistLocalOneDrawSpool(
							source, store, contract, output)
					}
					if err != nil || replayed {
						store.Close()
						t.Fatalf("initial %s: replay=%v err=%v",
							scenario.name, replayed, err)
					}
					ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
					if err != nil {
						store.Close()
						t.Fatal(err)
					}
					certificateSHA := formalFinalizerHandoffTestSHA(
						t.Name() + "/certificate")
					proof, err := formalFinalizerHandoffBuildCommitProof(
						binding, ticketSHA, certificateSHA,
						fixture.formal.identities.private[local.PeerName],
						fixture.formal.identities.public)
					if err != nil {
						store.Close()
						t.Fatal(err)
					}
					config := formalGLMPhase21TerminalRaceHelperConfig{
						Dir: dir, Binding: binding, Local: local,
						StorageRoot: storageRoot,
						Pins:        fixture.formal.identities.public,
						Proof:       proof, Contract: contract,
						ExpectedTransportRemoved: scenario.transportRemoved,
					}
					formalGLMPhase21RunTerminalRaceHelper(t, config, 23)
					store.Close()
					formalGLMPhase21RunTerminalRaceHelper(t, config, 0)

					restarted, err := newFormalFinalizerHandoffAuthorityStoreForTest(
						dir, binding, local, storageRoot,
						fixture.formal.identities.public)
					if err != nil {
						t.Fatal(err)
					}
					defer restarted.Close()
					if scenario.seal {
						_, replayed, err = formalGLMPhase21SealLocalOneDraw(
							source, restarted, contract, ticket, output,
							fixture.formal.identities.private[local.PeerName], nil)
					} else {
						replayed, err = formalGLMPhase21PersistLocalOneDrawSpool(
							source, restarted, contract, output)
					}
					var terminal *formalFinalizerHandoffTerminalAckError
					if !replayed || !errors.As(err, &terminal) ||
						terminal.Proof.CertificateSHA256 != certificateSHA {
						t.Fatalf("late %s did not resolve terminal ACK: replay=%v err=%v",
							scenario.name, replayed, err)
					}
					formalGLMPhase21AssertTerminalTransportAbsent(
						t, restarted, local.Role)
				})
			}
		})
	}
}
