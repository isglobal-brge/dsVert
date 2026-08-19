package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func formalGLMPhase19ScheduleTestConfig(t testing.TB,
	fixture formalGLMPhase18FinalizerFixture,
	inputs map[string]formalGLMPhase19RuntimeLocalInput,
	peer, role, spool string) formalGLMPhase19ScheduleWorkerConfig {
	t.Helper()
	local := inputs[peer]
	paths := append([]string(nil), local.IngressPaths...)
	local.BlockIndex = -1
	local.IngressPaths = nil
	pins := make(map[string]string, len(fixture.identities.public))
	for name, value := range fixture.identities.public {
		pins[name] = base64.StdEncoding.EncodeToString(value)
	}
	checkpoint := sha256.Sum256(
		[]byte(t.Name() + "/checkpoint-key/" + peer))
	heartbeat := sha256.Sum256(
		[]byte(t.Name() + "/heartbeat-key/" + peer))
	root := sha256.Sum256([]byte(t.Name() + "/schedule-root"))
	semanticRoot := sha256.Sum256([]byte(t.Name() + "/semantic-root"))
	attempt := sha256.Sum256([]byte(t.Name() + "/attempt"))
	manifestPath := filepath.Join(spool, "formal-block-manifest-v1.jsonl")
	manifest, err := json.Marshal(formalGLMPhase19ScheduleManifestBlock{
		BlockIndex: 0, IngressPaths: paths,
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest = append(manifest, '\n')
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestDigest := sha256.Sum256(manifest)
	_, storeBytes, err := formalGLMPhase19StreamStoreRequiredBytes(local.Plan)
	if err != nil {
		t.Fatal(err)
	}
	return formalGLMPhase19ScheduleWorkerConfig{
		Version: formalGLMPhase19ScheduleWorkerVersion,
		Role:    role, LocalTemplate: local,
		BlockManifestPath:   manifestPath,
		BlockManifestSHA256: hex.EncodeToString(manifestDigest[:]),
		BlockManifestBytes:  int64(len(manifest)),
		MaxBlockStoreBytes:  storeBytes,
		SemanticRootSHA256:  hex.EncodeToString(semanticRoot[:]),
		ScheduleRootSHA256:  hex.EncodeToString(root[:]),
		AttemptID:           hex.EncodeToString(attempt[:]),
		HandoffDir:          filepath.Join(t.TempDir(), "handoff", peer),
		SpoolDir:            spool, MaxSpoolBytes: 64 << 20, TTLSeconds: 30,
		HeartbeatKey: base64.StdEncoding.EncodeToString(heartbeat[:]),
		Durable: formalGLMPhase19ScheduleDurableConfig{
			CheckpointDir: filepath.Join(t.TempDir(), "checkpoint", peer),
			CheckpointKey: base64.StdEncoding.EncodeToString(checkpoint[:]),
			SigningSecretKey: base64.StdEncoding.EncodeToString(
				fixture.identities.private[peer]),
			PinnedPublicKeys:  pins,
			OutputLatticeBits: fixture.plan.Kernel.FracBits,
		},
	}
}

func formalGLMPhase19ScheduleWriteConfig(t testing.TB, spool string,
	config formalGLMPhase19ScheduleWorkerConfig) string {
	t.Helper()
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(spool, "formal-schedule-config.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func formalGLMPhase19ScheduleReadCompletion(t testing.TB, spool string) (
	formalGLMPhase19ScheduleCompletion, []byte) {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join(spool, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result formalGLMPhase19ScheduleCompletion
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result, encoded
}

func formalGLMPhase19ScheduleLoadHandoff(t testing.TB,
	config formalGLMPhase19ScheduleWorkerConfig,
) (formalGLMPhase20HandoffSource, *formalGLMPhase20HandoffStore) {
	t.Helper()
	checkpoint, err := formalGLMPhase19RuntimeDecodeKey(
		config.Durable.CheckpointKey, "test checkpoint key")
	if err != nil {
		t.Fatal(err)
	}
	backend, err := formalGLMPhase19RuntimeDecodeKey(
		config.LocalTemplate.BackendKey, "test backend key")
	if err != nil {
		t.Fatal(err)
	}
	pins, err := formalGLMPhase19ScheduleDecodePins(
		config.Durable.PinnedPublicKeys,
		config.LocalTemplate.Plan.Kernel.CustodianPeers)
	if err != nil {
		t.Fatal(err)
	}
	store, err := newFormalGLMPhase20HandoffStore(
		config.HandoffDir, config.SemanticRootSHA256,
		config.LocalTemplate.Recipient, checkpoint, backend, pins)
	clear(checkpoint[:])
	clear(backend[:])
	if err != nil {
		t.Fatal(err)
	}
	source, _, err := store.Load()
	if err != nil {
		store.close()
		t.Fatal(err)
	}
	return source, store
}

func TestFormalGLMPhase19DurableScheduleWorkerOverSegmentedSpoolK2K3K4K5(
	t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		for _, custodians := range []int{2, 3, 4, 5} {
			name := family + "-K" + string(rune('0'+custodians))
			t.Run(name, func(t *testing.T) {
				fixture := formalGLMPhase18TestBuildFinalizerFixtureFamily(
					t, custodians, family)
				inputs := formalGLMPhase19RuntimeTestInputs(t, fixture)
				garblerPeer := fixture.ctx.ComputePeers[0]
				evaluatorPeer := fixture.ctx.ComputePeers[1]
				garblerDir := exactGCTestSpool(t, "formal-schedule-garbler")
				evaluatorDir := exactGCTestSpool(t, "formal-schedule-evaluator")
				garblerConfig := formalGLMPhase19ScheduleTestConfig(
					t, fixture, inputs, garblerPeer, "garbler", garblerDir)
				evaluatorConfig := formalGLMPhase19ScheduleTestConfig(
					t, fixture, inputs, evaluatorPeer, "evaluator", evaluatorDir)
				garblerPath := formalGLMPhase19ScheduleWriteConfig(
					t, garblerDir, garblerConfig)
				evaluatorPath := formalGLMPhase19ScheduleWriteConfig(
					t, evaluatorDir, evaluatorConfig)

				errors := make(chan error, 2)
				go func() {
					errors <- handleFormalGLMPhase19ScheduleWorker(garblerPath)
				}()
				go func() {
					errors <- handleFormalGLMPhase19ScheduleWorker(evaluatorPath)
				}()
				garblerOffset, evaluatorOffset := int64(0), int64(0)
				// Retain unacknowledged data briefly to exercise durable spool
				// backpressure/retry rather than an in-memory net.Pipe shortcut.
				time.Sleep(20 * time.Millisecond)
				deadline := time.Now().Add(90 * time.Second)
				for !exactGCTestBothDone(garblerDir, evaluatorDir) &&
					time.Now().Before(deadline) {
					garblerOffset = exactGCTestRelaySpool(
						t, garblerDir, evaluatorDir, garblerOffset)
					evaluatorOffset = exactGCTestRelaySpool(
						t, evaluatorDir, garblerDir, evaluatorOffset)
					now := time.Now()
					for _, dir := range []string{garblerDir, evaluatorDir} {
						if err := os.Chtimes(
							filepath.Join(dir, "exchange.hb"), now, now); err != nil {
							t.Fatal(err)
						}
					}
					time.Sleep(time.Millisecond)
				}
				if !exactGCTestBothDone(garblerDir, evaluatorDir) {
					t.Fatal("durable schedule workers did not complete")
				}
				for index := 0; index < 2; index++ {
					if err := <-errors; err != nil {
						t.Fatalf("durable schedule worker: %v", err)
					}
				}
				garblerCompletion, garblerJSON := formalGLMPhase19ScheduleReadCompletion(
					t, garblerDir)
				evaluatorCompletion, evaluatorJSON := formalGLMPhase19ScheduleReadCompletion(
					t, evaluatorDir)
				for _, result := range []formalGLMPhase19ScheduleCompletion{
					garblerCompletion, evaluatorCompletion,
				} {
					if result.Version != formalGLMPhase19ScheduleCompletionVersion ||
						result.Kind != formalGLMPhase19ScheduleCompletionKind ||
						!formalGLMIsSHA256(result.HandoffSHA256) ||
						result.HandoffBytes < 64 || result.HandoffReplayed ||
						!result.ExecutionValidSealed ||
						result.ExecutionValidityOpened ||
						result.OpeningsPerformed != 0 || result.ProductionReady {
						t.Fatalf("invalid private schedule result: %#v", result)
					}
				}
				if garblerCompletion.ContextSHA256 !=
					evaluatorCompletion.ContextSHA256 ||
					garblerCompletion.PlanSHA256 != evaluatorCompletion.PlanSHA256 ||
					garblerOffset == 0 || evaluatorOffset == 0 {
					t.Fatal("durable schedule peers did not commit one transcript")
				}
				for _, encoded := range [][]byte{garblerJSON, evaluatorJSON} {
					if bytes.Contains(encoded, []byte(`"dp_share"`)) ||
						bytes.Contains(encoded, []byte(`"betaShares"`)) ||
						bytes.Contains(encoded, []byte(`"backend_key"`)) ||
						bytes.Contains(encoded, []byte(`"signing_secret_key"`)) ||
						bytes.Contains(encoded, []byte(`"local_ingress_key"`)) {
						t.Fatal("private schedule result serialized an upstream secret")
					}
				}
				garblerSource, garblerStore := formalGLMPhase19ScheduleLoadHandoff(
					t, garblerConfig)
				defer garblerSource.clear()
				defer garblerStore.close()
				evaluatorSource, evaluatorStore := formalGLMPhase19ScheduleLoadHandoff(
					t, evaluatorConfig)
				defer evaluatorSource.clear()
				defer evaluatorStore.close()
				garbler := garblerSource.Result
				evaluator := evaluatorSource.Result
				if garbler.PostExecutionToken.TokenSHA256 !=
					evaluator.PostExecutionToken.TokenSHA256 ||
					garbler.DPBridge.FinalReceiptPairSHA256 !=
						evaluator.DPBridge.FinalReceiptPairSHA256 {
					t.Fatal("encrypted handoffs did not bind one transcript")
				}
				garblerShares := garblerSource.DPShares
				evaluatorShares := evaluatorSource.DPShares
				complete := formalGLMPhase19RuntimeExpected(fixture)
				beta, err := referenceFormalGLMPhase15(fixture.plan, complete)
				if err != nil {
					t.Fatal(err)
				}
				want, err := referenceFormalGLMPhase15DPBridge(
					fixture.plan, garbler.DPBridge, beta)
				if err != nil {
					t.Fatal(err)
				}
				for index := range want {
					got := exactGCReferenceReconstruct(
						garblerShares[index], evaluatorShares[index], 128)
					if got.Cmp(want[index]) != 0 {
						t.Fatalf("DP bridge %d got %s want %s", index, got, want[index])
					}
				}
				if family == "binomial" && custodians == 2 {
					replayDir := exactGCTestSpool(t, "formal-schedule-restart")
					replayConfig := formalGLMPhase19ScheduleTestConfig(
						t, fixture, inputs, garblerPeer, "garbler", replayDir)
					replayConfig.HandoffDir = garblerConfig.HandoffDir
					replayConfig.SemanticRootSHA256 =
						garblerConfig.SemanticRootSHA256
					replayRoot := sha256.Sum256([]byte(t.Name() + "/restart-root"))
					replayAttempt := sha256.Sum256([]byte(t.Name() + "/restart-attempt"))
					replayConfig.ScheduleRootSHA256 = hex.EncodeToString(replayRoot[:])
					replayConfig.AttemptID = hex.EncodeToString(replayAttempt[:])
					replayPath := formalGLMPhase19ScheduleWriteConfig(
						t, replayDir, replayConfig)
					if err := handleFormalGLMPhase19ScheduleWorker(replayPath); err != nil {
						t.Fatal(err)
					}
					replayed, _ := formalGLMPhase19ScheduleReadCompletion(t, replayDir)
					if !replayed.HandoffReplayed ||
						replayed.HandoffSHA256 != garblerCompletion.HandoffSHA256 ||
						replayed.ScheduleRootSHA256 !=
							replayConfig.ScheduleRootSHA256 ||
						replayed.AttemptID != replayConfig.AttemptID {
						t.Fatal("worker restart did not reuse the committed handoff")
					}
				}
				exactGCZeroBigInts(beta)
				exactGCZeroBigInts(want)
			})
		}
	}
}

func TestFormalGLMPhase19ScheduleWorkerRejectsUnsafeOrRoleChangedConfig(
	t *testing.T) {
	fixture := formalGLMPhase18TestBuildFinalizerFixtureFamily(t, 2, "binomial")
	inputs := formalGLMPhase19RuntimeTestInputs(t, fixture)
	spool := exactGCTestSpool(t, "formal-schedule-invalid")
	config := formalGLMPhase19ScheduleTestConfig(
		t, fixture, inputs, fixture.ctx.ComputePeers[0],
		"garbler", spool)
	path := formalGLMPhase19ScheduleWriteConfig(t, spool, config)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := formalGLMPhase19ScheduleReadWorkerConfig(path); err == nil {
		t.Fatal("schedule worker accepted a group-readable secret config")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	config.Role = "evaluator"
	if _, err := formalGLMPhase19ScheduleValidateConfig(config); err == nil {
		t.Fatal("schedule worker accepted a role/recipient substitution")
	}
}

func TestFormalGLMPhase19ScheduleWorkerBindsCryptographicRoleOrderK2K3K5(
	t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		name := "K" + string(rune('0'+custodians))
		t.Run(name, func(t *testing.T) {
			fixture := formalGLMPhase18TestBuildFinalizerFixtureFamily(
				t, custodians, "binomial")
			inputs := formalGLMPhase19RuntimeTestInputs(t, fixture)
			spool := exactGCTestSpool(t, "formal-schedule-role-binding")
			config := formalGLMPhase19ScheduleTestConfig(
				t, fixture, inputs, fixture.ctx.ComputePeers[0],
				"garbler", spool)

			computeNames := append([]string(nil),
				config.LocalTemplate.Plan.Kernel.ComputePeers...)
			signingSecrets := map[string]string{
				computeNames[0]: base64.StdEncoding.EncodeToString(
					fixture.identities.private[computeNames[0]]),
				computeNames[1]: base64.StdEncoding.EncodeToString(
					fixture.identities.private[computeNames[1]]),
			}
			pins, err := formalGLMPhase19ScheduleDecodePins(
				config.Durable.PinnedPublicKeys,
				config.LocalTemplate.Plan.Kernel.CustodianPeers)
			if err != nil {
				t.Fatal(err)
			}
			roles, err := formalGLMPhase15DPBridgePinnedRoles(
				config.LocalTemplate.Plan, pins)
			if err != nil {
				t.Fatal(err)
			}
			if roles.garblerName == computeNames[0] {
				config.Durable.PinnedPublicKeys[computeNames[0]],
					config.Durable.PinnedPublicKeys[computeNames[1]] =
					config.Durable.PinnedPublicKeys[computeNames[1]],
					config.Durable.PinnedPublicKeys[computeNames[0]]
				signingSecrets[computeNames[0]], signingSecrets[computeNames[1]] =
					signingSecrets[computeNames[1]], signingSecrets[computeNames[0]]
				pins, err = formalGLMPhase19ScheduleDecodePins(
					config.Durable.PinnedPublicKeys,
					config.LocalTemplate.Plan.Kernel.CustodianPeers)
				if err != nil {
					t.Fatal(err)
				}
				roles, err = formalGLMPhase15DPBridgePinnedRoles(
					config.LocalTemplate.Plan, pins)
				if err != nil {
					t.Fatal(err)
				}
			}
			if roles.garblerName != computeNames[1] ||
				roles.evaluatorName != computeNames[0] {
				t.Fatal("test did not invert logical-name and cryptographic role order")
			}
			config.LocalTemplate.Plan.Kernel.ComputePeers = []string{
				roles.garblerName, roles.evaluatorName,
			}
			config.LocalTemplate.Recipient = roles.garblerName
			config.Durable.SigningSecretKey = signingSecrets[roles.garblerName]

			if _, err := formalGLMPhase19ScheduleValidateConfig(config); err != nil {
				t.Fatalf("canonical cryptographic role order: %v", err)
			}
			canonicalDigest, err := formalGLMPhase15PlanDigest(
				config.LocalTemplate.Plan)
			if err != nil {
				t.Fatal(err)
			}

			tampered := config
			tampered.LocalTemplate.Plan.Kernel.ComputePeers = append(
				[]string(nil), config.LocalTemplate.Plan.Kernel.ComputePeers...)
			tampered.LocalTemplate.Plan.Kernel.ComputePeers[0],
				tampered.LocalTemplate.Plan.Kernel.ComputePeers[1] =
				tampered.LocalTemplate.Plan.Kernel.ComputePeers[1],
				tampered.LocalTemplate.Plan.Kernel.ComputePeers[0]
			tampered.LocalTemplate.Recipient =
				tampered.LocalTemplate.Plan.Kernel.ComputePeers[0]
			tamperedDigest, err := formalGLMPhase15PlanDigest(
				tampered.LocalTemplate.Plan)
			if err != nil {
				t.Fatal(err)
			}
			if canonicalDigest == tamperedDigest {
				t.Fatal("compute-role order was not bound into the signed plan digest")
			}
			if _, err := formalGLMPhase19ScheduleValidateConfig(tampered); err == nil {
				t.Fatal("schedule worker accepted name-ordered role tampering")
			}

			pinTampered := config
			pinTampered.Durable.PinnedPublicKeys = make(map[string]string,
				len(config.Durable.PinnedPublicKeys))
			for peer, pin := range config.Durable.PinnedPublicKeys {
				pinTampered.Durable.PinnedPublicKeys[peer] = pin
			}
			pinTampered.Durable.PinnedPublicKeys[computeNames[0]],
				pinTampered.Durable.PinnedPublicKeys[computeNames[1]] =
				pinTampered.Durable.PinnedPublicKeys[computeNames[1]],
				pinTampered.Durable.PinnedPublicKeys[computeNames[0]]
			if _, err := formalGLMPhase19ScheduleValidateConfig(pinTampered); err == nil {
				t.Fatal("schedule worker accepted identity-pin role tampering")
			}
		})
	}
}
