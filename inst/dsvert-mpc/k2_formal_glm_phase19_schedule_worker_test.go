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

func formalGLMPhase19ScheduleReadResult(t testing.TB, spool string) (
	formalGLMPhase19ScheduleResult, []byte) {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join(spool, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result formalGLMPhase19ScheduleResult
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result, encoded
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
				garbler, garblerJSON := formalGLMPhase19ScheduleReadResult(
					t, garblerDir)
				evaluator, evaluatorJSON := formalGLMPhase19ScheduleReadResult(
					t, evaluatorDir)
				for _, result := range []formalGLMPhase19ScheduleResult{
					garbler, evaluator,
				} {
					if result.Version != formalGLMPhase19ScheduleResultVersion ||
						result.Kind != formalGLMPhase19ScheduleResultKind ||
						!formalGLMIsSHA256(result.HandoffSHA256) ||
						result.HandoffBytes < 64 || result.HandoffReplayed ||
						!result.ExecutionValidSealed ||
						result.ExecutionValidityOpened ||
						result.OpeningsPerformed != 0 || result.ProductionReady ||
						result.PostExecutionToken.TokenSHA256 == "" {
						t.Fatalf("invalid private schedule result: %#v", result)
					}
				}
				if garbler.PostExecutionToken.TokenSHA256 !=
					evaluator.PostExecutionToken.TokenSHA256 ||
					garbler.DPBridge.FinalReceiptPairSHA256 !=
						evaluator.DPBridge.FinalReceiptPairSHA256 ||
					garblerOffset == 0 || evaluatorOffset == 0 {
					t.Fatal("durable schedule peers did not commit one transcript")
				}
				for _, encoded := range [][]byte{garblerJSON, evaluatorJSON} {
					if bytes.Contains(encoded, []byte(`"betaShares"`)) ||
						bytes.Contains(encoded, []byte(`"backend_key"`)) ||
						bytes.Contains(encoded, []byte(`"signing_secret_key"`)) ||
						bytes.Contains(encoded, []byte(`"local_ingress_key"`)) {
						t.Fatal("private schedule result serialized an upstream secret")
					}
				}
				spec := exactGCCircuitSpec{
					Operation: exactGCFormalGLMDPBridge,
					RingBits:  128, FracBits: 0,
					VectorLen: fixture.plan.Kernel.CoefficientCount,
				}
				garblerShares, err := exactGCDecodeWorkerCanonicalShares(
					garbler.DPShare, spec)
				if err != nil {
					t.Fatal(err)
				}
				evaluatorShares, err := exactGCDecodeWorkerCanonicalShares(
					evaluator.DPShare, spec)
				if err != nil {
					t.Fatal(err)
				}
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
					replayed, _ := formalGLMPhase19ScheduleReadResult(t, replayDir)
					if !replayed.HandoffReplayed ||
						replayed.HandoffSHA256 != garbler.HandoffSHA256 ||
						replayed.DPShare != garbler.DPShare ||
						replayed.ScheduleRootSHA256 !=
							replayConfig.ScheduleRootSHA256 ||
						replayed.AttemptID != replayConfig.AttemptID {
						t.Fatal("worker restart did not reuse the committed handoff")
					}
				}
				exactGCZeroBigInts(garblerShares)
				exactGCZeroBigInts(evaluatorShares)
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
