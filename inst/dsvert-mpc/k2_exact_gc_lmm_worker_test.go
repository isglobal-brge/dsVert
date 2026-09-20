package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func groupedLMMWorkerTestConfig(t *testing.T, role int, spec groupedLMMSourceSpec, source *groupedLMMSourceRecord, side *groupedRouteSidecar, directory, spool string, attempt int) exactGCWorkerConfig {
	t.Helper()
	key := crossGridStageTestKey(exactGCRole(role))
	session := sha256.Sum256([]byte(fmt.Sprintf("lmm worker transport/%s/%d", t.Name(), attempt)))
	master := sha256.Sum256([]byte(fmt.Sprintf("lmm worker transport master/%s/%d", t.Name(), attempt)))
	name := "garbler"
	if role == 1 {
		name, side = "evaluator", nil
	}
	return exactGCWorkerConfig{Version: exactGCWorkerConfigVersion, Role: name,
		SessionID: hex.EncodeToString(session[:]), MasterKey: base64.StdEncoding.EncodeToString(master[:]),
		GarblerID: spec.Authorities[0], EvaluatorID: spec.Authorities[1], Purpose: groupedLMMWorkerPurpose(spec),
		Operation: string(groupedLMMWorkerOperation), RingBits: 128, VectorLen: len(spec.LMM.Beta),
		SpoolDir: spool, MaxSpoolBytes: 1 << 30, TTLSeconds: 120,
		GroupedLMM: &groupedLMMWorkerInput{Spec: spec, Source: source, Routing: side,
			StoreDirectory: directory, StoreKey: base64.StdEncoding.EncodeToString(key[:])}}
}

func groupedLMMWorkerTestSession(t *testing.T, config exactGCWorkerConfig) exactGCSession {
	t.Helper()
	session, err := exactGCSessionFromWire(config.SessionID, config.MasterKey, config.GarblerID, config.EvaluatorID,
		config.Purpose, config.Operation, config.RingBits, config.FracBits, config.Threshold, config.MulBackend,
		config.BoundX, config.BoundY, config.VectorLen)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestGroupedLMMWorkerOpaqueNativeIntegers(t *testing.T) {
	s, sources, side, _ := groupedLMMSourceFixture(t)
	config := groupedLMMWorkerTestConfig(t, 0, s, sources[0], side, filepath.Join(t.TempDir(), "durable"), exactGCTestSpool(t, "spool"), 0)
	// Deliberately not representable in a binary64 mantissa.
	config.GroupedLMM.Spec.LMM.Numeric.Sigma2Q64 = new(big.Int).Add(exactGCModulus(64), big.NewInt(1))
	raw, err := json.Marshal(config.GroupedLMM)
	if err != nil {
		t.Fatal(err)
	}
	var encoded string
	if json.Unmarshal(raw, &encoded) != nil || encoded == "" {
		t.Fatal("native input was not opaque")
	}
	var recovered groupedLMMWorkerInput
	if json.Unmarshal(raw, &recovered) != nil || recovered.Spec.LMM.Numeric.Sigma2Q64.Cmp(config.GroupedLMM.Spec.LMM.Numeric.Sigma2Q64) != 0 {
		t.Fatal("opaque worker input lost integer bits")
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range [][]byte{append([]byte(" "), decoded...), append(decoded[:len(decoded)-1], []byte(",\"unexpected\":1}")...)} {
		value, _ := json.Marshal(base64.StdEncoding.EncodeToString(malformed))
		if json.Unmarshal(value, &recovered) == nil {
			t.Fatal("noncanonical native object accepted")
		}
	}
}

func TestGroupedLMMWorkerSourceBindingRejectsReplacement(t *testing.T) {
	s, sources, side, _ := groupedLMMSourceFixture(t)
	config := groupedLMMWorkerTestConfig(t, 0, s, sources[0], side, filepath.Join(t.TempDir(), "durable"), exactGCTestSpool(t, "spool"), 0)
	session := groupedLMMWorkerTestSession(t, config)
	prepared, err := groupedLMMWorkerPrepare(config, session)
	if err != nil {
		t.Fatal(err)
	}
	store, err := crossGridStageOpenStore(prepared.directory, prepared.key, prepared.graph.Graph, prepared.role)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := prepared.bindSource(store); err != nil {
		t.Fatal(err)
	}
	if err := prepared.bindSource(store); err != nil {
		t.Fatal("idempotent source binding rejected")
	}
	// Re-seal changed local bytes to distinguish replacement from a bad MAC.
	sources[0].Numeric.Share[0] ^= 1
	sources[0].MAC = groupedLMMSourceMAC(prepared.key, *sources[0])
	changed, err := groupedLMMWorkerPrepare(config, session)
	if err != nil {
		t.Fatal(err)
	}
	if changed.bindSource(store) == nil {
		t.Fatal("authenticated source replacement accepted")
	}
	first := store.empty(store.graph.Stages[0], nil)
	first.State, first.Generation = "ABORTED", 1
	if err := store.save(first); err != nil {
		t.Fatal(err)
	}
	if err := store.root.Remove("lmm-source.binding"); err != nil {
		t.Fatal(err)
	}
	if prepared.bindSource(store) == nil {
		t.Fatal("missing binding beside existing stage accepted")
	}
	for _, change := range []string{"purpose", "legacy-source", "seed", "role", "spool-store"} {
		t.Run(change, func(t *testing.T) {
			bad := config
			input := *config.GroupedLMM
			bad.GroupedLMM = &input
			ss := session
			switch change {
			case "purpose":
				ss.Purpose += "/changed"
			case "legacy-source":
				bad.SourceShare = "AAAA"
			case "seed":
				bad.PrivateSeed = "AAAA"
			case "role":
				bad.Role = "unexpected"
			case "spool-store":
				input.StoreDirectory = filepath.Join(bad.SpoolDir, "durable")
			}
			if _, err := groupedLMMWorkerPrepare(bad, ss); err == nil {
				t.Fatal("invalid typed worker policy accepted")
			}
		})
	}
}

func TestGroupedLMMStagedSpoolWorkers(t *testing.T) {
	s, sources, side, rows := groupedLMMSourceFixture(t)
	directories := [2]string{filepath.Join(t.TempDir(), "durable"), filepath.Join(t.TempDir(), "durable")}
	var prior [2]exactGCWorkerResult
	for attempt := 0; attempt < 2; attempt++ {
		spools := [2]string{exactGCTestSpool(t, "garbler"), exactGCTestSpool(t, "evaluator")}
		paths := [2]string{}
		for role := range paths {
			config := groupedLMMWorkerTestConfig(t, role, s, sources[role], side, directories[role], spools[role], attempt)
			paths[role] = exactGCTestWriteConfig(t, spools[role], config)
		}
		done := make(chan error, 2)
		for _, path := range paths {
			go func(path string) { done <- handleExactGCWorker(path) }(path)
		}
		offsets := [2]int64{}
		deadline, completed := time.Now().Add(2*time.Minute), 0
		for !exactGCTestBothDone(spools[0], spools[1]) && time.Now().Before(deadline) {
			select {
			case err := <-done:
				completed++
				if err != nil {
					t.Fatal(err)
				}
			default:
			}
			for role := range spools {
				offsets[role] = exactGCTestRelaySpool(t, spools[role], spools[1-role], offsets[role])
				now := time.Now()
				if err := os.Chtimes(filepath.Join(spools[role], "exchange.hb"), now, now); err != nil {
					t.Fatal(err)
				}
			}
			time.Sleep(time.Millisecond)
		}
		if !exactGCTestBothDone(spools[0], spools[1]) {
			t.Fatal("LMM staged spool workers timed out")
		}
		for ; completed < 2; completed++ {
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		}
		var results [2]exactGCWorkerResult
		var opened [2][]*big.Int
		var validity [2][]bool
		for role := range results {
			if fileExists(paths[role]) {
				t.Fatal("private worker configuration survived readiness")
			}
			results[role] = exactGCTestReadResult(t, spools[role])
			r := results[role]
			if r.Kind != "grouped-lmm-staged-ring128-share-v1" || len(r.StageReceipt) != 64 || len(r.StagePlanDigest) != 64 {
				t.Fatal("terminal staged evidence missing")
			}
			var err error
			opened[role], err = exactGCDecodeWorkerShares(r.Share, exactGCCircuitSpec{Operation: exactGCTruncateFloor, RingBits: 128, VectorLen: len(s.LMM.Beta)})
			if err != nil {
				t.Fatal(err)
			}
			validity[role], err = unpackBoolsB64(r.ValidityShare, len(s.LMM.Beta))
			if err != nil {
				t.Fatal(err)
			}
			if attempt > 0 && (r.Share != prior[role].Share || r.ValidityShare != prior[role].ValidityShare || r.StageReceipt != prior[role].StageReceipt || r.StagePlanDigest != prior[role].StagePlanDigest || r.ContextHash == prior[role].ContextHash) {
				t.Fatal("fresh-transport cold replay changed committed bytes/receipt or reused context")
			}
		}
		if results[0].StageReceipt != results[1].StageReceipt || results[0].StagePlanDigest != results[1].StagePlanDigest || results[0].ContextHash != results[1].ContextHash {
			t.Fatal("authority receipt/context disagreement")
		}
		for j, beta := range s.LMM.Beta {
			want := new(big.Int)
			for c := 0; c < s.Route.Clusters; c++ {
				want.Add(want, groupedLMMStatsOracle(s.LMM.Numeric, rows[c*s.Route.Slots:(c+1)*s.Route.Slots], beta))
			}
			if exactGCReferenceReconstruct(opened[0][j], opened[1][j], 128).Cmp(want) != 0 || validity[0][j] == validity[1][j] {
				t.Fatal("staged worker private terminal differs from exact oracle")
			}
		}
		prior = results
	}
}
