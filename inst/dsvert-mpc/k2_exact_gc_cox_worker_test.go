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

func coxLossWorkerTestConfig(t *testing.T, role int, spec coxLossSourceSpec, source *coxLossSourceRecord, side *coxLossStagedRouting, directory, spool string, attempt int) exactGCWorkerConfig {
	t.Helper()
	key := crossGridStageTestKey(exactGCRole(role))
	session := sha256.Sum256([]byte(fmt.Sprintf("cox worker transport/%s/%d", t.Name(), attempt)))
	master := sha256.Sum256([]byte(fmt.Sprintf("cox worker transport master/%s/%d", t.Name(), attempt)))
	name := "garbler"
	if role == 1 {
		name, side = "evaluator", nil
	}
	return exactGCWorkerConfig{Version: exactGCWorkerConfigVersion, Role: name,
		SessionID: hex.EncodeToString(session[:]), MasterKey: base64.StdEncoding.EncodeToString(master[:]),
		GarblerID: spec.Authorities[0], EvaluatorID: spec.Authorities[1], Purpose: coxLossWorkerPurpose(spec),
		Operation: string(coxLossWorkerOperation), RingBits: 128, VectorLen: spec.Cox.Plan.Spec.Candidates,
		SpoolDir: spool, MaxSpoolBytes: 1 << 30, TTLSeconds: 600,
		CoxLoss: &coxLossWorkerInput{Spec: spec, Source: source, Routing: side,
			StoreDirectory: directory, StoreKey: base64.StdEncoding.EncodeToString(key[:])}}
}

func coxLossWorkerTestSession(t *testing.T, config exactGCWorkerConfig) exactGCSession {
	t.Helper()
	session, err := exactGCSessionFromWire(config.SessionID, config.MasterKey, config.GarblerID, config.EvaluatorID,
		config.Purpose, config.Operation, config.RingBits, config.FracBits, config.Threshold, config.MulBackend,
		config.BoundX, config.BoundY, config.VectorLen)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestCoxLossWorkerOpaqueNativeIntegers(t *testing.T) {
	s, sources, side, _ := coxLossSourceFixture(t)
	config := coxLossWorkerTestConfig(t, 0, s, sources[0], side, filepath.Join(t.TempDir(), "durable"), exactGCTestSpool(t, "spool"), 0)
	// Deliberately not representable in a binary64 mantissa.
	config.CoxLoss.Spec.Cox.Plan.Spec.Caps[0] = (uint64(1) << 60) + 1
	raw, err := json.Marshal(config.CoxLoss)
	if err != nil {
		t.Fatal(err)
	}
	var encoded string
	if json.Unmarshal(raw, &encoded) != nil || encoded == "" {
		t.Fatal("native input was not opaque")
	}
	var recovered coxLossWorkerInput
	if json.Unmarshal(raw, &recovered) != nil || recovered.Spec.Cox.Plan.Spec.Caps[0] != config.CoxLoss.Spec.Cox.Plan.Spec.Caps[0] {
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

func TestCoxLossWorkerSourceBindingRejectsReplacement(t *testing.T) {
	s, sources, side, _ := coxLossSourceFixture(t)
	config := coxLossWorkerTestConfig(t, 0, s, sources[0], side, filepath.Join(t.TempDir(), "durable"), exactGCTestSpool(t, "spool"), 0)
	session := coxLossWorkerTestSession(t, config)
	prepared, err := coxLossWorkerPrepare(config, session)
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
	sources[0].Predictors.Share[0] ^= 1
	sources[0].MAC = coxLossSourceMAC(prepared.key, *sources[0])
	changed, err := coxLossWorkerPrepare(config, session)
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
	if err := store.root.Remove("cox-source.binding"); err != nil {
		t.Fatal(err)
	}
	if prepared.bindSource(store) == nil {
		t.Fatal("missing binding beside existing stage accepted")
	}
	for _, change := range []string{"purpose", "legacy-source", "lmm-source", "glmm-source", "gee-source", "seed", "role", "spool-store"} {
		t.Run(change, func(t *testing.T) {
			bad := config
			input := *config.CoxLoss
			bad.CoxLoss = &input
			ss := session
			switch change {
			case "purpose":
				ss.Purpose += "/changed"
			case "legacy-source":
				bad.SourceShare = "AAAA"
			case "lmm-source":
				bad.GroupedLMM = &groupedLMMWorkerInput{}
			case "glmm-source":
				bad.GroupedGLMM = &groupedGLMMWorkerInput{}
			case "gee-source":
				bad.GroupedGEE = &groupedGEEWorkerInput{}
			case "seed":
				bad.PrivateSeed = "AAAA"
			case "role":
				bad.Role = "unexpected"
			case "spool-store":
				input.StoreDirectory = filepath.Join(bad.SpoolDir, "durable")
			}
			if _, err := coxLossWorkerPrepare(bad, ss); err == nil {
				t.Fatal("invalid typed worker policy accepted")
			}
		})
	}
}

func TestCoxLossStagedSpoolWorkers(t *testing.T) {
	s, sources, side, rows := coxLossSourceFixture(t)
	directories := [2]string{filepath.Join(t.TempDir(), "durable"), filepath.Join(t.TempDir(), "durable")}
	var prior [2]exactGCWorkerResult
	for attempt := 0; attempt < 2; attempt++ {
		spools := [2]string{exactGCTestSpool(t, "garbler"), exactGCTestSpool(t, "evaluator")}
		paths := [2]string{}
		for role := range paths {
			config := coxLossWorkerTestConfig(t, role, s, sources[role], side, directories[role], spools[role], attempt)
			paths[role] = exactGCTestWriteConfig(t, spools[role], config)
		}
		done := make(chan error, 2)
		for _, path := range paths {
			go func(path string) { done <- handleExactGCWorker(path) }(path)
		}
		offsets := [2]int64{}
		deadline, completed := time.Now().Add(10*time.Minute), 0
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
			t.Fatal("Cox staged spool workers timed out")
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
			if r.Kind != "cox-loss-staged-ring128-share-v1" || len(r.StageReceipt) != 64 || len(r.StagePlanDigest) != 64 {
				t.Fatal("terminal staged evidence missing")
			}
			var err error
			opened[role], err = exactGCDecodeWorkerShares(r.Share, exactGCCircuitSpec{Operation: exactGCTruncateFloor, RingBits: 128, VectorLen: s.Cox.Plan.Spec.Candidates})
			if err != nil {
				t.Fatal(err)
			}
			validity[role], err = unpackBoolsB64(r.ValidityShare, s.Cox.Plan.Spec.Candidates)
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
		for j := range s.Cox.Plan.Spec.Caps {
			want := new(big.Int).SetUint64(rows[j])
			if exactGCReferenceReconstruct(opened[0][j], opened[1][j], 128).Cmp(want) != 0 || validity[0][j] == validity[1][j] {
				t.Fatal("staged worker private terminal differs from exact oracle")
			}
		}
		prior = results
	}
}

func coxLossSourceFixture(t *testing.T) (coxLossSourceSpec, [2]*coxLossSourceRecord, *coxLossStagedRouting, []uint64) {
	t.Helper()
	const n, jcount = 4, 2
	cap, err := coxLossCap(n, 12, []float64{4, 4})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := registerCoxGridCrossLoss().SharedPlan(coxLossSpec{n, jcount, 12, []uint64{cap, cap}, CoxGridCrossProfileID})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("signed Cox worker source fixture"))
	spec := coxLossSourceSpec{Session: "cox-worker-source-test", Authorities: [2]string{"peer-a-pinned-key", "peer-b-pinned-key"}, SchemaDigest: digest, SemanticKey: digest, Cox: coxLossStagedSpec{Plan: plan, Prefix: "cox.worker", SourceDigest: digest, Contract: digest}}
	var source [2][2]crossGridStageOutput
	for field := 0; field < 2; field++ {
		coordinates := make([]string, 8)
		for i := range coordinates {
			coordinates[i] = fmt.Sprintf("row:%d:column:%d", i/2, i%2)
		}
		spec.Cox.Sources[field] = crossGridStagePlan{ID: fmt.Sprintf("cox.source.%d", field), Kind: []string{"cox.complete-f100-dots", "cox.q0-live-event"}[field], Ring: 128, FPScale: []int{100, 0}[field], CoordOrder: coordinates, PublicBounds: map[string]int{"rows": n, "candidates": jcount}, SourceDigest: digest, ProfileDigest: digest}
		for role := 0; role < 2; role++ {
			source[role][field] = crossGridStageOutput{Share: make([]byte, 128), Validity: make([]byte, 8)}
		}
	}
	times := []float64{1, 2, 2, 0}
	live := []bool{true, true, true, false}
	events := []bool{true, true, false, false}
	etas := [][]int32{{65536, -65536, 32768, 0}, {0, 16384, -32768, 0}}
	for row := 0; row < n; row++ {
		for field := 0; field < 2; field++ {
			for column := 0; column < 2; column++ {
				value := new(big.Int)
				if field == 0 {
					value.Lsh(big.NewInt(int64(etas[column][row])), 84)
				} else if (column == 0 && live[row]) || (column == 1 && events[row]) {
					value.SetInt64(1)
				}
				mask, err := groupedRandomWord()
				if err != nil {
					t.Fatal(err)
				}
				a := Uint128{Lo: mask[0], Hi: mask[1]}
				b := U128FromBig(exactGCEncodeSigned(value, 128)).Sub(a)
				index := 2*row + column
				putUint128LE(source[0][field].Share[16*index:16*(index+1)], a)
				putUint128LE(source[1][field].Share[16*index:16*(index+1)], b)
				source[0][field].Validity[index] = byte(mask[2] & 1)
				source[1][field].Validity[index] = byte(mask[2]&1) ^ 1
			}
		}
	}
	controls, err := primitiveVPermutationControls([]int{1, 2, 0, 3})
	if err != nil {
		t.Fatal(err)
	}
	side, err := coxLossSealStagedRouting(spec.Cox, controls, []bool{false, true, true, true}, crossGridStageTestKey(0))
	if err != nil {
		t.Fatal(err)
	}
	spec.Cox.RoutingDigest = side.MAC
	var records [2]*coxLossSourceRecord
	for role := range records {
		records[role], err = coxLossSealSource(spec, exactGCRole(role), source[role][0], source[role][1], crossGridStageTestKey(exactGCRole(role)))
		if err != nil {
			t.Fatal(err)
		}
	}
	wants := make([]uint64, jcount)
	for j := range wants {
		wants[j], err = coxLossReference(etas[j], times, events, live, cap, 12)
		if err != nil {
			t.Fatal(err)
		}
	}
	return spec, records, side, wants
}
