package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestGroupedLMMWorkerCapacitySmoke(t *testing.T) {
	groupedLMMWorkerCapacity(t, 2, t.TempDir())
}

// Actual complete internal typed worker, including authenticated synthetic
// source, private routing/conversion, exact products and certified terminal.
// This does not invoke real owner materialization or the subsequent DP gate.
func TestGroupedLMMWorkerCapacityN2000C500(t *testing.T) {
	if os.Getenv("DSVERT_LMM_WORKER_CAPACITY") != "1" {
		t.Skip("set DSVERT_LMM_WORKER_CAPACITY=1 on the isolated proof host")
	}
	parent := os.Getenv("DSVERT_LMM_CAPACITY_ROOT")
	if !filepath.IsAbs(parent) || filepath.Clean(parent) != parent {
		t.Fatal("an absolute private capacity evidence root is required")
	}
	root, err := os.MkdirTemp(parent, "lmm-n2000-c500-")
	if err != nil {
		t.Fatal(err)
	}
	// Keep both authority stores for independently reviewable cold/tamper
	// evidence; this directory contains public synthetic fixture shares only.
	t.Logf("synthetic_private_evidence_directory=%s", root)
	groupedLMMWorkerCapacity(t, 500, root)
}

func groupedLMMWorkerCapacity(t *testing.T, clusters int, root string) {
	t.Helper()
	started := time.Now()
	const slots, predictors, candidates = 4, 3, 2
	rows, numeric, metadata, cols := clusters*slots, predictors+1, predictors+3, predictors+2
	labels, present, live := make([]int, rows), make([]bool, rows), make([]bool, rows)
	values, meta := make([]Uint128, rows*numeric), make([]Uint128, rows*metadata)
	oracleRows := make([][]*big.Int, rows)
	positions := make([]int, clusters)
	for r := 0; r < rows; r++ {
		labels[r], present[r], live[r] = (r*137)%clusters, true, true
		for c := 0; c < numeric; c++ {
			// Include non-dyadic f50 encodings and exact boundaries. The oracle
			// works on these integer inputs, never floats or rounded moments.
			values[r*numeric+c] = U128FromBig(new(big.Int).Quo(new(big.Int).Lsh(big.NewInt(int64((r*103+c*17)%1025)), 50), big.NewInt(1024)))
			if r%17 == 3 {
				values[r*numeric+c] = U128FromBig(new(big.Int).Quo(new(big.Int).Lsh(big.NewInt(1), 50), big.NewInt(int64(3+2*c))))
			}
			p := uint64(1)
			if (c == numeric-1 && r%113 == 0) || (c == 0 && r%157 == 0) {
				p, live[r] = 0, false
			}
			meta[r*metadata+c] = Uint128{Lo: p}
		}
		meta[r*metadata+numeric], meta[r*metadata+numeric+1] = Uint128{Lo: uint64(labels[r])}, Uint128{Lo: 1}
		destination := labels[r]*slots + positions[labels[r]]
		positions[labels[r]]++
		oracleRows[destination] = make([]*big.Int, cols)
		for c := 0; c < cols; c++ {
			oracleRows[destination][c] = new(big.Int)
			if live[r] {
				if c == 0 {
					oracleRows[destination][c].Lsh(big.NewInt(1), 50)
				} else {
					oracleRows[destination][c].Set(values[r*numeric+c-1].ToBig())
				}
			}
		}
	}
	sources := [2][2]crossGridStageOutput{}
	for field, data := range [][]Uint128{values, meta} {
		for role := range sources {
			sources[role][field] = crossGridStageOutput{Share: make([]byte, 16*len(data)), Validity: make([]byte, len(data))}
		}
		for i, value := range data {
			mask := sha256.Sum256([]byte(fmt.Sprintf("public synthetic LMM capacity/%d/%d/%d", clusters, field, i)))
			a := getUint128LE(mask[:16])
			putUint128LE(sources[0][field].Share[16*i:16*(i+1)], a)
			putUint128LE(sources[1][field].Share[16*i:16*(i+1)], value.Sub(a))
			sources[0][field].Validity[i], sources[1][field].Validity[i] = mask[16]&1, (mask[16]&1)^1
		}
	}
	hexDigest := func(label string) string { value := sha256.Sum256([]byte(label)); return hex.EncodeToString(value[:]) }
	wire := groupedLMMSourceWirePlan{Version: "dsvert-lmm-staged-source-handoff-v1",
		SpecSHA256: hexDigest("synthetic LMM capacity signed spec"), SourceContractSHA256: hexDigest("synthetic LMM capacity source contract"),
		ProfileSHA256: hexDigest("synthetic retained fixed variance LMM profile"), SchemaSHA256: hexDigest("synthetic LMM capacity schema"),
		Clusters: clusters, Slots: slots, Predictors: predictors}
	wire.Numeric.Slots, wire.Numeric.GridBits, wire.Numeric.ResidualCap = slots, 8, 2
	wire.Numeric.Sigma2Q64, wire.Numeric.Tau2Q64, wire.Numeric.OutputCap = "18447025548686262272", "4611686018427387904", "4096"
	f := new(big.Int).Lsh(big.NewInt(1), 50)
	quarter, half := new(big.Int).Rsh(new(big.Int).Set(f), 2), new(big.Int).Rsh(new(big.Int).Set(f), 1)
	wire.Beta = [][]string{{"0", "0", "0", "0"}, {quarter.String(), half.String(), new(big.Int).Neg(quarter).String(), quarter.String()}}
	wire.Caps = []string{wire.Numeric.OutputCap, wire.Numeric.OutputCap}
	inputs := [2]*groupedLMMWorkerInput{}
	for role := range inputs {
		key, roleName := crossGridStageTestKey(exactGCRole(role)), "garbler"
		if role == 1 {
			roleName = "evaluator"
		}
		input := groupedLMMPrepareWireInput{Role: roleName, Session: fmt.Sprintf("synthetic-lmm-capacity-c%d", clusters),
			Authorities: [2]string{"peer-a-pinned-key", "peer-b-pinned-key"}, SemanticKey: hexDigest("sticky synthetic LMM capacity release"),
			StoreDirectory: filepath.Join(root, fmt.Sprintf("authority-%d", role)), StoreKey: base64.StdEncoding.EncodeToString(key[:]),
			Handoff: groupedLMMSourceWireHandoff{Plan: wire}}
		encode := func(out crossGridStageOutput) groupedLMMSourceWireOutput {
			return groupedLMMSourceWireOutput{base64.StdEncoding.EncodeToString(out.Share), base64.StdEncoding.EncodeToString(out.Validity)}
		}
		input.Handoff.Numeric, input.Handoff.Metadata = encode(sources[role][0]), encode(sources[role][1])
		if role == 0 {
			input.Routing = &struct {
				Labels  []int  `json:"labels"`
				Present []bool `json:"present"`
			}{labels, present}
		}
		prepared, err := groupedLMMPrepareWire(input)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(prepared)
		if err != nil {
			t.Fatal(err)
		}
		inputs[role] = new(groupedLMMWorkerInput)
		if json.Unmarshal(raw, inputs[role]) != nil {
			t.Fatal("canonical opaque typed worker input failed")
		}
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("synthetic-worker-input-%d.json", role)), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	prepared := [2]*groupedLMMWorkerPrepared{}
	config := [2]exactGCWorkerConfig{}
	session := [2]exactGCSession{}
	var attempted atomic.Int64
	var stopped atomic.Bool
	measurement := map[string]any{"component": "complete-internal-typed-lmm-worker", "n": rows, "clusters": clusters, "slots": slots,
		"predictors": predictors, "candidates": candidates, "traffic_limit_bytes": 256000000000, "time_limit_seconds": 21600,
		"completed": false, "oracle_equal": false, "cold_replay_equal": false, "source_replacement_rejected": false, "stage_tamper_rejected": false,
		"production_release": false, "dp_executed": false, "promoted": false, "objective": "retained certified fixed-variance quadratic"}
	defer func() {
		measurement["all_checks_seconds"], measurement["budget_stop"] = time.Since(started).Seconds(), stopped.Load()
		raw, _ := json.Marshal(measurement)
		os.WriteFile(filepath.Join(root, "measurement.json"), raw, 0600)
		t.Log(string(raw))
	}()
	prepare := func(attempt int, cold bool) {
		for role := range prepared {
			in := inputs[role]
			config[role] = groupedLMMWorkerTestConfig(t, role, in.Spec, in.Source, in.Routing, in.StoreDirectory, filepath.Join(root, fmt.Sprintf("spool-%d", role)), attempt)
			session[role] = groupedLMMWorkerTestSession(t, config[role])
			var err error
			prepared[role], err = groupedLMMWorkerPrepare(config[role], session[role])
			if err != nil {
				t.Fatal(err)
			}
			if cold {
				for i := range prepared[role].graph.Compute {
					prepared[role].graph.Compute[i] = func(io.ReadWriter, crossGridStageAttempt, []crossGridStageOutput) (crossGridStageOutput, error) {
						return crossGridStageOutput{}, errors.New("cold typed worker recomputed a committed stage")
					}
				}
			}
		}
	}
	type result struct {
		output exactGCWorkerResult
		err    error
	}
	run := func() ([2]result, [2]int64) {
		left, right := net.Pipe()
		left.SetDeadline(started.Add(6 * time.Hour))
		right.SetDeadline(started.Add(6 * time.Hour))
		defer left.Close()
		defer right.Close()
		counts := [2]*primitiveVCountingRW{{Conn: left}, {Conn: right}}
		connections := [2]*coxBenchmarkConn{{counts[0], &attempted, &stopped, 256000000000}, {counts[1], &attempted, &stopped, 256000000000}}
		ch := make(chan result, 1)
		go func() {
			output, err := prepared[0].run(connections[0], session[0])
			left.Close()
			ch <- result{output, err}
		}()
		output, err := prepared[1].run(connections[1], session[1])
		right.Close()
		return [2]result{<-ch, {output, err}}, [2]int64{counts[0].Written, counts[1].Written}
	}
	prepare(0, false)
	measurement["stages"] = len(prepared[0].graph.Graph.Stages)
	t.Logf("public_schedule n=%d C=%d B=%d p=%d J=%d stages=%d products=%d precision_products=%d", rows, clusters, slots, predictors, candidates,
		len(prepared[0].graph.Graph.Stages), inputs[0].Spec.LMM.Moments.products(), clusters*inputs[0].Spec.LMM.Moments.triangle())
	got, traffic := run()
	measurement["seconds"], measurement["garbler_bytes"], measurement["evaluator_bytes"] = time.Since(started).Seconds(), traffic[0], traffic[1]
	measurement["total_bytes"] = traffic[0] + traffic[1]
	for _, r := range got {
		if r.err != nil {
			t.Fatal(r.err)
		}
	}
	measurement["completed"] = true
	if got[0].output.StageReceipt != got[1].output.StageReceipt || got[0].output.StagePlanDigest != got[1].output.StagePlanDigest {
		t.Fatal("typed worker terminal receipts disagree")
	}
	decoded := [2][]*big.Int{}
	validity := [2][]bool{}
	for role, r := range got {
		var err error
		decoded[role], err = exactGCDecodeWorkerShares(r.output.Share, exactGCCircuitSpec{Operation: exactGCTruncateFloor, RingBits: 128, VectorLen: candidates})
		if err != nil {
			t.Fatal(err)
		}
		validity[role], err = unpackBoolsB64(r.output.ValidityShare, candidates)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(r.output)
		if os.WriteFile(filepath.Join(root, fmt.Sprintf("synthetic-worker-result-%d.json", role)), raw, 0600) != nil {
			t.Fatal("could not preserve private component result")
		}
	}
	want := make([]string, candidates)
	for j, beta := range inputs[0].Spec.LMM.Beta {
		oracle := new(big.Int)
		for c := 0; c < clusters; c++ {
			oracle.Add(oracle, groupedLMMStatsOracle(inputs[0].Spec.LMM.Numeric, oracleRows[c*slots:(c+1)*slots], beta))
		}
		if exactGCReferenceReconstruct(decoded[0][j], decoded[1][j], 128).Cmp(oracle) != 0 || validity[0][j] == validity[1][j] {
			t.Fatalf("complete typed worker differs from independent exact oracle at candidate %d", j)
		}
		want[j] = oracle.String()
	}
	measurement["oracle_equal"], measurement["synthetic_oracle_coordinates"] = true, want
	prepare(1, true)
	coldStarted := time.Now()
	cold, coldTraffic := run()
	for role, r := range cold {
		prior := got[role].output
		if r.err != nil || r.output.Share != prior.Share || r.output.ValidityShare != prior.ValidityShare || r.output.StageReceipt != prior.StageReceipt || r.output.StagePlanDigest != prior.StagePlanDigest || r.output.ContextHash == prior.ContextHash {
			t.Fatal("fresh-transport cold replay changed committed bytes or recomputed", r.err)
		}
	}
	measurement["cold_replay_equal"], measurement["cold_seconds"], measurement["cold_total_bytes"] = true, time.Since(coldStarted).Seconds(), coldTraffic[0]+coldTraffic[1]
	// Re-MACed replacement must still fail against the durable exact-source
	// binding, separately from the source record's ordinary MAC rejection.
	p := prepared[0]
	store, err := crossGridStageOpenStore(p.directory, p.key, p.graph.Graph, p.role)
	if err != nil {
		t.Fatal(err)
	}
	changed := *config[0].GroupedLMM
	changedSource := *changed.Source
	changedSource.Numeric = crossGridStageClone(changedSource.Numeric)
	changedSource.Numeric.Share[0] ^= 1
	changedSource.MAC = groupedLMMSourceMAC(p.key, changedSource)
	changed.Source = &changedSource
	changedConfig := config[0]
	changedConfig.GroupedLMM = &changed
	replacement, err := groupedLMMWorkerPrepare(changedConfig, session[0])
	if err != nil || replacement.bindSource(store) == nil {
		store.Close()
		t.Fatal("durable source replacement gate failed", err)
	}
	measurement["source_replacement_rejected"] = true
	first := p.graph.Graph.Stages[0]
	path := filepath.Join(p.directory, store.name(first.ID))
	original, err := os.ReadFile(path)
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	tampered := bytes.Clone(original)
	tampered[len(tampered)-1] ^= 1
	if os.WriteFile(path, tampered, 0600) != nil {
		store.Close()
		t.Fatal("could not inject synthetic stage tamper")
	}
	_, rejected := store.load(first, nil)
	restored := os.WriteFile(path, original, 0600)
	store.Close()
	if rejected == nil || restored != nil {
		t.Fatal("stage tamper was accepted or restoration failed")
	}
	measurement["stage_tamper_rejected"] = true
}
