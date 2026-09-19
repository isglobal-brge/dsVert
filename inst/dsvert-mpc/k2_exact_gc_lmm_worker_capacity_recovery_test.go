package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Reuse a completed real n2000 run's authenticated prefix, then interrupt an
// actually recomputed terminal stage. No PREPARE/COMMIT marker is fabricated,
// and no production store or original baseline file is changed.
func TestGroupedLMMWorkerCapacityRecoveryN2000(t *testing.T) {
	baseline := os.Getenv("DSVERT_LMM_CAPACITY_BASELINE")
	if baseline == "" {
		t.Skip("set DSVERT_LMM_CAPACITY_BASELINE to the completed private n2000 evidence directory")
	}
	groupedLMMWorkerCapacityRecovery(t, baseline, 2000, 500)
}

func TestGroupedLMMWorkerCapacityRecoverySmoke(t *testing.T) {
	baseline := t.TempDir()
	groupedLMMWorkerCapacity(t, 2, baseline)
	groupedLMMWorkerCapacityRecovery(t, baseline, 8, 2)
}

func groupedLMMWorkerCapacityRecovery(t *testing.T, baseline string, rows, clusters int) {
	t.Helper()
	if !filepath.IsAbs(baseline) || filepath.Clean(baseline) != baseline {
		t.Fatal("invalid baseline path")
	}
	var measured struct {
		Completed   bool `json:"completed"`
		Oracle      bool `json:"oracle_equal"`
		Cold        bool `json:"cold_replay_equal"`
		N, Clusters int
	}
	raw, err := os.ReadFile(filepath.Join(baseline, "measurement.json"))
	if err != nil || json.Unmarshal(raw, &measured) != nil || !measured.Completed || !measured.Oracle || !measured.Cold || measured.N != rows || measured.Clusters != clusters {
		t.Fatal("baseline is not a completed verified capacity run", err)
	}
	inputs := [2]*groupedLMMWorkerInput{}
	for role := range inputs {
		raw, err := os.ReadFile(filepath.Join(baseline, fmt.Sprintf("synthetic-worker-input-%d.json", role)))
		if err != nil {
			t.Fatal(err)
		}
		inputs[role] = new(groupedLMMWorkerInput)
		if json.Unmarshal(raw, inputs[role]) != nil {
			t.Fatal("invalid preserved typed worker input")
		}
	}
	want := groupedLMMCapacityIndependentOracle(t, inputs)
	for _, scenario := range []string{"bilateral-terminal-prepare", "unilateral-terminal-commit"} {
		t.Run(scenario, func(t *testing.T) {
			started := time.Now()
			root, err := os.MkdirTemp(filepath.Dir(baseline), "lmm-recovery-")
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("synthetic_private_recovery_directory=%s", root)
			prepared := [2]*groupedLMMWorkerPrepared{}
			sessions := [2]exactGCSession{}
			for role := range prepared {
				in := *inputs[role]
				in.StoreDirectory = filepath.Join(root, fmt.Sprintf("authority-%d", role))
				config := groupedLMMWorkerTestConfig(t, role, in.Spec, in.Source, in.Routing, in.StoreDirectory, filepath.Join(root, fmt.Sprintf("spool-%d", role)), 10)
				sessions[role] = groupedLMMWorkerTestSession(t, config)
				prepared[role], err = groupedLMMWorkerPrepare(config, sessions[role])
				if err != nil {
					t.Fatal(err)
				}
				if os.Mkdir(in.StoreDirectory, 0700) != nil {
					t.Fatal("could not create private recovery store")
				}
				terminal := prepared[role].graph.Graph.Stages[len(prepared[role].graph.Graph.Stages)-1].ID
				omit := fmt.Sprintf("%x.stage", crossGridStageHash("record-path", []string{in.Spec.Session, terminal}))
				files, err := os.ReadDir(inputs[role].StoreDirectory)
				if err != nil {
					t.Fatal(err)
				}
				for _, file := range files {
					if file.Name() == omit || (file.Name() != "lmm-source.binding" && !strings.HasSuffix(file.Name(), ".stage")) {
						continue
					}
					data, err := os.ReadFile(filepath.Join(inputs[role].StoreDirectory, file.Name()))
					if err != nil || os.WriteFile(filepath.Join(in.StoreDirectory, file.Name()), data, 0600) != nil {
						t.Fatal("could not preserve authenticated prefix", err)
					}
				}
				for i, stage := range prepared[role].graph.Graph.Stages {
					if stage.ID != terminal {
						prepared[role].graph.Compute[i] = groupedLMMCapacityForbiddenCompute
					}
				}
			}
			var attempted atomic.Int64
			var stopped atomic.Bool
			pair := func(run func(int, io.ReadWriter) error) ([2]error, [2]int64) {
				left, right := net.Pipe()
				left.SetDeadline(started.Add(6 * time.Hour))
				right.SetDeadline(started.Add(6 * time.Hour))
				defer left.Close()
				defer right.Close()
				counts := [2]*primitiveVCountingRW{{Conn: left}, {Conn: right}}
				connections := [2]*coxBenchmarkConn{{counts[0], &attempted, &stopped, 256000000000}, {counts[1], &attempted, &stopped, 256000000000}}
				ch := make(chan error, 1)
				go func() { e := run(0, connections[0]); left.Close(); ch <- e }()
				e := run(1, connections[1])
				right.Close()
				return [2]error{<-ch, e}, [2]int64{counts[0].Written, counts[1].Written}
			}
			faulted, firstTraffic := pair(func(role int, rw io.ReadWriter) error {
				p := prepared[role]
				store, e := crossGridStageOpenStore(p.directory, p.key, p.graph.Graph, p.role)
				if e != nil {
					return e
				}
				defer store.Close()
				if e = p.bindSource(store); e != nil {
					return e
				}
				executor := crossGridStageExecutor{Store: store, Base: sessions[role]}
				terminal := p.graph.Graph.Stages[len(p.graph.Graph.Stages)-1].ID
				event := "after-prepare"
				if scenario == "unilateral-terminal-commit" {
					if role == 0 {
						event = "after-commit"
					} else {
						event = "after-prepare-exchange"
					}
				}
				executor.fault = func(at string, r crossGridStageRecord) error {
					if r.StageID == terminal && at == event {
						return errors.New("synthetic actual terminal interruption")
					}
					return nil
				}
				_, e = executor.Execute(rw, p.graph.Compute)
				return e
			})
			if faulted[0] == nil || faulted[1] == nil {
				t.Fatal("terminal fault was not observed by both authorities")
			}
			before := groupedLMMCapacityTerminalRecords(t, prepared)
			states := [2]string{"PREPARE", "PREPARE"}
			if scenario == "unilateral-terminal-commit" {
				states[0] = "COMMIT"
			}
			for role, r := range before {
				if r.State != states[role] {
					t.Fatalf("expected %s, found %s", states[role], r.State)
				}
			}
			results := [2]exactGCWorkerResult{}
			for role := range prepared {
				config := groupedLMMWorkerTestConfig(t, role, inputs[role].Spec, inputs[role].Source, inputs[role].Routing, prepared[role].directory, filepath.Join(root, fmt.Sprintf("retry-spool-%d", role)), 11)
				sessions[role] = groupedLMMWorkerTestSession(t, config)
				if scenario == "unilateral-terminal-commit" {
					for i := range prepared[role].graph.Compute {
						prepared[role].graph.Compute[i] = groupedLMMCapacityForbiddenCompute
					}
				}
			}
			recovered, lastTraffic := pair(func(role int, rw io.ReadWriter) error {
				var e error
				results[role], e = prepared[role].run(rw, sessions[role])
				return e
			})
			for _, e := range recovered {
				if e != nil {
					t.Fatal(e)
				}
			}
			after := groupedLMMCapacityTerminalRecords(t, prepared)
			for role, r := range after {
				if r.State != "COMMIT" {
					t.Fatal("terminal did not commit")
				}
				if scenario == "bilateral-terminal-prepare" {
					if r.AttemptNonce == before[role].AttemptNonce || r.OutputMaskDomainTag == before[role].OutputMaskDomainTag || r.StageReceipt == before[role].StageReceipt {
						t.Fatal("aborted terminal reused attempt randomness")
					}
				} else if r.AttemptNonce != before[role].AttemptNonce || r.StageReceipt != before[role].StageReceipt || !bytes.Equal(r.Output.Share, before[role].Output.Share) || !bytes.Equal(r.Output.Validity, before[role].Output.Validity) {
					t.Fatal("unilateral terminal recomputed persisted shares")
				}
			}
			decoded := [2][]*big.Int{}
			flags := [2][]bool{}
			for role, r := range results {
				decoded[role], err = exactGCDecodeWorkerShares(r.Share, exactGCCircuitSpec{Operation: exactGCTruncateFloor, RingBits: 128, VectorLen: len(want)})
				if err != nil {
					t.Fatal(err)
				}
				flags[role], err = unpackBoolsB64(r.ValidityShare, len(want))
				if err != nil {
					t.Fatal(err)
				}
			}
			for j, oracle := range want {
				if exactGCReferenceReconstruct(decoded[0][j], decoded[1][j], 128).Cmp(oracle) != 0 || flags[0][j] == flags[1][j] {
					t.Fatal("terminal recovery changed exact artifact")
				}
			}
			if results[0].StageReceipt != results[1].StageReceipt {
				t.Fatal("recovered terminal receipt disagreement")
			}
			measurement := map[string]any{"component": "complete-internal-typed-lmm-terminal-recovery", "scenario": scenario, "n": rows, "clusters": clusters,
				"completed": true, "oracle_equal": true, "observed_interrupted_states": states, "prefix_recomputed": false,
				"first_attempt_bytes": firstTraffic[0] + firstTraffic[1], "recovery_bytes": lastTraffic[0] + lastTraffic[1], "total_bytes": firstTraffic[0] + firstTraffic[1] + lastTraffic[0] + lastTraffic[1],
				"seconds": time.Since(started).Seconds(), "budget_stop": stopped.Load(), "traffic_limit_bytes": 256000000000, "time_limit_seconds": 21600,
				"production_release": false, "dp_executed": false, "promoted": false, "baseline": baseline}
			raw, _ := json.Marshal(measurement)
			os.WriteFile(filepath.Join(root, "measurement.json"), raw, 0600)
			t.Log(string(raw))
		})
	}
}

func groupedLMMCapacityForbiddenCompute(io.ReadWriter, crossGridStageAttempt, []crossGridStageOutput) (crossGridStageOutput, error) {
	return crossGridStageOutput{}, errors.New("committed authenticated capacity prefix was recomputed")
}

func groupedLMMCapacityTerminalRecords(t *testing.T, prepared [2]*groupedLMMWorkerPrepared) [2]crossGridStageRecord {
	t.Helper()
	var records [2]crossGridStageRecord
	for role, p := range prepared {
		store, err := crossGridStageOpenStore(p.directory, p.key, p.graph.Graph, p.role)
		if err != nil {
			t.Fatal(err)
		}
		receipts := map[string][32]byte{}
		for _, abi := range p.graph.Graph.Stages {
			var previous [][32]byte
			for _, id := range abi.Predecessors {
				previous = append(previous, receipts[id])
			}
			r, err := store.load(abi, previous)
			if err != nil {
				store.Close()
				t.Fatal(err)
			}
			receipts[abi.ID] = r.StageReceipt
			records[role] = r
		}
		store.Close()
	}
	return records
}

func groupedLMMCapacityIndependentOracle(t *testing.T, inputs [2]*groupedLMMWorkerInput) []*big.Int {
	t.Helper()
	s := inputs[0].Spec
	rows, cols := s.Route.Clusters*s.Route.Slots, s.Route.Predictors+2
	numeric, metadata := cols-1, cols+1
	routed := make([][]*big.Int, rows)
	position := make([]int, s.Route.Clusters)
	for r := 0; r < rows; r++ {
		label := inputs[0].Routing.Labels[r]
		if label < 0 || label >= s.Route.Clusters {
			t.Fatal("invalid synthetic label")
		}
		destination := label*s.Route.Slots + position[label]
		position[label]++
		if destination >= len(routed) {
			t.Fatal("synthetic cluster overflow")
		}
		routed[destination] = make([]*big.Int, cols)
		live := true
		for c := 0; c < numeric; c++ {
			i := 16 * (r*metadata + c)
			p := getUint128LE(inputs[0].Source.Metadata.Share[i : i+16]).Add(getUint128LE(inputs[1].Source.Metadata.Share[i : i+16]))
			live = live && p == (Uint128{Lo: 1})
		}
		for c := 0; c < cols; c++ {
			v := new(big.Int)
			if live {
				if c == 0 {
					v.Lsh(big.NewInt(1), 50)
				} else {
					i := 16 * (r*numeric + c - 1)
					v = getUint128LE(inputs[0].Source.Numeric.Share[i : i+16]).Add(getUint128LE(inputs[1].Source.Numeric.Share[i : i+16])).ToBig()
				}
			}
			routed[destination][c] = v
		}
	}
	want := make([]*big.Int, len(s.LMM.Beta))
	for j, beta := range s.LMM.Beta {
		want[j] = new(big.Int)
		for c := 0; c < s.Route.Clusters; c++ {
			want[j].Add(want[j], groupedLMMStatsOracle(s.LMM.Numeric, routed[c*s.Route.Slots:(c+1)*s.Route.Slots], beta))
		}
	}
	return want
}
