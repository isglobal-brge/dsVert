package main

import (
	"bytes"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/markkurossi/mpc/circuit"
)

// Only this synthetic test reconstructs the two private aggregate shares.
func dpIRLSB2CheckStageOutput(t testing.TB, outputs [2]crossGridStageOutput, want []*big.Int) {
	t.Helper()
	for j := range want {
		got := exactGCReferenceReconstruct(
			crossGridStageTestInteger(outputs[0].Share[j*16:(j+1)*16]),
			crossGridStageTestInteger(outputs[1].Share[j*16:(j+1)*16]), 128)
		if got.Cmp(want[j]) != 0 {
			t.Fatalf("coordinate %d: protected=%s independent=%s", j, got, want[j])
		}
		if outputs[0].Validity[j]^outputs[1].Validity[j] != 1 {
			t.Fatalf("coordinate %d: shared validity mismatch", j)
		}
	}
}

func TestDPIRLSB2RealTwoParty64(t *testing.T) { dpIRLSB2RealTwoParty(t, 64) }

func TestDPIRLSB2ExecutorSmall(t *testing.T) { dpIRLSB2RealTwoParty(t, 1) }

func dpIRLSB2RealTwoParty(t *testing.T, n int) {
	for _, family := range []string{"binomial", "poisson"} {
		t.Run(family, func(t *testing.T) {
			beta := []int64{16384, -8192, 4096}
			p := dpIRLSB2TestPlan(family, n, beta)
			plan, err := dpIRLSStageKernelPlan(p)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			k, err := crossGridKernelPrepare(plan)
			if err != nil {
				t.Fatal(err)
			}
			compile := time.Since(start)
			rows := dpIRLSB2Fixtures(family, n)
			for j := range rows {
				if rows[j].Present != 1 {
					rows[j].Present = 0
				}
				if family == "binomial" && rows[j].Y != 0 && rows[j].Y != 1 {
					rows[j].Y = 0
				}
			}
			source := dpIRLSB2Source(rows, 2)
			g, e := exactGCTestSplit(rand.New(rand.NewSource(132)), source, 128)
			for j := len(rows) * (p.P + 3); j < len(source); j++ {
				e[j].Xor(g[j], source[j])
			}
			sources := [2][]*big.Int{g, e}
			graph, err := dpIRLSBuildStageGraph(p, [2]string{"peer-a", "peer-b"})
			if err != nil {
				t.Fatal(err)
			}
			dirs := crossGridStageTestDirs(t)
			var stores [2]*crossGridStageStore
			for role := range stores {
				stores[role], err = crossGridStageOpenStore(dirs[role], crossGridStageTestKey(exactGCRole(role)), graph, exactGCRole(role))
				if err != nil {
					t.Fatal(err)
				}
				defer stores[role].Close()
			}
			base := exactGCTestSession(exactGCCircuitSpec{Operation: dpIRLSStageOperation, RingBits: 128, VectorLen: 9})
			base.GarblerID, base.EvaluatorID = graph.Authorities[0], graph.Authorities[1]
			run := func() ([2]crossGridStageOutput, [2]exactGCProtocolTimings, uint64, time.Duration) {
				left, right := net.Pipe()
				conns := [2]*crossGridPWCountingConn{{Conn: left}, {Conn: right}}
				defer left.Close()
				defer right.Close()
				left.SetDeadline(time.Now().Add(12 * time.Minute))
				right.SetDeadline(time.Now().Add(12 * time.Minute))
				var out [2]crossGridStageOutput
				var times [2]exactGCProtocolTimings
				done := make(chan error, 2)
				started := time.Now()
				for role := range stores {
					go func(role int) {
						ex := &crossGridStageExecutor{Store: stores[role], Base: base}
						var err error
						out[role], err = dpIRLSExecuteStage(conns[role], ex, k, sources[role], &times[role])
						if err != nil {
							conns[role].Close()
						}
						done <- err
					}(role)
				}
				first, second := <-done, <-done
				if first != nil || second != nil {
					t.Fatalf("real two-party stage: %v / %v", first, second)
				}
				return out, times, conns[0].written.Load() + conns[1].written.Load(), time.Since(started)
			}
			out, times, wireBytes, wall := run()
			dpIRLSB2CheckStageOutput(t, out, dpIRLSB2Oracle(t, family, beta, rows, n))
			t.Logf("B2_MEASUREMENT family=%s p=3 n=%d gates=%d and=%d compile_s=%.6f garble_s=%.6f transfer_s=%.6f ot_g_s=%.6f ot_e_s=%.6f evaluate_s=%.6f stage_wall_s=%.6f wire_bytes=%d", family, n,
				k.circuit.NumGates, k.circuit.Stats[circuit.AND], compile.Seconds(), times[0].Garble.Seconds(), times[0].Transfer.Seconds(), times[0].OT.Seconds(), times[1].OT.Seconds(), times[1].Evaluate.Seconds(), wall.Seconds(), wireBytes)
			for _, forecastN := range []int{200, 1000} {
				if n != 64 {
					continue
				}
				factor := float64(forecastN) / 64
				t.Logf("B2_EXTRAPOLATION family=%s p=3 n=%d unadmitted=true model=linear-from-64 stage_wall_s=%.6f compile_s=%.6f wire_bytes=%.0f", family, forecastN, factor*wall.Seconds(), factor*compile.Seconds(), factor*float64(wireBytes))
			}
			// A cold transport retry loads the exact private COMMIT, without new GC
			// or output masks. Production DP draw ownership remains a B3/B4 task.
			replay, replayTimes, _, _ := run()
			if !reflect.DeepEqual(out, replay) || replayTimes != [2]exactGCProtocolTimings{} {
				t.Fatal("retained COMMIT replay changed private shares or re-executed GC")
			}
			// Rebinding a different authenticated-looking point to the old durable
			// graph fails locally, even when its internal point digest is coherent.
			changed := p
			changed.Beta = append([]string(nil), p.Beta...)
			changed.Beta[0] = "16385"
			changed.PointDigest = changed.pointDigest()
			otherPlan, err := dpIRLSStageKernelPlan(changed)
			if err != nil {
				t.Fatal(err)
			}
			other := &crossGridKernelPrepared{plan: otherPlan, circuit: k.circuit}
			var channel bytes.Buffer
			_, err = dpIRLSExecuteStage(&channel, &crossGridStageExecutor{Store: stores[0], Base: base}, other, g, nil)
			if err == nil || channel.Len() != 0 {
				t.Fatal("alternate public beta reached protocol")
			}
			t.Logf("B2_COUNTS family=%s real_2pc=1 aggregate_coordinates=9 replay=1 alternate_point_rejected=1", family)
		})
	}
}

func TestDPIRLSB2NoOrdinaryGCOpening(t *testing.T) {
	for _, op := range []exactGCOperation{dpIRLSStageOperation} {
		if _, err := exactGCCompileCircuit(exactGCCircuitSpec{Operation: op, RingBits: 128, VectorLen: 9}); err == nil {
			t.Fatal(fmt.Sprint("ordinary dispatcher admitted ", op))
		}
	}
}
