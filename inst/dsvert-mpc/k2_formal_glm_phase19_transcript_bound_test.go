package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func formalGLMPhase19TranscriptBoundTestDP(t testing.TB,
	plan formalGLMPhase15Plan, lattice int) formalGLMCanonicalPreSourceDPV1 {
	t.Helper()
	dp, err := formalGLMPhase19CanonicalPreSourceDPForLatticeV1(plan, lattice)
	if err != nil {
		t.Fatal(err)
	}
	return dp
}

func formalGLMPhase19TranscriptBoundMultiplicity(
	bound formalGLMPhase19TranscriptBoundV1) uint64 {
	var result uint64
	for _, item := range bound.CircuitInventory {
		result += item.Multiplicity
	}
	return result
}

func formalGLMPhase19TranscriptBoundExpectedCircuits(blocks, iterations int) uint64 {
	result := uint64(blocks)*(uint64(iterations)+1) + uint64(iterations) + 2
	states := uint64(blocks)
	for {
		states = (states + formalGLMPhase19AccumulatorMaxFanIn - 1) /
			formalGLMPhase19AccumulatorMaxFanIn
		result += states
		if states == 1 {
			return result
		}
	}
}

func TestFormalGLMPhase19TranscriptBoundInventoryB1B64B65K2K3K5(
	t *testing.T) {
	tests := []struct {
		k, blocks, iterations int
	}{
		{k: 2, blocks: 1, iterations: 1},
		{k: 3, blocks: 64, iterations: 2},
		{k: 5, blocks: 65, iterations: 3},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("K%d/B%d/I%d", test.k, test.blocks,
			test.iterations), func(t *testing.T) {
			plan := formalGLMPhase15TestPlan(t, "binomial", test.k,
				1, 1, test.blocks, test.iterations)
			dp := formalGLMPhase19TranscriptBoundTestDP(
				t, plan, plan.Kernel.FracBits)
			bound, err := formalGLMPhase19BuildTranscriptBoundV1(plan, dp)
			if err != nil {
				t.Fatal(err)
			}
			if bound.Version != formalGLMPhase19TranscriptBoundVersion ||
				bound.Purpose != formalGLMPhase19TranscriptBoundPurpose ||
				bound.WireBoundVersion != formalGLMPhase19ExactGCWireBoundVersion ||
				!formalGLMIsSHA256(bound.WireABISHA256) ||
				!formalGLMIsSHA256(bound.ShapeSHA256) ||
				!formalGLMIsSHA256(bound.CircuitInventorySHA256) {
				t.Fatalf("incomplete transcript binding: %+v", bound)
			}
			wantCircuits := formalGLMPhase19TranscriptBoundExpectedCircuits(
				test.blocks, test.iterations)
			if got := formalGLMPhase19TranscriptBoundMultiplicity(bound); got != wantCircuits {
				t.Fatalf("circuit count %d want %d", got, wantCircuits)
			}
			if bound.G2EPhysicalBytes < bound.G2EPlainBytes ||
				bound.E2GPhysicalBytes < bound.E2GPlainBytes ||
				bound.TotalPhysicalBytes != bound.G2EPhysicalBytes+
					bound.E2GPhysicalBytes ||
				bound.UniqueRecordCount == 0 ||
				bound.MaxUniqueChunks != bound.UniqueRecordCount {
				t.Fatalf("invalid aggregate byte bound: %+v", bound)
			}
			if err := formalGLMPhase19ValidateTranscriptBoundV1(
				bound, plan, dp); err != nil {
				t.Fatal(err)
			}
			for index, item := range bound.CircuitInventory {
				if index > 0 && bound.CircuitInventory[index-1].Kind >= item.Kind {
					t.Fatal("circuit inventory is not canonically sorted")
				}
				g2e := uint64(9321) + 4*item.Gates +
					16*(item.GarblerInputBits+item.CompilerRelativeCost) +
					32*item.EvaluatorInputBits + (item.OutputBits+7)/8
				e2g := uint64(9436) + 128*((item.EvaluatorInputBits+7)/8) +
					4*((item.EvaluatorInputBits+511)/512)
				if item.G2EPlainBytes != g2e || item.E2GPlainBytes != e2g ||
					item.G2EPhysicalBytes < g2e || item.E2GPhysicalBytes < e2g ||
					item.G2ERecordCount == 0 || item.E2GRecordCount == 0 {
					t.Fatalf("bad per-circuit formula for %s: %+v", item.Kind, item)
				}
			}
		})
	}
}

func TestFormalGLMPhase19TranscriptBoundDistinguishesPartialFinalBlock(
	t *testing.T) {
	full := formalGLMPhase15TestPlan(t, "binomial", 3, 4, 1, 8, 2)
	partial := formalGLMPhase15TestPlan(t, "binomial", 3, 4, 1, 7, 2)
	fullBound, err := formalGLMPhase19BuildTranscriptBoundV1(full,
		formalGLMPhase19TranscriptBoundTestDP(t, full, full.Kernel.FracBits))
	if err != nil {
		t.Fatal(err)
	}
	partialBound, err := formalGLMPhase19BuildTranscriptBoundV1(partial,
		formalGLMPhase19TranscriptBoundTestDP(
			t, partial, partial.Kernel.FracBits))
	if err != nil {
		t.Fatal(err)
	}
	if fullBound.CircuitInventorySHA256 == partialBound.CircuitInventorySHA256 ||
		fullBound.ShapeSHA256 == partialBound.ShapeSHA256 {
		t.Fatal("partial final block did not change the exact circuit inventory")
	}
	found := false
	for _, item := range partialBound.CircuitInventory {
		if item.Kind == "phase19-protected-fanin/final-partial/3" {
			found = item.Multiplicity == 1
		}
	}
	if !found {
		t.Fatal("partial final fan-in circuit is absent from inventory")
	}
}

func TestFormalGLMPhase19TranscriptBoundRunInvariantAndShapeDivergence(
	t *testing.T) {
	base := formalGLMPhase15TestPlan(t, "binomial", 3, 2, 1, 3, 2)
	baseDP := formalGLMPhase19TranscriptBoundTestDP(t, base, base.Kernel.FracBits)
	want, err := formalGLMPhase19BuildTranscriptBoundV1(base, baseDP)
	if err != nil {
		t.Fatal(err)
	}
	runChanged := base
	runChanged.RunID = sha256Hex([]byte(t.Name() + "/another-run"))
	runDP := formalGLMPhase19TranscriptBoundTestDP(
		t, runChanged, runChanged.Kernel.FracBits)
	got, err := formalGLMPhase19BuildTranscriptBoundV1(runChanged, runDP)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatal("RunID changed the data-independent transcript bound")
	}

	variants := []struct {
		name    string
		plan    formalGLMPhase15Plan
		lattice int
	}{
		{name: "K", plan: formalGLMPhase15TestPlan(
			t, "binomial", 5, 2, 1, 3, 2), lattice: base.Kernel.FracBits},
		{name: "blocks", plan: formalGLMPhase15TestPlan(
			t, "binomial", 3, 2, 1, 5, 2), lattice: base.Kernel.FracBits},
		{name: "capacity", plan: formalGLMPhase15TestPlan(
			t, "binomial", 3, 1, 1, 3, 2), lattice: base.Kernel.FracBits},
		{name: "iterations", plan: formalGLMPhase15TestPlan(
			t, "binomial", 3, 2, 1, 3, 3), lattice: base.Kernel.FracBits},
		{name: "family", plan: formalGLMPhase15TestPlan(
			t, "poisson", 3, 2, 1, 3, 2), lattice: base.Kernel.FracBits},
	}
	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			dp := formalGLMPhase19TranscriptBoundTestDP(
				t, variant.plan, variant.lattice)
			bound, err := formalGLMPhase19BuildTranscriptBoundV1(variant.plan, dp)
			if err != nil {
				t.Fatal(err)
			}
			if bound.ShapeSHA256 == want.ShapeSHA256 {
				t.Fatal("public shape change retained transcript-bound hash")
			}
		})
	}

	lattice := base.Kernel.FracBits - 1
	latticeDP := formalGLMPhase19TranscriptBoundTestDP(t, base, lattice)
	latticeBound, err := formalGLMPhase19BuildTranscriptBoundV1(base, latticeDP)
	if err != nil {
		t.Fatal(err)
	}
	if latticeBound.ShapeSHA256 == want.ShapeSHA256 ||
		latticeBound.CircuitInventorySHA256 == want.CircuitInventorySHA256 {
		t.Fatal("DP lattice change retained bridge inventory/bound hash")
	}

	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{
		[]byte(`"run_id"`), []byte(`"attempt"`), []byte(`"ttl"`),
		[]byte(`"chunk_bytes"`), []byte(`"spool"`),
	} {
		if bytes.Contains(bytes.ToLower(encoded), forbidden) {
			t.Fatalf("bound contains execution-local field %q", forbidden)
		}
	}
}

func TestFormalGLMPhase19TranscriptBoundTamperFailsClosedBeforeWorker(
	t *testing.T) {
	plan := formalGLMPhase15TestPlan(t, "binomial", 3, 2, 1, 3, 2)
	dp := formalGLMPhase19TranscriptBoundTestDP(t, plan, plan.Kernel.FracBits)
	valid, err := formalGLMPhase19BuildTranscriptBoundV1(plan, dp)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*formalGLMPhase19TranscriptBoundV1){
		"version":      func(v *formalGLMPhase19TranscriptBoundV1) { v.Version += "x" },
		"purpose":      func(v *formalGLMPhase19TranscriptBoundV1) { v.Purpose += "x" },
		"wire-version": func(v *formalGLMPhase19TranscriptBoundV1) { v.WireBoundVersion += "x" },
		"wire-abi":     func(v *formalGLMPhase19TranscriptBoundV1) { v.WireABISHA256 = sha256Hex([]byte("wrong ABI")) },
		"shape":        func(v *formalGLMPhase19TranscriptBoundV1) { v.ShapeSHA256 = sha256Hex([]byte("wrong shape")) },
		"inventory-hash": func(v *formalGLMPhase19TranscriptBoundV1) {
			v.CircuitInventorySHA256 = sha256Hex([]byte("wrong inventory"))
		},
		"plus-one":  func(v *formalGLMPhase19TranscriptBoundV1) { v.G2EPhysicalBytes++ },
		"minus-one": func(v *formalGLMPhase19TranscriptBoundV1) { v.E2GPhysicalBytes-- },
		"directions": func(v *formalGLMPhase19TranscriptBoundV1) {
			v.G2EPhysicalBytes, v.E2GPhysicalBytes =
				v.E2GPhysicalBytes, v.G2EPhysicalBytes
		},
		"missing-circuit": func(v *formalGLMPhase19TranscriptBoundV1) {
			v.CircuitInventory = v.CircuitInventory[1:]
		},
		"extra-circuit": func(v *formalGLMPhase19TranscriptBoundV1) {
			v.CircuitInventory = append(v.CircuitInventory,
				v.CircuitInventory[len(v.CircuitInventory)-1])
		},
		"reordered-circuit": func(v *formalGLMPhase19TranscriptBoundV1) {
			if len(v.CircuitInventory) > 1 {
				v.CircuitInventory[0], v.CircuitInventory[1] =
					v.CircuitInventory[1], v.CircuitInventory[0]
			}
		},
		"circuit-hash": func(v *formalGLMPhase19TranscriptBoundV1) {
			v.CircuitInventory[0].CircuitSourceSHA256 = sha256Hex([]byte("wrong circuit"))
		},
		"multiplicity": func(v *formalGLMPhase19TranscriptBoundV1) {
			v.CircuitInventory[0].Multiplicity++
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.CircuitInventory = append(
				[]formalGLMPhase19TranscriptCircuitV1(nil), valid.CircuitInventory...)
			mutate(&candidate)
			workerCalls := 0
			if err := formalGLMPhase19ValidateTranscriptBoundV1(
				candidate, plan, dp); err == nil {
				workerCalls++
			}
			if workerCalls != 0 {
				t.Fatal("tampered bound crossed the pre-worker validation gate")
			}
		})
	}
}

type formalGLMPhase19TranscriptCountingConn struct {
	net.Conn
	bytes  atomic.Uint64
	writes atomic.Uint64
}

func (conn *formalGLMPhase19TranscriptCountingConn) Write(p []byte) (int, error) {
	n, err := conn.Conn.Write(p)
	if n > 0 {
		conn.bytes.Add(uint64(n))
		conn.writes.Add(1)
	}
	return n, err
}

func TestFormalGLMPhase19TranscriptBoundDominatesActualSecureDuplex(
	t *testing.T) {
	plan, ctx, accumulator := formalGLMPhase19BoundedAccumulatorTestPlan(t, 1)
	dp := formalGLMPhase19TranscriptBoundTestDP(t, plan, plan.Kernel.FracBits)
	bound, err := formalGLMPhase19BuildTranscriptBoundV1(plan, dp)
	if err != nil {
		t.Fatal(err)
	}
	var item *formalGLMPhase19TranscriptCircuitV1
	for index := range bound.CircuitInventory {
		if bound.CircuitInventory[index].Kind ==
			"phase19-execution-accumulator/final/1" {
			item = &bound.CircuitInventory[index]
		}
	}
	if item == nil {
		t.Fatal("missing bounded accumulator final circuit")
	}
	circ, err := compileFormalGLMPhase19BoundedAccumulator("final", 1)
	if err != nil {
		t.Fatal(err)
	}
	attempt := [32]byte{1}
	master := [32]byte{2}
	session, err := formalGLMPhase19BoundedAccumulatorSession(
		plan, ctx, accumulator, attempt, "final", 0, 0, 1, master)
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	garblerConn := &formalGLMPhase19TranscriptCountingConn{Conn: left}
	evaluatorConn := &formalGLMPhase19TranscriptCountingConn{Conn: right}
	defer garblerConn.Close()
	defer evaluatorConn.Close()
	_ = garblerConn.SetDeadline(time.Now().Add(30 * time.Second))
	_ = evaluatorConn.SetDeadline(time.Now().Add(30 * time.Second))
	var garblerErr, evaluatorErr error
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		_, garblerErr = formalGLMPhase19BoundedAccumulatorRunCircuit(
			garblerConn, "garbler", circ, session,
			[]*big.Int{big.NewInt(1), big.NewInt(1), big.NewInt(0)})
	}()
	go func() {
		defer wait.Done()
		_, evaluatorErr = formalGLMPhase19BoundedAccumulatorRunCircuit(
			evaluatorConn, "evaluator", circ, session,
			[]*big.Int{big.NewInt(0), big.NewInt(0)})
	}()
	wait.Wait()
	if garblerErr != nil || evaluatorErr != nil {
		t.Fatalf("actual duplex failed: garbler=%v evaluator=%v",
			garblerErr, evaluatorErr)
	}
	if got := garblerConn.bytes.Load(); got > item.G2EPhysicalBytes {
		t.Fatalf("actual G2E outbound head %d exceeds %d", got,
			item.G2EPhysicalBytes)
	}
	if got := evaluatorConn.bytes.Load(); got > item.E2GPhysicalBytes {
		t.Fatalf("actual E2G outbound head %d exceeds %d", got,
			item.E2GPhysicalBytes)
	}
	if got := garblerConn.writes.Load(); got > item.G2ERecordCount {
		t.Fatalf("actual G2E records %d exceeds %d", got,
			item.G2ERecordCount)
	}
	if got := evaluatorConn.writes.Load(); got > item.E2GRecordCount {
		t.Fatalf("actual E2G records %d exceeds %d", got,
			item.E2GRecordCount)
	}
}

func TestFormalGLMPhase19TranscriptBoundCheckedArithmetic(t *testing.T) {
	if _, err := formalGLMPhase19TranscriptCheckedAddV1(math.MaxUint64, 1); err == nil {
		t.Fatal("checked addition wrapped")
	}
	if _, err := formalGLMPhase19TranscriptCheckedMulV1(math.MaxUint64, 2); err == nil {
		t.Fatal("checked multiplication wrapped")
	}
	if got, err := formalGLMPhase19TranscriptCheckedAddV1(40, 2); err != nil || got != 42 {
		t.Fatalf("checked addition got %d, %v", got, err)
	}
	if got, err := formalGLMPhase19TranscriptCheckedMulV1(6, 7); err != nil || got != 42 {
		t.Fatalf("checked multiplication got %d, %v", got, err)
	}
}

func TestFormalGLMPhase19TranscriptBoundCanonicalInventoryKinds(t *testing.T) {
	plan := formalGLMPhase15TestPlan(t, "binomial", 2, 1, 1, 65, 2)
	dp := formalGLMPhase19TranscriptBoundTestDP(t, plan, plan.Kernel.FracBits)
	bound, err := formalGLMPhase19BuildTranscriptBoundV1(plan, dp)
	if err != nil {
		t.Fatal(err)
	}
	kinds := make([]string, len(bound.CircuitInventory))
	for index := range bound.CircuitInventory {
		kinds[index] = bound.CircuitInventory[index].Kind
	}
	if !sort.StringsAreSorted(kinds) {
		t.Fatal("inventory kinds are not sorted")
	}
	for _, want := range []string{
		"phase15-dp-bridge",
		"phase15-optimizer/block",
		"phase15-optimizer/finalize",
		"phase19-execution-accumulator/final/1",
		"phase19-execution-accumulator/leaf/1",
		"phase19-execution-accumulator/leaf/64",
		"phase19-execution-accumulator/state/2",
		"phase19-protected-fanin/full",
	} {
		if index := sort.SearchStrings(kinds, want); index >= len(kinds) ||
			kinds[index] != want {
			t.Fatalf("missing circuit kind %q in %v", want, kinds)
		}
	}
}
