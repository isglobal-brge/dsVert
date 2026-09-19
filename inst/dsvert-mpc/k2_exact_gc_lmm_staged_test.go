package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func groupedLMMStagedTestSpec() groupedLMMStagedSpec {
	s := groupedLMMTestSpec()
	f := new(big.Int).Lsh(big.NewInt(1), 50)
	return groupedLMMStagedSpec{Moments: groupedLMMMomentPlan{2, 2, 3}, Numeric: s,
		Beta: [][]*big.Int{{big.NewInt(0), big.NewInt(0)}, {new(big.Int).Rsh(new(big.Int).Set(f), 2), new(big.Int).Rsh(new(big.Int).Set(f), 1)}},
		Caps: []int64{s.OutputCap, s.OutputCap}, SourceDigest: sha256.Sum256([]byte("authenticated synthetic source")), ProfileDigest: sha256.Sum256([]byte("signed synthetic profile")), RoutedStage: "route.convert192"}
}

func TestGroupedLMMStagedGraphContract(t *testing.T) {
	s := groupedLMMStagedTestSpec()
	a, err := groupedLMMBuildStagedGraph(s, exactGCRoleGarbler)
	if err != nil {
		t.Fatal(err)
	}
	b, err := groupedLMMBuildStagedGraph(s, exactGCRoleEvaluator)
	if err != nil {
		t.Fatal(err)
	}
	ap, _ := json.Marshal(a.Plans)
	bp, _ := json.Marshal(b.Plans)
	if !bytes.Equal(ap, bp) {
		t.Fatal("authority public plans disagree")
	}
	seen := map[string]bool{s.RoutedStage: true}
	for _, stage := range a.Plans {
		if seen[stage.ID] {
			t.Fatal("duplicate stage")
		}
		for _, previous := range stage.Predecessors {
			if !seen[previous] {
				t.Fatal("non-topological stage")
			}
		}
		seen[stage.ID] = true
		if len(stage.CoordOrder) == 0 {
			t.Fatal("missing coordinate ABI")
		}
	}
	last := a.Plans[len(a.Plans)-1]
	if last.Ring != 128 || last.FPScale != s.Numeric.GridBits || len(last.CoordOrder) != len(s.Beta) {
		t.Fatal("wrong final ABI")
	}
	changed := s
	changed.Caps = append([]int64(nil), s.Caps...)
	changed.Caps[0]++
	c, err := groupedLMMBuildStagedGraph(changed, exactGCRoleGarbler)
	if err != nil {
		t.Fatal(err)
	}
	if c.Plans[0].ProfileDigest == a.Plans[0].ProfileDigest {
		t.Fatal("arithmetic parameter was not pinned")
	}
	// Descriptors support the realistic public topology without claiming a
	// measurement or changing the signed production admission guard.
	s.Moments.Clusters = 500
	c, err = groupedLMMBuildStagedGraph(s, exactGCRoleGarbler)
	if err != nil {
		t.Fatal(err)
	}
	if c.Plans[0].PublicBounds["clusters"] != 500 {
		t.Fatal("lost cluster capacity")
	}
}

func TestGroupedLMMStagedGraphTwoAuthority(t *testing.T) {
	s := groupedLMMStagedTestSpec()
	f := new(big.Int).Lsh(big.NewInt(1), 50)
	rows := [][]*big.Int{{new(big.Int).Set(f), new(big.Int).Rsh(new(big.Int).Set(f), 1), new(big.Int).Rsh(new(big.Int).Set(f), 2)},
		{new(big.Int).Set(f), new(big.Int).Rsh(new(big.Int).Set(f), 2), new(big.Int).Rsh(new(big.Int).Set(f), 1)},
		{new(big.Int), new(big.Int), new(big.Int)},
		{new(big.Int).Set(f), new(big.Int).Rsh(new(big.Int).Set(f), 3), new(big.Int).Rsh(new(big.Int).Set(f), 1)}}
	want := make([]*big.Int, len(s.Beta))
	for j, beta := range s.Beta {
		want[j] = new(big.Int)
		for c := 0; c < s.Moments.Clusters; c++ {
			want[j].Add(want[j], groupedLMMStatsOracle(s.Numeric, rows[2*c:2*c+2], beta))
		}
	}
	var previous []byte
	for _, test := range []struct {
		name    string
		invalid bool
	}{{"fresh", false}, {"new-randomness", false}, {"bilateral-midstage-recovery", false}, {"unilateral-commit-recovery", false}, {"source-invalid", true}} {
		t.Run(test.name, func(t *testing.T) {
			got, valid := groupedLMMStagedRunTest(t, s, rows, test.invalid, test.name)
			for j := range want {
				if test.invalid {
					if valid[j] != 0 || new(big.Int).SetBytes(reverseBytesCopy(got[16*j:16*(j+1)])).Sign() != 0 {
						t.Fatal("invalid source escaped final gate")
					}
				} else {
					if valid[j] != 1 {
						t.Fatal("valid input rejected")
					}
					value := new(big.Int).SetBytes(reverseBytesCopy(got[16*j : 16*(j+1)]))
					if value.Cmp(want[j]) != 0 {
						t.Fatalf("candidate %d got %s want %s", j, value, want[j])
					}
				}
			}
			if !test.invalid {
				if previous != nil && !bytes.Equal(previous, got) {
					t.Fatal("fresh share randomness changed exact artifact")
				}
				previous = append([]byte(nil), got...)
			}
		})
	}
}

func reverseBytesCopy(raw []byte) []byte {
	out := append([]byte(nil), raw...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func groupedLMMStagedRunTest(t *testing.T, s groupedLMMStagedSpec, rows [][]*big.Int, invalid bool, scenario string) ([]byte, []byte) {
	t.Helper()
	faultStage := "lmm.grid"
	if s.Objective == "ml" {
		faultStage = "lmm.ml.variance.000.objective"
	}
	graphA, err := groupedLMMBuildStagedGraph(s, exactGCRoleGarbler)
	if err != nil {
		t.Fatal(err)
	}
	graphB, err := groupedLMMBuildStagedGraph(s, exactGCRoleEvaluator)
	if err != nil {
		t.Fatal(err)
	}
	a, b := make([]groupedWord, 0, len(rows)*s.Moments.Columns), make([]groupedWord, 0, len(rows)*s.Moments.Columns)
	flagsA, flagsB := []byte{}, []byte{}
	for _, row := range rows {
		for _, value := range row {
			mask, err := groupedRandomWord()
			if err != nil {
				t.Fatal(err)
			}
			a = append(a, mask)
			b = append(b, groupedWordFromBig(value).sub(mask))
			flag := byte(mask[0] & 1)
			flagsA = append(flagsA, flag)
			flagsB = append(flagsB, flag^1)
		}
	}
	if invalid {
		flagsB[4] ^= 1
	}
	sourceA := crossGridStageOutput{Share: groupedEncodeWords(a), Validity: flagsA}
	sourceB := crossGridStageOutput{Share: groupedEncodeWords(b), Validity: flagsB}
	sourcePlan := crossGridStagePlan{ID: s.RoutedStage, Kind: "test.authenticated-routed-share", Ring: 192, FPScale: 50,
		CoordOrder: make([]string, len(a)), PublicBounds: map[string]int{"rows": len(rows)}, SourceDigest: s.SourceDigest, ProfileDigest: s.ProfileDigest}
	for i := range sourcePlan.CoordOrder {
		sourcePlan.CoordOrder[i] = fmt.Sprintf("routed:%d", i)
	}
	base := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 192, VectorLen: 1})
	plan := crossGridStageGraph{Version: "cross-grid-stage-graph-v1", Family: "lmm", Session: "lmm-synthetic-staged",
		Authorities: [2]string{base.GarblerID, base.EvaluatorID}, SchemaDigest: sha256.Sum256([]byte("signed synthetic schema")),
		SemanticKey: sha256.Sum256([]byte("sticky synthetic release")), Stages: append([]crossGridStagePlan{sourcePlan}, graphA.Plans...)}
	kernelsA := append([]crossGridStageCompute{func(io.ReadWriter, crossGridStageAttempt, []crossGridStageOutput) (crossGridStageOutput, error) {
		return sourceA, nil
	}}, graphA.Compute...)
	kernelsB := append([]crossGridStageCompute{func(io.ReadWriter, crossGridStageAttempt, []crossGridStageOutput) (crossGridStageOutput, error) {
		return sourceB, nil
	}}, graphB.Compute...)
	dirs := [2]string{filepath.Join(t.TempDir(), "authority"), filepath.Join(t.TempDir(), "authority")}
	keys := [2][32]byte{sha256.Sum256([]byte("authority a local key")), sha256.Sum256([]byte("authority b local key"))}
	type result struct {
		value []crossGridStageOutput
		err   error
	}
	run := func(faultRole int, event string, cold bool) (result, result) {
		stores := [2]*crossGridStageStore{}
		for role := range stores {
			var err error
			stores[role], err = crossGridStageOpenStore(dirs[role], keys[role], plan, exactGCRole(role))
			if err != nil {
				t.Fatal(err)
			}
			defer stores[role].Close()
		}
		left, right := net.Pipe()
		defer left.Close()
		defer right.Close()
		left.SetDeadline(time.Now().Add(2 * time.Minute))
		right.SetDeadline(time.Now().Add(2 * time.Minute))
		// Every recovery uses a fresh transport context while keeping the same
		// signed graph, semantic identity and authority-local durable stores.
		transport := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 192, VectorLen: 1})
		executors := [2]*crossGridStageExecutor{{Store: stores[0], Base: transport}, {Store: stores[1], Base: transport}}
		if faultRole >= 0 {
			executors[faultRole].fault = func(at string, r crossGridStageRecord) error {
				if r.StageID == faultStage && at == event {
					return errors.New("synthetic midstage death")
				}
				return nil
			}
		}
		ka, kb := kernelsA, kernelsB
		if cold {
			ka = make([]crossGridStageCompute, len(kernelsA))
			kb = make([]crossGridStageCompute, len(kernelsB))
			for i := range ka {
				ka[i] = func(io.ReadWriter, crossGridStageAttempt, []crossGridStageOutput) (crossGridStageOutput, error) {
					return crossGridStageOutput{}, errors.New("cold replay recomputed a committed stage")
				}
				kb[i] = ka[i]
			}
		}
		ch := make(chan result, 1)
		go func() {
			v, e := executors[0].Execute(left, ka)
			if e != nil {
				left.Close()
			}
			ch <- result{v, e}
		}()
		v, e := executors[1].Execute(right, kb)
		if e != nil {
			right.Close()
		}
		ar := <-ch
		return ar, result{v, e}
	}
	readGrid := func() [2]crossGridStageRecord {
		var records [2]crossGridStageRecord
		for role := range records {
			store, err := crossGridStageOpenStore(dirs[role], keys[role], plan, exactGCRole(role))
			if err != nil {
				t.Fatal(err)
			}
			receipts := make(map[string][32]byte)
			for _, stage := range plan.Stages {
				var previous [][32]byte
				for _, id := range stage.Predecessors {
					previous = append(previous, receipts[id])
				}
				record, err := store.load(stage, previous)
				if err != nil {
					store.Close()
					t.Fatal(err)
				}
				receipts[stage.ID] = record.StageReceipt
				if stage.ID == faultStage {
					records[role] = record
					break
				}
			}
			store.Close()
		}
		return records
	}
	var interrupted [2]crossGridStageRecord
	if scenario == "bilateral-midstage-recovery" || scenario == "unilateral-commit-recovery" {
		role, event := 0, "after-compute"
		if scenario == "unilateral-commit-recovery" {
			role, event = 1, "after-prepare-exchange"
		}
		ar, br := run(role, event, false)
		if ar.err == nil || br.err == nil {
			t.Fatal("injected stage interruption was ignored")
		}
		interrupted = readGrid()
		if scenario == "unilateral-commit-recovery" {
			if interrupted[0].State != "COMMIT" || interrupted[1].State != "PREPARE" {
				t.Fatal("fault did not produce unilateral COMMIT/PREPARE")
			}
		} else if interrupted[0].State == "COMMIT" || interrupted[1].State == "COMMIT" {
			t.Fatal("midstage crash unexpectedly committed")
		}
	}
	ar, br := run(-1, "", false)
	if ar.err != nil || br.err != nil {
		t.Fatalf("durable LMM graph: %v / %v", ar.err, br.err)
	}
	outA, outB := ar.value[len(ar.value)-1], br.value[len(br.value)-1]
	if interrupted[0].State != "" {
		recovered := readGrid()
		for role := range recovered {
			if recovered[role].State != "COMMIT" {
				t.Fatal("recovery did not commit bilaterally")
			}
			if scenario == "unilateral-commit-recovery" {
				if recovered[role].AttemptNonce != interrupted[role].AttemptNonce || !bytes.Equal(recovered[role].Output.Share, interrupted[role].Output.Share) {
					t.Fatal("unilateral recovery regenerated a prepared share")
				}
			} else if recovered[role].AttemptNonce == interrupted[role].AttemptNonce {
				t.Fatal("aborted attempt reused its nonce")
			}
		}
	}
	coldA, coldB := run(-1, "", true)
	if coldA.err != nil || coldB.err != nil {
		t.Fatalf("cold replay: %v / %v", coldA.err, coldB.err)
	}
	lastA, lastB := coldA.value[len(coldA.value)-1], coldB.value[len(coldB.value)-1]
	if !bytes.Equal(outA.Share, lastA.Share) || !bytes.Equal(outB.Share, lastB.Share) || !bytes.Equal(outA.Validity, lastA.Validity) || !bytes.Equal(outB.Validity, lastB.Validity) {
		t.Fatal("cold replay changed committed private bytes")
	}
	out := make([]byte, len(outA.Share))
	valid := make([]byte, len(outA.Validity))
	mod := new(big.Int).Lsh(big.NewInt(1), 128)
	for j := range valid {
		aa := new(big.Int).SetBytes(reverseBytesCopy(outA.Share[16*j : 16*(j+1)]))
		bb := new(big.Int).SetBytes(reverseBytesCopy(outB.Share[16*j : 16*(j+1)]))
		aa.Add(aa, bb).Mod(aa, mod)
		buffer := make([]byte, 16)
		aa.FillBytes(buffer)
		copy(out[16*j:16*(j+1)], reverseBytesCopy(buffer))
		valid[j] = outA.Validity[j] ^ outB.Validity[j]
	}
	return out, valid
}
