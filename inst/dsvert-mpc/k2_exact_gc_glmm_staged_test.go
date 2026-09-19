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
	"os"
	"path/filepath"
	"testing"
	"time"
)

func groupedGLMMStagedTestSpec() groupedGLMMStagedSpec {
	f := new(big.Int).Lsh(big.NewInt(1), 50)
	return groupedGLMMStagedSpec{Clusters: 2, Slots: 2, Predictors: 1, GridBits: 8,
		Beta: [][]*big.Int{{big.NewInt(0), big.NewInt(0)}, {new(big.Int).Neg(new(big.Int).Rsh(new(big.Int).Set(f), 2)), new(big.Int).Rsh(new(big.Int).Set(f), 1)}},
		Caps: []int64{700, 2000, 700, 2000}, VarianceGrid: []int64{0, 16384}, SourceDigest: sha256.Sum256([]byte("glmm authenticated synthetic source")), ProfileDigest: sha256.Sum256([]byte("glmm signed synthetic profile")), RoutedStage: "route.convert192"}
}

// Independent clear integer GH5 oracle; never calls a staged compiler or share
// assembly. Complete dot rounding follows the frozen f100->q64->q16 schedule.
func groupedGLMMStagedOracle(s groupedGLMMStagedSpec, rows [][]*big.Int, candidate int) *big.Int {
	sum := new(big.Int)
	beta := s.Beta[candidate%len(s.Beta)]
	variance := s.VarianceGrid[candidate/len(s.Beta)]
	for cluster := 0; cluster < s.Clusters; cluster++ {
		score := groupedGLMMLogWeights
		count := 0
		for _, row := range rows[cluster*s.Slots : (cluster+1)*s.Slots] {
			if row[0].Sign() == 0 {
				continue
			}
			count++
			dot := new(big.Int)
			for j, b := range beta {
				dot.Add(dot, new(big.Int).Mul(row[j], b))
			}
			q64 := primitiveVRoundDivReference(dot, new(big.Int).Lsh(big.NewInt(1), 36))
			eta := primitiveVRoundDivReference(q64, new(big.Int).Lsh(big.NewInt(1), 48)).Int64()
			y := int64(0)
			if row[len(row)-1].Sign() != 0 {
				y = 1
			}
			for q := range score {
				argument := eta
				if variance != 0 {
					argument += groupedGLMMNodes[q]
				}
				profile, _ := groupedProfileEval("softplus", argument)
				score[q] -= profile - y*argument
			}
		}
		if count == 0 {
			continue
		}
		maximum := score[0]
		for _, v := range score[1:] {
			if v > maximum {
				maximum = v
			}
		}
		expSum := int64(0)
		for _, v := range score {
			d := v - maximum
			if d < -1048576 {
				d = -1048576
			}
			e, _ := groupedProfileEval("exp_negative", d)
			expSum += e
		}
		log, _ := groupedProfileEval("log", expSum)
		loss := -maximum - log
		if loss < 0 {
			loss = 0
		}
		if s.GridBits < 16 {
			loss = groupedRoundDiv(loss, 1<<uint(16-s.GridBits))
		} else {
			loss <<= uint(s.GridBits - 16)
		}
		if loss > s.Caps[candidate] {
			loss = s.Caps[candidate]
		}
		sum.Add(sum, big.NewInt(loss))
	}
	return sum
}

func TestGroupedGLMMStagedGraphContract(t *testing.T) {
	s := groupedGLMMStagedTestSpec()
	a, e := groupedGLMMBuildStagedGraph(s, 0)
	if e != nil {
		t.Fatal(e)
	}
	b, e := groupedGLMMBuildStagedGraph(s, 1)
	if e != nil {
		t.Fatal(e)
	}
	aa, _ := json.Marshal(a.Plans)
	bb, _ := json.Marshal(b.Plans)
	if !bytes.Equal(aa, bb) {
		t.Fatal("public graph differs")
	}
	seen := map[string]bool{s.RoutedStage: true}
	for _, p := range a.Plans {
		if seen[p.ID] {
			t.Fatal("duplicate stage")
		}
		for _, id := range p.Predecessors {
			if !seen[id] {
				t.Fatal("non-topological edge")
			}
		}
		seen[p.ID] = true
	}
	last := a.Plans[len(a.Plans)-1]
	if last.Ring != 128 || last.FPScale != 8 || len(last.CoordOrder) != 4 {
		t.Fatal("terminal ABI")
	}
	s.Clusters = 500
	s.Slots = 4
	s.Predictors = 3
	for j := range s.Beta {
		s.Beta[j] = append(s.Beta[j], big.NewInt(0), big.NewInt(0))
	}
	if _, e := groupedGLMMBuildStagedGraph(s, 0); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{"variance-order", "variance-domain", "beta-range", "cap", "candidate-count"} {
		t.Run(bad, func(t *testing.T) {
			x := groupedGLMMStagedTestSpec()
			switch bad {
			case "variance-order":
				x.VarianceGrid = []int64{16384, 0}
			case "variance-domain":
				x.VarianceGrid[1] = 1
			case "beta-range":
				x.Beta[0][0].Lsh(big.NewInt(1), 51)
			case "cap":
				x.Caps[0] = 0
			case "candidate-count":
				x.Caps = x.Caps[:1]
			}
			if _, e := groupedGLMMBuildStagedGraph(x, 0); e == nil {
				t.Fatal("accepted invalid contract")
			}
		})
	}
}

func TestGroupedGLMMStagedGraphTwoAuthority(t *testing.T) {
	s := groupedGLMMStagedTestSpec()
	f := new(big.Int).Lsh(big.NewInt(1), 50)
	zero := func() *big.Int { return new(big.Int) }
	rows := [][]*big.Int{{new(big.Int).Set(f), new(big.Int).Rsh(new(big.Int).Set(f), 1), new(big.Int).Set(f)}, {zero(), zero(), zero()}, {zero(), zero(), zero()}, {zero(), zero(), zero()}}
	var previous []byte
	for _, scenario := range []string{"fresh", "new-randomness", "bilateral-midstage-recovery", "unilateral-commit-recovery", "source-invalid", "g18", "signed-cap", "nonbinary", "nonbinary-high-alias", "live-high-alias", "predictor-range"} {
		t.Run(scenario, func(t *testing.T) {
			spec := s
			raw, _ := json.Marshal(rows)
			var input [][]*big.Int
			json.Unmarshal(raw, &input)
			invalid := scenario == "source-invalid"
			switch scenario {
			case "signed-cap":
				spec.Caps = append([]int64(nil), s.Caps...)
				spec.Caps[0], spec.Caps[2] = 100, 100
			case "g18":
				spec.GridBits = 18
				spec.Caps = []int64{700 << 10, 2000 << 10, 700 << 10, 2000 << 10}
			case "nonbinary":
				input[0][2] = new(big.Int).Lsh(big.NewInt(2), 50)
			case "nonbinary-high-alias":
				input[0][2] = new(big.Int).Add(input[0][2], new(big.Int).Lsh(big.NewInt(1), 100))
			case "live-high-alias":
				input[0][0] = new(big.Int).Add(input[0][0], new(big.Int).Lsh(big.NewInt(1), 100))
			case "predictor-range":
				input[0][1] = new(big.Int).Lsh(big.NewInt(8), 50)
			}
			reject := invalid || scenario == "nonbinary" || scenario == "nonbinary-high-alias" || scenario == "live-high-alias" || scenario == "predictor-range"
			got, valid := groupedGLMMStagedRunTest(t, spec, input, invalid, scenario)
			for j := range spec.Caps {
				value := new(big.Int).SetBytes(reverseBytesCopy(got[16*j : 16*(j+1)]))
				want := new(big.Int)
				flag := byte(0)
				if !reject {
					want = groupedGLMMStagedOracle(spec, input, j)
					flag = 1
				}
				if value.Cmp(want) != 0 || valid[j] != flag {
					t.Fatalf("candidate %d got=%s valid=%d want=%s valid=%d", j, value, valid[j], want, flag)
				}
			}
			if !reject && scenario != "g18" && scenario != "signed-cap" {
				if previous != nil && !bytes.Equal(previous, got) {
					t.Fatal("attempt-dependent opened artifact")
				}
				previous = append([]byte(nil), got...)
			}
		})
	}
}

func groupedGLMMStagedRunTest(t *testing.T, s groupedGLMMStagedSpec, rows [][]*big.Int, invalid bool, scenario string) ([]byte, []byte) {
	t.Helper()
	faultStage := "glmm.candidate.000.center"
	graphA, err := groupedGLMMBuildStagedGraph(s, exactGCRoleGarbler)
	if err != nil {
		t.Fatal(err)
	}
	graphB, err := groupedGLMMBuildStagedGraph(s, exactGCRoleEvaluator)
	if err != nil {
		t.Fatal(err)
	}
	a, b := make([]groupedWord, 0, len(rows)*(s.Predictors+2)), make([]groupedWord, 0, len(rows)*(s.Predictors+2))
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
	plan := crossGridStageGraph{Version: "cross-grid-stage-graph-v1", Family: "glmm", Session: "glmm-synthetic-staged",
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
		t.Fatalf("durable GLMM graph: %v / %v", ar.err, br.err)
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
	// Tamper and swap actual complete-graph committed records, then require
	// bilateral fail-closed replay before any private terminal can be reused.
	store, e := crossGridStageOpenStore(dirs[0], keys[0], plan, 0)
	if e != nil {
		t.Fatal(e)
	}
	terminalPath := filepath.Join(dirs[0], store.name("glmm.terminal"))
	otherPath := filepath.Join(dirs[0], store.name(faultStage))
	store.Close()
	original, e := os.ReadFile(terminalPath)
	if e != nil {
		t.Fatal(e)
	}
	var record crossGridStageRecord
	if json.Unmarshal(original[32:], &record) != nil {
		t.Fatal("record decode")
	}
	record.Output.Share[0] ^= 1
	modified, _ := json.Marshal(record)
	modified = append(append([]byte(nil), original[:32]...), modified...)
	swapped, e := os.ReadFile(otherPath)
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{modified, swapped} {
		if e := os.WriteFile(terminalPath, bad, 0600); e != nil {
			t.Fatal(e)
		}
		ta, tb := run(-1, "", true)
		if ta.err == nil || tb.err == nil {
			t.Fatal("tampered or swapped stage survived cold replay")
		}
	}
	if e := os.WriteFile(terminalPath, original, 0600); e != nil {
		t.Fatal(e)
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

func TestGroupedGLMMStagedFullWidthGuards(t *testing.T) {
	for _, liveOutcome := range []bool{true, false} {
		program, err := groupedGLMMGuardCompile(1, liveOutcome)
		if err != nil {
			t.Fatal(err)
		}
		inputs, outputs := 1, 1
		if liveOutcome {
			inputs, outputs = 2, 2
		}
		for _, alias := range []int{0, 32, 128} {
			g, e := make([]*big.Int, inputs+outputs+1), make([]*big.Int, inputs)
			for i := range g {
				g[i] = new(big.Int)
			}
			for i := range e {
				e[i] = new(big.Int)
			}
			value := big.NewInt(65536)
			if liveOutcome {
				value = new(big.Int).Lsh(big.NewInt(1), 50)
				g[1].Set(value)
			}
			if alias > 0 {
				value.Add(value, new(big.Int).Lsh(big.NewInt(1), uint(alias)))
			}
			// A wrapped sharing is required, including the canonical valid boundary.
			g[0].Sub(exactGCModulus(192), big.NewInt(1))
			e[0].Add(value, big.NewInt(1))
			got := primitiveVTestCompute(t, program, g, e)
			want := int64(0)
			if alias == 0 {
				want = 1
			}
			if got[outputs].Int64() != want {
				t.Fatalf("live=%v alias=%d guard=%s", liveOutcome, alias, got[outputs])
			}
		}
	}
}
