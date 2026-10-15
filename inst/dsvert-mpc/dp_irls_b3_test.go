package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func dpIRLSB3TestPolicy(t testing.TB, n int) dpIRLSNoisePolicy {
	p := dpIRLSStageUnitPlan(t, "binomial", n)
	p.SourceABI = dpIRLSB3SourceABI
	return dpIRLSNoisePolicy{Adjacency: "add_remove", EpsilonG: dpIRLSRat{D: "1", N: "1"}, EpsilonH: dpIRLSRat{D: "1", N: "2"}, Plan: p}
}
func dpIRLSB3LaneFixture(t testing.TB, policy dpIRLSNoisePolicy) dpIRLSFinalizeInput {
	t.Helper()
	lanes, e := dpIRLSNoiseLanes(policy)
	if e != nil {
		t.Fatal(e)
	}
	out := dpIRLSFinalizeInput{Policy: policy}
	for _, lane := range lanes {
		for role := 0; role < 2; role++ {
			seed := sha256.Sum256([]byte{byte(role + 1)})
			block, e := dpIRLSSampleLane(lane, []string{"peer-a", "peer-b"}[role], seed, make([]byte, 16*lane.Coordinates))
			if e != nil {
				t.Fatal(e)
			}
			if role == 0 {
				out.Left = append(out.Left, block)
			} else {
				out.Right = append(out.Right, block)
			}
		}
	}
	return out
}
func TestDPIRLSB3NoiseLaw(t *testing.T) {
	policy := dpIRLSB3TestPolicy(t, 64)
	in := dpIRLSB3LaneFixture(t, policy)
	lanes, e := dpIRLSNoiseLanes(policy)
	if e != nil {
		t.Fatal(e)
	}
	for i, want := range []string{"1/12288", "1/3072"} {
		r, _ := dpIRLSNoiseRational(lanes[i].Alpha)
		if r.RatString() != want {
			t.Fatal(r, want)
		}
	}
	if _, e := dpIRLSFinalize(in); e != nil {
		t.Fatal(e)
	}
	mutations := []func(*dpIRLSFinalizeInput){func(x *dpIRLSFinalizeInput) { x.Left[0].Metadata.Epsilon.N = "2" }, func(x *dpIRLSFinalizeInput) { x.Left[1].Metadata.Sensitivity = "3" }, func(x *dpIRLSFinalizeInput) { x.Left[0].Metadata.Alpha.N = "2" }, func(x *dpIRLSFinalizeInput) { x.Right[1].Sampler.Plan.SensitivitySteps = "9" }, func(x *dpIRLSFinalizeInput) { x.Policy.EpsilonG.N = "2" }, func(x *dpIRLSFinalizeInput) { x.Right[0].Sampler.EpsilonDividedByPeerCount = true }}
	for _, mutate := range mutations {
		b, _ := json.Marshal(in)
		var changed dpIRLSFinalizeInput
		json.Unmarshal(b, &changed)
		mutate(&changed)
		if _, e := dpIRLSFinalize(changed); e == nil {
			t.Fatal("tampered epsilon/S1/alpha accepted")
		}
	}
	policy.Adjacency = "replace_one"
	lanes, _ = dpIRLSNoiseLanes(policy)
	if lanes[0].Sensitivity != "24576" || lanes[1].Sensitivity != "12288" {
		t.Fatal("replace-one calibration")
	}
}
func TestDPIRLSB3SignedTranslation(t *testing.T) {
	in := dpIRLSB3LaneFixture(t, dpIRLSB3TestPolicy(t, 64))
	for i := 0; i < 2; i++ {
		lane := in.Left[i].Metadata
		share := make([]byte, 16*lane.Coordinates)
		for j := 0; j < lane.Coordinates; j++ {
			a, _ := new(big.Int).SetString(lane.Translation[j], 10)
			v := new(big.Int).Sub(a, big.NewInt(17))
			if j == 0 {
				v.SetInt64(-1)
			}
			if j == 1 {
				v.Mul(a, big.NewInt(2)).Add(v, big.NewInt(1))
			}
			v.Mod(v, exactGCModulus(128))
			enc, _ := exactGCBigLittleEndian(v, 16)
			copy(share[16*j:], enc)
		}
		in.Left[i].NoisedShare = base64.StdEncoding.EncodeToString(share)
		in.Left[i].Sampler.NoisedShare = in.Left[i].NoisedShare
		in.Right[i].NoisedShare = base64.StdEncoding.EncodeToString(make([]byte, len(share)))
		in.Right[i].Sampler.NoisedShare = in.Right[i].NoisedShare
	}
	out, e := dpIRLSFinalize(in)
	if e != nil {
		t.Fatal(e)
	}
	for _, lane := range out {
		if !lane.EndpointHits[0] || !lane.EndpointHits[1] || lane.EndpointHits[2] || lane.SignedValues[2] != "-17" {
			t.Fatalf("signed translation: %+v", lane)
		}
		if lane.SignedValues[0] != "-"+lane.Metadata.Translation[0] || lane.SignedValues[1] != lane.Metadata.Translation[1] {
			t.Fatal("endpoint decode")
		}
	}
}
func TestDPIRLSB3PersonZero(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		t.Run(family, func(t *testing.T) {
			p := dpIRLSB2TestPlan(family, 2, []int64{16384, -8192, 4096})
			p.SourceABI = dpIRLSB3SourceABI
			plan, _ := dpIRLSStageKernelPlan(p)
			kernel, e := crossGridKernelPrepare(plan)
			if e != nil {
				t.Fatal(e)
			}
			base := []int64{1, 1, 65536, -32768, 16384, 1, 0, 1, 1, 32768, 32768, -32768, 1, 0, 37, 91, 37, 91}
			for _, pos := range []int{0, 1, 2, 3, 4, 5, 6} {
				values := append([]int64(nil), base...)
				values[pos] = 999999
				rows := []dpIRLSB2Row{{Present: 0, X: []int64{65536, -32768, 16384}, Y: 1}, {Present: 1, X: []int64{32768, 32768, -32768}, Y: 1}}
				want := dpIRLSB2Oracle(t, family, []int64{16384, -8192, 4096}, rows, 2)
				source := make([]*big.Int, len(values))
				for i, v := range values {
					source[i] = new(big.Int).Mod(big.NewInt(v), exactGCModulus(128))
				}
				left, right := exactGCTestSplit(rand.New(rand.NewSource(int64(pos+19))), source, 128)
				for i := 14; i < 18; i++ {
					right[i].Xor(left[i], source[i])
				}
				g, _ := crossGridKernelPrivateInput(plan, left, true)
				ev, _ := crossGridKernelPrivateInput(plan, right, false)
				masks := make([]*big.Int, 10)
				for i := range masks {
					masks[i] = big.NewInt(0)
				}
				got, e := kernel.circuit.Compute([]*big.Int{exactGCPackChunks(append(g, masks...), 128), exactGCPackChunks(ev, 128)})
				if e != nil {
					t.Fatal(e)
				}
				for j, w := range want {
					actual := new(big.Int).Rsh(new(big.Int).Set(got[0]), uint(128*j))
					actual.Mod(actual, exactGCModulus(128))
					if actual.Cmp(w) != 0 {
						t.Fatalf("bad person field %d coordinate %d got %s want %s", pos, j, actual, w)
					}
				}
			}
		})
	}
}
func TestDPIRLSB3CrashReplay(t *testing.T) {
	policy := dpIRLSB3TestPolicy(t, 1)
	plan, _ := dpIRLSStageKernelPlan(policy.Plan)
	kernel, e := crossGridKernelPrepare(plan)
	if e != nil {
		t.Fatal(e)
	}
	graph, _ := dpIRLSBuildStageGraph(policy.Plan, [2]string{"peer-a", "peer-b"})
	base := exactGCTestSession(exactGCCircuitSpec{Operation: dpIRLSStageOperation, RingBits: 128, VectorLen: 9})
	base.GarblerID, base.EvaluatorID = graph.Authorities[0], graph.Authorities[1]
	base.Purpose = plan.purpose()
	source := []*big.Int{big.NewInt(1), big.NewInt(1), big.NewInt(65536), big.NewInt(0), big.NewInt(0), big.NewInt(1), big.NewInt(0), big.NewInt(37), big.NewInt(91), big.NewInt(37), big.NewInt(91)}
	left, right := exactGCTestSplit(rand.New(rand.NewSource(99)), source, 128)
	for i := 7; i < len(source); i++ {
		right[i].Xor(left[i], source[i])
	}
	for _, event := range []string{"protected", "lane-g", "barrier-g", "lane-H", "barrier-H"} {
		t.Run(event, func(t *testing.T) {
			var p [2]*dpIRLSWorkerPrepared
			for role := range p {
				dir := t.TempDir()
				os.Chmod(dir, 0700)
				p[role] = &dpIRLSWorkerPrepared{input: dpIRLSWorkerInput{dpIRLSNoisePolicy: policy, StoreDirectory: dir}, kernel: kernel, source: [][]*big.Int{left, right}[role], role: exactGCRole(role), key: sha256.Sum256([]byte{byte(role + 1)}), seed: sha256.Sum256([]byte{byte(role + 3)}), binding: sha256.Sum256([]byte{byte(role + 5)})}
			}
			run := func(fail bool) ([2]exactGCWorkerResult, [2]error) {
				l, r := net.Pipe()
				conns := [2]net.Conn{l, r}
				var result [2]exactGCWorkerResult
				var errors [2]error
				done := make(chan int, 2)
				for role := range p {
					p[role].fault = nil
					if fail && role == 0 {
						p[role].fault = func(at string) error {
							if at == event {
								return errorsNew()
							}
							return nil
						}
					}
					conns[role].SetDeadline(time.Now().Add(time.Minute))
					go func(role int) {
						defer conns[role].Close()
						result[role], errors[role] = p[role].run(conns[role], base)
						done <- role
					}(role)
				}
				<-done
				<-done
				return result, errors
			}
			_, errs := run(true)
			if errs[0] == nil {
				t.Fatal("fault not reached")
			}
			first, errs := run(false)
			if errs[0] != nil || errs[1] != nil {
				t.Fatal(errs)
			}
			second, errs := run(false)
			if errs[0] != nil || errs[1] != nil {
				t.Fatal(errs)
			}
			for role := range first {
				if !reflect.DeepEqual(first[role].DPIRLS.Lanes, second[role].DPIRLS.Lanes) || first[role].DPIRLS.LaneReceipts != second[role].DPIRLS.LaneReceipts {
					t.Fatal("noise replay changed")
				}
				if first[role].Share != "" || first[role].ValidityShare != "" {
					t.Fatal("pre-noise opening")
				}
				b, _ := json.Marshal(first[role])
				if bytes.Contains(b, []byte("validity_share")) {
					t.Fatal("validity surfaced")
				}
			}
			if first[0].DPIRLS.LaneReceipts != first[1].DPIRLS.LaneReceipts {
				t.Fatal("barrier mismatch")
			}
			if _, e := dpIRLSFinalize(dpIRLSFinalizeInput{Policy: policy, Left: first[0].DPIRLS.Lanes, Right: first[1].DPIRLS.Lanes}); e != nil {
				t.Fatal(e)
			}
			store, e := crossGridStageOpenStore(p[0].input.StoreDirectory, p[0].key, graph, p[0].role)
			if e != nil {
				t.Fatal(e)
			}
			journal, _, e := dpIRLSJournalRead(store)
			if e != nil {
				t.Fatal(e)
			}
			if e = store.root.Remove(store.name(graph.Stages[0].ID)); e != nil {
				t.Fatal(e)
			}
			store.Close()
			if !journal.Protected {
				t.Fatal("missing commit binding")
			}
			if _, e = p[0].run(dpIRLSStageNoIO{}, base); e == nil {
				t.Fatal("lost protected COMMIT reran")
			}
		})
	}
}
func errorsNew() error { return errors.New("injected crash") }

// Exercise the actual strict private-config/spool/result command boundary.
func TestDPIRLSB3WorkerSpool(t *testing.T) {
	policy := dpIRLSB3TestPolicy(t, 1)
	plan, _ := dpIRLSStageKernelPlan(policy.Plan)
	source := []*big.Int{big.NewInt(1), big.NewInt(1), big.NewInt(65536), big.NewInt(0), big.NewInt(0), big.NewInt(1), big.NewInt(0), big.NewInt(37), big.NewInt(91), big.NewInt(37), big.NewInt(91)}
	left, right := exactGCTestSplit(rand.New(rand.NewSource(999)), source, 128)
	for i := 7; i < len(source); i++ {
		right[i].Xor(left[i], source[i])
	}
	dirs := [2]string{exactGCTestSpool(t, "irls-g"), exactGCTestSpool(t, "irls-e")}
	sid := sha256.Sum256([]byte("irls-spool-test"))
	master := sha256.Sum256([]byte("irls-master-test"))
	done := make(chan error, 2)
	for role, dir := range dirs {
		key := sha256.Sum256([]byte{byte(role + 1)})
		seed := sha256.Sum256([]byte{byte(role + 3)})
		state := t.TempDir()
		os.Chmod(state, 0700)
		cfg := exactGCWorkerConfig{Version: exactGCWorkerConfigVersion, Role: []string{"garbler", "evaluator"}[role], SessionID: hex.EncodeToString(sid[:]), MasterKey: base64.StdEncoding.EncodeToString(master[:]), GarblerID: "peer-a", EvaluatorID: "peer-b", Purpose: plan.purpose(), Operation: string(dpIRLSStageOperation), RingBits: 128, VectorLen: 9, SpoolDir: dir, MaxSpoolBytes: 1 << 28, TTLSeconds: 120, DPIRLS: &dpIRLSWorkerInput{dpIRLSNoisePolicy: policy, StoreDirectory: state, StoreKey: base64.StdEncoding.EncodeToString(key[:]), NoiseSeed: hex.EncodeToString(seed[:])}}
		cfg.SourceShare = exactGCTestEncodeSource(t, [][]*big.Int{left, right}[role], exactGCCircuitSpec{Operation: exactGCTruncateFloor, RingBits: 128, FracBits: 1, VectorLen: len(source)})
		path := exactGCTestWriteConfig(t, dir, cfg)
		go func() { done <- handleExactGCWorker(path) }()
	}
	offsets := [2]int64{}
	received := 0
	deadline := time.Now().Add(time.Minute)
	for !exactGCTestBothDone(dirs[0], dirs[1]) && time.Now().Before(deadline) {
		select {
		case e := <-done:
			received++
			if e != nil {
				t.Fatal(e)
			}
		default:
		}
		for role, dir := range dirs {
			offsets[role] = exactGCTestRelaySpool(t, dir, dirs[1-role], offsets[role])
			now := time.Now()
			if e := os.Chtimes(filepath.Join(dir, "exchange.hb"), now, now); e != nil {
				t.Fatal(e)
			}
		}
		time.Sleep(time.Millisecond)
	}
	if !exactGCTestBothDone(dirs[0], dirs[1]) {
		t.Fatal("workers did not finish")
	}
	for i := received; i < 2; i++ {
		if e := <-done; e != nil {
			t.Fatal(e)
		}
	}
	a, b := exactGCTestReadResult(t, dirs[0]), exactGCTestReadResult(t, dirs[1])
	for _, r := range []exactGCWorkerResult{a, b} {
		if r.Kind != "dp-irls-noised-lanes-v1" || r.Share != "" || r.ValidityShare != "" || r.DPIRLS == nil {
			t.Fatal("raw or missing private worker result")
		}
	}
	if _, e := dpIRLSFinalize(dpIRLSFinalizeInput{Policy: policy, Left: a.DPIRLS.Lanes, Right: b.DPIRLS.Lanes}); e != nil {
		t.Fatal(e)
	}
}
