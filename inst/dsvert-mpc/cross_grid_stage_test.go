package main

// These tests prove the durable protocol and sticky noise invariant on a small
// synthetic statistic. They are not an authenticated family release or a
// capacity measurement. The child processes use the real joint-DP circuit.
import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func crossGridStageTestGraph() crossGridStageGraph {
	h := func(s string) [32]byte { return sha256.Sum256([]byte(s)) }
	p := crossGridStageGraph{Version: "cross-grid-stage-graph-v1", Family: "protocol-test",
		Session: "durable-synthetic-session", Authorities: [2]string{"peer-a", "peer-b"},
		SchemaDigest: h("signed synthetic schema"), SemanticKey: h("sticky semantic release")}
	for i, id := range []string{"source", "stats", "dp"} {
		stage := crossGridStagePlan{ID: id, Kind: id, Ring: 128, FPScale: 8, CoordOrder: []string{"coordinate:0"},
			PublicBounds: map[string]int{"rows": 1, "upper": 1000}, SourceDigest: h("source"), ProfileDigest: h("profile")}
		if i > 0 {
			stage.Predecessors = []string{p.Stages[i-1].ID}
		}
		p.Stages = append(p.Stages, stage)
	}
	return p
}

func crossGridStageTestKey(role exactGCRole) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("synthetic authority-local secret %d", role)))
}

func crossGridStageTestNoise(t testing.TB) (jointDPVectorSpec, [2][32]byte) {
	p := crossGridStageTestGraph()
	seeds := [2][32]byte{crossGridStageHash("synthetic sticky garbler seed", p.SemanticKey), crossGridStageHash("synthetic sticky evaluator seed", p.SemanticKey)}
	plan := jointDPVectorTestPlan(t, "4", "0.000001", "1", 1)
	return jointDPVectorTestSpec(t, plan, 0, []int64{1000}, fmt.Sprintf("semantic/%x", p.SemanticKey), seeds[0], seeds[1]), seeds
}

func crossGridStageTestBytes(x *big.Int) []byte {
	data := make([]byte, 16)
	x = new(big.Int).Mod(x, exactGCModulus(128))
	be := x.Bytes()
	for i := range be {
		data[i] = be[len(be)-1-i]
	}
	return data
}

func crossGridStageTestInteger(data []byte) *big.Int {
	be := bytes.Clone(data)
	for i, j := 0, len(be)-1; i < j; i, j = i+1, j-1 {
		be[i], be[j] = be[j], be[i]
	}
	return new(big.Int).SetBytes(be)
}

type crossGridStageTestResult struct {
	Output crossGridStageOutput
	Calls  [3]int
}

type crossGridStageTestStopWriter struct {
	io.ReadWriter
	written int
	stop    func() error
}

func (w *crossGridStageTestStopWriter) Write(data []byte) (int, error) {
	n, err := w.ReadWriter.Write(data)
	w.written += n
	if err == nil && w.written > 16384 {
		err = w.stop()
	}
	return n, err
}

func crossGridStageTestKernels(t testing.TB, role exactGCRole, result *crossGridStageTestResult) []crossGridStageCompute {
	spec, seeds := crossGridStageTestNoise(t)
	return []crossGridStageCompute{
		func(_ io.ReadWriter, _ crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
			result.Calls[0]++
			// Independent wrapped Ring128 source shares sum to 17.
			x := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(19))
			if role == exactGCRoleEvaluator {
				x.Sub(big.NewInt(17), x)
			}
			return crossGridStageOutput{crossGridStageTestBytes(x), []byte{byte(1 - role)}}, nil
		},
		func(_ io.ReadWriter, _ crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
			result.Calls[1]++
			x := crossGridStageTestInteger(in[0].Share)
			x.Lsh(x, 1)
			return crossGridStageOutput{crossGridStageTestBytes(x), bytes.Clone(in[0].Validity)}, nil
		},
		func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
			result.Calls[2]++
			// The noise transcript and seed use ONLY the semantic release key.
			// The encrypted transport retains its fresh attempt ID/master key.
			session := a.Session
			session.Purpose = spec.purpose()
			session.Spec = exactGCCircuitSpec{Operation: jointDPVectorOperation, RingBits: 128, VectorLen: 1}
			run := jointDPVectorRunGarbler
			if role == exactGCRoleEvaluator {
				run = jointDPVectorRunEvaluator
			}
			out, err := run(rw, session, spec, []*big.Int{crossGridStageTestInteger(in[0].Share)}, seeds[role])
			if err != nil {
				return crossGridStageOutput{}, err
			}
			return crossGridStageOutput{crossGridStageTestBytes(out[0]), bytes.Clone(in[0].Validity)}, nil
		},
	}
}

// Invoked as a fresh OS process by the kill/restart matrix below. Each child
// has one private authority directory and never loads its peer's shares.
func TestCrossGridStageProcessAuthority(t *testing.T) {
	if os.Getenv("DSVERT_STAGE_CHILD") != "1" {
		return
	}
	r, err := strconv.Atoi(os.Getenv("DSVERT_STAGE_ROLE"))
	if err != nil || r < 0 || r > 1 {
		t.Fatal("invalid child role")
	}
	role := exactGCRole(r)
	dir := os.Getenv("DSVERT_STAGE_DIR")
	store, err := crossGridStageOpenStore(dir, crossGridStageTestKey(role), crossGridStageTestGraph(), role)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	conn, err := net.DialTimeout("tcp", os.Getenv("DSVERT_STAGE_ADDR"), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Minute))
	if err := exactGCWriteFull(conn, []byte{byte(role)}); err != nil {
		t.Fatal(err)
	}
	base := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 128, VectorLen: 1})
	base.GarblerID, base.EvaluatorID = "peer-a", "peer-b"
	executor := &crossGridStageExecutor{Store: store, Base: base}
	var active crossGridStageRecord
	executor.fault = func(event string, record crossGridStageRecord) error {
		if event == "after-begin" {
			active = record
		}
		if event != os.Getenv("DSVERT_STAGE_FAULT") || record.StageID != os.Getenv("DSVERT_STAGE_FAULT_ID") {
			return nil
		}
		data, _ := json.Marshal(record)
		if err := os.WriteFile(filepath.Join(dir, "ready.json"), data, 0600); err != nil {
			return err
		}
		// Parent sends SIGKILL, exercising actual OS death and flock release.
		select {}
	}
	var result crossGridStageTestResult
	kernels := crossGridStageTestKernels(t, role, &result)
	if os.Getenv("DSVERT_STAGE_FAULT") == "inside-private-exchange" {
		noise := kernels[2]
		kernels[2] = func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
			return noise(&crossGridStageTestStopWriter{ReadWriter: rw, stop: func() error { return executor.checkpoint("inside-private-exchange", active) }}, a, in)
		}
	}
	outputs, err := executor.Execute(conn, kernels)
	if err != nil {
		t.Fatal(err)
	}
	result.Output = outputs[len(outputs)-1]
	data, _ := json.Marshal(result)
	if err := os.WriteFile(filepath.Join(dir, "result.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func crossGridStageTestProcessPair(t *testing.T, dirs [2]string, events [2]string, stage string) ([2]crossGridStageTestResult, [2]crossGridStageRecord) {
	return crossGridStageTestProcessPairMode(t, dirs, events, stage, false)
}

func crossGridStageTestProcessPairMode(t *testing.T, dirs [2]string, events [2]string, stage string, reject bool) ([2]crossGridStageTestResult, [2]crossGridStageRecord) {
	t.Helper()
	var results [2]crossGridStageTestResult
	var records [2]crossGridStageRecord
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Second))
	var commands [2]*exec.Cmd
	var logs [2]*os.File
	for role := range commands {
		os.Remove(filepath.Join(dirs[role], "ready.json"))
		os.Remove(filepath.Join(dirs[role], "result.json"))
		logs[role], err = os.OpenFile(filepath.Join(dirs[role], "child.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer logs[role].Close()
		cmd := exec.Command(os.Args[0], "-test.run=^TestCrossGridStageProcessAuthority$", "-test.timeout=90s")
		cmd.Env = append(os.Environ(), "DSVERT_STAGE_CHILD=1", fmt.Sprintf("DSVERT_STAGE_ROLE=%d", role),
			"DSVERT_STAGE_DIR="+dirs[role], "DSVERT_STAGE_ADDR="+listener.Addr().String(),
			"DSVERT_STAGE_FAULT="+events[role], "DSVERT_STAGE_FAULT_ID="+stage)
		cmd.Stdout, cmd.Stderr = logs[role], logs[role]
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		commands[role] = cmd
		defer cmd.Process.Kill()
	}
	var conns [2]net.Conn
	for range conns {
		c, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(time.Minute))
		var role [1]byte
		if _, err := io.ReadFull(c, role[:]); err != nil || role[0] > 1 || conns[role[0]] != nil {
			t.Fatal("child connection rejected")
		}
		conns[role[0]] = c
		defer c.Close()
	}
	for role := range conns {
		go func(role int) { _, _ = io.Copy(conns[1-role], conns[role]); conns[1-role].Close() }(role)
	}
	if events[0] != "" || events[1] != "" {
		deadline := time.Now().Add(30 * time.Second)
		for {
			ready := true
			for role := range records {
				if events[role] == "" {
					continue
				}
				data, e := os.ReadFile(filepath.Join(dirs[role], "ready.json"))
				if e != nil {
					ready = false
					continue
				}
				if json.Unmarshal(data, &records[role]) != nil {
					ready = false
				}
			}
			if ready {
				break
			}
			if time.Now().After(deadline) {
				for role := range commands {
					data, _ := os.ReadFile(filepath.Join(dirs[role], "child.log"))
					t.Logf("role%d: %s", role, data)
				}
				t.Fatal("processes did not reach durable fault boundary")
			}
			time.Sleep(10 * time.Millisecond)
		}
		for _, cmd := range commands {
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
		}
		for _, cmd := range commands {
			if cmd.Wait() == nil {
				t.Fatal("expected actual process death")
			}
		}
		return results, records
	}
	for role, cmd := range commands {
		err := cmd.Wait()
		// Propagate EOF through the relay when one authority rejects, allowing
		// its peer to fail immediately instead of waiting for a test deadline.
		conns[role].Close()
		if reject {
			if err == nil {
				t.Fatal("authority accepted inconsistent durable state")
			}
			continue
		}
		if err != nil {
			data, _ := os.ReadFile(filepath.Join(dirs[role], "child.log"))
			t.Fatalf("child%d: %v\n%s", role, err, data)
		}
		data, err := os.ReadFile(filepath.Join(dirs[role], "result.json"))
		if err != nil || json.Unmarshal(data, &results[role]) != nil {
			t.Fatal("missing child artifact")
		}
	}
	return results, records
}

func crossGridStageTestDirs(t *testing.T) [2]string {
	t.Helper()
	root := t.TempDir()
	dirs := [2]string{filepath.Join(root, "g"), filepath.Join(root, "e")}
	for _, dir := range dirs {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	return dirs
}

func crossGridStageTestOpened(t *testing.T, results [2]crossGridStageTestResult) []byte {
	t.Helper()
	if len(results[0].Output.Validity) != 1 || len(results[1].Output.Validity) != 1 || results[0].Output.Validity[0]^results[1].Output.Validity[0] != 1 {
		t.Fatal("lost validity")
	}
	x := new(big.Int).Add(crossGridStageTestInteger(results[0].Output.Share), crossGridStageTestInteger(results[1].Output.Share))
	return crossGridStageTestBytes(x)
}

func TestCrossGridStageProcessDeathStickyDP(t *testing.T) {
	dirs := crossGridStageTestDirs(t)
	base, _ := crossGridStageTestProcessPair(t, dirs, [2]string{}, "")
	want := crossGridStageTestOpened(t, base)
	spec, seeds := crossGridStageTestNoise(t)
	noise, err := jointDPVectorReferenceNoise(spec, seeds[0], seeds[1])
	if err != nil {
		t.Fatal(err)
	}
	oracle := new(big.Int).Add(big.NewInt(34), noise[0])
	if oracle.Sign() < 0 {
		oracle.SetInt64(0)
	}
	if oracle.Cmp(big.NewInt(1000)) > 0 {
		oracle.SetInt64(1000)
	}
	if !bytes.Equal(want, crossGridStageTestBytes(oracle)) {
		t.Fatal("independent integer DP oracle mismatch")
	}
	cold, _ := crossGridStageTestProcessPair(t, dirs, [2]string{}, "")
	if !bytes.Equal(want, crossGridStageTestOpened(t, cold)) {
		t.Fatal("cold replay changed bytes")
	}
	for _, r := range cold {
		if r.Calls != ([3]int{}) {
			t.Fatal("cold replay recomputed committed kernel/noise")
		}
	}
	for _, test := range []struct {
		name      string
		events    [2]string
		state     [2]string
		recompute bool
	}{
		{"mid-stage", [2]string{"after-compute", "after-compute"}, [2]string{"RUNNING", "RUNNING"}, true},
		{"bilateral-prepare", [2]string{"after-prepare", "after-prepare"}, [2]string{"PREPARE", "PREPARE"}, true},
		{"unilateral-commit", [2]string{"after-commit", "after-prepare-exchange"}, [2]string{"COMMIT", "PREPARE"}, false},
		{"lost-ack", [2]string{"after-commit", "after-commit"}, [2]string{"COMMIT", "COMMIT"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			dirs := crossGridStageTestDirs(t)
			_, old := crossGridStageTestProcessPair(t, dirs, test.events, "stats")
			for role, r := range old {
				if r.State != test.state[role] {
					t.Fatalf("wrong killed state %s", r.State)
				}
			}
			got, _ := crossGridStageTestProcessPair(t, dirs, [2]string{}, "")
			if !bytes.Equal(want, crossGridStageTestOpened(t, got)) {
				t.Fatal("recovery changed final bytes")
			}
			for role := range got {
				count := 0
				if test.recompute {
					count = 1
				}
				if got[role].Calls[0] != 0 || got[role].Calls[1] != count || got[role].Calls[2] != 1 {
					t.Fatalf("incorrect replay/fresh schedule %v", got[role].Calls)
				}
				store, err := crossGridStageOpenStore(dirs[role], crossGridStageTestKey(exactGCRole(role)), crossGridStageTestGraph(), exactGCRole(role))
				if err != nil {
					t.Fatal(err)
				}
				r, err := store.load(store.graph.Stages[1], old[role].PredecessorReceipts)
				store.Close()
				if err != nil {
					t.Fatal(err)
				}
				if test.recompute {
					if r.AttemptNonce == old[role].AttemptNonce || r.OutputMaskDomainTag == old[role].OutputMaskDomainTag || r.StageReceipt == old[role].StageReceipt {
						t.Fatal("fresh attempt reused nonce/mask/receipt")
					}
				} else if !reflect.DeepEqual(r.Output, old[role].Output) || r.AttemptNonce != old[role].AttemptNonce {
					t.Fatal("unilateral/replay regenerated persisted share")
				}
			}
		})
	}
	// Kill DURING the noise stage as well. Retries change OT streams but retain
	// the semantic noise seed, producing exactly the baseline artifact bytes.
	t.Run("noise-retry", func(t *testing.T) {
		dirs := crossGridStageTestDirs(t)
		crossGridStageTestProcessPair(t, dirs, [2]string{"after-prepare", "after-prepare"}, "dp")
		got, _ := crossGridStageTestProcessPair(t, dirs, [2]string{}, "")
		if !bytes.Equal(want, crossGridStageTestOpened(t, got)) {
			t.Fatal("execution retry caused a new noise draw")
		}
	})
	t.Run("killed-active-private-exchange", func(t *testing.T) {
		dirs := crossGridStageTestDirs(t)
		_, old := crossGridStageTestProcessPair(t, dirs, [2]string{"inside-private-exchange", ""}, "dp")
		if old[0].State != "RUNNING" || len(old[0].Output.Share) != 0 {
			t.Fatal("kill did not interrupt running private kernel")
		}
		got, _ := crossGridStageTestProcessPair(t, dirs, [2]string{}, "")
		if !bytes.Equal(want, crossGridStageTestOpened(t, got)) {
			t.Fatal("private exchange retry changed artifact")
		}
		for _, r := range got {
			if r.Calls != ([3]int{0, 0, 1}) {
				t.Fatal("incorrect private exchange restart schedule")
			}
		}
	})
	t.Run("missing-committed-peer-share-rejected", func(t *testing.T) {
		dirs := crossGridStageTestDirs(t)
		crossGridStageTestProcessPair(t, dirs, [2]string{}, "")
		store, err := crossGridStageOpenStore(dirs[0], crossGridStageTestKey(0), crossGridStageTestGraph(), 0)
		if err != nil {
			t.Fatal(err)
		}
		name := store.name("stats")
		store.Close()
		if err := os.Remove(filepath.Join(dirs[0], name)); err != nil {
			t.Fatal(err)
		}
		crossGridStageTestProcessPairMode(t, dirs, [2]string{}, "", true)
	})
}

func TestCrossGridStagePlanAndStoreTamper(t *testing.T) {
	p := crossGridStageTestGraph()
	for _, mutate := range []func(*crossGridStageGraph){
		func(p *crossGridStageGraph) { p.Stages[0].Ring = 64 },
		func(p *crossGridStageGraph) { p.Stages[0].Predecessors = []string{"stats"} },
		func(p *crossGridStageGraph) { p.Stages[1].ID = "source" },
		func(p *crossGridStageGraph) { p.Stages[0].CoordOrder = []string{"x", "x"} },
	} {
		q := crossGridStageTestGraph()
		mutate(&q)
		if q.validate() == nil {
			t.Fatal("invalid plan admitted")
		}
	}
	dir := crossGridStageTestDirs(t)[0]
	store, err := crossGridStageOpenStore(dir, crossGridStageTestKey(0), p, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if other, err := crossGridStageOpenStore(dir, crossGridStageTestKey(0), p, 0); err == nil {
		other.Close()
		t.Fatal("concurrent authority writer admitted")
	}
	r := store.empty(store.graph.Stages[0], nil)
	r.State, r.Generation = "ABORTED", 1
	if err := store.save(r); err != nil {
		t.Fatal(err)
	}
	r.State, r.Generation, r.AttemptNonce = "PREPARE", 1, sha256.Sum256([]byte("nonce"))
	r.OutputMaskDomainTag = crossGridStageMaskDomain(r.Session, r.StageID, r.AttemptNonce)
	r.State = "RUNNING"
	if err := store.save(r); err != nil {
		t.Fatal(err)
	}
	r.State = "PREPARE"
	r.Output = crossGridStageOutput{make([]byte, 16), []byte{1}}
	r.Commitments[0] = crossGridStageCommitment(r)
	r.Commitments[1] = sha256.Sum256([]byte("peer commitment"))
	r.StageReceipt = crossGridStageReceipt(r)
	r.ShareMAC = crossGridStageShareMAC(store.key, r)
	if err := store.save(r); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*crossGridStageRecord){
		func(r *crossGridStageRecord) { r.Output.Share[0] ^= 1 },
		func(r *crossGridStageRecord) { r.Output.Validity[0] ^= 1 },
		func(r *crossGridStageRecord) { r.AttemptNonce[0] ^= 1 },
		func(r *crossGridStageRecord) { r.Commitments[1][0] ^= 1 },
		func(r *crossGridStageRecord) { r.ABI.SourceDigest[0] ^= 1 },
		func(r *crossGridStageRecord) { r.ABI.ProfileDigest[0] ^= 1 },
		func(r *crossGridStageRecord) { r.PredecessorReceipts = [][32]byte{{1}} },
	} {
		data, _ := json.Marshal(r)
		var q crossGridStageRecord
		json.Unmarshal(data, &q)
		mutate(&q)
		if store.validate(q, store.graph.Stages[0], nil) == nil {
			t.Fatal("tampered stage record admitted")
		}
	}
	r.State = "COMMIT"
	if err := store.save(r); err != nil {
		t.Fatal(err)
	}
	q := r
	q.State = "ABORTED"
	if store.save(q) == nil {
		t.Fatal("committed output overwritten")
	}
	// Whole-record swaps and semantic plan changes fail even when the record's
	// original outer MAC remains valid.
	if _, err := store.load(store.graph.Stages[0], [][32]byte{{1}}); err == nil {
		t.Fatal("swapped predecessor accepted")
	}
	store.plan[0] ^= 1
	if _, err := store.load(store.graph.Stages[0], nil); err == nil {
		t.Fatal("swapped public plan accepted")
	}
	store.plan[0] ^= 1
	store.key[0] ^= 1
	if _, err := store.load(store.graph.Stages[0], nil); err == nil {
		t.Fatal("foreign authority MAC accepted")
	}
	store.key[0] ^= 1
	if err := store.root.Rename(store.name("source"), store.name("stats")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.load(store.graph.Stages[1], nil); err == nil {
		t.Fatal("swapped stage record accepted")
	}
	if err := store.root.Rename(store.name("stats"), store.name("source")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, store.name(r.StageID))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-2] ^= 1
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.load(store.graph.Stages[0], nil); err == nil {
		t.Fatal("private-store tampering admitted")
	}
}
