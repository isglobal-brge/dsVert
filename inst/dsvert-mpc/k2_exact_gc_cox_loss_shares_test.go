package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"
)

func TestCoxGridCrossSharedProfiles(t *testing.T) {
	src, w, g, e, o := coxLossSharedExpSource(2)
	exp := coxTestCompile(t, src, w, g, e, o)
	values := coxTestInts(-524288, 1, 1, 524288, 1, 0, 1)
	for _, i := range []int{0, 3} {
		values[i].Lsh(values[i], 84)
	}
	out := coxTestCompute(t, exp, values, nil)
	// Bridge outputs are intentionally Ring64 within the 128-bit transport.
	for i := range out {
		out[i] = exactGCReferenceSigned(new(big.Int).And(out[i], exactGCMask(64)), 64)
	}
	a, _ := CoxGridCrossExpProfileQ16(-524288)
	b, _ := CoxGridCrossExpProfileQ16(524288)
	want := coxTestInts(int64(a), -8388608, 1, int64(b), 0, 0, 1)
	for i := range want {
		if out[i].Cmp(want[i]) != 0 {
			t.Fatalf("exp lane %d: %s != %s", i, out[i], want[i])
		}
	}
	src, w, g, e, o = coxLossSharedLogSource(10000, 2)
	log := coxTestCompile(t, src, w, g, e, o)
	for _, risk := range []uint64{0, 352, 1048575, 1048576, 1 << 44, uint64(10000) * uint64(CoxGridCrossExpKnotsQ20[64])} {
		active := int64(1)
		if risk == 0 {
			active = 0
		}
		got := coxTestCompute(t, log, coxTestInts(int64(risk), active, 0, 0, 1), nil)
		h := int64(0)
		if active == 1 {
			h, _ = CoxGridCrossLogProfileQ20(new(big.Int).SetUint64(risk))
		}
		if got[0].Int64() != h || got[1].Sign() != 0 || got[2].Int64() != 1 {
			t.Fatal("log boundary differs", risk, got)
		}
	}
	for _, values := range [][]*big.Int{coxTestInts(-1, 1, 0, 0, 1), coxTestInts(0, 1, 0, 0, 1), coxTestInts(1, 2, 0, 0, 1), coxTestInts(1, 1, 0, 0, 0)} {
		if got := coxTestCompute(t, log, values, nil); got[len(got)-1].Sign() != 0 {
			t.Fatal("invalid log accepted")
		}
	}
	t.Logf("exp gates=%d tables=%d; log gates=%d tables=%d", exp.Circuit.NumGates, primitiveVTableBytes(exp.Circuit), log.Circuit.NumGates, primitiveVTableBytes(log.Circuit))
}

// Real two-peer encrypted protocols; reconstruction is test-only, after both
// peers return. The production package has no plaintext/reference entry.
func coxSharedProtocolFixture(t *testing.T, n, jcount int, programs *coxLossSharedPrograms) (map[string]any, error) {
	t.Helper()
	compileStart := time.Now()
	caps := make([]uint64, jcount)
	for j := range caps {
		caps[j], _ = coxLossCap(n, 12, []float64{4, 4})
	}
	p, err := coxLossPlanShares(coxLossSpec{n, jcount, 12, caps, CoxGridCrossProfileID})
	if err != nil {
		return nil, err
	}
	if programs == nil {
		programs, err = coxLossCompileShares(p)
		if err != nil {
			return nil, err
		}
	}
	compileSeconds := time.Since(compileStart).Seconds()
	m := p.PaddedRows
	cols := p.PackedColumns
	owner, peer := make([]Uint128, m*cols), make([]Uint128, m*cols)
	times := make([]float64, n)
	live, event := make([]bool, n), make([]bool, n)
	etas := make([][]int32, jcount)
	for j := range etas {
		etas[j] = make([]int32, n)
	}
	perm := make([]int, m)
	for i := 0; i < m; i++ {
		perm[i] = i
		if i < n {
			times[i] = float64((i * 37) % max(2, n/3))
			live[i] = i%11 != 0
			event[i] = i%3 != 0
		}
		for c := 0; c < cols; c++ {
			v := new(big.Int)
			if i < n {
				switch c {
				case jcount:
					if live[i] {
						v.SetInt64(1)
					}
				case jcount + 1:
					if event[i] {
						v.SetInt64(1)
					}
				default:
					eta := int32(((i*7919 + c*103) % 1048577) - 524288)
					etas[c][i] = eta
					v.Lsh(big.NewInt(int64(eta)), 84)
				}
			}
			// Independent deterministic random-looking TEST shares, full ring; no
			// protected inputs, production masks use crypto/rand inside the runner.
			mask := sha256.Sum256([]byte(fmt.Sprintf("public synthetic/%d/%d", i, c)))
			owner[i*cols+c] = U128FromBig(new(big.Int).SetBytes(mask[:16]))
			peer[i*cols+c] = U128FromBig(exactGCEncodeSigned(v, 128)).Sub(owner[i*cols+c])
		}
	}
	sort.SliceStable(perm, func(a, b int) bool {
		i, k := perm[a], perm[b]
		if i >= n || k >= n {
			return i < k
		}
		return times[i] > times[k]
	})
	controls, _ := primitiveVPermutationControls(perm)
	ends := make([]bool, m)
	for i := range ends {
		ends[i] = i == m-1 || perm[i] >= n || perm[i+1] >= n || times[perm[i]] != times[perm[i+1]]
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(4 * time.Hour))
	b.SetDeadline(time.Now().Add(4 * time.Hour))
	ga, eb := &primitiveVCountingRW{Conn: a}, &primitiveVCountingRW{Conn: b}
	session := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 128, VectorLen: 1})
	contract := sha256.Sum256([]byte(fmt.Sprintf("public synthetic measured Cox/%d/%d", n, jcount)))
	type response struct {
		result coxLossShareResult
		err    error
	}
	ch := make(chan response, 1)
	start := time.Now()
	go func() {
		out, e := coxLossRunShares(ga, true, p, programs, session, contract, owner, controls, ends)
		if e != nil {
			a.Close()
		}
		ch <- response{out, e}
	}()
	other, e := coxLossRunShares(eb, false, p, programs, session, contract, peer, nil, nil)
	if e != nil {
		b.Close()
	}
	own := <-ch
	if e != nil || own.err != nil {
		return nil, fmt.Errorf("synthetic protocol: %v / %v", own.err, e)
	}
	if own.result.Receipt != other.Receipt || own.result.Chunks != other.Chunks {
		return nil, fmt.Errorf("receipt mismatch")
	}
	elapsed := time.Since(start).Seconds()
	for j := 0; j < jcount; j++ {
		want, e := coxLossReference(etas[j], times, event, live, caps[j], 12)
		if e != nil {
			return nil, e
		}
		if own.result.Coordinates[j]+other.Coordinates[j] != want || own.result.Validity[j]+other.Validity[j] != 1 {
			return nil, fmt.Errorf("synthetic oracle differs candidate %d: q=%d want=%d valid=%d", j, own.result.Coordinates[j]+other.Coordinates[j], want, own.result.Validity[j]+other.Validity[j])
		}
	}
	return map[string]any{"capacity": n, "candidates": jcount, "padded_rows": m, "seconds": elapsed + compileSeconds, "online_seconds": elapsed, "compile_seconds": compileSeconds, "garbler_bytes": ga.Written, "evaluator_bytes": eb.Written, "total_bytes": ga.Written + eb.Written, "chunks": own.result.Chunks, "oracle_equal": true, "production_fusion": false, "transport": "two encrypted peers via net.Pipe; host recorded by benchmark launcher", "profile": CoxGridCrossProfileID,
		"exp_batch_nonxor":  programs.Exp.Circuit.Stats.NumNonXOR(),
		"log_batch_nonxor":  programs.Log.Circuit.Stats.NumNonXOR(),
		"exp_source_sha256": fmt.Sprintf("%x", programs.Exp.SourceSHA256),
		"log_source_sha256": fmt.Sprintf("%x", programs.Log.SourceSHA256),
		"row_batch":         min(p.RowBatch, m)}, nil
}
func TestCoxGridCrossSharedProtocol(t *testing.T) {
	result, err := coxSharedProtocolFixture(t, 34, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(result)
	t.Log(string(data))
}
func TestCoxGridCrossSharedEnvelope(t *testing.T) {
	if os.Getenv("DSVERT_COX_ENVELOPE") != "1" {
		t.Skip("explicit public synthetic envelope run")
	}
	n, _ := strconv.Atoi(os.Getenv("DSVERT_COX_N"))
	j, _ := strconv.Atoi(os.Getenv("DSVERT_COX_J"))
	if (n != 2000 && n != 4000 && n != 10000) || (j != 16 && j != 32 && j != 50) {
		t.Fatal("invalid public benchmark shape")
	}
	result, err := coxSharedProtocolFixture(t, n, j, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.MarshalIndent(result, "", "  ")
	if path := os.Getenv("DSVERT_COX_REPORT"); path != "" {
		if err = os.WriteFile(path, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Log(string(data))
}

func TestCoxGridCrossSharedPlanAndTopology(t *testing.T) {
	for _, n := range []int{2, 4, 8, 32, 2048, 4096, 16384} {
		var original []coxLossSwitch
		primitiveVWalkBenes(n, 0, 1, func(a, b int) { original = append(original, coxLossSwitch{a, b, len(original)}) })
		count := 0
		for _, layer := range coxLossLayers(n) {
			touched := map[int]bool{}
			for _, s := range layer {
				if touched[s.Left] || touched[s.Right] || original[s.Control] != s {
					t.Fatal("changed primitive geometry", n)
				}
				touched[s.Left] = true
				touched[s.Right] = true
				count++
			}
		}
		if count != len(original) {
			t.Fatal("missing switches")
		}
	}
	cap, _ := coxLossCap(2000, 12, []float64{4, 4})
	p, err := registerCoxGridCrossLoss().SharedPlan(coxLossSpec{2000, 1, 12, []uint64{cap}, CoxGridCrossProfileID})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := p.digest()
	if err != nil || digest == [32]byte{} {
		t.Fatal("invalid public plan")
	}
	for _, mutate := range []func(*coxLossSharedPlan){
		func(p *coxLossSharedPlan) { p.RowBatch++ }, func(p *coxLossSharedPlan) { p.OTBatch++ }, func(p *coxLossSharedPlan) { p.PackedColumns++ }, func(p *coxLossSharedPlan) { p.Version = "old" }, func(p *coxLossSharedPlan) { p.Framing = "legacy" },
	} {
		q := p
		mutate(&q)
		if _, err := q.digest(); err == nil {
			t.Fatal("altered plan accepted")
		}
	}
	if _, err := coxLossRunShares(nil, true, p, nil, exactGCSession{}, digest, nil, nil, nil); err == nil {
		t.Fatal("missing source/session accepted")
	}
}

func TestCoxGridCrossSharedCompactTopologyBinding(t *testing.T) {
	src, w, g, e, o := coxLossFinalizeSource(coxLossSpec{2, 1, 12, []uint64{100}, CoxGridCrossProfileID}, 0)
	p := coxTestCompile(t, src, w, g, e, o)
	session := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 64, VectorLen: 1})
	a := coxLossCompactDigest(session, p.Circuit, true)
	if a == coxLossCompactDigest(session, p.Circuit, false) || coxLossCompactDigest(session, p.Circuit, false) != exactGCContextDigest(session) {
		t.Fatal("compact/legacy context collision")
	}
	p.Circuit.Gates[0].Output++
	if a == coxLossCompactDigest(session, p.Circuit, true) {
		t.Fatal("topology substitution accepted")
	}
}
