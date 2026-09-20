package main

// Public synthetic measurements only. No resource acceptance or protected
// source dispatch is inferred from a successful benchmark test.
import (
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func groupedMeasuredProtocol(t *testing.T, p *primitiveVProgram, want []int64) (int64, int64) {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(5 * time.Minute))
	b.SetDeadline(time.Now().Add(5 * time.Minute))
	ca, cb := &primitiveVCountingRW{Conn: a}, &primitiveVCountingRW{Conn: b}
	session := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: p.WordBits, VectorLen: 1})
	contract := sha256.Sum256([]byte("public grouped revised gate synthetic probe"))
	words := func(n int) []*big.Int {
		v := make([]*big.Int, n)
		for i := range v {
			v[i] = new(big.Int)
		}
		return v
	}
	type result struct {
		out []*big.Int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		v, e := primitiveVRunGarbler(ca, p, session, contract, words(p.InputWordsG-p.OutputWords))
		ch <- result{v, e}
	}()
	ev, err := primitiveVRunEvaluator(cb, p, session, contract, words(p.InputWordsE))
	if err != nil {
		b.Close()
	}
	gr := <-ch
	if err != nil || gr.err != nil {
		t.Fatalf("synthetic protocol failed: %v %v", err, gr.err)
	}
	for i := range ev {
		v := exactGCReferenceReconstruct(gr.out[i], ev[i], p.WordBits)
		if v.Int64() != want[i] {
			t.Fatalf("empty cluster coordinate %d differs: got=%s want=%d", i, v, want[i])
		}
	}
	return ca.Written, cb.Written
}

func TestGroupedRevisedGateMeasuredCosts(t *testing.T) {
	if os.Getenv("DSVERT_GROUPED_COST_PROBE") != "1" {
		t.Skip("opt-in public synthetic resource probe")
	}
	cases := []struct {
		name             string
		rows, predictors int
		compile          func() (*primitiveVProgram, error)
	}{
		{"lmm", 32, 10, func() (*primitiveVProgram, error) {
			s := groupedLMMTestSpec()
			s.Slots = 32
			return groupedLMMCompile(s)
		}},
		{"binomial_glmm", 16, 10, func() (*primitiveVProgram, error) {
			return groupedGLMMCompile(groupedGLMMSpec{"binomial", 16, 16, 16384})
		}},
		{"poisson_glmm", 16, 10, func() (*primitiveVProgram, error) {
			return groupedGLMMCompile(groupedGLMMSpec{"poisson", 16, 16, 16384})
		}},
	}
	for _, family := range []string{"binomial", "poisson"} {
		for _, correlation := range []string{"independence", "exchangeable", "ar1"} {
			family, correlation := family, correlation
			cases = append(cases, struct {
				name             string
				rows, predictors int
				compile          func() (*primitiveVProgram, error)
			}{
				family + "_gee_" + correlation, 8, 3, func() (*primitiveVProgram, error) {
					rho := int64(16384)
					if correlation == "independence" {
						rho = 0
					}
					maxOutcome := int64(1)
					if family == "poisson" {
						maxOutcome = 4
					}
					return groupedGEECompile(groupedGEESpec{Slots: 8, Predictors: 3, GridBits: 16, Family: family, Correlation: correlation, RhoQ16: rho, ScoreClipQ16: 65536, RowLossCap: 1 << 24, BreadCap: 1 << 24, MaxOutcome: maxOutcome})
				}})
		}
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			runtime.GC()
			start := time.Now()
			p, err := c.compile()
			compileSeconds := time.Since(start).Seconds()
			if err != nil {
				t.Fatal(err)
			}
			want := make([]int64, p.OutputWords)
			want[len(want)-1] = 1
			if strings.Contains(c.name, "_gee_") {
				tri := (p.OutputWords - 2) / 2
				for i := 1; i <= tri; i++ {
					// GEE's public shifts remain even for empty padded clusters.
					if !strings.HasSuffix(c.name, "independence") {
						want[i] = 1 << 24
					}
					want[tri+i] = 65536
				}
			}
			start = time.Now()
			garbler, evaluator := groupedMeasuredProtocol(t, p, want)
			seconds := time.Since(start).Seconds()
			chunks := int64((10000 + c.rows - 1) / c.rows * 50)
			tables := primitiveVTableBytes(p.Circuit)
			if garbler+evaluator < tables {
				t.Fatal("traffic counter below garbled payload")
			}
			record := map[string]interface{}{
				"family": c.name, "rows_per_chunk": c.rows, "predictors": c.predictors, "gates": p.Circuit.NumGates,
				"source_sha256": p.SourceSHA256, "table_bytes_per_chunk": tables, "compile_seconds": compileSeconds,
				"protocol_seconds": seconds, "garbler_bytes": garbler, "evaluator_bytes": evaluator,
				"hypothetical_n10000_grid50_chunks": chunks, "mandatory_table_byte_lower_bound": tables * chunks,
				"sample_wire_bytes_times_chunks_NOT_full_measurement": (garbler + evaluator) * chunks,
				"lower_bound_exceeds_256GB":                            tables*chunks > 256000000000,
				"includes_routing_dot_noise_ledger":                   false, "full_release_measured": false,
				"go": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH,
			}
			encoded, _ := json.Marshal(record)
			t.Log(string(encoded))
		})
	}
}
