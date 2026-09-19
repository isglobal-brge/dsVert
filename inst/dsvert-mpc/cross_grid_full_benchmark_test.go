package main

// Explicit opt-in synthetic whole-workload measurement. This exercises every
// frozen batch and the real joint-noise circuit; it is not R release admission.
import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/markkurossi/mpc/circuit"
)

func crossGridFullNoise(t testing.TB, p crossGridKernelPlan, n int, g, e, raw []*big.Int, label string) uint64 {
	t.Helper()
	sensitivity := new(big.Int)
	upper := make([]int64, len(p.Caps))
	for j, cap := range p.Caps {
		sensitivity.Add(sensitivity, new(big.Int).SetUint64(cap))
		upper[j] = int64(n) * int64(cap)
	}
	plan := jointDPVectorTestPlan(t, "4", "7.888609052210118054117285652827862296732064351090230047702789306640625e-31", sensitivity.String(), len(upper))
	gs := sha256.Sum256([]byte(label + "/synthetic-g"))
	es := sha256.Sum256([]byte(label + "/synthetic-e"))
	var wire uint64
	for start := 0; start < len(upper); start += plan.MaximumChunkCoordinates {
		end := min(len(upper), start+plan.MaximumChunkCoordinates)
		wire += crossGridFullNoiseChunk(t, p.GridBits, plan, start, upper[start:end], g[start:end], e[start:end], raw[start:end], label, gs, es)
	}
	return wire
}

func crossGridFullNoiseChunk(t testing.TB, bits int, plan jointDPVectorPlanOutput, start int, upper []int64, g, e, raw []*big.Int, label string, gs, es [32]byte) uint64 {
	t.Helper()
	spec := jointDPVectorTestSpec(t, plan, start, upper, label, gs, es)
	spec.OutputLatticeBits = bits
	session := jointDPVectorTestSession(spec, fmt.Sprintf("%s/chunk/%d", label, start))
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	gc, ec := &crossGridPWCountingConn{Conn: a}, &crossGridPWCountingConn{Conn: b}
	a.SetDeadline(time.Now().Add(10 * time.Minute))
	b.SetDeadline(time.Now().Add(10 * time.Minute))
	var ng []*big.Int
	done := make(chan error, 1)
	go func() {
		var err error
		ng, err = jointDPVectorRunGarbler(gc, session, spec, g, gs)
		if err != nil {
			a.Close()
		}
		done <- err
	}()
	ne, err := jointDPVectorRunEvaluator(ec, session, spec, e, es)
	if err != nil {
		b.Close()
		<-done
		t.Fatal("whole-workload joint noise rejected")
	}
	if err = <-done; err != nil {
		t.Fatal("whole-workload joint noise rejected")
	}
	noise, err := jointDPVectorReferenceNoise(spec, gs, es)
	if err != nil {
		t.Fatal(err)
	}
	for j := range raw {
		want := new(big.Int).Add(raw[j], noise[j])
		if want.Sign() < 0 {
			want.SetInt64(0)
		}
		if want.Cmp(spec.RawUpperBounds[j]) > 0 {
			want.Set(spec.RawUpperBounds[j])
		}
		if exactGCReferenceReconstruct(ng[j], ne[j], 128).Cmp(want) != 0 {
			t.Fatal("whole-workload DP oracle mismatch")
		}
	}
	return gc.written.Load() + ec.written.Load()
}

func crossGridFullMeasurement(t *testing.T, family string, n, predictors, m, workers int) {
	start := time.Now()
	base := crossGridKernelCostPlan(t, family)
	base.Predictors = predictors
	base.Beta = nil
	base.Caps = nil
	base.ThetaExponents = nil
	cap := crossGridKernelCostPlan(t, family).Caps[0]
	for j := 0; j < m; j++ {
		// Distinct dyadic signed public candidates with exact L1=4 at either p.
		beta := make([]string, predictors+1)
		beta[0] = fmt.Sprint(int64(1<<48) + int64(j)*(1<<40))
		remaining := int64(15 << 48)
		for k := 1; k <= predictors; k++ {
			v := remaining / int64(predictors)
			if k == predictors {
				v = remaining - v*int64(predictors-1)
			}
			if k == 1 {
				v -= int64(j) * (1 << 40)
			}
			beta[k] = fmt.Sprint(v)
		}
		base.Beta = append(base.Beta, beta)
		base.Caps = append(base.Caps, cap)
		if family == "nb" {
			base.ThetaExponents = append(base.ThetaExponents, 7)
		}
	}
	type task struct {
		row, col int
		kernel   *crossGridKernelPrepared
	}
	tasks := make([]task, 0)
	kernels := make(map[string]*crossGridKernelPrepared)
	circuits := make(map[[32]byte]*circuit.Circuit)
	var gates uint64
	for row := 0; row < n; row += 32 {
		rows := min(32, n-row)
		for col := 0; col < m; col += 8 {
			count := min(8, m-col)
			key := fmt.Sprintf("%d/%d", rows, col)
			k := kernels[key]
			if k == nil {
				bp := base
				bp.Rows = rows
				bp.Beta = base.Beta[col : col+count]
				bp.Caps = base.Caps[col : col+count]
				if family == "nb" {
					bp.ThetaExponents = base.ThetaExponents[col : col+count]
				}
				var err error
				source, sourceErr := crossGridKernelSource(bp)
				if sourceErr != nil {
					t.Fatal(sourceErr)
				}
				hash := sha256.Sum256([]byte(source))
				compiled := circuits[hash]
				if compiled == nil {
					compiled, err = crossGridKernelCompile(bp)
					if err != nil {
						t.Fatal(err)
					}
					circuits[hash] = compiled
					t.Logf("compiled family=%s rows=%d candidates=%d elapsed=%.3f", family, rows, count, time.Since(start).Seconds())
				}
				// Source-identical circuits share topology only. Each immutable
				// plan retains its coefficients, private packer and purpose digest.
				k = &crossGridKernelPrepared{plan: bp, circuit: compiled}
				kernels[key] = k
			}
			tasks = append(tasks, task{row, col, k})
			gates += uint64(k.circuit.Stats[circuit.AND])
		}
	}
	compile := time.Since(start)
	g, e, raw := make([]*big.Int, m), make([]*big.Int, m), make([]*big.Int, m)
	for j := range g {
		g[j] = new(big.Int)
		e[j] = new(big.Int)
		raw[j] = new(big.Int)
	}
	jobs := make(chan task, len(tasks))
	for _, job := range tasks {
		jobs <- job
	}
	close(jobs)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var wire uint64
	completed := 0
	compute := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				x := crossGridKernelTestSource(job.kernel.plan, rand.New(rand.NewSource(int64(20260918+job.row))))
				label := fmt.Sprintf("synthetic/full/%s/%d/%d/%d/%d/%d", family, n, predictors, m, job.row, job.col)
				left, right, bytes := crossGridKernelProtocolTest(t, job.kernel, x, label)
				size := len(job.kernel.plan.Beta)
				if left[size].Bit(0) == right[size].Bit(0) {
					t.Fatal("whole-workload alignment rejected")
				}
				expected := crossGridKernelOracle(t, job.kernel.plan, x)
				mu.Lock()
				for j := range expected {
					at := job.col + j
					g[at].Add(g[at], left[j]).Mod(g[at], exactGCModulus(128))
					e[at].Add(e[at], right[j]).Mod(e[at], exactGCModulus(128))
					raw[at].Add(raw[at], expected[j])
				}
				wire += bytes
				completed++
				if completed%100 == 0 {
					t.Logf("progress family=%s n=%d completed=%d/%d seconds=%.3f", family, n, completed, len(tasks), time.Since(compute).Seconds())
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if t.Failed() || completed != len(tasks) {
		t.Fatal("whole-workload batch failed")
	}
	kernelSeconds := time.Since(compute).Seconds()
	noiseStart := time.Now()
	// One mechanism calibrates the entire vector, not independently calibrated batches.
	t.Logf("KERNEL_MEASUREMENT family=%s n=%d p=%d grid=%d batches=%d and=%d wire_bytes=%d seconds=%.3f", family, n, predictors, m, completed, gates, wire, kernelSeconds)
	noiseBytes := crossGridFullNoise(t, base, n, g, e, raw, fmt.Sprintf("synthetic/full/%s/%d/%d/%d", family, n, predictors, m))
	report := map[string]interface{}{"family": family, "n": n, "p": predictors, "grid": m, "peer_pairs": workers, "batches": completed, "kernel_and": gates, "kernel_and_per_eval": float64(gates) / float64(n*m), "kernel_wire_bytes": wire, "joint_noise_wire_bytes": noiseBytes, "total_wire_bytes": wire + noiseBytes, "compile_seconds": compile.Seconds(), "kernel_seconds": kernelSeconds, "joint_noise_seconds": time.Since(noiseStart).Seconds(), "total_seconds": time.Since(start).Seconds(), "integer_and_dp_oracle_equal": true, "authenticated_server_release": false}
	if family == "nb" {
		report["max_outcome"] = base.MaxOutcome
		report["theta_exponents"] = base.ThetaExponents
	}
	encoded, _ := json.Marshal(report)
	t.Logf("FULL_MEASUREMENT %s", encoded)
	if n == 10000 && predictors == 10 && m == 50 && (wire+noiseBytes > 110000000000 || time.Since(start) > 4*time.Hour) {
		t.Fatal("whole-workload resource gate exceeded")
	}
}

func TestCrossGridFullMeasurement(t *testing.T) {
	if os.Getenv("DSVERT_CROSS_FULL_MEASURE") != "1" {
		t.Skip("explicit synthetic whole-workload measurement only")
	}
	value := func(name string, fallback int) int {
		if s := os.Getenv(name); s != "" {
			v, err := strconv.Atoi(s)
			if err != nil || v < 1 {
				t.Fatal("invalid public measurement dimensions")
			}
			return v
		}
		return fallback
	}
	n := value("DSVERT_CROSS_N", 10000)
	p := value("DSVERT_CROSS_P", 10)
	m := value("DSVERT_CROSS_GRID", 50)
	workers := value("DSVERT_CROSS_WORKERS", 48)
	if n > 10000 || p > 16 || m > 256 || workers > 48 {
		t.Fatal("invalid public measurement dimensions")
	}
	for _, family := range []string{"binomial", "poisson", "nb"} {
		t.Run(family, func(t *testing.T) { crossGridFullMeasurement(t, family, n, p, m, workers) })
	}
}
