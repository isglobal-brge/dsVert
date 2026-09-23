package main

// This opt-in, synthetic-fixture adapter exists only in the Go test binary.
// It never adds a plaintext source/noise route to the installed worker.
import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func TestCrossGridLayeredOracleCandidateChunks(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		t.Run(family, func(t *testing.T) {
			dir := t.TempDir()
			p := crossGridKernelPlan{Family: family, Rows: 32, Predictors: 1, Owners: 3,
				A: 1, GridBits: 16, MaxOutcome: 1}
			for j := 0; j < 10; j++ {
				p.Beta = append(p.Beta, []string{"0", "0"})
				p.Caps = append(p.Caps, 1<<24)
			}
			rows := make([][]string, 35)
			for i := range rows {
				rows[i] = []string{"0", "0"}
			}
			output := filepath.Join(dir, "out.json")
			data, err := json.Marshal(map[string]any{"Plan": p, "Rows": rows, "Output": output})
			if err != nil || os.WriteFile(filepath.Join(dir, "in.json"), data, 0600) != nil {
				t.Fatal("cannot create synthetic chunk fixture")
			}
			t.Setenv("DSVERT_CROSS_ORACLE_FIXTURE", filepath.Join(dir, "in.json"))
			TestCrossGridLayeredOracle(t)
			data, err = os.ReadFile(output)
			var result struct{ Exact []string }
			if err != nil || json.Unmarshal(data, &result) != nil || len(result.Exact) != 10 {
				t.Fatal("invalid oracle chunk result")
			}
			unit := int64(45426) // nearest integer to 2^16 * log(2)
			if family == "poisson" {
				unit = 65536 // exp(0) at the signed loss lattice
			}
			for _, value := range result.Exact {
				if value != big.NewInt(35*unit).String() {
					t.Fatal("candidate or row tail was not accumulated exactly once")
				}
			}
		})
	}
}

type crossGridOracleDraw struct {
	Operation       string                              `json:"operation"`
	Purpose         string                              `json:"purpose"`
	GarblerID       string                              `json:"garbler_id"`
	EvaluatorID     string                              `json:"evaluator_id"`
	JointDPVector   *jointDPVectorWorkerPolicy          `json:"joint_dp_vector"`
	JointDPGaussian *jointDPGaussianOneDrawWorkerPolicy `json:"joint_dp_gaussian_one_draw"`
	GarblerSeed     string                              `json:"garbler_seed"`
	EvaluatorSeed   string                              `json:"evaluator_seed"`
}

func TestCrossGridLayeredOracle(t *testing.T) {
	path := os.Getenv("DSVERT_CROSS_ORACLE_FIXTURE")
	if path == "" {
		t.Skip("synthetic layered fixture opt-in")
	}
	var f struct {
		Plan        crossGridKernelPlan
		Rows        [][]string
		Draws       []crossGridOracleDraw
		NativeCalls []crossGridNativeCall
		Output      string
	}
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &f) != nil {
		t.Fatal("invalid synthetic fixture")
	}
	if f.Output == "" || len(f.Rows) == 0 {
		t.Fatal("invalid synthetic fixture shape")
	}
	total := make([]*big.Int, len(f.Plan.Beta))
	for i := range total {
		total[i] = new(big.Int)
	}
	for candidateStart := 0; candidateStart < len(f.Plan.Beta); candidateStart += 8 {
		for start := 0; start < len(f.Rows); start += 32 {
			p := f.Plan
			end := min(candidateStart+8, len(f.Plan.Beta))
			p.Beta = f.Plan.Beta[candidateStart:end]
			p.Caps = f.Plan.Caps[candidateStart:end]
			if p.Family == "nb" {
				p.ThetaExponents = f.Plan.ThetaExponents[candidateStart:end]
			}
			if p.Family == "ordinal" {
				p.Thresholds = f.Plan.Thresholds[candidateStart:end]
			}
			p.Rows = min(32, len(f.Rows)-start)
			if err := p.validate(); err != nil {
				t.Fatal(err)
			}
			x := make([]*big.Int, 0, p.sourceCount())
			for _, row := range f.Rows[start : start+p.Rows] {
				if len(row) != p.Predictors+1 {
					t.Fatal("invalid synthetic row")
				}
				for _, v := range row {
					z, ok := new(big.Int).SetString(v, 10)
					if !ok {
						t.Fatal("invalid synthetic scalar")
					}
					x = append(x, z, big.NewInt(1))
				}
			}
			for owner := 0; owner < p.Owners; owner++ {
				x = append(x, big.NewInt(1), big.NewInt(2))
			}
			loss := crossGridKernelOracle(t, p, x)
			for i := range loss {
				total[candidateStart+i].Add(total[candidateStart+i], loss[i])
			}
		}
	}
	raw := append([]*big.Int{big.NewInt(int64(len(f.Rows)))}, total...)
	var released []string
	if len(f.NativeCalls) > 0 {
		if len(f.Draws) != 0 {
			t.Fatal("mixed synthetic sampler backends")
		}
		released, f.NativeCalls = crossGridNativeRelease(t, raw, f.NativeCalls)
	} else {
		released = crossGridOracleRelease(t, raw, f.Draws)
	}

	exact := make([]string, len(total))
	for i := range total {
		exact[i] = total[i].String()
	}
	out, err := json.Marshal(struct {
		Exact, Released []string
		NativeCalls     []crossGridNativeCall `json:",omitempty"`
	}{exact, released, f.NativeCalls})
	if err != nil || os.WriteFile(f.Output, out, 0600) != nil {
		t.Fatal("cannot write synthetic oracle result")
	}
}

func crossGridOracleRelease(t *testing.T, raw []*big.Int, draws []crossGridOracleDraw) []string {
	t.Helper()
	released := make([]string, len(raw))
	for _, d := range draws {
		var gs, es [32]byte
		for _, pair := range []struct {
			text string
			dst  *[32]byte
		}{{d.GarblerSeed, &gs}, {d.EvaluatorSeed, &es}} {
			bytes, err := base64.StdEncoding.DecodeString(pair.text)
			if err != nil || len(bytes) != 32 {
				t.Fatal("invalid synthetic seed")
			}
			copy(pair.dst[:], bytes)
		}
		session := exactGCSession{Purpose: d.Purpose, GarblerID: d.GarblerID, EvaluatorID: d.EvaluatorID,
			Spec: exactGCCircuitSpec{Operation: exactGCOperation(d.Operation), RingBits: 128}}
		var noise, upper []*big.Int
		var shifts []int
		var start int
		if d.JointDPVector != nil {
			session.Spec.VectorLen = d.JointDPVector.CoordinateCount
			spec, err := jointDPVectorSpecFromPolicy(*d.JointDPVector, session)
			if err != nil {
				t.Fatal(err)
			}
			noise, err = jointDPVectorReferenceNoise(spec, gs, es)
			if err != nil {
				t.Fatal(err)
			}
			upper, shifts, start = spec.RawUpperBounds, spec.ScaleShifts, spec.ChunkStart
		} else if d.JointDPGaussian != nil {
			spec, err := jointDPGaussianOneDrawSpecFromPolicy(*d.JointDPGaussian, session)
			if err != nil {
				t.Fatal(err)
			}
			noise, err = jointDPGaussianOneDrawReferenceNoise(spec, gs, es)
			if err != nil {
				t.Fatal(err)
			}
			upper, shifts, start = spec.RawUpperBounds, spec.ScaleShifts, spec.ChunkStart
		} else {
			t.Fatal("missing production noise policy")
		}
		for j, z := range noise {
			if start+j < 0 || start+j >= len(raw) || released[start+j] != "" {
				t.Fatal("invalid oracle coordinate")
			}
			u := new(big.Int).Lsh(new(big.Int).Set(upper[j]), uint(shifts[j]))
			value := new(big.Int).Lsh(new(big.Int).Set(raw[start+j]), uint(shifts[j]))
			value.Add(value, z)
			if value.Sign() < 0 {
				value.SetInt64(0)
			}
			if value.Cmp(u) > 0 {
				value.Set(u)
			}
			released[start+j] = value.String()
		}
	}
	return released
}
