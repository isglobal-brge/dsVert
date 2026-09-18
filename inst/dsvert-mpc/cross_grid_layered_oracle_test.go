package main

// This opt-in, synthetic-fixture adapter exists only in the Go test binary.
// It never adds a plaintext source/noise route to the installed worker.
import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

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
		Plan   crossGridKernelPlan
		Rows   [][]string
		Draws  []crossGridOracleDraw
		Output string
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
	for start := 0; start < len(f.Rows); start += 32 {
		p := f.Plan
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
		for i := range total {
			total[i].Add(total[i], loss[i])
		}
	}
	raw := append([]*big.Int{big.NewInt(int64(len(f.Rows)))}, total...)
	released := make([]string, len(raw))
	for _, d := range f.Draws {
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
			if start+j >= len(raw) {
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
	exact := make([]string, len(total))
	for i := range total {
		exact[i] = total[i].String()
	}
	out, err := json.Marshal(struct{ Exact, Released []string }{exact, released})
	if err != nil || os.WriteFile(f.Output, out, 0600) != nil {
		t.Fatal("cannot write synthetic oracle result")
	}
}
