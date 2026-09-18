package main

// Cox finite grids are an internal producer library. Registration is not a
// release capability: the fused caller must authenticate the complete schedule,
// sources, private alignment, validity and the existing joint DP publication.
import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
)

const coxGridCrossVersion = "cox_grid_cross_v1"
const coxLossChunkRows = 32
const coxLossChunkSwitches = 64

func coxLossError() error { return errors.New("cox-grid-cross: rejected") }

type coxLossSpec struct {
	Capacity   int      `json:"capacity"`
	Candidates int      `json:"candidates"`
	GridBits   int      `json:"grid_bits"`
	Caps       []uint64 `json:"caps"`
	Profile    string   `json:"profile"`
}

func (s coxLossSpec) validate() error {
	if s.Capacity < 2 || s.Capacity > 10000 || s.Candidates < 1 || s.Candidates > 128 ||
		s.GridBits < 8 || s.GridBits > 18 || len(s.Caps) != s.Candidates || s.Profile != CoxGridCrossProfileID {
		return coxLossError()
	}
	var total uint64
	for _, cap := range s.Caps {
		if cap == 0 || cap > (1<<53)-1 || total > (1<<53)-1-cap {
			return coxLossError()
		}
		total += cap
	}
	return nil
}

// Public endpoints follow the primitive's exact routing order. A tile may
// contain dependent switches; each reads/writes a local wire array in order.
// Only touched endpoints cross its boundary and ALL emitted lanes are remasked.
type coxLossSwitch struct{ Left, Right, Control int }
type coxLossChunk struct {
	Kind      string          `json:"kind"`
	Candidate int             `json:"candidate"`
	Start     int             `json:"start"`
	Rows      int             `json:"rows"`
	Switches  []coxLossSwitch `json:"switches,omitempty"`
}
type coxLossSchedule struct {
	Version    string         `json:"version"`
	Spec       coxLossSpec    `json:"spec"`
	PaddedRows int            `json:"padded_rows"`
	Chunks     []coxLossChunk `json:"chunks"`
}

func coxLossPlan(s coxLossSpec) (coxLossSchedule, error) {
	if s.validate() != nil {
		return coxLossSchedule{}, coxLossError()
	}
	net, _ := primitiveVPermutationShape(s.Capacity, 3, 64)
	p := coxLossSchedule{Version: "cox-breslow-chunks-v1", Spec: s, PaddedRows: net.PaddedRows}
	var switches []coxLossSwitch
	primitiveVWalkBenes(net.PaddedRows, 0, 1, func(a, b int) {
		switches = append(switches, coxLossSwitch{a, b, len(switches)})
	})
	for j := 0; j < s.Candidates; j++ {
		for start := 0; start < s.Capacity; start += coxLossChunkRows {
			p.Chunks = append(p.Chunks, coxLossChunk{Kind: "prepare", Candidate: j, Start: start, Rows: min(coxLossChunkRows, s.Capacity-start)})
		}
		for start := 0; start < len(switches); start += coxLossChunkSwitches {
			end := min(start+coxLossChunkSwitches, len(switches))
			p.Chunks = append(p.Chunks, coxLossChunk{Kind: "permute", Candidate: j, Start: start, Switches: append([]coxLossSwitch(nil), switches[start:end]...)})
		}
		for start := 0; start < net.PaddedRows; start += coxLossChunkRows {
			p.Chunks = append(p.Chunks, coxLossChunk{Kind: "forward", Candidate: j, Start: start, Rows: min(coxLossChunkRows, net.PaddedRows-start)})
		}
		for end := net.PaddedRows; end > 0; {
			start := max(0, end-coxLossChunkRows)
			p.Chunks = append(p.Chunks, coxLossChunk{Kind: "backward", Candidate: j, Start: start, Rows: end - start})
			end = start
		}
		p.Chunks = append(p.Chunks, coxLossChunk{Kind: "finalize", Candidate: j, Rows: 1})
	}
	return p, nil
}

func (p coxLossSchedule) digest() ([32]byte, error) {
	want, err := coxLossPlan(p.Spec)
	if err != nil {
		return [32]byte{}, err
	}
	a, _ := json.Marshal(p)
	b, _ := json.Marshal(want)
	if string(a) != string(b) {
		return [32]byte{}, coxLossError()
	}
	return sha256.Sum256(a), nil
}

// A caller binds contract+schedule+ordinal+predecessor receipts into each
// authenticated session. This prevents shape-compatible stage substitution.
func coxLossChunkBinding(p coxLossSchedule, ordinal int, contract, predecessor [32]byte) ([32]byte, error) {
	schedule, err := p.digest()
	if err != nil || ordinal < 0 || ordinal >= len(p.Chunks) || contract == [32]byte{} ||
		(ordinal > 0 && predecessor == [32]byte{}) {
		return [32]byte{}, coxLossError()
	}
	b, _ := json.Marshal(struct {
		Domain                          string
		Contract, Schedule, Predecessor [32]byte
		Ordinal                         int
	}{
		"cox-grid-cross-chunk-binding-v1", contract, schedule, predecessor, ordinal})
	return sha256.Sum256(b), nil
}

type coxLossRegistration struct {
	Version string
	Plan    func(coxLossSpec) (coxLossSchedule, error)
	Compile func(coxLossSchedule, int) (*primitiveVProgram, error)
}

// ONE registration function is the integration entry. No init/main/RPC entry
// exposes either arbitrary kernels or plaintext evaluation in production.
func registerCoxGridCrossLoss() coxLossRegistration {
	return coxLossRegistration{coxGridCrossVersion, coxLossPlan, coxLossCompileChunk}
}

// Pure public cap arithmetic, mirrored in R. All divisions are outward and
// integer; no platform log/ceil can round a cap inward. Q24 atanh with sixteen
// terms has residual <one Q24 unit for 0<=t<=1/3 (including upward rounding).
func coxLossLogUpperQ24(n int) (uint64, error) {
	if n < 2 || n > 10000 {
		return 0, coxLossError()
	}
	const q uint64 = 1 << 24
	ceil := func(a, b uint64) uint64 { return (a + b - 1) / b }
	atanh := func(num, den uint64) uint64 {
		x := ceil(num*q, den)
		x2 := ceil(x*x, q)
		power := x
		sum := uint64(0)
		for r := uint64(0); r < 16; r++ {
			sum += ceil(power, 2*r+1)
			power = ceil(power*x2, q)
		}
		return 2*sum + 1
	}
	k := uint64(0)
	m := uint64(1)
	for m*2 <= uint64(n) {
		m *= 2
		k++
	}
	return k*atanh(1, 3) + atanh(uint64(n)-m, uint64(n)+m), nil
}

func coxLossCap(capacity, gridBits int, beta []float64) (uint64, error) {
	logN, err := coxLossLogUpperQ24(capacity)
	if err != nil || gridBits < 8 || gridBits > 18 || len(beta) < 1 || len(beta) > 16 {
		return 0, coxLossError()
	}
	radius := uint64(0)
	total := new(big.Rat)
	for _, v := range beta {
		r := new(big.Rat).SetFloat64(v)
		if r == nil {
			return 0, coxLossError()
		}
		r.Abs(r)
		if r.Cmp(big.NewRat(4, 1)) > 0 {
			return 0, coxLossError()
		}
		total.Add(total, r)
		r.Mul(r, big.NewRat(1<<24, 1))
		z, rem := new(big.Int), new(big.Int)
		z.QuoRem(r.Num(), r.Denom(), rem)
		if rem.Sign() > 0 {
			z.Add(z, big.NewInt(1))
		}
		radius += z.Uint64()
	}
	if total.Cmp(big.NewRat(8, 1)) > 0 {
		return 0, coxLossError()
	}
	numerator := uint64(capacity) * (logN + 2*radius + (1 << 18)) // certified per-event error 1/64
	den := uint64(1) << uint(24-gridBits)
	return (numerator + den - 1) / den, nil
}
