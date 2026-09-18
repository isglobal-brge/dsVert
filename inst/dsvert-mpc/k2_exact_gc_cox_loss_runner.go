package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/big"

	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/p2p"
)

type coxLossSharedPlan struct {
	Version       string      `json:"version"`
	Spec          coxLossSpec `json:"spec"`
	PaddedRows    int         `json:"padded_rows"`
	PackedColumns int         `json:"packed_columns"`
	RowBatch      int         `json:"row_batch"`
	OTBatch       int         `json:"ot_batch"`
	Framing       string      `json:"framing"`
	OTMode        string      `json:"ot_mode"`
	ReceiptMode   string      `json:"receipt_mode"`
}

func coxLossPlanShares(s coxLossSpec) (coxLossSharedPlan, error) {
	if s.validate() != nil {
		return coxLossSharedPlan{}, coxLossError()
	}
	return coxLossSharedPlan{coxLossSharesVersion, s, intNextPowerOfTwo(s.Capacity), s.Candidates + 2, coxLossChunkRows, coxLossOTBatch, "fixed-topology-framing-v1", "two_checked_streaming_extensions_per_connection_v1", "private_keyed_state_commitments_v1"}, nil
}
func (p coxLossSharedPlan) digest() ([32]byte, error) {
	want, err := coxLossPlanShares(p.Spec)
	a, _ := json.Marshal(p)
	b, _ := json.Marshal(want)
	if err != nil || string(a) != string(b) {
		return [32]byte{}, coxLossError()
	}
	return sha256.Sum256(a), nil
}

type coxLossSharedPrograms struct {
	Exp, Log *primitiveVProgram
	Final    []*primitiveVProgram
}

func coxLossCompileShares(p coxLossSharedPlan) (*coxLossSharedPrograms, error) {
	if _, err := p.digest(); err != nil {
		return nil, err
	}
	rows := min(p.RowBatch, p.PaddedRows)
	exp, err := coxLossCompileSource(coxLossSharedExpSource(rows))
	if err != nil {
		return nil, err
	}
	log, err := coxLossCompileSource(coxLossSharedLogSource(p.Spec.Capacity, rows))
	if err != nil {
		return nil, err
	}
	if exp.Circuit.Stats.NumNonXOR() > uint64(5000*rows) || log.Circuit.Stats.NumNonXOR() > uint64(5000*rows) {
		return nil, coxLossError()
	}
	result := &coxLossSharedPrograms{Exp: exp, Log: log}
	for j := 0; j < p.Spec.Candidates; j++ {
		f, err := coxLossCompileSource(coxLossFinalizeSource(p.Spec, j))
		if err != nil {
			return nil, err
		}
		if f.Circuit.Stats.NumNonXOR() > 4096 {
			return nil, coxLossError()
		}
		result.Final = append(result.Final, f)
	}
	return result, nil
}

// Validate supplied compiled programs against this exact public plan before
// any source shares are used; reject stale capacities, masks or source hashes.
func coxLossProgramsMatch(p coxLossSharedPlan, programs *coxLossSharedPrograms) bool {
	if programs == nil || len(programs.Final) != p.Spec.Candidates {
		return false
	}
	match := func(program *primitiveVProgram, source string, w, g, e, o int) bool {
		return program != nil && program.Circuit != nil && program.SourceSHA256 == sha256.Sum256([]byte(source)) && program.WordBits == w && program.InputWordsG == g && program.InputWordsE == e && program.OutputWords == o && program.Circuit.NumGates <= 32000000
	}
	rows := min(p.RowBatch, p.PaddedRows)
	source, w, g, e, o := coxLossSharedExpSource(rows)
	if !match(programs.Exp, source, w, g, e, o) {
		return false
	}
	source, w, g, e, o = coxLossSharedLogSource(p.Spec.Capacity, rows)
	if !match(programs.Log, source, w, g, e, o) {
		return false
	}
	for j, f := range programs.Final {
		source, w, g, e, o = coxLossFinalizeSource(p.Spec, j)
		if !match(f, source, w, g, e, o) {
			return false
		}
	}
	return true
}

type coxLossShareRunner struct {
	conn              *p2p.Conn
	owner             bool
	session           exactGCSession
	receipt           [32]byte
	ordinal           int
	gcOT              *ot.COT
	selectOT          *ot.COT
	privateReceiptKey [32]byte
}

func (r *coxLossShareRunner) checkpoint(state []Uint128) error {
	next, err := coxLossReceipt(r.conn, r.owner, r.session, r.privateReceiptKey, r.receipt, r.ordinal, state)
	if err != nil {
		return err
	}
	r.receipt = next
	r.ordinal++
	return nil
}
func (r *coxLossShareRunner) gc(p *primitiveVProgram, words []*big.Int) ([]*big.Int, error) {
	count := p.InputWordsE
	if r.owner {
		count = p.InputWordsG - p.OutputWords
	}
	if primitiveVValidateWords(words, count, p.WordBits) != nil {
		return nil, coxLossError()
	}
	session, err := p.session(r.session, r.receipt)
	if err != nil {
		return nil, coxLossError()
	}
	session.Purpose += fmt.Sprintf("/chunk/%d", r.ordinal)
	var out []*big.Int
	if r.owner {
		out = make([]*big.Int, p.OutputWords)
		for i := range out {
			out[i], err = rand.Int(rand.Reader, exactGCModulus(p.WordBits))
			if err != nil {
				return nil, coxLossError()
			}
		}
		inputs := append(append([]*big.Int(nil), words...), out...)
		err = coxLossCompactGarbler(r.conn, p.Circuit, exactGCPackChunks(inputs, p.WordBits), session, true, r.gcOT)
	} else {
		var packed *big.Int
		packed, err = coxLossCompactEvaluator(r.conn, p.Circuit, exactGCPackChunks(words, p.WordBits), session, true, r.gcOT)
		if err == nil {
			out = make([]*big.Int, p.OutputWords)
			for i := range out {
				out[i] = new(big.Int).And(new(big.Int).Rsh(new(big.Int).Set(packed), uint(i*p.WordBits)), exactGCMask(p.WordBits))
			}
		}
	}
	if err != nil {
		return nil, coxLossError()
	}
	state := make([]Uint128, len(out))
	for i, v := range out {
		state[i] = U128FromBig(v)
	}
	if err = r.checkpoint(state); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *coxLossShareRunner) permute(p coxLossSharedPlan, rows []Uint128, controls []bool) error {
	cols := p.PackedColumns
	for _, layer := range coxLossLayers(p.PaddedRows) {
		// Every switch's packed columns stay together; batching depends only on J.
		tile := max(1, p.OTBatch/cols)
		for start := 0; start < len(layer); start += tile {
			switches := layer[start:min(start+tile, len(layer))]
			x := make([]Uint128, len(switches)*cols)
			var choices []bool
			if r.owner {
				choices = make([]bool, len(x))
			}
			for i, s := range switches {
				for c := 0; c < cols; c++ {
					k := i*cols + c
					x[k] = rows[s.Right*cols+c].Sub(rows[s.Left*cols+c])
					if r.owner {
						choices[k] = controls[s.Control]
					}
				}
			}
			masks, err := coxLossOTSelect(r.conn, r.owner, x, choices, r.selectOT)
			if err != nil {
				return err
			}
			state := make([]Uint128, 0, 2*len(x))
			for i, s := range switches {
				for c := 0; c < cols; c++ {
					a, b := s.Left*cols+c, s.Right*cols+c
					if r.owner && controls[s.Control] {
						rows[a], rows[b] = rows[b], rows[a]
					}
					rows[a] = rows[a].Add(masks[i*cols+c])
					rows[b] = rows[b].Sub(masks[i*cols+c])
					state = append(state, rows[a], rows[b])
				}
			}
			if err = r.checkpoint(state); err != nil {
				return err
			}
		}
	}
	return nil
}

// Parallel reverse segmented selection. The owner knows only its own time
// tie boundaries; no peer learns these boundaries or any risk sums. Prefixes
// themselves are exact local Ring64 additions. OT handles private selection.
func (r *coxLossShareRunner) ties(risk []uint64, ends []bool) error {
	n := len(risk)
	var endPrefix []int
	if r.owner {
		endPrefix = make([]int, n+1)
		for i, v := range ends {
			endPrefix[i+1] = endPrefix[i]
			if v {
				endPrefix[i+1]++
			}
		}
	}
	for distance := 1; distance < n; distance *= 2 {
		old := append([]uint64(nil), risk...)
		for start := 0; start < n-distance; start += coxLossOTBatch {
			count := min(coxLossOTBatch, n-distance-start)
			x := make([]Uint128, count)
			var choices []bool
			if r.owner {
				choices = make([]bool, count)
			}
			for k := range x {
				i := start + k
				x[k] = Uint128{Lo: old[i+distance] - old[i]}
				if r.owner {
					choices[k] = endPrefix[i+distance] == endPrefix[i]
				}
			}
			masks, err := coxLossOTSelect(r.conn, r.owner, x, choices, r.selectOT)
			if err != nil {
				return err
			}
			state := make([]Uint128, count)
			for k := range x {
				i := start + k
				risk[i] = old[i] + masks[k].Lo
				if r.owner && choices[k] {
					risk[i] += x[k].Lo
				}
				state[k] = Uint128{Lo: risk[i]}
			}
			if err = r.checkpoint(state); err != nil {
				return err
			}
		}
	}
	return nil
}

type coxLossShareResult struct {
	Coordinates []uint64
	Validity    []uint64
	Receipt     [32]byte
	Chunks      int
}

// ONE release call, one packed permutation. The caller supplies authenticated
// source shares: J exact joined f100 dots followed by live/event per padded
// PSI row. Only the outcome owner receives controls and sorted tie ends.
// This is an internal kernel, not a release endpoint. Returned validity shares
// MUST be checked inside the fused DP gate; no party may open these outputs.
func coxLossRunShares(rw io.ReadWriter, owner bool, p coxLossSharedPlan, programs *coxLossSharedPrograms, base exactGCSession, contract [32]byte, packed []Uint128, controls, ends []bool) (result coxLossShareResult, failure error) {
	digest, err := p.digest()
	shape, _ := primitiveVPermutationShape(p.PaddedRows, 1, 1)
	if err != nil || base.validate() != nil || contract == [32]byte{} || rw == nil || !coxLossProgramsMatch(p, programs) || len(packed) != p.PaddedRows*p.PackedColumns ||
		(owner && (len(controls) != shape.Switches || len(ends) != p.PaddedRows || !ends[len(ends)-1])) || (!owner && (len(controls) != 0 || len(ends) != 0)) {
		return result, coxLossError()
	}
	base.Purpose = fmt.Sprintf("cox-shared/%x/%x/%x", sha256.Sum256([]byte(base.Purpose)), contract, digest)
	base.Spec = exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 128, VectorLen: 1}
	role := exactGCRoleEvaluator
	if owner {
		role = exactGCRoleGarbler
	}
	secure, err := newExactGCSecureRecordRW(rw, base, role)
	if err != nil {
		return result, coxLossError()
	}
	conn := p2p.NewConn(secure)
	defer func() {
		if exactGCFinishConn(conn, rw, failure) != nil {
			result = coxLossShareResult{}
			failure = coxLossError()
		}
	}()
	// Two distinct checked OT extensions persist only on this authenticated
	// connection. The pinned library's shared mode advances its PRG streams on
	// every Send/Receive; no base seeds or extension outputs are reset/reused.
	gcOT := ot.NewCOT(ot.NewCO(rand.Reader), rand.Reader, true, true)
	selectOT := ot.NewCOT(ot.NewCO(rand.Reader), rand.Reader, true, true)
	var receiptKey [32]byte
	if _, err = rand.Read(receiptKey[:]); err != nil {
		return result, coxLossError()
	}
	runner := coxLossShareRunner{privateReceiptKey: receiptKey, gcOT: gcOT, selectOT: selectOT, conn: conn, owner: owner, session: base, receipt: sha256.Sum256(append(contract[:], digest[:]...))}
	rows := append([]Uint128(nil), packed...)
	if err = runner.permute(p, rows, controls); err != nil {
		return result, err
	}
	n, jcount := p.PaddedRows, p.Spec.Candidates
	batch := min(p.RowBatch, n)
	for j := 0; j < jcount; j++ {
		risk, active := make([]uint64, n), make([]uint64, n)
		var loss, bad uint64
		for start := 0; start < n; start += batch {
			input := make([]*big.Int, 3*batch+1)
			for k := 0; k < batch; k++ {
				i := (start + k) * p.PackedColumns
				input[3*k] = rows[i+j].ToBig()
				input[3*k+1] = rows[i+jcount].ToBig()
				input[3*k+2] = rows[i+jcount+1].ToBig()
			}
			input[len(input)-1] = new(big.Int)
			if owner {
				input[len(input)-1].SetInt64(1)
			}
			out, e := runner.gc(programs.Exp, input)
			if e != nil {
				return result, e
			}
			for k := 0; k < batch; k++ {
				risk[start+k] = out[3*k].Uint64()
				loss -= out[3*k+1].Uint64()
				active[start+k] = out[3*k+2].Uint64()
			}
			if owner {
				bad++
			}
			bad -= out[len(out)-1].Uint64()
		}
		for i := 1; i < n; i++ {
			risk[i] += risk[i-1]
		}
		if err = runner.ties(risk, ends); err != nil {
			return result, err
		}
		for start := 0; start < n; start += batch {
			input := make([]*big.Int, 2*batch+1)
			for k := 0; k < batch; k++ {
				input[2*k] = new(big.Int).SetUint64(risk[start+k])
				input[2*k+1] = new(big.Int).SetUint64(active[start+k])
			}
			input[len(input)-1] = new(big.Int)
			if owner {
				input[len(input)-1].SetInt64(1)
			}
			out, e := runner.gc(programs.Log, input)
			if e != nil {
				return result, e
			}
			for k := 0; k < batch; k++ {
				loss += out[k].Uint64()
			}
			if owner {
				bad++
			}
			bad -= out[len(out)-1].Uint64()
		}
		validity := uint64(0) - bad
		if owner {
			validity++
		}
		out, e := runner.gc(programs.Final[j], []*big.Int{new(big.Int).SetUint64(loss), new(big.Int).SetUint64(validity)})
		if e != nil {
			return result, e
		}
		result.Coordinates = append(result.Coordinates, out[0].Uint64())
		result.Validity = append(result.Validity, out[1].Uint64())
	}
	result.Receipt = runner.receipt
	result.Chunks = runner.ordinal
	return result, nil
}
