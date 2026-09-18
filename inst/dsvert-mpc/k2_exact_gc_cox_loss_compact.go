package main

// Family-local adaptation of step-2 commit 0006f1a. Kept additive so integration
// can replace these functions with the shared mode-aware protocol verbatim.
import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/p2p"
	"io"
	"math/big"
)

// Compact framing omits redundant per-gate row lengths. The authenticated
// context commits the entire public topology, so both peers derive exactly the
// same lengths before input transfer. Existing callers retain their V1 digest
// and byte framing; no production dispatcher selects compact mode yet.
func coxLossCompactDigest(session exactGCSession, c *circuit.Circuit, compact bool) [32]byte {
	context := exactGCContextDigest(session)
	if !compact {
		return context
	}
	h := sha256.New()
	h.Write([]byte("dsvert-exact-gc-fixed-topology-framing-v1\x00"))
	h.Write(context[:])
	var word [8]byte
	put := func(n uint64) { binary.LittleEndian.PutUint64(word[:], n); h.Write(word[:]) }
	put(uint64(len(c.Inputs)))
	for _, input := range c.Inputs {
		put(uint64(input.Type.Bits))
	}
	put(uint64(c.Outputs.Size()))
	put(uint64(c.NumWires))
	put(uint64(c.NumGates))
	for _, g := range c.Gates {
		put(uint64(g.Op))
		put(uint64(g.Input0))
		put(uint64(g.Input1))
		put(uint64(g.Output))
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func coxLossCompactGarbler(conn *p2p.Conn, circ *circuit.Circuit,
	input *big.Int, session exactGCSession, compact bool) error {
	digest := coxLossCompactDigest(session, circ, compact)
	if err := conn.SendData(digest[:]); err != nil {
		return fmt.Errorf("exact-gc: send context: %w", err)
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("exact-gc: flush context: %w", err)
	}
	ack, err := conn.ReceiveData()
	if err != nil {
		return fmt.Errorf("exact-gc: receive context acknowledgement: %w", err)
	}
	if !bytes.Equal(ack, digest[:]) {
		return fmt.Errorf("exact-gc: peer context mismatch")
	}

	// This is the public fixed-key AES hash key used by the garbling scheme,
	// exactly as in markkurossi/mpc's Garbler/Evaluator protocol. It is not the
	// secret record-layer MasterKey and does not derive random wire labels.
	var garblingHashKey [32]byte
	if _, err := io.ReadFull(crand.Reader, garblingHashKey[:]); err != nil {
		return fmt.Errorf("exact-gc: generate garbling key: %w", err)
	}
	garbled, err := circ.Garble(crand.Reader, garblingHashKey[:])
	if err != nil {
		return fmt.Errorf("exact-gc: garble circuit: %w", err)
	}
	if err := conn.SendData(garblingHashKey[:]); err != nil {
		return fmt.Errorf("exact-gc: send garbling key: %w", err)
	}
	if err := conn.SendUint32(len(garbled.Gates)); err != nil {
		return fmt.Errorf("exact-gc: send gate count: %w", err)
	}
	var labelData ot.LabelData
	for _, row := range garbled.Gates {
		if !compact {
			if err := conn.SendUint32(len(row)); err != nil {
				return fmt.Errorf("exact-gc: send gate row size: %w", err)
			}
		}
		for _, label := range row {
			if err := conn.SendLabel(label, &labelData); err != nil {
				return fmt.Errorf("exact-gc: send garbled gate: %w", err)
			}
		}
	}

	garblerBits := int(circ.Inputs[0].Type.Bits)
	for i := 0; i < garblerBits; i++ {
		label := circuit.LabelForBit(garbled.Wires[i], input.Bit(i) == 1)
		if err := conn.SendLabel(label, &labelData); err != nil {
			return fmt.Errorf("exact-gc: send garbler input: %w", err)
		}
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("exact-gc: flush garbled circuit: %w", err)
	}

	oti := ot.NewCOT(ot.NewCO(crand.Reader), crand.Reader, true, false)
	if err := oti.InitSender(conn); err != nil {
		return fmt.Errorf("exact-gc: initialize OT sender: %w", err)
	}
	offset, err := conn.ReceiveUint32()
	if err != nil {
		return fmt.Errorf("exact-gc: receive OT offset: %w", err)
	}
	count, err := conn.ReceiveUint32()
	if err != nil {
		return fmt.Errorf("exact-gc: receive OT count: %w", err)
	}
	evaluatorBits := int(circ.Inputs[1].Type.Bits)
	if offset != garblerBits || count != evaluatorBits {
		return fmt.Errorf("exact-gc: invalid evaluator OT range")
	}
	if err := oti.Send(garbled.Wires[offset : offset+count]); err != nil {
		return fmt.Errorf("exact-gc: transfer evaluator inputs: %w", err)
	}

	decode := make([]byte, (circ.Outputs.Size()+7)/8)
	firstOutput := circ.NumWires - circ.Outputs.Size()
	for i := 0; i < circ.Outputs.Size(); i++ {
		if garbled.Wires[firstOutput+i].L0.S() {
			decode[i/8] |= 1 << uint(i%8)
		}
	}
	if err := conn.SendData(decode); err != nil {
		return fmt.Errorf("exact-gc: send output decoding mask: %w", err)
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("exact-gc: flush output decoding mask: %w", err)
	}
	done, err := conn.ReceiveData()
	if err != nil {
		return fmt.Errorf("exact-gc: receive completion: %w", err)
	}
	expectedDone := exactGCDoneDigest(digest)
	if !bytes.Equal(done, expectedDone[:]) {
		return fmt.Errorf("exact-gc: invalid completion acknowledgement")
	}
	return nil
}

func coxLossCompactEvaluator(conn *p2p.Conn, circ *circuit.Circuit,
	input *big.Int, session exactGCSession, compact bool) (*big.Int, error) {
	digest := coxLossCompactDigest(session, circ, compact)
	gotContext, err := conn.ReceiveData()
	if err != nil {
		return nil, fmt.Errorf("exact-gc: receive context: %w", err)
	}
	if !bytes.Equal(gotContext, digest[:]) {
		return nil, fmt.Errorf("exact-gc: peer context mismatch")
	}
	if err := conn.SendData(digest[:]); err != nil {
		return nil, fmt.Errorf("exact-gc: acknowledge context: %w", err)
	}
	if err := conn.Flush(); err != nil {
		return nil, fmt.Errorf("exact-gc: flush context acknowledgement: %w", err)
	}

	garblingHashKey, err := conn.ReceiveData()
	if err != nil {
		return nil, fmt.Errorf("exact-gc: receive garbling key: %w", err)
	}
	if len(garblingHashKey) != 32 {
		return nil, fmt.Errorf("exact-gc: invalid garbling key length")
	}
	gateCount, err := conn.ReceiveUint32()
	if err != nil {
		return nil, fmt.Errorf("exact-gc: receive gate count: %w", err)
	}
	if gateCount != circ.NumGates {
		return nil, fmt.Errorf("exact-gc: invalid gate count")
	}
	garbled := make([][]ot.Label, circ.NumGates)
	var labelData ot.LabelData
	for i, gate := range circ.Gates {
		expected := exactGCGarbledRowSize(gate.Op)
		count := expected
		if !compact {
			var err error
			count, err = conn.ReceiveUint32()
			if err != nil {
				return nil, fmt.Errorf("exact-gc: receive gate row size: %w", err)
			}
			if count != expected {
				return nil, fmt.Errorf("exact-gc: invalid row size for gate %d", i)
			}
		}
		row := make([]ot.Label, count)
		for j := range row {
			if err := conn.ReceiveLabel(&row[j], &labelData); err != nil {
				return nil, fmt.Errorf("exact-gc: receive garbled gate: %w", err)
			}
		}
		garbled[i] = row
	}

	wires := make([]ot.Label, circ.NumWires)
	garblerBits := int(circ.Inputs[0].Type.Bits)
	for i := 0; i < garblerBits; i++ {
		if err := conn.ReceiveLabel(&wires[i], &labelData); err != nil {
			return nil, fmt.Errorf("exact-gc: receive garbler input: %w", err)
		}
	}

	oti := ot.NewCOT(ot.NewCO(crand.Reader), crand.Reader, true, false)
	if err := oti.InitReceiver(conn); err != nil {
		return nil, fmt.Errorf("exact-gc: initialize OT receiver: %w", err)
	}
	evaluatorBits := int(circ.Inputs[1].Type.Bits)
	if err := conn.SendUint32(garblerBits); err != nil {
		return nil, fmt.Errorf("exact-gc: send OT offset: %w", err)
	}
	if err := conn.SendUint32(evaluatorBits); err != nil {
		return nil, fmt.Errorf("exact-gc: send OT count: %w", err)
	}
	if err := conn.Flush(); err != nil {
		return nil, fmt.Errorf("exact-gc: flush OT request: %w", err)
	}
	choices := make([]bool, evaluatorBits)
	for i := range choices {
		choices[i] = input.Bit(i) == 1
	}
	if err := oti.Receive(choices, wires[garblerBits:garblerBits+evaluatorBits]); err != nil {
		return nil, fmt.Errorf("exact-gc: receive evaluator inputs: %w", err)
	}
	if err := circ.Eval(garblingHashKey, wires, garbled); err != nil {
		return nil, fmt.Errorf("exact-gc: evaluate circuit: %w", err)
	}

	decode, err := conn.ReceiveData()
	if err != nil {
		return nil, fmt.Errorf("exact-gc: receive output decoding mask: %w", err)
	}
	if len(decode) != (circ.Outputs.Size()+7)/8 {
		return nil, fmt.Errorf("exact-gc: invalid output decoding mask length")
	}
	result := new(big.Int)
	firstOutput := circ.NumWires - circ.Outputs.Size()
	for i := 0; i < circ.Outputs.Size(); i++ {
		lambda := (decode[i/8] >> uint(i%8)) & 1
		bit := uint(0)
		if wires[firstOutput+i].S() != (lambda == 1) {
			bit = 1
		}
		result.SetBit(result, i, bit)
	}
	done := exactGCDoneDigest(digest)
	if err := conn.SendData(done[:]); err != nil {
		return nil, fmt.Errorf("exact-gc: send completion: %w", err)
	}
	if err := conn.Flush(); err != nil {
		return nil, fmt.Errorf("exact-gc: flush completion: %w", err)
	}
	return result, nil
}
