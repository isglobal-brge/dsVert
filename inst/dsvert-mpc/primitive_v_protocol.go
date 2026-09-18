package main

// Internal composition only: no command, source loader, or release capability.
// Callers must validate the signed family contract before resolving inputs.
// Garbling, checked OT and encrypted records are the existing exact-GC engine.

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/compiler/utils"
	"github.com/markkurossi/mpc/p2p"
)

const exactGCPrimitiveV exactGCOperation = "oblivious-grouping-internal-v1"

func primitiveVError() error { return fmt.Errorf("primitive-v: rejected") }

type primitiveVProgram struct {
	Circuit      *circuit.Circuit
	SourceSHA256 [32]byte
	WordBits     int
	InputWordsG  int // includes the final OutputWords fresh masks
	InputWordsE  int
	OutputWords  int
}

// primitiveVCompile accepts only source constructed from validated public
// parameters by internal emitters. It must never be exposed as an RPC.
func primitiveVCompile(source string, wordBits, inputWordsG, inputWordsE, outputWords int) (*primitiveVProgram, error) {
	if len(source) == 0 || len(source) > 2<<20 || wordBits < 2 || wordBits > 256 ||
		inputWordsG <= outputWords || inputWordsE < 1 || outputWords < 1 ||
		inputWordsG > exactGCMaxCircuitTypeBits/wordBits || inputWordsE > exactGCMaxCircuitTypeBits/wordBits ||
		outputWords > exactGCMaxCircuitTypeBits/wordBits {
		return nil, primitiveVError()
	}
	c, _, err := compiler.New(utils.NewParams()).Compile(source, nil)
	if err != nil || c == nil || len(c.Inputs) != 2 || int(c.Inputs[0].Type.Bits) != inputWordsG*wordBits ||
		int(c.Inputs[1].Type.Bits) != inputWordsE*wordBits || c.Outputs.Size() != outputWords*wordBits || c.NumGates > 25000000 {
		return nil, primitiveVError()
	}
	return &primitiveVProgram{c, sha256.Sum256([]byte(source)), wordBits, inputWordsG, inputWordsE, outputWords}, nil
}

// The authenticated signed-contract hash must cover ownership, row capacity,
// candidate caps, numeric profile, adjacency, batching, and alignment contract.
// Binding it and the exact source prevents cross-shape and cross-purpose reuse.
func (p *primitiveVProgram) session(base exactGCSession, contract [32]byte) (exactGCSession, error) {
	if p == nil || p.Circuit == nil || contract == [32]byte{} || p.SourceSHA256 == [32]byte{} || base.Purpose == "" {
		return exactGCSession{}, primitiveVError()
	}
	purpose := sha256.Sum256([]byte(base.Purpose))
	base.Purpose = fmt.Sprintf("primitive-v/%x/%x/%x", purpose, contract, p.SourceSHA256)
	base.Spec = exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: p.WordBits, VectorLen: 1}
	if base.validate() != nil {
		return exactGCSession{}, primitiveVError()
	}
	return base, nil
}

func primitiveVValidateWords(words []*big.Int, count, bits int) error {
	if len(words) != count {
		return primitiveVError()
	}
	for _, word := range words {
		if word == nil || word.Sign() < 0 || word.BitLen() > bits {
			return primitiveVError()
		}
	}
	return nil
}

// primitiveVRunGarbler returns fresh local output shares. Generated source
// subtracts these masks from every output, including the private validity bit.
func primitiveVRunGarbler(rw io.ReadWriter, p *primitiveVProgram, base exactGCSession, contract [32]byte, words []*big.Int) ([]*big.Int, error) {
	s, err := p.session(base, contract)
	if err != nil || rw == nil {
		return nil, primitiveVError()
	}
	if primitiveVValidateWords(words, p.InputWordsG-p.OutputWords, p.WordBits) != nil {
		return nil, primitiveVError()
	}
	masks := make([]*big.Int, p.OutputWords)
	for i := range masks {
		masks[i], err = rand.Int(rand.Reader, exactGCModulus(p.WordBits))
		if err != nil {
			return nil, primitiveVError()
		}
	}
	inputs := append(append([]*big.Int(nil), words...), masks...)
	secure, err := newExactGCSecureRecordRW(rw, s, exactGCRoleGarbler)
	if err != nil {
		return nil, primitiveVError()
	}
	conn := p2p.NewConn(secure)
	err = exactGCGarblerProtocol(conn, p.Circuit, exactGCPackChunks(inputs, p.WordBits), s)
	if exactGCFinishConn(conn, rw, err) != nil {
		return nil, primitiveVError()
	}
	return masks, nil
}

func primitiveVRunEvaluator(rw io.ReadWriter, p *primitiveVProgram, base exactGCSession, contract [32]byte, words []*big.Int) ([]*big.Int, error) {
	s, err := p.session(base, contract)
	if err != nil || rw == nil {
		return nil, primitiveVError()
	}
	if primitiveVValidateWords(words, p.InputWordsE, p.WordBits) != nil {
		return nil, primitiveVError()
	}
	secure, err := newExactGCSecureRecordRW(rw, s, exactGCRoleEvaluator)
	if err != nil {
		return nil, primitiveVError()
	}
	conn := p2p.NewConn(secure)
	result, protocolErr := exactGCEvaluatorProtocol(conn, p.Circuit, exactGCPackChunks(words, p.WordBits), s)
	if exactGCFinishConn(conn, rw, protocolErr) != nil {
		return nil, primitiveVError()
	}
	outputs := make([]*big.Int, p.OutputWords)
	for i := range outputs {
		outputs[i] = new(big.Int).And(new(big.Int).Rsh(new(big.Int).Set(result), uint(i*p.WordBits)), exactGCMask(p.WordBits))
	}
	return outputs, nil
}

// Garbled table bytes excludes the encrypted-record framing, OT, labels,
// input/output decoding and acknowledgements, all separately measurable.
func primitiveVTableBytes(c *circuit.Circuit) int64 {
	var bytes int64
	for _, gate := range c.Gates {
		bytes += int64(16 * exactGCGarbledRowSize(gate.Op))
	}
	return bytes
}
