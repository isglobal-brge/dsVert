package main

// Internal compact runner, adapted from primitive_v_protocol.go. No dispatcher
// or release registration. Keep the primitive and generation-one framing intact.
// The fusion caller must authenticate contract, source and predecessor receipts.
import (
	"crypto/rand"
	"github.com/markkurossi/mpc/p2p"
	"io"
	"math/big"
)

func groupedCompactRunGarbler(rw io.ReadWriter, p *primitiveVProgram, base exactGCSession, contract [32]byte, words []*big.Int) ([]*big.Int, error) {
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
	err = exactGCGarblerProtocolMode(conn, p.Circuit, exactGCPackChunks(inputs, p.WordBits), s, true)
	if exactGCFinishConn(conn, rw, err) != nil {
		return nil, primitiveVError()
	}
	return masks, nil
}

func groupedCompactRunEvaluator(rw io.ReadWriter, p *primitiveVProgram, base exactGCSession, contract [32]byte, words []*big.Int) ([]*big.Int, error) {
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
	result, protocolErr := exactGCEvaluatorProtocolMode(conn, p.Circuit, exactGCPackChunks(words, p.WordBits), s, true)
	if exactGCFinishConn(conn, rw, protocolErr) != nil {
		return nil, primitiveVError()
	}
	outputs := make([]*big.Int, p.OutputWords)
	for i := range outputs {
		outputs[i] = new(big.Int).And(new(big.Int).Rsh(new(big.Int).Set(result), uint(i*p.WordBits)), exactGCMask(p.WordBits))
	}
	return outputs, nil
}
