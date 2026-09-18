package main

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/markkurossi/mpc/circuit"
)

// Compact framing omits redundant per-gate row lengths. The authenticated
// context commits the entire public topology, so both peers derive exactly the
// same lengths before input transfer. Existing callers retain their V1 digest
// and byte framing; no production dispatcher selects compact mode yet.
func exactGCProtocolDigest(session exactGCSession, c *circuit.Circuit, compact bool) [32]byte {
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
