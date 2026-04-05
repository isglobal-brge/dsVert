// util.go: Shared utilities for k2-mpc-tool.

package main

import (
	"crypto/rand"
	"encoding/binary"
)

// cryptoRandUint64 returns a cryptographically secure random uint64.
func cryptoRandUint64() uint64 {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return binary.LittleEndian.Uint64(buf[:])
}
