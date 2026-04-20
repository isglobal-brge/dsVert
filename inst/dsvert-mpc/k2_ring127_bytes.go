// k2_ring127_bytes.go — Uint128 vector byte (de)serialization.
//
// 16-byte little-endian per element: [Lo(8) | Hi(8)]. Matches the convention
// used by the DCF key serialization (putUint128LE / getUint128LE in
// k2_dcf_ring127_serialize.go) so that a single endian-word layout is used
// throughout the Ring127 transport path.

package main

// uint128VecToBytes packs a Uint128 slice into 16-byte-per-element bytes.
func uint128VecToBytes(v []Uint128) []byte {
	buf := make([]byte, len(v)*16)
	for i, x := range v {
		putUint128LE(buf[i*16:], x)
	}
	return buf
}

// bytesToUint128Vec unpacks a 16-byte-per-element byte slice into Uint128s.
// Silently trims any trailing bytes that don't form a full 16-byte record.
func bytesToUint128Vec(buf []byte) []Uint128 {
	n := len(buf) / 16
	v := make([]Uint128, n)
	for i := 0; i < n; i++ {
		v[i] = getUint128LE(buf[i*16:])
	}
	return v
}
