// k2_dcf_ring127_serialize.go — binary serialization of Ring127 DCF
// preprocessing (keys + mask shares) for transport over the DataSHIELD
// relay. Parallel of serializeDcfBatch / deserializeDcfBatch in
// k2_dcf_protocol.go.
//
// Layout (all little-endian):
//   Per threshold t, per element i:
//     DCFKey127:
//       Seed0   : 16 bytes
//       T0      :  1 byte
//       CW[127] : 127 × dcfCW127 = 127 × 34 bytes
//         dcfCW127:
//           SeedCW : 16 bytes
//           VCW    : 16 bytes (Uint128 LE: Lo then Hi)
//           TCW_L  :  1 byte
//           TCW_R  :  1 byte
//       FinalCW : 16 bytes (Uint128 LE)
//     MaskShare : 16 bytes (Uint128 LE)
//   Per element: keySize = 16 + 1 + 127·34 + 16                = 4351 bytes
//   Per element with MaskShare: elemSize = keySize + 16        = 4367 bytes
//
// Byte budget note: Ring127 blobs are ~2.6× larger than the Ring63 blob
// (1671 B/elem → 4367 B/elem). For Cox Path B at n≤500, numThresh≈102
// (K2ReciprocalIntervals+2), one DCF batch is ~223 MB → pre-P1 GLM is
// unaffected; Ring127 specifically targets the recip/score paths whose
// n is typically ≤ sample size. Keep in mind if n scales.

package main

import (
	"encoding/binary"
)

// ring127DcfNumBits is fixed at 127 for Ring127 DCF. Exposed as a const
// so serialization sizes are unambiguous.
const ring127DcfNumBits = 127

const (
	ring127DcfCWSize   = 16 + 16 + 1 + 1                                   // SeedCW + VCW(Uint128) + TCW_L + TCW_R
	ring127DcfKeySize  = 16 + 1 + ring127DcfNumBits*ring127DcfCWSize + 16  // Seed0 + T0 + CW[] + FinalCW
	ring127DcfElemSize = ring127DcfKeySize + 16                            // + MaskShare (Uint128)
)

// putUint128LE writes v to buf[0:16] in little-endian (Lo then Hi), matching
// the convention used by dcfConvertG128 / cryptoRandUint128.
func putUint128LE(buf []byte, v Uint128) {
	binary.LittleEndian.PutUint64(buf[0:8], v.Lo)
	binary.LittleEndian.PutUint64(buf[8:16], v.Hi)
}

// getUint128LE reads a Uint128 from buf[0:16] in little-endian (Lo then Hi).
func getUint128LE(buf []byte) Uint128 {
	return Uint128{
		Lo: binary.LittleEndian.Uint64(buf[0:8]),
		Hi: binary.LittleEndian.Uint64(buf[8:16]),
	}
}

// serializeDcfBatch127 packs Ring127 DCF keys + mask shares into a single
// byte slice. Mirrors serializeDcfBatch but at 16-byte Uint128 precision.
func serializeDcfBatch127(keys []CmpPreprocessPerParty127, n, numThresh int) []byte {
	buf := make([]byte, numThresh*n*ring127DcfElemSize)

	for t := 0; t < numThresh; t++ {
		for i := 0; i < n; i++ {
			offset := (t*n + i) * ring127DcfElemSize
			key := keys[t].Keys[i]

			// Seed0
			copy(buf[offset:offset+16], key.Seed0[:])
			// T0
			buf[offset+16] = key.T0
			// CW array
			for b := 0; b < ring127DcfNumBits; b++ {
				cwOff := offset + 17 + b*ring127DcfCWSize
				copy(buf[cwOff:cwOff+16], key.CW[b].SeedCW[:])
				putUint128LE(buf[cwOff+16:cwOff+32], key.CW[b].VCW)
				buf[cwOff+32] = key.CW[b].TCW_L
				buf[cwOff+33] = key.CW[b].TCW_R
			}
			// FinalCW
			finalCWOff := offset + 17 + ring127DcfNumBits*ring127DcfCWSize
			putUint128LE(buf[finalCWOff:finalCWOff+16], key.FinalCW)
			// MaskShare
			putUint128LE(buf[offset+ring127DcfKeySize:offset+ring127DcfKeySize+16], keys[t].MaskShare[i])
		}
	}

	return buf
}

// deserializeDcfBatch127 is the inverse of serializeDcfBatch127.
func deserializeDcfBatch127(buf []byte, n, numThresh int) []CmpPreprocessPerParty127 {
	keys := make([]CmpPreprocessPerParty127, numThresh)
	for t := 0; t < numThresh; t++ {
		keys[t].Keys = make([]DCFKey127, n)
		keys[t].MaskShare = make([]Uint128, n)

		for i := 0; i < n; i++ {
			offset := (t*n + i) * ring127DcfElemSize

			// Seed0
			copy(keys[t].Keys[i].Seed0[:], buf[offset:offset+16])
			// T0
			keys[t].Keys[i].T0 = buf[offset+16]
			// CW array
			keys[t].Keys[i].CW = make([]dcfCW127, ring127DcfNumBits)
			keys[t].Keys[i].NumBits = ring127DcfNumBits
			for b := 0; b < ring127DcfNumBits; b++ {
				cwOff := offset + 17 + b*ring127DcfCWSize
				copy(keys[t].Keys[i].CW[b].SeedCW[:], buf[cwOff:cwOff+16])
				keys[t].Keys[i].CW[b].VCW = getUint128LE(buf[cwOff+16 : cwOff+32])
				keys[t].Keys[i].CW[b].TCW_L = buf[cwOff+32]
				keys[t].Keys[i].CW[b].TCW_R = buf[cwOff+33]
			}
			// FinalCW
			finalCWOff := offset + 17 + ring127DcfNumBits*ring127DcfCWSize
			keys[t].Keys[i].FinalCW = getUint128LE(buf[finalCWOff : finalCWOff+16])
			// MaskShare
			keys[t].MaskShare[i] = getUint128LE(buf[offset+ring127DcfKeySize : offset+ring127DcfKeySize+16])
		}
	}

	return keys
}
