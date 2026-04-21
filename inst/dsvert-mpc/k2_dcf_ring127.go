// k2_dcf_ring127.go — Distributed Comparison Function (DCF) over Ring127.
//
// Ring127 parallel of k2_dcf.go. Structural copy of the Boyle et al. 2020
// FSS construction (EUROCRYPT 2021, https://eprint.iacr.org/2020/1392),
// retargeted from (uint64, int64, numBits=63, group Z_{2^64}) to
// (Uint128, Uint128, numBits=127, group Z_{2^128}).
//
// What changes vs. Ring63:
//   - Domain bits: 63 → 127.
//   - Output group element: int64 → Uint128 (two's-complement wrap at 2^128).
//   - getBit128 supports bit positions ≥ 64 (Hi-word extraction).
//   - dcfConvertG128 consumes all 16 bytes of the AES output (vs. 8 bytes
//     for the Ring63 int64 group) — same AES key, same MMO PRG, only the
//     output width grows.
//   - vCW / FinalCW / vAlpha use Uint128 arithmetic with natural 2^128 wrap
//     (Uint128.Add/Sub already wrap, Uint128.Neg returns two's complement).
//
// What is preserved verbatim:
//   - AES PRG seeds (16 bytes), expansion keys, MMO mode.
//   - Tree structure, Keep/Lose branching by alpha_i, correction-word layout.
//   - sign = -1 when curT1 == 1 (realised here as Uint128.Neg).
//
// A note on the identity (sign^2 = 1):
//   vCW_stored = sign · (v1Lose - v0Lose - vAlpha + [alphaBit==1]·beta)
//                         (call the parenthesised quantity "inner")
//   vAlpha ← vAlpha - v1Keep + v0Keep + sign · vCW_stored
//          = vAlpha - v1Keep + v0Keep + sign · sign · inner
//          = vAlpha - v1Keep + v0Keep + inner          (sign²=1 always)
//   so the update can use `inner` directly, avoiding a second Neg branch.
//   Both Ring63 and Ring127 share this simplification; expressed here
//   explicitly for clarity in the Uint128 code.

package main

import (
	"encoding/binary"
)

// DCFKey127 is the Ring127 parallel of DCFKey.
type DCFKey127 struct {
	Seed0   [dcfLambda]byte
	T0      byte
	CW      []dcfCW127
	FinalCW Uint128
	NumBits int // typically 127 for Ring127; kept parametric for testing.
}

// dcfCW127 is the Ring127 parallel of dcfCW.
type dcfCW127 struct {
	SeedCW [dcfLambda]byte
	VCW    Uint128
	TCW_L  byte
	TCW_R  byte
}

// dcfConvertG128 maps a 128-bit seed to a Uint128 group element.
// Uses the same AES convert-key as the Ring63 path (dcfCipherConvert)
// to keep the PRG family consistent; takes all 16 bytes of the output.
func dcfConvertG128(seed [dcfLambda]byte) Uint128 {
	var out [dcfLambda]byte
	dcfCipherConvert.Encrypt(out[:], seed[:])
	for i := range out {
		out[i] ^= seed[i]
	}
	return Uint128{
		Hi: binary.LittleEndian.Uint64(out[8:16]),
		Lo: binary.LittleEndian.Uint64(out[0:8]),
	}
}

// dcfPRG128 is like dcfPRG but returns Uint128 group elements for v.
// Seeds and control bits are identical to the Ring63 path.
func dcfPRG128(seed [dcfLambda]byte) (
	seedL [dcfLambda]byte, vL Uint128, tL byte,
	seedR [dcfLambda]byte, vR Uint128, tR byte) {

	var outL [dcfLambda]byte
	dcfCipherLeft.Encrypt(outL[:], seed[:])
	for i := range outL {
		outL[i] ^= seed[i]
	}
	var outR [dcfLambda]byte
	dcfCipherRight.Encrypt(outR[:], seed[:])
	for i := range outR {
		outR[i] ^= seed[i]
	}

	copy(seedL[:], outL[:])
	vL = dcfConvertG128(seedL)
	tL = outL[0] & 1

	copy(seedR[:], outR[:])
	vR = dcfConvertG128(seedR)
	tR = outR[0] & 1

	return
}

// getBit128 returns the i-th bit of x (MSB first, 0-indexed, numBits up to 128).
func getBit128(x Uint128, i, numBits int) byte {
	pos := uint(numBits - 1 - i) // bit position from LSB
	if pos >= 64 {
		return byte((x.Hi >> (pos - 64)) & 1)
	}
	return byte((x.Lo >> pos) & 1)
}

// --- DCF Gen127 ---

// DCFGen127 generates Ring127 DCF keys for f(x) = beta · 1{x < alpha}.
// Domain is [0, 2^numBits); output group is Z_{2^128} (Uint128 wrap).
// For Ring127 use numBits=127.
func DCFGen127(alpha Uint128, beta Uint128, numBits int) (key0, key1 DCFKey127) {
	s0 := dcfRandomSeed()
	s1 := dcfRandomSeed()

	key0.Seed0 = s0
	key1.Seed0 = s1
	key0.T0 = 0
	key1.T0 = 1
	key0.NumBits = numBits
	key1.NumBits = numBits
	key0.CW = make([]dcfCW127, numBits)
	key1.CW = make([]dcfCW127, numBits)

	var vAlpha Uint128

	curS0, curS1 := s0, s1
	curT0, curT1 := byte(0), byte(1)

	for i := 0; i < numBits; i++ {
		alphaBit := getBit128(alpha, i, numBits)

		s0L, v0L, t0L, s0R, v0R, t0R := dcfPRG128(curS0)
		s1L, v1L, t1L, s1R, v1R, t1R := dcfPRG128(curS1)

		var s0Keep, s1Keep [dcfLambda]byte
		var s0Lose, s1Lose [dcfLambda]byte
		var v0Lose, v1Lose Uint128
		var t0Keep, t1Keep byte

		if alphaBit == 0 {
			// Keep = Left, Lose = Right
			s0Keep, s1Keep = s0L, s1L
			s0Lose, s1Lose = s0R, s1R
			v0Lose, v1Lose = v0R, v1R
			t0Keep, t1Keep = t0L, t1L
		} else {
			// Keep = Right, Lose = Left
			s0Keep, s1Keep = s0R, s1R
			s0Lose, s1Lose = s0L, s1L
			v0Lose, v1Lose = v0L, v1L
			t0Keep, t1Keep = t0R, t1R
		}

		sCW := xorSeeds(s0Lose, s1Lose)

		// inner = v1Lose - v0Lose - vAlpha + [alphaBit==1] · beta
		inner := v1Lose.Sub(v0Lose).Sub(vAlpha)
		if alphaBit == 1 {
			inner = inner.Add(beta)
		}
		// vCW_stored = sign · inner, sign = -1 iff curT1 == 1
		vCW := inner
		if curT1 == 1 {
			vCW = inner.Neg()
		}

		var v0Keep, v1Keep Uint128
		if alphaBit == 0 {
			v0Keep, v1Keep = v0L, v1L
		} else {
			v0Keep, v1Keep = v0R, v1R
		}
		// vAlpha update: invariant in sign because sign²=1. See file header.
		vAlpha = vAlpha.Sub(v1Keep).Add(v0Keep).Add(inner)

		tCW_L := t0L ^ t1L ^ alphaBit ^ 1
		tCW_R := t0R ^ t1R ^ alphaBit

		cw := dcfCW127{
			SeedCW: sCW,
			VCW:    vCW,
			TCW_L:  tCW_L,
			TCW_R:  tCW_R,
		}
		key0.CW[i] = cw
		key1.CW[i] = cw // same CW for both parties

		var tCWKeep byte
		if alphaBit == 0 {
			tCWKeep = tCW_L
		} else {
			tCWKeep = tCW_R
		}

		curS0 = condXorSeed(s0Keep, sCW, curT0)
		curS1 = condXorSeed(s1Keep, sCW, curT1)
		curT0 = t0Keep ^ (curT0 & tCWKeep)
		curT1 = t1Keep ^ (curT1 & tCWKeep)

		_ = s0Lose
		_ = s1Lose
	}

	// Final correction word
	finalInner := dcfConvertG128(curS1).Sub(dcfConvertG128(curS0)).Sub(vAlpha)
	finalCW := finalInner
	if curT1 == 1 {
		finalCW = finalInner.Neg()
	}

	key0.FinalCW = finalCW
	key1.FinalCW = finalCW

	return
}

// --- DCF Eval127 ---

// DCFEval127 evaluates the Ring127 DCF on input x ∈ [0, 2^numBits).
// Returns partyID's Uint128 share of f(x) = beta · 1{x < alpha}.
// share0 + share1 (mod 2^128) == beta if x < alpha, else 0.
func DCFEval127(partyID int, key DCFKey127, x Uint128) Uint128 {
	curS := key.Seed0
	curT := key.T0
	var V Uint128

	negate := partyID == 1

	for i := 0; i < key.NumBits; i++ {
		cw := key.CW[i]
		xBit := getBit128(x, i, key.NumBits)

		sL, vL, tL, sR, vR, tR := dcfPRG128(curS)
		sL = condXorSeed(sL, cw.SeedCW, curT)
		sR = condXorSeed(sR, cw.SeedCW, curT)
		tL ^= curT & cw.TCW_L
		tR ^= curT & cw.TCW_R

		cvL := vL
		cvR := vR
		if curT == 1 {
			cvL = cvL.Add(cw.VCW)
			cvR = cvR.Add(cw.VCW)
		}

		var contribution Uint128
		if xBit == 0 {
			contribution = cvL
			curS = sL
			curT = tL
		} else {
			contribution = cvR
			curS = sR
			curT = tR
		}

		if negate {
			V = V.Sub(contribution)
		} else {
			V = V.Add(contribution)
		}
	}

	// Final level
	finalV := dcfConvertG128(curS)
	if curT == 1 {
		finalV = finalV.Add(key.FinalCW)
	}
	if negate {
		V = V.Sub(finalV)
	} else {
		V = V.Add(finalV)
	}

	return V
}
