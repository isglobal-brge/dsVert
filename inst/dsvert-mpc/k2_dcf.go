// k2_dcf.go: Distributed Comparison Function (DCF) for 2-party MPC.
//
// Port of the DCF construction from:
//   Boyle, Chandran, Gilboa, Gupta, Ishai, Kumar, Rathee.
//   "Function Secret Sharing for Mixed-Mode and Fixed-Point Secure Computation"
//   EUROCRYPT 2021 (https://eprint.iacr.org/2020/1392)
//
// DCF computes f^<_{alpha,beta}(x) = beta if x < alpha, else 0.
// Gen produces two keys (k0, k1) such that:
//   Eval(0, k0, x) + Eval(1, k1, x) = f^<_{alpha,beta}(x)  for all x.
//
// Uses AES-128 in MMO mode as the PRG: G(s) = AES_k(s) XOR s.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/binary"
)

const (
	dcfLambda = 16 // seed size in bytes (128 bits)
)

// DCFKey holds one party's key for the DCF.
type DCFKey struct {
	Seed0    [dcfLambda]byte // initial seed
	T0       byte            // initial control bit (0 for party 0, 1 for party 1)
	CW       []dcfCW         // correction words, one per level
	FinalCW  int64           // final correction value (group element)
	NumBits  int             // number of bits in the domain (log2 of domain size)
}

// dcfCW is a correction word for one level of the DCF tree.
type dcfCW struct {
	SeedCW [dcfLambda]byte // seed correction
	VCW    int64           // value correction (group element in Z_{2^64})
	TCW_L  byte            // control bit correction for left child
	TCW_R  byte            // control bit correction for right child
}

// PRG using AES-128 in MMO mode: G(s) = AES_fixedKey(s) XOR s
// Output: 2 * (lambda + sizeof(group) + 1 bit) = left_seed || left_v || left_t || right_seed || right_v || right_t
//
// We use two fixed AES keys: one for left, one for right expansion.
var (
	dcfAESKeyLeft  = [16]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}
	dcfAESKeyRight = [16]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01}
)

// dcfPRG expands a seed into (seed, value, controlBit) for left and right children.
func dcfPRG(seed [dcfLambda]byte) (
	seedL [dcfLambda]byte, vL int64, tL byte,
	seedR [dcfLambda]byte, vR int64, tR byte) {

	// Left expansion: AES_keyL(seed) XOR seed (MMO mode)
	var outL [dcfLambda]byte
	dcfCipherLeft.Encrypt(outL[:], seed[:])
	for i := range outL {
		outL[i] ^= seed[i]
	}

	// Right expansion: AES_keyR(seed) XOR seed
	var outR [dcfLambda]byte
	dcfCipherRight.Encrypt(outR[:], seed[:])
	for i := range outR {
		outR[i] ^= seed[i]
	}

	// Parse left output: seed (first 16 bytes from outL)
	copy(seedL[:], outL[:])
	// Value: derive from seed hash (use another AES round)
	vL = dcfConvertG(seedL)
	// Control bit: LSB of the hash
	tL = outL[0] & 1

	// Parse right output
	copy(seedR[:], outR[:])
	vR = dcfConvertG(seedR)
	tR = outR[0] & 1

	return
}

// dcfConvertG maps a seed to a group element in Z_{2^64}.
// Uses AES with a third fixed key.
var dcfAESKeyConvert = [16]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}

func dcfConvertG(seed [dcfLambda]byte) int64 {
	var out [dcfLambda]byte
	dcfCipherConvert.Encrypt(out[:], seed[:])
	for i := range out {
		out[i] ^= seed[i]
	}
	return int64(binary.LittleEndian.Uint64(out[:8]))
}

// dcfRandomSeed generates a random 128-bit seed.
func dcfRandomSeed() [dcfLambda]byte {
	var s [dcfLambda]byte
	crand.Read(s[:])
	return s
}

// getBit returns the i-th bit of x (MSB first, 0-indexed).
func getBit(x uint64, i, numBits int) byte {
	return byte((x >> (numBits - 1 - i)) & 1)
}

// xorSeeds XORs two seeds.
func xorSeeds(a, b [dcfLambda]byte) [dcfLambda]byte {
	var result [dcfLambda]byte
	for i := range result {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// condXorSeed conditionally XORs: if t=1, returns seed XOR correction; else returns seed.
func condXorSeed(seed, correction [dcfLambda]byte, t byte) [dcfLambda]byte {
	if t == 0 {
		return seed
	}
	return xorSeeds(seed, correction)
}

// --- DCF Gen ---

// DCFGen generates DCF keys for the comparison function f(x) = beta if x < alpha, else 0.
// Domain is [0, 2^numBits). Output group is Z_{2^64} (int64 wrapping).
func DCFGen(alpha uint64, beta int64, numBits int) (key0, key1 DCFKey) {
	// Step 1: Random initial seeds
	s0 := dcfRandomSeed()
	s1 := dcfRandomSeed()

	key0.Seed0 = s0
	key1.Seed0 = s1
	key0.T0 = 0 // t0^(0) = 0
	key1.T0 = 1 // t1^(0) = 1
	key0.NumBits = numBits
	key1.NumBits = numBits
	key0.CW = make([]dcfCW, numBits)
	key1.CW = make([]dcfCW, numBits)

	var vAlpha int64 // accumulated value correction

	curS0, curS1 := s0, s1
	curT0, curT1 := byte(0), byte(1)

	for i := 0; i < numBits; i++ {
		alphaBit := getBit(alpha, i, numBits)

		// Expand both seeds
		s0L, v0L, t0L, s0R, v0R, t0R := dcfPRG(curS0)
		s1L, v1L, t1L, s1R, v1R, t1R := dcfPRG(curS1)

		// Keep/Lose based on alpha bit
		var s0Keep, s1Keep [dcfLambda]byte
		var s0Lose, s1Lose [dcfLambda]byte
		var v0Lose, v1Lose int64
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

		// Correction word seed
		sCW := xorSeeds(s0Lose, s1Lose)

		// Value correction
		sign := int64(1)
		if curT1 == 1 {
			sign = -1
		}
		vCW := sign * (v1Lose - v0Lose - vAlpha)

		// DCF key difference: add beta when Lose == Left (alpha_i == 1)
		if alphaBit == 1 {
			vCW += sign * beta
		}

		// Update vAlpha
		var v0Keep, v1Keep int64
		if alphaBit == 0 {
			v0Keep, v1Keep = v0L, v1L
		} else {
			v0Keep, v1Keep = v0R, v1R
		}
		vAlpha = vAlpha - v1Keep + v0Keep + sign*vCW

		// Control bit corrections
		tCW_L := t0L ^ t1L ^ alphaBit ^ 1
		tCW_R := t0R ^ t1R ^ alphaBit

		cw := dcfCW{
			SeedCW: sCW,
			VCW:    vCW,
			TCW_L:  tCW_L,
			TCW_R:  tCW_R,
		}
		key0.CW[i] = cw
		key1.CW[i] = cw // same CW for both parties

		// Update seeds
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
	signFinal := int64(1)
	if curT1 == 1 {
		signFinal = -1
	}
	finalCW := signFinal * (dcfConvertG(curS1) - dcfConvertG(curS0) - vAlpha)

	key0.FinalCW = finalCW
	key1.FinalCW = finalCW

	return
}

// --- DCF Eval ---

// DCFEval evaluates the DCF on input x.
// partyID is 0 or 1. Returns the party's share of f(x) = beta * 1{x < alpha}.
func DCFEval(partyID int, key DCFKey, x uint64) int64 {
	curS := key.Seed0
	curT := key.T0
	var V int64

	sign := int64(1)
	if partyID == 1 {
		sign = -1
	}

	for i := 0; i < key.NumBits; i++ {
		cw := key.CW[i]
		xBit := getBit(x, i, key.NumBits)

		// Expand and apply correction
		sL, vL, tL, sR, vR, tR := dcfPRG(curS)
		sL = condXorSeed(sL, cw.SeedCW, curT)
		sR = condXorSeed(sR, cw.SeedCW, curT)
		tL ^= curT & cw.TCW_L
		tR ^= curT & cw.TCW_R

		// Corrected values
		cvL := vL
		cvR := vR
		if curT == 1 {
			cvL += cw.VCW
			cvR += cw.VCW
		}

		// Follow path
		if xBit == 0 {
			V += sign * cvL
			curS = sL
			curT = tL
		} else {
			V += sign * cvR
			curS = sR
			curT = tR
		}
	}

	// Final level
	finalV := dcfConvertG(curS)
	if curT == 1 {
		finalV += key.FinalCW
	}
	V += sign * finalV

	return V
}

// --- Helper: create AES cipher once ---
var (
	dcfCipherLeft    cipher.Block
	dcfCipherRight   cipher.Block
	dcfCipherConvert cipher.Block
)

func init() {
	dcfCipherLeft, _ = aes.NewCipher(dcfAESKeyLeft[:])
	dcfCipherRight, _ = aes.NewCipher(dcfAESKeyRight[:])
	dcfCipherConvert, _ = aes.NewCipher(dcfAESKeyConvert[:])
}
