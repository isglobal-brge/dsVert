// k2_iknp_kos.go -- KOS15 / SoftSpoken-style correlation (consistency) check
// for the IKNP OT extension in k2_iknp_ot.go.
//
// Plain IKNP (Ishai-Kilian-Nissim-Petrank 2003) is secure only against a
// semi-honest receiver: a malicious receiver can place inconsistent choice
// bits in different columns of the U matrix and mount a selective-failure
// attack that leaks bits of the sender's global secret Delta. Keller-Orsini-
// Scholl (KOS15, CRYPTO 2015) close this with a single random linear-combination
// check over GF(2^128); Roy (SoftSpoken OT, CRYPTO 2022) repaired a gap in the
// KOS soundness proof. The *protocol* is the linear-combination check used here.
// A single 128-bit challenge gives ~2^-128 soundness against a chi-coincidence
// forgery; note that (as with all KOS-style checks) the pass/fail outcome is
// itself a Delta-correlated selective-failure channel leaking a bounded number
// of bits — so this is a defence-in-depth hardening for a semi-honest-default,
// governed-peer deployment, not a claim of clean 2^-128 "no leakage".
//
// The check is folded into the EXISTING extend->encrypt message flow (no extra
// relay round): the challenge weights chi_i are derived by Fiat-Shamir from the
// U matrix that the receiver has already committed to, so the receiver cannot
// adapt U to the challenge. The receiver sends (x_hat, t_hat); the sender
// recomputes q_hat and verifies q_hat == t_hat XOR (x_hat . Delta).
//
// NOTE (scope): this hardens the OT-extension primitive only. It does NOT by
// itself yield end-to-end malicious security — the Beaver openings and share
// reveals remain semi-honest — so it is a defence-in-depth measure, not a
// malicious-MPC guarantee.

package main

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/markkurossi/mpc/ot"
)

// gfElem is an element of GF(2^128): lo = bits 0..63 (x^0..x^63), hi = bits
// 64..127 (x^64..x^127). Reduction polynomial x^128 + x^7 + x^2 + x + 1.
type gfElem struct {
	lo uint64
	hi uint64
}

const gfReducePoly = 0x87 // x^7 + x^2 + x + 1

func gfAdd(a, b gfElem) gfElem { return gfElem{a.lo ^ b.lo, a.hi ^ b.hi} }

// gfMul multiplies two GF(2^128) elements (shift-and-add, MSB reduction).
func gfMul(a, b gfElem) gfElem {
	var z gfElem
	v := a
	for i := 0; i < 128; i++ {
		var bit uint64
		if i < 64 {
			bit = (b.lo >> uint(i)) & 1
		} else {
			bit = (b.hi >> uint(i-64)) & 1
		}
		if bit == 1 {
			z.lo ^= v.lo
			z.hi ^= v.hi
		}
		carry := v.hi >> 63
		v.hi = (v.hi << 1) | (v.lo >> 63)
		v.lo = v.lo << 1
		if carry == 1 {
			v.lo ^= gfReducePoly
		}
	}
	return z
}

func labelToGf(l ot.Label) gfElem { return gfElem{lo: l.D0, hi: l.D1} }

// iknpKOSEncode / iknpKOSDecode serialise (x_hat, t_hat) as 32 little-endian
// bytes: x_hat.lo | x_hat.hi | t_hat.lo | t_hat.hi.
func iknpKOSEncode(xHat, tHat gfElem) string {
	var raw [32]byte
	binary.LittleEndian.PutUint64(raw[0:8], xHat.lo)
	binary.LittleEndian.PutUint64(raw[8:16], xHat.hi)
	binary.LittleEndian.PutUint64(raw[16:24], tHat.lo)
	binary.LittleEndian.PutUint64(raw[24:32], tHat.hi)
	return bytesToBase64(raw[:])
}

func iknpKOSDecode(s string) (xHat, tHat gfElem, ok bool) {
	raw := base64ToBytes(s)
	if raw == nil || len(raw) != 32 {
		return gfElem{}, gfElem{}, false
	}
	xHat = gfElem{binary.LittleEndian.Uint64(raw[0:8]), binary.LittleEndian.Uint64(raw[8:16])}
	tHat = gfElem{binary.LittleEndian.Uint64(raw[16:24]), binary.LittleEndian.Uint64(raw[24:32])}
	return xHat, tHat, true
}

// iknpKOSSeed binds the Fiat-Shamir transcript: the committed U matrix plus the
// public batch parameters (n, ring, domain) for domain separation.
func iknpKOSSeed(uMatrix []byte, n int, ring, domain string) [32]byte {
	h := sha256.New()
	h.Write([]byte("dsvert-iknp-kos-v1"))
	var nb [8]byte
	binary.LittleEndian.PutUint64(nb[:], uint64(n))
	h.Write(nb[:])
	h.Write([]byte(ring))
	h.Write([]byte{0})
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(uMatrix)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// iknpKOSChi expands the seed into per-row challenge weights chi_i in GF(2^128).
func iknpKOSChi(seed [32]byte, i int) gfElem {
	h := sha256.New()
	h.Write(seed[:])
	var ib [8]byte
	binary.LittleEndian.PutUint64(ib[:], uint64(i))
	h.Write(ib[:])
	sum := h.Sum(nil)
	return gfElem{
		lo: binary.LittleEndian.Uint64(sum[0:8]),
		hi: binary.LittleEndian.Uint64(sum[8:16]),
	}
}

// iknpReceiverKOSCheck computes the receiver's check openers:
//
//	x_hat = sum_i chi_i * x_i   (x_i in {0,1}: field 0 or field 1)
//	t_hat = sum_i chi_i * t_i   (t_i = receiver seed row)
func iknpReceiverKOSCheck(labels []ot.Label, choices []bool, uMatrix []byte,
	n int, ring, domain string) (xHat, tHat gfElem) {
	seed := iknpKOSSeed(uMatrix, n, ring, domain)
	m := len(choices)
	if len(labels) < m {
		m = len(labels)
	}
	for i := 0; i < m; i++ {
		chi := iknpKOSChi(seed, i)
		if choices[i] {
			// x_i = 1: chi_i * 1 = chi_i
			xHat = gfAdd(xHat, chi)
		}
		tHat = gfAdd(tHat, gfMul(chi, labelToGf(labels[i])))
	}
	return xHat, tHat
}

// iknpSenderKOSVerify recomputes q_hat = sum_i chi_i * q_i and verifies the KOS
// correlation q_hat == t_hat XOR (x_hat . Delta). Returns true iff consistent.
func iknpSenderKOSVerify(qLabels []ot.Label, delta ot.Label, uMatrix []byte,
	n int, ring, domain string, xHat, tHat gfElem) bool {
	seed := iknpKOSSeed(uMatrix, n, ring, domain)
	var qHat gfElem
	for i := 0; i < len(qLabels); i++ {
		chi := iknpKOSChi(seed, i)
		qHat = gfAdd(qHat, gfMul(chi, labelToGf(qLabels[i])))
	}
	rhs := gfAdd(tHat, gfMul(xHat, labelToGf(delta)))
	return qHat == rhs
}
