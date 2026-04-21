// k2_ring127.go — Ring127 fixed-point arithmetic for 2-party MPC.
//
// Goal: provide a wider modulus (2^127) + larger fracBits (up to 63) for
// protocols that compound more noise than Ring63 can tolerate — Cox Path B
// score/Fisher and LMM closed-form Gram assembly being the primary drivers.
//
// Representation: Uint128{Hi, Lo} with schoolbook arithmetic via math/bits.
// This avoids big.Int allocation in the hot path; each Beaver vecmul over
// n elements does O(n) Uint128 ops instead of O(n) big.Int allocations.
//
// Share convention: same additive-secret-share model as Ring63.
//   x = s0 + s1 (mod 2^127), where s0 is a fresh crypto/rand sample and
//   s1 = x - s0 (mod 2^127).
// TruncMul: (a*b) >> fracBits (mod 2^127). Stochastic truncation preserved
// via the same carry-bit mechanism used in Ring63.

package main

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"math/bits"
)

// Uint128 is a 128-bit unsigned integer in (Hi<<64 | Lo) layout.
type Uint128 struct {
	Hi uint64
	Lo uint64
}

func U128Zero() Uint128             { return Uint128{} }
func U128FromUint64(x uint64) Uint128 { return Uint128{Lo: x} }

// Add returns a+b mod 2^128.
func (a Uint128) Add(b Uint128) Uint128 {
	lo, carry := bits.Add64(a.Lo, b.Lo, 0)
	hi, _ := bits.Add64(a.Hi, b.Hi, carry)
	return Uint128{Hi: hi, Lo: lo}
}

// Sub returns a-b mod 2^128.
func (a Uint128) Sub(b Uint128) Uint128 {
	lo, borrow := bits.Sub64(a.Lo, b.Lo, 0)
	hi, _ := bits.Sub64(a.Hi, b.Hi, borrow)
	return Uint128{Hi: hi, Lo: lo}
}

// Mul returns the LOW 128 bits of a*b. Upper 128 bits are discarded
// (this is what "mod 2^128" needs).
func (a Uint128) Mul(b Uint128) Uint128 {
	// Schoolbook:
	//   (aHi·2^64 + aLo)(bHi·2^64 + bLo)
	//   = aLo·bLo + (aLo·bHi + aHi·bLo)<<64 + (aHi·bHi)<<128
	// We keep only the low 128 bits.
	aLoBLoHi, aLoBLoLo := bits.Mul64(a.Lo, b.Lo)
	// cross terms: only their low halves contribute to bits [64,128)
	aLoBHiLo := a.Lo * b.Hi
	aHiBLoLo := a.Hi * b.Lo
	// hi := aLoBLoHi + aLoBHiLo + aHiBLoLo (mod 2^64)
	hi := aLoBLoHi + aLoBHiLo + aHiBLoLo
	return Uint128{Hi: hi, Lo: aLoBLoLo}
}

// Neg returns -a (mod 2^128).
func (a Uint128) Neg() Uint128 {
	return Uint128{}.Sub(a)
}

// Cmp: -1 if a<b, 0 if a==b, 1 if a>b (unsigned).
func (a Uint128) Cmp(b Uint128) int {
	if a.Hi != b.Hi {
		if a.Hi < b.Hi {
			return -1
		}
		return 1
	}
	if a.Lo != b.Lo {
		if a.Lo < b.Lo {
			return -1
		}
		return 1
	}
	return 0
}

// Shr returns a >> n (unsigned). 0 <= n < 128.
func (a Uint128) Shr(n uint) Uint128 {
	if n == 0 {
		return a
	}
	if n >= 128 {
		return Uint128{}
	}
	if n >= 64 {
		return Uint128{Hi: 0, Lo: a.Hi >> (n - 64)}
	}
	return Uint128{
		Hi: a.Hi >> n,
		Lo: (a.Lo >> n) | (a.Hi << (64 - n)),
	}
}

// Shl returns a << n. 0 <= n < 128.
func (a Uint128) Shl(n uint) Uint128 {
	if n == 0 {
		return a
	}
	if n >= 128 {
		return Uint128{}
	}
	if n >= 64 {
		return Uint128{Hi: a.Lo << (n - 64), Lo: 0}
	}
	return Uint128{
		Hi: (a.Hi << n) | (a.Lo >> (64 - n)),
		Lo: a.Lo << n,
	}
}

// Mod reduces a modulo 2^127 (zeros out the top bit).
func (a Uint128) ModPow127() Uint128 {
	return Uint128{Hi: a.Hi & ((uint64(1) << 63) - 1), Lo: a.Lo}
}

// ToBig returns the big.Int equivalent. For cold-path conversions only.
func (a Uint128) ToBig() *big.Int {
	out := new(big.Int).SetUint64(a.Hi)
	out.Lsh(out, 64)
	loBig := new(big.Int).SetUint64(a.Lo)
	out.Or(out, loBig)
	return out
}

// U128FromBig converts a big.Int back to Uint128 (low 128 bits).
func U128FromBig(b *big.Int) Uint128 {
	mask := new(big.Int).Lsh(big.NewInt(1), 64)
	lo := new(big.Int).Mod(b, mask).Uint64()
	shifted := new(big.Int).Rsh(b, 64)
	hi := new(big.Int).Mod(shifted, mask).Uint64()
	return Uint128{Hi: hi, Lo: lo}
}

// Ring127 holds parameters for the 2^127 ring.
type Ring127 struct {
	// Modulus is 2^127 (we use the top bit of Hi as an implicit mask).
	FracBits      int
	FracMul       Uint128 // 1 << fracBits
	SignThreshold Uint128 // modulus / 2 = 2^126
}

// NewRing127 creates a Ring127 with fracBits fractional bits.
// fracBits can be up to 63 without overflow of FracMul within a Uint64.
func NewRing127(fracBits int) Ring127 {
	if fracBits < 1 || fracBits > 126 {
		panic("Ring127: fracBits must be in [1, 126]")
	}
	fm := Uint128{}.Add(Uint128{Lo: 1}).Shl(uint(fracBits))
	st := Uint128{}.Add(Uint128{Lo: 1}).Shl(126)
	return Ring127{
		FracBits:      fracBits,
		FracMul:       fm,
		SignThreshold: st,
	}
}

// Modulus is implicit 2^127; returned via ModPow127().
func (r Ring127) Add(a, b Uint128) Uint128 { return a.Add(b).ModPow127() }
func (r Ring127) Sub(a, b Uint128) Uint128 { return a.Sub(b).ModPow127() }
func (r Ring127) Neg(a Uint128) Uint128    { return a.Neg().ModPow127() }

// IsNeg: true if a > 2^126 (negative in two's-complement-like convention).
func (r Ring127) IsNeg(a Uint128) bool { return a.Cmp(r.SignThreshold) >= 0 }

// FromDouble converts a float64 to Ring127 FP. Uses big.Float for precision
// (cold path — one-off conversion per input, not per-element hot loop).
func (r Ring127) FromDouble(x float64) Uint128 {
	if x == 0 {
		return Uint128{}
	}
	neg := x < 0
	if neg {
		x = -x
	}
	// Scale x by 2^fracBits THEN convert to integer (big.Int route).
	// big.Float gives full precision until the truncation at integer.
	bf := new(big.Float).SetPrec(256).SetFloat64(x)
	scale := new(big.Float).SetPrec(256).SetInt(new(big.Int).Lsh(big.NewInt(1), uint(r.FracBits)))
	bf.Mul(bf, scale)
	// Round to nearest integer
	half := new(big.Float).SetPrec(256).SetFloat64(0.5)
	bf.Add(bf, half)
	scaledInt, _ := bf.Int(nil)
	abs := U128FromBig(scaledInt).ModPow127()
	if neg {
		return r.Neg(abs)
	}
	return abs
}

// ToDouble converts a Ring127 FP to float64. Sign-aware.
func (r Ring127) ToDouble(a Uint128) float64 {
	a = a.ModPow127()
	isNeg := r.IsNeg(a)
	mag := a
	if isNeg {
		mag = r.Neg(a)
	}
	// Use big.Float for precision regardless of magnitude.
	bf := new(big.Float).SetPrec(256).SetInt(mag.ToBig())
	divisor := new(big.Float).SetPrec(256).SetInt(new(big.Int).Lsh(big.NewInt(1), uint(r.FracBits)))
	bf.Quo(bf, divisor)
	f, _ := bf.Float64()
	if isNeg {
		return -f
	}
	return f
}

// TruncMul: (a*b) >> fracBits mod 2^127. Uses big.Int for the 256-bit
// intermediate product; Uint128 × Uint128 → up to 256 bits, need exact
// high/low so we can shift precisely. big.Int is simplest + correct here.
// For hot-path optimization later we can inline the 2x2 schoolbook 64-bit
// multiplication with proper carry chains.
func (r Ring127) TruncMul(a, b Uint128) Uint128 {
	prod := new(big.Int).Mul(a.ToBig(), b.ToBig())
	prod.Rsh(prod, uint(r.FracBits))
	// mod 2^127
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1))
	prod.And(prod, mask)
	return U128FromBig(prod)
}

// TruncMulSigned: sign-aware truncated multiply.
func (r Ring127) TruncMulSigned(a, b Uint128) Uint128 {
	aNeg := r.IsNeg(a)
	bNeg := r.IsNeg(b)
	aa, bb := a, b
	if aNeg {
		aa = r.Neg(a)
	}
	if bNeg {
		bb = r.Neg(b)
	}
	res := r.TruncMul(aa, bb)
	if aNeg != bNeg {
		res = r.Neg(res)
	}
	return res
}

// SplitShare: x = s0 + s1 mod 2^127, s0 uniform random.
func (r Ring127) SplitShare(value Uint128) (s0, s1 Uint128) {
	s0 = cryptoRandUint128()
	s1 = r.Sub(value, s0)
	return
}

func cryptoRandUint128() Uint128 {
	var buf [16]byte
	rand.Read(buf[:])
	return Uint128{
		Hi: binary.LittleEndian.Uint64(buf[0:8]) & ((uint64(1) << 63) - 1),
		Lo: binary.LittleEndian.Uint64(buf[8:16]),
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
