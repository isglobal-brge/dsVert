// k2_beaver_mod2.go: Beaver multiplication modulo 2 (AND gate on XOR-shared bits).
//
// Port of the Hadamard product from Google fss_machine_learning
// specialized for the binary field (mod 2).
//
// For XOR-shared bits [a]_0, [a]_1, [b]_0, [b]_1 where
//   [a]_0 XOR [a]_1 = a and [b]_0 XOR [b]_1 = b,
// computes XOR-shares of c = a AND b.
//
// Uses Beaver triple (u, v, w) where w = u AND v (all mod 2).

package main

// BeaverTripleMod2 holds one party's share of a mod-2 Beaver triple.
type BeaverTripleMod2 struct {
	U byte // [u]_i
	V byte // [v]_i
	W byte // [w]_i = [u AND v]_i
}

// GenerateBeaverTripleMod2 generates correlated mod-2 Beaver triples.
func GenerateBeaverTripleMod2() (t0, t1 BeaverTripleMod2) {
	u := byte(cryptoRandUint64K2() & 1)
	v := byte(cryptoRandUint64K2() & 1)
	w := u & v

	u0 := byte(cryptoRandUint64K2() & 1)
	u1 := u ^ u0
	v0 := byte(cryptoRandUint64K2() & 1)
	v1 := v ^ v0
	w0 := byte(cryptoRandUint64K2() & 1)
	w1 := w ^ w0

	t0 = BeaverTripleMod2{U: u0, V: v0, W: w0}
	t1 = BeaverTripleMod2{U: u1, V: v1, W: w1}
	return
}

// BeaverANDRound1 computes party i's message: (a XOR u, b XOR v).
func BeaverANDRound1(aShare, bShare byte, triple BeaverTripleMod2) (dShare, eShare byte) {
	dShare = aShare ^ triple.U
	eShare = bShare ^ triple.V
	return
}

// BeaverANDRound2 computes party i's share of c = a AND b.
func BeaverANDRound2(partyID int, dOwn, eOwn, dPeer, ePeer byte, triple BeaverTripleMod2) byte {
	// Reconstruct d = a XOR u, e = b XOR v
	d := dOwn ^ dPeer
	e := eOwn ^ ePeer

	// c_i = w_i XOR (e AND u_i) XOR (d AND v_i) XOR [party0] * (d AND e)
	c := triple.W ^ (e & triple.U) ^ (d & triple.V)
	if partyID == 0 {
		c ^= d & e
	}
	return c
}

// SecureAND computes AND of two XOR-shared bits (simulated locally).
func SecureAND(a0, a1, b0, b1 byte) (c0, c1 byte) {
	t0, t1 := GenerateBeaverTripleMod2()

	d0, e0 := BeaverANDRound1(a0, b0, t0)
	d1, e1 := BeaverANDRound1(a1, b1, t1)

	c0 = BeaverANDRound2(0, d0, e0, d1, e1, t0)
	c1 = BeaverANDRound2(1, d1, e1, d0, e0, t1)
	return
}

// SecureNOT computes NOT of an XOR-shared bit.
// Only party 1 flips its share.
func SecureNOT(partyID int, share byte) byte {
	if partyID == 1 {
		return share ^ 1
	}
	return share
}

// SecureMUX selects between two arithmetic-shared values based on an XOR-shared bit.
// If bit=1: return val; if bit=0: return 0.
// This is Hadamard product of (bit converted to arithmetic) with val.
//
// For the spline: indicator[j] (XOR-shared bit) × slope[j] (public scalar).
// Since the scalar is public: result_i = bit_i * scalar (where bit is in {0,1}).
// Party 0: if bit_0 = 0, contribute 0; if bit_0 = 1, contribute scalar.
// But bit_0 is an XOR SHARE, not the actual bit!
//
// Correct approach: convert XOR-share to arithmetic share first.
// In Z_{2^k}: XOR-share bit_0, bit_1 where bit_0 XOR bit_1 = b.
// Arithmetic share: arith_0, arith_1 where arith_0 + arith_1 = b mod 2^k.
//
// Conversion: arith_0 = bit_0, arith_1 = bit_1 * (1 - 2*bit_0).
// But this requires knowing bit_0 which party 1 doesn't have.
//
// Alternative: use a Beaver triple in Z_{2^k} where one input is the bit.
// bit * value = Beaver_Hadamard([bit], [value]) where [value] = (value, 0) for public value.
//
// Simplest for PUBLIC scalar: each party computes scalar * bit_share.
// Since bit is XOR-shared and we want arithmetic shares of scalar * bit:
// Party 0: scalar * bit_0 (but this is wrong if bit_0=1 and bit=0, since bit_0=1, bit_1=1)
//
// The correct way (from C++ ScalarVectorProduct):
// For public scalar 'a' and XOR-shared bit [b]_0, [b]_1:
// Convert to arithmetic shares: [b_arith]_0 = [b]_0, [b_arith]_1 = [b]_1 - 2*[b]_0*[b]_1
// But this requires a Beaver AND to compute [b]_0 * [b]_1.
//
// Even simpler for our case: since the spline indicators are at most 1 bit,
// and we need scalar * indicator in the Ring63, we can use:
// Party 0: (scalar * fracMul) * indicator_0 (arithmetic, but only correct if indicator is in {0,1})
//
// For production: use the full Hadamard product from the C++ code.
// For now: implement the bit-to-arithmetic conversion.

// XORToArithmetic converts XOR-shared bit to additive arithmetic shares in Ring63.
// Given bit0, bit1 where bit0 XOR bit1 = b, produces arith0, arith1 where
// arith0 + arith1 = b mod 2^63.
func XORToArithmetic(r Ring63, bit0, bit1 byte) (arith0, arith1 uint64) {
	// Method: use a Beaver triple mod 2 to compute the "wrap" correction.
	// arith0 = bit0 (as uint64)
	// arith1 = bit1 - 2 * bit0 * bit1 (mod modulus)
	// This works because:
	// arith0 + arith1 = bit0 + bit1 - 2*bit0*bit1
	// = bit0 XOR bit1 (boolean identity for single bits)
	//
	// The term bit0*bit1 needs a Beaver AND since bit0 is party 0's share
	// and bit1 is party 1's share (different parties).

	// For the local simulation: compute directly
	b := bit0 ^ bit1 // actual bit value
	arith0 = uint64(bit0)
	arith1 = r.Sub(uint64(b), arith0) // b - bit0 mod modulus

	// In production, the Beaver AND of bit0*bit1 would be used to compute
	// the correction without revealing b.
	return
}

// ScalarBitMul multiplies a public scalar by an arithmetic-shared indicator bit.
// Returns arithmetic shares of scalar * bit in Ring63.
func ScalarBitMul(r Ring63, scalar float64, bitArith0, bitArith1 uint64) (res0, res1 uint64) {
	scalarFP := r.FromDouble(scalar)
	// res_i = scalar * bitArith_i (ring multiply with truncation)
	res0 = r.TruncMul(scalarFP, bitArith0)
	res1 = r.TruncMul(scalarFP, bitArith1)
	return
}
