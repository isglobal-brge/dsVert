// beaver.go: Beaver triple multiplication protocol for 2-party MPC.
//
// Ported from Google fss_machine_learning: poisson_regression/beaver_triple_utils.h
//
// For fixed-point multiplication [X*Y / 2^lf]:
//   1. Generate triple (A, B, C) where C = A*B mod ring (UNTRUNCATED ring multiply).
//   2. Run standard Beaver protocol using RING multiply (not truncated).
//   3. After protocol: each party truncates its share asymmetrically:
//      P0: floor(share / 2^lf)
//      P1: modulus - floor((modulus - share) / 2^lf)
//   This introduces at most 1 ULP error in the reconstructed value.

package main

// BeaverTriple holds one party's share of a Beaver triple.
type BeaverTriple struct {
	A []uint64 // [A]_i share
	B []uint64 // [B]_i share
	C []uint64 // [C]_i = [A*B]_i share (UNTRUNCATED ring product)
}

// GenerateBeaverTriples generates correlated Beaver triples for both parties.
// C = A*B using ring multiplication (NOT truncated).
func GenerateBeaverTriples(rp RingParams, n int) (BeaverTriple, BeaverTriple) {
	t0 := BeaverTriple{
		A: make([]uint64, n),
		B: make([]uint64, n),
		C: make([]uint64, n),
	}
	t1 := BeaverTriple{
		A: make([]uint64, n),
		B: make([]uint64, n),
		C: make([]uint64, n),
	}
	for i := 0; i < n; i++ {
		a := cryptoRandUint64() % rp.Modulus
		b := cryptoRandUint64() % rp.Modulus
		c := rp.ModMul(a, b) // RING multiply, not truncated

		t0.A[i], t1.A[i] = rp.SplitShare(a)
		t0.B[i], t1.B[i] = rp.SplitShare(b)
		t0.C[i], t1.C[i] = rp.SplitShare(c)
	}
	return t0, t1
}

// BeaverMulMessage is what each party sends to the other in round 1.
type BeaverMulMessage struct {
	XMinusA []uint64
	YMinusB []uint64
}

// BeaverMulRound1 computes the message to send to the peer.
func BeaverMulRound1(rp RingParams, x, y []uint64, triple BeaverTriple) BeaverMulMessage {
	n := len(x)
	msg := BeaverMulMessage{
		XMinusA: make([]uint64, n),
		YMinusB: make([]uint64, n),
	}
	for i := 0; i < n; i++ {
		msg.XMinusA[i] = rp.ModSub(x[i], triple.A[i])
		msg.YMinusB[i] = rp.ModSub(y[i], triple.B[i])
	}
	return msg
}

// BeaverMulRound2 computes this party's share of [X*Y] (UNTRUNCATED ring product).
// Call TruncateShare on the result for fixed-point.
func BeaverMulRound2(rp RingParams, ownMsg, peerMsg BeaverMulMessage,
	triple BeaverTriple, partyID int) []uint64 {

	n := len(triple.A)
	result := make([]uint64, n)

	for i := 0; i < n; i++ {
		// Reconstruct (X-A) and (Y-B)
		xMinusA := rp.ModAdd(ownMsg.XMinusA[i], peerMsg.XMinusA[i])
		yMinusB := rp.ModAdd(ownMsg.YMinusB[i], peerMsg.YMinusB[i])

		// [Z]_i = [C]_i + (X-A)*[B]_i + (Y-B)*[A]_i   (all RING multiply)
		z := triple.C[i]
		z = rp.ModAdd(z, rp.ModMul(xMinusA, triple.B[i]))
		z = rp.ModAdd(z, rp.ModMul(yMinusB, triple.A[i]))

		// Party 0 adds (X-A)*(Y-B)
		if partyID == 0 {
			z = rp.ModAdd(z, rp.ModMul(xMinusA, yMinusB))
		}
		result[i] = z
	}
	return result
}

// TruncateShareP0 truncates party 0's share for fixed-point:
// floor(share / 2^fracBits)
func (rp RingParams) TruncateShareP0(share uint64) uint64 {
	return (share >> uint(rp.NumFractionalBits)) % rp.Modulus
}

// TruncateShareP1 truncates party 1's share for fixed-point:
// modulus - floor((modulus - share) / 2^fracBits)
// This asymmetric truncation ensures the reconstructed value is correct
// up to at most 1 ULP error.
func (rp RingParams) TruncateShareP1(share uint64) uint64 {
	negShare := rp.ModSub(rp.Modulus, share) // modulus - share (but handle 0 case)
	if share == 0 {
		return 0
	}
	negShare = (rp.Modulus - share) % rp.Modulus
	truncNeg := negShare >> uint(rp.NumFractionalBits)
	return rp.ModSub(rp.Modulus, truncNeg%rp.Modulus)
}

// TruncateVecShare truncates a vector of shares for the given party.
func (rp RingParams) TruncateVecShare(shares []uint64, partyID int) []uint64 {
	out := make([]uint64, len(shares))
	for i, s := range shares {
		if partyID == 0 {
			out[i] = rp.TruncateShareP0(s)
		} else {
			out[i] = rp.TruncateShareP1(s)
		}
	}
	return out
}

// BeaverFixedPointMul performs the complete Beaver multiplication protocol
// for fixed-point values, including truncation. Returns truncated shares.
// This is the main entry point for secure fixed-point multiplication.
func BeaverFixedPointMul(rp RingParams, x0, y0, x1, y1 []uint64,
	t0, t1 BeaverTriple) (z0, z1 []uint64) {

	// Round 1
	msg0 := BeaverMulRound1(rp, x0, y0, t0)
	msg1 := BeaverMulRound1(rp, x1, y1, t1)

	// Round 2 (untruncated)
	raw0 := BeaverMulRound2(rp, msg0, msg1, t0, 0)
	raw1 := BeaverMulRound2(rp, msg1, msg0, t1, 1)

	// Truncate
	z0 = rp.TruncateVecShare(raw0, 0)
	z1 = rp.TruncateVecShare(raw1, 1)
	return
}
