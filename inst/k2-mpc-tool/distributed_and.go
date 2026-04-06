// distributed_and.go: Distributed AND gate on additive-shared bits.
//
// Given additive shares of bits a and b (where a0+a1 mod 2 = a, b0+b1 mod 2 = b),
// computes additive shares of c = a AND b = a*b mod 2.
//
// Uses Beaver triples mod 2 (from k2_beaver_mod2.go pattern).
//
// Protocol (1 round):
//   Preprocessing: Generate mod-2 Beaver triple (u,v,w) where w = u*v mod 2
//   Round 1: Each party computes d_i = a_i + u_i mod 2, e_i = b_i + v_i mod 2
//   Exchange: Parties exchange (d_i, e_i)
//   Output: c_i = w_i + e*u_i + d*v_i + [i=0]*d*e  (mod 2)

package main

// --- Preprocessing ---

// ANDTriple holds one party's share of a mod-2 Beaver triple.
type ANDTriple struct {
	U byte // share of u
	V byte // share of v
	W byte // share of w = u AND v
}

// ANDPreprocessBatch generates mod-2 Beaver triples for n AND operations.
// Returns (party0_triples, party1_triples).
func ANDPreprocessBatch(n int) ([]ANDTriple, []ANDTriple) {
	t0 := make([]ANDTriple, n)
	t1 := make([]ANDTriple, n)

	for i := 0; i < n; i++ {
		u := byte(cryptoRandUint64() & 1)
		v := byte(cryptoRandUint64() & 1)
		w := u & v

		u0 := byte(cryptoRandUint64() & 1)
		u1 := u ^ u0
		v0 := byte(cryptoRandUint64() & 1)
		v1 := v ^ v0
		w0 := byte(cryptoRandUint64() & 1)
		w1 := w ^ w0

		t0[i] = ANDTriple{U: u0, V: v0, W: w0}
		t1[i] = ANDTriple{U: u1, V: v1, W: w1}
	}

	return t0, t1
}

// --- Round 1 message ---

// ANDMessage holds the masked bits sent from one party to the peer.
type ANDMessage struct {
	D []byte // d_i = a_i XOR u_i
	E []byte // e_i = b_i XOR v_i
}

// ANDRound1 computes party's message: d = a XOR u, e = b XOR v.
func ANDRound1(aShares, bShares []byte, triples []ANDTriple) ANDMessage {
	n := len(aShares)
	msg := ANDMessage{
		D: make([]byte, n),
		E: make([]byte, n),
	}
	for i := 0; i < n; i++ {
		msg.D[i] = aShares[i] ^ triples[i].U
		msg.E[i] = bShares[i] ^ triples[i].V
	}
	return msg
}

// --- Round 2: compute output ---

// ANDRound2 computes party's share of c = a AND b using Beaver formula.
// d = d_own XOR d_peer (reconstructed), e = e_own XOR e_peer (reconstructed).
// c_i = w_i XOR (e AND u_i) XOR (d AND v_i) XOR [partyID=0] * (d AND e)
func ANDRound2(partyID int, triples []ANDTriple, ownMsg, peerMsg ANDMessage) []byte {
	n := len(triples)
	result := make([]byte, n)
	for i := 0; i < n; i++ {
		d := ownMsg.D[i] ^ peerMsg.D[i]
		e := ownMsg.E[i] ^ peerMsg.E[i]

		c := triples[i].W ^ (e & triples[i].U) ^ (d & triples[i].V)
		if partyID == 0 {
			c ^= d & e
		}
		result[i] = c
	}
	return result
}

// --- Interval indicator computation ---

// ComputeIntervalIndicators computes 6 interval indicators from comparison bits.
//
// Given additive shares of comparison bits cmp[0..5] where:
//   cmp[0] = [x < 0]
//   cmp[1] = [x < 1]
//   cmp[2] = [x < lfLn2]
//   cmp[3] = [x < -lfLn2]  (i.e., [x < mod - lfLn2_fp])
//   cmp[4] = [x < -1]      (i.e., [x < mod - 1_fp])
//
// Actually, for the unsigned-shifted comparison:
//   cmp[j] = [x_shifted < threshold_j_shifted]
//
// The 6 sigmoid intervals for signed x are:
//   I0: 0 <= x < 1     (positive small: spline)
//   I1: 1 <= x < L     (positive medium: exp+Taylor)
//   I2: x >= L          (positive large: saturate 1)
//   I3: x < -L          (negative large: saturate 0)
//   I4: -L <= x < -1    (negative medium: 1 - exp+Taylor)
//   I5: -1 <= x < 0     (negative small: 1 - spline)
//
// Using 5 thresholds [0, 1, L, -L, -1] in shifted unsigned form:
//   c0 = [x < 0],  c1 = [x < 1],  c2 = [x < L],  c3 = [x < -L],  c4 = [x < -1]
//
// Wait — in unsigned shifted representation:
//   x_shifted = x + offset, where offset = 2^62
//   Negative x → x_shifted < offset
//   Positive x → x_shifted >= offset
//
// Thresholds in shifted form (sorted):
//   t0 = (-L + offset)  → smallest
//   t1 = (-1 + offset)
//   t2 = (0 + offset) = offset
//   t3 = (1 + offset)
//   t4 = (L + offset)   → largest
//
// Comparisons give us: c[j] = [x_shifted < t_j]
//   c0 = [x < -L]     → negative large
//   c1 = [x < -1]     → negative (small or large)
//   c2 = [x < 0]      → negative
//   c3 = [x < 1]      → negative or positive small
//   c4 = [x < L]      → not positive large
//
// Interval indicators (using AND and NOT on comparison bits):
//   I0 = NOT(c2) AND c3           → [x >= 0] AND [x < 1]
//   I1 = NOT(c3) AND c4           → [x >= 1] AND [x < L]
//   I2 = NOT(c4)                  → [x >= L]
//   I3 = c0                       → [x < -L]
//   I4 = NOT(c0) AND c1           → [x >= -L] AND [x < -1]
//   I5 = NOT(c1) AND c2           → [x >= -1] AND [x < 0]
//
// NOT on additive mod-2 share: party 0 flips its bit.
// AND requires Beaver mod-2 triple (1 communication round).
//
// Total AND gates needed: 4 (for I0, I1, I4, I5).
// I2 and I3 are just NOT(c4) and c0 — no AND needed.

// IntervalPreprocess holds preprocessing for indicator AND gates.
type IntervalPreprocess struct {
	P0Triples []ANDTriple // 4 AND triples for party 0
	P1Triples []ANDTriple // 4 AND triples for party 1
}

// IntervalPreprocessBatch generates AND triple preprocessing for n elements.
// Each element needs 4 AND operations.
func IntervalPreprocessBatch(n int) IntervalPreprocess {
	p0, p1 := ANDPreprocessBatch(4 * n)
	return IntervalPreprocess{P0Triples: p0, P1Triples: p1}
}

// IntervalANDMessage holds AND round 1 messages for indicator computation.
type IntervalANDMessage struct {
	Msgs []ANDMessage // 4 AND messages
}

// IntervalIndicatorR1 computes AND round 1 for interval indicators.
// cmpBits: [5][n] comparison bit shares (from CmpResult).
// Returns AND message + non-AND indicators (I2, I3).
func IntervalIndicatorR1(partyID int, n int, cmpBits [][]byte, triples []ANDTriple) IntervalANDMessage {
	// 4 AND operations per element, batched:
	// AND0: NOT(c2) AND c3 → I0
	// AND1: NOT(c3) AND c4 → I1
	// AND2: NOT(c0) AND c1 → I4
	// AND3: NOT(c1) AND c2 → I5

	a0 := make([]byte, n) // NOT(c2)
	b0 := make([]byte, n) // c3
	a1 := make([]byte, n) // NOT(c3)
	b1 := make([]byte, n) // c4
	a2 := make([]byte, n) // NOT(c0)
	b2 := make([]byte, n) // c1
	a3 := make([]byte, n) // NOT(c1)
	b3 := make([]byte, n) // c2

	for i := 0; i < n; i++ {
		// NOT: party 0 flips its share
		notC2 := cmpBits[2][i]
		notC3 := cmpBits[3][i]
		notC0 := cmpBits[0][i]
		notC1 := cmpBits[1][i]
		if partyID == 0 {
			notC2 ^= 1
			notC3 ^= 1
			notC0 ^= 1
			notC1 ^= 1
		}

		a0[i] = notC2
		b0[i] = cmpBits[3][i]
		a1[i] = notC3
		b1[i] = cmpBits[4][i]
		a2[i] = notC0
		b2[i] = cmpBits[1][i]
		a3[i] = notC1
		b3[i] = cmpBits[2][i]
	}

	// Interleave into single arrays for batch AND
	allA := make([]byte, 4*n)
	allB := make([]byte, 4*n)
	copy(allA[0:n], a0)
	copy(allA[n:2*n], a1)
	copy(allA[2*n:3*n], a2)
	copy(allA[3*n:4*n], a3)
	copy(allB[0:n], b0)
	copy(allB[n:2*n], b1)
	copy(allB[2*n:3*n], b2)
	copy(allB[3*n:4*n], b3)

	// AND round 1
	msg := ANDRound1(allA, allB, triples)

	return IntervalANDMessage{Msgs: []ANDMessage{msg}}
}

// IntervalIndicatorR2 completes AND computation and returns 6 interval indicators.
// Returns [6][n] additive bit shares.
func IntervalIndicatorR2(partyID int, n int, cmpBits [][]byte,
	triples []ANDTriple, ownANDMsg, peerANDMsg IntervalANDMessage) [][]byte {

	// Complete AND operations
	andResult := ANDRound2(partyID, triples, ownANDMsg.Msgs[0], peerANDMsg.Msgs[0])

	// Split into 4 AND results
	and0 := andResult[0:n]      // NOT(c2) AND c3 → I0
	and1 := andResult[n : 2*n]  // NOT(c3) AND c4 → I1
	and2 := andResult[2*n : 3*n] // NOT(c0) AND c1 → I4
	and3 := andResult[3*n : 4*n] // NOT(c1) AND c2 → I5

	// Build 6 indicators
	indicators := make([][]byte, 6)
	for k := 0; k < 6; k++ {
		indicators[k] = make([]byte, n)
	}

	for i := 0; i < n; i++ {
		indicators[0][i] = and0[i] // I0: 0 <= x < 1 (spline)
		indicators[1][i] = and1[i] // I1: 1 <= x < L (exp+Taylor)

		// I2 = NOT(c4): x >= L (saturate 1)
		notC4 := cmpBits[4][i]
		if partyID == 0 {
			notC4 ^= 1
		}
		indicators[2][i] = notC4

		// I3 = c0: x < -L (saturate 0)
		indicators[3][i] = cmpBits[0][i]

		indicators[4][i] = and2[i] // I4: -L <= x < -1 (1 - exp+Taylor)
		indicators[5][i] = and3[i] // I5: -1 <= x < 0 (1 - spline)
	}

	return indicators
}
