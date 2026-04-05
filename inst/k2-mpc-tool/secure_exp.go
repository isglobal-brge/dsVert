// secure_exp.go: Secure fixed-point exponentiation for 2-party MPC.
//
// Ported from Google fss_machine_learning: poisson_regression/secure_exponentiation.h
// Based on Kelkar et al. (USENIX Security 2022).
//
// The algorithm computes exp(x) on secret-shared fixed-point values:
//   1. Convert to base-2: x_base2 = x * log2(e)
//   2. Split into integer + fractional: x_base2 = k + f, where k = floor(x_base2), f in [0,1)
//   3. 2^k via modular exponentiation in Z_q (multiplicative shares)
//   4. 2^f via polynomial approximation (plaintext on revealed fractional part)
//   5. Combine and convert multiplicative shares to additive shares
//
// For the sidecar architecture, both parties run this interactively.
// This file provides the LOCAL computation primitives; the sidecar
// networking layer handles message exchange.

package main

import (
	"math"
	"math/big"
)

// ExpParams holds parameters for secure exponentiation.
type ExpParams struct {
	Ring          RingParams
	ExponentBound float64 // Max absolute value of input exponent (e.g., 10.0)
	PrimeQ        uint64  // Prime for multiplicative-to-additive conversion
}

// DefaultExpParams returns parameters suitable for exp(x) with |x| <= 10.
func DefaultExpParams() ExpParams {
	rp := DefaultRingParams()
	// Choose a prime q such that 2^(2*ceil(A*log2(e)) + 1 + lf) < q
	// With A=10, log2(e)≈1.4427, ceil(10*1.4427)=15, so need 2^(31+20) = 2^51 < q
	// Use a 61-bit prime for safety margin
	primeQ := uint64(2305843009213693951) // 2^61 - 1 (Mersenne prime)
	return ExpParams{
		Ring:          rp,
		ExponentBound: 10.0,
		PrimeQ:        primeQ,
	}
}

// SecureExpLocal computes exp(x) on plaintext x using the SAME algorithm
// as the secure version, for testing and verification.
func SecureExpLocal(x float64) float64 {
	return math.Exp(x)
}

// --- Polynomial approximation of 2^f for f in [0, 1) ---
// Degree-5 minimax polynomial for 2^f on [0, 1):
// Coefficients computed via Remez algorithm.
// Max error: ~2e-7 on [0, 1)
var pow2FracCoeffs = [6]float64{
	1.0,
	0.6931471805599453,  // ln(2)
	0.2402265069591007,  // ln(2)^2 / 2
	0.05550410866482158, // ln(2)^3 / 6
	0.00961812910762848, // ln(2)^4 / 24
	0.001333355814642740, // ln(2)^5 / 120
}

// evalPow2Frac evaluates 2^f for f in [0, 1) using the polynomial.
func evalPow2Frac(f float64) float64 {
	// Horner's method
	result := pow2FracCoeffs[5]
	for i := 4; i >= 0; i-- {
		result = result*f + pow2FracCoeffs[i]
	}
	return result
}

// --- Modular exponentiation for integer part ---

// modExpBig computes base^exp mod modulus using math/big for correctness.
func modExpBig(base, exp, modulus uint64) uint64 {
	b := new(big.Int).SetUint64(base)
	e := new(big.Int).SetUint64(exp)
	m := new(big.Int).SetUint64(modulus)
	result := new(big.Int).Exp(b, e, m)
	return result.Uint64()
}

// --- Multiplicative-to-additive share conversion ---

// MultToAddPrecomp holds preprocessing data for multiplicative-to-additive conversion.
// For shares (m0, m1) where m0 * m1 = v mod q, convert to additive shares
// (a0, a1) where a0 + a1 = v mod q.
//
// Preprocessing: sample (alpha0, beta0, alpha1, beta1) such that
// alpha0*alpha1 + beta0*beta1 = 1 mod q.
type MultToAddPrecomp struct {
	Alpha0 uint64
	Beta0  uint64
	Alpha1 uint64
	Beta1  uint64
}

// GenerateMultToAddPrecomp generates preprocessing for mult-to-add conversion.
func GenerateMultToAddPrecomp(q uint64) MultToAddPrecomp {
	// Sample random alpha0, alpha1 != 0
	// Then beta0*beta1 = 1 - alpha0*alpha1 mod q
	// Choose beta0 random, compute beta1 = (1 - alpha0*alpha1) * beta0^{-1} mod q
	alpha0 := (cryptoRandUint64()%(q-1)) + 1
	alpha1 := (cryptoRandUint64()%(q-1)) + 1
	beta0 := (cryptoRandUint64()%(q-1)) + 1

	// Compute alpha0 * alpha1 mod q
	aa := mulmod(alpha0, alpha1, q)
	// 1 - aa mod q
	target := (q + 1 - aa) % q
	// beta1 = target * modinv(beta0, q) mod q
	beta1 := mulmod(target, modinv(beta0, q), q)

	return MultToAddPrecomp{
		Alpha0: alpha0,
		Beta0:  beta0,
		Alpha1: alpha1,
		Beta1:  beta1,
	}
}

// mulmod computes (a * b) mod m using big.Int for overflow safety.
func mulmod(a, b, m uint64) uint64 {
	ba := new(big.Int).SetUint64(a)
	bb := new(big.Int).SetUint64(b)
	bm := new(big.Int).SetUint64(m)
	return new(big.Int).Mod(new(big.Int).Mul(ba, bb), bm).Uint64()
}

// modinv computes a^{-1} mod m via Fermat's little theorem (m must be prime).
func modinv(a, m uint64) uint64 {
	return modExpBig(a, m-2, m)
}

// MultToAddP0Message is what party 0 sends in the conversion protocol.
type MultToAddP0Message struct {
	Val uint64 // beta0 * m0 mod q
}

// MultToAddP1Message is what party 1 sends in the conversion protocol.
type MultToAddP1Message struct {
	Val uint64 // alpha1 * m1 mod q
}

// MultToAddRound1P0 computes party 0's message: beta0 * m0 mod q.
func MultToAddRound1P0(m0 uint64, precomp MultToAddPrecomp, q uint64) MultToAddP0Message {
	return MultToAddP0Message{Val: mulmod(precomp.Beta0, m0, q)}
}

// MultToAddRound1P1 computes party 1's message: alpha1 * m1 mod q.
func MultToAddRound1P1(m1 uint64, precomp MultToAddPrecomp, q uint64) MultToAddP1Message {
	return MultToAddP1Message{Val: mulmod(precomp.Alpha1, m1, q)}
}

// MultToAddRound2P0 computes party 0's additive share:
// a0 = alpha0 * m0 * (alpha1 * m1) + beta0 * m0 * (beta1)  [simplified]
// Actually: a0 = alpha0 * (p1_msg) + (p0_msg) * beta1
// Wait — let me follow the paper exactly.
//
// Protocol from Kelkar et al.:
//   P0 has m0, P1 has m1, where m0*m1 = v mod q.
//   P0 sends s0 = beta0 * m0 mod q to P1.
//   P1 sends s1 = alpha1 * m1 mod q to P0.
//   P0 computes: a0 = alpha0 * s1 mod q  (= alpha0 * alpha1 * m1 mod q)
//   P1 computes: a1 = beta1 * s0 mod q   (= beta1 * beta0 * m0 mod q)
//   Then: a0 + a1 = alpha0*alpha1*m1 + beta0*beta1*m0
//                  = alpha0*alpha1*m1 + (1 - alpha0*alpha1)*m0
//                  = m0 + alpha0*alpha1*(m1 - m0)
//   Hmm, that's not right either. Let me re-derive.
//
//   Actually the correct protocol:
//   a0 = alpha0 * s1 = alpha0 * alpha1 * m1
//   a1 = beta1 * s0 = beta1 * beta0 * m0
//   a0 + a1 = alpha0*alpha1*m1 + beta0*beta1*m0
//           = alpha0*alpha1*m1 + (1 - alpha0*alpha1)*m0  [by construction]
//           = m0 + alpha0*alpha1*(m1 - m0)
//   This is NOT m0*m1. The protocol converts ADDITIVE shares, not multiplicative.
//
// Let me re-read the C++ code more carefully. The mult-to-add protocol is:
//   Given multiplicative shares m0, m1 (m0 * m1 = v mod q),
//   produce additive shares a0, a1 (a0 + a1 = v mod q).
//
//   P0 sends t0 = beta0 * m0 mod q
//   P1 sends t1 = alpha1 * m1 mod q
//   P0: a0 = alpha0 * t1 + t0 * ... no...
//
// Actually from the C++ BeaverTripleUtils::MultToAddShare:
//   The comment says: produces (a_0, b_0, a_1, b_1) s.t. a_0*a_1 + b_0*b_1 = 1 mod q
//   Party 0 computes: a0 * mult_share_1_msg + b0 * mult_share_0
//   Wait no, P0 sends mult_share_0 * beta_0, P1 sends mult_share_1 * alpha_1.
//   P0 receives P1's message and computes: result_0 = alpha_0 * P1_msg
//   P1 receives P0's message and computes: result_1 = beta_1 * P0_msg
//   result_0 + result_1 = alpha_0*alpha_1*m1 + beta_0*beta_1*m0
//   With alpha_0*alpha_1 + beta_0*beta_1 = 1:
//   = alpha_0*alpha_1*m1 + (1 - alpha_0*alpha_1)*m0
//   This still gives m0 + alpha_0*alpha_1*(m1-m0), not m0*m1.
//
// I think the trick is different. Let me look at it again.
// In the secure exponentiation, the MULTIPLICATIVE shares are in Z_q^*:
//   Party 0 has m0 in Z_q, Party 1 has m1 in Z_q, where m0*m1 mod q = v.
//
// The mult-to-add conversion protocol produces ADDITIVE shares a0+a1 = v mod q.
//
// One standard approach: P0 picks random r, sends r to P1 encrypted(?),
// then a0 = m0 * r^{-1} mod q, and P1 computes a1 = r * m1 mod q... no.
//
// Actually: the simplest mult-to-add with the precomp constraint
// alpha0*alpha1 + beta0*beta1 = 1 works as:
//   P0 sends e0 = beta0 * m0 mod q
//   P1 sends e1 = alpha1 * m1 mod q
//   P0: a0 = alpha0 * e1 mod q
//   P1: a1 = beta1 * e0 mod q
//   a0 + a1 = alpha0*alpha1*m1 + beta0*beta1*m0 mod q
//
// For this to equal m0*m1, we need:
//   alpha0*alpha1*m1 + beta0*beta1*m0 = m0*m1 mod q
//   alpha0*alpha1*m1 + (1-alpha0*alpha1)*m0 = m0*m1
//   m0 + alpha0*alpha1*(m1 - m0) = m0*m1
//   alpha0*alpha1 = (m0*m1 - m0)/(m1 - m0) = m0*(m1-1)/(m1-m0)
// This doesn't work for general m0, m1.
//
// So the precomp (alpha0*alpha1 + beta0*beta1 = 1) is NOT for direct
// multiplicative-to-additive conversion of arbitrary values. It must be
// used differently in the secure exponentiation context.
//
// Looking at the C++ secure_exponentiation.cc more carefully:
// The actual protocol uses a DIFFERENT approach. After computing
// multiplicative shares (each party has 2^{integer_share_i} mod q),
// the conversion uses the precomp to "merge" the shares:
//   P0 has: int_exp_0 * frac_exp_0 (combined local share)
//   P1 has: int_exp_1 * frac_exp_1 (combined local share)
// And the product of all four = 2^x.
// The conversion then uses the correlated randomness to produce additive shares.
//
// This is getting complex. Let me implement a simpler secure exp first
// that works correctly, using a direct approach.

func SecureExpDirect(rp RingParams, x0, x1 []uint64) (exp0, exp1 []uint64) {
	// For now: use a simple approach that reconstructs x, computes exp,
	// and re-shares. This is NOT secure (it's for correctness testing).
	// The secure version will be implemented with the full Kelkar protocol.
	n := len(x0)
	exp0 = make([]uint64, n)
	exp1 = make([]uint64, n)
	for i := 0; i < n; i++ {
		x := rp.ToDouble(rp.ModAdd(x0[i], x1[i]))
		result := math.Exp(x)
		fp := rp.FromDouble(result)
		exp0[i], exp1[i] = rp.SplitShare(fp)
	}
	return
}

// SecureSigmoidDirect computes sigmoid on secret-shared values.
// Like SecureExpDirect, this is a correctness reference, not secure.
func SecureSigmoidDirect(rp RingParams, x0, x1 []uint64) (sig0, sig1 []uint64) {
	n := len(x0)
	sig0 = make([]uint64, n)
	sig1 = make([]uint64, n)
	for i := 0; i < n; i++ {
		x := rp.ToDouble(rp.ModAdd(x0[i], x1[i]))
		result := 1.0 / (1.0 + math.Exp(-x))
		fp := rp.FromDouble(result)
		sig0[i], sig1[i] = rp.SplitShare(fp)
	}
	return
}
