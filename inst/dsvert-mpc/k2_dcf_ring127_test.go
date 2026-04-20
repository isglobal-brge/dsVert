// k2_dcf_ring127_test.go — end-to-end correctness tests for Ring127 DCF.
//
// DCF is EXACT arithmetic over Z_{2^128}: share0 + share1 (mod 2^128) equals
// beta if x < alpha, else 0 — with zero error. So the tests assert exact
// equality (rel err = 0), far below the <1e-10 bar set in P1 step 2 criteria.
package main

import (
	"math/rand"
	"testing"
)

// TestDCFRing127_Small_Exhaustive: exhaustive over a small domain to catch
// structural bugs (sign handling, Keep/Lose, bit extraction). numBits=6 gives
// 64 x values per (alpha, beta); 5 random seeds = 320 x values per seed.
func TestDCFRing127_Small_Exhaustive(t *testing.T) {
	numBits := 6
	domain := uint64(1) << numBits
	seeds := []int64{1, 2, 3, 4, 5}

	for _, s := range seeds {
		rng := rand.New(rand.NewSource(s))
		alpha := Uint128{Lo: uint64(rng.Intn(int(domain)))}
		beta := Uint128{
			Hi: rng.Uint64(),
			Lo: rng.Uint64(),
		}
		key0, key1 := DCFGen127(alpha, beta, numBits)

		for x := uint64(0); x < domain; x++ {
			xU := Uint128{Lo: x}
			v0 := DCFEval127(0, key0, xU)
			v1 := DCFEval127(1, key1, xU)
			sum := v0.Add(v1)

			var expected Uint128
			if x < alpha.Lo {
				expected = beta
			}
			if sum.Cmp(expected) != 0 {
				t.Fatalf("seed=%d x=%d alpha=%d beta={%x,%x}: sum={%x,%x} expected={%x,%x}",
					s, x, alpha.Lo, beta.Hi, beta.Lo, sum.Hi, sum.Lo, expected.Hi, expected.Lo)
			}
		}
	}
}

// TestDCFRing127_MidDomain: numBits=16 so alpha crosses the 8-bit byte
// boundary. 4 random (alpha, beta) pairs × 500 sampled x = 2000 checks.
func TestDCFRing127_MidDomain(t *testing.T) {
	numBits := 16
	domain := uint64(1) << numBits
	rng := rand.New(rand.NewSource(77))

	for trial := 0; trial < 4; trial++ {
		alpha := Uint128{Lo: uint64(rng.Intn(int(domain)))}
		beta := Uint128{
			Hi: rng.Uint64(),
			Lo: rng.Uint64(),
		}
		key0, key1 := DCFGen127(alpha, beta, numBits)

		for k := 0; k < 500; k++ {
			x := uint64(rng.Intn(int(domain)))
			xU := Uint128{Lo: x}
			v0 := DCFEval127(0, key0, xU)
			v1 := DCFEval127(1, key1, xU)
			sum := v0.Add(v1)

			var expected Uint128
			if x < alpha.Lo {
				expected = beta
			}
			if sum.Cmp(expected) != 0 {
				t.Fatalf("trial=%d x=%d alpha=%d: sum={%x,%x} expected={%x,%x}",
					trial, x, alpha.Lo, sum.Hi, sum.Lo, expected.Hi, expected.Lo)
			}
		}
	}
}

// TestDCFRing127_FullDomain: numBits=127 (full Ring127 domain), exercising
// the Hi-word bit extraction path in getBit128 and full 128-bit Uint128 arithmetic
// in vCW / FinalCW / vAlpha. 3 trials × 200 random x = 600 checks.
func TestDCFRing127_FullDomain(t *testing.T) {
	numBits := 127
	// Mask keeps the top bit clear so values remain in [0, 2^127).
	maskHi := (uint64(1) << 63) - 1

	rng := rand.New(rand.NewSource(12345))

	for trial := 0; trial < 3; trial++ {
		alpha := Uint128{
			Hi: rng.Uint64() & maskHi,
			Lo: rng.Uint64(),
		}
		beta := Uint128{
			Hi: rng.Uint64(),
			Lo: rng.Uint64(),
		}
		key0, key1 := DCFGen127(alpha, beta, numBits)

		for k := 0; k < 200; k++ {
			x := Uint128{
				Hi: rng.Uint64() & maskHi,
				Lo: rng.Uint64(),
			}
			v0 := DCFEval127(0, key0, x)
			v1 := DCFEval127(1, key1, x)
			sum := v0.Add(v1)

			var expected Uint128
			if x.Cmp(alpha) < 0 {
				expected = beta
			}
			if sum.Cmp(expected) != 0 {
				t.Fatalf("trial=%d k=%d x<alpha=%v: sum={%x,%x} expected={%x,%x}",
					trial, k, x.Cmp(alpha) < 0, sum.Hi, sum.Lo, expected.Hi, expected.Lo)
			}
		}
	}
}

// TestDCFRing127_EdgeAlphaZero: alpha = 0 means "no x triggers beta".
func TestDCFRing127_EdgeAlphaZero(t *testing.T) {
	numBits := 127
	beta := Uint128{Hi: 0xDEAD, Lo: 0xBEEF}
	key0, key1 := DCFGen127(Uint128{}, beta, numBits)
	testInputs := []Uint128{
		{},                         // x = 0
		{Lo: 1},                    // x = 1
		{Hi: 1},                    // x crosses into Hi
		{Hi: (uint64(1) << 63) - 1, Lo: ^uint64(0)}, // max in [0, 2^127)
	}
	for _, x := range testInputs {
		v0 := DCFEval127(0, key0, x)
		v1 := DCFEval127(1, key1, x)
		sum := v0.Add(v1)
		if sum.Cmp(Uint128{}) != 0 {
			t.Fatalf("alpha=0 x={%x,%x}: expected 0, got {%x,%x}",
				x.Hi, x.Lo, sum.Hi, sum.Lo)
		}
	}
}

// TestDCFRing127_BetaWraps: beta with high bit set exercises the two's-complement
// wrap semantics of Uint128 sum (Add wraps at 2^128).
func TestDCFRing127_BetaWraps(t *testing.T) {
	numBits := 127
	alpha := Uint128{Lo: 100}
	beta := Uint128{Hi: ^uint64(0), Lo: ^uint64(0)} // "-1" in two's complement

	key0, key1 := DCFGen127(alpha, beta, numBits)

	// x < alpha → sum == beta (-1). x >= alpha → sum == 0.
	for _, tc := range []struct {
		x      Uint128
		belows bool
	}{
		{Uint128{Lo: 0}, true},
		{Uint128{Lo: 50}, true},
		{Uint128{Lo: 99}, true},
		{Uint128{Lo: 100}, false},
		{Uint128{Lo: 101}, false},
		{Uint128{Hi: 1}, false},
	} {
		v0 := DCFEval127(0, key0, tc.x)
		v1 := DCFEval127(1, key1, tc.x)
		sum := v0.Add(v1)

		var expected Uint128
		if tc.belows {
			expected = beta
		}
		if sum.Cmp(expected) != 0 {
			t.Fatalf("x={%x,%x} below=%v: sum={%x,%x} expected={%x,%x}",
				tc.x.Hi, tc.x.Lo, tc.belows, sum.Hi, sum.Lo, expected.Hi, expected.Lo)
		}
	}
}

// TestDCFRing127_ShareIndistinguishability: individual shares should look
// pseudo-random (no trivial leakage). We sample 100 (alpha, beta, x) tuples
// and confirm neither share equals the plaintext output — a sanity check
// that FSS isn't trivially degenerate.
func TestDCFRing127_ShareIndistinguishability(t *testing.T) {
	numBits := 127
	rng := rand.New(rand.NewSource(9999))
	maskHi := (uint64(1) << 63) - 1

	for k := 0; k < 100; k++ {
		alpha := Uint128{Hi: rng.Uint64() & maskHi, Lo: rng.Uint64()}
		beta := Uint128{Hi: rng.Uint64(), Lo: rng.Uint64()}
		x := Uint128{Hi: rng.Uint64() & maskHi, Lo: rng.Uint64()}

		key0, key1 := DCFGen127(alpha, beta, numBits)
		v0 := DCFEval127(0, key0, x)
		v1 := DCFEval127(1, key1, x)

		// Shares should not equal the plaintext output (beta or 0).
		// Probability of coincidental equality is ~2·2^-128 per pair; with 100
		// trials, we'd need astronomic bad luck to trip this.
		var plain Uint128
		if x.Cmp(alpha) < 0 {
			plain = beta
		}
		if v0.Cmp(plain) == 0 && v1.Cmp(Uint128{}) == 0 {
			t.Fatalf("k=%d: share0 == plain and share1 == 0 (trivial FSS)", k)
		}
		if v1.Cmp(plain) == 0 && v0.Cmp(Uint128{}) == 0 {
			t.Fatalf("k=%d: share1 == plain and share0 == 0 (trivial FSS)", k)
		}
	}
}
