// k2_beaver_google_ring127_ops.go — Ring127 parallel of the Beaver op helpers
// beyond the basic Gate/Output exchanges shipped in step 1.
//
// Provides:
//   - TruncateSharePartyZero127 / TruncateSharePartyOne127 : integer-division
//     truncation in Ring127 (2^127 modulus). Parallel of the uint64 pair in
//     k2_beaver_google.go. Equivalent to "divide share by 2^fracBits" with
//     the P1 sign-flip trick that recovers the true FP value under additive
//     sharing with at most ±1 ULP bias (the Google C++ SecureML formula).
//   - HadamardProductPartyZero127 / HadamardProductPartyOne127 : combines
//     GenerateBatchedMultiplicationOutputPartyZero/One127 with the truncation
//     above. Input shares at fracBits, output shares at fracBits (not
//     2*fracBits).
//   - ScalarVectorProductPartyZero127 / ScalarVectorProductPartyOne127 :
//     multiplies a plaintext public scalar by Uint128 shares with the same
//     (a·b - a·mod)/2^lf formula used by Ring63. The intermediate product
//     (scalar × share - scalar × 2^127) is a signed ~256-bit quantity, so
//     big.Int is used for correctness; the scalar-times-vector is typically
//     outside the per-element hot loop so the allocation cost is tolerable.

package main

import (
	"math/big"
)

// TruncateSharePartyZero127 truncates P0's Uint128 share by 2^fracBits.
// result[i] = (s / 2^fracBits) mod 2^127, where `/` is unsigned integer
// division (= right shift for unsigned values).
func TruncateSharePartyZero127(shares []Uint128, fracBits int, r Ring127) []Uint128 {
	result := make([]Uint128, len(shares))
	for i, s := range shares {
		result[i] = s.Shr(uint(fracBits)).ModPow127()
	}
	return result
}

// TruncateSharePartyOne127 truncates P1's Uint128 share by 2^fracBits.
// Ring127 analogue of TruncateSharePartyOne:
//   negS = modulus - s              (= -s mod 2^127)
//   result = modulus - (negS / 2^fracBits)
// The s==0 special case is preserved to avoid the 2^127 artifact.
func TruncateSharePartyOne127(shares []Uint128, fracBits int, r Ring127) []Uint128 {
	result := make([]Uint128, len(shares))
	zero := Uint128{}
	for i, s := range shares {
		if s.Cmp(zero) == 0 {
			result[i] = zero
			continue
		}
		negS := r.Neg(s)
		result[i] = r.Neg(negS.Shr(uint(fracBits)))
	}
	return result
}

// HadamardProductPartyZero127 = Beaver round 2 (P0) + FP truncation.
// Input x-shares and y-shares at fracBits → output shares at fracBits.
func HadamardProductPartyZero127(
	state BatchedMultState127,
	beaver BeaverTripleVec127,
	otherMsg MultGateMessage127,
	fracBits int,
	r Ring127,
) []Uint128 {
	raw := GenerateBatchedMultiplicationOutputPartyZero127(state, beaver, otherMsg, r)
	return TruncateSharePartyZero127(raw, fracBits, r)
}

// HadamardProductPartyOne127 = Beaver round 2 (P1) + FP truncation.
func HadamardProductPartyOne127(
	state BatchedMultState127,
	beaver BeaverTripleVec127,
	otherMsg MultGateMessage127,
	fracBits int,
	r Ring127,
) []Uint128 {
	raw := GenerateBatchedMultiplicationOutputPartyOne127(state, beaver, otherMsg, r)
	return TruncateSharePartyOne127(raw, fracBits, r)
}

// --- Big.Int helpers for ScalarVectorProduct127 ---

// u128ToBigSigned interprets a Uint128 as a signed value in [-2^126, 2^126)
// via two's complement around 2^127.
func u128ToBigSigned(v Uint128, signThreshold Uint128) *big.Int {
	b := v.ToBig()
	if v.Cmp(signThreshold) >= 0 {
		// negative: b - 2^127
		modBig := new(big.Int).Lsh(big.NewInt(1), 127)
		b.Sub(b, modBig)
	}
	return b
}

// bigSignedToU128Mod reduces a signed big.Int to Uint128 mod 2^127.
func bigSignedToU128Mod(b *big.Int) Uint128 {
	modBig := new(big.Int).Lsh(big.NewInt(1), 127)
	r := new(big.Int).Mod(b, modBig)
	if r.Sign() < 0 {
		r.Add(r, modBig)
	}
	return U128FromBig(r)
}

// ScalarVectorProductPartyZero127 multiplies a public float64 scalar by P0's
// Uint128 share vector. Mirrors ScalarVectorProductPartyZero structurally but
// uses big.Int for the ~256-bit intermediate (scalar × share - scalar × 2^127).
//
// result[i] = floor((ringA · share[i] - ringA · 2^127) / 2^fracBits) mod 2^127
// with sign flip if the input scalarA was negative.
func ScalarVectorProductPartyZero127(scalarA float64, vectorB []Uint128, r Ring127) []Uint128 {
	negative := scalarA < 0
	if negative {
		scalarA = -scalarA
	}

	ringA := r.FromDouble(scalarA)
	result := make([]Uint128, len(vectorB))

	aBig := ringA.ToBig()
	modBig := new(big.Int).Lsh(big.NewInt(1), 127)
	aTimesMod := new(big.Int).Mul(aBig, modBig)
	fracShift := new(big.Int).Lsh(big.NewInt(1), uint(r.FracBits))

	zero := Uint128{}
	for i, b := range vectorB {
		// Guard: share == 0 → product is 0 (avoids the ab - a*mod negative
		// artifact when the share pair doesn't need a wrap-around).
		if b.Cmp(zero) == 0 {
			result[i] = zero
			continue
		}
		ab := new(big.Int).Mul(aBig, b.ToBig())
		ab.Sub(ab, aTimesMod)
		ab.Div(ab, fracShift) // big.Int Div truncates toward zero
		ab.Mod(ab, modBig)
		if ab.Sign() < 0 {
			ab.Add(ab, modBig)
		}
		result[i] = U128FromBig(ab)
	}

	if negative {
		for i := range result {
			result[i] = r.Neg(result[i])
		}
	}

	return result
}

// ScalarVectorProductPartyOne127 multiplies a public float64 scalar by P1's
// Uint128 share vector. Uses Ring127.TruncMul (which already does
// (a·b) >> fracBits mod 2^127 via big.Int internally).
func ScalarVectorProductPartyOne127(scalarA float64, vectorB []Uint128, r Ring127) []Uint128 {
	negative := scalarA < 0
	if negative {
		scalarA = -scalarA
	}

	ringA := r.FromDouble(scalarA)
	result := make([]Uint128, len(vectorB))

	for i, b := range vectorB {
		result[i] = r.TruncMul(ringA, b)
	}

	if negative {
		for i := range result {
			result[i] = r.Neg(result[i])
		}
	}

	return result
}
