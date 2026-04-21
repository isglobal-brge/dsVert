// k2_distributed_cmp_ring127.go — Ring127 parallel of k2_distributed_cmp.go.
//
// Distributed secure comparison over Ring127: preprocessing (dealer),
// round 1 (share + mask), round 2 (DCF eval). All arithmetic is Uint128
// at modulus 2^127. Reuses DCFKey127/DCFGen127/DCFEval127 from
// k2_dcf_ring127.go.
//
// Output is an arithmetic share in Ring127: share0 + share1 (mod 2^127)
// is 0 or 1 (exact, not an approximation).
//
// Protocol (same structure as Ring63):
//   Preprocess: dealer draws r ∈ [0, 2^125), splits it as (r0, r1). Computes
//     alpha := (threshold + SignThreshold) + r (mod 2^127). Generates DCF
//     keys for f(x) = 1 if x < alpha, else 0.
//   Round 1 (per party): masked_share_i := eta_share_i + (partyID==0 ?
//     SignThreshold : 0) + r_i_share.
//   Round 2: m := own_masked + peer_masked. share := DCFEval127(partyID, key, m).
//
// SafeMax headroom: modulus/4 = 2^125 (2 bits of safety, matching Ring63's
// 2^61 = modulus/4). Keeps eta_shifted + r from wrapping in a way that
// corrupts the comparison.

package main

// CmpPreprocessPerParty127 is the Ring127 parallel of CmpPreprocessPerParty.
type CmpPreprocessPerParty127 struct {
	Keys      []DCFKey127
	MaskShare []Uint128
}

// CmpMaskedValues127 is the Ring127 round 1 message.
type CmpMaskedValues127 struct {
	Values []Uint128
}

// CmpArithResult127 holds arithmetic Ring127 shares of comparison results.
type CmpArithResult127 struct {
	Shares []Uint128
}

// cmpGenMaskHiBits127: safeMax = 2^125 means r.Hi ∈ [0, 2^61), i.e. mask
// Hi with (1<<61)-1 and keep Lo unconstrained.
const cmpGenMaskHiBits127 uint64 = (uint64(1) << 61) - 1

// cmpGeneratePreprocess127 creates preprocessing for n Ring127 comparisons
// against a single threshold. Mirrors cmpGeneratePreprocess structure.
func cmpGeneratePreprocess127(ring Ring127, n int, threshold Uint128) (CmpPreprocessPerParty127, CmpPreprocessPerParty127) {
	threshShifted := ring.Add(threshold, ring.SignThreshold)

	p0 := CmpPreprocessPerParty127{
		Keys:      make([]DCFKey127, n),
		MaskShare: make([]Uint128, n),
	}
	p1 := CmpPreprocessPerParty127{
		Keys:      make([]DCFKey127, n),
		MaskShare: make([]Uint128, n),
	}

	numBits := 127 // Ring127 domain
	beta := Uint128{Lo: 1}

	for i := 0; i < n; i++ {
		// r ∈ [0, 2^125) via Hi-bit restriction.
		r := cryptoRandUint128()
		r.Hi &= cmpGenMaskHiBits127

		// r0 uniform on Ring127 ([0, 2^127)); r1 = r - r0 mod 2^127.
		r0 := cryptoRandUint128().ModPow127()
		r1 := ring.Sub(r, r0)

		alpha := ring.Add(threshShifted, r)
		key0, key1 := DCFGen127(alpha, beta, numBits)

		p0.Keys[i] = key0
		p0.MaskShare[i] = r0
		p1.Keys[i] = key1
		p1.MaskShare[i] = r1
	}

	return p0, p1
}

// cmpRound1_127 computes the masked value for each element.
// partyID 0 adds SignThreshold to shift signed → unsigned (same convention
// as Ring63 cmpRound1).
func cmpRound1_127(ring Ring127, partyID int, etaShare []Uint128, preproc CmpPreprocessPerParty127) CmpMaskedValues127 {
	n := len(etaShare)
	msg := CmpMaskedValues127{Values: make([]Uint128, n)}

	for i := 0; i < n; i++ {
		shifted := etaShare[i]
		if partyID == 0 {
			shifted = ring.Add(etaShare[i], ring.SignThreshold)
		}
		msg.Values[i] = ring.Add(shifted, preproc.MaskShare[i])
	}
	return msg
}

// cmpRound2_127 evaluates DCF and returns arithmetic Ring127 shares.
// share0 + share1 (mod 2^127) == 1 iff original eta < threshold, else 0.
func cmpRound2_127(ring Ring127, partyID int, preproc CmpPreprocessPerParty127, ownMsg, peerMsg CmpMaskedValues127) CmpArithResult127 {
	n := len(ownMsg.Values)
	result := CmpArithResult127{Shares: make([]Uint128, n)}

	for i := 0; i < n; i++ {
		m := ring.Add(ownMsg.Values[i], peerMsg.Values[i])
		v := DCFEval127(partyID, preproc.Keys[i], m)
		result.Shares[i] = v.ModPow127()
	}
	return result
}
