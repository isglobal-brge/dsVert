// k2_distributed_cmp.go: masked DCF comparison building block.
//
// Port from k2-mpc-tool/distributed_comparison.go, adapted to Ring63. This
// historical construction is not a promotion-safe comparison protocol by
// itself: its mask is uniform over only one quarter of the ring, so opening
// the masked value leaks coarse range information, and the comparison is
// wrong when the masked input and masked threshold wrap differently. A
// server-proven interior-domain contract can address correctness but not the
// range leakage. See the counterexamples in k2_numeric_validation_test.go.
//
// Protocol:
//   Preprocessing (dealer): Generate DCF keys + random masks for [x < threshold]
//   Round 1: Each party computes masked_share = share + mask_share, sends to peer
//   Round 2: Each party reconstructs masked value, evaluates DCF → arithmetic share
//
// The DCF output is an ARITHMETIC share in Ring63 (not a mod-2 bit). Its
// reconstruction is the exact DCF predicate on the masked values; it equals
// the intended signed comparison only when the no-differential-wrap
// precondition holds.

package main

// CmpPreprocessPerParty holds one party's preprocessing for comparisons.
type CmpPreprocessPerParty struct {
	Keys      []DCFKey // One DCF key per element
	MaskShare []uint64 // Party's share of random mask
}

// CmpMaskedValues is the round 1 message: masked eta values for each comparison.
type CmpMaskedValues struct {
	Values []uint64 // n values: share + mask_share (mod Modulus)
}

// CmpArithResult holds arithmetic shares of comparison results.
type CmpArithResult struct {
	Shares []uint64 // n values: party's Ring63 share (sum = 0 or 1)
}

// cmpGeneratePreprocess creates preprocessing for n elements, one threshold.
// Uses Ring63 from dsvert-mpc. The threshold is in Ring63 representation.
// To handle signed values, party 0 adds SignThreshold in round 1.
func cmpGeneratePreprocess(ring Ring63, n int, threshold uint64) (CmpPreprocessPerParty, CmpPreprocessPerParty) {
	mod := ring.Modulus
	maskRange := mod / 4

	// Shift threshold for unsigned comparison
	threshShifted := ring.Add(threshold, ring.SignThreshold)

	p0 := CmpPreprocessPerParty{
		Keys:      make([]DCFKey, n),
		MaskShare: make([]uint64, n),
	}
	p1 := CmpPreprocessPerParty{
		Keys:      make([]DCFKey, n),
		MaskShare: make([]uint64, n),
	}

	numBits := 63 // Ring63

	for i := 0; i < n; i++ {
		r := cryptoRandUint64K2() % maskRange
		r0 := cryptoRandUint64K2() % mod
		r1 := ring.Sub(r, r0)

		alpha := ring.Add(threshShifted, r)
		key0, key1 := DCFGen(alpha, 1, numBits)

		p0.Keys[i] = key0
		p0.MaskShare[i] = r0
		p1.Keys[i] = key1
		p1.MaskShare[i] = r1
	}

	return p0, p1
}

// cmpRound1 computes the masked value for each element.
// partyID 0 adds SignThreshold to shift signed → unsigned.
func cmpRound1(ring Ring63, partyID int, etaShare []uint64, preproc CmpPreprocessPerParty) CmpMaskedValues {
	n := len(etaShare)
	msg := CmpMaskedValues{Values: make([]uint64, n)}

	for i := 0; i < n; i++ {
		shifted := etaShare[i]
		if partyID == 0 {
			shifted = ring.Add(etaShare[i], ring.SignThreshold)
		}
		msg.Values[i] = ring.Add(shifted, preproc.MaskShare[i])
	}
	return msg
}

// cmpRound2 evaluates DCF and returns arithmetic Ring63 shares.
func cmpRound2(ring Ring63, partyID int, preproc CmpPreprocessPerParty, ownMsg, peerMsg CmpMaskedValues) CmpArithResult {
	n := len(ownMsg.Values)
	result := CmpArithResult{Shares: make([]uint64, n)}

	for i := 0; i < n; i++ {
		m := ring.Add(ownMsg.Values[i], peerMsg.Values[i])
		v := DCFEval(partyID, preproc.Keys[i], m)
		result.Shares[i] = uint64(v) % ring.Modulus
	}
	return result
}
