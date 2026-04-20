// k2_spline_protocol_ring127.go — Ring127 parallel of the 4-phase wide
// spline evaluation in k2_spline_protocol.go.
//
// Structurally identical to the Ring63 path but operates on Uint128 shares
// throughout: eta, DCF keys, Beaver triples, peer R1 messages, and the
// output mu share are all serialized at 16 bytes/element.
//
// Phase 1 : DCF round-1 masked values (one per threshold per element)
// Phase 2 : DCF round-2 close + indicator rebuild + Beaver R1 for AND + Had1
// Phase 3 : AND + Had1 round-2 close → I_mid, slope·x → Beaver R1 for Had2
// Phase 4 : Had2 close + assembly (mu = I_low·satLow + I_high·satHigh + I_mid·spline)
//
// The Ring63 handleK2WideSplineFullEval dispatches to this module when
// input.Ring == "ring127". The Ring63 path remains unchanged.

package main

import (
	"encoding/binary"
	"fmt"
	"math"
)

// wsComputeIndicators127: Ring127 parallel of wsComputeIndicators. Same
// outputs, same semantics; Uint128 arithmetic throughout.
func wsComputeIndicators127(
	ring Ring127, n, numInt, numThresh, partyID int,
	etaShare []Uint128, dcfKeys []CmpPreprocessPerParty127, peerMaskedBuf []byte,
	family string, lower, upper float64,
) (notCLowFP, cHighFP, iLow, iHigh, aSlope, bInt, etaR127 []Uint128) {

	// DCF close: combine own Round1 with peer's to evaluate DCF at the
	// combined masked value.
	peerMasked := bytesToUint128Vec(peerMaskedBuf)

	ownMasked := make([]Uint128, numThresh*n)
	for t := 0; t < numThresh; t++ {
		msg := cmpRound1_127(ring, partyID, etaShare, dcfKeys[t])
		copy(ownMasked[t*n:], msg.Values)
	}

	allCmp := make([]Uint128, numThresh*n)
	for t := 0; t < numThresh; t++ {
		ownMsg := CmpMaskedValues127{Values: ownMasked[t*n : (t+1)*n]}
		peerMsg := CmpMaskedValues127{Values: peerMasked[t*n : (t+1)*n]}
		result := cmpRound2_127(ring, partyID, dcfKeys[t], ownMsg, peerMsg)
		copy(allCmp[t*n:], result.Shares)
	}

	cLow := allCmp[0:n]
	cHigh := allCmp[n : 2*n]

	// Sub-indicator shares (numInt elements derived from numInt-1 comparisons).
	subCmp := make([][]Uint128, numInt-1)
	for j := 0; j < numInt-1; j++ {
		subCmp[j] = allCmp[(2+j)*n : (3+j)*n]
	}
	subInd := make([][]Uint128, numInt)
	for k := 0; k < numInt; k++ {
		subInd[k] = make([]Uint128, n)
	}
	one := Uint128{Lo: 1}
	zero := Uint128{}
	for i := 0; i < n; i++ {
		subInd[0][i] = subCmp[0][i]
		for j := 1; j < numInt-1; j++ {
			subInd[j][i] = ring.Sub(subCmp[j][i], subCmp[j-1][i])
		}
		if partyID == 0 {
			subInd[numInt-1][i] = ring.Sub(one, subCmp[numInt-2][i])
		} else {
			subInd[numInt-1][i] = ring.Sub(zero, subCmp[numInt-2][i])
		}
	}
	// Scale {0,1}-shares to {0, 2^fracBits}-shares via left-shift.
	for k := 0; k < numInt; k++ {
		for i := 0; i < n; i++ {
			subInd[k][i] = subInd[k][i].Shl(uint(ring.FracBits)).ModPow127()
		}
	}

	// Spline slopes/intercepts (public; same float64 values as Ring63 path).
	var slopes, intercepts []float64
	var satLow float64 = 0.0
	var satHigh float64 = 1.0
	switch family {
	case "poisson":
		slopes, intercepts, _, _ = WideExpParams(numInt)
		satHigh = math.Exp(8.0)
	case "softplus":
		slopes, intercepts, _ = WideSoftplusParams(numInt)
		satHigh = math.Log(1.0 + math.Exp(8.0))
	case "reciprocal":
		if lower <= 0 {
			lower = K2ReciprocalLower
		}
		if upper <= 0 {
			upper = K2ReciprocalUpper
		}
		slopes, intercepts, _ = WideReciprocalParamsWithRange(numInt, lower, upper)
		satLow = 1.0 / lower
		satHigh = 1.0 / upper
	case "log":
		if lower <= 0 {
			lower = K2LogLower
		}
		if upper <= 0 {
			upper = K2LogUpper
		}
		slopes, intercepts, _ = WideLogParamsWithRange(numInt, lower, upper)
		satLow = math.Log(lower)
		satHigh = math.Log(upper)
	default:
		slopes, intercepts, _ = WideSigmoidParams(numInt)
		satHigh = 1.0
	}

	// Scalar × vector accumulators for slope and intercept (weighted by subInd).
	aSlope = make([]Uint128, n)
	bInt = make([]Uint128, n)
	for j := 0; j < numInt; j++ {
		var sv, bi []Uint128
		if partyID == 0 {
			sv = ScalarVectorProductPartyZero127(slopes[j], subInd[j], ring)
			bi = ScalarVectorProductPartyZero127(intercepts[j], subInd[j], ring)
		} else {
			sv = ScalarVectorProductPartyOne127(slopes[j], subInd[j], ring)
			bi = ScalarVectorProductPartyOne127(intercepts[j], subInd[j], ring)
		}
		for i := 0; i < n; i++ {
			aSlope[i] = ring.Add(aSlope[i], sv[i])
			bInt[i] = ring.Add(bInt[i], bi[i])
		}
	}

	// FP-scaled indicators for Beaver Hadamard / final assembly.
	iHigh = make([]Uint128, n)
	iLow = make([]Uint128, n)
	notCLowFP = make([]Uint128, n)
	cHighFP = make([]Uint128, n)
	satLowFP := ring.FromDouble(satLow)
	satHighFP := ring.FromDouble(satHigh)
	fracMul := ring.FracMul
	for i := 0; i < n; i++ {
		var notCH, notCL Uint128
		if partyID == 0 {
			notCH = ring.Sub(one, cHigh[i])
			notCL = ring.Sub(one, cLow[i])
		} else {
			notCH = ring.Sub(zero, cHigh[i])
			notCL = ring.Sub(zero, cLow[i])
		}
		iHigh[i] = notCH.Mul(satHighFP).ModPow127()
		iLow[i] = cLow[i].Mul(satLowFP).ModPow127()
		notCLowFP[i] = notCL.Mul(fracMul).ModPow127()
		cHighFP[i] = cHigh[i].Mul(fracMul).ModPow127()
	}
	etaR127 = etaShare
	return
}

// handleK2WideSplineFullEval127 implements phases 1-4 for the Ring127 path.
// Called from handleK2WideSplineFullEval when input.Ring == "ring127".
func handleK2WideSplineFullEval127(input K2WideSplineFullInput) {
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}

	ring := NewRing127(input.FracBits)
	n := input.N
	numInt := input.NumIntervals
	if numInt <= 0 {
		switch input.Family {
		case "poisson":
			numInt = K2ExpIntervals
		case "softplus":
			numInt = 80
		default:
			numInt = K2SigmoidIntervals
		}
	}
	numThresh := 2 + numInt - 1

	etaBytes := base64ToBytes(input.EtaShareFP)
	if len(etaBytes) == 0 {
		outputError(fmt.Sprintf("k2-wide-spline-full (ring127): eta empty (n=%d, b64len=%d)", n, len(input.EtaShareFP)))
		return
	}
	etaShare := bytesToUint128Vec(etaBytes)
	dcfKeys := deserializeDcfBatch127(base64ToBytes(input.DcfKeys), n, numThresh)

	switch input.Phase {
	case 1:
		// Phase 1: DCF round-1 masked values only.
		allMasked := make([]Uint128, numThresh*n)
		for t := 0; t < numThresh; t++ {
			msg := cmpRound1_127(ring, input.PartyID, etaShare, dcfKeys[t])
			copy(allMasked[t*n:], msg.Values)
		}
		mpcWriteOutput(K2WSPhase1Out{DcfMasked: bytesToBase64(uint128VecToBytes(allMasked))})

	case 2:
		// Phase 2: DCF close + indicators + Beaver R1 for AND + Had1.
		notCLowFP, cHighFP, _, _, aSlope, _, eta := wsComputeIndicators127(
			ring, n, numInt, numThresh, input.PartyID,
			etaShare, dcfKeys, base64ToBytes(input.PeerDcfMasked),
			input.Family, input.Lower, input.Upper)

		// AND: NOT(c_low)_FP * c_high_FP
		andA := bytesToUint128Vec(base64ToBytes(input.TripleAND_A))
		andB := bytesToUint128Vec(base64ToBytes(input.TripleAND_B))
		andBeaver := BeaverTripleVec127{A: andA, B: andB}
		_, andMsg := GenerateBatchedMultiplicationGateMessage127(notCLowFP, cHighFP, andBeaver, ring)

		// Had1: slope * eta
		h1A := bytesToUint128Vec(base64ToBytes(input.TripleHad1_A))
		h1B := bytesToUint128Vec(base64ToBytes(input.TripleHad1_B))
		h1Beaver := BeaverTripleVec127{A: h1A, B: h1B}
		_, h1Msg := GenerateBatchedMultiplicationGateMessage127(aSlope, eta, h1Beaver, ring)

		mpcWriteOutput(K2WSPhase2Out{
			AND_XMA:  bytesToBase64(uint128VecToBytes(andMsg.XMinusAShares)),
			AND_YMB:  bytesToBase64(uint128VecToBytes(andMsg.YMinusBShares)),
			Had1_XMA: bytesToBase64(uint128VecToBytes(h1Msg.XMinusAShares)),
			Had1_YMB: bytesToBase64(uint128VecToBytes(h1Msg.YMinusBShares)),
			Had2_XMA: "",
			Had2_YMB: "",
		})

	case 3:
		// Phase 3: AND + Had1 close → I_mid, spline_value → Had2 R1.
		notCLowFP, cHighFP, _, _, aSlope, bInt, eta := wsComputeIndicators127(
			ring, n, numInt, numThresh, input.PartyID,
			etaShare, dcfKeys, base64ToBytes(input.PeerDcfMasked),
			input.Family, input.Lower, input.Upper)

		andA := bytesToUint128Vec(base64ToBytes(input.TripleAND_A))
		andB := bytesToUint128Vec(base64ToBytes(input.TripleAND_B))
		andC := bytesToUint128Vec(base64ToBytes(input.TripleAND_C))
		andBeaver := BeaverTripleVec127{A: andA, B: andB, C: andC}
		andState, _ := GenerateBatchedMultiplicationGateMessage127(notCLowFP, cHighFP, andBeaver, ring)
		peerAND := MultGateMessage127{
			XMinusAShares: bytesToUint128Vec(base64ToBytes(input.PeerAND_XMA)),
			YMinusBShares: bytesToUint128Vec(base64ToBytes(input.PeerAND_YMB)),
		}
		var iMid []Uint128
		if input.PartyID == 0 {
			iMid = HadamardProductPartyZero127(andState, andBeaver, peerAND, ring.FracBits, ring)
		} else {
			iMid = HadamardProductPartyOne127(andState, andBeaver, peerAND, ring.FracBits, ring)
		}

		h1A := bytesToUint128Vec(base64ToBytes(input.TripleHad1_A))
		h1B := bytesToUint128Vec(base64ToBytes(input.TripleHad1_B))
		h1C := bytesToUint128Vec(base64ToBytes(input.TripleHad1_C))
		h1Beaver := BeaverTripleVec127{A: h1A, B: h1B, C: h1C}
		h1State, _ := GenerateBatchedMultiplicationGateMessage127(aSlope, eta, h1Beaver, ring)
		peerH1 := MultGateMessage127{
			XMinusAShares: bytesToUint128Vec(base64ToBytes(input.PeerHad1_XMA)),
			YMinusBShares: bytesToUint128Vec(base64ToBytes(input.PeerHad1_YMB)),
		}
		var slopeX []Uint128
		if input.PartyID == 0 {
			slopeX = HadamardProductPartyZero127(h1State, h1Beaver, peerH1, ring.FracBits, ring)
		} else {
			slopeX = HadamardProductPartyOne127(h1State, h1Beaver, peerH1, ring.FracBits, ring)
		}

		splineVal := make([]Uint128, n)
		for i := 0; i < n; i++ {
			splineVal[i] = ring.Add(slopeX[i], bInt[i])
		}

		h2A := bytesToUint128Vec(base64ToBytes(input.TripleHad2_A))
		h2B := bytesToUint128Vec(base64ToBytes(input.TripleHad2_B))
		h2Beaver := BeaverTripleVec127{A: h2A, B: h2B}
		_, h2Msg := GenerateBatchedMultiplicationGateMessage127(iMid, splineVal, h2Beaver, ring)

		mpcWriteOutput(K2WSPhase2Out{
			AND_XMA:  "", AND_YMB: "",
			Had1_XMA: "", Had1_YMB: "",
			Had2_XMA: bytesToBase64(uint128VecToBytes(h2Msg.XMinusAShares)),
			Had2_YMB: bytesToBase64(uint128VecToBytes(h2Msg.YMinusBShares)),
		})

	case 4:
		// Phase 4: Had2 close + assembly → mu.
		notCLowFP, cHighFP, iLow, iHigh, aSlope, bInt, eta := wsComputeIndicators127(
			ring, n, numInt, numThresh, input.PartyID,
			etaShare, dcfKeys, base64ToBytes(input.PeerDcfMasked),
			input.Family, input.Lower, input.Upper)

		andA := bytesToUint128Vec(base64ToBytes(input.TripleAND_A))
		andB := bytesToUint128Vec(base64ToBytes(input.TripleAND_B))
		andC := bytesToUint128Vec(base64ToBytes(input.TripleAND_C))
		andBeaver := BeaverTripleVec127{A: andA, B: andB, C: andC}
		andState, _ := GenerateBatchedMultiplicationGateMessage127(notCLowFP, cHighFP, andBeaver, ring)
		peerAND := MultGateMessage127{
			XMinusAShares: bytesToUint128Vec(base64ToBytes(input.PeerAND_XMA)),
			YMinusBShares: bytesToUint128Vec(base64ToBytes(input.PeerAND_YMB)),
		}
		var iMid []Uint128
		if input.PartyID == 0 {
			iMid = HadamardProductPartyZero127(andState, andBeaver, peerAND, ring.FracBits, ring)
		} else {
			iMid = HadamardProductPartyOne127(andState, andBeaver, peerAND, ring.FracBits, ring)
		}

		h1A := bytesToUint128Vec(base64ToBytes(input.TripleHad1_A))
		h1B := bytesToUint128Vec(base64ToBytes(input.TripleHad1_B))
		h1C := bytesToUint128Vec(base64ToBytes(input.TripleHad1_C))
		h1Beaver := BeaverTripleVec127{A: h1A, B: h1B, C: h1C}
		h1State, _ := GenerateBatchedMultiplicationGateMessage127(aSlope, eta, h1Beaver, ring)
		peerH1 := MultGateMessage127{
			XMinusAShares: bytesToUint128Vec(base64ToBytes(input.PeerHad1_XMA)),
			YMinusBShares: bytesToUint128Vec(base64ToBytes(input.PeerHad1_YMB)),
		}
		var slopeX []Uint128
		if input.PartyID == 0 {
			slopeX = HadamardProductPartyZero127(h1State, h1Beaver, peerH1, ring.FracBits, ring)
		} else {
			slopeX = HadamardProductPartyOne127(h1State, h1Beaver, peerH1, ring.FracBits, ring)
		}

		splineVal := make([]Uint128, n)
		for i := 0; i < n; i++ {
			splineVal[i] = ring.Add(slopeX[i], bInt[i])
		}

		h2A := bytesToUint128Vec(base64ToBytes(input.TripleHad2_A))
		h2B := bytesToUint128Vec(base64ToBytes(input.TripleHad2_B))
		h2C := bytesToUint128Vec(base64ToBytes(input.TripleHad2_C))
		h2Beaver := BeaverTripleVec127{A: h2A, B: h2B, C: h2C}
		h2State, _ := GenerateBatchedMultiplicationGateMessage127(iMid, splineVal, h2Beaver, ring)
		peerH2 := MultGateMessage127{
			XMinusAShares: bytesToUint128Vec(base64ToBytes(input.PeerHad2_XMA)),
			YMinusBShares: bytesToUint128Vec(base64ToBytes(input.PeerHad2_YMB)),
		}
		var midSpline []Uint128
		if input.PartyID == 0 {
			midSpline = HadamardProductPartyZero127(h2State, h2Beaver, peerH2, ring.FracBits, ring)
		} else {
			midSpline = HadamardProductPartyOne127(h2State, h2Beaver, peerH2, ring.FracBits, ring)
		}

		mu := make([]Uint128, n)
		for i := 0; i < n; i++ {
			mu[i] = ring.Add(ring.Add(iLow[i], iHigh[i]), midSpline[i])
		}

		mpcWriteOutput(K2WSPhase3Out{
			MuShareFP: bytesToBase64(uint128VecToBytes(mu)),
		})
	}
	_ = binary.LittleEndian // keep import in sync with sibling file
}
