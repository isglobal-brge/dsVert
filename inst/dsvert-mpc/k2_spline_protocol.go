// k2_spline_protocol.go: 4-phase wide spline sigmoid/exp evaluation for DataSHIELD.
package main

import (
	"encoding/binary"
	"fmt"
	"math"
)

// ============================================================================
// Command: k2-wide-spline-full
// 3-phase wide spline sigmoid/exp evaluation for DataSHIELD relay.
//
// Phase 1: DCF masked values (input: eta + DCF keys → output: masked values)
// Phase 2: DCF close + indicators + Beaver R1 (input: peer DCF masked + triples → R1 msgs)
// Phase 3: Beaver R2 + assembly (input: peer Beaver R1 → mu shares)
//
// Each phase recomputes needed values (no state between Go invocations).
// ============================================================================

type K2WideSplineFullInput struct {
	Phase        int    `json:"phase"`          // 1, 2, or 3
	PartyID      int    `json:"party_id"`
	Family       string `json:"family"`
	EtaShareFP   string `json:"eta_share_fp"`   // base64 FP (all phases)
	DcfKeys      string `json:"dcf_keys"`       // base64 (all phases)
	N            int    `json:"n"`
	FracBits     int    `json:"frac_bits"`
	NumIntervals int    `json:"num_intervals"`
	// Phase 2+3: peer DCF masked values (needed to recompute comparisons)
	PeerDcfMasked string `json:"peer_dcf_masked"` // base64
	// Phase 2+3: Beaver triples (3 ops: AND, Had1=slope*x, Had2=I_mid*spline)
	TripleAND_A  string `json:"t_and_a"`
	TripleAND_B  string `json:"t_and_b"`
	TripleAND_C  string `json:"t_and_c"`
	TripleHad1_A string `json:"t_had1_a"`
	TripleHad1_B string `json:"t_had1_b"`
	TripleHad1_C string `json:"t_had1_c"`
	TripleHad2_A string `json:"t_had2_a"`
	TripleHad2_B string `json:"t_had2_b"`
	TripleHad2_C string `json:"t_had2_c"`
	// Phase 3: peer's Beaver R1 messages (6 values)
	PeerAND_XMA  string `json:"p_and_xma"`
	PeerAND_YMB  string `json:"p_and_ymb"`
	PeerHad1_XMA string `json:"p_had1_xma"`
	PeerHad1_YMB string `json:"p_had1_ymb"`
	PeerHad2_XMA string `json:"p_had2_xma"`
	PeerHad2_YMB string `json:"p_had2_ymb"`
}

type K2WSPhase1Out struct {
	DcfMasked string `json:"dcf_masked"` // base64: masked values for relay
}

type K2WSPhase2Out struct {
	AND_XMA  string `json:"and_xma"`  // base64 FP: Beaver R1 for AND
	AND_YMB  string `json:"and_ymb"`
	Had1_XMA string `json:"had1_xma"` // Beaver R1 for slope*x
	Had1_YMB string `json:"had1_ymb"`
	Had2_XMA string `json:"had2_xma"` // Beaver R1 for I_mid*spline
	Had2_YMB string `json:"had2_ymb"`
}

type K2WSPhase3Out struct {
	MuShareFP string `json:"mu_share_fp"` // base64 FP: final mu share
}

// wsComputeIndicators recomputes DCF close + indicator shares from DCF keys,
// eta share, and peer's DCF masked values. Used by phases 2 and 3.
func wsComputeIndicators(ring Ring63, n, numInt, numThresh int, partyID int,
	etaShare []uint64, dcfKeys []CmpPreprocessPerParty, peerMaskedBuf []byte,
	family string) (notCLowFP, cHighFP, iHigh, aSlope, bInt []uint64, etaR63 []uint64) {

	// DCF close: recompute own masked + combine with peer
	peerMasked := make([]uint64, numThresh*n)
	for i := range peerMasked {
		peerMasked[i] = binary.LittleEndian.Uint64(peerMaskedBuf[i*8:])
	}

	ownMasked := make([]uint64, numThresh*n)
	for t := 0; t < numThresh; t++ {
		msg := cmpRound1(ring, partyID, etaShare, dcfKeys[t])
		copy(ownMasked[t*n:], msg.Values)
	}

	allCmp := make([]uint64, numThresh*n)
	for t := 0; t < numThresh; t++ {
		ownMsg := CmpMaskedValues{Values: ownMasked[t*n : (t+1)*n]}
		peerMsg := CmpMaskedValues{Values: peerMasked[t*n : (t+1)*n]}
		result := cmpRound2(ring, partyID, dcfKeys[t], ownMsg, peerMsg)
		copy(allCmp[t*n:], result.Shares)
	}

	cLow := allCmp[0:n]
	cHigh := allCmp[n : 2*n]

	// Sub-indicators
	subCmp := make([][]uint64, numInt-1)
	for j := 0; j < numInt-1; j++ {
		subCmp[j] = allCmp[(2+j)*n : (3+j)*n]
	}
	subInd := make([][]uint64, numInt)
	for k := 0; k < numInt; k++ {
		subInd[k] = make([]uint64, n)
	}
	for i := 0; i < n; i++ {
		subInd[0][i] = subCmp[0][i]
		for j := 1; j < numInt-1; j++ {
			subInd[j][i] = ring.Sub(subCmp[j][i], subCmp[j-1][i])
		}
		if partyID == 0 {
			subInd[numInt-1][i] = ring.Sub(1, subCmp[numInt-2][i])
		} else {
			subInd[numInt-1][i] = ring.Sub(0, subCmp[numInt-2][i])
		}
	}
	for k := 0; k < numInt; k++ {
		for i := 0; i < n; i++ {
			subInd[k][i] = modMulBig63(subInd[k][i], ring.FracMul, ring.Modulus)
		}
	}

	// Spline params + saturation value for upper bound
	var slopes, intercepts []float64
	var satHigh float64 = 1.0 // default: sigmoid saturates at 1
	if family == "poisson" {
		slopes, intercepts, _, _ = WideExpParams(numInt)
		satHigh = math.Exp(8.0) // exp(upper)
	} else if family == "softplus" {
		slopes, intercepts, _ = WideSoftplusParams(numInt)
		satHigh = math.Log(1.0 + math.Exp(8.0)) // softplus(upper) ≈ 8.0003
	} else {
		slopes, intercepts, _ = WideSigmoidParams(numInt)
		satHigh = 1.0
	}

	// ScalarVP for slopes and intercepts
	aSlope = make([]uint64, n)
	bInt = make([]uint64, n)
	for j := 0; j < numInt; j++ {
		var sv, bi []uint64
		if partyID == 0 {
			sv = ScalarVectorProductPartyZero(slopes[j], subInd[j], ring)
			bi = ScalarVectorProductPartyZero(intercepts[j], subInd[j], ring)
		} else {
			sv = ScalarVectorProductPartyOne(slopes[j], subInd[j], ring)
			bi = ScalarVectorProductPartyOne(intercepts[j], subInd[j], ring)
		}
		for i := 0; i < n; i++ {
			aSlope[i] = ring.Add(aSlope[i], sv[i])
			bInt[i] = ring.Add(bInt[i], bi[i])
		}
	}

	// Indicators: FP-scaled for Beaver Hadamard
	iHigh = make([]uint64, n)
	notCLowFP = make([]uint64, n)
	cHighFP = make([]uint64, n)
	for i := 0; i < n; i++ {
		var notCH, notCL uint64
		if partyID == 0 {
			notCH = ring.Sub(1, cHigh[i])
			notCL = ring.Sub(1, cLow[i])
		} else {
			notCH = ring.Sub(0, cHigh[i])
			notCL = ring.Sub(0, cLow[i])
		}
		iHigh[i] = modMulBig63(notCH, ring.FromDouble(satHigh), ring.Modulus)
		notCLowFP[i] = modMulBig63(notCL, ring.FracMul, ring.Modulus)
		cHighFP[i] = modMulBig63(cHigh[i], ring.FracMul, ring.Modulus)
	}
	etaR63 = etaShare
	return
}

func handleK2WideSplineFullEval() {
	var input K2WideSplineFullInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}

	ring := NewRing63(input.FracBits)
	n := input.N
	numInt := input.NumIntervals
	if numInt <= 0 {
		if input.Family == "poisson" {
			numInt = K2ExpIntervals
		} else {
			numInt = K2SigmoidIntervals
		}
	}
	numThresh := 2 + numInt - 1

	etaBytes := base64ToBytes(input.EtaShareFP)
	if len(etaBytes) == 0 {
		outputError(fmt.Sprintf("k2-wide-spline-full: eta empty (n=%d, b64len=%d)", n, len(input.EtaShareFP)))
		return
	}
	etaShare := fpToRing63(bytesToFPVec(etaBytes))
	dcfKeys := deserializeDcfBatch(base64ToBytes(input.DcfKeys), n, numThresh)

	switch input.Phase {
	case 1:
		// Phase 1: DCF masked values only
		allMasked := make([]uint64, numThresh*n)
		for t := 0; t < numThresh; t++ {
			msg := cmpRound1(ring, input.PartyID, etaShare, dcfKeys[t])
			copy(allMasked[t*n:], msg.Values)
		}
		buf := make([]byte, len(allMasked)*8)
		for i, v := range allMasked {
			binary.LittleEndian.PutUint64(buf[i*8:], v)
		}
		mpcWriteOutput(K2WSPhase1Out{DcfMasked: bytesToBase64(buf)})

	case 2:
		// Phase 2: DCF close + indicators + Beaver R1 for all 3 ops
		notCLowFP, cHighFP, _, aSlope, _, eta := wsComputeIndicators(
			ring, n, numInt, numThresh, input.PartyID,
			etaShare, dcfKeys, base64ToBytes(input.PeerDcfMasked),
			input.Family)

		// Beaver R1 for AND: NOT(c_low)_FP * c_high_FP
		andA := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleAND_A)))
		andB := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleAND_B)))
		andBeaver := BeaverTripleVec{A: andA, B: andB}
		_, andMsg := GenerateBatchedMultiplicationGateMessage(notCLowFP, cHighFP, andBeaver, ring)

		// Beaver R1 for Hadamard 1: slope * eta
		h1A := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleHad1_A)))
		h1B := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleHad1_B)))
		h1Beaver := BeaverTripleVec{A: h1A, B: h1B}
		_, h1Msg := GenerateBatchedMultiplicationGateMessage(aSlope, eta, h1Beaver, ring)

		// Beaver R1 for Hadamard 2: placeholder (need I_mid and spline_value which we don't have yet)
		// We CAN'T do Had2 R1 here because we need the results of AND and Had1 first!
		// Solution: combine Had2 into phase 3 (use 4 phases) or send dummy values.
		//
		// Actually, Had2 inputs (I_mid, spline_value) depend on AND and Had1 results.
		// So we need ANOTHER round: phase 2 = AND+Had1 R1, phase 3 = AND+Had1 R2 + Had2 R1,
		// phase 4 = Had2 R2 + assembly.
		//
		// This is 4 phases (3 relay rounds). Let me simplify:
		// Since AND and Had1 are independent, they can share a round.
		// But Had2 depends on both AND (for I_mid) and Had1 (for slope*x → spline_value).
		// So Had2 must happen AFTER AND and Had1 complete.
		//
		// Phases:
		// 1. DCF R1 → relay
		// 2. DCF R2 + indicators + (AND + Had1) R1 → relay
		// 3. (AND + Had1) R2 → compute I_mid, spline_value → Had2 R1 → relay
		// 4. Had2 R2 + assembly → mu
		//
		// That's 4 phases, 3 relay rounds. Let me implement this.

		mpcWriteOutput(K2WSPhase2Out{
			AND_XMA:  bytesToBase64(fpVecToBytes(ring63ToFP(andMsg.XMinusAShares))),
			AND_YMB:  bytesToBase64(fpVecToBytes(ring63ToFP(andMsg.YMinusBShares))),
			Had1_XMA: bytesToBase64(fpVecToBytes(ring63ToFP(h1Msg.XMinusAShares))),
			Had1_YMB: bytesToBase64(fpVecToBytes(ring63ToFP(h1Msg.YMinusBShares))),
			Had2_XMA: "", // Not available yet — computed in phase 3
			Had2_YMB: "",
		})

	case 3:
		// Phase 3: AND+Had1 close → compute I_mid, spline_value → Had2 R1
		notCLowFP, cHighFP, _, aSlope, bInt, eta := wsComputeIndicators(
			ring, n, numInt, numThresh, input.PartyID,
			etaShare, dcfKeys, base64ToBytes(input.PeerDcfMasked),
			input.Family)

		// AND close
		andA := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleAND_A)))
		andB := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleAND_B)))
		andC := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleAND_C)))
		andBeaver := BeaverTripleVec{A: andA, B: andB, C: andC}
		andState, _ := GenerateBatchedMultiplicationGateMessage(notCLowFP, cHighFP, andBeaver, ring)
		peerAND := MultGateMessage{
			XMinusAShares: fpToRing63(bytesToFPVec(base64ToBytes(input.PeerAND_XMA))),
			YMinusBShares: fpToRing63(bytesToFPVec(base64ToBytes(input.PeerAND_YMB))),
		}
		var iMid []uint64
		if input.PartyID == 0 {
			iMid = HadamardProductPartyZero(andState, andBeaver, peerAND, ring.FracBits, ring)
		} else {
			iMid = HadamardProductPartyOne(andState, andBeaver, peerAND, ring.FracBits, ring)
		}

		// Had1 close: slope * eta
		h1A := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleHad1_A)))
		h1B := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleHad1_B)))
		h1C := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleHad1_C)))
		h1Beaver := BeaverTripleVec{A: h1A, B: h1B, C: h1C}
		h1State, _ := GenerateBatchedMultiplicationGateMessage(aSlope, eta, h1Beaver, ring)
		peerH1 := MultGateMessage{
			XMinusAShares: fpToRing63(bytesToFPVec(base64ToBytes(input.PeerHad1_XMA))),
			YMinusBShares: fpToRing63(bytesToFPVec(base64ToBytes(input.PeerHad1_YMB))),
		}
		var slopeX []uint64
		if input.PartyID == 0 {
			slopeX = HadamardProductPartyZero(h1State, h1Beaver, peerH1, ring.FracBits, ring)
		} else {
			slopeX = HadamardProductPartyOne(h1State, h1Beaver, peerH1, ring.FracBits, ring)
		}

		// spline_value = slope*x + intercept
		splineVal := make([]uint64, n)
		for i := 0; i < n; i++ {
			splineVal[i] = ring.Add(slopeX[i], bInt[i])
		}

		// Had2 R1: I_mid * spline_value
		h2A := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleHad2_A)))
		h2B := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleHad2_B)))
		h2Beaver := BeaverTripleVec{A: h2A, B: h2B}
		_, h2Msg := GenerateBatchedMultiplicationGateMessage(iMid, splineVal, h2Beaver, ring)

		mpcWriteOutput(K2WSPhase2Out{
			AND_XMA:  "", AND_YMB: "",
			Had1_XMA: "", Had1_YMB: "",
			Had2_XMA: bytesToBase64(fpVecToBytes(ring63ToFP(h2Msg.XMinusAShares))),
			Had2_YMB: bytesToBase64(fpVecToBytes(ring63ToFP(h2Msg.YMinusBShares))),
		})

	case 4:
		// Phase 4: Had2 close + assembly → mu
		notCLowFP, cHighFP, iHigh, aSlope, bInt, eta := wsComputeIndicators(
			ring, n, numInt, numThresh, input.PartyID,
			etaShare, dcfKeys, base64ToBytes(input.PeerDcfMasked),
			input.Family)

		// Recompute AND + Had1 to get I_mid and spline_value
		andA := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleAND_A)))
		andB := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleAND_B)))
		andC := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleAND_C)))
		andBeaver := BeaverTripleVec{A: andA, B: andB, C: andC}
		andState, _ := GenerateBatchedMultiplicationGateMessage(notCLowFP, cHighFP, andBeaver, ring)
		peerAND := MultGateMessage{
			XMinusAShares: fpToRing63(bytesToFPVec(base64ToBytes(input.PeerAND_XMA))),
			YMinusBShares: fpToRing63(bytesToFPVec(base64ToBytes(input.PeerAND_YMB))),
		}
		var iMid []uint64
		if input.PartyID == 0 {
			iMid = HadamardProductPartyZero(andState, andBeaver, peerAND, ring.FracBits, ring)
		} else {
			iMid = HadamardProductPartyOne(andState, andBeaver, peerAND, ring.FracBits, ring)
		}

		h1A := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleHad1_A)))
		h1B := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleHad1_B)))
		h1C := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleHad1_C)))
		h1Beaver := BeaverTripleVec{A: h1A, B: h1B, C: h1C}
		h1State, _ := GenerateBatchedMultiplicationGateMessage(aSlope, eta, h1Beaver, ring)
		peerH1 := MultGateMessage{
			XMinusAShares: fpToRing63(bytesToFPVec(base64ToBytes(input.PeerHad1_XMA))),
			YMinusBShares: fpToRing63(bytesToFPVec(base64ToBytes(input.PeerHad1_YMB))),
		}
		var slopeX []uint64
		if input.PartyID == 0 {
			slopeX = HadamardProductPartyZero(h1State, h1Beaver, peerH1, ring.FracBits, ring)
		} else {
			slopeX = HadamardProductPartyOne(h1State, h1Beaver, peerH1, ring.FracBits, ring)
		}

		splineVal := make([]uint64, n)
		for i := 0; i < n; i++ {
			splineVal[i] = ring.Add(slopeX[i], bInt[i])
		}

		// Had2 close
		h2A := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleHad2_A)))
		h2B := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleHad2_B)))
		h2C := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleHad2_C)))
		h2Beaver := BeaverTripleVec{A: h2A, B: h2B, C: h2C}
		h2State, _ := GenerateBatchedMultiplicationGateMessage(iMid, splineVal, h2Beaver, ring)
		peerH2 := MultGateMessage{
			XMinusAShares: fpToRing63(bytesToFPVec(base64ToBytes(input.PeerHad2_XMA))),
			YMinusBShares: fpToRing63(bytesToFPVec(base64ToBytes(input.PeerHad2_YMB))),
		}
		var midSpline []uint64
		if input.PartyID == 0 {
			midSpline = HadamardProductPartyZero(h2State, h2Beaver, peerH2, ring.FracBits, ring)
		} else {
			midSpline = HadamardProductPartyOne(h2State, h2Beaver, peerH2, ring.FracBits, ring)
		}

		// Final: mu = I_high + I_mid * spline_value
		mu := make([]uint64, n)
		for i := 0; i < n; i++ {
			mu[i] = ring.Add(iHigh[i], midSpline[i])
		}
		_ = iMid

		mpcWriteOutput(K2WSPhase3Out{
			MuShareFP: bytesToBase64(fpVecToBytes(ring63ToFP(mu))),
		})
	}
}

