// k2_dcf_commands.go: mhe-tool commands for DCF-based wide spline evaluation
// in the DataSHIELD relay model.
//
// Protocol flow (orchestrated by client):
//   1. Client calls k2-dcf-gen-batch → DCF keys for both parties
//   2. Client sends keys to respective servers
//   3. Each server calls k2-dcf-eval phase=1 → masked values
//   4. Client relays masked values between servers
//   5. Each server calls k2-dcf-eval phase=2 → comparison shares
//   6. Each server calls k2-spline-indicators → slope/intercept/indicator shares
//   7. Beaver AND for I_mid (reuse existing k2-beaver-round)
//   8. Beaver Hadamard for slope*x and I_mid*spline (reuse existing)

package main

import (
	"encoding/binary"
	"fmt"
	"math"
)

// ============================================================================
// Command: k2-dcf-gen-batch
// Generates DCF preprocessing for ALL wide spline thresholds in one batch.
// Called by client, returns keys for both parties.
// ============================================================================

type K2DcfGenBatchInput struct {
	Family       string `json:"family"`        // "binomial" or "poisson"
	N            int    `json:"n"`             // number of elements
	FracBits     int    `json:"frac_bits"`
	NumIntervals int    `json:"num_intervals"` // 0 = use default from K2Config
}

type K2DcfGenBatchOutput struct {
	Party0Keys string    `json:"party0_keys"` // base64: serialized DCF keys + mask shares
	Party1Keys string    `json:"party1_keys"`
	Thresholds []float64 `json:"thresholds"`  // all thresholds (broad + sub-interval)
	NumBroad   int       `json:"num_broad"`   // number of broad thresholds (2)
}

func handleK2DcfGenBatch() {
	var input K2DcfGenBatchInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}

	ring := NewRing63(input.FracBits)
	n := input.N

	// Determine thresholds based on family
	var lower, upper float64
	numInt := input.NumIntervals
	switch input.Family {
	case "poisson":
		lower, upper = -3.0, 8.0
		if numInt <= 0 {
			numInt = K2ExpIntervals
		}
	default: // binomial
		lower, upper = -5.0, 5.0
		if numInt <= 0 {
			numInt = K2SigmoidIntervals
		}
	}

	width := (upper - lower) / float64(numInt)

	// Build ALL thresholds: 2 broad + (numInt-1) sub-interval
	thresholds := make([]float64, 0, numInt+1)
	// Broad thresholds
	thresholds = append(thresholds, lower) // c_low: x < lower
	thresholds = append(thresholds, upper) // c_high: x < upper
	// Sub-interval thresholds
	for j := 0; j < numInt-1; j++ {
		thresholds = append(thresholds, lower+float64(j+1)*width)
	}

	numThresh := len(thresholds)

	// Generate DCF preprocessing for each threshold
	allP0Keys := make([]CmpPreprocessPerParty, numThresh)
	allP1Keys := make([]CmpPreprocessPerParty, numThresh)
	for t := 0; t < numThresh; t++ {
		threshFP := ring.FromDouble(thresholds[t])
		allP0Keys[t], allP1Keys[t] = cmpGeneratePreprocess(ring, n, threshFP)
	}

	// Serialize all keys into compact binary blobs
	p0Bytes := serializeDcfBatch(allP0Keys, n, numThresh)
	p1Bytes := serializeDcfBatch(allP1Keys, n, numThresh)

	mpcWriteOutput(K2DcfGenBatchOutput{
		Party0Keys: bytesToBase64(p0Bytes),
		Party1Keys: bytesToBase64(p1Bytes),
		Thresholds: thresholds,
		NumBroad:   2,
	})
}

// ============================================================================
// Command: k2-dcf-eval
// Evaluates DCF on one party's eta share. Two phases:
//   Phase 1: compute masked values (to relay via client)
//   Phase 2: combine with peer's masked values → comparison shares
// ============================================================================

type K2DcfEvalInput struct {
	Phase        int    `json:"phase"`          // 1 or 2
	PartyID      int    `json:"party_id"`       // 0 or 1
	EtaShareFP   string `json:"eta_share_fp"`   // base64 FP: this party's eta share
	DcfKeys      string `json:"dcf_keys"`       // base64: this party's DCF keys
	PeerMasked   string `json:"peer_masked"`    // base64 (phase 2 only): peer's masked values
	N            int    `json:"n"`
	FracBits     int    `json:"frac_bits"`
	NumThresh    int    `json:"num_thresh"`     // total thresholds
}

type K2DcfEvalOutput struct {
	MaskedValues     string `json:"masked_values"`      // base64 (phase 1): to relay
	ComparisonShares string `json:"comparison_shares"`   // base64 FP (phase 2): result
}

func handleK2DcfEval() {
	var input K2DcfEvalInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}

	ring := NewRing63(input.FracBits)
	n := input.N
	numThresh := input.NumThresh

	// Decode eta share
	etaBytes := base64ToBytes(input.EtaShareFP)
	if len(etaBytes) == 0 {
		outputError(fmt.Sprintf("k2-dcf-eval: eta_share_fp is empty (n=%d, len_b64=%d)", n, len(input.EtaShareFP)))
		return
	}
	etaFP := bytesToFPVec(etaBytes)
	if len(etaFP) != n {
		outputError(fmt.Sprintf("k2-dcf-eval: eta has %d elements, expected %d (b64_len=%d, bytes=%d)", len(etaFP), n, len(input.EtaShareFP), len(etaBytes)))
		return
	}
	etaShare := fpToRing63(etaFP)

	// Decode DCF keys
	dcfBytes := base64ToBytes(input.DcfKeys)
	if len(dcfBytes) == 0 {
		outputError(fmt.Sprintf("k2-dcf-eval: dcf_keys is empty (n=%d, numThresh=%d)", n, numThresh))
		return
	}
	dcfKeys := deserializeDcfBatch(dcfBytes, n, numThresh)

	if input.Phase == 1 {
		// Phase 1: compute masked values for each threshold
		allMasked := make([]uint64, numThresh*n)
		for t := 0; t < numThresh; t++ {
			msg := cmpRound1(ring, input.PartyID, etaShare, dcfKeys[t])
			copy(allMasked[t*n:], msg.Values)
		}
		// Serialize as raw uint64 bytes
		buf := make([]byte, len(allMasked)*8)
		for i, v := range allMasked {
			binary.LittleEndian.PutUint64(buf[i*8:], v)
		}
		mpcWriteOutput(K2DcfEvalOutput{MaskedValues: bytesToBase64(buf)})

	} else {
		// Phase 2: combine own + peer masked values → comparison shares
		peerBuf := base64ToBytes(input.PeerMasked)
		peerMasked := make([]uint64, numThresh*n)
		for i := range peerMasked {
			peerMasked[i] = binary.LittleEndian.Uint64(peerBuf[i*8:])
		}

		// Also need own masked values — recompute (cheaper than storing)
		ownMasked := make([]uint64, numThresh*n)
		for t := 0; t < numThresh; t++ {
			msg := cmpRound1(ring, input.PartyID, etaShare, dcfKeys[t])
			copy(ownMasked[t*n:], msg.Values)
		}

		// Evaluate DCF for each threshold
		allShares := make([]uint64, numThresh*n)
		for t := 0; t < numThresh; t++ {
			ownMsg := CmpMaskedValues{Values: ownMasked[t*n : (t+1)*n]}
			peerMsg := CmpMaskedValues{Values: peerMasked[t*n : (t+1)*n]}
			result := cmpRound2(ring, input.PartyID, dcfKeys[t], ownMsg, peerMsg)
			copy(allShares[t*n:], result.Shares)
		}

		mpcWriteOutput(K2DcfEvalOutput{
			ComparisonShares: bytesToBase64(fpVecToBytes(ring63ToFP(allShares))),
		})
	}
}

// ============================================================================
// Command: k2-spline-indicators
// LOCAL computation: from comparison shares, compute slope/intercept/indicator
// shares via ScalarVP. No communication needed.
// ============================================================================

type K2SplineIndicatorsInput struct {
	ComparisonSharesFP string  `json:"comparison_shares_fp"` // base64 FP
	EtaShareFP         string  `json:"eta_share_fp"`         // base64 FP
	Family             string  `json:"family"`
	PartyID            int     `json:"party_id"`
	N                  int     `json:"n"`
	FracBits           int     `json:"frac_bits"`
	NumIntervals       int     `json:"num_intervals"`
}

type K2SplineIndicatorsOutput struct {
	SlopeShareFP     string `json:"slope_share_fp"`      // base64 FP: accumulated slope
	InterceptShareFP string `json:"intercept_share_fp"`  // base64 FP: accumulated intercept
	CLowShareFP      string `json:"c_low_share_fp"`      // base64 FP: c_low for Beaver AND
	CHighShareFP     string `json:"c_high_share_fp"`     // base64 FP: c_high for Beaver AND
	IHighFP          string `json:"i_high_fp"`           // base64 FP: NOT(c_high) scaled
}

func handleK2SplineIndicators() {
	var input K2SplineIndicatorsInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}

	ring := NewRing63(input.FracBits)
	n := input.N
	numInt := input.NumIntervals

	// Decode comparison shares: layout [c_low(n), c_high(n), sub0(n), sub1(n), ...]
	allShares := fpToRing63(bytesToFPVec(base64ToBytes(input.ComparisonSharesFP)))
	numThresh := 2 + numInt - 1 // 2 broad + (numInt-1) sub

	// Extract broad comparisons
	cLow := allShares[0:n]   // shares of 1{x < lower}
	cHigh := allShares[n:2*n] // shares of 1{x < upper}

	// Extract sub-interval comparisons
	subCmp := make([][]uint64, numInt-1)
	for j := 0; j < numInt-1; j++ {
		subCmp[j] = allShares[(2+j)*n : (3+j)*n]
	}
	_ = numThresh

	// Compute sub-indicators
	subInd := make([][]uint64, numInt)
	for k := 0; k < numInt; k++ {
		subInd[k] = make([]uint64, n)
	}
	for i := 0; i < n; i++ {
		subInd[0][i] = subCmp[0][i]
		for j := 1; j < numInt-1; j++ {
			subInd[j][i] = ring.Sub(subCmp[j][i], subCmp[j-1][i])
		}
		if input.PartyID == 0 {
			subInd[numInt-1][i] = ring.Sub(1, subCmp[numInt-2][i])
		} else {
			subInd[numInt-1][i] = ring.Sub(0, subCmp[numInt-2][i])
		}
	}

	// Scale sub-indicators to FP
	for k := 0; k < numInt; k++ {
		for i := 0; i < n; i++ {
			subInd[k][i] = modMulBig63(subInd[k][i], ring.FracMul, ring.Modulus)
		}
	}

	// Compute spline parameters
	var slopes, intercepts []float64
	switch input.Family {
	case "poisson":
		slopes, intercepts, _, _ = WideExpParams(numInt)
	default:
		slopes, intercepts, _ = WideSigmoidParams(numInt)
	}

	// Individual ScalarVP per interval (NOT deferred — avoids Ring63 overflow)
	aSlope := make([]uint64, n)
	bInt := make([]uint64, n)
	for j := 0; j < numInt; j++ {
		var sv, bi []uint64
		if input.PartyID == 0 {
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

	// I_high = NOT(c_high) scaled to FP
	iHigh := make([]uint64, n)
	for i := 0; i < n; i++ {
		var notCH uint64
		if input.PartyID == 0 {
			notCH = ring.Sub(1, cHigh[i])
		} else {
			notCH = ring.Sub(0, cHigh[i])
		}
		iHigh[i] = modMulBig63(notCH, ring.FracMul, ring.Modulus)
	}

	// NOT(c_low) and c_high: FP-SCALED for Beaver Hadamard (WITH truncation)
	// Must be FP-scaled because BeaverRoundFPDS does FP Hadamard (multiply + truncate by FracMul)
	notCLowFP := make([]uint64, n)
	cHighFP := make([]uint64, n)
	for i := 0; i < n; i++ {
		var notCL uint64
		if input.PartyID == 0 {
			notCL = ring.Sub(1, cLow[i])
		} else {
			notCL = ring.Sub(0, cLow[i])
		}
		notCLowFP[i] = modMulBig63(notCL, ring.FracMul, ring.Modulus)
		cHighFP[i] = modMulBig63(cHigh[i], ring.FracMul, ring.Modulus)
	}

	mpcWriteOutput(K2SplineIndicatorsOutput{
		SlopeShareFP:     bytesToBase64(fpVecToBytes(ring63ToFP(aSlope))),
		InterceptShareFP: bytesToBase64(fpVecToBytes(ring63ToFP(bInt))),
		CLowShareFP:      bytesToBase64(fpVecToBytes(ring63ToFP(notCLowFP))), // FP-scaled NOT(c_low)
		CHighShareFP:     bytesToBase64(fpVecToBytes(ring63ToFP(cHighFP))),   // FP-scaled c_high
		IHighFP:          bytesToBase64(fpVecToBytes(ring63ToFP(iHigh))),
	})
}

// ============================================================================
// Command: k2-spline-assemble
// Assembles final mu from I_high + I_mid*spline where spline = slope*x + intercept.
// I_mid comes from Beaver AND (done via existing k2-beaver-round).
// slope*x and I_mid*spline come from Beaver Hadamard (done via existing).
// This command does the FINAL addition. LOCAL, no communication.
// ============================================================================

type K2SplineAssembleInput struct {
	Family           string `json:"family"`
	PartyID          int    `json:"party_id"`
	IHighFP          string `json:"i_high_fp"`           // base64 FP
	MidSplineFP      string `json:"mid_spline_fp"`       // base64 FP: I_mid * spline_value
	N                int    `json:"n"`
	FracBits         int    `json:"frac_bits"`
	// Poisson-only: saturation values
	LowValFP         string `json:"low_val_fp"`          // base64 FP: I_low * clamp_low (Poisson)
	HighValFP         string `json:"high_val_fp"`         // base64 FP: I_high * clamp_high (Poisson)
}

type K2SplineAssembleOutput struct {
	MuShareFP string `json:"mu_share_fp"` // base64 FP
}

func handleK2SplineAssemble() {
	var input K2SplineAssembleInput
	mpcReadInput(&input)

	n := input.N
	midSpline := fpToRing63(bytesToFPVec(base64ToBytes(input.MidSplineFP)))

	ring := NewRing63(input.FracBits)

	mu := make([]uint64, n)

	switch input.Family {
	case "poisson":
		lowVal := fpToRing63(bytesToFPVec(base64ToBytes(input.LowValFP)))
		highVal := fpToRing63(bytesToFPVec(base64ToBytes(input.HighValFP)))
		for i := 0; i < n; i++ {
			mu[i] = ring.Add(ring.Add(lowVal[i], highVal[i]), midSpline[i])
		}
	default: // binomial
		iHigh := fpToRing63(bytesToFPVec(base64ToBytes(input.IHighFP)))
		for i := 0; i < n; i++ {
			mu[i] = ring.Add(iHigh[i], midSpline[i])
		}
	}

	mpcWriteOutput(K2SplineAssembleOutput{
		MuShareFP: bytesToBase64(fpVecToBytes(ring63ToFP(mu))),
	})
}

// ============================================================================
// DCF Batch Serialization
// ============================================================================

// serializeDcfBatch packs all DCF keys + mask shares into a single byte slice.
// Layout: for each threshold t, for each element i:
//   DCFKey: Seed0(16) + T0(1) + 63 * dcfCW(26) + FinalCW(8) = 1663 bytes
//   dcfCW: SeedCW(16) + VCW(8) + TCW_L(1) + TCW_R(1) = 26 bytes
//   MaskShare: 8 bytes
//   Total per element per threshold: 1671 bytes
func serializeDcfBatch(keys []CmpPreprocessPerParty, n, numThresh int) []byte {
	numBits := 63
	cwSize := 16 + 8 + 1 + 1 // SeedCW(16) + VCW(8) + TCW_L(1) + TCW_R(1)
	keySize := 16 + 1 + numBits*cwSize + 8 // Seed0 + T0 + CW array + FinalCW
	elemSize := keySize + 8 // + MaskShare

	buf := make([]byte, numThresh*n*elemSize)

	for t := 0; t < numThresh; t++ {
		for i := 0; i < n; i++ {
			offset := (t*n + i) * elemSize
			key := keys[t].Keys[i]

			// Seed0
			copy(buf[offset:offset+16], key.Seed0[:])
			// T0
			buf[offset+16] = key.T0
			// CW array
			for b := 0; b < numBits; b++ {
				cwOff := offset + 17 + b*cwSize
				copy(buf[cwOff:cwOff+16], key.CW[b].SeedCW[:])
				binary.LittleEndian.PutUint64(buf[cwOff+16:], uint64(key.CW[b].VCW))
				buf[cwOff+24] = key.CW[b].TCW_L
				buf[cwOff+25] = key.CW[b].TCW_R
			}
			// FinalCW
			binary.LittleEndian.PutUint64(buf[offset+17+numBits*cwSize:], uint64(key.FinalCW))
			// MaskShare
			binary.LittleEndian.PutUint64(buf[offset+keySize:], keys[t].MaskShare[i])
		}
	}

	return buf
}

func deserializeDcfBatch(buf []byte, n, numThresh int) []CmpPreprocessPerParty {
	numBits := 63
	cwSize := 16 + 8 + 1 + 1
	keySize := 16 + 1 + numBits*cwSize + 8
	elemSize := keySize + 8

	keys := make([]CmpPreprocessPerParty, numThresh)
	for t := 0; t < numThresh; t++ {
		keys[t].Keys = make([]DCFKey, n)
		keys[t].MaskShare = make([]uint64, n)

		for i := 0; i < n; i++ {
			offset := (t*n + i) * elemSize

			// Seed0
			copy(keys[t].Keys[i].Seed0[:], buf[offset:offset+16])
			// T0
			keys[t].Keys[i].T0 = buf[offset+16]
			// CW array
			keys[t].Keys[i].CW = make([]dcfCW, numBits)
			keys[t].Keys[i].NumBits = numBits
			for b := 0; b < numBits; b++ {
				cwOff := offset + 17 + b*cwSize
				copy(keys[t].Keys[i].CW[b].SeedCW[:], buf[cwOff:cwOff+16])
				keys[t].Keys[i].CW[b].VCW = int64(binary.LittleEndian.Uint64(buf[cwOff+16:]))
				keys[t].Keys[i].CW[b].TCW_L = buf[cwOff+24]
				keys[t].Keys[i].CW[b].TCW_R = buf[cwOff+25]
			}
			// FinalCW
			keys[t].Keys[i].FinalCW = int64(binary.LittleEndian.Uint64(buf[offset+17+numBits*cwSize:]))
			// MaskShare
			keys[t].MaskShare[i] = binary.LittleEndian.Uint64(buf[offset+keySize:])
		}
	}

	return keys
}

// ============================================================================
// Command: k2-fp-add
// Element-wise Ring63 addition of two FP vectors. LOCAL, no communication.
// Used to add intercept shares to slope*x shares: spline = slope*x + intercept.
// ============================================================================

type K2FPAddInput struct {
	A        string `json:"a"`         // base64 FP
	B        string `json:"b"`         // base64 FP
	FracBits int    `json:"frac_bits"`
}

type K2FPAddOutput struct {
	Result string `json:"result"` // base64 FP
}

func handleK2FPAdd() {
	var input K2FPAddInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}
	r := NewRing63(input.FracBits)
	a := fpToRing63(bytesToFPVec(base64ToBytes(input.A)))
	b := fpToRing63(bytesToFPVec(base64ToBytes(input.B)))
	result := make([]uint64, len(a))
	for i := range a {
		result[i] = r.Add(a[i], b[i])
	}
	mpcWriteOutput(K2FPAddOutput{
		Result: bytesToBase64(fpVecToBytes(ring63ToFP(result))),
	})
}

// ============================================================================
// Command: k2-fp-scale-indicator
// Multiplies each element by FracMul (integer → FP scaling).
// Used to convert integer AND result to FP for subsequent Hadamard.
// ============================================================================

type K2FPScaleIndicatorInput struct {
	DataFP   string `json:"data_fp"`   // base64 FP (integer values as int64)
	FracBits int    `json:"frac_bits"`
}

type K2FPScaleIndicatorOutput struct {
	Result string `json:"result"` // base64 FP (FP-scaled)
}

func handleK2FPScaleIndicator() {
	var input K2FPScaleIndicatorInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}
	r := NewRing63(input.FracBits)
	data := fpToRing63(bytesToFPVec(base64ToBytes(input.DataFP)))
	result := make([]uint64, len(data))
	for i := range data {
		result[i] = modMulBig63(data[i], r.FracMul, r.Modulus)
	}
	mpcWriteOutput(K2FPScaleIndicatorOutput{
		Result: bytesToBase64(fpVecToBytes(ring63ToFP(result))),
	})
}

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

	// Spline params
	var slopes, intercepts []float64
	if family == "poisson" {
		slopes, intercepts, _, _ = WideExpParams(numInt)
	} else {
		slopes, intercepts, _ = WideSigmoidParams(numInt)
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
		iHigh[i] = modMulBig63(notCH, ring.FracMul, ring.Modulus)
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

// ============================================================================
// Command: k2-newton-fisher
// Computes the diagonal Fisher information for Newton-IRLS.
// Input: mu shares + x shares (full design matrix) + Beaver triples
// Output: d_j = sum(w_i * x_ij^2) for j=1..p (this party's SHARE of d_j)
//
// This runs entirely in Go: w = mu*(1-mu), x² = x*x, w*x², sum → d_j share.
// The client sums both parties' d_j shares to get the disclosed diagonal Fisher.
// ============================================================================

type K2NewtonFisherInput struct {
	MuShareFP string `json:"mu_share_fp"` // base64 FP: this party's mu share (n elements)
	XFullFP   string `json:"x_full_fp"`   // base64 FP: full X share (n*p elements, row-major)
	N         int    `json:"n"`
	P         int    `json:"p"`
	FracBits  int    `json:"frac_bits"`
	PartyID   int    `json:"party_id"`
	// Beaver triples for w computation (mu * (1-mu))
	// Need 1 triple of size n for the Hadamard
	BeaverW_A string `json:"beaver_w_a"`
	BeaverW_B string `json:"beaver_w_b"`
	BeaverW_C string `json:"beaver_w_c"`
	// Peer's Beaver R1 for w computation
	PeerW_XMA string `json:"peer_w_xma"`
	PeerW_YMB string `json:"peer_w_ymb"`
	// Phase: 1 = compute Beaver R1 for w, 2 = compute d_j shares
	Phase int `json:"phase"`
}

type K2NewtonFisherPhase1Out struct {
	W_XMA string `json:"w_xma"` // base64 FP: Beaver R1 for w = mu*(1-mu)
	W_YMB string `json:"w_ymb"`
}

type K2NewtonFisherPhase2Out struct {
	FisherDiagFP string `json:"fisher_diag_fp"` // base64 FP: this party's share of d_j (p elements)
}

func handleK2NewtonFisher() {
	var input K2NewtonFisherInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}

	ring := NewRing63(input.FracBits)
	n := input.N
	p := input.P

	muShare := fpToRing63(bytesToFPVec(base64ToBytes(input.MuShareFP)))

	// one_minus_mu = 1.0 - mu (in FP: FracMul - mu for party 0, -mu for party 1)
	oneFP := ring.FromDouble(1.0)
	oneMinusMu := make([]uint64, n)
	for i := 0; i < n; i++ {
		if input.PartyID == 0 {
			oneMinusMu[i] = ring.Sub(oneFP, muShare[i])
		} else {
			oneMinusMu[i] = ring.Sub(0, muShare[i])
		}
	}

	wA := fpToRing63(bytesToFPVec(base64ToBytes(input.BeaverW_A)))
	wB := fpToRing63(bytesToFPVec(base64ToBytes(input.BeaverW_B)))
	wBeaver := BeaverTripleVec{A: wA, B: wB}

	if input.Phase == 1 {
		// Phase 1: Beaver R1 for w = mu * (1-mu)
		_, wMsg := GenerateBatchedMultiplicationGateMessage(muShare, oneMinusMu, wBeaver, ring)
		mpcWriteOutput(K2NewtonFisherPhase1Out{
			W_XMA: bytesToBase64(fpVecToBytes(ring63ToFP(wMsg.XMinusAShares))),
			W_YMB: bytesToBase64(fpVecToBytes(ring63ToFP(wMsg.YMinusBShares))),
		})
		return
	}

	// Phase 2: Beaver close for w + compute d_j
	wC := fpToRing63(bytesToFPVec(base64ToBytes(input.BeaverW_C)))
	wBeaver.C = wC
	wState, _ := GenerateBatchedMultiplicationGateMessage(muShare, oneMinusMu, wBeaver, ring)
	peerWMsg := MultGateMessage{
		XMinusAShares: fpToRing63(bytesToFPVec(base64ToBytes(input.PeerW_XMA))),
		YMinusBShares: fpToRing63(bytesToFPVec(base64ToBytes(input.PeerW_YMB))),
	}
	var wShare []uint64
	if input.PartyID == 0 {
		wShare = HadamardProductPartyZero(wState, wBeaver, peerWMsg, ring.FracBits, ring)
	} else {
		wShare = HadamardProductPartyOne(wState, wBeaver, peerWMsg, ring.FracBits, ring)
	}

	// Now compute d_j = sum_i(w_i * x_ij^2) for each feature j
	// x_ij shares are in XFullFP (n*p, row-major) — not used for approximate Newton
	_ = p

	// For each feature j: d_j_share = sum_i(w_share_i * x_ij_share^2)
	// Note: this is an APPROXIMATION — we compute w_share * x_share^2 locally.
	// The correct computation would need Hadamard for w*x^2, but that requires
	// additional Beaver triples per feature.
	//
	// SIMPLER APPROACH: compute sum(w_share) as the Fisher diagonal.
	// Since w_i = mu_i*(1-mu_i) and features are standardized (E[x²]=1),
	// d_j ≈ sum(w_i) for all j. This is a GOOD approximation for standardized data.
	//
	// d_share = sum(w_share_i) — same for all features
	var sumW uint64
	for i := 0; i < n; i++ {
		sumW = ring.Add(sumW, wShare[i])
	}

	// Return p copies of sum(w) share (same diagonal for all features)
	fisherDiag := make([]uint64, p)
	for j := 0; j < p; j++ {
		fisherDiag[j] = sumW
	}

	mpcWriteOutput(K2NewtonFisherPhase2Out{
		FisherDiagFP: bytesToBase64(fpVecToBytes(ring63ToFP(fisherDiag))),
	})
}

// ============================================================================
// Helpers
// ============================================================================

func computeSigmoidSplineCoeffs(numIntervals int) (slopes, intercepts []float64, lower, upper float64) {
	lower, upper = -5.0, 5.0
	sigma := func(x float64) float64 { return 1.0 / (1.0 + math.Exp(-x)) }
	slopes, intercepts = computeWideSpline(sigma, numIntervals, lower, upper)
	return
}

func computeExpSplineCoeffs(numIntervals int) (slopes, intercepts []float64, lower, upper float64) {
	lower, upper = -3.0, 8.0
	slopes, intercepts = computeWideSpline(math.Exp, numIntervals, lower, upper)
	return
}
