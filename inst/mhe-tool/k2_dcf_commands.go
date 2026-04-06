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
// FULL wide spline evaluation in a single Go call per party.
// Takes this party's eta share + DCF keys, generates Beaver triples internally,
// and returns this party's mu share. Used when BOTH parties call this command
// and relay masked values via the client.
//
// This avoids the R session storage / base64 conversion issues that arise from
// splitting the protocol across multiple R calls.
// ============================================================================

type K2WideSplineFullInput struct {
	Phase     int    `json:"phase"`      // 1 = generate masked values, 2 = compute mu share
	PartyID   int    `json:"party_id"`
	Family    string `json:"family"`
	EtaShareFP string `json:"eta_share_fp"` // base64 FP
	DcfKeys    string `json:"dcf_keys"`     // base64: DCF keys for this party
	PeerMasked string `json:"peer_masked"`  // base64 (phase 2 only)
	N          int    `json:"n"`
	FracBits   int    `json:"frac_bits"`
	NumIntervals int  `json:"num_intervals"`
	// Beaver triples for AND + 2 Hadamards (3 triples, phase 2 only)
	BeaverAND_A  string `json:"beaver_and_a"`  // base64 FP
	BeaverAND_B  string `json:"beaver_and_b"`
	BeaverAND_C  string `json:"beaver_and_c"`
	BeaverHad1_A string `json:"beaver_had1_a"` // slope*x Hadamard
	BeaverHad1_B string `json:"beaver_had1_b"`
	BeaverHad1_C string `json:"beaver_had1_c"`
	BeaverHad2_A string `json:"beaver_had2_a"` // I_mid*spline Hadamard
	BeaverHad2_B string `json:"beaver_had2_b"`
	BeaverHad2_C string `json:"beaver_had2_c"`
	// Peer's round-1 messages (phase 2 only, 3 per-op: AND + 2 Hadamard)
	PeerAND_XMA  string `json:"peer_and_xma"`
	PeerAND_YMB  string `json:"peer_and_ymb"`
	PeerHad1_XMA string `json:"peer_had1_xma"`
	PeerHad1_YMB string `json:"peer_had1_ymb"`
	PeerHad2_XMA string `json:"peer_had2_xma"`
	PeerHad2_YMB string `json:"peer_had2_ymb"`
}

type K2WideSplineFullPhase1Output struct {
	// DCF masked values (for comparison relay)
	DcfMasked string `json:"dcf_masked"` // base64
	// Beaver round-1 messages for 3 operations
	AND_XMA   string `json:"and_xma"`
	AND_YMB   string `json:"and_ymb"`
	Had1_XMA  string `json:"had1_xma"`
	Had1_YMB  string `json:"had1_ymb"`
	Had2_XMA  string `json:"had2_xma"`
	Had2_YMB  string `json:"had2_ymb"`
}

type K2WideSplineFullPhase2Output struct {
	MuShareFP string `json:"mu_share_fp"` // base64 FP
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

	// Decode eta share
	etaBytes := base64ToBytes(input.EtaShareFP)
	if len(etaBytes) == 0 {
		outputError(fmt.Sprintf("k2-wide-spline-full: eta_share_fp is empty (n=%d)", n))
		return
	}
	etaShare := fpToRing63(bytesToFPVec(etaBytes))

	// Decode DCF keys
	dcfKeys := deserializeDcfBatch(base64ToBytes(input.DcfKeys), n, numThresh)

	if input.Phase == 1 {
		// Phase 1: DCF masked values + all 3 Beaver round-1 messages

		// 1a. DCF masked values
		allMasked := make([]uint64, numThresh*n)
		for t := 0; t < numThresh; t++ {
			msg := cmpRound1(ring, input.PartyID, etaShare, dcfKeys[t])
			copy(allMasked[t*n:], msg.Values)
		}
		dcfBuf := make([]byte, len(allMasked)*8)
		for i, v := range allMasked {
			binary.LittleEndian.PutUint64(dcfBuf[i*8:], v)
		}

		// 1b. Decode spline params and comparison shares needed for indicator computation
		// (We'll compute indicators locally in phase 2 after DCF completes)
		// For now, just return DCF masked values
		// The Beaver round-1 messages require knowing the indicator values, which we
		// don't have yet (need peer's DCF masked values first).
		// So Phase 1 is JUST DCF.

		mpcWriteOutput(K2WideSplineFullPhase1Output{
			DcfMasked: bytesToBase64(dcfBuf),
		})
		return
	}

	// Phase 2: Complete the evaluation
	// 2a. DCF phase 2: combine own + peer masked values
	peerBuf := base64ToBytes(input.PeerMasked)
	peerMasked := make([]uint64, numThresh*n)
	for i := range peerMasked {
		peerMasked[i] = binary.LittleEndian.Uint64(peerBuf[i*8:])
	}

	ownMasked := make([]uint64, numThresh*n)
	for t := 0; t < numThresh; t++ {
		msg := cmpRound1(ring, input.PartyID, etaShare, dcfKeys[t])
		copy(ownMasked[t*n:], msg.Values)
	}

	allCmp := make([]uint64, numThresh*n)
	for t := 0; t < numThresh; t++ {
		ownMsg := CmpMaskedValues{Values: ownMasked[t*n : (t+1)*n]}
		peerMsg := CmpMaskedValues{Values: peerMasked[t*n : (t+1)*n]}
		result := cmpRound2(ring, input.PartyID, dcfKeys[t], ownMsg, peerMsg)
		copy(allCmp[t*n:], result.Shares)
	}

	// 2b. Compute indicators + spline coefficients (same as k2-spline-indicators)
	cLow := allCmp[0:n]
	cHigh := allCmp[n : 2*n]
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
		if input.PartyID == 0 {
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
	if input.Family == "poisson" {
		slopes, intercepts, _, _ = WideExpParams(numInt)
	} else {
		slopes, intercepts, _ = WideSigmoidParams(numInt)
	}

	// ScalarVP for slopes and intercepts
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

	// I_high and I_mid indicators
	iHigh := make([]uint64, n)
	notCLowFP := make([]uint64, n)
	cHighFP := make([]uint64, n)
	for i := 0; i < n; i++ {
		var notCH, notCL uint64
		if input.PartyID == 0 {
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

	// 2c. Beaver AND: I_mid = NOT(c_low)_FP * c_high_FP (Hadamard with truncation)
	andA := fpToRing63(bytesToFPVec(base64ToBytes(input.BeaverAND_A)))
	andB := fpToRing63(bytesToFPVec(base64ToBytes(input.BeaverAND_B)))
	andC := fpToRing63(bytesToFPVec(base64ToBytes(input.BeaverAND_C)))
	andBeaver := BeaverTripleVec{A: andA, B: andB, C: andC}
	andState, andMsg := GenerateBatchedMultiplicationGateMessage(notCLowFP, cHighFP, andBeaver, ring)
	peerANDMsg := MultGateMessage{
		XMinusAShares: fpToRing63(bytesToFPVec(base64ToBytes(input.PeerAND_XMA))),
		YMinusBShares: fpToRing63(bytesToFPVec(base64ToBytes(input.PeerAND_YMB))),
	}
	var iMid []uint64
	if input.PartyID == 0 {
		iMid = HadamardProductPartyZero(andState, andBeaver, peerANDMsg, ring.FracBits, ring)
	} else {
		iMid = HadamardProductPartyOne(andState, andBeaver, peerANDMsg, ring.FracBits, ring)
	}
	_ = andMsg // own message was sent in phase 1

	// 2d. Hadamard: slope * x
	had1A := fpToRing63(bytesToFPVec(base64ToBytes(input.BeaverHad1_A)))
	had1B := fpToRing63(bytesToFPVec(base64ToBytes(input.BeaverHad1_B)))
	had1C := fpToRing63(bytesToFPVec(base64ToBytes(input.BeaverHad1_C)))
	had1Beaver := BeaverTripleVec{A: had1A, B: had1B, C: had1C}
	had1State, _ := GenerateBatchedMultiplicationGateMessage(aSlope, etaShare, had1Beaver, ring)
	peerHad1Msg := MultGateMessage{
		XMinusAShares: fpToRing63(bytesToFPVec(base64ToBytes(input.PeerHad1_XMA))),
		YMinusBShares: fpToRing63(bytesToFPVec(base64ToBytes(input.PeerHad1_YMB))),
	}
	var slopeX []uint64
	if input.PartyID == 0 {
		slopeX = HadamardProductPartyZero(had1State, had1Beaver, peerHad1Msg, ring.FracBits, ring)
	} else {
		slopeX = HadamardProductPartyOne(had1State, had1Beaver, peerHad1Msg, ring.FracBits, ring)
	}

	// spline_value = slope*x + intercept
	splineVal := make([]uint64, n)
	for i := 0; i < n; i++ {
		splineVal[i] = ring.Add(slopeX[i], bInt[i])
	}

	// 2e. Hadamard: I_mid * spline_value
	had2A := fpToRing63(bytesToFPVec(base64ToBytes(input.BeaverHad2_A)))
	had2B := fpToRing63(bytesToFPVec(base64ToBytes(input.BeaverHad2_B)))
	had2C := fpToRing63(bytesToFPVec(base64ToBytes(input.BeaverHad2_C)))
	had2Beaver := BeaverTripleVec{A: had2A, B: had2B, C: had2C}
	had2State, _ := GenerateBatchedMultiplicationGateMessage(iMid, splineVal, had2Beaver, ring)
	peerHad2Msg := MultGateMessage{
		XMinusAShares: fpToRing63(bytesToFPVec(base64ToBytes(input.PeerHad2_XMA))),
		YMinusBShares: fpToRing63(bytesToFPVec(base64ToBytes(input.PeerHad2_YMB))),
	}
	var midSpline []uint64
	if input.PartyID == 0 {
		midSpline = HadamardProductPartyZero(had2State, had2Beaver, peerHad2Msg, ring.FracBits, ring)
	} else {
		midSpline = HadamardProductPartyOne(had2State, had2Beaver, peerHad2Msg, ring.FracBits, ring)
	}

	// 2f. Final assembly: mu = I_high + I_mid * spline_value
	mu := make([]uint64, n)
	for i := 0; i < n; i++ {
		mu[i] = ring.Add(iHigh[i], midSpline[i])
	}

	mpcWriteOutput(K2WideSplineFullPhase2Output{
		MuShareFP: bytesToBase64(fpVecToBytes(ring63ToFP(mu))),
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
