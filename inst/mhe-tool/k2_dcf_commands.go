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

	// NOT(c_low) for Beaver AND input
	notCLow := make([]uint64, n)
	for i := 0; i < n; i++ {
		if input.PartyID == 0 {
			notCLow[i] = ring.Sub(1, cLow[i])
		} else {
			notCLow[i] = ring.Sub(0, cLow[i])
		}
	}

	mpcWriteOutput(K2SplineIndicatorsOutput{
		SlopeShareFP:     bytesToBase64(fpVecToBytes(ring63ToFP(aSlope))),
		InterceptShareFP: bytesToBase64(fpVecToBytes(ring63ToFP(bInt))),
		CLowShareFP:      bytesToBase64(fpVecToBytes(ring63ToFP(notCLow))), // NOT(c_low) for AND
		CHighShareFP:     bytesToBase64(fpVecToBytes(ring63ToFP(cHigh))),   // c_high for AND
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
