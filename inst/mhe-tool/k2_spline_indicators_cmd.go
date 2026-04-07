// k2_spline_indicators_cmd.go: Spline indicator + assembly commands for DataSHIELD.
package main

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

