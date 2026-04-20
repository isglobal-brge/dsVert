// k2_full_iter.go: All-int64 gradient computation for K=2 secure training.
//
// ALL arithmetic uses FixedPoint (int64, wrapping at 2^64) to be consistent
// with the poly_eval and Beaver steps that also use int64 FixedPoint.
//
// The Beaver formula uses RING multiply (int64 * int64 → 128-bit → mod 2^64)
// with truncation (right-shift by fracBits) applied ONCE at the end using
// the asymmetric truncation from the C++ code.

package main

// K2FullIterR3Input: gradient computation phase 1 or 2.
type K2FullIterR3Input struct {
	XShareFP  string `json:"x_share_fp"`
	MuShareFP string `json:"mu_share_fp"`
	YShareFP  string `json:"y_share_fp"`
	AShareFP  string `json:"a_share_fp"`
	BShareFP  string `json:"b_share_fp"`
	CShareFP  string `json:"c_share_fp"`
	PeerXmaFP string `json:"peer_xma_fp"`
	PeerRmbFP string `json:"peer_rmb_fp"`
	N         int    `json:"n"`
	P         int    `json:"p"`
	PartyID   int    `json:"party_id"`
	Phase     int    `json:"phase"`
}

type K2FullIterR3Phase1Output struct {
	XmaFP          string  `json:"xma_fp"`
	RmbFP          string  `json:"rmb_fp"`
	SumResidual    float64 `json:"sum_residual"`
	SumResidualFP  string  `json:"sum_residual_fp"` // Ring63 value as base64 FP (for ring-level aggregation)
}

type K2FullIterR3Phase2Output struct {
	Gradient       []float64 `json:"gradient"`
	SumResidual    float64   `json:"sum_residual"`
	SumResidualFP  string    `json:"sum_residual_fp"`
	GradientFP     string    `json:"gradient_fp"`  // Ring63 gradient shares as base64 FP
}

func handleK2FullIterR3() {
	var input K2FullIterR3Input
	mpcReadInput(&input)

	n := input.N
	p := input.P
	fracBits := K2DefaultFracBits

	ring := NewRing63(fracBits)

	xShare := bytesToFPVec(base64ToBytes(input.XShareFP))
	muShare := bytesToFPVec(base64ToBytes(input.MuShareFP))
	yShare := bytesToFPVec(base64ToBytes(input.YShareFP))

	// Convert to Ring63 for all arithmetic (mu and y are Ring63 values stored as FP)
	muR63 := fpToRing63(muShare)
	yR63 := fpToRing63(yShare)

	// Residual share in Ring63: r = mu - y
	residualR63 := make([]uint64, n)
	for i := 0; i < n; i++ {
		residualR63[i] = ring.Sub(muR63[i], yR63[i])
	}

	// Also keep FP version for the residual shares used in Phase 1/2
	residualShare := ring63ToFP(residualR63)

	// Sum residual in Ring63, then convert to float
	var sumResidualR63 uint64
	for i := 0; i < n; i++ {
		sumResidualR63 = ring.Add(sumResidualR63, residualR63[i])
	}
	sumResidual := ring.ToDouble(sumResidualR63)

	if input.Phase == 1 {
		aShare := bytesToFPVec(base64ToBytes(input.AShareFP))
		bShare := bytesToFPVec(base64ToBytes(input.BShareFP))

		// Compute (X-A) and (r-B) in Ring63
		xR63 := fpToRing63(xShare)
		aR63 := fpToRing63(aShare)
		resR63 := fpToRing63(residualShare)
		bR63 := fpToRing63(bShare)

		xma := make([]uint64, n*p)
		rmb := make([]uint64, n)
		for i := range xma { xma[i] = ring.Sub(xR63[i], aR63[i]) }
		for i := range rmb { rmb[i] = ring.Sub(resR63[i], bR63[i]) }

		mpcWriteOutput(K2FullIterR3Phase1Output{
			XmaFP:          bytesToBase64(fpVecToBytes(ring63ToFP(xma))),
			RmbFP:          bytesToBase64(fpVecToBytes(ring63ToFP(rmb))),
			SumResidual:    sumResidual,
			SumResidualFP:  bytesToBase64(fpVecToBytes(ring63ToFP([]uint64{sumResidualR63}))),
		})
		return
	}

	// Phase 2: Beaver matvec gradient using Ring63 arithmetic
	aShare := bytesToFPVec(base64ToBytes(input.AShareFP))
	bShare := bytesToFPVec(base64ToBytes(input.BShareFP))
	cShare := bytesToFPVec(base64ToBytes(input.CShareFP))
	peerXMA := bytesToFPVec(base64ToBytes(input.PeerXmaFP))
	peerRMB := bytesToFPVec(base64ToBytes(input.PeerRmbFP))

	// Convert everything to Ring63
	xR63 := fpToRing63(xShare)
	aR63 := fpToRing63(aShare)
	bR63 := fpToRing63(bShare)
	cR63 := fpToRing63(cShare)
	resR63 := fpToRing63(residualShare)

	// Own (X-A) and (r-B) in Ring63
	ownXMA := make([]uint64, n*p)
	ownRMB := make([]uint64, n)
	for i := range ownXMA { ownXMA[i] = ring.Sub(xR63[i], aR63[i]) }
	for i := range ownRMB { ownRMB[i] = ring.Sub(resR63[i], bR63[i]) }

	// Reconstruct full (X-A) and (r-B) in Ring63
	peerXMAR63 := fpToRing63(peerXMA)
	peerRMBR63 := fpToRing63(peerRMB)
	fullXMA := make([]uint64, n*p)
	fullRMB := make([]uint64, n)
	for i := range fullXMA { fullXMA[i] = ring.Add(ownXMA[i], peerXMAR63[i]) }
	for i := range fullRMB { fullRMB[i] = ring.Add(ownRMB[i], peerRMBR63[i]) }

	// Beaver matvec formula in Ring63: g[j] = C[j] + sum_i(A[i,j]*fullRMB[i]) + sum_i(fullXMA[i,j]*B[i]) + [P0]*sum_i(fullXMA[i,j]*fullRMB[i])
	// Each ring product is modMulBig63 (matching the Google C++ code).
	// Accumulate raw (untruncated) products, then truncate once at the end.
	gRaw := make([]uint64, p)
	copy(gRaw, cR63)

	for j := 0; j < p; j++ {
		for i := 0; i < n; i++ {
			// A[i,j] * fullRMB[i] in Ring63
			prod1 := modMulBig63(aR63[i*p+j], fullRMB[i], ring.Modulus)
			gRaw[j] = ring.Add(gRaw[j], prod1)

			// fullXMA[i,j] * B[i] in Ring63
			prod2 := modMulBig63(fullXMA[i*p+j], bR63[i], ring.Modulus)
			gRaw[j] = ring.Add(gRaw[j], prod2)
		}
	}

	if input.PartyID == 0 {
		for j := 0; j < p; j++ {
			for i := 0; i < n; i++ {
				prod := modMulBig63(fullXMA[i*p+j], fullRMB[i], ring.Modulus)
				gRaw[j] = ring.Add(gRaw[j], prod)
			}
		}
	}

	// Asymmetric truncation using validated TruncateSharePartyZero/One
	divisor := uint64(1) << fracBits
	var truncated []uint64
	if input.PartyID == 0 {
		truncated = TruncateSharePartyZero(gRaw, divisor, ring.Modulus)
	} else {
		truncated = TruncateSharePartyOne(gRaw, divisor, ring.Modulus)
	}

	gradient := make([]float64, p)
	for j := 0; j < p; j++ {
		gradient[j] = ring.ToDouble(truncated[j])
	}

	mpcWriteOutput(K2FullIterR3Phase2Output{
		Gradient:       gradient,
		SumResidual:    sumResidual,
		SumResidualFP:  bytesToBase64(fpVecToBytes(ring63ToFP([]uint64{sumResidualR63}))),
		GradientFP:     bytesToBase64(fpVecToBytes(ring63ToFP(truncated))),
	})
}

// --- Ring63 aggregation (client-side) ---

type K2Ring63AggregateInput struct {
	ShareA   string `json:"share_a"`   // base64 FP (Ring63 share from party 0)
	ShareB   string `json:"share_b"`   // base64 FP (Ring63 share from party 1)
	FracBits int    `json:"frac_bits"`
	// Ring selector. "" or "ring63" (default, 8-byte input records) /
	// "ring127" (16-byte Uint128 input records). Output is []float64 either
	// way — the aggregate op is what converts shares back to plaintext
	// floats for the client. Despite the name, the handler supports both
	// rings since step 5a (task #116 Cox/LMM plumbing).
	Ring string `json:"ring"`
}

type K2Ring63AggregateOutput struct {
	Values []float64 `json:"values"` // reconstructed float64 values
}

func handleK2Ring63Aggregate() {
	var input K2Ring63AggregateInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}

	// Ring127 dispatch — parse 16-byte input records, add in Ring127, decode.
	if input.Ring == "ring127" {
		ring127 := NewRing127(input.FracBits)
		a127 := bytesToUint128Vec(base64ToBytes(input.ShareA))
		b127 := bytesToUint128Vec(base64ToBytes(input.ShareB))
		n := len(a127)
		values := make([]float64, n)
		for i := 0; i < n; i++ {
			values[i] = ring127.ToDouble(ring127.Add(a127[i], b127[i]))
		}
		mpcWriteOutput(K2Ring63AggregateOutput{Values: values})
		return
	}
	if input.Ring != "" && input.Ring != "ring63" {
		panic("k2-ring63-aggregate: unknown ring='" + input.Ring + "'")
	}

	ring := NewRing63(input.FracBits)
	aR63 := fpToRing63(bytesToFPVec(base64ToBytes(input.ShareA)))
	bR63 := fpToRing63(bytesToFPVec(base64ToBytes(input.ShareB)))

	n := len(aR63)
	values := make([]float64, n)
	for i := 0; i < n; i++ {
		sum := ring.Add(aR63[i], bR63[i])
		values[i] = ring.ToDouble(sum)
	}
	mpcWriteOutput(K2Ring63AggregateOutput{Values: values})
}

// --- Utility commands ---

type K2SplitFPInput struct {
	DataFP string `json:"data_fp"`
	N      int    `json:"n"`
}

type K2SplitFPOutput struct {
	OwnShare  string `json:"own_share"`
	PeerShare string `json:"peer_share"`
}

func handleK2SplitFPShare() {
	var input K2SplitFPInput
	mpcReadInput(&input)
	data := bytesToFPVec(base64ToBytes(input.DataFP))
	ring := NewRing63(K2DefaultFracBits)

	// Convert data to Ring63 and split using Ring63 arithmetic
	// This ensures shares are valid Ring63 values that sum to the original mod 2^63
	dataR63 := fpToRing63(data)
	ownR63 := make([]uint64, len(data))
	peerR63 := make([]uint64, len(data))
	for i := range dataR63 {
		ownR63[i], peerR63[i] = ring.SplitShare(dataR63[i])
	}

	mpcWriteOutput(K2SplitFPOutput{
		OwnShare:  bytesToBase64(fpVecToBytes(ring63ToFP(ownR63))),
		PeerShare: bytesToBase64(fpVecToBytes(ring63ToFP(peerR63))),
	})
}

type K2ComputeEtaFPInput struct {
	XOwnFP    string  `json:"x_own_fp"`
	XPeerFP   string  `json:"x_peer_fp"`
	BetaFP    string  `json:"beta_fp"`
	Intercept float64 `json:"intercept"`
	IsPartyZero bool  `json:"is_party_zero"`
	N         int     `json:"n"`
	POwn      int     `json:"p_own"`
	PPeer     int     `json:"p_peer"`
	FracBits  int     `json:"frac_bits"`
}

func handleK2ComputeEtaFP() {
	var input K2ComputeEtaFPInput
	mpcReadInput(&input)
	if input.FracBits <= 0 { input.FracBits = K2DefaultFracBits }

	ring := NewRing63(input.FracBits)
	n := input.N
	pOwn := input.POwn
	pPeer := input.PPeer
	pTotal := pOwn + pPeer

	// X shares are Ring63 values stored as FP
	xOwnR63 := fpToRing63(bytesToFPVec(base64ToBytes(input.XOwnFP)))
	xPeerR63 := fpToRing63(bytesToFPVec(base64ToBytes(input.XPeerFP)))
	// Beta is a public float64 vector encoded as FP
	betaFP := bytesToFPVec(base64ToBytes(input.BetaFP))

	// Compute eta = X_share * beta using Ring63 ScalarVectorProduct
	// Beta values are public, X shares are secret → use asymmetric P0/P1 truncation
	etaR63 := make([]uint64, n)
	for i := 0; i < n; i++ {
		if input.IsPartyZero {
			for j := 0; j < pOwn; j++ {
				betaFloat := betaFP[j].ToFloat64(input.FracBits)
				term := ScalarVectorProductPartyZero(betaFloat, []uint64{xOwnR63[i*pOwn+j]}, ring)
				etaR63[i] = ring.Add(etaR63[i], term[0])
			}
			for j := 0; j < pPeer; j++ {
				betaFloat := betaFP[pOwn+j].ToFloat64(input.FracBits)
				term := ScalarVectorProductPartyZero(betaFloat, []uint64{xPeerR63[i*pPeer+j]}, ring)
				etaR63[i] = ring.Add(etaR63[i], term[0])
			}
		} else {
			for j := 0; j < pPeer; j++ {
				betaFloat := betaFP[j].ToFloat64(input.FracBits)
				term := ScalarVectorProductPartyOne(betaFloat, []uint64{xPeerR63[i*pPeer+j]}, ring)
				etaR63[i] = ring.Add(etaR63[i], term[0])
			}
			for j := 0; j < pOwn; j++ {
				betaFloat := betaFP[pPeer+j].ToFloat64(input.FracBits)
				term := ScalarVectorProductPartyOne(betaFloat, []uint64{xOwnR63[i*pOwn+j]}, ring)
				etaR63[i] = ring.Add(etaR63[i], term[0])
			}
		}
	}

	// Intercept: only Party Zero adds the public intercept
	if input.IsPartyZero && input.Intercept != 0 {
		interceptR63 := ring.FromDouble(input.Intercept)
		for i := 0; i < n; i++ {
			etaR63[i] = ring.Add(etaR63[i], interceptR63)
		}
	}

	// Build full X share in CANONICAL order: [coord features | nonlabel features]
	xFullR63 := make([]uint64, n*pTotal)
	for i := 0; i < n; i++ {
		if input.IsPartyZero {
			for j := 0; j < pOwn; j++ { xFullR63[i*pTotal+j] = xOwnR63[i*pOwn+j] }
			for j := 0; j < pPeer; j++ { xFullR63[i*pTotal+pOwn+j] = xPeerR63[i*pPeer+j] }
		} else {
			for j := 0; j < pPeer; j++ { xFullR63[i*pTotal+j] = xPeerR63[i*pPeer+j] }
			for j := 0; j < pOwn; j++ { xFullR63[i*pTotal+pPeer+j] = xOwnR63[i*pOwn+j] }
		}
	}

	mpcWriteOutput(struct {
		EtaFP   string `json:"eta_fp"`
		XFullFP string `json:"x_full_fp"`
	}{
		EtaFP:   bytesToBase64(fpVecToBytes(ring63ToFP(etaR63))),
		XFullFP: bytesToBase64(fpVecToBytes(ring63ToFP(xFullR63))),
	})
}

// Matvec triple generation (int64 ring, ring multiply for C)
type K2GenMatvecTriplesInput struct {
	N int `json:"n"`
	P int `json:"p"`
}

type K2GenMatvecTriplesOutput struct {
	Party0A string `json:"party0_a"`
	Party0B string `json:"party0_b"`
	Party0C string `json:"party0_c"`
	Party1A string `json:"party1_a"`
	Party1B string `json:"party1_b"`
	Party1C string `json:"party1_c"`
}

func handleK2GenMatvecTriples() {
	var input K2GenMatvecTriplesInput
	mpcReadInput(&input)

	n := input.N
	p := input.P
	ring := NewRing63(K2DefaultFracBits)

	// Generate A (n*p) and B (n) in Ring63
	A := make([]uint64, n*p)
	B := make([]uint64, n)
	for i := range A { A[i] = cryptoRandUint64K2() % ring.Modulus }
	for i := range B { B[i] = cryptoRandUint64K2() % ring.Modulus }

	// C[j] = sum_i A[i,j] * B[i] in Ring63 (modMulBig63, matching Beaver close)
	C := make([]uint64, p)
	for j := 0; j < p; j++ {
		for i := 0; i < n; i++ {
			prod := modMulBig63(A[i*p+j], B[i], ring.Modulus)
			C[j] = ring.Add(C[j], prod)
		}
	}

	// Split in Ring63
	a0 := make([]uint64, n*p); a1 := make([]uint64, n*p)
	b0 := make([]uint64, n); b1 := make([]uint64, n)
	c0 := make([]uint64, p); c1 := make([]uint64, p)
	for i := range A { a0[i], a1[i] = ring.SplitShare(A[i]) }
	for i := range B { b0[i], b1[i] = ring.SplitShare(B[i]) }
	for i := range C { c0[i], c1[i] = ring.SplitShare(C[i]) }

	// Convert Ring63 to FP for base64 transport
	mpcWriteOutput(K2GenMatvecTriplesOutput{
		Party0A: bytesToBase64(fpVecToBytes(ring63ToFP(a0))),
		Party0B: bytesToBase64(fpVecToBytes(ring63ToFP(b0))),
		Party0C: bytesToBase64(fpVecToBytes(ring63ToFP(c0))),
		Party1A: bytesToBase64(fpVecToBytes(ring63ToFP(a1))),
		Party1B: bytesToBase64(fpVecToBytes(ring63ToFP(b1))),
		Party1C: bytesToBase64(fpVecToBytes(ring63ToFP(c1))),
	})
}
