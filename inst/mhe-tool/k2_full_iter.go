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
	XmaFP       string  `json:"xma_fp"`
	RmbFP       string  `json:"rmb_fp"`
	SumResidual float64 `json:"sum_residual"`
}

type K2FullIterR3Phase2Output struct {
	Gradient    []float64 `json:"gradient"`
	SumResidual float64   `json:"sum_residual"`
}

func handleK2FullIterR3() {
	var input K2FullIterR3Input
	mpcReadInput(&input)

	n := input.N
	p := input.P
	fracBits := 20

	xShare := bytesToFPVec(base64ToBytes(input.XShareFP))
	muShare := bytesToFPVec(base64ToBytes(input.MuShareFP))
	yShare := bytesToFPVec(base64ToBytes(input.YShareFP))

	// Residual share in int64: r = mu - y (wrapping subtraction)
	residualShare := make([]FixedPoint, n)
	for i := 0; i < n; i++ {
		residualShare[i] = FPSub(muShare[i], yShare[i])
	}

	// Sum residual shares IN THE RING first, then convert to float ONCE.
	// Individual ToFloat64 of random shares gives wrong results due to wrapping.
	var sumResidualFP FixedPoint
	for i := 0; i < n; i++ {
		sumResidualFP += residualShare[i]
	}
	sumResidual := sumResidualFP.ToFloat64(fracBits)

	if input.Phase == 1 {
		aShare := bytesToFPVec(base64ToBytes(input.AShareFP))
		bShare := bytesToFPVec(base64ToBytes(input.BShareFP))

		xma := make([]FixedPoint, n*p)
		rmb := make([]FixedPoint, n)
		for i := range xma { xma[i] = FPSub(xShare[i], aShare[i]) }
		for i := range rmb { rmb[i] = FPSub(residualShare[i], bShare[i]) }

		mpcWriteOutput(K2FullIterR3Phase1Output{
			XmaFP:       bytesToBase64(fpVecToBytes(xma)),
			RmbFP:       bytesToBase64(fpVecToBytes(rmb)),
			SumResidual: sumResidual,
		})
		return
	}

	// Phase 2: Beaver matvec gradient in int64 ring
	aShare := bytesToFPVec(base64ToBytes(input.AShareFP))
	bShare := bytesToFPVec(base64ToBytes(input.BShareFP))
	cShare := bytesToFPVec(base64ToBytes(input.CShareFP))
	peerXMA := bytesToFPVec(base64ToBytes(input.PeerXmaFP))
	peerRMB := bytesToFPVec(base64ToBytes(input.PeerRmbFP))

	ownXMA := make([]FixedPoint, n*p)
	ownRMB := make([]FixedPoint, n)
	for i := range ownXMA { ownXMA[i] = FPSub(xShare[i], aShare[i]) }
	for i := range ownRMB { ownRMB[i] = FPSub(residualShare[i], bShare[i]) }

	// Reconstruct full (X-A) and (r-B) — int64 wrapping addition
	fullXMA := make([]FixedPoint, n*p)
	fullRMB := make([]FixedPoint, n)
	for i := range fullXMA { fullXMA[i] = FPAdd(ownXMA[i], peerXMA[i]) }
	for i := range fullRMB { fullRMB[i] = FPAdd(ownRMB[i], peerRMB[i]) }

	// Beaver formula: ALL int64 ring multiply (mul64, wrapping at 2^64)
	// NO per-term truncation. Truncate ONCE at the end.
	gRaw := make([]FixedPoint, p)
	copy(gRaw, cShare)

	for j := 0; j < p; j++ {
		for i := 0; i < n; i++ {
			// A[i,j] * fullRMB[i] — int64 ring multiply
			hi, lo := mul64(int64(aShare[i*p+j]), int64(fullRMB[i]))
			gRaw[j] += FixedPoint(rshift128(hi, lo, 0)) // no shift yet, accumulate raw

			// fullXMA[i,j] * B[i]
			hi2, lo2 := mul64(int64(fullXMA[i*p+j]), int64(bShare[i]))
			gRaw[j] += FixedPoint(rshift128(hi2, lo2, 0))
		}
	}

	if input.PartyID == 0 {
		for j := 0; j < p; j++ {
			for i := 0; i < n; i++ {
				hi, lo := mul64(int64(fullXMA[i*p+j]), int64(fullRMB[i]))
				gRaw[j] += FixedPoint(rshift128(hi, lo, 0))
			}
		}
	}

	// Wait — rshift128 with shift=0 just returns the low 64 bits (lo).
	// But mul64 returns (hi, lo) of a 128-bit product. The low 64 bits IS
	// the int64 ring multiply result (mod 2^64). So rshift128(hi, lo, 0) = lo.
	// This means gRaw is the UNTRUNCATED ring product sum.

	// Truncate by fracBits: right-shift each element
	// Party 0: simple right-shift (arithmetic, since int64)
	// Party 1: modulus - floor((modulus - share) / divisor) BUT for int64 ring (2^64),
	//          this simplifies to: -((-share) >> fracBits)
	gradient := make([]float64, p)
	for j := 0; j < p; j++ {
		var truncated FixedPoint
		if input.PartyID == 0 {
			truncated = FixedPoint(int64(gRaw[j]) >> fracBits)
		} else {
			neg := -gRaw[j] // int64 negation
			truncated = -FixedPoint(int64(neg) >> fracBits)
		}
		gradient[j] = truncated.ToFloat64(fracBits)
	}

	mpcWriteOutput(K2FullIterR3Phase2Output{
		Gradient:    gradient,
		SumResidual: sumResidual,
	})
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
	own := make([]FixedPoint, len(data))
	peer := make([]FixedPoint, len(data))
	for i := range data {
		own[i] = FixedPoint(int64(cryptoRandUint64K2()))
		peer[i] = data[i] - own[i]
	}
	mpcWriteOutput(K2SplitFPOutput{
		OwnShare:  bytesToBase64(fpVecToBytes(own)),
		PeerShare: bytesToBase64(fpVecToBytes(peer)),
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
	if input.FracBits <= 0 { input.FracBits = 20 }

	n := input.N
	pOwn := input.POwn
	pPeer := input.PPeer
	pTotal := pOwn + pPeer

	xOwn := bytesToFPVec(base64ToBytes(input.XOwnFP))
	xPeer := bytesToFPVec(base64ToBytes(input.XPeerFP))
	beta := bytesToFPVec(base64ToBytes(input.BetaFP))

	eta := make([]FixedPoint, n)
	for i := 0; i < n; i++ {
		var val FixedPoint
		for j := 0; j < pOwn; j++ {
			val = FPAdd(val, FPMulLocal(xOwn[i*pOwn+j], beta[j], input.FracBits))
		}
		for j := 0; j < pPeer; j++ {
			val = FPAdd(val, FPMulLocal(xPeer[i*pPeer+j], beta[pOwn+j], input.FracBits))
		}
		eta[i] = val
	}

	if input.IsPartyZero && input.Intercept != 0 {
		interceptFP := FromFloat64(input.Intercept, input.FracBits)
		for i := 0; i < n; i++ {
			eta[i] = FPAdd(eta[i], interceptFP)
		}
	}

	// Build full X share (own+peer interleaved)
	xFull := make([]FixedPoint, n*pTotal)
	for i := 0; i < n; i++ {
		for j := 0; j < pOwn; j++ { xFull[i*pTotal+j] = xOwn[i*pOwn+j] }
		for j := 0; j < pPeer; j++ { xFull[i*pTotal+pOwn+j] = xPeer[i*pPeer+j] }
	}

	mpcWriteOutput(struct {
		EtaFP   string `json:"eta_fp"`
		XFullFP string `json:"x_full_fp"`
	}{
		EtaFP:   bytesToBase64(fpVecToBytes(eta)),
		XFullFP: bytesToBase64(fpVecToBytes(xFull)),
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

	A := make([]FixedPoint, n*p)
	B := make([]FixedPoint, n)
	for i := range A { A[i] = FixedPoint(int64(cryptoRandUint64K2())) }
	for i := range B { B[i] = FixedPoint(int64(cryptoRandUint64K2())) }

	// C[j] = sum_i A[i,j] * B[i] — int64 ring multiply (wrapping at 2^64)
	C := make([]FixedPoint, p)
	for j := 0; j < p; j++ {
		for i := 0; i < n; i++ {
			hi, lo := mul64(int64(A[i*p+j]), int64(B[i]))
			C[j] += FixedPoint(rshift128(hi, lo, 0)) // low 64 bits = ring product
		}
	}

	// Split
	a0 := make([]FixedPoint, n*p); a1 := make([]FixedPoint, n*p)
	b0 := make([]FixedPoint, n); b1 := make([]FixedPoint, n)
	c0 := make([]FixedPoint, p); c1 := make([]FixedPoint, p)
	for i := range A { s := FixedPoint(int64(cryptoRandUint64K2())); a0[i] = s; a1[i] = A[i]-s }
	for i := range B { s := FixedPoint(int64(cryptoRandUint64K2())); b0[i] = s; b1[i] = B[i]-s }
	for i := range C { s := FixedPoint(int64(cryptoRandUint64K2())); c0[i] = s; c1[i] = C[i]-s }

	mpcWriteOutput(K2GenMatvecTriplesOutput{
		Party0A: bytesToBase64(fpVecToBytes(a0)),
		Party0B: bytesToBase64(fpVecToBytes(b0)),
		Party0C: bytesToBase64(fpVecToBytes(c0)),
		Party1A: bytesToBase64(fpVecToBytes(a1)),
		Party1B: bytesToBase64(fpVecToBytes(b1)),
		Party1C: bytesToBase64(fpVecToBytes(c1)),
	})
}
