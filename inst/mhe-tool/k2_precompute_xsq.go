// k2_precompute_xsq.go: Pre-compute x²_j for diagonal Fisher.
package main

// ============================================================================
// Command: k2-precompute-xsq
// Pre-computes x²_j for each feature via Beaver Hadamard.
// Called ONCE before the iteration loop. Results stored in session.
// ============================================================================

type K2PrecomputeXSqInput struct {
	XFullFP  string `json:"x_full_fp"`  // base64 FP: n*p row-major
	N        int    `json:"n"`
	P        int    `json:"p"`
	FracBits int    `json:"frac_bits"`
	PartyID  int    `json:"party_id"`
	Phase    int    `json:"phase"` // 1 = R1, 2 = close
	// Beaver triples: p*n elements packed (one triple per feature)
	TripleA  string `json:"triple_a"`
	TripleB  string `json:"triple_b"`
	TripleC  string `json:"triple_c"` // phase 2 only
	// Peer messages (phase 2 only)
	PeerXMA  string `json:"peer_xma"`
	PeerYMB  string `json:"peer_ymb"`
}

type K2PrecomputeXSqPhase1Out struct {
	XMA string `json:"xma"` // base64 FP: p*n packed
	YMB string `json:"ymb"`
}

type K2PrecomputeXSqPhase2Out struct {
	XSqFP string `json:"xsq_fp"` // base64 FP: n*p row-major (x² shares)
}

func handleK2PrecomputeXSq() {
	var input K2PrecomputeXSqInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}

	ring := NewRing63(input.FracBits)
	n := input.N
	p := input.P
	xShare := fpToRing63(bytesToFPVec(base64ToBytes(input.XFullFP)))
	aAll := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleA)))
	bAll := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleB)))

	if input.Phase == 1 {
		// Phase 1: Beaver R1 for x_j * x_j (all p features)
		allXMA := make([]uint64, p*n)
		allYMB := make([]uint64, p*n)
		for j := 0; j < p; j++ {
			xj := make([]uint64, n)
			aj := make([]uint64, n)
			bj := make([]uint64, n)
			for i := 0; i < n; i++ {
				xj[i] = xShare[i*p+j]
				aj[i] = aAll[j*n+i]
				bj[i] = bAll[j*n+i]
			}
			beaver := BeaverTripleVec{A: aj, B: bj}
			_, msg := GenerateBatchedMultiplicationGateMessage(xj, xj, beaver, ring)
			copy(allXMA[j*n:], msg.XMinusAShares)
			copy(allYMB[j*n:], msg.YMinusBShares)
		}
		mpcWriteOutput(K2PrecomputeXSqPhase1Out{
			XMA: bytesToBase64(fpVecToBytes(ring63ToFP(allXMA))),
			YMB: bytesToBase64(fpVecToBytes(ring63ToFP(allYMB))),
		})
		return
	}

	// Phase 2: Beaver close → x²_j shares
	cAll := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleC)))
	peerXMA := fpToRing63(bytesToFPVec(base64ToBytes(input.PeerXMA)))
	peerYMB := fpToRing63(bytesToFPVec(base64ToBytes(input.PeerYMB)))

	xSqShare := make([]uint64, n*p)
	for j := 0; j < p; j++ {
		xj := make([]uint64, n)
		aj := make([]uint64, n)
		bj := make([]uint64, n)
		cj := make([]uint64, n)
		pxma := make([]uint64, n)
		pymb := make([]uint64, n)
		for i := 0; i < n; i++ {
			xj[i] = xShare[i*p+j]
			aj[i] = aAll[j*n+i]
			bj[i] = bAll[j*n+i]
			cj[i] = cAll[j*n+i]
			pxma[i] = peerXMA[j*n+i]
			pymb[i] = peerYMB[j*n+i]
		}
		beaver := BeaverTripleVec{A: aj, B: bj, C: cj}
		state, _ := GenerateBatchedMultiplicationGateMessage(xj, xj, beaver, ring)
		peerMsg := MultGateMessage{XMinusAShares: pxma, YMinusBShares: pymb}
		var xSqJ []uint64
		if input.PartyID == 0 {
			xSqJ = HadamardProductPartyZero(state, beaver, peerMsg, ring.FracBits, ring)
		} else {
			xSqJ = HadamardProductPartyOne(state, beaver, peerMsg, ring.FracBits, ring)
		}
		for i := 0; i < n; i++ {
			xSqShare[i*p+j] = xSqJ[i]
		}
	}

	mpcWriteOutput(K2PrecomputeXSqPhase2Out{
		XSqFP: bytesToBase64(fpVecToBytes(ring63ToFP(xSqShare))),
	})
}

