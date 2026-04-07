// k2_newton_fisher.go: Real diagonal Fisher for Newton-IRLS.
//
// 3-phase protocol:
//   Phase 1: Beaver R1 for w = mu*(1-mu)
//   Phase 2: Beaver close for w + Beaver R1 for w*x²_j (all p features)
//   Phase 3: Beaver close for w*x²_j → d_j = sum(w*x²_j) shares
//
// Disclosed per iteration: d_j for j=1..p (aggregate optimization summary).
// Non-disclosive: these are sums over n observations, not observation-level.

package main

type K2NewtonFisherRealInput struct {
	Phase    int    `json:"phase"`    // 1, 2, or 3
	PartyID  int    `json:"party_id"`
	FracBits int    `json:"frac_bits"`
	N        int    `json:"n"`
	P        int    `json:"p"`
	// mu share (all phases — recomputes 1-mu internally)
	MuShareFP string `json:"mu_share_fp"`
	// x_full share (phase 2+3: for extracting x_j columns)
	XFullFP string `json:"x_full_fp"`
	// x² share (phase 2+3: pre-computed)
	XSqFP string `json:"xsq_fp"`
	// Beaver triple for w (all phases)
	WTripleA string `json:"w_a"`
	WTripleB string `json:"w_b"`
	WTripleC string `json:"w_c"` // phase 2+3 only
	// Peer's w Beaver R1 (phase 2+3)
	PeerW_XMA string `json:"peer_w_xma"`
	PeerW_YMB string `json:"peer_w_ymb"`
	// Beaver triples for w*x² (p*n elements packed, phase 2+3)
	WXTripleA string `json:"wx_a"`
	WXTripleB string `json:"wx_b"`
	WXTripleC string `json:"wx_c"` // phase 3 only
	// Peer's w*x² Beaver R1 (phase 3 only)
	PeerWX_XMA string `json:"peer_wx_xma"`
	PeerWX_YMB string `json:"peer_wx_ymb"`
}

type K2FisherPhase1Out struct {
	W_XMA string `json:"w_xma"`
	W_YMB string `json:"w_ymb"`
}

type K2FisherPhase2Out struct {
	// w*x² Beaver R1 messages (p*n elements packed)
	WX_XMA string `json:"wx_xma"`
	WX_YMB string `json:"wx_ymb"`
}

type K2FisherPhase3Out struct {
	// d_j shares (p elements)
	FisherDiagFP string `json:"fisher_diag_fp"`
}

func handleK2NewtonFisherReal() {
	var input K2NewtonFisherRealInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}

	ring := NewRing63(input.FracBits)
	n := input.N
	p := input.P

	// Decode mu share
	muShare := fpToRing63(bytesToFPVec(base64ToBytes(input.MuShareFP)))

	// Compute 1 - mu
	oneFP := ring.FromDouble(1.0)
	oneMinusMu := make([]uint64, n)
	for i := 0; i < n; i++ {
		if input.PartyID == 0 {
			oneMinusMu[i] = ring.Sub(oneFP, muShare[i])
		} else {
			oneMinusMu[i] = ring.Sub(0, muShare[i])
		}
	}

	// Decode w Beaver triple
	wA := fpToRing63(bytesToFPVec(base64ToBytes(input.WTripleA)))
	wB := fpToRing63(bytesToFPVec(base64ToBytes(input.WTripleB)))

	switch input.Phase {
	case 1:
		// Phase 1: Beaver R1 for w = mu * (1-mu)
		wBeaver := BeaverTripleVec{A: wA, B: wB}
		_, wMsg := GenerateBatchedMultiplicationGateMessage(muShare, oneMinusMu, wBeaver, ring)
		mpcWriteOutput(K2FisherPhase1Out{
			W_XMA: bytesToBase64(fpVecToBytes(ring63ToFP(wMsg.XMinusAShares))),
			W_YMB: bytesToBase64(fpVecToBytes(ring63ToFP(wMsg.YMinusBShares))),
		})

	case 2:
		// Phase 2: Beaver close for w + Beaver R1 for w*x²_j

		// Close w Beaver
		wC := fpToRing63(bytesToFPVec(base64ToBytes(input.WTripleC)))
		wBeaver := BeaverTripleVec{A: wA, B: wB, C: wC}
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

		// Now compute Beaver R1 for w * x²_j for each feature j
		xSqShare := fpToRing63(bytesToFPVec(base64ToBytes(input.XSqFP)))
		wxA := fpToRing63(bytesToFPVec(base64ToBytes(input.WXTripleA)))
		wxB := fpToRing63(bytesToFPVec(base64ToBytes(input.WXTripleB)))

		allXMA := make([]uint64, p*n)
		allYMB := make([]uint64, p*n)
		for j := 0; j < p; j++ {
			// Extract w and x²_j for this feature
			wj := make([]uint64, n)
			xsqJ := make([]uint64, n)
			aj := make([]uint64, n)
			bj := make([]uint64, n)
			for i := 0; i < n; i++ {
				wj[i] = wShare[i]
				xsqJ[i] = xSqShare[i*p+j]
				aj[i] = wxA[j*n+i]
				bj[i] = wxB[j*n+i]
			}
			beaver := BeaverTripleVec{A: aj, B: bj}
			_, msg := GenerateBatchedMultiplicationGateMessage(wj, xsqJ, beaver, ring)
			copy(allXMA[j*n:], msg.XMinusAShares)
			copy(allYMB[j*n:], msg.YMinusBShares)
		}

		mpcWriteOutput(K2FisherPhase2Out{
			WX_XMA: bytesToBase64(fpVecToBytes(ring63ToFP(allXMA))),
			WX_YMB: bytesToBase64(fpVecToBytes(ring63ToFP(allYMB))),
		})

	case 3:
		// Phase 3: Beaver close for w*x²_j → d_j = sum(w*x²_j)

		// Recompute w (same as phase 2)
		wC := fpToRing63(bytesToFPVec(base64ToBytes(input.WTripleC)))
		wBeaver := BeaverTripleVec{A: wA, B: wB, C: wC}
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

		// Close w*x² Beaver for each feature
		xSqShare := fpToRing63(bytesToFPVec(base64ToBytes(input.XSqFP)))
		wxA := fpToRing63(bytesToFPVec(base64ToBytes(input.WXTripleA)))
		wxB := fpToRing63(bytesToFPVec(base64ToBytes(input.WXTripleB)))
		wxC := fpToRing63(bytesToFPVec(base64ToBytes(input.WXTripleC)))
		peerWXXMA := fpToRing63(bytesToFPVec(base64ToBytes(input.PeerWX_XMA)))
		peerWXYMB := fpToRing63(bytesToFPVec(base64ToBytes(input.PeerWX_YMB)))

		fisherDiag := make([]uint64, p)
		for j := 0; j < p; j++ {
			wj := make([]uint64, n)
			xsqJ := make([]uint64, n)
			aj := make([]uint64, n)
			bj := make([]uint64, n)
			cj := make([]uint64, n)
			pxma := make([]uint64, n)
			pymb := make([]uint64, n)
			for i := 0; i < n; i++ {
				wj[i] = wShare[i]
				xsqJ[i] = xSqShare[i*p+j]
				aj[i] = wxA[j*n+i]
				bj[i] = wxB[j*n+i]
				cj[i] = wxC[j*n+i]
				pxma[i] = peerWXXMA[j*n+i]
				pymb[i] = peerWXYMB[j*n+i]
			}
			beaver := BeaverTripleVec{A: aj, B: bj, C: cj}
			state, _ := GenerateBatchedMultiplicationGateMessage(wj, xsqJ, beaver, ring)
			peerMsg := MultGateMessage{XMinusAShares: pxma, YMinusBShares: pymb}

			var wxSqJ []uint64
			if input.PartyID == 0 {
				wxSqJ = HadamardProductPartyZero(state, beaver, peerMsg, ring.FracBits, ring)
			} else {
				wxSqJ = HadamardProductPartyOne(state, beaver, peerMsg, ring.FracBits, ring)
			}

			// d_j = sum(w * x²_j)
			var sumJ uint64
			for i := 0; i < n; i++ {
				sumJ = ring.Add(sumJ, wxSqJ[i])
			}
			fisherDiag[j] = sumJ
		}

		mpcWriteOutput(K2FisherPhase3Out{
			FisherDiagFP: bytesToBase64(fpVecToBytes(ring63ToFP(fisherDiag))),
		})
	}
}
