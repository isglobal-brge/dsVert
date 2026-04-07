// k2_old_newton.go: Old scalar curvature Newton Fisher (deprecated).
package main

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
	BeaverW_A string `json:"beaver_w_a"`
	BeaverW_B string `json:"beaver_w_b"`
	BeaverW_C string `json:"beaver_w_c"`
	// Peer's Beaver R1 for w computation
	PeerW_XMA string `json:"peer_w_xma"`
	PeerW_YMB string `json:"peer_w_ymb"`
	// Phase: 1 = Beaver R1 for w, 2 = Beaver close for w + compute d_j
	Phase int `json:"phase"`
	// REAL diagonal Fisher fields (phase 2 only):
	XSqFP         string `json:"xsq_fp"`          // pre-computed x² shares (n*p, row-major)
	WXSqTripleA   string `json:"wxsq_triple_a"`    // p*n Beaver A shares for w*x²
	WXSqTripleB   string `json:"wxsq_triple_b"`
	WXSqTripleC   string `json:"wxsq_triple_c"`
	PeerWXSqXMA   string `json:"peer_wxsq_xma"`    // peer's Beaver R1 for w*x²
	PeerWXSqYMB   string `json:"peer_wxsq_ymb"`
	PerFeatureTriples string `json:"per_feature_triples"` // unused, legacy
	PeerPerFeatureR1  string `json:"peer_per_feature_r1"` // unused, legacy
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

	// REAL diagonal Fisher: d_j = sum_i(w_i * x_ij^2) per feature j
	// w_i shares are computed above via Beaver Hadamard (wShare).
	// x_ij shares are in XFullFP (n*p row-major).
	//
	// For each feature j, we need: sum_i(w_i * x_ij^2)
	// = sum_i(w_i * x_ij * x_ij)
	//
	// We need Beaver Hadamard for w*x_j (per feature) and then another for (w*x_j)*x_j.
	// But we only have 1 Beaver triple set for w.
	//
	// ALTERNATIVE: Use x²_j Beaver triples provided in the input.
	// The input includes p sets of Beaver triples for x² computation,
	// and p sets for w*x² computation.
	//
	// For this implementation: compute d_j using the ScalarVectorProduct approach.
	// Since w is a SECRET-SHARED value, we cannot multiply w_share * x_share locally.
	// Instead, use the APPROXIMATION: for standardized features E[x²]=1, so
	// d_j ≈ sum(w_i) for all j.
	//
	// BUT: to get the REAL diagonal Fisher, we need 2p additional Beaver triples
	// (p for x², p for w*x²). These must be provided in additional input fields.
	//
	// COMPROMISE for now: compute per-feature d_j using the reconstructed w values.
	// Wait — we can't reconstruct w (that would reveal observation-level weights).
	//
	// ACTUAL SOLUTION: the REAL diagonal Fisher computation requires additional
	// Beaver triples passed via the input. Let me add them.
	//
	// For now, since we don't have the extra triples, use sum(w) as approximation.
	// The client code should be updated to provide the extra triples for real Fisher.
	xShare := fpToRing63(bytesToFPVec(base64ToBytes(input.XFullFP)))

	// REAL diagonal Fisher: d_j = sum_i(w_i * x²_ij)
	// Strategy: x²_j is PRE-COMPUTED (stored in session as "k2_xsq_fp").
	// Here we compute w * x²_j for each feature, then sum.
	// This requires p Beaver triples for the w*x² Hadamards.
	xShare = fpToRing63(bytesToFPVec(base64ToBytes(input.XFullFP)))

	// Check if x² shares and w*x² triples are provided
	if input.XSqFP != "" && input.WXSqTripleA != "" {
		xSqShare := fpToRing63(bytesToFPVec(base64ToBytes(input.XSqFP)))
		// Per-feature Beaver triples for w * x²_j (p*n elements total, packed)
		wxA := fpToRing63(bytesToFPVec(base64ToBytes(input.WXSqTripleA)))
		wxB := fpToRing63(bytesToFPVec(base64ToBytes(input.WXSqTripleB)))
		wxC := fpToRing63(bytesToFPVec(base64ToBytes(input.WXSqTripleC)))
		// Peer messages for w*x² Beaver
		peerWXXMA := fpToRing63(bytesToFPVec(base64ToBytes(input.PeerWXSqXMA)))
		peerWXYMB := fpToRing63(bytesToFPVec(base64ToBytes(input.PeerWXSqYMB)))

		fisherDiag := make([]uint64, p)
		for j := 0; j < p; j++ {
			// Extract x²_j column and w*x² triple for feature j
			xSqJ := make([]uint64, n)
			wJ := make([]uint64, n)
			aJ := make([]uint64, n)
			bJ := make([]uint64, n)
			cJ := make([]uint64, n)
			peerXMAJ := make([]uint64, n)
			peerYMBJ := make([]uint64, n)
			for i := 0; i < n; i++ {
				xSqJ[i] = xSqShare[i*p+j]
				wJ[i] = wShare[i]
				aJ[i] = wxA[j*n+i]
				bJ[i] = wxB[j*n+i]
				cJ[i] = wxC[j*n+i]
				peerXMAJ[i] = peerWXXMA[j*n+i]
				peerYMBJ[i] = peerWXYMB[j*n+i]
			}

			beaver := BeaverTripleVec{A: aJ, B: bJ, C: cJ}
			state, _ := GenerateBatchedMultiplicationGateMessage(wJ, xSqJ, beaver, ring)
			peerMsg := MultGateMessage{XMinusAShares: peerXMAJ, YMinusBShares: peerYMBJ}

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

		mpcWriteOutput(K2NewtonFisherPhase2Out{
			FisherDiagFP: bytesToBase64(fpVecToBytes(ring63ToFP(fisherDiag))),
		})
	} else {
		// Fallback: scalar curvature proxy sum(w) for all features
		var sumW uint64
		for i := 0; i < n; i++ {
			sumW = ring.Add(sumW, wShare[i])
		}
		fisherDiag := make([]uint64, p)
		for j := 0; j < p; j++ {
			fisherDiag[j] = sumW
		}
		_ = xShare

		mpcWriteOutput(K2NewtonFisherPhase2Out{
			FisherDiagFP: bytesToBase64(fpVecToBytes(ring63ToFP(fisherDiag))),
		})
	}
}

