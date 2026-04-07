// k2_gaussian_oneshot.go: One-shot Gaussian solve via Beaver cross-products.
//
// Computes X^T X and X^T y securely via batched Beaver Hadamard products.
// For Gaussian GLM, beta = solve(X^T X/n + lambda*I, X^T y/n) — no iterations.
//
// Protocol (2 phases):
//   Phase 1: Beaver R1 for all column cross-products + X^T y
//   Phase 2: Beaver close + sum → shares of X^T X and X^T y
//
// Beaver products needed: p*p cross-products (X[:,j]*X[:,k]) + p products (X[:,j]*y)
// Total elements: (p*p + p) * n, batched in one Beaver round.

package main

type K2GaussianOneshotInput struct {
	Phase    int    `json:"phase"`      // 1 or 2
	PartyID  int    `json:"party_id"`
	FracBits int    `json:"frac_bits"`
	N        int    `json:"n"`
	P        int    `json:"p"`
	XFullFP  string `json:"x_full_fp"`  // n*p row-major
	YShareFP string `json:"y_share_fp"` // n elements
	// Beaver triples: (p*p + p) * n elements packed
	TripleA string `json:"triple_a"`
	TripleB string `json:"triple_b"`
	TripleC string `json:"triple_c"` // phase 2 only
	// Peer R1 (phase 2 only)
	PeerXMA string `json:"peer_xma"`
	PeerYMB string `json:"peer_ymb"`
}

type K2GaussianOneshotPhase1Out struct {
	// Local X^T X and X^T y (each server computes independently)
	LocalXtXFP string `json:"local_xtx_fp"` // p*p elements
	LocalXtYFP string `json:"local_xty_fp"` // p elements
	// Beaver R1 messages for cross-products
	XMA string `json:"xma"` // (p*p + p) * n elements
	YMB string `json:"ymb"`
}

type K2GaussianOneshotPhase2Out struct {
	// Cross-product shares (from Beaver close + sum)
	CrossXtXFP string `json:"cross_xtx_fp"` // p*p elements
	CrossXtYFP string `json:"cross_xty_fp"` // p elements
}

func handleK2GaussianOneshot() {
	var input K2GaussianOneshotInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}

	ring := NewRing63(input.FracBits)
	n := input.N
	p := input.P
	totalPairs := p*p + p // p*p for X^T X + p for X^T y

	xShare := fpToRing63(bytesToFPVec(base64ToBytes(input.XFullFP)))
	yShare := fpToRing63(bytesToFPVec(base64ToBytes(input.YShareFP)))

	// Extract columns from row-major X_share
	xCols := make([][]uint64, p)
	for j := 0; j < p; j++ {
		xCols[j] = make([]uint64, n)
		for i := 0; i < n; i++ {
			xCols[j][i] = xShare[i*p+j]
		}
	}

	// Build expanded operand vectors for all pairs:
	// First p*p pairs: (col_j, col_k) for j=0..p-1, k=0..p-1
	// Last p pairs: (col_j, y) for j=0..p-1
	opA := make([]uint64, totalPairs*n)
	opB := make([]uint64, totalPairs*n)
	idx := 0
	for j := 0; j < p; j++ {
		for k := 0; k < p; k++ {
			copy(opA[idx*n:], xCols[j])
			copy(opB[idx*n:], xCols[k])
			idx++
		}
	}
	for j := 0; j < p; j++ {
		copy(opA[idx*n:], xCols[j])
		copy(opB[idx*n:], yShare)
		idx++
	}

	aAll := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleA)))
	bAll := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleB)))

	if input.Phase == 1 {
		// Phase 1: compute local X^T X and X^T y + Beaver R1

		// Local: X_share^T * X_share (p×p) and X_share^T * y_share (p)
		localXtX := make([]uint64, p*p)
		for j := 0; j < p; j++ {
			for k := 0; k < p; k++ {
				var s uint64
				for i := 0; i < n; i++ {
					prod := ring.TruncMul(xCols[j][i], xCols[k][i])
					s = ring.Add(s, prod)
				}
				localXtX[j*p+k] = s
			}
		}
		localXtY := make([]uint64, p)
		for j := 0; j < p; j++ {
			var s uint64
			for i := 0; i < n; i++ {
				prod := ring.TruncMul(xCols[j][i], yShare[i])
				s = ring.Add(s, prod)
			}
			localXtY[j] = s
		}

		// Beaver R1 for all pairs
		beaver := BeaverTripleVec{A: aAll, B: bAll}
		_, msg := GenerateBatchedMultiplicationGateMessage(opA, opB, beaver, ring)

		mpcWriteOutput(K2GaussianOneshotPhase1Out{
			LocalXtXFP: bytesToBase64(fpVecToBytes(ring63ToFP(localXtX))),
			LocalXtYFP: bytesToBase64(fpVecToBytes(ring63ToFP(localXtY))),
			XMA:        bytesToBase64(fpVecToBytes(ring63ToFP(msg.XMinusAShares))),
			YMB:        bytesToBase64(fpVecToBytes(ring63ToFP(msg.YMinusBShares))),
		})
		return
	}

	// Phase 2: Beaver close + sum → cross-product shares
	cAll := fpToRing63(bytesToFPVec(base64ToBytes(input.TripleC)))
	peerXMA := fpToRing63(bytesToFPVec(base64ToBytes(input.PeerXMA)))
	peerYMB := fpToRing63(bytesToFPVec(base64ToBytes(input.PeerYMB)))

	beaver := BeaverTripleVec{A: aAll, B: bAll, C: cAll}
	state, _ := GenerateBatchedMultiplicationGateMessage(opA, opB, beaver, ring)
	peerMsg := MultGateMessage{XMinusAShares: peerXMA, YMinusBShares: peerYMB}

	var products []uint64
	if input.PartyID == 0 {
		products = HadamardProductPartyZero(state, beaver, peerMsg, ring.FracBits, ring)
	} else {
		products = HadamardProductPartyOne(state, beaver, peerMsg, ring.FracBits, ring)
	}

	// Sum groups of n elements to get the aggregate cross-products
	crossXtX := make([]uint64, p*p)
	for j := 0; j < p; j++ {
		for k := 0; k < p; k++ {
			idx := j*p + k
			var s uint64
			for i := 0; i < n; i++ {
				s = ring.Add(s, products[idx*n+i])
			}
			crossXtX[idx] = s
		}
	}

	crossXtY := make([]uint64, p)
	for j := 0; j < p; j++ {
		idx := p*p + j
		var s uint64
		for i := 0; i < n; i++ {
			s = ring.Add(s, products[idx*n+i])
		}
		crossXtY[j] = s
	}

	mpcWriteOutput(K2GaussianOneshotPhase2Out{
		CrossXtXFP: bytesToBase64(fpVecToBytes(ring63ToFP(crossXtX))),
		CrossXtYFP: bytesToBase64(fpVecToBytes(ring63ToFP(crossXtY))),
	})
}
