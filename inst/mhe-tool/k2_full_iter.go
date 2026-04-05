// k2_full_iter.go: Single Go command for one complete K=2 GD iteration.
//
// Performs eta computation, polynomial sigmoid eval, and gradient computation
// ALL in Ring63 — no float64 intermediate conversions.
//
// Called twice per iteration (once per party), with client-relayed messages
// for the Beaver rounds.
//
// Protocol per iteration:
//   R1: Each party computes eta_share = X_full_share * beta (local, Ring63)
//       Then splits eta into Beaver shares for poly eval
//   R2: Beaver power chain + poly eval (existing steps, Ring63)
//   R3: Gradient = X_full_share^T * (mu_share - y_share) via Beaver matvec
//       All in Ring63 with ring multiply + final asymmetric truncation
//   Output: p gradient scalars (float64) + sum_residual (float64)

package main

// K2FullIterR3Input is the input for round 3 (gradient computation).
// Receives: own FP shares of X, mu, y + Beaver triple + peer's round-3 message.
type K2FullIterR3Input struct {
	// Own shares (base64 FixedPoint in Ring63)
	XShareFP  string `json:"x_share_fp"`  // n*p_total (row-major)
	MuShareFP string `json:"mu_share_fp"` // n (from poly_eval)
	YShareFP  string `json:"y_share_fp"`  // n

	// Beaver triple shares (base64 FP, Ring63 with ring multiply)
	AShareFP string `json:"a_share_fp"` // n*p_total
	BShareFP string `json:"b_share_fp"` // n
	CShareFP string `json:"c_share_fp"` // p_total (C[j] = sum_i A[i,j]*B[i] mod ring)

	// Peer's round-3 message (empty for generating own message)
	PeerXmaFP string `json:"peer_xma_fp"` // n*p_total
	PeerRmbFP string `json:"peer_rmb_fp"` // n

	// Parameters
	N       int `json:"n"`
	P       int `json:"p"`       // p_total (coord + nonlabel features)
	PartyID int `json:"party_id"` // 0 or 1
	Phase   int `json:"phase"`    // 1 = compute own (X-A, r-B), 2 = compute gradient
}

type K2FullIterR3Phase1Output struct {
	XmaFP       string  `json:"xma_fp"`       // base64 FP: X_share - A_share
	RmbFP       string  `json:"rmb_fp"`       // base64 FP: residual_share - B_share
	SumResidual float64 `json:"sum_residual"` // float64 scalar
}

type K2FullIterR3Phase2Output struct {
	Gradient    []float64 `json:"gradient"`     // p float64 scalars
	SumResidual float64   `json:"sum_residual"` // float64 scalar
}

func handleK2FullIterR3() {
	var input K2FullIterR3Input
	mpcReadInput(&input)

	r := NewRing63(20) // fracBits = 20
	n := input.N
	p := input.P

	// Decode own shares
	xShare := bytesToFPVec(base64ToBytes(input.XShareFP))
	muShare := bytesToFPVec(base64ToBytes(input.MuShareFP))
	yShare := bytesToFPVec(base64ToBytes(input.YShareFP))

	// Compute residual share in ring: r = mu - y
	residualShare := make([]FixedPoint, n)
	for i := 0; i < n; i++ {
		residualShare[i] = FPSub(muShare[i], yShare[i])
	}

	// Sum residual (float64 scalar — safe to reveal)
	sumResidual := 0.0
	for i := 0; i < n; i++ {
		sumResidual += residualShare[i].ToFloat64(20)
	}

	if input.Phase == 1 {
		// Phase 1: compute (X_share - A) and (residual_share - B) in Ring63
		aShare := bytesToFPVec(base64ToBytes(input.AShareFP))
		bShare := bytesToFPVec(base64ToBytes(input.BShareFP))

		xma := make([]FixedPoint, n*p)
		rmb := make([]FixedPoint, n)
		for i := range xma {
			xma[i] = FPSub(xShare[i], aShare[i])
		}
		for i := range rmb {
			rmb[i] = FPSub(residualShare[i], bShare[i])
		}

		mpcWriteOutput(K2FullIterR3Phase1Output{
			XmaFP:       bytesToBase64(fpVecToBytes(xma)),
			RmbFP:       bytesToBase64(fpVecToBytes(rmb)),
			SumResidual: sumResidual,
		})
		return
	}

	// Phase 2: compute gradient using Beaver formula in Ring63
	aShare := bytesToFPVec(base64ToBytes(input.AShareFP))
	bShare := bytesToFPVec(base64ToBytes(input.BShareFP))
	cShare := bytesToFPVec(base64ToBytes(input.CShareFP))
	peerXMA := bytesToFPVec(base64ToBytes(input.PeerXmaFP))
	peerRMB := bytesToFPVec(base64ToBytes(input.PeerRmbFP))

	// Own (X-A) and (r-B)
	ownXMA := make([]FixedPoint, n*p)
	ownRMB := make([]FixedPoint, n)
	for i := range ownXMA {
		ownXMA[i] = FPSub(xShare[i], aShare[i])
	}
	for i := range ownRMB {
		ownRMB[i] = FPSub(residualShare[i], bShare[i])
	}

	// Reconstruct full (X-A) and (r-B) in Ring63
	fullXMA := make([]uint64, n*p)
	fullRMB := make([]uint64, n)
	for i := range fullXMA {
		fullXMA[i] = uint64(FPAdd(ownXMA[i], peerXMA[i])) % r.Modulus
	}
	for i := range fullRMB {
		fullRMB[i] = uint64(FPAdd(ownRMB[i], peerRMB[i])) % r.Modulus
	}

	// Beaver formula with RING multiply (no per-term truncation!)
	// Z_0[j] = C_0[j] + sum_i [A_0[i,j]*rmbFull[i] + xmaFull[i,j]*B_0[i] + xmaFull[i,j]*rmbFull[i]]
	// Z_1[j] = C_1[j] + sum_i [A_1[i,j]*rmbFull[i] + xmaFull[i,j]*B_1[i]]
	gRaw := make([]uint64, p)
	for j := 0; j < p; j++ {
		gRaw[j] = uint64(cShare[j]) % r.Modulus
	}

	for j := 0; j < p; j++ {
		for i := 0; i < n; i++ {
			aij := uint64(aShare[i*p+j]) % r.Modulus
			bij := uint64(bShare[i]) % r.Modulus
			xmaij := fullXMA[i*p+j]
			rmbi := fullRMB[i]

			// A_share[i,j] * fullRMB[i]  (ring multiply)
			gRaw[j] = r.Add(gRaw[j], modMulBig63(aij, rmbi, r.Modulus))
			// fullXMA[i,j] * B_share[i]  (ring multiply)
			gRaw[j] = r.Add(gRaw[j], modMulBig63(xmaij, bij, r.Modulus))
		}
	}

	// Party 0 only: add (X-A)^T * (r-B)
	if input.PartyID == 0 {
		for j := 0; j < p; j++ {
			for i := 0; i < n; i++ {
				gRaw[j] = r.Add(gRaw[j], modMulBig63(fullXMA[i*p+j], fullRMB[i], r.Modulus))
			}
		}
	}

	// Asymmetric truncation (ONCE, at the end)
	var gTrunc []uint64
	if input.PartyID == 0 {
		gTrunc = TruncateSharePartyZero(gRaw, r.FracMul, r.Modulus)
	} else {
		gTrunc = TruncateSharePartyOne(gRaw, r.FracMul, r.Modulus)
	}

	// Convert to float64 (the ONLY float conversion)
	gradient := make([]float64, p)
	for j := 0; j < p; j++ {
		gradient[j] = r.ToDouble(gTrunc[j])
	}

	mpcWriteOutput(K2FullIterR3Phase2Output{
		Gradient:    gradient,
		SumResidual: sumResidual,
	})
}

// ============================================================================
// Command: k2-gen-matvec-triples
// Generates Beaver triples for the matrix-vector gradient computation.
// A (n*p), B (n), C (p) where C[j] = sum_i A[i,j]*B[i] mod ring.
// Uses RING multiply (no truncation) matching the C++ ModMul.
// ============================================================================

type K2GenMatvecTriplesInput struct {
	N int `json:"n"`
	P int `json:"p"`
}

type K2GenMatvecTriplesOutput struct {
	Party0A string `json:"party0_a"` // base64 FP, n*p
	Party0B string `json:"party0_b"` // base64 FP, n
	Party0C string `json:"party0_c"` // base64 FP, p
	Party1A string `json:"party1_a"`
	Party1B string `json:"party1_b"`
	Party1C string `json:"party1_c"`
}

func handleK2GenMatvecTriples() {
	var input K2GenMatvecTriplesInput
	mpcReadInput(&input)

	n := input.N
	p := input.P
	r := NewRing63(20)

	// Random A (n*p) and B (n) in Ring63
	A := make([]FixedPoint, n*p)
	B := make([]FixedPoint, n)
	for i := range A { A[i] = FixedPoint(int64(cryptoRandUint64K2() % r.Modulus)) }
	for i := range B { B[i] = FixedPoint(int64(cryptoRandUint64K2() % r.Modulus)) }

	// C[j] = sum_i A[i,j] * B[i] mod ring (RING multiply, no truncation)
	C := make([]FixedPoint, p)
	for j := 0; j < p; j++ {
		var cj uint64
		for i := 0; i < n; i++ {
			cj = r.Add(cj, modMulBig63(uint64(A[i*p+j])%r.Modulus, uint64(B[i])%r.Modulus, r.Modulus))
		}
		C[j] = FixedPoint(int64(cj))
	}

	// Split into party shares
	a0 := make([]FixedPoint, n*p); a1 := make([]FixedPoint, n*p)
	b0 := make([]FixedPoint, n); b1 := make([]FixedPoint, n)
	c0 := make([]FixedPoint, p); c1 := make([]FixedPoint, p)
	for i := range A { s := FixedPoint(int64(cryptoRandUint64K2())); a0[i] = s; a1[i] = A[i] - s }
	for i := range B { s := FixedPoint(int64(cryptoRandUint64K2())); b0[i] = s; b1[i] = B[i] - s }
	for i := range C { s := FixedPoint(int64(cryptoRandUint64K2())); c0[i] = s; c1[i] = C[i] - s }

	mpcWriteOutput(K2GenMatvecTriplesOutput{
		Party0A: bytesToBase64(fpVecToBytes(a0)),
		Party0B: bytesToBase64(fpVecToBytes(b0)),
		Party0C: bytesToBase64(fpVecToBytes(c0)),
		Party1A: bytesToBase64(fpVecToBytes(a1)),
		Party1B: bytesToBase64(fpVecToBytes(b1)),
		Party1C: bytesToBase64(fpVecToBytes(c1)),
	})
}

// Command: k2-split-fp-share
// Splits a FixedPoint vector into two additive shares.

type K2SplitFPInput struct {
	DataFP string `json:"data_fp"` // base64 FP
	N      int    `json:"n"`
}

type K2SplitFPOutput struct {
	OwnShare  string `json:"own_share"`  // base64 FP
	PeerShare string `json:"peer_share"` // base64 FP
}

func handleK2SplitFPShare() {
	var input K2SplitFPInput
	mpcReadInput(&input)

	data := bytesToFPVec(base64ToBytes(input.DataFP))
	own := make([]FixedPoint, len(data))
	peer := make([]FixedPoint, len(data))
	for i := range data {
		own[i] = FixedPoint(int64(cryptoRandUint64K2()))
		peer[i] = data[i] - own[i] // wrapping int64 subtraction
	}

	mpcWriteOutput(K2SplitFPOutput{
		OwnShare:  bytesToBase64(fpVecToBytes(own)),
		PeerShare: bytesToBase64(fpVecToBytes(peer)),
	})
}
