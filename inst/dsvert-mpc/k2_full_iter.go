// k2_full_iter.go: Ring63/Ring127 gradient computation for K=2 secure training.
//
// The Beaver formula uses explicit ring multiplication and applies the
// deterministic asymmetric local-truncation convention once at the end.
// Its rare wrap-failure condition is documented in k2_truncation.go.

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
	FracBits  int    `json:"frac_bits"`
	// Ring selector. "" or "ring63" (default, 8-byte per element) /
	// "ring127" (16-byte Uint128 records). Task #116 Cox/LMM plumbing 5c(D).
	Ring string `json:"ring"`
}

type K2FullIterR3Phase1Output struct {
	XmaFP         string  `json:"xma_fp"`
	RmbFP         string  `json:"rmb_fp"`
	SumResidual   float64 `json:"sum_residual"`
	SumResidualFP string  `json:"sum_residual_fp"` // Ring63 value as base64 FP (for ring-level aggregation)
}

type K2FullIterR3Phase2Output struct {
	Gradient      []float64 `json:"gradient"`
	SumResidual   float64   `json:"sum_residual"`
	SumResidualFP string    `json:"sum_residual_fp"`
	GradientFP    string    `json:"gradient_fp"` // Ring63 gradient shares as base64 FP
}

func handleK2FullIterR3() {
	var input K2FullIterR3Input
	mpcReadInput(&input)
	ringName, fracBits, err := normalizeRingAndFracBits(input.Ring, input.FracBits)
	if err != nil {
		outputError("k2-full-iter-r3: " + err.Error())
		return
	}
	if input.N <= 0 || input.P <= 0 {
		outputError("k2-full-iter-r3: n and p must be positive")
		return
	}
	if input.PartyID != 0 && input.PartyID != 1 {
		outputError("k2-full-iter-r3: party_id must be 0 or 1")
		return
	}
	if input.Phase != 1 && input.Phase != 2 {
		outputError("k2-full-iter-r3: phase must be 1 or 2")
		return
	}
	np, err := checkedProduct("k2-full-iter-r3 matrix", input.N, input.P)
	if err != nil {
		outputError("k2-full-iter-r3: " + err.Error())
		return
	}
	input.Ring, input.FracBits = ringName, fracBits
	if ringName == "ring127" {
		handleK2FullIterR3_127(input)
		return
	}

	n := input.N
	p := input.P

	ring := NewRing63(fracBits)

	xR63, err := decodeRing63FPVector(input.XShareFP, np)
	if err != nil {
		outputError("k2-full-iter-r3: invalid x_share_fp: " + err.Error())
		return
	}
	muR63, err := decodeRing63FPVector(input.MuShareFP, n)
	if err != nil {
		outputError("k2-full-iter-r3: invalid mu_share_fp: " + err.Error())
		return
	}
	yR63, err := decodeRing63FPVector(input.YShareFP, n)
	if err != nil {
		outputError("k2-full-iter-r3: invalid y_share_fp: " + err.Error())
		return
	}

	// Residual share in Ring63: r = mu - y
	residualR63 := make([]uint64, n)
	for i := 0; i < n; i++ {
		residualR63[i] = ring.Sub(muR63[i], yR63[i])
	}

	// Sum residual in Ring63, then convert to float
	var sumResidualR63 uint64
	for i := 0; i < n; i++ {
		sumResidualR63 = ring.Add(sumResidualR63, residualR63[i])
	}
	sumResidual := ring.ToDouble(sumResidualR63)

	if input.Phase == 1 {
		aR63, err := decodeRing63FPVector(input.AShareFP, np)
		if err != nil {
			outputError("k2-full-iter-r3: invalid a_share_fp: " + err.Error())
			return
		}
		bR63, err := decodeRing63FPVector(input.BShareFP, n)
		if err != nil {
			outputError("k2-full-iter-r3: invalid b_share_fp: " + err.Error())
			return
		}

		// Compute (X-A) and (r-B) in Ring63
		xma := make([]uint64, np)
		rmb := make([]uint64, n)
		for i := range xma {
			xma[i] = ring.Sub(xR63[i], aR63[i])
		}
		for i := range rmb {
			rmb[i] = ring.Sub(residualR63[i], bR63[i])
		}

		mpcWriteOutput(K2FullIterR3Phase1Output{
			XmaFP:         bytesToBase64(fpVecToBytes(ring63ToFP(xma))),
			RmbFP:         bytesToBase64(fpVecToBytes(ring63ToFP(rmb))),
			SumResidual:   sumResidual,
			SumResidualFP: bytesToBase64(fpVecToBytes(ring63ToFP([]uint64{sumResidualR63}))),
		})
		return
	}

	// Phase 2: Beaver matvec gradient using Ring63 arithmetic
	aR63, err := decodeRing63FPVector(input.AShareFP, np)
	if err != nil {
		outputError("k2-full-iter-r3: invalid a_share_fp: " + err.Error())
		return
	}
	bR63, err := decodeRing63FPVector(input.BShareFP, n)
	if err != nil {
		outputError("k2-full-iter-r3: invalid b_share_fp: " + err.Error())
		return
	}
	cR63, err := decodeRing63FPVector(input.CShareFP, p)
	if err != nil {
		outputError("k2-full-iter-r3: invalid c_share_fp: " + err.Error())
		return
	}
	peerXMAR63, err := decodeRing63FPVector(input.PeerXmaFP, np)
	if err != nil {
		outputError("k2-full-iter-r3: invalid peer_xma_fp: " + err.Error())
		return
	}
	peerRMBR63, err := decodeRing63FPVector(input.PeerRmbFP, n)
	if err != nil {
		outputError("k2-full-iter-r3: invalid peer_rmb_fp: " + err.Error())
		return
	}

	// Own (X-A) and (r-B) in Ring63
	ownXMA := make([]uint64, np)
	ownRMB := make([]uint64, n)
	for i := range ownXMA {
		ownXMA[i] = ring.Sub(xR63[i], aR63[i])
	}
	for i := range ownRMB {
		ownRMB[i] = ring.Sub(residualR63[i], bR63[i])
	}

	// Reconstruct full (X-A) and (r-B) in Ring63
	fullXMA := make([]uint64, np)
	fullRMB := make([]uint64, n)
	for i := range fullXMA {
		fullXMA[i] = ring.Add(ownXMA[i], peerXMAR63[i])
	}
	for i := range fullRMB {
		fullRMB[i] = ring.Add(ownRMB[i], peerRMBR63[i])
	}

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

	// Deterministic asymmetric local truncation.
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
		Gradient:      gradient,
		SumResidual:   sumResidual,
		SumResidualFP: bytesToBase64(fpVecToBytes(ring63ToFP([]uint64{sumResidualR63}))),
		GradientFP:    bytesToBase64(fpVecToBytes(ring63ToFP(truncated))),
	})
}

// --- Ring63 aggregation (client-side) ---

type K2Ring63AggregateInput struct {
	ShareA   string `json:"share_a"` // base64 FP (Ring63 share from party 0)
	ShareB   string `json:"share_b"` // base64 FP (Ring63 share from party 1)
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
	ringName, fracBits, err := normalizeRingAndFracBits(input.Ring, input.FracBits)
	if err != nil {
		outputError("k2-ring63-aggregate: " + err.Error())
		return
	}
	input.Ring, input.FracBits = ringName, fracBits

	// Ring127 dispatch — parse 16-byte input records, add in Ring127, decode.
	if ringName == "ring127" {
		ring127 := NewRing127(fracBits)
		a127, err := decodeRing127Vector(input.ShareA, -1)
		if err != nil {
			outputError("k2-ring63-aggregate (ring127): invalid share_a: " + err.Error())
			return
		}
		b127, err := decodeRing127Vector(input.ShareB, len(a127))
		if err != nil {
			outputError("k2-ring63-aggregate (ring127): invalid share_b: " + err.Error())
			return
		}
		n := len(a127)
		values := make([]float64, n)
		for i := 0; i < n; i++ {
			values[i] = ring127.ToDouble(ring127.Add(a127[i], b127[i]))
		}
		mpcWriteOutput(K2Ring63AggregateOutput{Values: values})
		return
	}
	ring := NewRing63(fracBits)
	aR63, err := decodeRing63FPVector(input.ShareA, -1)
	if err != nil {
		outputError("k2-ring63-aggregate: invalid share_a: " + err.Error())
		return
	}
	bR63, err := decodeRing63FPVector(input.ShareB, len(aR63))
	if err != nil {
		outputError("k2-ring63-aggregate: invalid share_b: " + err.Error())
		return
	}

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
	DataFP   string `json:"data_fp"`
	N        int    `json:"n"`
	FracBits int    `json:"frac_bits"`
	// Ring selector. "" or "ring63" (default, 8-byte records) /
	// "ring127" (16-byte Uint128 records). Task #116 Cox/LMM plumbing.
	Ring string `json:"ring"`
}

type K2SplitFPOutput struct {
	OwnShare  string `json:"own_share"`
	PeerShare string `json:"peer_share"`
}

func handleK2SplitFPShare() {
	var input K2SplitFPInput
	mpcReadInput(&input)
	ringName, fracBits, err := normalizeRingAndFracBits(input.Ring, input.FracBits)
	if err != nil {
		outputError("k2-split-fp-share: " + err.Error())
		return
	}
	if input.N < 0 {
		outputError("k2-split-fp-share: n must not be negative")
		return
	}
	expected := -1
	if input.N > 0 {
		expected = input.N
	}

	// Ring127 dispatch — 16-byte input / 16-byte output per share.
	if ringName == "ring127" {
		ring127 := NewRing127(fracBits)
		data127, err := decodeRing127Vector(input.DataFP, expected)
		if err != nil {
			outputError("k2-split-fp-share (ring127): invalid data_fp: " + err.Error())
			return
		}
		own127 := make([]Uint128, len(data127))
		peer127 := make([]Uint128, len(data127))
		for i := range data127 {
			own127[i], peer127[i] = ring127.SplitShare(data127[i])
		}
		mpcWriteOutput(K2SplitFPOutput{
			OwnShare:  bytesToBase64(uint128VecToBytes(own127)),
			PeerShare: bytesToBase64(uint128VecToBytes(peer127)),
		})
		return
	}
	dataR63, err := decodeRing63FPVector(input.DataFP, expected)
	if err != nil {
		outputError("k2-split-fp-share: invalid data_fp: " + err.Error())
		return
	}
	ring := NewRing63(fracBits)

	// Convert data to Ring63 and split using Ring63 arithmetic
	// This ensures shares are valid Ring63 values that sum to the original mod 2^63
	ownR63 := make([]uint64, len(dataR63))
	peerR63 := make([]uint64, len(dataR63))
	for i := range dataR63 {
		ownR63[i], peerR63[i] = ring.SplitShare(dataR63[i])
	}

	mpcWriteOutput(K2SplitFPOutput{
		OwnShare:  bytesToBase64(fpVecToBytes(ring63ToFP(ownR63))),
		PeerShare: bytesToBase64(fpVecToBytes(ring63ToFP(peerR63))),
	})
}

type K2ComputeEtaFPInput struct {
	XOwnFP      string  `json:"x_own_fp"`
	XPeerFP     string  `json:"x_peer_fp"`
	BetaFP      string  `json:"beta_fp"`
	Intercept   float64 `json:"intercept"`
	IsPartyZero bool    `json:"is_party_zero"`
	N           int     `json:"n"`
	POwn        int     `json:"p_own"`
	PPeer       int     `json:"p_peer"`
	FracBits    int     `json:"frac_bits"`
	// Ring selector. "" or "ring63" (default, 8-byte per element) /
	// "ring127" (16-byte Uint128 records). Task #116 Cox/LMM plumbing 5c(D).
	Ring string `json:"ring"`
}

func handleK2ComputeEtaFP() {
	var input K2ComputeEtaFPInput
	mpcReadInput(&input)
	ringName, fracBits, err := normalizeRingAndFracBits(input.Ring, input.FracBits)
	if err != nil {
		outputError("k2-compute-eta-fp: " + err.Error())
		return
	}
	if err := validateFinite("intercept", input.Intercept); err != nil {
		outputError("k2-compute-eta-fp: " + err.Error())
		return
	}
	if input.N <= 0 || input.POwn < 0 || input.PPeer < 0 {
		outputError("k2-compute-eta-fp: invalid dimensions")
		return
	}
	if input.POwn > int(^uint(0)>>1)-input.PPeer {
		outputError("k2-compute-eta-fp: dimensions overflow")
		return
	}
	pTotal := input.POwn + input.PPeer
	if _, err := checkedProduct("k2-compute-eta-fp x_own", input.N, input.POwn); err != nil {
		outputError("k2-compute-eta-fp: " + err.Error())
		return
	}
	if _, err := checkedProduct("k2-compute-eta-fp x_peer", input.N, input.PPeer); err != nil {
		outputError("k2-compute-eta-fp: " + err.Error())
		return
	}
	if _, err := checkedProduct("k2-compute-eta-fp x_full", input.N, pTotal); err != nil {
		outputError("k2-compute-eta-fp: " + err.Error())
		return
	}
	input.Ring, input.FracBits = ringName, fracBits
	if ringName == "ring127" {
		handleK2ComputeEtaFP127(input)
		return
	}

	ring := NewRing63(fracBits)
	n := input.N
	pOwn := input.POwn
	pPeer := input.PPeer

	// X shares are Ring63 values stored as FP
	xOwnLen, _ := checkedProduct("x_own", n, pOwn)
	xPeerLen, _ := checkedProduct("x_peer", n, pPeer)
	xOwnR63, err := decodeRing63FPVector(input.XOwnFP, xOwnLen)
	if err != nil {
		outputError("k2-compute-eta-fp: invalid x_own_fp: " + err.Error())
		return
	}
	xPeerR63, err := decodeRing63FPVector(input.XPeerFP, xPeerLen)
	if err != nil {
		outputError("k2-compute-eta-fp: invalid x_peer_fp: " + err.Error())
		return
	}
	// Beta is a public float64 vector encoded as FP
	betaR63, err := decodeRing63FPVector(input.BetaFP, pTotal)
	if err != nil {
		outputError("k2-compute-eta-fp: invalid beta_fp: " + err.Error())
		return
	}

	// Compute eta = X_share * beta using Ring63 ScalarVectorProduct
	// Beta values are public, X shares are secret → use asymmetric P0/P1 truncation
	etaR63 := make([]uint64, n)
	for i := 0; i < n; i++ {
		if input.IsPartyZero {
			for j := 0; j < pOwn; j++ {
				betaFloat := ring.ToDouble(betaR63[j])
				term := ScalarVectorProductPartyZero(betaFloat, []uint64{xOwnR63[i*pOwn+j]}, ring)
				etaR63[i] = ring.Add(etaR63[i], term[0])
			}
			for j := 0; j < pPeer; j++ {
				betaFloat := ring.ToDouble(betaR63[pOwn+j])
				term := ScalarVectorProductPartyZero(betaFloat, []uint64{xPeerR63[i*pPeer+j]}, ring)
				etaR63[i] = ring.Add(etaR63[i], term[0])
			}
		} else {
			for j := 0; j < pPeer; j++ {
				betaFloat := ring.ToDouble(betaR63[j])
				term := ScalarVectorProductPartyOne(betaFloat, []uint64{xPeerR63[i*pPeer+j]}, ring)
				etaR63[i] = ring.Add(etaR63[i], term[0])
			}
			for j := 0; j < pOwn; j++ {
				betaFloat := ring.ToDouble(betaR63[pPeer+j])
				term := ScalarVectorProductPartyOne(betaFloat, []uint64{xOwnR63[i*pOwn+j]}, ring)
				etaR63[i] = ring.Add(etaR63[i], term[0])
			}
		}
	}

	// Intercept: only Party Zero adds the public intercept
	if input.IsPartyZero && input.Intercept != 0 {
		interceptR63, err := ring.FromDoubleChecked(input.Intercept)
		if err != nil {
			outputError("k2-compute-eta-fp: invalid intercept: " + err.Error())
			return
		}
		for i := 0; i < n; i++ {
			etaR63[i] = ring.Add(etaR63[i], interceptR63)
		}
	}

	// Build full X share in CANONICAL order: [coord features | nonlabel features]
	xFullR63 := make([]uint64, n*pTotal)
	for i := 0; i < n; i++ {
		if input.IsPartyZero {
			for j := 0; j < pOwn; j++ {
				xFullR63[i*pTotal+j] = xOwnR63[i*pOwn+j]
			}
			for j := 0; j < pPeer; j++ {
				xFullR63[i*pTotal+pOwn+j] = xPeerR63[i*pPeer+j]
			}
		} else {
			for j := 0; j < pPeer; j++ {
				xFullR63[i*pTotal+j] = xPeerR63[i*pPeer+j]
			}
			for j := 0; j < pOwn; j++ {
				xFullR63[i*pTotal+pPeer+j] = xOwnR63[i*pOwn+j]
			}
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
	// Ring selector. "" or "ring63" (default, 8-byte records) /
	// "ring127" (16-byte Uint128 records). Task #116 Cox/LMM plumbing 5c(D).
	Ring string `json:"ring"`
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
	ringName, _, err := normalizeRingAndFracBits(input.Ring, 0)
	if err != nil {
		outputError("k2-gen-matvec-triples: " + err.Error())
		return
	}
	if input.N <= 0 || input.P <= 0 {
		outputError("k2-gen-matvec-triples: n and p must be positive")
		return
	}
	np, err := checkedProduct("k2-gen-matvec-triples matrix", input.N, input.P)
	if err != nil {
		outputError("k2-gen-matvec-triples: " + err.Error())
		return
	}
	input.Ring = ringName
	if ringName == "ring127" {
		handleK2GenMatvecTriples127(input)
		return
	}

	n := input.N
	p := input.P
	ring := NewRing63(K2DefaultFracBits)

	// Generate A (n*p) and B (n) in Ring63
	A := make([]uint64, np)
	B := make([]uint64, n)
	for i := range A {
		A[i] = cryptoRandUint64K2() % ring.Modulus
	}
	for i := range B {
		B[i] = cryptoRandUint64K2() % ring.Modulus
	}

	// C[j] = sum_i A[i,j] * B[i] in Ring63 (modMulBig63, matching Beaver close)
	C := make([]uint64, p)
	for j := 0; j < p; j++ {
		for i := 0; i < n; i++ {
			prod := modMulBig63(A[i*p+j], B[i], ring.Modulus)
			C[j] = ring.Add(C[j], prod)
		}
	}

	// Split in Ring63
	a0 := make([]uint64, np)
	a1 := make([]uint64, np)
	b0 := make([]uint64, n)
	b1 := make([]uint64, n)
	c0 := make([]uint64, p)
	c1 := make([]uint64, p)
	for i := range A {
		a0[i], a1[i] = ring.SplitShare(A[i])
	}
	for i := range B {
		b0[i], b1[i] = ring.SplitShare(B[i])
	}
	for i := range C {
		c0[i], c1[i] = ring.SplitShare(C[i])
	}

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
