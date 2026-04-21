// k2_full_iter_ring127.go — Ring127 variants of k2-compute-eta-fp and
// k2-full-iter-r3 (Cox Path B scope-gap closure, task #116 step 5c(D)).
//
// Structurally identical to the Ring63 handlers in k2_full_iter.go and
// k2_chebyshev.go but operating on Uint128 under Ring127 (2^127 modulus).
// 16-byte little-endian per element, layout [Lo(8) | Hi(8)] — matches
// uint128VecToBytes / bytesToUint128Vec.
//
// Default fracBits for Ring127 = 50 (matches the Beaver sign-safety zone
// established in step 1: 2*fracBits = 100 << 2^126 sign threshold). This
// gives Beaver products ~2*fracBits=100 bits of fractional precision
// before the final TruncateShare brings it back to fracBits.
//
// Dispatch pattern: each helper takes a pre-parsed input struct (the
// corresponding Ring63 handler has already called mpcReadInput). Do NOT
// re-read stdin here.

package main

// ============================================================================
// k2-compute-eta-fp (Ring127)
// ============================================================================
// Parity with handleK2ComputeEtaFP:
//   eta share[i]  = sum_j beta[j] * X_share[i,j]    (Ring127 local scalar-vec)
//   + intercept on party 0
//   x_full[i,j]  = [coord | nonlabel] canonical order reassembly
//
// Beta is passed as a 16-byte Ring127-FP vector (public but encoded in the
// same ring as X so the R client just threads `ring=ring127` into the
// k2-float-to-fp call that generates beta_fp). Scalar per-element is
// converted back to float64 via r.ToDouble for ScalarVectorProduct
// (matches Ring63 path which also round-trips via ToFloat64).

func handleK2ComputeEtaFP127(input K2ComputeEtaFPInput) {
	fracBits := ring127DefaultFracBits(input.FracBits)
	ring := NewRing127(fracBits)

	n := input.N
	pOwn := input.POwn
	pPeer := input.PPeer
	pTotal := pOwn + pPeer

	// 16-byte Uint128 per element (X shares and beta).
	xOwn := bytesToUint128Vec(base64ToBytes(input.XOwnFP))
	xPeer := bytesToUint128Vec(base64ToBytes(input.XPeerFP))
	betaU128 := bytesToUint128Vec(base64ToBytes(input.BetaFP))

	eta := make([]Uint128, n)
	for i := 0; i < n; i++ {
		if input.IsPartyZero {
			for j := 0; j < pOwn; j++ {
				beta := ring.ToDouble(betaU128[j])
				term := ScalarVectorProductPartyZero127(beta, []Uint128{xOwn[i*pOwn+j]}, ring)
				eta[i] = ring.Add(eta[i], term[0])
			}
			for j := 0; j < pPeer; j++ {
				beta := ring.ToDouble(betaU128[pOwn+j])
				term := ScalarVectorProductPartyZero127(beta, []Uint128{xPeer[i*pPeer+j]}, ring)
				eta[i] = ring.Add(eta[i], term[0])
			}
		} else {
			for j := 0; j < pPeer; j++ {
				beta := ring.ToDouble(betaU128[j])
				term := ScalarVectorProductPartyOne127(beta, []Uint128{xPeer[i*pPeer+j]}, ring)
				eta[i] = ring.Add(eta[i], term[0])
			}
			for j := 0; j < pOwn; j++ {
				beta := ring.ToDouble(betaU128[pPeer+j])
				term := ScalarVectorProductPartyOne127(beta, []Uint128{xOwn[i*pOwn+j]}, ring)
				eta[i] = ring.Add(eta[i], term[0])
			}
		}
	}

	// Public intercept: only party zero contributes.
	if input.IsPartyZero && input.Intercept != 0 {
		interceptU128 := ring.FromDouble(input.Intercept)
		for i := 0; i < n; i++ {
			eta[i] = ring.Add(eta[i], interceptU128)
		}
	}

	// Reassemble x_full in canonical [coord | nonlabel] order.
	xFull := make([]Uint128, n*pTotal)
	for i := 0; i < n; i++ {
		if input.IsPartyZero {
			for j := 0; j < pOwn; j++ {
				xFull[i*pTotal+j] = xOwn[i*pOwn+j]
			}
			for j := 0; j < pPeer; j++ {
				xFull[i*pTotal+pOwn+j] = xPeer[i*pPeer+j]
			}
		} else {
			for j := 0; j < pPeer; j++ {
				xFull[i*pTotal+j] = xPeer[i*pPeer+j]
			}
			for j := 0; j < pOwn; j++ {
				xFull[i*pTotal+pPeer+j] = xOwn[i*pOwn+j]
			}
		}
	}

	mpcWriteOutput(struct {
		EtaFP   string `json:"eta_fp"`
		XFullFP string `json:"x_full_fp"`
	}{
		EtaFP:   Uint128VecToB64(eta),
		XFullFP: Uint128VecToB64(xFull),
	})
}

// ============================================================================
// k2-full-iter-r3 (Ring127) — phase 1 + phase 2
// ============================================================================
// Parity with handleK2FullIterR3. All intermediate values are Ring127
// (16-byte Uint128). Beaver matvec in Phase 2 follows the same formula:
//   g[j] = C[j] + sum_i(A[i,j]*fullRMB[i]) + sum_i(fullXMA[i,j]*B[i])
//          + [P0]*sum_i(fullXMA[i,j]*fullRMB[i])
// where each per-element product is UNtruncated (Uint128.Mul.ModPow127,
// the Ring127 analogue of modMulBig63). The full accumulated gradient is
// truncated ONCE at the end via TruncateSharePartyZero127/One127.

func handleK2FullIterR3_127(input K2FullIterR3Input) {
	fracBits := ring127DefaultFracBits(input.FracBits)
	ring := NewRing127(fracBits)

	n := input.N
	p := input.P

	// 16-byte Uint128 per element.
	xShare := bytesToUint128Vec(base64ToBytes(input.XShareFP))
	muShare := bytesToUint128Vec(base64ToBytes(input.MuShareFP))
	yShare := bytesToUint128Vec(base64ToBytes(input.YShareFP))

	// Residual share: r = mu - y (linear share op).
	residual := make([]Uint128, n)
	for i := 0; i < n; i++ {
		residual[i] = ring.Sub(muShare[i], yShare[i])
	}

	// Sum residual share (linear share op → still a share).
	var sumResidualU128 Uint128
	for i := 0; i < n; i++ {
		sumResidualU128 = ring.Add(sumResidualU128, residual[i])
	}
	// ToDouble on a share is meaningless (random-looking) — kept for parity
	// with the Ring63 output field; the R caller aggregates via
	// sum_residual_fp through k2-ring63-aggregate (which handles ring127).
	sumResidualFloat := ring.ToDouble(sumResidualU128)

	if input.Phase == 1 {
		aShare := bytesToUint128Vec(base64ToBytes(input.AShareFP))
		bShare := bytesToUint128Vec(base64ToBytes(input.BShareFP))

		xma := make([]Uint128, n*p)
		rmb := make([]Uint128, n)
		for i := range xma {
			xma[i] = ring.Sub(xShare[i], aShare[i])
		}
		for i := range rmb {
			rmb[i] = ring.Sub(residual[i], bShare[i])
		}

		mpcWriteOutput(K2FullIterR3Phase1Output{
			XmaFP:         Uint128VecToB64(xma),
			RmbFP:         Uint128VecToB64(rmb),
			SumResidual:   sumResidualFloat,
			SumResidualFP: Uint128VecToB64([]Uint128{sumResidualU128}),
		})
		return
	}

	// --- Phase 2: Beaver matvec ---
	aShare := bytesToUint128Vec(base64ToBytes(input.AShareFP))
	bShare := bytesToUint128Vec(base64ToBytes(input.BShareFP))
	cShare := bytesToUint128Vec(base64ToBytes(input.CShareFP))
	peerXMA := bytesToUint128Vec(base64ToBytes(input.PeerXmaFP))
	peerRMB := bytesToUint128Vec(base64ToBytes(input.PeerRmbFP))

	ownXMA := make([]Uint128, n*p)
	ownRMB := make([]Uint128, n)
	for i := range ownXMA {
		ownXMA[i] = ring.Sub(xShare[i], aShare[i])
	}
	for i := range ownRMB {
		ownRMB[i] = ring.Sub(residual[i], bShare[i])
	}

	// Reconstruct full (X-A), (r-B) by adding peer shares.
	fullXMA := make([]Uint128, n*p)
	fullRMB := make([]Uint128, n)
	for i := range fullXMA {
		fullXMA[i] = ring.Add(ownXMA[i], peerXMA[i])
	}
	for i := range fullRMB {
		fullRMB[i] = ring.Add(ownRMB[i], peerRMB[i])
	}

	// Accumulate raw Beaver matvec output at 2*fracBits scale.
	gRaw := make([]Uint128, p)
	copy(gRaw, cShare)

	for j := 0; j < p; j++ {
		for i := 0; i < n; i++ {
			// A[i,j] * fullRMB[i] untruncated.
			prod1 := aShare[i*p+j].Mul(fullRMB[i]).ModPow127()
			gRaw[j] = ring.Add(gRaw[j], prod1)
			// fullXMA[i,j] * B[i] untruncated.
			prod2 := fullXMA[i*p+j].Mul(bShare[i]).ModPow127()
			gRaw[j] = ring.Add(gRaw[j], prod2)
		}
	}

	if input.PartyID == 0 {
		for j := 0; j < p; j++ {
			for i := 0; i < n; i++ {
				prod := fullXMA[i*p+j].Mul(fullRMB[i]).ModPow127()
				gRaw[j] = ring.Add(gRaw[j], prod)
			}
		}
	}

	// Single truncation at end (asymmetric per party). Matches Ring63
	// TruncateSharePartyZero/One behaviour.
	var truncated []Uint128
	if input.PartyID == 0 {
		truncated = TruncateSharePartyZero127(gRaw, fracBits, ring)
	} else {
		truncated = TruncateSharePartyOne127(gRaw, fracBits, ring)
	}

	// Gradient []float64 field carries share-level ToDouble for parity
	// with Ring63 output; caller aggregates via GradientFP + k2-ring63-
	// aggregate (ring127) which reconstructs the plaintext gradient.
	gradient := make([]float64, p)
	for j := 0; j < p; j++ {
		gradient[j] = ring.ToDouble(truncated[j])
	}

	mpcWriteOutput(K2FullIterR3Phase2Output{
		Gradient:      gradient,
		SumResidual:   sumResidualFloat,
		SumResidualFP: Uint128VecToB64([]Uint128{sumResidualU128}),
		GradientFP:    Uint128VecToB64(truncated),
	})
}

// ============================================================================
// k2-gen-matvec-triples (Ring127)
// ============================================================================
// Parity with handleK2GenMatvecTriples: samples A (n*p), B (n) random
// Uint128 in Ring127, computes C[j] = sum_i A[i,j]*B[i] UNtruncated
// (ModPow127) — Beaver matvec triples at 2*fracBits FP scale. Triples are
// then additively split into {party0, party1} shares via SplitShare. The
// consumer (k2-full-iter-r3 Phase 2) applies the single truncation.
//
// Ring127 triple blob is 16 bytes/element (A: 16·n·p, B: 16·n, C: 16·p),
// compared to 8 bytes/element in Ring63 → 2× larger transport payload.

func handleK2GenMatvecTriples127(input K2GenMatvecTriplesInput) {
	n := input.N
	p := input.P
	ring := NewRing127(K2DefaultFracBits127)

	A := make([]Uint128, n*p)
	B := make([]Uint128, n)
	for i := range A {
		A[i] = cryptoRandUint128().ModPow127()
	}
	for i := range B {
		B[i] = cryptoRandUint128().ModPow127()
	}

	// C[j] = sum_i A[i,j] * B[i] UNtruncated in Ring127 (ModPow127 per
	// product, matching Ring63 modMulBig63 semantics).
	C := make([]Uint128, p)
	for j := 0; j < p; j++ {
		for i := 0; i < n; i++ {
			prod := A[i*p+j].Mul(B[i]).ModPow127()
			C[j] = ring.Add(C[j], prod)
		}
	}

	// Additively split.
	a0 := make([]Uint128, n*p)
	a1 := make([]Uint128, n*p)
	b0 := make([]Uint128, n)
	b1 := make([]Uint128, n)
	c0 := make([]Uint128, p)
	c1 := make([]Uint128, p)
	for i := range A {
		a0[i], a1[i] = ring.SplitShare(A[i])
	}
	for i := range B {
		b0[i], b1[i] = ring.SplitShare(B[i])
	}
	for i := range C {
		c0[i], c1[i] = ring.SplitShare(C[i])
	}

	mpcWriteOutput(K2GenMatvecTriplesOutput{
		Party0A: Uint128VecToB64(a0),
		Party0B: Uint128VecToB64(b0),
		Party0C: Uint128VecToB64(c0),
		Party1A: Uint128VecToB64(a1),
		Party1B: Uint128VecToB64(b1),
		Party1C: Uint128VecToB64(c1),
	})
}
