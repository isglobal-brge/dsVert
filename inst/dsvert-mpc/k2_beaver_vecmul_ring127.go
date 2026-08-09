// k2_beaver_vecmul_ring127.go — Ring127 handler variants for the
// element-wise Beaver multiplication protocol (gen-triples / round1 / round2).
//
// Wire format: 16 bytes per Uint128 element, little-endian [Lo|Hi] — matches
// uint128VecToBytes / bytesToUint128Vec. The triple blob is a base64-encoded
// JSON with {a, b, c} where each is a base64 string of the 16-byte-per-element
// vector. The extra base64 wrapping matches the Ring63 encodeTripleBlob
// convention so R-side plumbing (beaverVecmulDS.R) is ring-agnostic.
//
// FP truncation: as in Ring63, round 2 produces an UNtruncated (2*fracBits)
// share of x·y. The handler follows by applying
// TruncateSharePartyZero127 / TruncateSharePartyOne127 so the returned share
// sits back at fracBits worth of fraction.
//
// Dispatch pattern: each helper takes a pre-parsed input struct (stdin is
// already consumed by the Ring63 handler before it detects Ring == "ring127").

package main

import (
	"encoding/base64"
	"encoding/json"
)

// encodeTripleBlob127 serializes a Ring127 Beaver triple share as a base64
// JSON envelope with 16-byte-per-element payloads.
func encodeTripleBlob127(t BeaverTripleVec127) string {
	w := tripleWire{
		A: []string{Uint128VecToB64(t.A)},
		B: []string{Uint128VecToB64(t.B)},
		C: []string{Uint128VecToB64(t.C)},
	}
	buf, _ := json.Marshal(w)
	return base64.StdEncoding.EncodeToString(buf)
}

// decodeTripleBlob127 deserializes a Ring127 Beaver triple envelope.
func decodeTripleBlob127(blob string, n int) (BeaverTripleVec127, error) {
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return BeaverTripleVec127{}, err
	}
	var w tripleWire
	if err := json.Unmarshal(raw, &w); err != nil {
		return BeaverTripleVec127{}, err
	}
	if len(w.A) != 1 || len(w.B) != 1 || len(w.C) != 1 {
		return BeaverTripleVec127{}, &sizeMismatchErr{got: len(w.A), want: 1}
	}
	a, err := decodeRing127Vector(w.A[0], n)
	if err != nil {
		return BeaverTripleVec127{}, err
	}
	b, err := decodeRing127Vector(w.B[0], n)
	if err != nil {
		return BeaverTripleVec127{}, err
	}
	c, err := decodeRing127Vector(w.C[0], n)
	if err != nil {
		return BeaverTripleVec127{}, err
	}
	return BeaverTripleVec127{A: a, B: b, C: c}, nil
}

type sizeMismatchErr struct{ got, want int }

func (e *sizeMismatchErr) Error() string {
	return "triple blob length mismatch"
}

// handleK2BeaverVecmulGenTriples127: dealer-only, n Ring127 triples.
func handleK2BeaverVecmulGenTriples127(input K2BeaverVecmulGenInput) {
	fb := ring127DefaultFracBits(input.FracBits)
	if input.N <= 0 {
		outputError("k2-beaver-vecmul-gen-triples (ring127): n must be positive")
		return
	}
	r := NewRing127(fb)
	p0, p1 := SampleBeaverTripleVector127(input.N, r)
	mpcWriteOutput(K2BeaverVecmulGenOutput{
		Triple0: encodeTripleBlob127(p0),
		Triple1: encodeTripleBlob127(p1),
	})
}

// handleK2BeaverVecmulR1127: per-party round 1.
//
//	d_share = x_share - a_share
//	e_share = y_share - b_share
func handleK2BeaverVecmulR1127(input K2BeaverVecmulR1Input) {
	fb := ring127DefaultFracBits(input.FracBits)
	r := NewRing127(fb)
	start, end, totalN, err := k2BeaverVecmulWindow(
		input.N, input.TotalN, input.Offset)
	if err != nil {
		outputError("k2-beaver-vecmul-round1 (ring127): " + err.Error())
		return
	}
	xAll, err := decodeRing127Vector(input.XFp, totalN)
	if err != nil {
		outputError("k2-beaver-vecmul-round1 (ring127): invalid x_fp: " + err.Error())
		return
	}
	yAll, err := decodeRing127Vector(input.YFp, totalN)
	if err != nil {
		outputError("k2-beaver-vecmul-round1 (ring127): invalid y_fp: " + err.Error())
		return
	}
	tripleAll, err := decodeTripleBlob127(input.TripleBlob, totalN)
	if err != nil {
		outputError("k2-beaver-vecmul-round1 (ring127): bad triple: " + err.Error())
		return
	}
	x, y := xAll[start:end], yAll[start:end]
	triple := BeaverTripleVec127{
		A: tripleAll.A[start:end], B: tripleAll.B[start:end],
		C: tripleAll.C[start:end],
	}
	_, msg := GenerateBatchedMultiplicationGateMessage127(x, y, triple, r)
	mpcWriteOutput(K2BeaverVecmulR1Output{
		DFp: Uint128VecToB64(msg.XMinusAShares),
		EFp: Uint128VecToB64(msg.YMinusBShares),
	})
}

// handleK2BeaverVecmulR2127: per-party round 2. Reconstructs (x-a, y-b),
// computes the party's UNtruncated share of x·y, then truncates back to
// fracBits via TruncateSharePartyZero127 / TruncateSharePartyOne127.
func handleK2BeaverVecmulR2127(input K2BeaverVecmulR2Input) {
	fb := ring127DefaultFracBits(input.FracBits)
	r := NewRing127(fb)
	start, end, totalN, err := k2BeaverVecmulWindow(
		input.N, input.TotalN, input.Offset)
	if err != nil {
		outputError("k2-beaver-vecmul-round2 (ring127): " + err.Error())
		return
	}
	xAll, err := decodeRing127Vector(input.XFp, totalN)
	if err != nil {
		outputError("k2-beaver-vecmul-round2 (ring127): invalid x_fp: " + err.Error())
		return
	}
	yAll, err := decodeRing127Vector(input.YFp, totalN)
	if err != nil {
		outputError("k2-beaver-vecmul-round2 (ring127): invalid y_fp: " + err.Error())
		return
	}
	n := input.N
	tripleAll, err := decodeTripleBlob127(input.TripleBlob, totalN)
	if err != nil {
		outputError("k2-beaver-vecmul-round2 (ring127): bad triple: " + err.Error())
		return
	}
	x, y := xAll[start:end], yAll[start:end]
	triple := BeaverTripleVec127{
		A: tripleAll.A[start:end], B: tripleAll.B[start:end],
		C: tripleAll.C[start:end],
	}
	peerD, err := decodeRing127Vector(input.PeerDFp, n)
	if err != nil {
		outputError("k2-beaver-vecmul-round2 (ring127): invalid peer_d_fp: " + err.Error())
		return
	}
	peerE, err := decodeRing127Vector(input.PeerEFp, n)
	if err != nil {
		outputError("k2-beaver-vecmul-round2 (ring127): invalid peer_e_fp: " + err.Error())
		return
	}
	state := BatchedMultState127{
		ShareXMinusA: make([]Uint128, n),
		ShareYMinusB: make([]Uint128, n),
	}
	for i := 0; i < n; i++ {
		state.ShareXMinusA[i] = r.Sub(x[i], triple.A[i])
		state.ShareYMinusB[i] = r.Sub(y[i], triple.B[i])
	}
	peerMsg := MultGateMessage127{
		XMinusAShares: peerD,
		YMinusBShares: peerE,
	}
	var raw []Uint128
	if input.IsParty0 {
		raw = GenerateBatchedMultiplicationOutputPartyZero127(state, triple, peerMsg, r)
	} else {
		raw = GenerateBatchedMultiplicationOutputPartyOne127(state, triple, peerMsg, r)
	}
	if !input.ExactGCDeferTruncation {
		if input.IsParty0 {
			raw = TruncateSharePartyZero127(raw, fb, r)
		} else {
			raw = TruncateSharePartyOne127(raw, fb, r)
		}
	}
	mpcWriteOutput(K2BeaverVecmulR2Output{
		ZFp: Uint128VecToB64(raw),
	})
}
