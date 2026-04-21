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
	a := b64Uint128Vec(w.A[0])
	b := b64Uint128Vec(w.B[0])
	c := b64Uint128Vec(w.C[0])
	if n > 0 && (len(a) != n || len(b) != n || len(c) != n) {
		return BeaverTripleVec127{}, &sizeMismatchErr{got: len(a), want: n}
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
//   d_share = x_share - a_share
//   e_share = y_share - b_share
func handleK2BeaverVecmulR1127(input K2BeaverVecmulR1Input) {
	fb := ring127DefaultFracBits(input.FracBits)
	r := NewRing127(fb)
	x := b64Uint128Vec(input.XFp)
	y := b64Uint128Vec(input.YFp)
	if len(x) != len(y) {
		outputError("k2-beaver-vecmul-round1 (ring127): length mismatch")
		return
	}
	triple, err := decodeTripleBlob127(input.TripleBlob, len(x))
	if err != nil {
		outputError("k2-beaver-vecmul-round1 (ring127): bad triple: " + err.Error())
		return
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
	x := b64Uint128Vec(input.XFp)
	y := b64Uint128Vec(input.YFp)
	if len(x) != len(y) {
		outputError("k2-beaver-vecmul-round2 (ring127): length mismatch")
		return
	}
	n := len(x)
	triple, err := decodeTripleBlob127(input.TripleBlob, n)
	if err != nil {
		outputError("k2-beaver-vecmul-round2 (ring127): bad triple: " + err.Error())
		return
	}
	peerD := b64Uint128Vec(input.PeerDFp)
	peerE := b64Uint128Vec(input.PeerEFp)
	if len(peerD) != n || len(peerE) != n {
		outputError("k2-beaver-vecmul-round2 (ring127): peer msg length mismatch")
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
		raw = TruncateSharePartyZero127(raw, fb, r)
	} else {
		raw = GenerateBatchedMultiplicationOutputPartyOne127(state, triple, peerMsg, r)
		raw = TruncateSharePartyOne127(raw, fb, r)
	}
	mpcWriteOutput(K2BeaverVecmulR2Output{
		ZFp: Uint128VecToB64(raw),
	})
}
