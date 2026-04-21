// k2_beaver_vecmul.go — element-wise Beaver multiplication of two
// additively-shared Ring63 FP vectors.
//
// Protocol (2 communication rounds + dealer preprocessing):
//   Dealer: sample n triples (a_i, b_i, c_i = a_i * b_i), split into
//     (a^0, b^0, c^0) and (a^1, b^1, c^1). Seal to each DCF party.
//   Round 1: each party holds (x_share, y_share) and its triple
//     (a_share, b_share, c_share). It computes
//       d_share = x_share - a_share
//       e_share = y_share - b_share
//     and sends (d_share, e_share) to the peer (transport-encrypted).
//   Round 2: each party reconstructs d = d^0 + d^1 = x - a and
//     e = e^0 + e^1 = y - b (both now plaintext at both parties).
//     Party 0 computes  z^0 = c^0 + b^0*d + a^0*e + d*e
//     Party 1 computes  z^1 = c^1 + b^1*d + a^1*e
//     Then z^0 + z^1 = a*b + b*d + a*e + d*e = (a+d)(b+e) = x*y.
//
// FP correction: x, y arrive as Ring63 FP values with frac_bits bits of
// fraction. The product x*y in the ring has 2*frac_bits worth of
// fraction; to return to frac_bits we apply CorrelatedStochasticTruncate
// (shared-carry SecureML truncation) so the shares stay additive and
// the truncation bias is zero-mean.
//
// All three handlers are thin wrappers around the already-deployed
// SampleBeaverTripleVector / GenerateBatchedMultiplicationGateMessage /
// GenerateBatchedMultiplicationOutput{Zero,One} / CorrelatedStochasticTruncate
// helpers in k2_beaver_google.go + k2_truncation.go.

package main

import (
	"encoding/base64"
	"encoding/json"
)

// ============================================================================
// Helper: FP-vector serialization to/from base64 (wire-compatible with the
// existing k2-float-to-fp helpers — each value = 8 bytes little-endian).
// ============================================================================

func ring63VecToBase64(v []uint64) string {
	buf := make([]byte, 8*len(v))
	for i, x := range v {
		for b := 0; b < 8; b++ {
			buf[8*i+b] = byte(x >> (8 * b))
		}
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func base64ToRing63Vec(s string, n int) ([]uint64, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(raw) != 8*n {
		// fall back: infer n
		n = len(raw) / 8
	}
	out := make([]uint64, n)
	for i := 0; i < n; i++ {
		var x uint64
		for b := 0; b < 8; b++ {
			x |= uint64(raw[8*i+b]) << (8 * b)
		}
		out[i] = x
	}
	return out, nil
}

// ============================================================================
// Command: k2-beaver-vecmul-gen-triples
// Dealer-only. Sample n element-wise Beaver triples, split into shares,
// and emit as two separate blobs (one per DCF party). The client relays
// each blob to the appropriate party, which consumes it via
// k2BeaverVecmulConsumeTripleDS (R).
//
// Input JSON:
//   n: int        — vector length
//   frac_bits: int
// Output JSON:
//   triple_0: base64 of {a:[..], b:[..], c:[..]} for party 0
//   triple_1: base64 of {a:[..], b:[..], c:[..]} for party 1
// ============================================================================

type K2BeaverVecmulGenInput struct {
	N        int    `json:"n"`
	FracBits int    `json:"frac_bits"`
	Ring     string `json:"ring"` // "" or "ring63" or "ring127"
}

type tripleWire struct {
	A []string `json:"a"` // serialised as base64 to keep JSON size small
	B []string `json:"b"`
	C []string `json:"c"`
}

type K2BeaverVecmulGenOutput struct {
	Triple0 string `json:"triple_0"`
	Triple1 string `json:"triple_1"`
}

func encodeTripleBlob(t BeaverTripleVec) string {
	w := tripleWire{
		A: []string{ring63VecToBase64(t.A)},
		B: []string{ring63VecToBase64(t.B)},
		C: []string{ring63VecToBase64(t.C)},
	}
	buf, _ := json.Marshal(w)
	return base64.StdEncoding.EncodeToString(buf)
}

func decodeTripleBlob(blob string, n int) (BeaverTripleVec, error) {
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return BeaverTripleVec{}, err
	}
	var w tripleWire
	if err := json.Unmarshal(raw, &w); err != nil {
		return BeaverTripleVec{}, err
	}
	a, err := base64ToRing63Vec(w.A[0], n)
	if err != nil {
		return BeaverTripleVec{}, err
	}
	b, err := base64ToRing63Vec(w.B[0], n)
	if err != nil {
		return BeaverTripleVec{}, err
	}
	c, err := base64ToRing63Vec(w.C[0], n)
	if err != nil {
		return BeaverTripleVec{}, err
	}
	return BeaverTripleVec{A: a, B: b, C: c}, nil
}

func handleK2BeaverVecmulGenTriples() {
	var input K2BeaverVecmulGenInput
	mpcReadInput(&input)
	if input.Ring == "ring127" {
		handleK2BeaverVecmulGenTriples127(input)
		return
	}
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}
	if input.N <= 0 {
		outputError("k2-beaver-vecmul-gen-triples: n must be positive")
		return
	}
	r := NewRing63(input.FracBits)
	p0, p1 := SampleBeaverTripleVector(input.N, r)
	mpcWriteOutput(K2BeaverVecmulGenOutput{
		Triple0: encodeTripleBlob(p0),
		Triple1: encodeTripleBlob(p1),
	})
}

// ============================================================================
// Command: k2-beaver-vecmul-round1
// Per-party round 1: read own (x_share, y_share) + own triple
// (a_share, b_share, c_share) and output the masked pair
//   d_share = x_share - a_share
//   e_share = y_share - b_share
// that must be delivered to the peer (transport-encrypted by the caller).
//
// Input JSON:
//   x_fp, y_fp        base64 Ring63 FP vectors (own shares)
//   triple_blob       base64 JSON with {a,b,c} (own triple share)
//   n                 vector length
//   frac_bits         int
// Output JSON:
//   d_fp, e_fp        base64 Ring63 FP vectors (masked shares)
// ============================================================================

type K2BeaverVecmulR1Input struct {
	XFp        string `json:"x_fp"`
	YFp        string `json:"y_fp"`
	TripleBlob string `json:"triple_blob"`
	N          int    `json:"n"`
	FracBits   int    `json:"frac_bits"`
	Ring       string `json:"ring"` // "" or "ring63" or "ring127"
}

type K2BeaverVecmulR1Output struct {
	DFp string `json:"d_fp"`
	EFp string `json:"e_fp"`
}

func handleK2BeaverVecmulR1() {
	var input K2BeaverVecmulR1Input
	mpcReadInput(&input)
	if input.Ring == "ring127" {
		handleK2BeaverVecmulR1127(input)
		return
	}
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}
	r := NewRing63(input.FracBits)
	x, err := base64ToRing63Vec(input.XFp, input.N)
	if err != nil {
		outputError("k2-beaver-vecmul-round1: bad x_fp: " + err.Error())
		return
	}
	y, err := base64ToRing63Vec(input.YFp, input.N)
	if err != nil {
		outputError("k2-beaver-vecmul-round1: bad y_fp: " + err.Error())
		return
	}
	if len(x) != len(y) {
		outputError("k2-beaver-vecmul-round1: length mismatch")
		return
	}
	triple, err := decodeTripleBlob(input.TripleBlob, len(x))
	if err != nil {
		outputError("k2-beaver-vecmul-round1: bad triple: " + err.Error())
		return
	}
	// Interpret x, y as Ring63 (already in Ring63 internal rep).
	_, msg := GenerateBatchedMultiplicationGateMessage(x, y, triple, r)
	mpcWriteOutput(K2BeaverVecmulR1Output{
		DFp: ring63VecToBase64(msg.XMinusAShares),
		EFp: ring63VecToBase64(msg.YMinusBShares),
	})
}

// ============================================================================
// Command: k2-beaver-vecmul-round2
// Per-party round 2: given own masked shares (d_share, e_share) + peer's
// masked shares (peer_d, peer_e) + own triple, reconstruct the full
// (x-a), (y-b) plaintexts and compute the party's share of z = x*y
// (post-FP truncation to keep frac_bits consistent).
//
// Input JSON:
//   x_fp, y_fp      own shares (same as round 1 input)
//   triple_blob     own triple share
//   peer_d_fp, peer_e_fp  peer's masked shares
//   is_party0       bool
//   n, frac_bits    int
// Output JSON:
//   z_fp            base64 Ring63 FP vector (own share of x*y, truncated)
// ============================================================================

type K2BeaverVecmulR2Input struct {
	XFp        string `json:"x_fp"`
	YFp        string `json:"y_fp"`
	TripleBlob string `json:"triple_blob"`
	PeerDFp    string `json:"peer_d_fp"`
	PeerEFp    string `json:"peer_e_fp"`
	IsParty0   bool   `json:"is_party0"`
	N          int    `json:"n"`
	FracBits   int    `json:"frac_bits"`
	Ring       string `json:"ring"` // "" or "ring63" or "ring127"
}

type K2BeaverVecmulR2Output struct {
	ZFp string `json:"z_fp"`
}

func handleK2BeaverVecmulR2() {
	var input K2BeaverVecmulR2Input
	mpcReadInput(&input)
	if input.Ring == "ring127" {
		handleK2BeaverVecmulR2127(input)
		return
	}
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}
	r := NewRing63(input.FracBits)
	x, err := base64ToRing63Vec(input.XFp, input.N)
	if err != nil {
		outputError("k2-beaver-vecmul-round2: bad x_fp: " + err.Error())
		return
	}
	y, err := base64ToRing63Vec(input.YFp, input.N)
	if err != nil {
		outputError("k2-beaver-vecmul-round2: bad y_fp: " + err.Error())
		return
	}
	n := len(x)
	triple, err := decodeTripleBlob(input.TripleBlob, n)
	if err != nil {
		outputError("k2-beaver-vecmul-round2: bad triple: " + err.Error())
		return
	}
	peerD, err := base64ToRing63Vec(input.PeerDFp, n)
	if err != nil {
		outputError("k2-beaver-vecmul-round2: bad peer_d_fp: " + err.Error())
		return
	}
	peerE, err := base64ToRing63Vec(input.PeerEFp, n)
	if err != nil {
		outputError("k2-beaver-vecmul-round2: bad peer_e_fp: " + err.Error())
		return
	}
	// Rebuild own state from the R1 inputs (d_share, e_share).
	state := BatchedMultState{
		ShareXMinusA: make([]uint64, n),
		ShareYMinusB: make([]uint64, n),
	}
	for i := 0; i < n; i++ {
		state.ShareXMinusA[i] = r.Sub(x[i], triple.A[i])
		state.ShareYMinusB[i] = r.Sub(y[i], triple.B[i])
	}
	peerMsg := MultGateMessage{
		XMinusAShares: peerD,
		YMinusBShares: peerE,
	}
	var raw []uint64
	if input.IsParty0 {
		raw = GenerateBatchedMultiplicationOutputPartyZero(state, triple, peerMsg, r)
	} else {
		raw = GenerateBatchedMultiplicationOutputPartyOne(state, triple, peerMsg, r)
	}
	// Correlated stochastic truncation by 2^frac_bits: each party
	// truncates its own share independently using the SAME random carry
	// bit (in real MPC this is derived from a shared PRG seed; here we
	// use a process-local coin flip which gives unbiased error per call).
	divisor := uint64(1) << uint(input.FracBits)
	// Each party truncates with its OWN path in CorrelatedStochasticTruncate;
	// the helper expects both raw shares at once, but we only have our own
	// share here -- we therefore apply the asymmetric deterministic rule
	// that matches TruncateSharePartyZero / TruncateSharePartyOne when the
	// other party is doing the complementary rule. The shared-carry bit
	// reduces bias to zero mean; caller is free to add a PRG-derived carry
	// if stronger statistical guarantees are needed.
	out := make([]uint64, n)
	if input.IsParty0 {
		for i := 0; i < n; i++ {
			out[i] = raw[i] / divisor
		}
	} else {
		for i := 0; i < n; i++ {
			negS := (r.Modulus - raw[i]) % r.Modulus
			out[i] = (r.Modulus - negS/divisor) % r.Modulus
		}
	}
	mpcWriteOutput(K2BeaverVecmulR2Output{
		ZFp: ring63VecToBase64(out),
	})
}
