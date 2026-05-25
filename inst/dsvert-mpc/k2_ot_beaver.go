// k2_ot_beaver.go -- stepwise OT-Beaver preprocessing for dsVert.
//
// The existing online Beaver multiplication rounds consume additive shares of
// triples (a, b, c=a*b).  This file adds an offline generator that derives the
// cross terms with Chou-Orlandi 1-out-of-2 OT instead of asking one server to
// sample the whole triple and split it.  The protocol is intentionally exposed
// as small stateless commands so the DataSHIELD client can relay public OT
// messages between servers without opening a direct server-to-server socket.

package main

import (
	"crypto/elliptic"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/markkurossi/mpc/ot"
)

type otBeaverSampleInput struct {
	Kind string `json:"kind"` // "vecmul" or "matvec"
	N    int    `json:"n"`
	P    int    `json:"p"`
	Ring string `json:"ring"` // "ring63" or "ring127"
}

type otBeaverSampleOutput struct {
	A         string `json:"a"`
	B         string `json:"b"`
	BExpanded string `json:"b_expanded,omitempty"`
}

type otSetupPublicWire struct {
	Curve string `json:"curve"`
	Ax    string `json:"ax"`
	Ay    string `json:"ay"`
}

type otSetupSecretWire struct {
	Curve  string `json:"curve"`
	Scalar string `json:"scalar"`
	Ax     string `json:"ax"`
	Ay     string `json:"ay"`
	AaInvX string `json:"aa_inv_x"`
	AaInvY string `json:"aa_inv_y"`
}

type otPointWire struct {
	X string `json:"x"`
	Y string `json:"y"`
}

type otChoiceBundleWire struct {
	Curve   string   `json:"curve"`
	Ax      string   `json:"ax"`
	Ay      string   `json:"ay"`
	Scalars []string `json:"scalars"`
	Bits    string   `json:"bits"`
	Count   int      `json:"count"`
}

type otCipherWire struct {
	Zero string `json:"zero"`
	One  string `json:"one"`
}

type otMulSenderSetupOutput struct {
	PublicSetup string `json:"public_setup"`
	SecretSetup string `json:"secret_setup"`
}

type otMulReceiverChoicesInput struct {
	PublicSetup string `json:"public_setup"`
	Y           string `json:"y"`
	N           int    `json:"n"`
	Ring        string `json:"ring"`
}

type otMulReceiverChoicesOutput struct {
	ChoiceBundle string `json:"choice_bundle"`
	Points       string `json:"points"`
}

type otMulSenderEncryptInput struct {
	SecretSetup string `json:"secret_setup"`
	Points      string `json:"points"`
	X           string `json:"x"`
	N           int    `json:"n"`
	Ring        string `json:"ring"`
}

type otMulSenderEncryptOutput struct {
	SenderShare string `json:"sender_share"`
	Ciphertexts string `json:"ciphertexts"`
}

type otMulReceiverDecryptInput struct {
	ChoiceBundle string `json:"choice_bundle"`
	Ciphertexts  string `json:"ciphertexts"`
	N            int    `json:"n"`
	Ring         string `json:"ring"`
}

type otMulReceiverDecryptOutput struct {
	ReceiverShare string `json:"receiver_share"`
}

type otBeaverFinalizeInput struct {
	Kind         string `json:"kind"` // "vecmul" or "matvec"
	N            int    `json:"n"`
	P            int    `json:"p"`
	Ring         string `json:"ring"`
	A            string `json:"a"`
	B            string `json:"b"`
	CrossSend    string `json:"cross_send"`
	CrossReceive string `json:"cross_receive"`
}

type otBeaverFinalizeOutput struct {
	TripleBlob string `json:"triple_blob,omitempty"`
	A          string `json:"a,omitempty"`
	B          string `json:"b,omitempty"`
	C          string `json:"c,omitempty"`
}

func handleK2OTBeaverSample() {
	var input otBeaverSampleInput
	mpcReadInput(&input)
	if input.N <= 0 {
		outputError("k2-ot-beaver-sample: n must be positive")
		return
	}
	ring := normalizeOTRing(input.Ring)
	kind := input.Kind
	if kind == "" {
		kind = "vecmul"
	}
	switch ring {
	case "ring127":
		handleK2OTBeaverSample127(kind, input.N, input.P)
	default:
		handleK2OTBeaverSample63(kind, input.N, input.P)
	}
}

func handleK2OTBeaverSample63(kind string, n, p int) {
	switch kind {
	case "vecmul":
		a := make([]uint64, n)
		b := make([]uint64, n)
		for i := 0; i < n; i++ {
			a[i] = cryptoRandUint64K2() % (uint64(1) << 63)
			b[i] = cryptoRandUint64K2() % (uint64(1) << 63)
		}
		mpcWriteOutput(otBeaverSampleOutput{
			A: ring63VectorToFPB64(a),
			B: ring63VectorToFPB64(b),
		})
	case "matvec":
		if p <= 0 {
			outputError("k2-ot-beaver-sample: p must be positive for matvec")
			return
		}
		a := make([]uint64, n*p)
		b := make([]uint64, n)
		bx := make([]uint64, n*p)
		for i := range a {
			a[i] = cryptoRandUint64K2() % (uint64(1) << 63)
		}
		for i := range b {
			b[i] = cryptoRandUint64K2() % (uint64(1) << 63)
			for j := 0; j < p; j++ {
				bx[i*p+j] = b[i]
			}
		}
		mpcWriteOutput(otBeaverSampleOutput{
			A:         ring63VectorToFPB64(a),
			B:         ring63VectorToFPB64(b),
			BExpanded: ring63VectorToFPB64(bx),
		})
	default:
		outputError("k2-ot-beaver-sample: unsupported kind " + kind)
	}
}

func handleK2OTBeaverSample127(kind string, n, p int) {
	r := NewRing127(K2DefaultFracBits127)
	switch kind {
	case "vecmul":
		a := make([]Uint128, n)
		b := make([]Uint128, n)
		for i := 0; i < n; i++ {
			a[i] = cryptoRandUint128().ModPow127()
			b[i] = cryptoRandUint128().ModPow127()
		}
		_ = r
		mpcWriteOutput(otBeaverSampleOutput{A: Uint128VecToB64(a), B: Uint128VecToB64(b)})
	case "matvec":
		if p <= 0 {
			outputError("k2-ot-beaver-sample: p must be positive for matvec")
			return
		}
		a := make([]Uint128, n*p)
		b := make([]Uint128, n)
		bx := make([]Uint128, n*p)
		for i := range a {
			a[i] = cryptoRandUint128().ModPow127()
		}
		for i := range b {
			b[i] = cryptoRandUint128().ModPow127()
			for j := 0; j < p; j++ {
				bx[i*p+j] = b[i]
			}
		}
		_ = r
		mpcWriteOutput(otBeaverSampleOutput{A: Uint128VecToB64(a), B: Uint128VecToB64(b), BExpanded: Uint128VecToB64(bx)})
	default:
		outputError("k2-ot-beaver-sample: unsupported kind " + kind)
	}
}

func handleK2OTMulSenderSetup() {
	curve := elliptic.P256()
	setup, err := ot.GenerateCOSenderSetup(crand.Reader, curve)
	if err != nil {
		outputError("k2-ot-mul-sender-setup: " + err.Error())
		return
	}
	pub := otSetupPublicWire{
		Curve: setup.CurveName,
		Ax:    b64Big(setup.Ax),
		Ay:    b64Big(setup.Ay),
	}
	sec := otSetupSecretWire{
		Curve:  setup.CurveName,
		Scalar: b64Big(setup.Scalar),
		Ax:     b64Big(setup.Ax),
		Ay:     b64Big(setup.Ay),
		AaInvX: b64Big(setup.AaInvX),
		AaInvY: b64Big(setup.AaInvY),
	}
	mpcWriteOutput(otMulSenderSetupOutput{
		PublicSetup: encodeJSONB64(pub),
		SecretSetup: encodeJSONB64(sec),
	})
}

func handleK2OTMulReceiverChoices() {
	var input otMulReceiverChoicesInput
	mpcReadInput(&input)
	ring := normalizeOTRing(input.Ring)
	curve := elliptic.P256()
	pub, err := decodePublicSetup(input.PublicSetup)
	if err != nil {
		outputError("k2-ot-mul-receiver-choices: " + err.Error())
		return
	}
	yBits, err := otChoiceBits(input.Y, input.N, ring)
	if err != nil {
		outputError("k2-ot-mul-receiver-choices: " + err.Error())
		return
	}
	bundle, points, err := ot.BuildCOChoices(crand.Reader, curve, pub.Ax, pub.Ay, yBits)
	if err != nil {
		outputError("k2-ot-mul-receiver-choices: " + err.Error())
		return
	}
	bw := otChoiceBundleWire{
		Curve:   bundle.CurveName,
		Ax:      b64Big(bundle.Ax),
		Ay:      b64Big(bundle.Ay),
		Scalars: make([]string, len(bundle.Scalars)),
		Bits:    packBoolsB64(bundle.Bits),
		Count:   len(bundle.Bits),
	}
	for i, s := range bundle.Scalars {
		bw.Scalars[i] = b64Big(s)
	}
	pw := make([]otPointWire, len(points))
	for i, p := range points {
		pw[i] = otPointWire{X: b64Big(p.X), Y: b64Big(p.Y)}
	}
	mpcWriteOutput(otMulReceiverChoicesOutput{
		ChoiceBundle: encodeJSONB64(bw),
		Points:       encodeJSONB64(pw),
	})
}

func handleK2OTMulSenderEncrypt() {
	var input otMulSenderEncryptInput
	mpcReadInput(&input)
	ring := normalizeOTRing(input.Ring)
	curve := elliptic.P256()
	setup, err := decodeSecretSetup(input.SecretSetup)
	if err != nil {
		outputError("k2-ot-mul-sender-encrypt: " + err.Error())
		return
	}
	points, err := decodePoints(input.Points)
	if err != nil {
		outputError("k2-ot-mul-sender-encrypt: " + err.Error())
		return
	}
	wires, senderShare, err := otArithmeticWires(input.X, input.N, ring)
	if err != nil {
		outputError("k2-ot-mul-sender-encrypt: " + err.Error())
		return
	}
	if len(points) != len(wires) {
		outputError(fmt.Sprintf("k2-ot-mul-sender-encrypt: point count %d != wire count %d", len(points), len(wires)))
		return
	}
	ciphertexts, err := ot.EncryptCOCiphertexts(curve, setup, points, wires)
	if err != nil {
		outputError("k2-ot-mul-sender-encrypt: " + err.Error())
		return
	}
	cw := make([]otCipherWire, len(ciphertexts))
	for i, ct := range ciphertexts {
		cw[i] = otCipherWire{
			Zero: base64.StdEncoding.EncodeToString(ct.Zero[:]),
			One:  base64.StdEncoding.EncodeToString(ct.One[:]),
		}
	}
	mpcWriteOutput(otMulSenderEncryptOutput{
		SenderShare: encodeRingVectorB64(senderShare, ring),
		Ciphertexts: encodeJSONB64(cw),
	})
}

func handleK2OTMulReceiverDecrypt() {
	var input otMulReceiverDecryptInput
	mpcReadInput(&input)
	ring := normalizeOTRing(input.Ring)
	curve := elliptic.P256()
	bundle, err := decodeChoiceBundle(input.ChoiceBundle)
	if err != nil {
		outputError("k2-ot-mul-receiver-decrypt: " + err.Error())
		return
	}
	ciphertexts, err := decodeCiphertexts(input.Ciphertexts)
	if err != nil {
		outputError("k2-ot-mul-receiver-decrypt: " + err.Error())
		return
	}
	labels, err := ot.DecryptCOCiphertexts(curve, bundle, ciphertexts)
	if err != nil {
		outputError("k2-ot-mul-receiver-decrypt: " + err.Error())
		return
	}
	share, err := otLabelsToRingShare(labels, input.N, ring)
	if err != nil {
		outputError("k2-ot-mul-receiver-decrypt: " + err.Error())
		return
	}
	mpcWriteOutput(otMulReceiverDecryptOutput{ReceiverShare: encodeRingVectorB64(share, ring)})
}

func handleK2OTBeaverFinalize() {
	var input otBeaverFinalizeInput
	mpcReadInput(&input)
	ring := normalizeOTRing(input.Ring)
	kind := input.Kind
	if kind == "" {
		kind = "vecmul"
	}
	switch ring {
	case "ring127":
		handleK2OTBeaverFinalize127(input, kind)
	default:
		handleK2OTBeaverFinalize63(input, kind)
	}
}

func handleK2OTBeaverFinalize63(input otBeaverFinalizeInput, kind string) {
	a, err := decodeRing63FP(input.A, expectedAInputLen(input.N, input.P, kind))
	if err != nil {
		outputError("k2-ot-beaver-finalize: " + err.Error())
		return
	}
	b, err := decodeRing63FP(input.B, input.N)
	if err != nil {
		outputError("k2-ot-beaver-finalize: " + err.Error())
		return
	}
	cs, err := decodeRing63FP(input.CrossSend, len(a))
	if err != nil {
		outputError("k2-ot-beaver-finalize: " + err.Error())
		return
	}
	cr, err := decodeRing63FP(input.CrossReceive, len(a))
	if err != nil {
		outputError("k2-ot-beaver-finalize: " + err.Error())
		return
	}
	mod := uint64(1) << 63
	switch kind {
	case "vecmul":
		if len(a) != input.N || len(b) != input.N {
			outputError("k2-ot-beaver-finalize: vecmul length mismatch")
			return
		}
		c := make([]uint64, input.N)
		for i := 0; i < input.N; i++ {
			c[i] = (modMulBig63(a[i], b[i], mod) + cs[i] + cr[i]) % mod
		}
		mpcWriteOutput(otBeaverFinalizeOutput{
			TripleBlob: encodeTripleBlob(BeaverTripleVec{A: a, B: b, C: c}),
			A:          ring63VectorToFPB64(a),
			B:          ring63VectorToFPB64(b),
			C:          ring63VectorToFPB64(c),
		})
	case "matvec":
		p := input.P
		if input.N <= 0 || p <= 0 || len(a) != input.N*p || len(b) != input.N {
			outputError("k2-ot-beaver-finalize: matvec length mismatch")
			return
		}
		c := make([]uint64, p)
		for i := 0; i < input.N; i++ {
			for j := 0; j < p; j++ {
				idx := i*p + j
				term := (modMulBig63(a[idx], b[i], mod) + cs[idx] + cr[idx]) % mod
				c[j] = (c[j] + term) % mod
			}
		}
		mpcWriteOutput(otBeaverFinalizeOutput{
			A: ring63VectorToFPB64(a),
			B: ring63VectorToFPB64(b),
			C: ring63VectorToFPB64(c),
		})
	default:
		outputError("k2-ot-beaver-finalize: unsupported kind " + kind)
	}
}

func handleK2OTBeaverFinalize127(input otBeaverFinalizeInput, kind string) {
	r := NewRing127(K2DefaultFracBits127)
	a, err := decodeRing127(input.A, expectedAInputLen(input.N, input.P, kind))
	if err != nil {
		outputError("k2-ot-beaver-finalize: " + err.Error())
		return
	}
	b, err := decodeRing127(input.B, input.N)
	if err != nil {
		outputError("k2-ot-beaver-finalize: " + err.Error())
		return
	}
	cs, err := decodeRing127(input.CrossSend, len(a))
	if err != nil {
		outputError("k2-ot-beaver-finalize: " + err.Error())
		return
	}
	cr, err := decodeRing127(input.CrossReceive, len(a))
	if err != nil {
		outputError("k2-ot-beaver-finalize: " + err.Error())
		return
	}
	switch kind {
	case "vecmul":
		if len(a) != input.N || len(b) != input.N {
			outputError("k2-ot-beaver-finalize: vecmul length mismatch")
			return
		}
		c := make([]Uint128, input.N)
		for i := 0; i < input.N; i++ {
			c[i] = r.Add(r.Add(a[i].Mul(b[i]).ModPow127(), cs[i]), cr[i])
		}
		mpcWriteOutput(otBeaverFinalizeOutput{
			TripleBlob: encodeTripleBlob127(BeaverTripleVec127{A: a, B: b, C: c}),
			A:          Uint128VecToB64(a),
			B:          Uint128VecToB64(b),
			C:          Uint128VecToB64(c),
		})
	case "matvec":
		p := input.P
		if input.N <= 0 || p <= 0 || len(a) != input.N*p || len(b) != input.N {
			outputError("k2-ot-beaver-finalize: matvec length mismatch")
			return
		}
		c := make([]Uint128, p)
		for i := 0; i < input.N; i++ {
			for j := 0; j < p; j++ {
				idx := i*p + j
				term := r.Add(r.Add(a[idx].Mul(b[i]).ModPow127(), cs[idx]), cr[idx])
				c[j] = r.Add(c[j], term)
			}
		}
		mpcWriteOutput(otBeaverFinalizeOutput{
			A: Uint128VecToB64(a),
			B: Uint128VecToB64(b),
			C: Uint128VecToB64(c),
		})
	default:
		outputError("k2-ot-beaver-finalize: unsupported kind " + kind)
	}
}

func normalizeOTRing(ring string) string {
	if ring == "ring127" || ring == "127" {
		return "ring127"
	}
	return "ring63"
}

func expectedAInputLen(n, p int, kind string) int {
	if kind == "matvec" {
		return n * p
	}
	return n
}

func ringBitLen(ring string) int {
	if ring == "ring127" {
		return 127
	}
	return 63
}

func ring63VectorToFPB64(v []uint64) string {
	return bytesToBase64(fpVecToBytes(ring63ToFP(v)))
}

func decodeRing63FP(s string, expected int) ([]uint64, error) {
	raw := base64ToBytes(s)
	if raw == nil {
		return nil, fmt.Errorf("bad ring63 base64")
	}
	v := fpToRing63(bytesToFPVec(raw))
	if expected > 0 && len(v) != expected {
		return nil, fmt.Errorf("ring63 length mismatch: got %d want %d", len(v), expected)
	}
	return v, nil
}

func decodeRing127(s string, expected int) ([]Uint128, error) {
	raw := base64ToBytes(s)
	if raw == nil {
		return nil, fmt.Errorf("bad ring127 base64")
	}
	v := bytesToUint128Vec(raw)
	if expected > 0 && len(v) != expected {
		return nil, fmt.Errorf("ring127 length mismatch: got %d want %d", len(v), expected)
	}
	return v, nil
}

func encodeRingVectorB64(v any, ring string) string {
	if ring == "ring127" {
		return Uint128VecToB64(v.([]Uint128))
	}
	return ring63VectorToFPB64(v.([]uint64))
}

func otChoiceBits(yB64 string, n int, ring string) ([]bool, error) {
	bitsPer := ringBitLen(ring)
	out := make([]bool, n*bitsPer)
	if ring == "ring127" {
		y, err := decodeRing127(yB64, n)
		if err != nil {
			return nil, err
		}
		for i, val := range y {
			for j := 0; j < bitsPer; j++ {
				var bit bool
				if j < 64 {
					bit = ((val.Lo >> uint(j)) & 1) == 1
				} else {
					bit = ((val.Hi >> uint(j-64)) & 1) == 1
				}
				out[i*bitsPer+j] = bit
			}
		}
		return out, nil
	}
	y, err := decodeRing63FP(yB64, n)
	if err != nil {
		return nil, err
	}
	for i, val := range y {
		for j := 0; j < bitsPer; j++ {
			out[i*bitsPer+j] = ((val >> uint(j)) & 1) == 1
		}
	}
	return out, nil
}

func otArithmeticWires(xB64 string, n int, ring string) ([]ot.Wire, any, error) {
	bitsPer := ringBitLen(ring)
	wires := make([]ot.Wire, n*bitsPer)
	if ring == "ring127" {
		r := NewRing127(K2DefaultFracBits127)
		x, err := decodeRing127(xB64, n)
		if err != nil {
			return nil, nil, err
		}
		share := make([]Uint128, n)
		for i, xi := range x {
			for j := 0; j < bitsPer; j++ {
				mask := cryptoRandUint128().ModPow127()
				term := xi.Shl(uint(j)).ModPow127()
				m1 := r.Add(mask, term)
				wires[i*bitsPer+j] = ot.Wire{L0: labelFromUint128(mask), L1: labelFromUint128(m1)}
				share[i] = r.Sub(share[i], mask)
			}
		}
		return wires, share, nil
	}
	x, err := decodeRing63FP(xB64, n)
	if err != nil {
		return nil, nil, err
	}
	mod := uint64(1) << 63
	share := make([]uint64, n)
	for i, xi := range x {
		for j := 0; j < bitsPer; j++ {
			mask := cryptoRandUint64K2() % mod
			term := (xi << uint(j)) % mod
			m1 := (mask + term) % mod
			wires[i*bitsPer+j] = ot.Wire{L0: labelFromUint64(mask), L1: labelFromUint64(m1)}
			share[i] = (share[i] + mod - mask) % mod
		}
	}
	return wires, share, nil
}

func otLabelsToRingShare(labels []ot.Label, n int, ring string) (any, error) {
	bitsPer := ringBitLen(ring)
	if len(labels) != n*bitsPer {
		return nil, fmt.Errorf("label count mismatch: got %d want %d", len(labels), n*bitsPer)
	}
	if ring == "ring127" {
		r := NewRing127(K2DefaultFracBits127)
		out := make([]Uint128, n)
		for i := 0; i < n; i++ {
			var acc Uint128
			for j := 0; j < bitsPer; j++ {
				acc = r.Add(acc, uint128FromLabel(labels[i*bitsPer+j]))
			}
			out[i] = acc
		}
		return out, nil
	}
	mod := uint64(1) << 63
	out := make([]uint64, n)
	for i := 0; i < n; i++ {
		var acc uint64
		for j := 0; j < bitsPer; j++ {
			acc = (acc + uint64FromLabel(labels[i*bitsPer+j])) % mod
		}
		out[i] = acc
	}
	return out, nil
}

func labelFromUint64(x uint64) ot.Label {
	var data ot.LabelData
	// Put the ring payload in the low 64 bits of the label data.
	data[8] = byte(x >> 56)
	data[9] = byte(x >> 48)
	data[10] = byte(x >> 40)
	data[11] = byte(x >> 32)
	data[12] = byte(x >> 24)
	data[13] = byte(x >> 16)
	data[14] = byte(x >> 8)
	data[15] = byte(x)
	var l ot.Label
	l.SetData(&data)
	return l
}

func uint64FromLabel(l ot.Label) uint64 {
	var data ot.LabelData
	l.GetData(&data)
	return uint64(data[8])<<56 | uint64(data[9])<<48 | uint64(data[10])<<40 | uint64(data[11])<<32 |
		uint64(data[12])<<24 | uint64(data[13])<<16 | uint64(data[14])<<8 | uint64(data[15])
}

func labelFromUint128(x Uint128) ot.Label {
	var data ot.LabelData
	putUint128LE(data[:], x)
	var l ot.Label
	l.SetData(&data)
	return l
}

func uint128FromLabel(l ot.Label) Uint128 {
	var data ot.LabelData
	l.GetData(&data)
	return getUint128LE(data[:]).ModPow127()
}

func b64Big(x *big.Int) string {
	if x == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(x.Bytes())
}

func bigFromB64(s string) (*big.Int, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(raw), nil
}

func encodeJSONB64(v any) string {
	raw, _ := json.Marshal(v)
	return base64.StdEncoding.EncodeToString(raw)
}

func decodeJSONB64(s string, v any) error {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func decodePublicSetup(s string) (otSetupPublicWireDecoded, error) {
	var w otSetupPublicWire
	if err := decodeJSONB64(s, &w); err != nil {
		return otSetupPublicWireDecoded{}, err
	}
	ax, err := bigFromB64(w.Ax)
	if err != nil {
		return otSetupPublicWireDecoded{}, err
	}
	ay, err := bigFromB64(w.Ay)
	if err != nil {
		return otSetupPublicWireDecoded{}, err
	}
	return otSetupPublicWireDecoded{Ax: ax, Ay: ay}, nil
}

type otSetupPublicWireDecoded struct {
	Ax *big.Int
	Ay *big.Int
}

func decodeSecretSetup(s string) (ot.COSenderSetup, error) {
	var w otSetupSecretWire
	if err := decodeJSONB64(s, &w); err != nil {
		return ot.COSenderSetup{}, err
	}
	sc, err := bigFromB64(w.Scalar)
	if err != nil {
		return ot.COSenderSetup{}, err
	}
	ax, err := bigFromB64(w.Ax)
	if err != nil {
		return ot.COSenderSetup{}, err
	}
	ay, err := bigFromB64(w.Ay)
	if err != nil {
		return ot.COSenderSetup{}, err
	}
	aix, err := bigFromB64(w.AaInvX)
	if err != nil {
		return ot.COSenderSetup{}, err
	}
	aiy, err := bigFromB64(w.AaInvY)
	if err != nil {
		return ot.COSenderSetup{}, err
	}
	return ot.COSenderSetup{CurveName: w.Curve, Scalar: sc, Ax: ax, Ay: ay, AaInvX: aix, AaInvY: aiy}, nil
}

func decodePoints(s string) ([]ot.ECPoint, error) {
	var w []otPointWire
	if err := decodeJSONB64(s, &w); err != nil {
		return nil, err
	}
	out := make([]ot.ECPoint, len(w))
	for i, p := range w {
		x, err := bigFromB64(p.X)
		if err != nil {
			return nil, err
		}
		y, err := bigFromB64(p.Y)
		if err != nil {
			return nil, err
		}
		out[i] = ot.ECPoint{X: x, Y: y}
	}
	return out, nil
}

func decodeChoiceBundle(s string) (ot.COChoiceBundle, error) {
	var w otChoiceBundleWire
	if err := decodeJSONB64(s, &w); err != nil {
		return ot.COChoiceBundle{}, err
	}
	ax, err := bigFromB64(w.Ax)
	if err != nil {
		return ot.COChoiceBundle{}, err
	}
	ay, err := bigFromB64(w.Ay)
	if err != nil {
		return ot.COChoiceBundle{}, err
	}
	bits, err := unpackBoolsB64(w.Bits, w.Count)
	if err != nil {
		return ot.COChoiceBundle{}, err
	}
	scalars := make([]*big.Int, len(w.Scalars))
	for i, s := range w.Scalars {
		scalars[i], err = bigFromB64(s)
		if err != nil {
			return ot.COChoiceBundle{}, err
		}
	}
	return ot.COChoiceBundle{CurveName: w.Curve, Ax: ax, Ay: ay, Scalars: scalars, Bits: bits}, nil
}

func decodeCiphertexts(s string) ([]ot.LabelCiphertext, error) {
	var w []otCipherWire
	if err := decodeJSONB64(s, &w); err != nil {
		return nil, err
	}
	out := make([]ot.LabelCiphertext, len(w))
	for i, c := range w {
		z, err := base64.StdEncoding.DecodeString(c.Zero)
		if err != nil {
			return nil, err
		}
		o, err := base64.StdEncoding.DecodeString(c.One)
		if err != nil {
			return nil, err
		}
		if len(z) != 16 || len(o) != 16 {
			return nil, fmt.Errorf("invalid label ciphertext length")
		}
		copy(out[i].Zero[:], z)
		copy(out[i].One[:], o)
	}
	return out, nil
}

func packBoolsB64(bits []bool) string {
	raw := make([]byte, (len(bits)+7)/8)
	for i, b := range bits {
		if b {
			raw[i/8] |= 1 << uint(i%8)
		}
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func unpackBoolsB64(s string, n int) ([]bool, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	out := make([]bool, n)
	for i := 0; i < n; i++ {
		out[i] = ((raw[i/8] >> uint(i%8)) & 1) == 1
	}
	return out, nil
}
