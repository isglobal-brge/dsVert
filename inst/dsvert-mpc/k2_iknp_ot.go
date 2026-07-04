// k2_iknp_ot.go -- relayable IKNP OT extension for dsVert.
//
// These commands implement a semi-honest IKNP OT-extension backend in the
// same stateless style as k2_ot_beaver.go. The DataSHIELD client relays public
// messages; base seeds and extension labels remain server-side.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/markkurossi/mpc/ot"
)

const (
	iknpK             = 128
	iknpChunkSize     = 8 * 1024
	iknpChunkByteRows = iknpChunkSize / iknpK
	iknpChunkRows     = iknpChunkByteRows * 8
)

type iknpBaseReceiverSetupOutput struct {
	PublicSetup   string `json:"public_setup"`
	ReceiverState string `json:"receiver_state"`
}

type iknpBaseReceiverStateWire struct {
	SecretSetup string `json:"secret_setup"`
	L0          string `json:"l0"`
	L1          string `json:"l1"`
}

type iknpBaseSenderChoicesInput struct {
	PublicSetup string `json:"public_setup"`
}

type iknpBaseSenderStateWire struct {
	Delta        string `json:"delta"`
	ChoiceBundle string `json:"choice_bundle"`
	BaseLabels   string `json:"base_labels,omitempty"`
}

type iknpBaseSenderChoicesOutput struct {
	SenderState string `json:"sender_state"`
	Points      string `json:"points"`
}

type iknpBaseReceiverEncryptInput struct {
	ReceiverState string `json:"receiver_state"`
	Points        string `json:"points"`
}

type iknpBaseReceiverEncryptOutput struct {
	Ciphertexts string `json:"ciphertexts"`
}

type iknpBaseSenderFinalizeInput struct {
	SenderState string `json:"sender_state"`
	Ciphertexts string `json:"ciphertexts"`
}

type iknpBaseSenderFinalizeOutput struct {
	SenderState string `json:"sender_state"`
}

type iknpReceiverExtendInput struct {
	ReceiverState string `json:"receiver_state"`
	Y             string `json:"y"`
	N             int    `json:"n"`
	Ring          string `json:"ring"`
	Domain        string `json:"domain"`
}

type iknpReceiverExtendStateWire struct {
	Labels  string `json:"labels"`
	Choices string `json:"choices"`
	Count   int    `json:"count"`
	N       int    `json:"n"`
	Ring    string `json:"ring"`
}

type iknpReceiverExtendOutput struct {
	ReceiverExtendState string `json:"receiver_extend_state"`
	UMatrix             string `json:"u_matrix"`
	Check               string `json:"kos_check"`
}

type iknpSenderEncryptInput struct {
	SenderState string `json:"sender_state"`
	UMatrix     string `json:"u_matrix"`
	X           string `json:"x"`
	N           int    `json:"n"`
	Ring        string `json:"ring"`
	Domain      string `json:"domain"`
	Check       string `json:"kos_check"`
}

type iknpCiphertextsWire struct {
	Zero  string `json:"zero"`
	One   string `json:"one"`
	Count int    `json:"count"`
}

type iknpSenderEncryptOutput struct {
	SenderShare string `json:"sender_share"`
	Ciphertexts string `json:"ciphertexts"`
}

type iknpReceiverDecryptInput struct {
	ReceiverExtendState string `json:"receiver_extend_state"`
	Ciphertexts         string `json:"ciphertexts"`
	N                   int    `json:"n"`
	Ring                string `json:"ring"`
}

type iknpReceiverDecryptOutput struct {
	ReceiverShare string `json:"receiver_share"`
}

func handleK2IKNPBaseReceiverSetup() {
	curve := ellipticP256()
	setup, err := ot.GenerateCOSenderSetup(crand.Reader, curve)
	if err != nil {
		outputError("k2-iknp-base-receiver-setup: " + err.Error())
		return
	}
	wires, err := iknpRandomBaseWires()
	if err != nil {
		outputError("k2-iknp-base-receiver-setup: " + err.Error())
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
	l0, l1 := iknpEncodeWireLabels(wires)
	state := iknpBaseReceiverStateWire{
		SecretSetup: encodeJSONB64(sec),
		L0:          l0,
		L1:          l1,
	}
	mpcWriteOutput(iknpBaseReceiverSetupOutput{
		PublicSetup:   encodeJSONB64(pub),
		ReceiverState: encodeJSONB64(state),
	})
}

func handleK2IKNPBaseSenderChoices() {
	var input iknpBaseSenderChoicesInput
	mpcReadInput(&input)
	pub, err := decodePublicSetup(input.PublicSetup)
	if err != nil {
		outputError("k2-iknp-base-sender-choices: " + err.Error())
		return
	}
	delta, err := ot.NewLabel(crand.Reader)
	if err != nil {
		outputError("k2-iknp-base-sender-choices: " + err.Error())
		return
	}
	flags := make([]bool, iknpK)
	for i := 0; i < iknpK; i++ {
		flags[i] = delta.Bit(i) == 1
	}
	curve := ellipticP256()
	bundle, points, err := ot.BuildCOChoices(crand.Reader, curve, pub.Ax, pub.Ay, flags)
	if err != nil {
		outputError("k2-iknp-base-sender-choices: " + err.Error())
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
	state := iknpBaseSenderStateWire{
		Delta:        iknpEncodeLabels([]ot.Label{delta}),
		ChoiceBundle: encodeJSONB64(bw),
	}
	mpcWriteOutput(iknpBaseSenderChoicesOutput{
		SenderState: encodeJSONB64(state),
		Points:      encodeJSONB64(pw),
	})
}

func handleK2IKNPBaseReceiverEncrypt() {
	var input iknpBaseReceiverEncryptInput
	mpcReadInput(&input)
	state, err := iknpDecodeBaseReceiverState(input.ReceiverState)
	if err != nil {
		outputError("k2-iknp-base-receiver-encrypt: " + err.Error())
		return
	}
	points, err := decodePoints(input.Points)
	if err != nil {
		outputError("k2-iknp-base-receiver-encrypt: " + err.Error())
		return
	}
	setup, err := decodeSecretSetup(state.SecretSetup)
	if err != nil {
		outputError("k2-iknp-base-receiver-encrypt: " + err.Error())
		return
	}
	wires, err := iknpDecodeWireLabels(state.L0, state.L1, iknpK)
	if err != nil {
		outputError("k2-iknp-base-receiver-encrypt: " + err.Error())
		return
	}
	if len(points) != len(wires) {
		outputError("k2-iknp-base-receiver-encrypt: point count mismatch")
		return
	}
	ct, err := ot.EncryptCOCiphertexts(ellipticP256(), setup, points, wires)
	if err != nil {
		outputError("k2-iknp-base-receiver-encrypt: " + err.Error())
		return
	}
	cw := make([]otCipherWire, len(ct))
	for i, c := range ct {
		cw[i] = otCipherWire{
			Zero: bytesToBase64(c.Zero[:]),
			One:  bytesToBase64(c.One[:]),
		}
	}
	mpcWriteOutput(iknpBaseReceiverEncryptOutput{Ciphertexts: encodeJSONB64(cw)})
}

func handleK2IKNPBaseSenderFinalize() {
	var input iknpBaseSenderFinalizeInput
	mpcReadInput(&input)
	state, err := iknpDecodeBaseSenderState(input.SenderState)
	if err != nil {
		outputError("k2-iknp-base-sender-finalize: " + err.Error())
		return
	}
	bundle, err := decodeChoiceBundle(state.ChoiceBundle)
	if err != nil {
		outputError("k2-iknp-base-sender-finalize: " + err.Error())
		return
	}
	ciphertexts, err := decodeCiphertexts(input.Ciphertexts)
	if err != nil {
		outputError("k2-iknp-base-sender-finalize: " + err.Error())
		return
	}
	labels, err := ot.DecryptCOCiphertexts(ellipticP256(), bundle, ciphertexts)
	if err != nil {
		outputError("k2-iknp-base-sender-finalize: " + err.Error())
		return
	}
	if len(labels) != iknpK {
		outputError("k2-iknp-base-sender-finalize: base label count mismatch")
		return
	}
	state.BaseLabels = iknpEncodeLabels(labels)
	mpcWriteOutput(iknpBaseSenderFinalizeOutput{SenderState: encodeJSONB64(state)})
}

func handleK2IKNPReceiverExtend() {
	var input iknpReceiverExtendInput
	mpcReadInput(&input)
	ring := normalizeOTRing(input.Ring)
	state, err := iknpDecodeBaseReceiverState(input.ReceiverState)
	if err != nil {
		outputError("k2-iknp-receiver-extend: " + err.Error())
		return
	}
	wires, err := iknpDecodeWireLabels(state.L0, state.L1, iknpK)
	if err != nil {
		outputError("k2-iknp-receiver-extend: " + err.Error())
		return
	}
	choices, err := otChoiceBits(input.Y, input.N, ring)
	if err != nil {
		outputError("k2-iknp-receiver-extend: " + err.Error())
		return
	}
	labels, uMatrix, err := iknpReceiverExtend(wires, choices, input.Domain)
	if err != nil {
		outputError("k2-iknp-receiver-extend: " + err.Error())
		return
	}
	extState := iknpReceiverExtendStateWire{
		Labels:  iknpEncodeLabels(labels),
		Choices: packBoolsB64(choices),
		Count:   len(choices),
		N:       input.N,
		Ring:    ring,
	}
	// KOS15/SoftSpoken consistency-check openers, bound by Fiat-Shamir to the
	// U matrix the receiver has just committed to (see k2_iknp_kos.go).
	xHat, tHat := iknpReceiverKOSCheck(labels, choices, uMatrix, input.N, ring, input.Domain)
	mpcWriteOutput(iknpReceiverExtendOutput{
		ReceiverExtendState: encodeJSONB64(extState),
		UMatrix:             bytesToBase64(uMatrix),
		Check:               iknpKOSEncode(xHat, tHat),
	})
}

func handleK2IKNPSenderEncrypt() {
	var input iknpSenderEncryptInput
	mpcReadInput(&input)
	ring := normalizeOTRing(input.Ring)
	state, err := iknpDecodeBaseSenderState(input.SenderState)
	if err != nil {
		outputError("k2-iknp-sender-encrypt: " + err.Error())
		return
	}
	delta, baseLabels, err := iknpSenderBaseLabels(state)
	if err != nil {
		outputError("k2-iknp-sender-encrypt: " + err.Error())
		return
	}
	wires, senderShare, err := otArithmeticWires(input.X, input.N, ring)
	if err != nil {
		outputError("k2-iknp-sender-encrypt: " + err.Error())
		return
	}
	uMatrix := base64ToBytes(input.UMatrix)
	if uMatrix == nil {
		outputError("k2-iknp-sender-encrypt: bad u_matrix base64")
		return
	}
	labels, err := iknpSenderLabels(baseLabels, delta, uMatrix, len(wires), input.Domain)
	if err != nil {
		outputError("k2-iknp-sender-encrypt: " + err.Error())
		return
	}
	// KOS15/SoftSpoken consistency check: verify the receiver used consistent
	// choice bits across the U columns before releasing any OT payloads. If the
	// opener is absent (legacy relay) the check is skipped; when present a
	// failure aborts the extension (defence against a malicious receiver's
	// selective-failure attack on Delta). See k2_iknp_kos.go.
	if input.Check != "" {
		xHat, tHat, ok := iknpKOSDecode(input.Check)
		if !ok {
			outputError("k2-iknp-sender-encrypt: malformed KOS check opener")
			return
		}
		if !iknpSenderKOSVerify(labels, delta, uMatrix, input.N, ring, input.Domain, xHat, tHat) {
			outputError("k2-iknp-sender-encrypt: KOS consistency check FAILED -- aborting OT extension (possible malicious receiver)")
			return
		}
	}
	c0 := make([]ot.Label, len(wires))
	c1 := make([]ot.Label, len(wires))
	for i := range wires {
		q0 := labels[i]
		q1 := q0
		q1.Xor(delta)
		c0[i] = wires[i].L0
		c0[i].Xor(iknpPad(q0, i, 0))
		c1[i] = wires[i].L1
		c1[i].Xor(iknpPad(q1, i, 1))
	}
	mpcWriteOutput(iknpSenderEncryptOutput{
		SenderShare: encodeRingVectorB64(senderShare, ring),
		Ciphertexts: iknpEncodeCiphertexts(c0, c1),
	})
}

func handleK2IKNPReceiverDecrypt() {
	var input iknpReceiverDecryptInput
	mpcReadInput(&input)
	state, err := iknpDecodeReceiverExtendState(input.ReceiverExtendState)
	if err != nil {
		outputError("k2-iknp-receiver-decrypt: " + err.Error())
		return
	}
	ring := normalizeOTRing(input.Ring)
	if state.Ring != "" && state.Ring != ring {
		outputError("k2-iknp-receiver-decrypt: ring mismatch")
		return
	}
	if state.N != 0 && state.N != input.N {
		outputError("k2-iknp-receiver-decrypt: n mismatch")
		return
	}
	labels, err := iknpDecodeLabels(state.Labels, state.Count)
	if err != nil {
		outputError("k2-iknp-receiver-decrypt: " + err.Error())
		return
	}
	choices, err := unpackBoolsB64(state.Choices, state.Count)
	if err != nil {
		outputError("k2-iknp-receiver-decrypt: " + err.Error())
		return
	}
	c0, c1, err := iknpDecodeCiphertexts(input.Ciphertexts, state.Count)
	if err != nil {
		outputError("k2-iknp-receiver-decrypt: " + err.Error())
		return
	}
	msg := make([]ot.Label, state.Count)
	for i := range msg {
		if choices[i] {
			msg[i] = c1[i]
			msg[i].Xor(iknpPad(labels[i], i, 1))
		} else {
			msg[i] = c0[i]
			msg[i].Xor(iknpPad(labels[i], i, 0))
		}
	}
	share, err := otLabelsToRingShare(msg, input.N, ring)
	if err != nil {
		outputError("k2-iknp-receiver-decrypt: " + err.Error())
		return
	}
	mpcWriteOutput(iknpReceiverDecryptOutput{ReceiverShare: encodeRingVectorB64(share, ring)})
}

func ellipticP256() elliptic.Curve {
	return elliptic.P256()
}

func iknpRandomBaseWires() ([]ot.Wire, error) {
	wires := make([]ot.Wire, iknpK)
	for i := range wires {
		l0, err := ot.NewLabel(crand.Reader)
		if err != nil {
			return nil, err
		}
		l1, err := ot.NewLabel(crand.Reader)
		if err != nil {
			return nil, err
		}
		wires[i] = ot.Wire{L0: l0, L1: l1}
	}
	return wires, nil
}

func iknpEncodeWireLabels(wires []ot.Wire) (string, string) {
	l0 := make([]ot.Label, len(wires))
	l1 := make([]ot.Label, len(wires))
	for i := range wires {
		l0[i] = wires[i].L0
		l1[i] = wires[i].L1
	}
	return iknpEncodeLabels(l0), iknpEncodeLabels(l1)
}

func iknpDecodeWireLabels(l0B64, l1B64 string, expected int) ([]ot.Wire, error) {
	l0, err := iknpDecodeLabels(l0B64, expected)
	if err != nil {
		return nil, err
	}
	l1, err := iknpDecodeLabels(l1B64, expected)
	if err != nil {
		return nil, err
	}
	wires := make([]ot.Wire, expected)
	for i := range wires {
		wires[i] = ot.Wire{L0: l0[i], L1: l1[i]}
	}
	return wires, nil
}

func iknpEncodeLabels(labels []ot.Label) string {
	raw := make([]byte, 16*len(labels))
	var data ot.LabelData
	for i, l := range labels {
		l.GetData(&data)
		copy(raw[i*16:(i+1)*16], data[:])
	}
	return bytesToBase64(raw)
}

func iknpDecodeLabels(s string, expected int) ([]ot.Label, error) {
	raw := base64ToBytes(s)
	if raw == nil {
		return nil, fmt.Errorf("bad label base64")
	}
	if len(raw)%16 != 0 {
		return nil, fmt.Errorf("label payload length must be a multiple of 16")
	}
	n := len(raw) / 16
	if expected >= 0 && n != expected {
		return nil, fmt.Errorf("label count mismatch: got %d want %d", n, expected)
	}
	labels := make([]ot.Label, n)
	for i := range labels {
		labels[i].SetBytes(raw[i*16 : (i+1)*16])
	}
	return labels, nil
}

func iknpDecodeBaseReceiverState(s string) (iknpBaseReceiverStateWire, error) {
	var state iknpBaseReceiverStateWire
	if err := decodeJSONB64(s, &state); err != nil {
		return state, err
	}
	return state, nil
}

func iknpDecodeBaseSenderState(s string) (iknpBaseSenderStateWire, error) {
	var state iknpBaseSenderStateWire
	if err := decodeJSONB64(s, &state); err != nil {
		return state, err
	}
	return state, nil
}

func iknpDecodeReceiverExtendState(s string) (iknpReceiverExtendStateWire, error) {
	var state iknpReceiverExtendStateWire
	if err := decodeJSONB64(s, &state); err != nil {
		return state, err
	}
	return state, nil
}

func iknpSenderBaseLabels(state iknpBaseSenderStateWire) (ot.Label, []ot.Label, error) {
	deltaLabels, err := iknpDecodeLabels(state.Delta, 1)
	if err != nil {
		return ot.Label{}, nil, err
	}
	baseLabels, err := iknpDecodeLabels(state.BaseLabels, iknpK)
	if err != nil {
		return ot.Label{}, nil, err
	}
	return deltaLabels[0], baseLabels, nil
}

func iknpReceiverExtend(wires []ot.Wire, choices []bool, domain string) ([]ot.Label, []byte, error) {
	var g0 [iknpK]cipher.Stream
	var g1 [iknpK]cipher.Stream
	var err error
	for i := 0; i < iknpK; i++ {
		g0[i], err = iknpNewPrg(iknpDeriveSeed(wires[i].L0, domain))
		if err != nil {
			return nil, nil, err
		}
		g1[i], err = iknpNewPrg(iknpDeriveSeed(wires[i].L1, domain))
		if err != nil {
			return nil, nil, err
		}
	}

	labels := make([]ot.Label, len(choices))
	uMatrix := make([]byte, 0, ((len(choices)+7)/8)*iknpK)
	var chunk [iknpChunkSize]byte
	var tmp [iknpChunkByteRows]byte

	for ofs := 0; ofs < len(choices); {
		rows := iknpChunkRows
		if rows > len(choices)-ofs {
			rows = len(choices) - ofs
		}
		byteRows := (rows + 7) / 8
		choiceBytes := iknpPackChoiceChunk(choices[ofs:ofs+rows], byteRows)

		for i := 0; i < iknpK; i++ {
			col := chunk[i*byteRows : (i+1)*byteRows]
			iknpPrg(g0[i], col)
			iknpPrg(g1[i], tmp[:byteRows])
			iknpXor(tmp[:byteRows], col)
			iknpXor(tmp[:byteRows], choiceBytes)
			uMatrix = append(uMatrix, tmp[:byteRows]...)
		}
		iknpCreateLabels(labels[ofs:], chunk[:], byteRows)
		ofs += rows
	}
	return labels, uMatrix, nil
}

func iknpSenderLabels(baseLabels []ot.Label, delta ot.Label, uMatrix []byte, n int, domain string) ([]ot.Label, error) {
	var g0 [iknpK]cipher.Stream
	var err error
	for i := 0; i < iknpK; i++ {
		g0[i], err = iknpNewPrg(iknpDeriveSeed(baseLabels[i], domain))
		if err != nil {
			return nil, err
		}
	}
	labels := make([]ot.Label, n)
	var t [iknpChunkSize]byte
	pos := 0
	for ofs := 0; ofs < n; {
		rows := iknpChunkRows
		if rows > n-ofs {
			rows = n - ofs
		}
		byteRows := (rows + 7) / 8
		chunkLen := byteRows * iknpK
		if pos+chunkLen > len(uMatrix) {
			return nil, fmt.Errorf("u_matrix too short")
		}
		uChunk := uMatrix[pos : pos+chunkLen]
		for i := 0; i < iknpK; i++ {
			col := t[i*byteRows : (i+1)*byteRows]
			iknpPrg(g0[i], col)
			if delta.Bit(i) == 1 {
				iknpXor(col, uChunk[i*byteRows:(i+1)*byteRows])
			}
		}
		iknpCreateLabels(labels[ofs:], t[:], byteRows)
		ofs += rows
		pos += chunkLen
	}
	if pos != len(uMatrix) {
		return nil, fmt.Errorf("u_matrix trailing bytes: got %d want %d", len(uMatrix), pos)
	}
	return labels, nil
}

func iknpEncodeCiphertexts(c0, c1 []ot.Label) string {
	wire := iknpCiphertextsWire{
		Zero:  iknpEncodeLabels(c0),
		One:   iknpEncodeLabels(c1),
		Count: len(c0),
	}
	return encodeJSONB64(wire)
}

func iknpDecodeCiphertexts(s string, expected int) ([]ot.Label, []ot.Label, error) {
	var wire iknpCiphertextsWire
	if err := decodeJSONB64(s, &wire); err != nil {
		return nil, nil, err
	}
	if expected >= 0 && wire.Count != expected {
		return nil, nil, fmt.Errorf("ciphertext count mismatch: got %d want %d", wire.Count, expected)
	}
	c0, err := iknpDecodeLabels(wire.Zero, wire.Count)
	if err != nil {
		return nil, nil, err
	}
	c1, err := iknpDecodeLabels(wire.One, wire.Count)
	if err != nil {
		return nil, nil, err
	}
	return c0, c1, nil
}

func iknpPad(label ot.Label, index int, branch byte) ot.Label {
	var data ot.LabelData
	h := sha256.New()
	h.Write([]byte("dsvert-iknp-v1"))
	h.Write(label.Bytes(&data))
	var idx [8]byte
	binary.LittleEndian.PutUint64(idx[:], uint64(index))
	h.Write(idx[:])
	h.Write([]byte{branch})
	sum := h.Sum(nil)
	var out ot.Label
	out.SetBytes(sum[:16])
	return out
}

func iknpDeriveSeed(label ot.Label, domain string) ot.Label {
	var data ot.LabelData
	h := sha256.New()
	h.Write([]byte("dsvert-iknp-seed-v1"))
	h.Write(label.Bytes(&data))
	h.Write([]byte(domain))
	sum := h.Sum(nil)
	var out ot.Label
	out.SetBytes(sum[:16])
	return out
}

func iknpNewPrg(key ot.Label) (cipher.Stream, error) {
	var data ot.LabelData
	block, err := aes.NewCipher(key.Bytes(&data))
	if err != nil {
		return nil, err
	}
	var iv [16]byte
	return cipher.NewCTR(block, iv[:]), nil
}

func iknpPrg(c cipher.Stream, buf []byte) {
	clear(buf)
	c.XORKeyStream(buf, buf)
}

func iknpXor(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

func iknpPackChoiceChunk(bits []bool, byteRows int) []byte {
	out := make([]byte, byteRows)
	for i, b := range bits {
		if b {
			out[i/8] |= 1 << uint(i%8)
		}
	}
	return out
}

func iknpCreateLabels(labels []ot.Label, buf []byte, w int) {
	end := w * 8
	if end > len(labels) {
		end = len(labels)
	}
	for row := 0; row < w; row++ {
		var out [8]ot.Label
		for j := 0; j < iknpK; j++ {
			b := buf[j*w+row]
			mask := uint64(1) << (uint(j) & 63)
			for bit := 0; bit < 8; bit++ {
				if (b>>bit)&1 != 0 {
					if j < 64 {
						out[bit].D0 |= mask
					} else {
						out[bit].D1 |= mask
					}
				}
			}
		}
		base := row * 8
		for bit := 0; bit < 8; bit++ {
			i := base + bit
			if i >= end {
				return
			}
			labels[i] = out[bit]
		}
	}
}
