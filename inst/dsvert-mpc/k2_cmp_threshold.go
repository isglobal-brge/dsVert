package main

import "encoding/binary"

// k2_cmp_threshold.go: minimal DCF comparison commands for DataSHIELD
// relay workflows that need a threshold bit without reconstructing the
// underlying shared scalar/vector exactly. The current quarter-ring mask
// still leaks coarse range information and needs a no-differential-wrap
// domain proof; these commands remain historical/quarantined primitives.

type K2CmpGenInput struct {
	N         int     `json:"n"`
	Threshold float64 `json:"threshold"`
	FracBits  int     `json:"frac_bits"`
}

type K2CmpGenOutput struct {
	Party0Keys string `json:"party0_keys"`
	Party1Keys string `json:"party1_keys"`
}

func handleK2CmpGen() {
	var input K2CmpGenInput
	mpcReadInput(&input)
	if input.N <= 0 {
		outputError("k2-cmp-gen: n must be positive")
		return
	}
	_, fracBits, err := normalizeRingAndFracBits("ring63", input.FracBits)
	if err != nil {
		outputError("k2-cmp-gen: " + err.Error())
		return
	}
	ring := NewRing63(fracBits)
	thresholdFP, err := ring.FromDoubleChecked(input.Threshold)
	if err != nil {
		outputError("k2-cmp-gen: invalid threshold: " + err.Error())
		return
	}
	p0, p1 := cmpGeneratePreprocess(ring, input.N, thresholdFP)
	mpcWriteOutput(K2CmpGenOutput{
		Party0Keys: bytesToBase64(serializeDcfBatch(
			[]CmpPreprocessPerParty{p0}, input.N, 1)),
		Party1Keys: bytesToBase64(serializeDcfBatch(
			[]CmpPreprocessPerParty{p1}, input.N, 1)),
	})
}

type K2CmpRound1Input struct {
	ShareFP  string `json:"share_fp"`
	DcfKeys  string `json:"dcf_keys"`
	PartyID  int    `json:"party_id"`
	N        int    `json:"n"`
	FracBits int    `json:"frac_bits"`
}

type K2CmpRound1Output struct {
	Masked string `json:"masked"`
}

func handleK2CmpRound1() {
	var input K2CmpRound1Input
	mpcReadInput(&input)
	_, fracBits, err := normalizeRingAndFracBits("ring63", input.FracBits)
	if err != nil {
		outputError("k2-cmp-round1: " + err.Error())
		return
	}
	if input.PartyID != 0 && input.PartyID != 1 {
		outputError("k2-cmp-round1: party_id must be 0 or 1")
		return
	}
	if input.N <= 0 {
		outputError("k2-cmp-round1: n must be positive")
		return
	}
	ring := NewRing63(fracBits)
	share, err := decodeRing63FPVector(input.ShareFP, input.N)
	if err != nil {
		outputError("k2-cmp-round1: invalid share_fp: " + err.Error())
		return
	}
	keyBytes, err := decodeBase64Records(input.DcfKeys, k2Ring63DcfElemSize, input.N)
	if err != nil {
		outputError("k2-cmp-round1: invalid dcf_keys: " + err.Error())
		return
	}
	keys := deserializeDcfBatch(keyBytes, input.N, 1)
	msg := cmpRound1(ring, input.PartyID, share, keys[0])
	buf := make([]byte, len(msg.Values)*8)
	for i, v := range msg.Values {
		binary.LittleEndian.PutUint64(buf[i*8:], v)
	}
	mpcWriteOutput(K2CmpRound1Output{Masked: bytesToBase64(buf)})
}

type K2CmpRound2Input struct {
	ShareFP    string `json:"share_fp"`
	DcfKeys    string `json:"dcf_keys"`
	PeerMasked string `json:"peer_masked"`
	PartyID    int    `json:"party_id"`
	N          int    `json:"n"`
	FracBits   int    `json:"frac_bits"`
}

type K2CmpRound2Output struct {
	IndicatorFP string `json:"indicator_fp"`
}

func handleK2CmpRound2() {
	var input K2CmpRound2Input
	mpcReadInput(&input)
	_, fracBits, err := normalizeRingAndFracBits("ring63", input.FracBits)
	if err != nil {
		outputError("k2-cmp-round2: " + err.Error())
		return
	}
	if input.PartyID != 0 && input.PartyID != 1 {
		outputError("k2-cmp-round2: party_id must be 0 or 1")
		return
	}
	if input.N <= 0 {
		outputError("k2-cmp-round2: n must be positive")
		return
	}
	ring := NewRing63(fracBits)
	share, err := decodeRing63FPVector(input.ShareFP, input.N)
	if err != nil {
		outputError("k2-cmp-round2: invalid share_fp: " + err.Error())
		return
	}
	peerValues, err := decodeRing63ResidueVector(input.PeerMasked, input.N)
	if err != nil {
		outputError("k2-cmp-round2: invalid peer_masked: " + err.Error())
		return
	}
	peer := CmpMaskedValues{Values: peerValues}

	keyBytes, err := decodeBase64Records(input.DcfKeys, k2Ring63DcfElemSize, input.N)
	if err != nil {
		outputError("k2-cmp-round2: invalid dcf_keys: " + err.Error())
		return
	}
	keys := deserializeDcfBatch(keyBytes, input.N, 1)
	own := cmpRound1(ring, input.PartyID, share, keys[0])
	cmp := cmpRound2(ring, input.PartyID, keys[0], own, peer)

	indicator := make([]uint64, input.N)
	for i, bitShare := range cmp.Shares {
		// Convert arithmetic bit shares (sum = 0/1 in Ring63) into
		// fixed-point shares (sum = 0.0/1.0) so existing k2-fp-sum and
		// k2-ring63-aggregate can consume the result.
		indicator[i] = modMulBig63(
			bitShare, ring.FracMul, ring.Modulus)
	}
	mpcWriteOutput(K2CmpRound2Output{
		IndicatorFP: bytesToBase64(fpVecToBytes(ring63ToFP(indicator))),
	})
}
