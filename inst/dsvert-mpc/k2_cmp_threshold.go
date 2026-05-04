package main

import (
	"encoding/binary"
	"fmt"
)

// k2_cmp_threshold.go: minimal DCF comparison commands for DataSHIELD
// relay workflows that need a threshold bit without reconstructing the
// underlying shared scalar/vector.

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
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}
	ring := NewRing63(input.FracBits)
	thresholdFP := ring.FromDouble(input.Threshold)
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
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}
	if input.PartyID != 0 && input.PartyID != 1 {
		outputError("k2-cmp-round1: party_id must be 0 or 1")
		return
	}
	ring := NewRing63(input.FracBits)
	share := fpToRing63(bytesToFPVec(base64ToBytes(input.ShareFP)))
	if input.N <= 0 {
		input.N = len(share)
	}
	if len(share) != input.N {
		outputError(fmt.Sprintf(
			"k2-cmp-round1: share length mismatch (got %d, n=%d)",
			len(share), input.N))
		return
	}
	keys := deserializeDcfBatch(base64ToBytes(input.DcfKeys), input.N, 1)
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
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}
	if input.PartyID != 0 && input.PartyID != 1 {
		outputError("k2-cmp-round2: party_id must be 0 or 1")
		return
	}
	ring := NewRing63(input.FracBits)
	share := fpToRing63(bytesToFPVec(base64ToBytes(input.ShareFP)))
	if input.N <= 0 {
		input.N = len(share)
	}
	if len(share) != input.N {
		outputError(fmt.Sprintf(
			"k2-cmp-round2: share length mismatch (got %d, n=%d)",
			len(share), input.N))
		return
	}
	peerMaskedBytes := base64ToBytes(input.PeerMasked)
	if len(peerMaskedBytes) != input.N*8 {
		outputError(fmt.Sprintf(
			"k2-cmp-round2: peer masked length mismatch (got %d bytes, want %d)",
			len(peerMaskedBytes), input.N*8))
		return
	}
	peer := CmpMaskedValues{Values: make([]uint64, input.N)}
	for i := range peer.Values {
		peer.Values[i] = binary.LittleEndian.Uint64(peerMaskedBytes[i*8:])
	}

	keys := deserializeDcfBatch(base64ToBytes(input.DcfKeys), input.N, 1)
	own := cmpRound1(ring, input.PartyID, share, keys[0])
	cmp := cmpRound2(ring, input.PartyID, keys[0], own, peer)

	indicator := make([]FixedPoint, input.N)
	for i, bitShare := range cmp.Shares {
		// Convert arithmetic bit shares (sum = 0/1 in Ring63) into
		// fixed-point shares (sum = 0.0/1.0) so existing k2-fp-sum and
		// k2-ring63-aggregate can consume the result.
		indicator[i] = FixedPoint(modMulBig63(
			bitShare, ring.FracMul, ring.Modulus))
	}
	mpcWriteOutput(K2CmpRound2Output{
		IndicatorFP: bytesToBase64(fpVecToBytes(indicator)),
	})
}
