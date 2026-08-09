// k2_ring127_local_scale_share.go - party-aware public-scalar scaling for
// Ring127 additive FP shares.
//
// A fixed-point product by a public scalar is not just TruncMulSigned on each
// random share independently: truncation must use the same party-asymmetric
// correction as ScalarVectorProductPartyZero127 / ScalarVectorProductPartyOne127
// or the reconstructed value gets a share-dependent bias. This command exposes
// that already-tested primitive for R-side Horner / NR orchestration.

package main

type K2Ring127LocalScaleShareInput struct {
	ShareFP  string `json:"share_fp"`
	ScalarFP string `json:"scalar_fp"`
	IsParty0 bool   `json:"is_party0"`
	FracBits int    `json:"frac_bits"`
}

type K2Ring127LocalScaleShareOutput struct {
	Result string `json:"result"`
}

func handleK2Ring127LocalScaleShare() {
	var input K2Ring127LocalScaleShareInput
	mpcReadInput(&input)
	fb, err := normalizeRing127FracBits(input.FracBits)
	if err != nil {
		outputError("k2-ring127-local-scale-share: " + err.Error())
		return
	}
	r := NewRing127(fb)

	share, err := decodeRing127Vector(input.ShareFP, -1)
	if err != nil {
		outputError("k2-ring127-local-scale-share: invalid share_fp: " + err.Error())
		return
	}
	scalarVec, err := decodeRing127Vector(input.ScalarFP, 1)
	if err != nil {
		outputError("k2-ring127-local-scale-share: invalid scalar_fp: " + err.Error())
		return
	}
	scalar := r.ToDouble(scalarVec[0])

	var out []Uint128
	if input.IsParty0 {
		out = ScalarVectorProductPartyZero127(scalar, share, r)
	} else {
		out = ScalarVectorProductPartyOne127(scalar, share, r)
	}
	mpcWriteOutput(K2Ring127LocalScaleShareOutput{
		Result: Uint128VecToB64(out),
	})
}
