// k2_ring127_affine_combine.go — local-op handler for Ring127 share assembly.
//
// Computes element-wise:
//   out[i] = sign_a * a[i] + sign_b * b[i] + (public_const if is_party0 else 0)
// where sign_a, sign_b ∈ {-1, 0, +1}. If sign is 0 the corresponding vector
// may be empty (or any value; it is ignored).
//
// This is the local per-iteration assembly primitive for:
//   (1) Chebyshev Horner step at Ring127 (5c(I-c-4)):
//        b_k = 0 + twoYbKp1 + (-1)*bKp2 + c_k_party0
//       with a=twoYbKp1, b=bKp2, sign_a=+1, sign_b=-1, const=c_k.
//   (2) Goldschmidt NR iteration at Ring127 (5c(I-c-6)):
//        tmp = 2_party0 + 0*a + (-1)*xy_share
//       with a=zero-vec, b=xy_share, sign_a=0, sign_b=-1, const=2.
//        y_next share is produced by a subsequent Beaver(y, tmp).
//   (3) Initial guess assembly y_0 = 1.5 - 0.5*x_norm share:
//        after local 0.5-scaling via k2-fp-vec-mul Ring127, affine-combine
//        produces y_0 = 1.5_party0 - halfX_share.
//
// Pure local op — no Beaver, no DCF, no cross-party bytes. Runs once per
// Horner/NR iter on each server; R client issues it via datashield.aggregate.

package main

// K2Ring127AffineCombineInput: inputs for one affine combine call.
//   A, B:           base64 Ring127 FP shares (16 B per elt), length n each.
//                   Required iff corresponding sign is nonzero; may be "" if
//                   the sign is 0.
//   SignA, SignB:   -1, 0, or +1. Any other value → error.
//   PublicConst:    base64 of a single Uint128 (16 B). Broadcast scalar added
//                   to every element on party 0 only. May be "" for zero.
//   IsParty0:       bool. True → add PublicConst; false → skip.
//   FracBits:       Ring127 fracBits (default 50).
//   N:              vector length. Required; used to construct zero-shares
//                   when a sign is 0 and the corresponding vec is empty.
type K2Ring127AffineCombineInput struct {
	A           string `json:"a"`
	B           string `json:"b"`
	SignA       int    `json:"sign_a"`
	SignB       int    `json:"sign_b"`
	PublicConst string `json:"public_const"`
	IsParty0    bool   `json:"is_party0"`
	FracBits    int    `json:"frac_bits"`
	N           int    `json:"n"`
}

// K2Ring127AffineCombineOutput: the combined share vector, base64 Uint128.
type K2Ring127AffineCombineOutput struct {
	Result string `json:"result"`
}

func handleK2Ring127AffineCombine() {
	var input K2Ring127AffineCombineInput
	mpcReadInput(&input)

	fb := ring127DefaultFracBits(input.FracBits)
	r := NewRing127(fb)
	n := input.N
	if n <= 0 {
		outputError("k2-ring127-affine-combine: n must be > 0")
		return
	}
	if input.SignA < -1 || input.SignA > 1 {
		outputError("k2-ring127-affine-combine: sign_a must be -1, 0, or +1")
		return
	}
	if input.SignB < -1 || input.SignB > 1 {
		outputError("k2-ring127-affine-combine: sign_b must be -1, 0, or +1")
		return
	}

	// Decode vectors, substituting zero when the sign is 0.
	var a, b []Uint128
	if input.SignA != 0 {
		a = b64Uint128Vec(input.A)
		if len(a) != n {
			outputError("k2-ring127-affine-combine: |a| mismatch vs n")
			return
		}
	}
	if input.SignB != 0 {
		b = b64Uint128Vec(input.B)
		if len(b) != n {
			outputError("k2-ring127-affine-combine: |b| mismatch vs n")
			return
		}
	}

	// Public constant (broadcast scalar). Only applied on party 0.
	var cAdd Uint128
	addConst := false
	if input.IsParty0 && input.PublicConst != "" {
		cv := b64Uint128Vec(input.PublicConst)
		if len(cv) != 1 {
			outputError("k2-ring127-affine-combine: public_const must encode exactly 1 Uint128")
			return
		}
		cAdd = cv[0]
		addConst = true
	}

	out := make([]Uint128, n)
	for i := 0; i < n; i++ {
		var termA, termB Uint128
		switch input.SignA {
		case 1:
			termA = a[i]
		case -1:
			termA = r.Neg(a[i])
		}
		switch input.SignB {
		case 1:
			termB = b[i]
		case -1:
			termB = r.Neg(b[i])
		}
		s := r.Add(termA, termB)
		if addConst {
			s = r.Add(s, cAdd)
		}
		out[i] = s
	}

	mpcWriteOutput(K2Ring127AffineCombineOutput{
		Result: Uint128VecToB64(out),
	})
}
