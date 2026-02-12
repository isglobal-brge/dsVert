// psi_ops.go: ECDH-PSI operations using NIST P-256
//
// Implements Private Set Intersection using the commutativity property of
// elliptic curve scalar multiplication: α·(β·H(id)) = β·(α·H(id)).
//
// Security: DDH assumption on P-256 (semi-honest model).
// No additional dependencies beyond Go standard library.

package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"
)

const psiDomainSeparator = "dsVert-PSI-v1"

var p256Curve = elliptic.P256()

// hashToP256Point hashes a string ID to a point on the P-256 curve
// using try-and-increment with a domain separator.
func hashToP256Point(id string) (*big.Int, *big.Int) {
	params := p256Curve.Params()

	for counter := uint32(0); counter < 1000; counter++ {
		h := sha256.New()
		h.Write([]byte(psiDomainSeparator))
		h.Write([]byte(id))
		var counterBytes [4]byte
		binary.BigEndian.PutUint32(counterBytes[:], counter)
		h.Write(counterBytes[:])

		xBytes := h.Sum(nil)
		x := new(big.Int).SetBytes(xBytes)
		x.Mod(x, params.P)

		// y² = x³ - 3x + b (mod p) for P-256 (a = -3)
		x3 := new(big.Int).Mul(x, x)
		x3.Mul(x3, x)
		x3.Mod(x3, params.P)

		threeX := new(big.Int).Mul(big.NewInt(3), x)
		threeX.Mod(threeX, params.P)

		ySquared := new(big.Int).Sub(x3, threeX)
		ySquared.Add(ySquared, params.B)
		ySquared.Mod(ySquared, params.P)

		y := new(big.Int).ModSqrt(ySquared, params.P)
		if y != nil && p256Curve.IsOnCurve(x, y) {
			// Normalize: pick the even y
			if y.Bit(0) != 0 {
				y.Sub(params.P, y)
			}
			return x, y
		}
	}

	panic(fmt.Sprintf("hashToP256Point: failed after 1000 attempts for ID %q", id))
}

// generateScalar generates a random scalar in [1, n-1]
func generateScalar() (*big.Int, error) {
	params := p256Curve.Params()
	nMinus1 := new(big.Int).Sub(params.N, big.NewInt(1))

	k, err := rand.Int(rand.Reader, nMinus1)
	if err != nil {
		return nil, err
	}
	k.Add(k, big.NewInt(1))
	return k, nil
}

// encodePoint compresses an EC point to base64
func encodePoint(x, y *big.Int) string {
	compressed := elliptic.MarshalCompressed(p256Curve, x, y)
	return base64.StdEncoding.EncodeToString(compressed)
}

// decodePoint decompresses a base64 EC point
func decodePoint(encoded string) (*big.Int, *big.Int, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("base64 decode: %w", err)
	}
	x, y := elliptic.UnmarshalCompressed(p256Curve, data)
	if x == nil {
		return nil, nil, fmt.Errorf("invalid compressed P-256 point")
	}
	return x, y, nil
}

// --- JSON I/O types ---

type PSIMaskInput struct {
	IDs    []string `json:"ids"`
	Scalar string   `json:"scalar"` // empty = generate new
}

type PSIMaskOutput struct {
	MaskedPoints []string `json:"masked_points"`
	Scalar       string   `json:"scalar"`
}

type PSIDoubleMaskInput struct {
	Points []string `json:"points"`
	Scalar string   `json:"scalar"`
}

type PSIDoubleMaskOutput struct {
	DoubleMaskedPoints []string `json:"double_masked_points"`
}

type PSIMatchInput struct {
	OwnDoubled []string `json:"own_doubled"`
	RefDoubled []string `json:"ref_doubled"`
	RefIndices []int    `json:"ref_indices"`
}

type PSIMatchOutput struct {
	MatchedOwnRows    []int `json:"matched_own_rows"`
	MatchedRefIndices []int `json:"matched_ref_indices"`
	NMatched          int   `json:"n_matched"`
}

// --- Core operations ---

func psiMask(input *PSIMaskInput) (*PSIMaskOutput, error) {
	var scalar *big.Int
	var err error

	if input.Scalar == "" {
		scalar, err = generateScalar()
		if err != nil {
			return nil, fmt.Errorf("generate scalar: %w", err)
		}
	} else {
		scalarBytes, err := base64.StdEncoding.DecodeString(input.Scalar)
		if err != nil {
			return nil, fmt.Errorf("decode scalar: %w", err)
		}
		scalar = new(big.Int).SetBytes(scalarBytes)
	}

	maskedPoints := make([]string, len(input.IDs))
	for i, id := range input.IDs {
		px, py := hashToP256Point(id)
		mx, my := p256Curve.ScalarMult(px, py, scalar.Bytes())
		maskedPoints[i] = encodePoint(mx, my)
	}

	return &PSIMaskOutput{
		MaskedPoints: maskedPoints,
		Scalar:       base64.StdEncoding.EncodeToString(scalar.Bytes()),
	}, nil
}

func psiDoubleMask(input *PSIDoubleMaskInput) (*PSIDoubleMaskOutput, error) {
	scalarBytes, err := base64.StdEncoding.DecodeString(input.Scalar)
	if err != nil {
		return nil, fmt.Errorf("decode scalar: %w", err)
	}
	scalar := new(big.Int).SetBytes(scalarBytes)

	doubleMasked := make([]string, len(input.Points))
	for i, pt := range input.Points {
		px, py, err := decodePoint(pt)
		if err != nil {
			return nil, fmt.Errorf("decode point %d: %w", i, err)
		}
		mx, my := p256Curve.ScalarMult(px, py, scalar.Bytes())
		doubleMasked[i] = encodePoint(mx, my)
	}

	return &PSIDoubleMaskOutput{
		DoubleMaskedPoints: doubleMasked,
	}, nil
}

type matchPair struct {
	ownRow int
	refIdx int
}

func psiMatch(input *PSIMatchInput) (*PSIMatchOutput, error) {
	if len(input.RefDoubled) != len(input.RefIndices) {
		return nil, fmt.Errorf("ref_doubled length (%d) != ref_indices length (%d)",
			len(input.RefDoubled), len(input.RefIndices))
	}

	// Build map: ref point → ref index
	refMap := make(map[string]int, len(input.RefDoubled))
	for i, pt := range input.RefDoubled {
		refMap[pt] = input.RefIndices[i]
	}

	// Find matches
	var matches []matchPair
	for ownRow, pt := range input.OwnDoubled {
		if refIdx, found := refMap[pt]; found {
			matches = append(matches, matchPair{ownRow, refIdx})
		}
	}

	// Sort by ref index for deterministic alignment order
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].refIdx < matches[j].refIdx
	})

	// Flatten into output arrays (never nil — always empty slices for JSON)
	matchedOwnRows := make([]int, len(matches))
	matchedRefIndices := make([]int, len(matches))
	for i, m := range matches {
		matchedOwnRows[i] = m.ownRow
		matchedRefIndices[i] = m.refIdx
	}

	return &PSIMatchOutput{
		MatchedOwnRows:    matchedOwnRows,
		MatchedRefIndices: matchedRefIndices,
		NMatched:          len(matches),
	}, nil
}
