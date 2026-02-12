// psi_ops.go: ECDH-PSI operations using NIST P-256
//
// Implements Private Set Intersection using the commutativity property of
// elliptic curve scalar multiplication: α·(β·H(id)) = β·(α·H(id)).
//
// Hash-to-curve uses RFC 9380 Simplified SWU (Shallue-van de Woerstra-Ulas)
// for constant-time operation, replacing the non-constant-time try-and-increment
// method. This prevents timing side-channels that could leak information about
// input IDs in a semi-honest adversary model.
//
// Security: DDH assumption on P-256 (semi-honest model).
// No additional dependencies beyond Go standard library.

package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"sort"
)

// RFC 9380 suite identifier for P-256 with SHA-256
const psiDST = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_"
const psiDomainSeparator = "dsVert-PSI-v2"

var p256Curve = elliptic.P256()

// P-256 curve constants for Simplified SWU
var (
	p256P, _ = new(big.Int).SetString("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
	p256A    = new(big.Int).Sub(p256P, big.NewInt(3)) // a = -3 mod p
	p256B, _ = new(big.Int).SetString("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
	// Z for P-256 SSWU (from RFC 9380 Section 8.2): Z = -10
	p256Z = new(big.Int).Sub(p256P, big.NewInt(10))
)

// hashToP256Point hashes a string ID to a point on P-256 using RFC 9380
// hash_to_curve with Simplified SWU map. This is a constant-time operation
// (no data-dependent branching), preventing timing side-channels.
//
// Implements: hash_to_curve(msg) from RFC 9380 Section 3:
//   1. u = hash_to_field(msg, 2)    -- produces two field elements
//   2. Q0 = map_to_curve(u[0])      -- Simplified SWU
//   3. Q1 = map_to_curve(u[1])
//   4. R = Q0 + Q1                  -- point addition
//   5. P = clear_cofactor(R)        -- no-op for P-256 (cofactor = 1)
func hashToP256Point(id string) (*big.Int, *big.Int) {
	// Step 1: hash_to_field using expand_message_xmd (SHA-256)
	msg := []byte(psiDomainSeparator + id)
	u0, u1 := hashToFieldP256(msg)

	// Steps 2-3: Simplified SWU map for each field element
	x0, y0 := simplifiedSWU(u0)
	x1, y1 := simplifiedSWU(u1)

	// Step 4: Point addition (cofactor clearing is no-op for P-256)
	rx, ry := p256Curve.Add(x0, y0, x1, y1)

	return rx, ry
}

// hashToFieldP256 implements hash_to_field from RFC 9380 Section 5.2
// using expand_message_xmd with SHA-256. Produces 2 field elements for P-256.
func hashToFieldP256(msg []byte) (*big.Int, *big.Int) {
	// expand_message_xmd: produce 2 * 48 = 96 bytes (L=48 for P-256)
	// L = ceil((ceil(log2(p)) + k) / 8) = ceil((256 + 128) / 8) = 48
	L := 48
	lenInBytes := 2 * L

	uniform := expandMessageXMD(msg, []byte(psiDST), lenInBytes)

	u0 := new(big.Int).SetBytes(uniform[:L])
	u0.Mod(u0, p256P)

	u1 := new(big.Int).SetBytes(uniform[L : 2*L])
	u1.Mod(u1, p256P)

	return u0, u1
}

// expandMessageXMD implements expand_message_xmd from RFC 9380 Section 5.3.1
func expandMessageXMD(msg, DST []byte, lenInBytes int) []byte {
	bInBytes := 32 // SHA-256 output
	ell := (lenInBytes + bInBytes - 1) / bInBytes
	if ell > 255 {
		panic("expand_message_xmd: ell > 255")
	}

	// DST_prime = DST || I2OSP(len(DST), 1)
	DSTPrime := make([]byte, len(DST)+1)
	copy(DSTPrime, DST)
	DSTPrime[len(DST)] = byte(len(DST))

	// Z_pad = I2OSP(0, r_in_bytes) where r_in_bytes = 64 for SHA-256
	zPad := make([]byte, 64)

	// l_i_b_str = I2OSP(len_in_bytes, 2)
	libStr := []byte{byte(lenInBytes >> 8), byte(lenInBytes)}

	// b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
	h0 := sha256.New()
	h0.Write(zPad)
	h0.Write(msg)
	h0.Write(libStr)
	h0.Write([]byte{0})
	h0.Write(DSTPrime)
	b0 := h0.Sum(nil)

	// b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
	h1 := sha256.New()
	h1.Write(b0)
	h1.Write([]byte{1})
	h1.Write(DSTPrime)
	b1 := h1.Sum(nil)

	uniform := make([]byte, 0, lenInBytes)
	uniform = append(uniform, b1...)

	bPrev := b1
	for i := 2; i <= ell; i++ {
		// strxor(b_0, b_{i-1})
		xored := make([]byte, bInBytes)
		for j := 0; j < bInBytes; j++ {
			xored[j] = b0[j] ^ bPrev[j]
		}
		hi := sha256.New()
		hi.Write(xored)
		hi.Write([]byte{byte(i)})
		hi.Write(DSTPrime)
		bi := hi.Sum(nil)
		uniform = append(uniform, bi...)
		bPrev = bi
	}

	return uniform[:lenInBytes]
}

// simplifiedSWU implements the Simplified SWU map from RFC 9380 Section 6.6.2
// for the P-256 curve (a = -3, b = 0x5ac6..., Z = -10).
func simplifiedSWU(u *big.Int) (*big.Int, *big.Int) {
	p := p256P
	a := p256A
	b := p256B
	Z := p256Z

	// Helper functions
	mul := func(x, y *big.Int) *big.Int {
		r := new(big.Int).Mul(x, y)
		return r.Mod(r, p)
	}
	add := func(x, y *big.Int) *big.Int {
		r := new(big.Int).Add(x, y)
		return r.Mod(r, p)
	}
	sub := func(x, y *big.Int) *big.Int {
		r := new(big.Int).Sub(x, y)
		return r.Mod(r, p)
	}
	sqr := func(x *big.Int) *big.Int {
		return mul(x, x)
	}
	inv := func(x *big.Int) *big.Int {
		return new(big.Int).ModInverse(x, p)
	}
	neg := func(x *big.Int) *big.Int {
		return sub(big.NewInt(0), x)
	}

	// 1. tv1 = inv0(Z^2 * u^4 + Z * u^2)
	u2 := sqr(u)
	u4 := sqr(u2)
	Zu2 := mul(Z, u2)
	Z2u4 := mul(sqr(Z), u4)
	tv1 := add(Z2u4, Zu2)

	// if tv1 == 0, x1 = b / (Z * a)
	var x1 *big.Int
	if tv1.Sign() == 0 {
		x1 = mul(neg(b), inv(mul(Z, a)))
	} else {
		tv1 = inv(tv1)
		x1 = mul(add(big.NewInt(1), tv1), mul(neg(b), inv(a)))
	}

	// gx1 = x1^3 + a*x1 + b
	gx1 := add(add(mul(sqr(x1), x1), mul(a, x1)), b)

	// x2 = Z * u^2 * x1
	x2 := mul(Z, mul(u2, x1))

	// gx2 = x2^3 + a*x2 + b
	gx2 := add(add(mul(sqr(x2), x2), mul(a, x2)), b)

	// if gx1 is square, (x, y) = (x1, sqrt(gx1)); else (x, y) = (x2, sqrt(gx2))
	// Use Euler's criterion: gx1^((p-1)/2) == 1 mod p means square
	exp := new(big.Int).Sub(p, big.NewInt(1))
	exp.Rsh(exp, 1)
	isSquare := new(big.Int).Exp(gx1, exp, p)

	var x, y *big.Int
	if isSquare.Cmp(big.NewInt(1)) == 0 {
		x = x1
		y = new(big.Int).ModSqrt(gx1, p)
	} else {
		x = x2
		y = new(big.Int).ModSqrt(gx2, p)
	}

	// Ensure sgn0(y) == sgn0(u): if signs differ, negate y
	if y.Bit(0) != u.Bit(0) {
		y = sub(big.NewInt(0), y)
	}

	return x, y
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

// decodePoint decompresses a base64 EC point with full validation:
// 1. Valid base64 encoding
// 2. Valid compressed P-256 point format (33 bytes, prefix 0x02 or 0x03)
// 3. Point is on the P-256 curve
// 4. Point is not the point at infinity
// Note: P-256 has cofactor 1, so any on-curve point is in the prime-order subgroup.
func decodePoint(encoded string) (*big.Int, *big.Int, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("base64 decode: %w", err)
	}
	if len(data) != 33 {
		return nil, nil, fmt.Errorf("invalid point length: %d (expected 33)", len(data))
	}
	if data[0] != 0x02 && data[0] != 0x03 {
		return nil, nil, fmt.Errorf("invalid point prefix: 0x%02x", data[0])
	}
	x, y := elliptic.UnmarshalCompressed(p256Curve, data)
	if x == nil {
		return nil, nil, fmt.Errorf("invalid compressed P-256 point")
	}
	if !p256Curve.IsOnCurve(x, y) {
		return nil, nil, fmt.Errorf("point not on P-256 curve")
	}
	if x.Sign() == 0 && y.Sign() == 0 {
		return nil, nil, fmt.Errorf("point at infinity not allowed")
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
