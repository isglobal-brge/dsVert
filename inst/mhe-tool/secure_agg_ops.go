// secure_agg_ops.go: Pairwise PRG-mask secure aggregation for η vectors
//
// Implements the secure aggregation protocol for K≥3 non-label servers:
//   - Pairwise seed derivation via X25519 + HKDF
//   - Deterministic PRG mask generation via ChaCha20
//   - Fixed-point masking/unmasking for exact integer cancellation
//
// This prevents the coordinator from seeing individual per-server η vectors.
// Instead, each server adds correlated masks that cancel when summed,
// so the coordinator only learns Ση_k (the aggregate linear predictor).

package main

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

// ============================================================================
// derive-shared-seed: Pairwise seed derivation
// ============================================================================

type DeriveSharedSeedInput struct {
	SelfSK    string `json:"self_sk"`    // base64: X25519 secret key
	PeerPK    string `json:"peer_pk"`    // base64: peer X25519 public key
	SessionID string `json:"session_id"` // UUID binding seed to this session
	SelfName  string `json:"self_name"`  // canonical server name
	PeerName  string `json:"peer_name"`  // canonical server name
}

type DeriveSharedSeedOutput struct {
	Seed string `json:"seed"` // base64: 32-byte seed
}

func deriveSharedSeed(input *DeriveSharedSeedInput) (*DeriveSharedSeedOutput, error) {
	skBytes, err := base64.StdEncoding.DecodeString(input.SelfSK)
	if err != nil {
		return nil, fmt.Errorf("failed to decode self_sk: %v", err)
	}
	pkBytes, err := base64.StdEncoding.DecodeString(input.PeerPK)
	if err != nil {
		return nil, fmt.Errorf("failed to decode peer_pk: %v", err)
	}

	curve := ecdh.X25519()
	sk, err := curve.NewPrivateKey(skBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid self secret key: %v", err)
	}
	pk, err := curve.NewPublicKey(pkBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid peer public key: %v", err)
	}

	// X25519 ECDH
	sharedSecret, err := sk.ECDH(pk)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %v", err)
	}

	// Canonical pair ordering: ensures both peers derive the same seed
	names := []string{input.SelfName, input.PeerName}
	sort.Strings(names)
	info := "dsvert-eta-agg|" + names[0] + "|" + names[1]

	// salt = SHA256(session_id)
	saltHash := sha256.Sum256([]byte(input.SessionID))
	salt := saltHash[:]

	// HKDF-SHA256 to derive 32-byte seed
	hkdfReader := hkdf.New(sha256.New, sharedSecret, salt, []byte(info))
	seed := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, seed); err != nil {
		return nil, fmt.Errorf("HKDF seed derivation failed: %v", err)
	}

	return &DeriveSharedSeedOutput{
		Seed: base64.StdEncoding.EncodeToString(seed),
	}, nil
}

// ============================================================================
// prg-mask-vector: Deterministic PRG mask generation via ChaCha20
// ============================================================================

type PRGMaskVectorInput struct {
	Seed      string `json:"seed"`       // base64: 32-byte ChaCha20 key
	Iteration int    `json:"iteration"`  // BCD iteration (nonce)
	Length    int    `json:"length"`     // vector length (n_obs)
	ScaleBits int    `json:"scale_bits"` // fixed-point scale as power of 2 (default 20)
}

type PRGMaskVectorOutput struct {
	MaskScaled []float64 `json:"mask_scaled"` // int64 values as float64 (JSON-safe)
}

// prgMaskVector generates a deterministic mask vector from a seed and iteration.
// Uses ChaCha20 as a PRG keyed by seed, with nonce derived from iteration.
// Output values are bounded to [-2^45, 2^45] to fit in float64 without precision loss.
func prgMaskVector(input *PRGMaskVectorInput) (*PRGMaskVectorOutput, error) {
	seedBytes, err := base64.StdEncoding.DecodeString(input.Seed)
	if err != nil {
		return nil, fmt.Errorf("failed to decode seed: %v", err)
	}
	if len(seedBytes) != 32 {
		return nil, fmt.Errorf("seed must be 32 bytes, got %d", len(seedBytes))
	}

	scaleBits := input.ScaleBits
	if scaleBits == 0 {
		scaleBits = 20
	}

	// Construct 12-byte ChaCha20 nonce: [0x00 * 8 || big_endian_uint32(iteration)]
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint32(nonce[8:], uint32(input.Iteration))

	cipher, err := chacha20.NewUnauthenticatedCipher(seedBytes, nonce)
	if err != nil {
		return nil, fmt.Errorf("ChaCha20 cipher creation failed: %v", err)
	}

	// Generate random bytes: length * 8 bytes for int64 values
	randomBytes := make([]byte, input.Length*8)
	cipher.XORKeyStream(randomBytes, randomBytes) // XOR with zeros = raw keystream

	// Interpret as little-endian int64, bound to [-2^45, 2^45]
	const bound int64 = 1 << 45
	mask := make([]float64, input.Length)
	for i := 0; i < input.Length; i++ {
		raw := int64(binary.LittleEndian.Uint64(randomBytes[i*8 : (i+1)*8]))
		// Modular reduction to [-bound, bound)
		bounded := raw % bound
		mask[i] = float64(bounded)
	}

	return &PRGMaskVectorOutput{MaskScaled: mask}, nil
}

// ============================================================================
// fixed-point-mask-eta: Mask η in one step
// ============================================================================

type FixedPointMaskEtaInput struct {
	Eta       []float64 `json:"eta"`        // plaintext η vector
	Seeds     []string  `json:"seeds"`      // base64: one seed per peer pair
	Signs     []int     `json:"signs"`      // +1 or -1 for each seed
	Iteration int       `json:"iteration"`  // BCD iteration
	ScaleBits int       `json:"scale_bits"` // default 20 → scale = 2^20
}

type FixedPointMaskEtaOutput struct {
	MaskedScaled []float64 `json:"masked_scaled"` // masked fixed-point values
}

func fixedPointMaskEta(input *FixedPointMaskEtaInput) (*FixedPointMaskEtaOutput, error) {
	scaleBits := input.ScaleBits
	if scaleBits == 0 {
		scaleBits = 20
	}
	scale := float64(int64(1) << scaleBits)
	n := len(input.Eta)

	if len(input.Seeds) != len(input.Signs) {
		return nil, fmt.Errorf("seeds and signs must have same length: %d vs %d",
			len(input.Seeds), len(input.Signs))
	}

	// Step 1: Scale eta to fixed-point integers
	scaled := make([]int64, n)
	for i, v := range input.Eta {
		scaled[i] = int64(math.Round(v * scale))
	}

	// Step 2: Add masks for each peer pair
	for j, seedB64 := range input.Seeds {
		sign := int64(input.Signs[j])
		if sign != 1 && sign != -1 {
			return nil, fmt.Errorf("sign[%d] must be +1 or -1, got %d", j, sign)
		}

		// Generate mask using same logic as prgMaskVector
		maskOutput, err := prgMaskVector(&PRGMaskVectorInput{
			Seed:      seedB64,
			Iteration: input.Iteration,
			Length:    n,
			ScaleBits: scaleBits,
		})
		if err != nil {
			return nil, fmt.Errorf("mask generation for seed %d failed: %v", j, err)
		}

		for i := 0; i < n; i++ {
			scaled[i] += sign * int64(math.Round(maskOutput.MaskScaled[i]))
		}
	}

	// Return as float64 (int64 ≤ 2^53 fits exactly in float64)
	result := make([]float64, n)
	for i, v := range scaled {
		result[i] = float64(v)
	}

	return &FixedPointMaskEtaOutput{MaskedScaled: result}, nil
}

// ============================================================================
// fixed-point-unmask-sum: Coordinator sums masked vectors → float64
// ============================================================================

type FixedPointUnmaskSumInput struct {
	MaskedVectors [][]float64 `json:"masked_vectors"` // one per non-label server
	ScaleBits     int         `json:"scale_bits"`
}

type FixedPointUnmaskSumOutput struct {
	SumEta []float64 `json:"sum_eta"` // recovered aggregate η
}

func fixedPointUnmaskSum(input *FixedPointUnmaskSumInput) (*FixedPointUnmaskSumOutput, error) {
	scaleBits := input.ScaleBits
	if scaleBits == 0 {
		scaleBits = 20
	}

	if len(input.MaskedVectors) == 0 {
		return nil, fmt.Errorf("masked_vectors must not be empty")
	}

	n := len(input.MaskedVectors[0])
	for i, v := range input.MaskedVectors {
		if len(v) != n {
			return nil, fmt.Errorf("masked_vectors[%d] has length %d, expected %d", i, len(v), n)
		}
	}

	// Sum all vectors element-wise (masks cancel due to pairwise ±1 signs)
	sumScaled := make([]int64, n)
	for _, vec := range input.MaskedVectors {
		for i, v := range vec {
			sumScaled[i] += int64(math.Round(v))
		}
	}

	// Recover true aggregate η by dividing by 2^scale_bits
	scale := float64(int64(1) << scaleBits)
	result := make([]float64, n)
	for i, v := range sumScaled {
		result[i] = float64(v) / scale
	}

	return &FixedPointUnmaskSumOutput{SumEta: result}, nil
}

// ============================================================================
// Command handlers (called from main.go)
// ============================================================================

func handleDeriveSharedSeed() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		return
	}

	var input DeriveSharedSeedInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		return
	}

	output, err := deriveSharedSeed(&input)
	if err != nil {
		outputError(fmt.Sprintf("Derive shared seed failed: %v", err))
		return
	}

	outputJSON(output)
}

func handlePRGMaskVector() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		return
	}

	var input PRGMaskVectorInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		return
	}

	output, err := prgMaskVector(&input)
	if err != nil {
		outputError(fmt.Sprintf("PRG mask vector failed: %v", err))
		return
	}

	outputJSON(output)
}

func handleFixedPointMaskEta() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		return
	}

	var input FixedPointMaskEtaInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		return
	}

	output, err := fixedPointMaskEta(&input)
	if err != nil {
		outputError(fmt.Sprintf("Fixed-point mask eta failed: %v", err))
		return
	}

	outputJSON(output)
}

func handleFixedPointUnmaskSum() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		return
	}

	var input FixedPointUnmaskSumInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		return
	}

	output, err := fixedPointUnmaskSum(&input)
	if err != nil {
		outputError(fmt.Sprintf("Fixed-point unmask sum failed: %v", err))
		return
	}

	outputJSON(output)
}
