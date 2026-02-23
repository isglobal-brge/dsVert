// transport_ops.go: X25519 + AES-256-GCM transport encryption for dsVert
//
// Provides authenticated encryption for:
//   - Share-wrapping: partial decryption shares encrypted under fusion server's PK
//   - GLM Secure Routing: eta/mu/w/v vectors encrypted between coordinator and servers
//
// Protocol (standard ECIES):
//   1. Generate ephemeral X25519 keypair
//   2. ECDH(ephemeral_sk, recipient_pk) → shared_secret
//   3. HKDF-SHA256(shared_secret, "dsVert-transport-v1") → AES key (32 bytes)
//   4. AES-256-GCM encrypt(key, random_nonce, plaintext)
//   5. Output: ephemeral_pk (32) || nonce (12) || ciphertext || tag (16)

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"

	"golang.org/x/crypto/hkdf"
)

// Binary Vector Format v1 constants
const (
	bvfMagic   = 0xBF
	bvfVersion = 0x01
)

const transportInfoString = "dsVert-transport-v1"

// ============================================================================
// Key Generation
// ============================================================================

type TransportKeygenOutput struct {
	PublicKey  string `json:"public_key"`  // Base64
	SecretKey  string `json:"secret_key"`  // Base64
}

func transportKeygen() (*TransportKeygenOutput, error) {
	curve := ecdh.X25519()
	sk, err := curve.GenerateKey(crand.Reader)
	if err != nil {
		return nil, fmt.Errorf("X25519 keygen failed: %v", err)
	}

	return &TransportKeygenOutput{
		PublicKey: base64.StdEncoding.EncodeToString(sk.PublicKey().Bytes()),
		SecretKey: base64.StdEncoding.EncodeToString(sk.Bytes()),
	}, nil
}

// ============================================================================
// ECIES Encrypt / Decrypt (byte-level)
// ============================================================================

// transportEncryptBytes encrypts arbitrary data under a recipient's X25519 public key.
// Returns: ephemeral_pk (32) || nonce (12) || ciphertext || tag (16)
func transportEncryptBytes(data []byte, recipientPKBytes []byte) ([]byte, error) {
	curve := ecdh.X25519()

	recipientPK, err := curve.NewPublicKey(recipientPKBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient public key: %v", err)
	}

	// Generate ephemeral keypair
	ephSK, err := curve.GenerateKey(crand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ephemeral keygen failed: %v", err)
	}

	// ECDH
	sharedSecret, err := ephSK.ECDH(recipientPK)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %v", err)
	}

	// Derive AES key via HKDF
	aesKey, err := deriveAESKey(sharedSecret)
	if err != nil {
		return nil, err
	}

	// AES-256-GCM encrypt
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("AES cipher failed: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM failed: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := crand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %v", err)
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// Format: ephemeral_pk (32) || nonce (12) || ciphertext+tag
	result := make([]byte, 0, 32+12+len(ciphertext))
	result = append(result, ephSK.PublicKey().Bytes()...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// transportDecryptBytes decrypts data encrypted by transportEncryptBytes.
func transportDecryptBytes(sealed []byte, recipientSKBytes []byte) ([]byte, error) {
	if len(sealed) < 32+12+16 {
		return nil, fmt.Errorf("sealed data too short: %d bytes", len(sealed))
	}

	curve := ecdh.X25519()

	recipientSK, err := curve.NewPrivateKey(recipientSKBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient secret key: %v", err)
	}

	// Parse sealed: ephemeral_pk (32) || nonce (12) || ciphertext+tag
	ephPKBytes := sealed[:32]
	nonce := sealed[32:44]
	ciphertextWithTag := sealed[44:]

	ephPK, err := curve.NewPublicKey(ephPKBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %v", err)
	}

	// ECDH
	sharedSecret, err := recipientSK.ECDH(ephPK)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %v", err)
	}

	// Derive AES key
	aesKey, err := deriveAESKey(sharedSecret)
	if err != nil {
		return nil, err
	}

	// AES-256-GCM decrypt
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("AES cipher failed: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM failed: %v", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertextWithTag, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (authentication error): %v", err)
	}

	return plaintext, nil
}

// deriveAESKey derives a 32-byte AES key from the ECDH shared secret using HKDF-SHA256.
func deriveAESKey(sharedSecret []byte) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte(transportInfoString))
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("HKDF key derivation failed: %v", err)
	}
	return key, nil
}

// ============================================================================
// Vector Encrypt / Decrypt (for GLM routing: mu, w, v, eta)
// ============================================================================

// transportEncryptVectors encrypts a named map of float64 vectors.
// Uses Binary Vector Format v1 (compact float64 LE) for ~2x size reduction vs JSON.
func transportEncryptVectors(vectors map[string][]float64, recipientPKBytes []byte) ([]byte, error) {
	binaryBytes, err := marshalBinaryVectors(vectors)
	if err != nil {
		return nil, fmt.Errorf("binary vector marshal failed: %v", err)
	}
	return transportEncryptBytes(binaryBytes, recipientPKBytes)
}

// transportDecryptVectors decrypts and deserializes a named map of float64 vectors.
// Auto-detects format: 0xBF = Binary Vector Format v1, 0x7B ('{') = legacy JSON.
func transportDecryptVectors(sealed []byte, recipientSKBytes []byte) (map[string][]float64, error) {
	plaintext, err := transportDecryptBytes(sealed, recipientSKBytes)
	if err != nil {
		return nil, err
	}

	// Auto-detect: 0xBF = binary v1, 0x7B ('{') = JSON legacy
	if len(plaintext) >= 2 && plaintext[0] == bvfMagic && plaintext[1] == bvfVersion {
		return unmarshalBinaryVectors(plaintext)
	}

	// Fallback: JSON (for in-flight messages during rolling upgrade)
	var vectors map[string][]float64
	if err := json.Unmarshal(plaintext, &vectors); err != nil {
		return nil, fmt.Errorf("vector deserialization failed: %v", err)
	}
	return vectors, nil
}

// marshalBinaryVectors encodes a map of named float64 vectors into Binary Vector Format v1.
//
// Wire format:
//
//	Offset  Size     Field
//	0       1        Magic: 0xBF
//	1       1        Version: 0x01
//	2       1        Flags: 0x00 (reserved)
//	3       1        K: number of named vectors (uint8, max 255)
//	4       ...      Descriptor table: K entries, each:
//	                   - name_len (uint8)
//	                   - name (name_len bytes, UTF-8)
//	                   - vec_len (uint32 LE, number of float64 elements)
//	...     ...      Data blocks: K contiguous blocks of vec_len×8 bytes (float64 LE)
func marshalBinaryVectors(vectors map[string][]float64) ([]byte, error) {
	if len(vectors) > 255 {
		return nil, fmt.Errorf("too many vectors: %d (max 255)", len(vectors))
	}

	// Sort keys for deterministic output
	keys := make([]string, 0, len(vectors))
	for k := range vectors {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Calculate total size
	totalSize := 4 // header
	totalDataSize := 0
	for _, k := range keys {
		if len(k) > 255 {
			return nil, fmt.Errorf("vector name too long: %d bytes (max 255)", len(k))
		}
		totalSize += 1 + len(k) + 4 // name_len + name + vec_len
		totalDataSize += len(vectors[k]) * 8
	}
	totalSize += totalDataSize

	buf := make([]byte, totalSize)
	offset := 0

	// Header
	buf[offset] = bvfMagic
	buf[offset+1] = bvfVersion
	buf[offset+2] = 0x00 // flags
	buf[offset+3] = byte(len(keys))
	offset += 4

	// Descriptor table
	for _, k := range keys {
		buf[offset] = byte(len(k))
		offset++
		copy(buf[offset:], k)
		offset += len(k)
		binary.LittleEndian.PutUint32(buf[offset:], uint32(len(vectors[k])))
		offset += 4
	}

	// Data blocks
	for _, k := range keys {
		for _, v := range vectors[k] {
			binary.LittleEndian.PutUint64(buf[offset:], math.Float64bits(v))
			offset += 8
		}
	}

	return buf, nil
}

// unmarshalBinaryVectors decodes Binary Vector Format v1 back to a map of named float64 vectors.
func unmarshalBinaryVectors(data []byte) (map[string][]float64, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("binary vector data too short: %d bytes", len(data))
	}
	if data[0] != bvfMagic || data[1] != bvfVersion {
		return nil, fmt.Errorf("invalid binary vector magic/version: 0x%02x 0x%02x", data[0], data[1])
	}

	k := int(data[3])
	offset := 4

	// Read descriptor table
	type vecDesc struct {
		name   string
		vecLen uint32
	}
	descs := make([]vecDesc, k)

	for i := 0; i < k; i++ {
		if offset >= len(data) {
			return nil, fmt.Errorf("truncated descriptor table at vector %d", i)
		}
		nameLen := int(data[offset])
		offset++
		if offset+nameLen+4 > len(data) {
			return nil, fmt.Errorf("truncated descriptor for vector %d", i)
		}
		name := string(data[offset : offset+nameLen])
		offset += nameLen
		vecLen := binary.LittleEndian.Uint32(data[offset:])
		offset += 4
		descs[i] = vecDesc{name: name, vecLen: vecLen}
	}

	// Read data blocks
	vectors := make(map[string][]float64, k)
	for _, d := range descs {
		n := int(d.vecLen)
		needed := n * 8
		if offset+needed > len(data) {
			return nil, fmt.Errorf("truncated data block for vector %q: need %d bytes, have %d",
				d.name, needed, len(data)-offset)
		}
		vec := make([]float64, n)
		for j := 0; j < n; j++ {
			vec[j] = math.Float64frombits(binary.LittleEndian.Uint64(data[offset:]))
			offset += 8
		}
		vectors[d.name] = vec
	}

	return vectors, nil
}

// ============================================================================
// Command handlers (called from main.go)
// ============================================================================

func handleTransportKeygen() {
	output, err := transportKeygen()
	if err != nil {
		outputError(fmt.Sprintf("Transport keygen failed: %v", err))
		return
	}
	outputJSON(output)
}

// --- transport-encrypt ---

type TransportEncryptInput struct {
	Data        string `json:"data"`         // Base64 encoded plaintext
	RecipientPK string `json:"recipient_pk"` // Base64 encoded X25519 public key
}

type TransportEncryptOutput struct {
	Sealed string `json:"sealed"` // Base64 encoded sealed data
}

func handleTransportEncrypt() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		return
	}

	var input TransportEncryptInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		return
	}

	data, err := base64.StdEncoding.DecodeString(input.Data)
	if err != nil {
		outputError(fmt.Sprintf("Failed to decode data: %v", err))
		return
	}

	recipientPK, err := base64.StdEncoding.DecodeString(input.RecipientPK)
	if err != nil {
		outputError(fmt.Sprintf("Failed to decode recipient PK: %v", err))
		return
	}

	sealed, err := transportEncryptBytes(data, recipientPK)
	if err != nil {
		outputError(fmt.Sprintf("Transport encrypt failed: %v", err))
		return
	}

	outputJSON(TransportEncryptOutput{
		Sealed: base64.StdEncoding.EncodeToString(sealed),
	})
}

// --- transport-decrypt ---

type TransportDecryptInput struct {
	Sealed      string `json:"sealed"`       // Base64 encoded sealed data
	RecipientSK string `json:"recipient_sk"` // Base64 encoded X25519 secret key
}

type TransportDecryptOutput struct {
	Data string `json:"data"` // Base64 encoded plaintext
}

func handleTransportDecrypt() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		return
	}

	var input TransportDecryptInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		return
	}

	sealed, err := base64.StdEncoding.DecodeString(input.Sealed)
	if err != nil {
		outputError(fmt.Sprintf("Failed to decode sealed data: %v", err))
		return
	}

	recipientSK, err := base64.StdEncoding.DecodeString(input.RecipientSK)
	if err != nil {
		outputError(fmt.Sprintf("Failed to decode recipient SK: %v", err))
		return
	}

	data, err := transportDecryptBytes(sealed, recipientSK)
	if err != nil {
		outputError(fmt.Sprintf("Transport decrypt failed: %v", err))
		return
	}

	outputJSON(TransportDecryptOutput{
		Data: base64.StdEncoding.EncodeToString(data),
	})
}

// --- transport-encrypt-vectors ---

type TransportEncryptVectorsInput struct {
	Vectors     map[string][]float64 `json:"vectors"`      // Named vectors
	RecipientPK string               `json:"recipient_pk"` // Base64 encoded X25519 public key
}

type TransportEncryptVectorsOutput struct {
	Sealed string `json:"sealed"` // Base64 encoded sealed data
}

func handleTransportEncryptVectors() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		return
	}

	var input TransportEncryptVectorsInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		return
	}

	recipientPK, err := base64.StdEncoding.DecodeString(input.RecipientPK)
	if err != nil {
		outputError(fmt.Sprintf("Failed to decode recipient PK: %v", err))
		return
	}

	sealed, err := transportEncryptVectors(input.Vectors, recipientPK)
	if err != nil {
		outputError(fmt.Sprintf("Transport encrypt vectors failed: %v", err))
		return
	}

	outputJSON(TransportEncryptVectorsOutput{
		Sealed: base64.StdEncoding.EncodeToString(sealed),
	})
}

// --- transport-decrypt-vectors ---

type TransportDecryptVectorsInput struct {
	Sealed      string `json:"sealed"`       // Base64 encoded sealed data
	RecipientSK string `json:"recipient_sk"` // Base64 encoded X25519 secret key
}

type TransportDecryptVectorsOutput struct {
	Vectors map[string][]float64 `json:"vectors"` // Named vectors
}

func handleTransportDecryptVectors() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		return
	}

	var input TransportDecryptVectorsInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		return
	}

	sealed, err := base64.StdEncoding.DecodeString(input.Sealed)
	if err != nil {
		outputError(fmt.Sprintf("Failed to decode sealed data: %v", err))
		return
	}

	recipientSK, err := base64.StdEncoding.DecodeString(input.RecipientSK)
	if err != nil {
		outputError(fmt.Sprintf("Failed to decode recipient SK: %v", err))
		return
	}

	vectors, err := transportDecryptVectors(sealed, recipientSK)
	if err != nil {
		outputError(fmt.Sprintf("Transport decrypt vectors failed: %v", err))
		return
	}

	// Sort keys for deterministic output
	keys := make([]string, 0, len(vectors))
	for k := range vectors {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	outputJSON(TransportDecryptVectorsOutput{
		Vectors: vectors,
	})
}
