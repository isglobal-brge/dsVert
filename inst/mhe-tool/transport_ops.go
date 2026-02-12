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
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"golang.org/x/crypto/hkdf"
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
// The vectors are JSON-serialized, then encrypted with ECIES.
func transportEncryptVectors(vectors map[string][]float64, recipientPKBytes []byte) ([]byte, error) {
	// Serialize vectors to JSON
	jsonBytes, err := json.Marshal(vectors)
	if err != nil {
		return nil, fmt.Errorf("vector serialization failed: %v", err)
	}

	return transportEncryptBytes(jsonBytes, recipientPKBytes)
}

// transportDecryptVectors decrypts and deserializes a named map of float64 vectors.
func transportDecryptVectors(sealed []byte, recipientSKBytes []byte) (map[string][]float64, error) {
	jsonBytes, err := transportDecryptBytes(sealed, recipientSKBytes)
	if err != nil {
		return nil, err
	}

	var vectors map[string][]float64
	if err := json.Unmarshal(jsonBytes, &vectors); err != nil {
		return nil, fmt.Errorf("vector deserialization failed: %v", err)
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
