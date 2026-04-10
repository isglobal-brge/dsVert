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
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

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
	inputBytes, err := readInputBytes()
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
	inputBytes, err := readInputBytes()
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

// ============================================================================
// Ed25519 Identity Commands (pinned peers)
// ============================================================================

// --- derive-identity ---
// Derives a deterministic Ed25519 keypair from a base64-encoded seed.
// seed → SHA-256 → 32-byte Ed25519 seed → keypair

type DeriveIdentityInput struct {
	Seed string `json:"seed"` // Base64-encoded seed (any length)
}

type DeriveIdentityOutput struct {
	IdentityPK string `json:"identity_pk"` // Base64 Ed25519 public key (32 bytes)
	IdentitySK string `json:"identity_sk"` // Base64 Ed25519 private key (64 bytes)
}

func handleDeriveIdentity() {
	var input DeriveIdentityInput
	mpcReadInput(&input)

	seedBytes, err := base64.StdEncoding.DecodeString(input.Seed)
	if err != nil {
		outputError("Failed to decode seed: " + err.Error())
		return
	}

	// SHA-256 of seed → 32-byte Ed25519 seed
	hash := sha256.Sum256(seedBytes)
	sk := ed25519.NewKeyFromSeed(hash[:])
	pk := sk.Public().(ed25519.PublicKey)

	mpcWriteOutput(DeriveIdentityOutput{
		IdentityPK: base64.StdEncoding.EncodeToString(pk),
		IdentitySK: base64.StdEncoding.EncodeToString(sk),
	})
}

// --- sign-transport ---
// Signs an X25519 transport PK with the Ed25519 identity SK.

type SignTransportInput struct {
	TransportPK string `json:"transport_pk"` // Base64 X25519 public key
	IdentitySK  string `json:"identity_sk"`  // Base64 Ed25519 private key
}

type SignTransportOutput struct {
	Signature string `json:"signature"` // Base64 Ed25519 signature (64 bytes)
}

func handleSignTransport() {
	var input SignTransportInput
	mpcReadInput(&input)

	transportPK, err := base64.StdEncoding.DecodeString(input.TransportPK)
	if err != nil {
		outputError("Failed to decode transport PK: " + err.Error())
		return
	}

	identitySK, err := base64.StdEncoding.DecodeString(input.IdentitySK)
	if err != nil {
		outputError("Failed to decode identity SK: " + err.Error())
		return
	}

	if len(identitySK) != ed25519.PrivateKeySize {
		outputError(fmt.Sprintf("Invalid identity SK size: %d (expected %d)", len(identitySK), ed25519.PrivateKeySize))
		return
	}

	sig := ed25519.Sign(ed25519.PrivateKey(identitySK), transportPK)

	mpcWriteOutput(SignTransportOutput{
		Signature: base64.StdEncoding.EncodeToString(sig),
	})
}

// --- verify-transport ---
// Verifies an Ed25519 signature on an X25519 transport PK.

type VerifyTransportInput struct {
	TransportPK string `json:"transport_pk"` // Base64 X25519 public key
	IdentityPK  string `json:"identity_pk"`  // Base64 Ed25519 public key
	Signature   string `json:"signature"`    // Base64 Ed25519 signature
}

type VerifyTransportOutput struct {
	Valid bool `json:"valid"`
}

func handleVerifyTransport() {
	var input VerifyTransportInput
	mpcReadInput(&input)

	transportPK, err := base64.StdEncoding.DecodeString(input.TransportPK)
	if err != nil {
		mpcWriteOutput(VerifyTransportOutput{Valid: false})
		return
	}

	identityPK, err := base64.StdEncoding.DecodeString(input.IdentityPK)
	if err != nil {
		mpcWriteOutput(VerifyTransportOutput{Valid: false})
		return
	}

	sig, err := base64.StdEncoding.DecodeString(input.Signature)
	if err != nil {
		mpcWriteOutput(VerifyTransportOutput{Valid: false})
		return
	}

	if len(identityPK) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		mpcWriteOutput(VerifyTransportOutput{Valid: false})
		return
	}

	valid := ed25519.Verify(ed25519.PublicKey(identityPK), transportPK, sig)
	mpcWriteOutput(VerifyTransportOutput{Valid: valid})
}
