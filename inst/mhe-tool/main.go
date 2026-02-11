// mhe-tool: Multiparty Homomorphic Encryption CLI for dsVert
//
// This tool provides MHE operations using Lattigo's CKKS scheme.
// It is designed to be called from R via system2().
//
// Usage:
//   mhe-tool <command> [arguments]
//
// Commands:
//   keygen          Generate a key share for multiparty setup
//   combine-keys    Combine public key shares into collective public key
//   encrypt         Encrypt a vector/matrix using the collective public key
//   partial-decrypt Compute partial decryption using local secret key share
//   fuse-decrypt    Combine partial decryptions to get plaintext
//   multiply-plain  Multiply ciphertext by plaintext (cipher * plain)
//   sum-reduce      Sum all slots in a ciphertext (for inner product)
//   cross-product   Compute Z_A' * Enc(Z_B) for correlation (returns encrypted G_AB)
//   encrypt-columns Encrypt data column-by-column (for cross-product)
//   version         Print version information

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const VERSION = "0.1.0"

// Input/Output structures for JSON communication with R

type KeyGenInput struct {
	PartyID    int `json:"party_id"`
	NumParties int `json:"num_parties"`
	LogN       int `json:"log_n"`       // Ring dimension (default 14)
	LogScale   int `json:"log_scale"`   // Scale for CKKS (default 40)
}

type KeyGenOutput struct {
	SecretKeyShare string `json:"secret_key_share"` // Base64 encoded
	PublicKeyShare string `json:"public_key_share"` // Base64 encoded
	PartyID        int    `json:"party_id"`
}

type CombineKeysInput struct {
	PublicKeyShares []string `json:"public_key_shares"` // Base64 encoded shares
	LogN            int      `json:"log_n"`
	LogScale        int      `json:"log_scale"`
}

type CombineKeysOutput struct {
	CollectivePublicKey string `json:"collective_public_key"` // Base64 encoded
	RelinearizationKey  string `json:"relinearization_key"`   // Base64 encoded
	RotationKeys        string `json:"rotation_keys"`         // Base64 encoded
}

type EncryptInput struct {
	Data                [][]float64 `json:"data"`                  // Matrix (rows x cols)
	CollectivePublicKey string      `json:"collective_public_key"` // Base64 encoded
	LogN                int         `json:"log_n"`
	LogScale            int         `json:"log_scale"`
}

type EncryptOutput struct {
	Ciphertext string `json:"ciphertext"` // Base64 encoded
	Rows       int    `json:"rows"`
	Cols       int    `json:"cols"`
}

type PartialDecryptInput struct {
	Ciphertext     string `json:"ciphertext"`       // Base64 encoded
	SecretKeyShare string `json:"secret_key_share"` // Base64 encoded
	PartyID        int    `json:"party_id"`
	LogN           int    `json:"log_n"`
	LogScale       int    `json:"log_scale"`
}

type PartialDecryptOutput struct {
	PartialDecryption string `json:"partial_decryption"` // Base64 encoded
	PartyID           int    `json:"party_id"`
}

type FuseDecryptInput struct {
	PartialDecryptions []string `json:"partial_decryptions"` // Base64 encoded
	Rows               int      `json:"rows"`
	Cols               int      `json:"cols"`
	LogN               int      `json:"log_n"`
	LogScale           int      `json:"log_scale"`
}

type FuseDecryptOutput struct {
	Data [][]float64 `json:"data"` // Decrypted matrix
}

type MultiplyPlainInput struct {
	Ciphertext         string      `json:"ciphertext"`          // Base64 encoded
	Plaintext          [][]float64 `json:"plaintext"`           // Matrix to multiply
	RelinearizationKey string      `json:"relinearization_key"` // Base64 encoded
	LogN               int         `json:"log_n"`
	LogScale           int         `json:"log_scale"`
}

type MultiplyPlainOutput struct {
	ResultCiphertext string `json:"result_ciphertext"` // Base64 encoded
	Rows             int    `json:"rows"`
	Cols             int    `json:"cols"`
}

type SumReduceInput struct {
	Ciphertext   string `json:"ciphertext"`    // Base64 encoded
	RotationKeys string `json:"rotation_keys"` // Base64 encoded
	NumElements  int    `json:"num_elements"`  // Number of elements to sum
	LogN         int    `json:"log_n"`
	LogScale     int    `json:"log_scale"`
}

type SumReduceOutput struct {
	ResultCiphertext string `json:"result_ciphertext"` // Base64 encoded
}

type ErrorOutput struct {
	Error string `json:"error"`
}

// CrossProductInput: Compute Z_A' * Enc(Z_B) where Z_A is plaintext, Z_B is encrypted
type CrossProductInput struct {
	PlaintextColumns  [][]float64 `json:"plaintext_columns"`  // Z_A columns (each column is a vector)
	EncryptedColumns  []string    `json:"encrypted_columns"`  // Enc(Z_B) columns (base64 encoded ciphertexts)
	SecretKey         string      `json:"secret_key"`         // For decryption (single-party mode)
	LogN              int         `json:"log_n"`
	LogScale          int         `json:"log_scale"`
}

type CrossProductOutput struct {
	Result [][]float64 `json:"result"` // G_AB matrix (p_A x p_B)
}

// EncryptColumnsInput: Encrypt a matrix column-by-column
type EncryptColumnsInput struct {
	Data                [][]float64 `json:"data"`                  // Matrix (rows x cols), will encrypt each column
	CollectivePublicKey string      `json:"collective_public_key"` // Base64 encoded
	LogN                int         `json:"log_n"`
	LogScale            int         `json:"log_scale"`
}

type EncryptColumnsOutput struct {
	EncryptedColumns []string `json:"encrypted_columns"` // One ciphertext per column (base64 encoded)
	NumRows          int      `json:"num_rows"`
	NumCols          int      `json:"num_cols"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "version":
		fmt.Printf(`{"version": "%s"}`, VERSION)
	case "keygen":
		handleKeyGen()
	case "combine-keys":
		handleCombineKeys()
	case "encrypt":
		handleEncrypt()
	case "partial-decrypt":
		handlePartialDecrypt()
	case "fuse-decrypt":
		handleFuseDecrypt()
	case "multiply-plain":
		handleMultiplyPlain()
	case "sum-reduce":
		handleSumReduce()
	case "cross-product":
		handleCrossProduct()
	case "encrypt-columns":
		handleEncryptColumns()
	case "help", "-h", "--help":
		printUsage()
	default:
		outputError(fmt.Sprintf("Unknown command: %s", command))
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `mhe-tool: Multiparty Homomorphic Encryption CLI for dsVert

Usage:
  mhe-tool <command> < input.json > output.json

Commands:
  keygen          Generate a key share for multiparty setup
  combine-keys    Combine public key shares into collective public key
  encrypt         Encrypt a vector/matrix using the collective public key
  partial-decrypt Compute partial decryption using local secret key share
  fuse-decrypt    Combine partial decryptions to get plaintext
  multiply-plain  Multiply ciphertext by plaintext (cipher * plain)
  sum-reduce      Sum all slots in a ciphertext (for inner product)
  cross-product   Compute Z_A' * Enc(Z_B) for encrypted cross-product matrix
  encrypt-columns Encrypt a matrix column-by-column
  version         Print version information
  help            Print this help message

All commands read JSON from stdin and write JSON to stdout.
See documentation for JSON schema for each command.`)
}

func readInput() ([]byte, error) {
	return io.ReadAll(os.Stdin)
}

func outputJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		outputError(fmt.Sprintf("Failed to encode output: %v", err))
		os.Exit(1)
	}
}

func outputError(msg string) {
	enc := json.NewEncoder(os.Stdout)
	enc.Encode(ErrorOutput{Error: msg})
}

// Handler implementations using Lattigo CKKS

func handleKeyGen() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input KeyGenInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	// Set defaults
	if input.LogN == 0 {
		input.LogN = 14
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}

	// Generate key share using Lattigo
	output, err := generateKeyShare(input.PartyID, input.NumParties, input.LogN, input.LogScale)
	if err != nil {
		outputError(fmt.Sprintf("Key generation failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

func handleCombineKeys() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input CombineKeysInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	// Set defaults
	if input.LogN == 0 {
		input.LogN = 14
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}

	// Combine public keys using Lattigo
	output, err := combinePublicKeys(input.PublicKeyShares, input.LogN, input.LogScale)
	if err != nil {
		outputError(fmt.Sprintf("Key combination failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

func handleEncrypt() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input EncryptInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	// Set defaults
	if input.LogN == 0 {
		input.LogN = 14
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}

	// Encrypt using Lattigo
	output, err := encryptMatrix(input.Data, input.CollectivePublicKey, input.LogN, input.LogScale)
	if err != nil {
		outputError(fmt.Sprintf("Encryption failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

func handlePartialDecrypt() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input PartialDecryptInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	// Set defaults
	if input.LogN == 0 {
		input.LogN = 14
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}

	// Compute partial decryption using Lattigo
	output, err := partialDecrypt(input.Ciphertext, input.SecretKeyShare, input.PartyID, input.LogN, input.LogScale)
	if err != nil {
		outputError(fmt.Sprintf("Partial decryption failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

func handleFuseDecrypt() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input FuseDecryptInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	// Set defaults
	if input.LogN == 0 {
		input.LogN = 14
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}

	// Fuse decryption shares using Lattigo
	output, err := fuseDecryptions(input.PartialDecryptions, input.Rows, input.Cols, input.LogN, input.LogScale)
	if err != nil {
		outputError(fmt.Sprintf("Decryption fusion failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

func handleMultiplyPlain() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input MultiplyPlainInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	// Set defaults
	if input.LogN == 0 {
		input.LogN = 14
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}

	// Multiply ciphertext by plaintext using Lattigo
	output, err := multiplyByPlaintext(input.Ciphertext, input.Plaintext, input.RelinearizationKey, input.LogN, input.LogScale)
	if err != nil {
		outputError(fmt.Sprintf("Multiplication failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

func handleSumReduce() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input SumReduceInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	// Set defaults
	if input.LogN == 0 {
		input.LogN = 14
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}

	// Sum reduce using Lattigo rotations
	output, err := sumReduce(input.Ciphertext, input.RotationKeys, input.NumElements, input.LogN, input.LogScale)
	if err != nil {
		outputError(fmt.Sprintf("Sum reduction failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

func handleCrossProduct() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input CrossProductInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	// Set defaults
	if input.LogN == 0 {
		input.LogN = 14
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}

	// Compute cross product using Lattigo
	output, err := computeCrossProduct(input.PlaintextColumns, input.EncryptedColumns,
		input.SecretKey, input.LogN, input.LogScale)
	if err != nil {
		outputError(fmt.Sprintf("Cross product failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

func handleEncryptColumns() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input EncryptColumnsInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	// Set defaults
	if input.LogN == 0 {
		input.LogN = 14
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}

	// Encrypt columns using Lattigo
	output, err := encryptColumns(input.Data, input.CollectivePublicKey, input.LogN, input.LogScale)
	if err != nil {
		outputError(fmt.Sprintf("Column encryption failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}
