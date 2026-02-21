// mhe-tool: Multiparty Homomorphic Encryption CLI for dsVert
//
// This tool provides MHE operations using Lattigo's CKKS scheme with
// threshold decryption. Each server holds a secret key share; decryption
// requires ALL servers to cooperate.
//
// Usage:
//   mhe-tool <command> < input.json > output.json
//
// Commands:
//   mhe-setup           Generate secret key and public key share for this party
//   mhe-combine         Combine public key shares into collective public key
//   encrypt-columns     Encrypt data column-by-column using the collective public key
//   mhe-cross-product   Compute plaintext * ciphertext element-wise products
//   mhe-partial-decrypt Compute partial decryption share using this party's secret key
//   mhe-fuse            Fuse all partial decryption shares to recover plaintext
//   mhe-fuse-server     Unwrap + fuse shares server-side (share-wrapping)
//   transport-keygen    Generate X25519 transport keypair
//   transport-encrypt   Encrypt arbitrary bytes (X25519 + AES-256-GCM)
//   transport-decrypt   Decrypt arbitrary bytes
//   transport-encrypt-vectors  Encrypt named float64 vectors
//   transport-decrypt-vectors  Decrypt named float64 vectors
//   psi-mask            Hash IDs to P-256 points and multiply by random scalar
//   psi-double-mask     Multiply received curve points by a stored scalar
//   psi-match           Find intersection of two sets of double-masked points
//   version             Print version information

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const VERSION = "1.8.0"

// EncryptColumnsInput: Encrypt a matrix column-by-column
type EncryptColumnsInput struct {
	Data                [][]float64 `json:"data"`                  // Matrix (rows x cols), will encrypt each column
	CollectivePublicKey string      `json:"collective_public_key"` // Base64 encoded
	LogN                int         `json:"log_n"`
	LogScale            int         `json:"log_scale"`
}

// EncryptColumnsOutput: One ciphertext per column
type EncryptColumnsOutput struct {
	EncryptedColumns []string `json:"encrypted_columns"` // One ciphertext per column (base64 encoded)
	NumRows          int      `json:"num_rows"`
	NumCols          int      `json:"num_cols"`
}

// ErrorOutput for reporting errors as JSON
type ErrorOutput struct {
	Error string `json:"error"`
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
	case "encrypt-columns":
		handleEncryptColumns()
	case "mhe-setup":
		handleMHESetup()
	case "mhe-combine":
		handleMHECombine()
	case "mhe-cross-product":
		handleMHECrossProduct()
	case "mhe-partial-decrypt":
		handleMHEPartialDecrypt()
	case "mhe-fuse":
		handleMHEFuse()
	case "mhe-glm-gradient":
		handleMHEGLMGradient()
	case "psi-mask":
		handlePSIMask()
	case "psi-double-mask":
		handlePSIDoubleMask()
	case "psi-match":
		handlePSIMatch()
	case "transport-keygen":
		handleTransportKeygen()
	case "transport-encrypt":
		handleTransportEncrypt()
	case "transport-decrypt":
		handleTransportDecrypt()
	case "transport-encrypt-vectors":
		handleTransportEncryptVectors()
	case "transport-decrypt-vectors":
		handleTransportDecryptVectors()
	case "mhe-fuse-server":
		handleMHEFuseServer()
	case "mhe-rlk-aggregate-r1":
		handleMHERLKAggregateR1()
	case "mhe-rlk-round2":
		handleMHERLKRound2()
	case "mhe-ct-add":
		handleMHECTAdd()
	case "mhe-eval-poly":
		handleMHEEvalPoly()
	case "mhe-he-gradient":
		handleMHEHEGradient()
	case "mhe-encrypt-vector":
		handleMHEEncryptVector()
	case "derive-shared-seed":
		handleDeriveSharedSeed()
	case "prg-mask-vector":
		handlePRGMaskVector()
	case "fixed-point-mask-eta":
		handleFixedPointMaskEta()
	case "fixed-point-unmask-sum":
		handleFixedPointUnmaskSum()
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
  mhe-setup                  Generate secret key and public key share for this party
  mhe-combine                Combine public key shares into collective public key (CPK)
  encrypt-columns            Encrypt data column-by-column using the CPK
  mhe-cross-product          Compute plaintext * ciphertext element-wise products (encrypted)
  mhe-glm-gradient           Compute encrypted GLM gradient g_k = X_k^T (v*(ct_y - mu))
  mhe-partial-decrypt        Compute partial decryption share using this party's secret key
  mhe-fuse                   Fuse all partial decryption shares to recover plaintext
  mhe-fuse-server            Unwrap + fuse shares server-side (share-wrapping protocol)
  mhe-rlk-aggregate-r1       Aggregate RLK round 1 shares
  mhe-rlk-round2             Generate RLK round 2 share from aggregated round 1
  mhe-ct-add                 Homomorphic addition of two ciphertexts
  mhe-eval-poly              Evaluate polynomial on ciphertext (BSGS, degree ≤ 7)
  mhe-he-gradient            Compute encrypted gradient with encrypted mu (HE-Link)
  mhe-encrypt-vector         Encrypt a single float64 vector under CPK
  derive-shared-seed         Derive pairwise PRG seed (X25519 + HKDF)
  prg-mask-vector            Generate deterministic ChaCha20 mask vector
  fixed-point-mask-eta       Mask η with fixed-point + PRG masks
  fixed-point-unmask-sum     Sum masked vectors → recover aggregate η
  transport-keygen           Generate X25519 transport keypair
  transport-encrypt          Encrypt arbitrary bytes (ECIES: X25519 + AES-256-GCM)
  transport-decrypt          Decrypt arbitrary bytes
  transport-encrypt-vectors  Encrypt named float64 vectors for GLM secure routing
  transport-decrypt-vectors  Decrypt named float64 vectors
  psi-mask                   Hash IDs to P-256 points and multiply by random scalar
  psi-double-mask            Multiply received curve points by a stored scalar
  psi-match                  Find intersection of two sets of double-masked points
  version                    Print version information
  help                       Print this help message

All commands read JSON from stdin and write JSON to stdout.
See package documentation for the JSON schema of each command.`)
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

// ============================================================================
// Command handlers
// ============================================================================

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

	if input.LogN == 0 {
		input.LogN = 12
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}

	output, err := encryptColumns(input.Data, input.CollectivePublicKey, input.LogN, input.LogScale)
	if err != nil {
		outputError(fmt.Sprintf("Column encryption failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

func handleMHESetup() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input MHESetupInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	if input.LogN == 0 {
		input.LogN = 12
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}
	if input.NumObs == 0 {
		input.NumObs = 100
	}

	output, err := mheSetup(&input)
	if err != nil {
		outputError(fmt.Sprintf("MHE setup failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

func handleMHECombine() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input MHECombineInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	if input.LogN == 0 {
		input.LogN = 12
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}
	if input.NumObs == 0 {
		input.NumObs = 100
	}

	output, err := mheCombine(&input)
	if err != nil {
		outputError(fmt.Sprintf("MHE combine failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

func handleMHECrossProduct() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input MHECrossProductInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	if input.LogN == 0 {
		input.LogN = 12
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}

	output, err := mheCrossProduct(&input)
	if err != nil {
		outputError(fmt.Sprintf("MHE cross-product failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

func handleMHEPartialDecrypt() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input MHEPartialDecryptInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	if input.LogN == 0 {
		input.LogN = 12
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}

	output, err := mhePartialDecrypt(&input)
	if err != nil {
		outputError(fmt.Sprintf("MHE partial decrypt failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

func handleMHEFuse() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input MHEFuseInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	if input.LogN == 0 {
		input.LogN = 12
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}

	output, err := mheFuse(&input)
	if err != nil {
		outputError(fmt.Sprintf("MHE fuse failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

func handleMHEGLMGradient() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input GLMGradientInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	if input.LogN == 0 {
		input.LogN = 12
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}
	if input.NumObs == 0 {
		input.NumObs = 100
	}

	output, err := mheGLMGradient(&input)
	if err != nil {
		outputError(fmt.Sprintf("GLM gradient failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

// ============================================================================
// PSI command handlers
// ============================================================================

func handlePSIMask() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input PSIMaskInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	output, err := psiMask(&input)
	if err != nil {
		outputError(fmt.Sprintf("PSI mask failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

func handlePSIDoubleMask() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input PSIDoubleMaskInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	output, err := psiDoubleMask(&input)
	if err != nil {
		outputError(fmt.Sprintf("PSI double-mask failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

func handlePSIMatch() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input PSIMatchInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	output, err := psiMatch(&input)
	if err != nil {
		outputError(fmt.Sprintf("PSI match failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

// ============================================================================
// MHE Fuse Server command handler
// ============================================================================

func handleMHEFuseServer() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input MHEFuseServerInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	if input.LogN == 0 {
		input.LogN = 12
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}

	output, err := mheFuseServer(&input)
	if err != nil {
		outputError(fmt.Sprintf("MHE fuse server failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

// ============================================================================
// RLK protocol command handlers
// ============================================================================

func handleMHERLKAggregateR1() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input RLKAggregateR1Input
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	if input.LogN == 0 {
		input.LogN = 14
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}

	output, err := mheRLKAggregateR1(&input)
	if err != nil {
		outputError(fmt.Sprintf("RLK aggregate R1 failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

func handleMHERLKRound2() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input RLKRound2Input
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	if input.LogN == 0 {
		input.LogN = 14
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}

	output, err := mheRLKRound2(&input)
	if err != nil {
		outputError(fmt.Sprintf("RLK round2 failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

// ============================================================================
// HE-Link command handlers
// ============================================================================

func handleMHECTAdd() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input CTAddInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	if input.LogN == 0 {
		input.LogN = 12
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}

	output, err := mheCTAdd(&input)
	if err != nil {
		outputError(fmt.Sprintf("CT add failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

func handleMHEEvalPoly() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input EvalPolyInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	if input.LogN == 0 {
		input.LogN = 14
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}

	output, err := mheEvalPoly(&input)
	if err != nil {
		outputError(fmt.Sprintf("Polynomial eval failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

func handleMHEHEGradient() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input HEGradientInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	if input.LogN == 0 {
		input.LogN = 14
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}
	if input.NumObs == 0 {
		input.NumObs = 100
	}

	output, err := mheHEGradient(&input)
	if err != nil {
		outputError(fmt.Sprintf("HE gradient failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

func handleMHEEncryptVector() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input EncryptVectorInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	if input.LogN == 0 {
		input.LogN = 14
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}

	output, err := mheEncryptVector(&input)
	if err != nil {
		outputError(fmt.Sprintf("Vector encryption failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}
