package main

// ckks_local_test.go: Single-key CKKS test for the full polynomial sigmoid pipeline.
// Tests: encrypt eta → poly sigmoid → Enc(mu) → gradient X^T*(y-mu) → decrypt
// No MHE, no threshold — pure single-key CKKS to validate the circuit.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"os"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

type CKKSLocalTestInput struct {
	Eta      []float64   `json:"eta"`       // η_total vector (n observations)
	Y        []float64   `json:"y"`         // Response vector (n observations)
	XCols    [][]float64 `json:"x_cols"`    // Feature columns (p columns, each n elements)
	Family   string      `json:"family"`    // "binomial" or "poisson"
	LogN     int         `json:"log_n"`
	LogScale int         `json:"log_scale"`
}

type CKKSLocalTestOutput struct {
	Gradient    []float64 `json:"gradient"`     // Plaintext gradient (p elements)
	MuPlaintext []float64 `json:"mu_plaintext"` // Decrypted mu for verification
	MuExact     []float64 `json:"mu_exact"`     // Exact sigmoid/exp for comparison
	MuError     float64   `json:"mu_error"`     // Max |mu_ckks - mu_exact|
	GradError   float64   `json:"grad_error"`   // Max |grad_ckks - grad_exact|
	LevelsUsed  int       `json:"levels_used"`  // How many CKKS levels consumed
}

func handleCKKSLocalTest() {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input CKKSLocalTestInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	if input.LogN == 0 {
		input.LogN = 13
	}
	if input.LogScale == 0 {
		input.LogScale = 40
	}

	output, err := ckksLocalTest(&input)
	if err != nil {
		outputError(fmt.Sprintf("CKKS local test failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

func ckksLocalTest(input *CKKSLocalTestInput) (*CKKSLocalTestOutput, error) {
	params, err := getParams(input.LogN, input.LogScale)
	if err != nil {
		return nil, fmt.Errorf("failed to get params: %v", err)
	}

	n := len(input.Eta)
	nSlots := params.MaxSlots()

	// ========== Step 1: Key Generation ==========
	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk)
	rlk := kgen.GenRelinearizationKeyNew(sk)

	// Galois keys for InnerSum rotations
	galEls := params.GaloisElementsForInnerSum(1, n)
	gks := kgen.GenGaloisKeysNew(galEls, sk)
	evk := rlwe.NewMemEvaluationKeySet(rlk, gks...)

	encoder := ckks.NewEncoder(params)
	encryptor := ckks.NewEncryptor(params, pk)
	decryptor := ckks.NewDecryptor(params, sk)
	evaluator := ckks.NewEvaluator(params, evk)

	// ========== Step 2: Encrypt eta ==========
	ptEta := ckks.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(input.Eta, ptEta); err != nil {
		return nil, fmt.Errorf("failed to encode eta: %v", err)
	}
	ctEta, err := encryptor.EncryptNew(ptEta)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt eta: %v", err)
	}

	// ========== Step 3: Polynomial sigmoid evaluation ==========
	// Degree-7: needs 3 multiplicative levels
	startLevel := ctEta.Level()

	coeffs := SigmoidCoefficients()
	if input.Family == "poisson" {
		// For Poisson, use exp approximation instead
		// Simple degree-4 Taylor: exp(x) ≈ 1 + x + x²/2 + x³/6 + x⁴/24
		coeffs = []float64{1.0, 1.0, 0.5, 1.0 / 6.0, 1.0 / 24.0, 0.0, 0.0, 0.0}
	}

	// --- x² ---
	ctX2, err := evaluator.MulRelinNew(ctEta, ctEta)
	if err != nil {
		return nil, fmt.Errorf("x²: %v", err)
	}
	if err := evaluator.Rescale(ctX2, ctX2); err != nil {
		return nil, fmt.Errorf("rescale x²: %v", err)
	}

	// --- x⁴ ---
	ctX4, err := evaluator.MulRelinNew(ctX2, ctX2)
	if err != nil {
		return nil, fmt.Errorf("x⁴: %v", err)
	}
	if err := evaluator.Rescale(ctX4, ctX4); err != nil {
		return nil, fmt.Errorf("rescale x⁴: %v", err)
	}

	// --- Baby-step polynomials ---
	// q_low(x) = (c0 + c2*x²) + x*(c1 + c3*x²)
	// q_high(x) = (c4 + c6*x²) + x*(c5 + c7*x²)

	babyLevel := ctX2.Level()

	constPt := func(val float64, level int) *rlwe.Plaintext {
		vals := make([]float64, nSlots)
		for i := range vals {
			vals[i] = val
		}
		pt := ckks.NewPlaintext(params, level)
		encoder.Encode(vals, pt)
		return pt
	}

	// Drop ctEta (x) to match x² level
	ctX1 := ctEta.CopyNew()
	if ctX1.Level() > babyLevel {
		evaluator.DropLevel(ctX1, ctX1.Level()-babyLevel)
	}

	// q_low_even = c0 + c2*x²
	ctQLowEven, err := evaluator.MulNew(ctX2, constPt(coeffs[2], babyLevel))
	if err != nil {
		return nil, fmt.Errorf("c2*x²: %v", err)
	}
	if err := evaluator.Rescale(ctQLowEven, ctQLowEven); err != nil {
		return nil, fmt.Errorf("rescale c2*x²: %v", err)
	}
	if err := evaluator.Add(ctQLowEven, constPt(coeffs[0], ctQLowEven.Level()), ctQLowEven); err != nil {
		return nil, fmt.Errorf("c0+c2*x²: %v", err)
	}

	// q_low_odd = c1 + c3*x²
	ctQLowOdd, err := evaluator.MulNew(ctX2, constPt(coeffs[3], babyLevel))
	if err != nil {
		return nil, fmt.Errorf("c3*x²: %v", err)
	}
	if err := evaluator.Rescale(ctQLowOdd, ctQLowOdd); err != nil {
		return nil, fmt.Errorf("rescale c3*x²: %v", err)
	}
	if err := evaluator.Add(ctQLowOdd, constPt(coeffs[1], ctQLowOdd.Level()), ctQLowOdd); err != nil {
		return nil, fmt.Errorf("c1+c3*x²: %v", err)
	}

	// q_low = q_low_even + x * q_low_odd
	// x at baby level, q_low_odd at baby level - 1
	// Need to drop x to match
	if ctX1.Level() > ctQLowOdd.Level() {
		evaluator.DropLevel(ctX1, ctX1.Level()-ctQLowOdd.Level())
	}
	ctXOdd, err := evaluator.MulRelinNew(ctX1, ctQLowOdd)
	if err != nil {
		return nil, fmt.Errorf("x*q_low_odd: %v", err)
	}
	if err := evaluator.Rescale(ctXOdd, ctXOdd); err != nil {
		return nil, fmt.Errorf("rescale x*q_low_odd: %v", err)
	}

	// Match levels for addition
	if ctQLowEven.Level() > ctXOdd.Level() {
		evaluator.DropLevel(ctQLowEven, ctQLowEven.Level()-ctXOdd.Level())
	} else if ctXOdd.Level() > ctQLowEven.Level() {
		evaluator.DropLevel(ctXOdd, ctXOdd.Level()-ctQLowEven.Level())
	}
	ctQLow, err := evaluator.AddNew(ctQLowEven, ctXOdd)
	if err != nil {
		return nil, fmt.Errorf("q_low: %v", err)
	}

	// q_high_even = c4 + c6*x²
	ctQHighEven, err := evaluator.MulNew(ctX2, constPt(coeffs[6], babyLevel))
	if err != nil {
		return nil, fmt.Errorf("c6*x²: %v", err)
	}
	if err := evaluator.Rescale(ctQHighEven, ctQHighEven); err != nil {
		return nil, fmt.Errorf("rescale c6*x²: %v", err)
	}
	if err := evaluator.Add(ctQHighEven, constPt(coeffs[4], ctQHighEven.Level()), ctQHighEven); err != nil {
		return nil, fmt.Errorf("c4+c6*x²: %v", err)
	}

	// q_high_odd = c5 + c7*x²
	ctQHighOdd, err := evaluator.MulNew(ctX2, constPt(coeffs[7], babyLevel))
	if err != nil {
		return nil, fmt.Errorf("c7*x²: %v", err)
	}
	if err := evaluator.Rescale(ctQHighOdd, ctQHighOdd); err != nil {
		return nil, fmt.Errorf("rescale c7*x²: %v", err)
	}
	if err := evaluator.Add(ctQHighOdd, constPt(coeffs[5], ctQHighOdd.Level()), ctQHighOdd); err != nil {
		return nil, fmt.Errorf("c5+c7*x²: %v", err)
	}

	// q_high = q_high_even + x * q_high_odd
	ctX1b := ctEta.CopyNew()
	if ctX1b.Level() > ctQHighOdd.Level() {
		evaluator.DropLevel(ctX1b, ctX1b.Level()-ctQHighOdd.Level())
	}
	ctXHighOdd, err := evaluator.MulRelinNew(ctX1b, ctQHighOdd)
	if err != nil {
		return nil, fmt.Errorf("x*q_high_odd: %v", err)
	}
	if err := evaluator.Rescale(ctXHighOdd, ctXHighOdd); err != nil {
		return nil, fmt.Errorf("rescale x*q_high_odd: %v", err)
	}
	if ctQHighEven.Level() > ctXHighOdd.Level() {
		evaluator.DropLevel(ctQHighEven, ctQHighEven.Level()-ctXHighOdd.Level())
	} else if ctXHighOdd.Level() > ctQHighEven.Level() {
		evaluator.DropLevel(ctXHighOdd, ctXHighOdd.Level()-ctQHighEven.Level())
	}
	ctQHigh, err := evaluator.AddNew(ctQHighEven, ctXHighOdd)
	if err != nil {
		return nil, fmt.Errorf("q_high: %v", err)
	}

	// result = q_low + x⁴ * q_high
	if ctX4.Level() > ctQHigh.Level() {
		evaluator.DropLevel(ctX4, ctX4.Level()-ctQHigh.Level())
	} else if ctQHigh.Level() > ctX4.Level() {
		evaluator.DropLevel(ctQHigh, ctQHigh.Level()-ctX4.Level())
	}
	ctX4QH, err := evaluator.MulRelinNew(ctX4, ctQHigh)
	if err != nil {
		return nil, fmt.Errorf("x⁴*q_high: %v", err)
	}
	if err := evaluator.Rescale(ctX4QH, ctX4QH); err != nil {
		return nil, fmt.Errorf("rescale x⁴*q_high: %v", err)
	}

	if ctQLow.Level() > ctX4QH.Level() {
		evaluator.DropLevel(ctQLow, ctQLow.Level()-ctX4QH.Level())
	} else if ctX4QH.Level() > ctQLow.Level() {
		evaluator.DropLevel(ctX4QH, ctX4QH.Level()-ctQLow.Level())
	}
	ctMu, err := evaluator.AddNew(ctQLow, ctX4QH)
	if err != nil {
		return nil, fmt.Errorf("q_low + x⁴*q_high: %v", err)
	}

	polyLevel := ctMu.Level()

	// ========== Step 4: Decrypt mu for verification ==========
	ptMuDec := decryptor.DecryptNew(ctMu)
	muDecoded := make([]float64, nSlots)
	encoder.Decode(ptMuDec, muDecoded)

	// ========== Step 5: Compute gradient X^T * (y - mu) ==========
	// Encrypt y
	ptY := ckks.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(input.Y, ptY); err != nil {
		return nil, fmt.Errorf("failed to encode y: %v", err)
	}
	ctY, err := encryptor.EncryptNew(ptY)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt y: %v", err)
	}

	// Drop ctY to match ctMu level
	if ctY.Level() > ctMu.Level() {
		evaluator.DropLevel(ctY, ctY.Level()-ctMu.Level())
	}

	// Enc(y - mu)
	ctResidual, err := evaluator.SubNew(ctY, ctMu)
	if err != nil {
		return nil, fmt.Errorf("y - mu: %v", err)
	}

	// For each feature column: grad_j = InnerSum(x_j * (y - mu))
	pK := len(input.XCols)
	gradient := make([]float64, pK)

	for j := 0; j < pK; j++ {
		ptXj := ckks.NewPlaintext(params, ctResidual.Level())
		if err := encoder.Encode(input.XCols[j], ptXj); err != nil {
			return nil, fmt.Errorf("encode x_col %d: %v", j, err)
		}

		ctJ, err := evaluator.MulNew(ctResidual, ptXj)
		if err != nil {
			return nil, fmt.Errorf("x_j * residual %d: %v", j, err)
		}
		if err := evaluator.Rescale(ctJ, ctJ); err != nil {
			return nil, fmt.Errorf("rescale gradient %d: %v", j, err)
		}

		ctSum := rlwe.NewCiphertext(params, ctJ.Degree(), ctJ.Level())
		if err := evaluator.InnerSum(ctJ, 1, n, ctSum); err != nil {
			return nil, fmt.Errorf("InnerSum %d: %v", j, err)
		}

		// Decrypt gradient component
		ptGrad := decryptor.DecryptNew(ctSum)
		gradDecoded := make([]float64, nSlots)
		encoder.Decode(ptGrad, gradDecoded)
		gradient[j] = gradDecoded[0] // slot 0 has the InnerSum result
	}

	// ========== Step 6: Compute exact values for comparison ==========
	muExact := make([]float64, n)
	for i := 0; i < n; i++ {
		if input.Family == "poisson" {
			muExact[i] = math.Exp(math.Min(input.Eta[i], 20))
		} else {
			muExact[i] = 1.0 / (1.0 + math.Exp(-input.Eta[i]))
		}
	}

	// Exact gradient
	gradExact := make([]float64, pK)
	for j := 0; j < pK; j++ {
		for i := 0; i < n; i++ {
			gradExact[j] += input.XCols[j][i] * (input.Y[i] - muExact[i])
		}
	}

	// Errors
	muError := 0.0
	for i := 0; i < n; i++ {
		e := math.Abs(muDecoded[i] - muExact[i])
		if e > muError {
			muError = e
		}
	}

	gradError := 0.0
	for j := 0; j < pK; j++ {
		e := math.Abs(gradient[j] - gradExact[j])
		if e > gradError {
			gradError = e
		}
	}

	// Also compute gradient with polynomial mu (not exact sigmoid) for fair comparison
	_ = base64.StdEncoding // suppress import warning if needed

	return &CKKSLocalTestOutput{
		Gradient:    gradient,
		MuPlaintext: muDecoded[:n],
		MuExact:     muExact,
		MuError:     muError,
		GradError:   gradError,
		LevelsUsed:  startLevel - polyLevel,
	}, nil
}
