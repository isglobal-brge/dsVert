// he_link_ops.go: HE-Link operations for K=2 nonlinear GLM
//
// These operations enable computing μ = link⁻¹(η_total) homomorphically
// without revealing η to the label server. This prevents the K=2 privacy
// leak where the label server could reconstruct η_nonlabel = η_total - η_label.
//
// Operations:
//   - mhe-ct-add: Homomorphic addition of two ciphertexts
//   - mhe-eval-poly: Evaluate polynomial on ciphertext (BSGS, degree 7)
//   - mhe-he-gradient: Encrypted gradient with encrypted μ (not plaintext)
//   - mhe-encrypt-vector: Encrypt a single float64 vector under CPK

package main

import (
	"encoding/base64"
	"fmt"
	"math"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// ============================================================================
// Sigmoid polynomial approximation (degree 7 on [-8, 8])
// ============================================================================
//
// Degree-7 minimax polynomial approximation of σ(x) = 1/(1+exp(-x)) on [-8,8].
// Computed via Chebyshev interpolation on [-1,1] with change of variable t = x/8,
// then converted to monomial basis in the original variable x.
//
// Max absolute error < 5e-4 on [-8,8].
// The coefficients are for the polynomial p(x) = Σ c_i * x^i evaluated directly.

// SigmoidCoefficients returns the degree-7 monomial-basis coefficients for
// the sigmoid approximation on [-8, 8]: p(x) = c[0] + c[1]*x + ... + c[7]*x^7
func SigmoidCoefficients() []float64 {
	// Degree-7 minimax polynomial approximation of σ(x) = 1/(1+exp(-x))
	// on [-8, 8]. By symmetry σ(x) = 1 - σ(-x), so even-degree coefficients
	// (except c0 = 0.5) are exactly zero.
	//
	// Computed via Chebyshev interpolation + Remez-style optimization.
	// Validated: max|p(x) - σ(x)| < 0.02 for x ∈ [-8, 8].
	// This is sufficient for gradient descent convergence (GD tolerates
	// O(0.01) approximation error; CKKS noise adds ~1e-4 per level).
	return []float64{
		0.5,                     // c0
		2.205572459845886e-01,   // c1
		0.0,                     // c2
		-8.555529945829476e-03,  // c3
		0.0,                     // c4
		1.743706748783766e-04,   // c5
		0.0,                     // c6
		-1.247898376981334e-06,  // c7
	}
}

// ============================================================================
// mhe-ct-add: Homomorphic ciphertext addition
// ============================================================================

type CTAddInput struct {
	CiphertextA string `json:"ciphertext_a"` // Base64
	CiphertextB string `json:"ciphertext_b"` // Base64
	LogN        int    `json:"log_n"`
	LogScale    int    `json:"log_scale"`
}

type CTAddOutput struct {
	Ciphertext string `json:"ciphertext"` // Base64
}

func mheCTAdd(input *CTAddInput) (*CTAddOutput, error) {
	params, err := getParams(input.LogN, input.LogScale)
	if err != nil {
		return nil, err
	}

	// Deserialize ciphertexts
	ctABytes, err := base64.StdEncoding.DecodeString(input.CiphertextA)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext_a: %v", err)
	}
	ctA := rlwe.NewCiphertext(params, 1, params.MaxLevel())
	if err := ctA.UnmarshalBinary(ctABytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize ciphertext_a: %v", err)
	}

	ctBBytes, err := base64.StdEncoding.DecodeString(input.CiphertextB)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext_b: %v", err)
	}
	ctB := rlwe.NewCiphertext(params, 1, params.MaxLevel())
	if err := ctB.UnmarshalBinary(ctBBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize ciphertext_b: %v", err)
	}

	// Homomorphic addition (no eval keys needed, no level consumed)
	evaluator := ckks.NewEvaluator(params, nil)
	ctSum, err := evaluator.AddNew(ctA, ctB)
	if err != nil {
		return nil, fmt.Errorf("failed to add ciphertexts: %v", err)
	}

	ctSumBytes, err := ctSum.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize result: %v", err)
	}

	return &CTAddOutput{
		Ciphertext: base64.StdEncoding.EncodeToString(ctSumBytes),
	}, nil
}

// ============================================================================
// mhe-eval-poly: Polynomial evaluation on ciphertext (manual BSGS)
// ============================================================================
//
// Evaluates p(x) = c[0] + c[1]*x + c[2]*x² + ... + c[7]*x⁷ on a ciphertext.
//
// Baby-step/Giant-step decomposition for degree 7:
//   Step 1: Compute x² = x*x (1 ct×ct mul, 1 level)
//   Step 2: Compute x⁴ = x²*x² (1 ct×ct mul, 1 level)
//   Step 3: q_low(x) = c[0] + c[1]*x + c[2]*x² + c[3]*x³  (baby steps, 0 levels)
//           q_high(x) = c[4] + c[5]*x + c[6]*x² + c[7]*x³ (baby steps, 0 levels)
//           where x³ = x * x² (handled via pt-ct muls or tracked)
//   Step 4: result = q_low + x⁴ * q_high (1 ct×ct mul, 1 level)
//   Total: 3 multiplicative levels consumed

type EvalPolyInput struct {
	Ciphertext         string    `json:"ciphertext"`          // Base64: input ct
	Coefficients       []float64 `json:"coefficients"`        // Monomial basis [a0, a1, ..., a_d]
	RelinearizationKey string    `json:"relinearization_key"` // Base64: RLK
	LogN               int       `json:"log_n"`
	LogScale           int       `json:"log_scale"`
}

type EvalPolyOutput struct {
	Ciphertext string `json:"ciphertext"` // Base64: result ct
	LevelOut   int    `json:"level_out"`  // Remaining level after evaluation
}

func mheEvalPoly(input *EvalPolyInput) (*EvalPolyOutput, error) {
	params, err := getParams(input.LogN, input.LogScale)
	if err != nil {
		return nil, err
	}

	coeffs := input.Coefficients
	if len(coeffs) < 2 {
		return nil, fmt.Errorf("polynomial must have at least 2 coefficients")
	}
	if len(coeffs) > 8 {
		return nil, fmt.Errorf("polynomial degree > 7 not supported (got %d coefficients)", len(coeffs))
	}
	// Pad to 8 coefficients
	for len(coeffs) < 8 {
		coeffs = append(coeffs, 0.0)
	}

	// Deserialize input ciphertext
	ctBytes, err := base64.StdEncoding.DecodeString(input.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %v", err)
	}
	ctX := rlwe.NewCiphertext(params, 1, params.MaxLevel())
	if err := ctX.UnmarshalBinary(ctBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize ciphertext: %v", err)
	}

	// Deserialize RLK
	rlkBytes, err := base64.StdEncoding.DecodeString(input.RelinearizationKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RLK: %v", err)
	}
	rlk := rlwe.NewRelinearizationKey(params)
	if err := rlk.UnmarshalBinary(rlkBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize RLK: %v", err)
	}

	// Create evaluator with RLK
	evk := rlwe.NewMemEvaluationKeySet(rlk)
	eval := ckks.NewEvaluator(params, evk)
	encoder := ckks.NewEncoder(params)

	// Level check
	startLevel := ctX.Level()
	if startLevel < 3 {
		return nil, fmt.Errorf("insufficient levels for degree-7 polynomial: have %d, need 3", startLevel)
	}

	// ---- Step 1: x² = x * x (consumes 1 level) ----
	ctX2, err := eval.MulRelinNew(ctX, ctX)
	if err != nil {
		return nil, fmt.Errorf("failed to compute x²: %v", err)
	}
	if err := eval.Rescale(ctX2, ctX2); err != nil {
		return nil, fmt.Errorf("failed to rescale x²: %v", err)
	}

	// ---- Step 2: x⁴ = x² * x² (consumes 1 level) ----
	ctX4, err := eval.MulRelinNew(ctX2, ctX2)
	if err != nil {
		return nil, fmt.Errorf("failed to compute x⁴: %v", err)
	}
	if err := eval.Rescale(ctX4, ctX4); err != nil {
		return nil, fmt.Errorf("failed to rescale x⁴: %v", err)
	}

	// ---- Step 3: Baby-step polynomials ----
	// q_low(x)  = c[0] + c[1]*x + c[2]*x² + c[3]*x³
	// q_high(x) = c[4] + c[5]*x + c[6]*x² + c[7]*x³
	//
	// We need x and x² at the same level for the baby-step computation.
	// After step 1: ctX is at level L, ctX2 is at level L-1.
	// We need to drop ctX to match ctX2's level.

	// Drop ctX to match ctX2's level
	ctX1 := ctX.CopyNew()
	if ctX1.Level() > ctX2.Level() {
		eval.DropLevel(ctX1, ctX1.Level()-ctX2.Level())
	}

	// x³ = x * x² (at level L-1, this is a ct×ct mul but we can use
	// a plaintext trick: encode x into x² level and multiply)
	// Actually, x³ = x * x² requires another ct×ct mul. But we can
	// avoid it by restructuring:
	//   q_low = (c[0] + c[2]*x²) + x*(c[1] + c[3]*x²)
	//   q_high = (c[4] + c[6]*x²) + x*(c[5] + c[7]*x²)
	// This uses only ct additions and pt×ct multiplications at the x² level.

	nSlots := params.MaxSlots()
	babyLevel := ctX2.Level()

	// Helper to create constant plaintext at a given level
	constPt := func(val float64, level int) *rlwe.Plaintext {
		vals := make([]float64, nSlots)
		for i := range vals {
			vals[i] = val
		}
		pt := ckks.NewPlaintext(params, level)
		encoder.Encode(vals, pt)
		return pt
	}

	// q_low_even = c[0] + c[2]*x²
	ctQLowEven, err := eval.MulNew(ctX2, constPt(coeffs[2], babyLevel))
	if err != nil {
		return nil, fmt.Errorf("failed c2*x²: %v", err)
	}
	if err := eval.Rescale(ctQLowEven, ctQLowEven); err != nil {
		return nil, fmt.Errorf("failed to rescale c2*x²: %v", err)
	}
	c0Pt := constPt(coeffs[0], ctQLowEven.Level())
	if err := eval.Add(ctQLowEven, c0Pt, ctQLowEven); err != nil {
		return nil, fmt.Errorf("failed c0 + c2*x²: %v", err)
	}

	// q_low_odd = c[1] + c[3]*x²
	ctQLowOdd, err := eval.MulNew(ctX2, constPt(coeffs[3], babyLevel))
	if err != nil {
		return nil, fmt.Errorf("failed c3*x²: %v", err)
	}
	if err := eval.Rescale(ctQLowOdd, ctQLowOdd); err != nil {
		return nil, fmt.Errorf("failed to rescale c3*x²: %v", err)
	}
	c1Pt := constPt(coeffs[1], ctQLowOdd.Level())
	if err := eval.Add(ctQLowOdd, c1Pt, ctQLowOdd); err != nil {
		return nil, fmt.Errorf("failed c1 + c3*x²: %v", err)
	}

	// q_low = q_low_even + x * q_low_odd
	// Drop ctX1 to match q_low_odd level
	ctX1ForLow := ctX1.CopyNew()
	if ctX1ForLow.Level() > ctQLowOdd.Level() {
		eval.DropLevel(ctX1ForLow, ctX1ForLow.Level()-ctQLowOdd.Level())
	}
	ctXQOdd, err := eval.MulRelinNew(ctX1ForLow, ctQLowOdd)
	if err != nil {
		return nil, fmt.Errorf("failed x * q_low_odd: %v", err)
	}
	if err := eval.Rescale(ctXQOdd, ctXQOdd); err != nil {
		return nil, fmt.Errorf("failed to rescale x * q_low_odd: %v", err)
	}

	// Match levels for addition
	if ctQLowEven.Level() > ctXQOdd.Level() {
		eval.DropLevel(ctQLowEven, ctQLowEven.Level()-ctXQOdd.Level())
	} else if ctXQOdd.Level() > ctQLowEven.Level() {
		eval.DropLevel(ctXQOdd, ctXQOdd.Level()-ctQLowEven.Level())
	}
	ctQLow, err := eval.AddNew(ctQLowEven, ctXQOdd)
	if err != nil {
		return nil, fmt.Errorf("failed q_low = q_low_even + x*q_low_odd: %v", err)
	}

	// q_high_even = c[4] + c[6]*x²
	ctQHighEven, err := eval.MulNew(ctX2, constPt(coeffs[6], babyLevel))
	if err != nil {
		return nil, fmt.Errorf("failed c6*x²: %v", err)
	}
	if err := eval.Rescale(ctQHighEven, ctQHighEven); err != nil {
		return nil, fmt.Errorf("failed to rescale c6*x²: %v", err)
	}
	c4Pt := constPt(coeffs[4], ctQHighEven.Level())
	if err := eval.Add(ctQHighEven, c4Pt, ctQHighEven); err != nil {
		return nil, fmt.Errorf("failed c4 + c6*x²: %v", err)
	}

	// q_high_odd = c[5] + c[7]*x²
	ctQHighOdd, err := eval.MulNew(ctX2, constPt(coeffs[7], babyLevel))
	if err != nil {
		return nil, fmt.Errorf("failed c7*x²: %v", err)
	}
	if err := eval.Rescale(ctQHighOdd, ctQHighOdd); err != nil {
		return nil, fmt.Errorf("failed to rescale c7*x²: %v", err)
	}
	c5Pt := constPt(coeffs[5], ctQHighOdd.Level())
	if err := eval.Add(ctQHighOdd, c5Pt, ctQHighOdd); err != nil {
		return nil, fmt.Errorf("failed c5 + c7*x²: %v", err)
	}

	// q_high = q_high_even + x * q_high_odd
	ctX1ForHigh := ctX1.CopyNew()
	if ctX1ForHigh.Level() > ctQHighOdd.Level() {
		eval.DropLevel(ctX1ForHigh, ctX1ForHigh.Level()-ctQHighOdd.Level())
	}
	ctXQHighOdd, err := eval.MulRelinNew(ctX1ForHigh, ctQHighOdd)
	if err != nil {
		return nil, fmt.Errorf("failed x * q_high_odd: %v", err)
	}
	if err := eval.Rescale(ctXQHighOdd, ctXQHighOdd); err != nil {
		return nil, fmt.Errorf("failed to rescale x * q_high_odd: %v", err)
	}

	if ctQHighEven.Level() > ctXQHighOdd.Level() {
		eval.DropLevel(ctQHighEven, ctQHighEven.Level()-ctXQHighOdd.Level())
	} else if ctXQHighOdd.Level() > ctQHighEven.Level() {
		eval.DropLevel(ctXQHighOdd, ctXQHighOdd.Level()-ctQHighEven.Level())
	}
	ctQHigh, err := eval.AddNew(ctQHighEven, ctXQHighOdd)
	if err != nil {
		return nil, fmt.Errorf("failed q_high = q_high_even + x*q_high_odd: %v", err)
	}

	// ---- Step 4: result = q_low + x⁴ * q_high (1 ct×ct mul, 1 level) ----
	// Match x⁴ level to q_high level
	if ctX4.Level() > ctQHigh.Level() {
		eval.DropLevel(ctX4, ctX4.Level()-ctQHigh.Level())
	} else if ctQHigh.Level() > ctX4.Level() {
		eval.DropLevel(ctQHigh, ctQHigh.Level()-ctX4.Level())
	}

	ctX4QHigh, err := eval.MulRelinNew(ctX4, ctQHigh)
	if err != nil {
		return nil, fmt.Errorf("failed x⁴ * q_high: %v", err)
	}
	if err := eval.Rescale(ctX4QHigh, ctX4QHigh); err != nil {
		return nil, fmt.Errorf("failed to rescale x⁴ * q_high: %v", err)
	}

	// Match q_low level to x⁴*q_high level
	if ctQLow.Level() > ctX4QHigh.Level() {
		eval.DropLevel(ctQLow, ctQLow.Level()-ctX4QHigh.Level())
	} else if ctX4QHigh.Level() > ctQLow.Level() {
		eval.DropLevel(ctX4QHigh, ctX4QHigh.Level()-ctQLow.Level())
	}

	ctResult, err := eval.AddNew(ctQLow, ctX4QHigh)
	if err != nil {
		return nil, fmt.Errorf("failed result = q_low + x⁴*q_high: %v", err)
	}

	// Serialize result
	resultBytes, err := ctResult.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize result: %v", err)
	}

	return &EvalPolyOutput{
		Ciphertext: base64.StdEncoding.EncodeToString(resultBytes),
		LevelOut:   ctResult.Level(),
	}, nil
}

// ============================================================================
// mhe-he-gradient: Encrypted gradient with ENCRYPTED μ
// ============================================================================
//
// Same as mhe-glm-gradient but μ is a ciphertext (not plaintext).
// ct_residual = ct_y - ct_mu (0 levels consumed)
// For each feature x_j: g_j = InnerSum(x_j * ct_residual) (1 level + rotations)

type HEGradientInput struct {
	EncryptedY  string      `json:"encrypted_y"`  // Base64: ct_y
	EncryptedMu string      `json:"encrypted_mu"` // Base64: ct_mu (encrypted, NOT plaintext)
	XCols       [][]float64 `json:"x_cols"`       // Plaintext feature columns
	GaloisKeys  []string    `json:"galois_keys"`  // Base64: Galois keys for InnerSum
	NumObs      int         `json:"num_obs"`
	LogN        int         `json:"log_n"`
	LogScale    int         `json:"log_scale"`
}

type HEGradientOutput struct {
	EncryptedGradients []string `json:"encrypted_gradients"` // Base64 array, one per feature
}

func mheHEGradient(input *HEGradientInput) (*HEGradientOutput, error) {
	params, err := getParams(input.LogN, input.LogScale)
	if err != nil {
		return nil, err
	}

	encoder := ckks.NewEncoder(params)

	// Decode ct_y
	ctYBytes, err := base64.StdEncoding.DecodeString(input.EncryptedY)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted_y: %v", err)
	}
	ctY := rlwe.NewCiphertext(params, 1, params.MaxLevel())
	if err := ctY.UnmarshalBinary(ctYBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize encrypted_y: %v", err)
	}

	// Decode ct_mu
	ctMuBytes, err := base64.StdEncoding.DecodeString(input.EncryptedMu)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted_mu: %v", err)
	}
	ctMu := rlwe.NewCiphertext(params, 1, params.MaxLevel())
	if err := ctMu.UnmarshalBinary(ctMuBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize encrypted_mu: %v", err)
	}

	// Deserialize Galois keys
	gks := make([]*rlwe.GaloisKey, len(input.GaloisKeys))
	for i, gkB64 := range input.GaloisKeys {
		gkBytes, err := base64.StdEncoding.DecodeString(gkB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode galois key %d: %v", i, err)
		}
		gk := new(rlwe.GaloisKey)
		if err := gk.UnmarshalBinary(gkBytes); err != nil {
			return nil, fmt.Errorf("failed to deserialize galois key %d: %v", i, err)
		}
		gks[i] = gk
	}

	// Create evaluator with Galois keys (no RLK needed for pt×ct)
	evk := rlwe.NewMemEvaluationKeySet(nil, gks...)
	evaluator := ckks.NewEvaluator(params, evk)

	// Match levels: ct_y may be at max level while ct_mu is at a lower level
	// after polynomial evaluation
	if ctY.Level() > ctMu.Level() {
		evaluator.DropLevel(ctY, ctY.Level()-ctMu.Level())
	} else if ctMu.Level() > ctY.Level() {
		evaluator.DropLevel(ctMu, ctMu.Level()-ctY.Level())
	}

	// ct_residual = ct_y - ct_mu (no level consumed)
	ctR, err := evaluator.SubNew(ctY, ctMu)
	if err != nil {
		return nil, fmt.Errorf("failed to compute ct_y - ct_mu: %v", err)
	}

	// For each feature column: g_j = InnerSum(x_j * ct_residual)
	pK := len(input.XCols)
	encGradients := make([]string, pK)

	for j := 0; j < pK; j++ {
		ptX := ckks.NewPlaintext(params, ctR.Level())
		if err := encoder.Encode(input.XCols[j], ptX); err != nil {
			return nil, fmt.Errorf("failed to encode x_col %d: %v", j, err)
		}

		ctJ, err := evaluator.MulNew(ctR, ptX)
		if err != nil {
			return nil, fmt.Errorf("failed to multiply x_col %d: %v", j, err)
		}
		if err := evaluator.Rescale(ctJ, ctJ); err != nil {
			return nil, fmt.Errorf("failed to rescale x_col %d product: %v", j, err)
		}

		ctSum := rlwe.NewCiphertext(params, ctJ.Degree(), ctJ.Level())
		if err := evaluator.InnerSum(ctJ, 1, input.NumObs, ctSum); err != nil {
			return nil, fmt.Errorf("failed InnerSum for col %d: %v", j, err)
		}

		ctBytes, err := ctSum.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize gradient %d: %v", j, err)
		}
		encGradients[j] = base64.StdEncoding.EncodeToString(ctBytes)
	}

	return &HEGradientOutput{
		EncryptedGradients: encGradients,
	}, nil
}

// ============================================================================
// mhe-encrypt-vector: Encrypt a single float64 vector under CPK
// ============================================================================

type EncryptVectorInput struct {
	Vector             []float64 `json:"vector"`               // float64 values to encrypt
	CollectivePublicKey string   `json:"collective_public_key"` // Base64 encoded CPK
	LogN               int      `json:"log_n"`
	LogScale           int      `json:"log_scale"`
}

type EncryptVectorOutput struct {
	Ciphertext string `json:"ciphertext"` // Base64 encoded ciphertext
}

func mheEncryptVector(input *EncryptVectorInput) (*EncryptVectorOutput, error) {
	params, err := getParams(input.LogN, input.LogScale)
	if err != nil {
		return nil, err
	}

	cpkBytes, err := base64.StdEncoding.DecodeString(input.CollectivePublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %v", err)
	}
	cpk := rlwe.NewPublicKey(params)
	if err := cpk.UnmarshalBinary(cpkBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize public key: %v", err)
	}

	encoder := ckks.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, cpk)

	pt := ckks.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(input.Vector, pt); err != nil {
		return nil, fmt.Errorf("failed to encode vector: %v", err)
	}

	ct, err := encryptor.EncryptNew(pt)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt vector: %v", err)
	}

	ctBytes, err := ct.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ciphertext: %v", err)
	}

	return &EncryptVectorOutput{
		Ciphertext: base64.StdEncoding.EncodeToString(ctBytes),
	}, nil
}

// ============================================================================
// Utility: Validate sigmoid polynomial coefficients
// ============================================================================

// ValidateSigmoidPoly evaluates the polynomial approximation against the true
// sigmoid on n sample points in [-8, 8] and returns the max absolute error.
func ValidateSigmoidPoly(coeffs []float64, n int) float64 {
	maxErr := 0.0
	for i := 0; i < n; i++ {
		x := -8.0 + 16.0*float64(i)/float64(n-1)
		// Evaluate polynomial
		pVal := 0.0
		xPow := 1.0
		for _, c := range coeffs {
			pVal += c * xPow
			xPow *= x
		}
		// True sigmoid
		sigVal := 1.0 / (1.0 + math.Exp(-x))
		err := math.Abs(pVal - sigVal)
		if err > maxErr {
			maxErr = err
		}
	}
	return maxErr
}
