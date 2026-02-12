// glm_ops.go: Encrypted GLM gradient computation
//
// Computes the gradient g_k = X_k^T u where u = v ⊙ (y - μ) using
// homomorphic encryption. The response y is encrypted under the
// collective public key; μ and v are plaintext (known to this server).
//
// For canonical links (Gaussian, Binomial+logit, Poisson+log), v = 1
// and the computation simplifies to g_k[j] = Σ_i x_kij * (y_i - μ_i).
//
// Security: Only the p_k-length gradient vector is revealed after
// threshold decryption. Individual observations x_kij * u_i never leave
// the encrypted domain (InnerSum aggregates them inside encryption).

package main

import (
	"encoding/base64"
	"fmt"
	"math"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// GLMGradientInput: compute encrypted gradient g_k = X_k^T (v ⊙ (ct_y - μ))
type GLMGradientInput struct {
	EncryptedY string      `json:"encrypted_y"`  // Base64: ct_y (encrypted under CPK)
	Mu         []float64   `json:"mu"`           // Plaintext μ = g^{-1}(η_total), length n
	V          []float64   `json:"v"`            // Plaintext v vector, length n (nil or all-1 for canonical links)
	XCols      [][]float64 `json:"x_cols"`       // Plaintext X_k columns: x_cols[j][i] = x_kij
	GaloisKeys []string    `json:"galois_keys"`  // Base64 Galois keys for InnerSum rotations
	NumObs     int         `json:"num_obs"`      // Number of observations n
	LogN       int         `json:"log_n"`
	LogScale   int         `json:"log_scale"`
}

// GLMGradientOutput: one encrypted ciphertext per feature column.
// After threshold decryption, slot 0 of each contains g_k[j] = Σ_i x_kij * u_i.
type GLMGradientOutput struct {
	EncryptedGradients []string `json:"encrypted_gradients"` // Base64 array, length p_k
}

func mheGLMGradient(input *GLMGradientInput) (*GLMGradientOutput, error) {
	params, err := getParams(input.LogN, input.LogScale)
	if err != nil {
		return nil, err
	}

	encoder := ckks.NewEncoder(params)

	// Decode encrypted y
	ctYBytes, err := base64.StdEncoding.DecodeString(input.EncryptedY)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted_y: %v", err)
	}
	ctY := rlwe.NewCiphertext(params, 1, params.MaxLevel())
	if err := ctY.UnmarshalBinary(ctYBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize encrypted_y: %v", err)
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

	// Create evaluator with Galois keys (no relinearization key needed)
	evk := rlwe.NewMemEvaluationKeySet(nil, gks...)
	evaluator := ckks.NewEvaluator(params, evk)

	// Step 1: ct_r = ct_y - encode(μ)
	// Subtraction doesn't consume a level
	ptMu := ckks.NewPlaintext(params, ctY.Level())
	if err := encoder.Encode(input.Mu, ptMu); err != nil {
		return nil, fmt.Errorf("failed to encode mu: %v", err)
	}

	ctR, err := evaluator.SubNew(ctY, ptMu)
	if err != nil {
		return nil, fmt.Errorf("failed to compute ct_y - mu: %v", err)
	}

	// Step 2: ct_u = encode(v) * ct_r (skip if v is all ones → canonical link)
	// Multiplication consumes one level after rescale
	ctU := ctR
	if input.V != nil && len(input.V) > 0 && !allOnes(input.V) {
		ptV := ckks.NewPlaintext(params, ctR.Level())
		if err := encoder.Encode(input.V, ptV); err != nil {
			return nil, fmt.Errorf("failed to encode v: %v", err)
		}
		ctU, err = evaluator.MulNew(ctR, ptV)
		if err != nil {
			return nil, fmt.Errorf("failed to compute v * (ct_y - mu): %v", err)
		}
		if err := evaluator.Rescale(ctU, ctU); err != nil {
			return nil, fmt.Errorf("failed to rescale ct_u: %v", err)
		}
	}

	// Step 3: For each feature column x_j, compute g_k[j] via InnerSum
	pK := len(input.XCols)
	encGradients := make([]string, pK)

	for j := 0; j < pK; j++ {
		// ct_j = encode(x_j) * ct_u  (element-wise: x_kij * u_i in each slot)
		ptX := ckks.NewPlaintext(params, ctU.Level())
		if err := encoder.Encode(input.XCols[j], ptX); err != nil {
			return nil, fmt.Errorf("failed to encode x_col %d: %v", j, err)
		}

		ctJ, err := evaluator.MulNew(ctU, ptX)
		if err != nil {
			return nil, fmt.Errorf("failed to multiply x_col %d: %v", j, err)
		}
		if err := evaluator.Rescale(ctJ, ctJ); err != nil {
			return nil, fmt.Errorf("failed to rescale x_col %d product: %v", j, err)
		}

		// InnerSum: sum n slots → slot 0 = Σ_i (x_kij * u_i) = g_k[j]
		// Uses Galois keys for log2(n) rotations; no level consumed
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

	return &GLMGradientOutput{
		EncryptedGradients: encGradients,
	}, nil
}

// allOnes returns true if all elements of v are 1.0 (within floating-point tolerance).
func allOnes(v []float64) bool {
	for _, x := range v {
		if math.Abs(x-1.0) > 1e-10 {
			return false
		}
	}
	return true
}
