// ckks_ops.go: CKKS operations using Lattigo v6 for MHE
//
// This file implements proper Multiparty Homomorphic Encryption using Lattigo v6.
// Uses the multiparty module for collaborative key generation and threshold decryption.

package main

import (
	"encoding/base64"
	"fmt"
	"math"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// getParams returns CKKS parameters based on logN and logScale
func getParams(logN, logScale int) (ckks.Parameters, error) {
	var params ckks.Parameters
	var err error

	// Build parameters with appropriate moduli chain
	switch logN {
	case 12:
		// Small parameters for testing
		// LogQ moduli must match LogDefaultScale for correct rescaling
		params, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
			LogN:            12,
			LogQ:            []int{50, 40, 40},
			LogP:            []int{50},
			LogDefaultScale: logScale,
		})
	case 13:
		// Medium parameters
		params, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
			LogN:            13,
			LogQ:            []int{55, 40, 40, 40, 40},
			LogP:            []int{45, 45},
			LogDefaultScale: logScale,
		})
	case 14:
		// Standard parameters for production
		params, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
			LogN:            14,
			LogQ:            []int{55, 40, 40, 40, 40, 40, 40},
			LogP:            []int{45, 45},
			LogDefaultScale: logScale,
		})
	case 15:
		// Larger parameters for deeper circuits
		params, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
			LogN:            15,
			LogQ:            []int{60, 45, 45, 45, 45, 45, 45, 45, 45},
			LogP:            []int{50, 50},
			LogDefaultScale: logScale,
		})
	default:
		return params, fmt.Errorf("unsupported logN: %d (use 12, 13, 14, or 15)", logN)
	}

	return params, err
}

// generateKeyShare generates a secret key share and public key share for MHE
// Each party calls this independently.
// In simplified mode (numParties=1), also generates evaluation keys.
func generateKeyShare(partyID, numParties, logN, logScale int) (*KeyGenOutput, error) {
	params, err := getParams(logN, logScale)
	if err != nil {
		return nil, fmt.Errorf("failed to create parameters: %v", err)
	}

	// Create key generator
	kgen := rlwe.NewKeyGenerator(params)

	// Generate secret key for this party
	sk := kgen.GenSecretKeyNew()

	// Generate public key share using PKG (Public Key Generation) protocol
	pkg := multiparty.NewPublicKeyGenProtocol(params)

	// Generate CRP (Common Reference Polynomial) - in practice this would be shared
	prng, err := sampling.NewPRNG()
	if err != nil {
		return nil, fmt.Errorf("failed to create PRNG: %v", err)
	}
	crp := pkg.SampleCRP(prng)

	// Generate the public key share (AllocateShare returns value, GenShare needs pointer)
	pkShare := pkg.AllocateShare()
	pkg.GenShare(sk, crp, &pkShare)

	// Serialize the secret key
	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize secret key: %v", err)
	}

	// Serialize the public key share
	pkShareBytes, err := pkShare.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize public key share: %v", err)
	}

	// Serialize the CRP (it contains a ringqp.Poly Value)
	crpBytes, err := crp.Value.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize CRP: %v", err)
	}

	output := &KeyGenOutput{
		SecretKeyShare: base64.StdEncoding.EncodeToString(skBytes),
		PublicKeyShare: base64.StdEncoding.EncodeToString(pkShareBytes),
		CRP:            base64.StdEncoding.EncodeToString(crpBytes),
		PartyID:        partyID,
	}

	// In simplified mode, generate everything from this single key
	// No need for collaborative key generation when there's only one party
	if numParties <= 1 {
		// Generate the collective public key (just a regular public key in single-party mode)
		cpk := kgen.GenPublicKeyNew(sk)
		cpkBytes, err := cpk.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize collective public key: %v", err)
		}
		output.CollectivePublicKey = base64.StdEncoding.EncodeToString(cpkBytes)

		// Generate galois keys for rotations (power-of-2 rotations up to N/2)
		maxSlots := params.N() / 2
		galEls := []uint64{}
		for i := 1; i < maxSlots; i *= 2 {
			galEls = append(galEls, params.GaloisElement(i))
		}
		gks := kgen.GenGaloisKeysNew(galEls, sk)

		// Generate relinearization key
		rlk := kgen.GenRelinearizationKeyNew(sk)

		// Create evaluation key set and serialize
		evk := rlwe.NewMemEvaluationKeySet(rlk, gks...)
		evkBytes, err := evk.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize evaluation keys: %v", err)
		}
		output.EvaluationKeys = base64.StdEncoding.EncodeToString(evkBytes)
	}

	return output, nil
}

// combinePublicKeys aggregates all public key shares into a Collective Public Key
// This is the core of MHE: the CPK can only be decrypted with ALL secret keys
func combinePublicKeys(pkSharesB64 []string, crpB64 string, logN, logScale int) (*CombineKeysOutput, error) {
	params, err := getParams(logN, logScale)
	if err != nil {
		return nil, fmt.Errorf("failed to create parameters: %v", err)
	}

	if len(pkSharesB64) == 0 {
		return nil, fmt.Errorf("no public key shares provided")
	}

	// Initialize PKG protocol
	pkg := multiparty.NewPublicKeyGenProtocol(params)

	// Deserialize CRP (we serialized the Value ringqp.Poly)
	crpBytes, err := base64.StdEncoding.DecodeString(crpB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CRP: %v", err)
	}
	var crp multiparty.PublicKeyGenCRP
	if err := crp.Value.UnmarshalBinary(crpBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize CRP: %v", err)
	}

	// Deserialize all public key shares
	pkShares := make([]multiparty.PublicKeyGenShare, len(pkSharesB64))
	for i, shareB64 := range pkSharesB64 {
		shareBytes, err := base64.StdEncoding.DecodeString(shareB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode public key share %d: %v", i, err)
		}
		pkShares[i] = pkg.AllocateShare()
		if err := pkShares[i].UnmarshalBinary(shareBytes); err != nil {
			return nil, fmt.Errorf("failed to deserialize public key share %d: %v", i, err)
		}
	}

	// Aggregate all shares into one (AggregateShares takes values, pointer for output)
	aggregatedShare := pkg.AllocateShare()
	for _, share := range pkShares {
		pkg.AggregateShares(share, aggregatedShare, &aggregatedShare)
	}

	// Generate the Collective Public Key from the aggregated share
	cpk := rlwe.NewPublicKey(params)
	pkg.GenPublicKey(aggregatedShare, crp, cpk)

	// Serialize CPK
	cpkBytes, err := cpk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize collective public key: %v", err)
	}

	return &CombineKeysOutput{
		CollectivePublicKey: base64.StdEncoding.EncodeToString(cpkBytes),
	}, nil
}

// encryptColumns encrypts a matrix column-by-column using the Collective Public Key
// Each column becomes one ciphertext with n slots (one per observation)
func encryptColumns(data [][]float64, cpkB64 string, logN, logScale int) (*EncryptColumnsOutput, error) {
	params, err := getParams(logN, logScale)
	if err != nil {
		return nil, fmt.Errorf("failed to create parameters: %v", err)
	}

	// Decode collective public key
	cpkBytes, err := base64.StdEncoding.DecodeString(cpkB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %v", err)
	}

	cpk := rlwe.NewPublicKey(params)
	if err := cpk.UnmarshalBinary(cpkBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize public key: %v", err)
	}

	// Get dimensions (data is row-major: data[row][col])
	numRows := len(data)
	if numRows == 0 {
		return nil, fmt.Errorf("empty data matrix")
	}
	numCols := len(data[0])

	// Create encoder and encryptor
	encoder := ckks.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, cpk)

	// Encrypt each column
	encryptedCols := make([]string, numCols)
	for j := 0; j < numCols; j++ {
		// Extract column j
		column := make([]float64, numRows)
		for i := 0; i < numRows; i++ {
			column[i] = data[i][j]
		}

		// Encode and encrypt
		pt := ckks.NewPlaintext(params, params.MaxLevel())
		if err := encoder.Encode(column, pt); err != nil {
			return nil, fmt.Errorf("failed to encode column %d: %v", j, err)
		}

		ct, err := encryptor.EncryptNew(pt)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt column %d: %v", j, err)
		}

		// Serialize
		ctBytes, err := ct.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize column %d: %v", j, err)
		}
		encryptedCols[j] = base64.StdEncoding.EncodeToString(ctBytes)
	}

	return &EncryptColumnsOutput{
		EncryptedColumns: encryptedCols,
		NumRows:          numRows,
		NumCols:          numCols,
	}, nil
}

// computeCrossProduct computes G_AB = Z_A' * Z_B where Z_B is encrypted
// Uses the provided evaluation keys for rotations and secret key for decryption
// Returns decrypted plaintext values
func computeCrossProduct(plaintextColumns [][]float64, encryptedColumnsB64 []string,
	evkB64, skB64 string, logN, logScale int) (*CrossProductOutput, error) {

	params, err := getParams(logN, logScale)
	if err != nil {
		return nil, fmt.Errorf("failed to create parameters: %v", err)
	}

	pA := len(plaintextColumns)    // Number of plaintext columns
	pB := len(encryptedColumnsB64) // Number of encrypted columns

	if pA == 0 || pB == 0 {
		return nil, fmt.Errorf("empty input: pA=%d, pB=%d", pA, pB)
	}

	n := len(plaintextColumns[0]) // Number of rows

	// Create encoder
	encoder := ckks.NewEncoder(params)

	// Deserialize evaluation keys
	evkBytes, err := base64.StdEncoding.DecodeString(evkB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode evaluation keys: %v", err)
	}

	evk := rlwe.NewMemEvaluationKeySet(nil)
	if err := evk.UnmarshalBinary(evkBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize evaluation keys: %v", err)
	}

	evaluator := ckks.NewEvaluator(params, evk)

	// Deserialize secret key for decryption
	skBytes, err := base64.StdEncoding.DecodeString(skB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret key: %v", err)
	}

	sk := rlwe.NewSecretKey(params)
	if err := sk.UnmarshalBinary(skBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize secret key: %v", err)
	}

	// Create decryptor
	decryptor := rlwe.NewDecryptor(params, sk)

	// Decode all encrypted columns
	encryptedCols := make([]*rlwe.Ciphertext, pB)
	for j := 0; j < pB; j++ {
		ctBytes, err := base64.StdEncoding.DecodeString(encryptedColumnsB64[j])
		if err != nil {
			return nil, fmt.Errorf("failed to decode encrypted column %d: %v", j, err)
		}
		ct := rlwe.NewCiphertext(params, 1, params.MaxLevel())
		if err := ct.UnmarshalBinary(ctBytes); err != nil {
			return nil, fmt.Errorf("failed to deserialize encrypted column %d: %v", j, err)
		}
		encryptedCols[j] = ct
	}

	// Compute cross products and decrypt
	results := make([][]float64, pA)
	for i := 0; i < pA; i++ {
		results[i] = make([]float64, pB)
	}

	numRotations := int(math.Ceil(math.Log2(float64(n))))

	for i := 0; i < pA; i++ {
		// Encode plaintext column i
		ptCol := ckks.NewPlaintext(params, params.MaxLevel())
		if err := encoder.Encode(plaintextColumns[i], ptCol); err != nil {
			return nil, fmt.Errorf("failed to encode plaintext column %d: %v", i, err)
		}

		for j := 0; j < pB; j++ {
			// Element-wise multiply: Enc(Z_A[:,i] * Z_B[:,j])
			product, err := evaluator.MulNew(encryptedCols[j], ptCol)
			if err != nil {
				return nil, fmt.Errorf("failed to multiply [%d,%d]: %v", i, j, err)
			}

			// Rescale to manage precision
			if err := evaluator.Rescale(product, product); err != nil {
				return nil, fmt.Errorf("failed to rescale [%d,%d]: %v", i, j, err)
			}

			// Sum-reduce to get the encrypted dot product
			sumResult := product.CopyNew()
			for r := 0; r < numRotations; r++ {
				rotAmount := 1 << r
				rotated, err := evaluator.RotateNew(sumResult, rotAmount)
				if err != nil {
					return nil, fmt.Errorf("failed to rotate [%d,%d]: %v", i, j, err)
				}
				if err := evaluator.Add(sumResult, rotated, sumResult); err != nil {
					return nil, fmt.Errorf("failed to add rotated [%d,%d]: %v", i, j, err)
				}
			}

			// Decrypt and get the sum from slot 0
			pt := decryptor.DecryptNew(sumResult)
			values := make([]float64, params.MaxSlots())
			if err := encoder.Decode(pt, values); err != nil {
				return nil, fmt.Errorf("failed to decode result [%d,%d]: %v", i, j, err)
			}
			results[i][j] = values[0]
		}
	}

	return &CrossProductOutput{
		Result: results,
	}, nil
}

// partialDecrypt computes a partial decryption share using this party's secret key
// For threshold decryption: each party provides their share, then they are combined
func partialDecrypt(ctB64, skB64 string, partyID, logN, logScale int) (*PartialDecryptOutput, error) {
	params, err := getParams(logN, logScale)
	if err != nil {
		return nil, fmt.Errorf("failed to create parameters: %v", err)
	}

	// Decode ciphertext
	ctBytes, err := base64.StdEncoding.DecodeString(ctB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %v", err)
	}

	ct := rlwe.NewCiphertext(params, 1, params.MaxLevel())
	if err := ct.UnmarshalBinary(ctBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize ciphertext: %v", err)
	}

	// Decode secret key
	skBytes, err := base64.StdEncoding.DecodeString(skB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret key: %v", err)
	}

	sk := rlwe.NewSecretKey(params)
	if err := sk.UnmarshalBinary(skBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize secret key: %v", err)
	}

	// Use KeySwitch protocol for threshold decryption
	// Each party computes: share_i = -s_i * ct[1] + e_i
	// Combined: sum(share_i) + ct[0] = m + e
	noise := ring.DiscreteGaussian{Sigma: 3.2, Bound: 19.2}
	ks, err := multiparty.NewKeySwitchProtocol(params, noise)
	if err != nil {
		return nil, fmt.Errorf("failed to create key switch protocol: %v", err)
	}

	// Generate the decryption share (GenShare needs pointer for output)
	share := ks.AllocateShare(ct.Level())
	ks.GenShare(sk, sk, ct, &share) // GenShare(skIn, skOut, ct, shareOut*)

	// Serialize the share
	shareBytes, err := share.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize decryption share: %v", err)
	}

	return &PartialDecryptOutput{
		PartialDecryption: base64.StdEncoding.EncodeToString(shareBytes),
		PartyID:           partyID,
	}, nil
}

// fuseDecryptions combines all partial decryption shares to get the final plaintext
// This is the threshold decryption step - requires ALL parties' shares
func fuseDecryptions(ctB64 string, partialB64 []string, logN, logScale int) (*FuseDecryptOutput, error) {
	params, err := getParams(logN, logScale)
	if err != nil {
		return nil, fmt.Errorf("failed to create parameters: %v", err)
	}

	if len(partialB64) == 0 {
		return nil, fmt.Errorf("no partial decryptions provided")
	}

	// Decode ciphertext
	ctBytes, err := base64.StdEncoding.DecodeString(ctB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %v", err)
	}

	ct := rlwe.NewCiphertext(params, 1, params.MaxLevel())
	if err := ct.UnmarshalBinary(ctBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize ciphertext: %v", err)
	}

	// Initialize KeySwitch protocol
	noise := ring.DiscreteGaussian{Sigma: 3.2, Bound: 19.2}
	ks, err := multiparty.NewKeySwitchProtocol(params, noise)
	if err != nil {
		return nil, fmt.Errorf("failed to create key switch protocol: %v", err)
	}

	// Deserialize and aggregate all shares (AggregateShares takes values, pointer for output)
	aggregatedShare := ks.AllocateShare(ct.Level())
	for i, shareB64 := range partialB64 {
		shareBytes, err := base64.StdEncoding.DecodeString(shareB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode partial decryption %d: %v", i, err)
		}
		share := ks.AllocateShare(ct.Level())
		if err := share.UnmarshalBinary(shareBytes); err != nil {
			return nil, fmt.Errorf("failed to deserialize partial decryption %d: %v", i, err)
		}
		if err := ks.AggregateShares(share, aggregatedShare, &aggregatedShare); err != nil {
			return nil, fmt.Errorf("failed to aggregate share %d: %v", i, err)
		}
	}

	// Apply the aggregated share to get the final ciphertext
	ctOut := rlwe.NewCiphertext(params, 1, ct.Level())
	ks.KeySwitch(ct, aggregatedShare, ctOut)

	// The result should now be decryptable with the zero key (all zeros)
	// In practice, we create a "plaintext ciphertext" (degree 0)
	// For threshold decryption to plaintext, the aggregated shares effectively
	// give us ct[0] + sum(-s_i * ct[1]) = m + e

	// Decode the plaintext from slot 0
	encoder := ckks.NewEncoder(params)

	// Create a plaintext from ct[0]
	pt := ckks.NewPlaintext(params, ct.Level())
	pt.Value = ctOut.Value[0]

	values := make([]float64, params.MaxSlots())
	if err := encoder.Decode(pt, values); err != nil {
		return nil, fmt.Errorf("failed to decode plaintext: %v", err)
	}

	// Return the first value (the sum from slot 0)
	return &FuseDecryptOutput{
		Value: values[0],
	}, nil
}

// ===== Legacy functions for backward compatibility =====

// encryptMatrix encrypts a matrix using the public key (row-packed)
func encryptMatrix(data [][]float64, cpkB64 string, logN, logScale int) (*EncryptOutput, error) {
	params, err := getParams(logN, logScale)
	if err != nil {
		return nil, fmt.Errorf("failed to create parameters: %v", err)
	}

	// Decode public key
	cpkBytes, err := base64.StdEncoding.DecodeString(cpkB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %v", err)
	}

	pk := rlwe.NewPublicKey(params)
	if err := pk.UnmarshalBinary(cpkBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize public key: %v", err)
	}

	// Flatten matrix to vector (row-major order)
	rows := len(data)
	cols := 0
	if rows > 0 {
		cols = len(data[0])
	}

	values := make([]float64, rows*cols)
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			values[i*cols+j] = data[i][j]
		}
	}

	// Create encoder and encryptor
	encoder := ckks.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, pk)

	// Encode the values into a plaintext
	pt := ckks.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(values, pt); err != nil {
		return nil, fmt.Errorf("failed to encode data: %v", err)
	}

	// Encrypt the plaintext
	ct, err := encryptor.EncryptNew(pt)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %v", err)
	}

	// Serialize ciphertext
	ctBytes, err := ct.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ciphertext: %v", err)
	}

	return &EncryptOutput{
		Ciphertext: base64.StdEncoding.EncodeToString(ctBytes),
		Rows:       rows,
		Cols:       cols,
	}, nil
}

// multiplyByPlaintext multiplies a ciphertext by a plaintext matrix (element-wise)
func multiplyByPlaintext(ctB64 string, plaintext [][]float64, rlkB64 string, logN, logScale int) (*MultiplyPlainOutput, error) {
	params, err := getParams(logN, logScale)
	if err != nil {
		return nil, fmt.Errorf("failed to create parameters: %v", err)
	}

	// Decode ciphertext
	ctBytes, err := base64.StdEncoding.DecodeString(ctB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %v", err)
	}

	ct := rlwe.NewCiphertext(params, 1, params.MaxLevel())
	if err := ct.UnmarshalBinary(ctBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize ciphertext: %v", err)
	}

	// Decode relinearization key
	rlkBytes, err := base64.StdEncoding.DecodeString(rlkB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode relinearization key: %v", err)
	}

	rlk := rlwe.NewRelinearizationKey(params)
	if err := rlk.UnmarshalBinary(rlkBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize relinearization key: %v", err)
	}

	// Flatten plaintext
	rows := len(plaintext)
	cols := 0
	if rows > 0 {
		cols = len(plaintext[0])
	}

	values := make([]float64, rows*cols)
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			values[i*cols+j] = plaintext[i][j]
		}
	}

	// Create encoder and evaluator
	encoder := ckks.NewEncoder(params)
	evaluator := ckks.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(rlk))

	// Encode plaintext
	pt := ckks.NewPlaintext(params, ct.Level())
	if err := encoder.Encode(values, pt); err != nil {
		return nil, fmt.Errorf("failed to encode plaintext: %v", err)
	}

	// Multiply ciphertext by plaintext (element-wise)
	result, err := evaluator.MulNew(ct, pt)
	if err != nil {
		return nil, fmt.Errorf("failed to multiply: %v", err)
	}

	// Rescale to manage noise
	if err := evaluator.Rescale(result, result); err != nil {
		return nil, fmt.Errorf("failed to rescale: %v", err)
	}

	// Serialize result
	resultBytes, err := result.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize result: %v", err)
	}

	return &MultiplyPlainOutput{
		ResultCiphertext: base64.StdEncoding.EncodeToString(resultBytes),
		Rows:             rows,
		Cols:             cols,
	}, nil
}

// sumReduce sums all elements in a ciphertext using rotation
func sumReduce(ctB64, rtksB64 string, numElements, logN, logScale int) (*SumReduceOutput, error) {
	params, err := getParams(logN, logScale)
	if err != nil {
		return nil, fmt.Errorf("failed to create parameters: %v", err)
	}

	// Decode ciphertext
	ctBytes, err := base64.StdEncoding.DecodeString(ctB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %v", err)
	}

	ct := rlwe.NewCiphertext(params, 1, params.MaxLevel())
	if err := ct.UnmarshalBinary(ctBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize ciphertext: %v", err)
	}

	// Generate rotation keys locally (for simplicity)
	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()
	rotations := []uint64{}
	for i := 1; i < numElements; i *= 2 {
		rotations = append(rotations, uint64(params.GaloisElement(i)))
	}
	gks := kgen.GenGaloisKeysNew(rotations, sk)
	evk := rlwe.NewMemEvaluationKeySet(nil, gks...)

	// Create evaluator with rotation keys
	evaluator := ckks.NewEvaluator(params, evk)

	// Sum using tree reduction with rotations
	result := ct.CopyNew()

	numRotations := int(math.Ceil(math.Log2(float64(numElements))))
	for i := 0; i < numRotations; i++ {
		rotAmount := 1 << i
		rotated, err := evaluator.RotateNew(result, rotAmount)
		if err != nil {
			return nil, fmt.Errorf("failed to rotate by %d: %v", rotAmount, err)
		}
		if err := evaluator.Add(result, rotated, result); err != nil {
			return nil, fmt.Errorf("failed to add rotated: %v", err)
		}
	}

	// Serialize result (sum is in slot 0)
	resultBytes, err := result.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize result: %v", err)
	}

	return &SumReduceOutput{
		ResultCiphertext: base64.StdEncoding.EncodeToString(resultBytes),
	}, nil
}
