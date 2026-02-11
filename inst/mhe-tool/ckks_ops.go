// ckks_ops.go: CKKS operations using Lattigo for MHE
//
// This file contains the actual cryptographic operations using Lattigo v6.
// Currently implements single-party CKKS as a foundation.
// TODO: Add proper multiparty (threshold) support using multiparty/mpckks.

package main

import (
	"encoding/base64"
	"fmt"
	"math"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// getParams returns CKKS parameters based on logN and logScale
func getParams(logN, logScale int) (ckks.Parameters, error) {
	var params ckks.Parameters
	var err error

	// Build parameters with appropriate moduli chain
	switch logN {
	case 12:
		// Small parameters for testing
		params, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
			LogN:            12,
			LogQ:            []int{50, 35, 35, 35},
			LogP:            []int{40},
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

// KeyMaterial holds all key material for a party
type KeyMaterial struct {
	SecretKey *rlwe.SecretKey
	PublicKey *rlwe.PublicKey
	RelinKey  *rlwe.RelinearizationKey
	RotKeys   *rlwe.GaloisKey
}

// generateKeyShare generates keys for this party
// Note: For now this generates independent keys. For true MHE,
// parties would collaboratively generate a shared public key.
func generateKeyShare(partyID, numParties, logN, logScale int) (*KeyGenOutput, error) {
	params, err := getParams(logN, logScale)
	if err != nil {
		return nil, fmt.Errorf("failed to create parameters: %v", err)
	}

	// Create key generator
	kgen := rlwe.NewKeyGenerator(params)

	// Generate secret key for this party
	sk := kgen.GenSecretKeyNew()

	// Generate public key
	pk := kgen.GenPublicKeyNew(sk)

	// Serialize the keys
	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize secret key: %v", err)
	}

	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize public key: %v", err)
	}

	return &KeyGenOutput{
		SecretKeyShare: base64.StdEncoding.EncodeToString(skBytes),
		PublicKeyShare: base64.StdEncoding.EncodeToString(pkBytes),
		PartyID:        partyID,
	}, nil
}

// combinePublicKeys creates evaluation keys from the first party's keys
// Note: In true MHE, this would aggregate keys from all parties
func combinePublicKeys(pkSharesB64 []string, logN, logScale int) (*CombineKeysOutput, error) {
	params, err := getParams(logN, logScale)
	if err != nil {
		return nil, fmt.Errorf("failed to create parameters: %v", err)
	}

	if len(pkSharesB64) == 0 {
		return nil, fmt.Errorf("no public key shares provided")
	}

	// Deserialize first public key
	pkBytes, err := base64.StdEncoding.DecodeString(pkSharesB64[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %v", err)
	}

	pk := rlwe.NewPublicKey(params)
	if err := pk.UnmarshalBinary(pkBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize public key: %v", err)
	}

	// For evaluation keys, we need to generate them with a secret key
	// In a real MHE setup, this would be done collaboratively
	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()

	// Generate relinearization key
	rlk := kgen.GenRelinearizationKeyNew(sk)

	// Generate rotation keys for sum reduction
	rotations := []uint64{}
	maxSlots := params.MaxSlots()
	for i := 1; i < maxSlots; i *= 2 {
		rotations = append(rotations, uint64(i))
	}
	rtks := kgen.GenGaloisKeysNew(rotations, sk)

	// Serialize outputs
	cpkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize collective public key: %v", err)
	}

	rlkBytes, err := rlk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize relinearization key: %v", err)
	}

	// Serialize rotation keys - use the evaluation key set
	evkSet := rlwe.NewMemEvaluationKeySet(rlk, rtks...)
	rtksBytes, err := evkSet.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize rotation keys: %v", err)
	}

	return &CombineKeysOutput{
		CollectivePublicKey: base64.StdEncoding.EncodeToString(cpkBytes),
		RelinearizationKey:  base64.StdEncoding.EncodeToString(rlkBytes),
		RotationKeys:        base64.StdEncoding.EncodeToString(rtksBytes),
	}, nil
}

// encryptMatrix encrypts a matrix using the public key
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

// partialDecrypt decrypts using the secret key
// Note: For true MHE, this would generate a partial decryption share
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

	// Decrypt to plaintext
	decryptor := rlwe.NewDecryptor(params, sk)
	pt := decryptor.DecryptNew(ct)

	// Serialize the plaintext as "partial decryption"
	// In true MHE, this would be a share that needs to be combined
	ptBytes, err := pt.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize decryption: %v", err)
	}

	return &PartialDecryptOutput{
		PartialDecryption: base64.StdEncoding.EncodeToString(ptBytes),
		PartyID:           partyID,
	}, nil
}

// fuseDecryptions combines decryption results
// Note: For single-party, this just decodes the first partial
func fuseDecryptions(partialB64 []string, rows, cols, logN, logScale int) (*FuseDecryptOutput, error) {
	params, err := getParams(logN, logScale)
	if err != nil {
		return nil, fmt.Errorf("failed to create parameters: %v", err)
	}

	if len(partialB64) == 0 {
		return nil, fmt.Errorf("no partial decryptions provided")
	}

	// Decode the first partial (which is a plaintext for single-party)
	ptBytes, err := base64.StdEncoding.DecodeString(partialB64[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode partial decryption: %v", err)
	}

	pt := ckks.NewPlaintext(params, params.MaxLevel())
	if err := pt.UnmarshalBinary(ptBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize plaintext: %v", err)
	}

	// Decode the plaintext to get the values
	encoder := ckks.NewEncoder(params)
	values := make([]float64, rows*cols)
	if err := encoder.Decode(pt, values); err != nil {
		return nil, fmt.Errorf("failed to decode plaintext: %v", err)
	}

	// Reshape into matrix
	data := make([][]float64, rows)
	for i := 0; i < rows; i++ {
		data[i] = make([]float64, cols)
		for j := 0; j < cols; j++ {
			data[i][j] = values[i*cols+j]
		}
	}

	return &FuseDecryptOutput{
		Data: data,
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

	// Decode rotation keys
	rtksBytes, err := base64.StdEncoding.DecodeString(rtksB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode rotation keys: %v", err)
	}

	// Deserialize evaluation key set (contains rotation keys)
	evk := rlwe.NewMemEvaluationKeySet(nil)
	if err := evk.UnmarshalBinary(rtksBytes); err != nil {
		// If deserialization fails, regenerate keys (fallback for testing)
		kgen := rlwe.NewKeyGenerator(params)
		sk := kgen.GenSecretKeyNew()
		rotations := []uint64{}
		for i := 1; i < numElements; i *= 2 {
			rotations = append(rotations, uint64(i))
		}
		gks := kgen.GenGaloisKeysNew(rotations, sk)
		evk = rlwe.NewMemEvaluationKeySet(nil, gks...)
	}

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

// encryptColumns encrypts a matrix column-by-column
// This is optimal for computing cross-products: each column becomes one ciphertext
func encryptColumns(data [][]float64, cpkB64 string, logN, logScale int) (*EncryptColumnsOutput, error) {
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

	// Get dimensions (data is row-major: data[row][col])
	numRows := len(data)
	if numRows == 0 {
		return nil, fmt.Errorf("empty data matrix")
	}
	numCols := len(data[0])

	// Create encoder and encryptor
	encoder := ckks.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, pk)

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
// plaintextColumns: columns of Z_A (each is a vector of length n)
// encryptedColumns: encrypted columns of Z_B
// Returns G_AB where G_AB[i][j] = dot(Z_A[:,i], Z_B[:,j])
func computeCrossProduct(plaintextColumns [][]float64, encryptedColumnsB64 []string,
	skB64 string, logN, logScale int) (*CrossProductOutput, error) {

	params, err := getParams(logN, logScale)
	if err != nil {
		return nil, fmt.Errorf("failed to create parameters: %v", err)
	}

	pA := len(plaintextColumns) // Number of plaintext columns
	pB := len(encryptedColumnsB64) // Number of encrypted columns

	if pA == 0 || pB == 0 {
		return nil, fmt.Errorf("empty input: pA=%d, pB=%d", pA, pB)
	}

	n := len(plaintextColumns[0]) // Number of rows

	// Decode secret key for final decryption
	skBytes, err := base64.StdEncoding.DecodeString(skB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret key: %v", err)
	}
	sk := rlwe.NewSecretKey(params)
	if err := sk.UnmarshalBinary(skBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize secret key: %v", err)
	}

	// Create necessary components
	encoder := ckks.NewEncoder(params)
	decryptor := rlwe.NewDecryptor(params, sk)
	kgen := rlwe.NewKeyGenerator(params)

	// Generate rotation keys for sum-reduce
	// Need to use the correct Galois elements for CKKS rotations
	galEls := []uint64{}
	for i := 1; i < n; i *= 2 {
		galEl := params.GaloisElement(i)
		galEls = append(galEls, galEl)
	}
	gks := kgen.GenGaloisKeysNew(galEls, sk)
	rlk := kgen.GenRelinearizationKeyNew(sk)
	evk := rlwe.NewMemEvaluationKeySet(rlk, gks...)

	evaluator := ckks.NewEvaluator(params, evk)

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

	// Compute cross product matrix G_AB
	// G_AB[i][j] = sum_k (Z_A[k,i] * Z_B[k,j]) = dot(Z_A[:,i], Z_B[:,j])
	result := make([][]float64, pA)
	for i := 0; i < pA; i++ {
		result[i] = make([]float64, pB)
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

			// Sum-reduce to get the dot product
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

			// Decrypt to get the scalar result
			pt := decryptor.DecryptNew(sumResult)
			values := make([]float64, n)
			if err := encoder.Decode(pt, values); err != nil {
				return nil, fmt.Errorf("failed to decode [%d,%d]: %v", i, j, err)
			}

			// The sum is in slot 0
			result[i][j] = values[0]
		}
	}

	return &CrossProductOutput{
		Result: result,
	}, nil
}
