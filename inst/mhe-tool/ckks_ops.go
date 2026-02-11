// ckks_ops.go: CKKS parameter configuration and column encryption
//
// This file provides the CKKS parameter sets and the column-wise encryption
// function used by the MHE protocol. The threshold MHE protocol itself
// (setup, combine, cross-product, partial-decrypt, fuse) lives in
// mhe_protocol.go.

package main

import (
	"encoding/base64"
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// getParams returns CKKS parameters based on logN and logScale.
// LogQ intermediate moduli must match LogDefaultScale for correct rescaling.
func getParams(logN, logScale int) (ckks.Parameters, error) {
	var params ckks.Parameters
	var err error

	switch logN {
	case 12:
		// Small parameters (2048 slots) - fast, suitable for moderate datasets
		params, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
			LogN:            12,
			LogQ:            []int{50, 40, 40},
			LogP:            []int{50},
			LogDefaultScale: logScale,
		})
	case 13:
		// Medium parameters (4096 slots)
		params, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
			LogN:            13,
			LogQ:            []int{55, 40, 40, 40, 40},
			LogP:            []int{45, 45},
			LogDefaultScale: logScale,
		})
	case 14:
		// Large parameters (8192 slots) - production use
		params, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
			LogN:            14,
			LogQ:            []int{55, 40, 40, 40, 40, 40, 40},
			LogP:            []int{45, 45},
			LogDefaultScale: logScale,
		})
	case 15:
		// Very large parameters (16384 slots) - deeper circuits
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

// encryptColumns encrypts a matrix column-by-column using the Collective Public Key.
// Each column becomes one ciphertext with n slots (one per observation).
// Data is in row-major format: data[row][col].
func encryptColumns(data [][]float64, cpkB64 string, logN, logScale int) (*EncryptColumnsOutput, error) {
	params, err := getParams(logN, logScale)
	if err != nil {
		return nil, fmt.Errorf("failed to create parameters: %v", err)
	}

	cpkBytes, err := base64.StdEncoding.DecodeString(cpkB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %v", err)
	}

	cpk := rlwe.NewPublicKey(params)
	if err := cpk.UnmarshalBinary(cpkBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize public key: %v", err)
	}

	numRows := len(data)
	if numRows == 0 {
		return nil, fmt.Errorf("empty data matrix")
	}
	numCols := len(data[0])

	encoder := ckks.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, cpk)

	encryptedCols := make([]string, numCols)
	for j := 0; j < numCols; j++ {
		column := make([]float64, numRows)
		for i := 0; i < numRows; i++ {
			column[i] = data[i][j]
		}

		pt := ckks.NewPlaintext(params, params.MaxLevel())
		if err := encoder.Encode(column, pt); err != nil {
			return nil, fmt.Errorf("failed to encode column %d: %v", j, err)
		}

		ct, err := encryptor.EncryptNew(pt)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt column %d: %v", j, err)
		}

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
