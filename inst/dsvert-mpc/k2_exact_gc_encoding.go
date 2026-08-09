package main

import (
	"encoding/base64"
	"fmt"
	"math/big"
)

// exactGCRecordBytes is the canonical multi-limb container width. Limbs and
// records are little-endian; unused high bits above RingBits must be zero.
func exactGCRecordBytes(ringBits int) int {
	return exactGCTypeBits(ringBits) / 8
}

func exactGCDecodeCanonicalRecords(value string, spec exactGCCircuitSpec) ([][]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("exact-gc: non-canonical base64 share")
	}
	recordBytes := exactGCRecordBytes(spec.RingBits)
	recordCount := exactGCInputShareCount(spec)
	if len(decoded) != recordBytes*recordCount {
		return nil, fmt.Errorf("exact-gc: share length mismatch")
	}
	records := make([][]byte, recordCount)
	for i := range records {
		records[i] = decoded[i*recordBytes : (i+1)*recordBytes]
	}
	return records, nil
}

func exactGCLittleEndianBig(record []byte) *big.Int {
	bigEndian := make([]byte, len(record))
	for i, value := range record {
		bigEndian[len(record)-1-i] = value
	}
	return new(big.Int).SetBytes(bigEndian)
}

func exactGCBigLittleEndian(value *big.Int, size int) ([]byte, error) {
	if value == nil || value.Sign() < 0 || value.BitLen() > size*8 {
		return nil, fmt.Errorf("exact-gc: value does not fit canonical record")
	}
	record := make([]byte, size)
	bigEndian := value.Bytes()
	for i, b := range bigEndian {
		record[len(bigEndian)-1-i] = b
	}
	return record, nil
}

func exactGCDecodeWorkerCanonicalShares(value string,
	spec exactGCCircuitSpec) ([]*big.Int, error) {

	records, err := exactGCDecodeCanonicalRecords(value, spec)
	if err != nil {
		return nil, err
	}
	recordCount := exactGCInputShareCount(spec)
	result := make([]*big.Int, recordCount)
	if spec.RingBits == 63 {
		// Ring63's established FP wire is signed int64 little-endian. Preserve
		// that compatibility while all wider dynamic rings use residue records.
		decoded, err := decodeRing63FPVector(value, recordCount)
		if err != nil {
			return nil, err
		}
		for i := range decoded {
			result[i] = new(big.Int).SetUint64(decoded[i])
		}
		return result, nil
	}
	for i, record := range records {
		result[i] = exactGCLittleEndianBig(record)
		if result[i].BitLen() > spec.RingBits {
			return nil, fmt.Errorf("exact-gc: element %d is outside Ring%d", i,
				spec.RingBits)
		}
	}
	return result, nil
}

func exactGCEncodeWorkerCanonicalShares(values []*big.Int,
	spec exactGCCircuitSpec) (string, error) {

	if len(values) != spec.VectorLen {
		return "", fmt.Errorf("exact-gc: result length mismatch")
	}
	if spec.RingBits == 63 {
		encoded := make([]uint64, len(values))
		for i, value := range values {
			if value == nil || value.Sign() < 0 || value.BitLen() > spec.RingBits {
				return "", fmt.Errorf("exact-gc: result %d is outside Ring63", i)
			}
			encoded[i] = value.Uint64()
		}
		return ring63VectorToFPB64(encoded), nil
	}
	recordBytes := exactGCRecordBytes(spec.RingBits)
	encoded := make([]byte, recordBytes*len(values))
	for i, value := range values {
		if value == nil || value.Sign() < 0 || value.BitLen() > spec.RingBits {
			return "", fmt.Errorf("exact-gc: result %d is outside Ring%d", i,
				spec.RingBits)
		}
		record, err := exactGCBigLittleEndian(value, recordBytes)
		if err != nil {
			return "", err
		}
		copy(encoded[i*recordBytes:], record)
	}
	return base64.StdEncoding.EncodeToString(encoded), nil
}
