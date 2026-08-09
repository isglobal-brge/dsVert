package main

// This file contains one deliberately unpromoted, server-local arithmetic
// primitive for the cross-owner Gaussian capsule. It reduces fixed-width
// additive Ring128 share records without decoding them through float64. The
// command is absent from runtime-capabilities and no DataSHIELD endpoint
// exposes it directly.

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const (
	ring128SumRecordsVersion    = "dsvert-ring128-sum-records-v1"
	ring128SumRecordsRecordSize = 16
	ring128SumRecordsMaxRecords = 2_000_000
)

type ring128SumRecordsInput struct {
	Version        string `json:"version"`
	Records        string `json:"records"`
	SegmentLengths []int  `json:"segment_lengths"`
}

type ring128SumRecordsOutput struct {
	Version      string `json:"version"`
	SegmentCount int    `json:"segment_count"`
	Sums         string `json:"sums"`
}

func decodeRing128SumRecordsInput(reader io.Reader) (ring128SumRecordsInput, error) {
	var input ring128SumRecordsInput
	data, err := io.ReadAll(io.LimitReader(reader, dpNoiseMaxInputBytes+1))
	if err != nil || len(data) == 0 || len(data) > dpNoiseMaxInputBytes {
		return input, fmt.Errorf("invalid Ring128 reduction input")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return input, fmt.Errorf("invalid Ring128 reduction input")
	}
	if err := requireJSONEOF(decoder); err != nil {
		return input, fmt.Errorf("invalid Ring128 reduction input")
	}
	return input, nil
}

func sumRing128Records(input ring128SumRecordsInput) (ring128SumRecordsOutput, error) {
	var output ring128SumRecordsOutput
	if input.Version != ring128SumRecordsVersion ||
		len(input.SegmentLengths) == 0 ||
		len(input.SegmentLengths) > ring128SumRecordsMaxRecords {
		return output, fmt.Errorf("invalid Ring128 reduction contract")
	}
	total := 0
	for _, length := range input.SegmentLengths {
		if length < 1 || length > ring128SumRecordsMaxRecords ||
			total > ring128SumRecordsMaxRecords-length {
			return output, fmt.Errorf("invalid Ring128 reduction shape")
		}
		total += length
	}
	records, err := base64.StdEncoding.Strict().DecodeString(input.Records)
	if err != nil || base64.StdEncoding.EncodeToString(records) != input.Records ||
		len(records) != total*ring128SumRecordsRecordSize {
		return output, fmt.Errorf("invalid Ring128 reduction records")
	}

	sums := make([]byte, len(input.SegmentLengths)*ring128SumRecordsRecordSize)
	recordIndex := 0
	for segmentIndex, length := range input.SegmentLengths {
		sum := U128Zero()
		for index := 0; index < length; index++ {
			offset := recordIndex * ring128SumRecordsRecordSize
			record := Uint128{
				Lo: binary.LittleEndian.Uint64(records[offset : offset+8]),
				Hi: binary.LittleEndian.Uint64(records[offset+8 : offset+16]),
			}
			sum = sum.Add(record)
			recordIndex++
		}
		offset := segmentIndex * ring128SumRecordsRecordSize
		binary.LittleEndian.PutUint64(sums[offset:offset+8], sum.Lo)
		binary.LittleEndian.PutUint64(sums[offset+8:offset+16], sum.Hi)
	}
	clear(records)
	output = ring128SumRecordsOutput{
		Version:      ring128SumRecordsVersion,
		SegmentCount: len(input.SegmentLengths),
		Sums:         base64.StdEncoding.EncodeToString(sums),
	}
	clear(sums)
	return output, nil
}

func handleRing128SumRecords() {
	input, err := decodeRing128SumRecordsInput(os.Stdin)
	if err != nil {
		mpcFatalError(err.Error())
	}
	result, err := sumRing128Records(input)
	if err != nil {
		mpcFatalError(err.Error())
	}
	mpcWriteOutput(result)
}
