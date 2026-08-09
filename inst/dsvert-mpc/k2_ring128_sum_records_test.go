package main

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

func ring128SumTestRecords(values []Uint128) string {
	records := make([]byte, len(values)*ring128SumRecordsRecordSize)
	for index, value := range values {
		offset := index * ring128SumRecordsRecordSize
		binary.LittleEndian.PutUint64(records[offset:offset+8], value.Lo)
		binary.LittleEndian.PutUint64(records[offset+8:offset+16], value.Hi)
	}
	return base64.StdEncoding.EncodeToString(records)
}

func TestRing128SumRecordsSegmentsAndWrap(t *testing.T) {
	input := ring128SumRecordsInput{
		Version: ring128SumRecordsVersion,
		Records: ring128SumTestRecords([]Uint128{
			{Hi: ^uint64(0), Lo: ^uint64(0)}, U128FromUint64(2),
			{Hi: 3, Lo: 4}, {Hi: 5, Lo: 6}, {Hi: 7, Lo: 8},
		}),
		SegmentLengths: []int{2, 3},
	}
	output, err := sumRing128Records(input)
	if err != nil {
		t.Fatalf("sum records: %v", err)
	}
	if output.Version != ring128SumRecordsVersion || output.SegmentCount != 2 {
		t.Fatalf("unexpected output contract: %#v", output)
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(output.Sums)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("invalid output encoding: %v", err)
	}
	got := []Uint128{
		{Lo: binary.LittleEndian.Uint64(decoded[:8]), Hi: binary.LittleEndian.Uint64(decoded[8:16])},
		{Lo: binary.LittleEndian.Uint64(decoded[16:24]), Hi: binary.LittleEndian.Uint64(decoded[24:32])},
	}
	want := []Uint128{{Lo: 1}, {Hi: 15, Lo: 18}}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("segment %d=%#v want %#v", index, got[index], want[index])
		}
	}
}

func TestRing128SumRecordsRejectsMalformedContracts(t *testing.T) {
	valid := ring128SumRecordsInput{
		Version:        ring128SumRecordsVersion,
		Records:        ring128SumTestRecords([]Uint128{U128FromUint64(1)}),
		SegmentLengths: []int{1},
	}
	cases := []ring128SumRecordsInput{
		{Version: "wrong", Records: valid.Records, SegmentLengths: []int{1}},
		{Version: ring128SumRecordsVersion, Records: valid.Records},
		{Version: ring128SumRecordsVersion, Records: valid.Records, SegmentLengths: []int{0}},
		{Version: ring128SumRecordsVersion, Records: valid.Records + "=", SegmentLengths: []int{1}},
		{Version: ring128SumRecordsVersion, Records: valid.Records, SegmentLengths: []int{2}},
	}
	for index, input := range cases {
		if _, err := sumRing128Records(input); err == nil {
			t.Fatalf("case %d accepted malformed input", index)
		}
	}
}

func TestDecodeRing128SumRecordsInputIsStrictAndBounded(t *testing.T) {
	unknown := `{"version":"dsvert-ring128-sum-records-v1","records":"AAAAAAAAAAAAAAAAAAAAAA==","segment_lengths":[1],"extra":true}`
	if _, err := decodeRing128SumRecordsInput(strings.NewReader(unknown)); err == nil {
		t.Fatal("accepted unknown JSON field")
	}
	trailing := `{"version":"dsvert-ring128-sum-records-v1","records":"AAAAAAAAAAAAAAAAAAAAAA==","segment_lengths":[1]} {}`
	if _, err := decodeRing128SumRecordsInput(strings.NewReader(trailing)); err == nil {
		t.Fatal("accepted trailing JSON value")
	}
	tooLarge := strings.NewReader(strings.Repeat(" ", dpNoiseMaxInputBytes+1))
	if _, err := decodeRing128SumRecordsInput(tooLarge); err == nil {
		t.Fatal("accepted oversized JSON input")
	}
}
