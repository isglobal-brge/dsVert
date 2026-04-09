// utils.go: Core utility functions for Ring63 MPC tool.
// Base64 encoding, FixedPoint serialization, JSON I/O.

package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// fpVecToBytes serializes a FixedPoint vector to little-endian bytes.
func fpVecToBytes(v []FixedPoint) []byte {
	buf := make([]byte, len(v)*8)
	for i, fp := range v {
		binary.LittleEndian.PutUint64(buf[i*8:], uint64(fp))
	}
	return buf
}

// bytesToFPVec deserializes little-endian bytes to a FixedPoint vector.
func bytesToFPVec(buf []byte) []FixedPoint {
	n := len(buf) / 8
	v := make([]FixedPoint, n)
	for i := 0; i < n; i++ {
		v[i] = FixedPoint(binary.LittleEndian.Uint64(buf[i*8:]))
	}
	return v
}

// mpcReadInput reads JSON from stdin into the provided struct.
func mpcReadInput(v interface{}) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, `{"error":"read stdin: %s"}`, err)
		os.Exit(1)
	}
	if err := json.Unmarshal(data, v); err != nil {
		fmt.Fprintf(os.Stderr, `{"error":"parse input: %s"}`, err)
		os.Exit(1)
	}
}

// mpcWriteOutput writes a struct as JSON to stdout.
func mpcWriteOutput(v interface{}) {
	j, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, `{"error":"marshal output: %s"}`, err)
		os.Exit(1)
	}
	fmt.Println(string(j))
}

// bytesToBase64 encodes bytes as standard base64.
func bytesToBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// base64ToBytes decodes standard base64 to bytes.
func base64ToBytes(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		// Try URL-safe
		data, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return nil
		}
	}
	return data
}

// readInput reads raw bytes from stdin (for PSI commands).
func readInputBytes() ([]byte, error) {
	return io.ReadAll(os.Stdin)
}

// outputJSON writes a JSON object to stdout (PSI/transport compatibility).
func outputJSON(v interface{}) {
	j, _ := json.Marshal(v)
	fmt.Println(string(j))
}
