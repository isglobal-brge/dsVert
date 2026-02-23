package main

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"testing"
)

func TestBinaryVectorRoundTrip(t *testing.T) {
	vectors := map[string][]float64{
		"mu": {1.0, 2.5, -3.14159, 0.0, 1e-10},
		"w":  {100.0, 200.0, 300.0},
		"v":  {-1.0, 0.0, 1.0, 2.0, 3.0},
	}

	data, err := marshalBinaryVectors(vectors)
	if err != nil {
		t.Fatal(err)
	}

	// Verify header
	if data[0] != bvfMagic || data[1] != bvfVersion {
		t.Fatalf("bad header: 0x%02x 0x%02x", data[0], data[1])
	}

	result, err := unmarshalBinaryVectors(data)
	if err != nil {
		t.Fatal(err)
	}

	if len(result) != len(vectors) {
		t.Fatalf("expected %d vectors, got %d", len(vectors), len(result))
	}

	for k, expected := range vectors {
		got, ok := result[k]
		if !ok {
			t.Fatalf("missing vector %q", k)
		}
		if len(got) != len(expected) {
			t.Fatalf("vector %q: expected %d elements, got %d", k, len(expected), len(got))
		}
		for i, v := range expected {
			if got[i] != v {
				t.Errorf("vector %q[%d]: expected %v, got %v", k, i, v, got[i])
			}
		}
	}
}

func TestBinaryVectorLarge(t *testing.T) {
	n := 10000
	vec := make([]float64, n)
	for i := range vec {
		vec[i] = float64(i) * 0.001
	}
	vectors := map[string][]float64{"large": vec}

	data, err := marshalBinaryVectors(vectors)
	if err != nil {
		t.Fatal(err)
	}

	result, err := unmarshalBinaryVectors(data)
	if err != nil {
		t.Fatal(err)
	}

	got := result["large"]
	if len(got) != n {
		t.Fatalf("expected %d elements, got %d", n, len(got))
	}
	for i := range vec {
		if got[i] != vec[i] {
			t.Errorf("[%d]: expected %v, got %v", i, vec[i], got[i])
		}
	}
}

func TestBinaryVectorEmpty(t *testing.T) {
	vectors := map[string][]float64{}

	data, err := marshalBinaryVectors(vectors)
	if err != nil {
		t.Fatal(err)
	}

	result, err := unmarshalBinaryVectors(data)
	if err != nil {
		t.Fatal(err)
	}

	if len(result) != 0 {
		t.Fatalf("expected 0 vectors, got %d", len(result))
	}
}

func TestBinaryVectorSingle(t *testing.T) {
	vectors := map[string][]float64{"x": {42.0}}

	data, err := marshalBinaryVectors(vectors)
	if err != nil {
		t.Fatal(err)
	}

	result, err := unmarshalBinaryVectors(data)
	if err != nil {
		t.Fatal(err)
	}

	if result["x"][0] != 42.0 {
		t.Errorf("expected 42.0, got %v", result["x"][0])
	}
}

func TestBinaryVectorEncryptDecryptRoundTrip(t *testing.T) {
	vectors := map[string][]float64{
		"mu":  {1.0, 2.0, 3.0},
		"eta": {-1.5, 0.0, 1.5},
	}

	keys, err := transportKeygen()
	if err != nil {
		t.Fatal(err)
	}

	pkBytes, err := base64.StdEncoding.DecodeString(keys.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	skBytes, err := base64.StdEncoding.DecodeString(keys.SecretKey)
	if err != nil {
		t.Fatal(err)
	}

	sealed, err := transportEncryptVectors(vectors, pkBytes)
	if err != nil {
		t.Fatal(err)
	}

	result, err := transportDecryptVectors(sealed, skBytes)
	if err != nil {
		t.Fatal(err)
	}

	for k, expected := range vectors {
		got := result[k]
		if len(got) != len(expected) {
			t.Fatalf("vector %q: expected %d elements, got %d", k, len(expected), len(got))
		}
		for i, v := range expected {
			if got[i] != v {
				t.Errorf("vector %q[%d]: expected %v, got %v", k, i, v, got[i])
			}
		}
	}
}

func TestBinaryVectorAutoDetectJSONFallback(t *testing.T) {
	// Simulate legacy JSON-encrypted vectors: JSON → encrypt → decrypt should still work
	vectors := map[string][]float64{
		"mu": {1.0, 2.0, 3.0},
	}

	keys, err := transportKeygen()
	if err != nil {
		t.Fatal(err)
	}

	pkBytes, err := base64.StdEncoding.DecodeString(keys.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	skBytes, err := base64.StdEncoding.DecodeString(keys.SecretKey)
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt with legacy JSON format
	jsonBytes, err := json.Marshal(vectors)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := transportEncryptBytes(jsonBytes, pkBytes)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt with new auto-detecting function
	result, err := transportDecryptVectors(sealed, skBytes)
	if err != nil {
		t.Fatal(err)
	}

	got := result["mu"]
	if len(got) != 3 || got[0] != 1.0 || got[1] != 2.0 || got[2] != 3.0 {
		t.Errorf("JSON fallback failed: got %v", got)
	}
}

func TestBinaryVectorInt64RangeValues(t *testing.T) {
	// Values that stress float64 precision — representative of masked_eta
	// which contains fixed-point scaled int64 values up to 2^53
	vectors := map[string][]float64{
		"masked_eta": {
			math.Pow(2, 52) + 0.5,
			math.Pow(2, 53),
			-math.Pow(2, 52),
			math.MaxFloat64,
			math.SmallestNonzeroFloat64,
			math.Inf(1),
			math.Inf(-1),
		},
	}

	data, err := marshalBinaryVectors(vectors)
	if err != nil {
		t.Fatal(err)
	}

	result, err := unmarshalBinaryVectors(data)
	if err != nil {
		t.Fatal(err)
	}

	got := result["masked_eta"]
	expected := vectors["masked_eta"]
	for i, v := range expected {
		if math.IsInf(v, 0) {
			if !math.IsInf(got[i], 0) || math.Signbit(v) != math.Signbit(got[i]) {
				t.Errorf("[%d]: expected %v, got %v", i, v, got[i])
			}
		} else if got[i] != v {
			t.Errorf("[%d]: expected %v, got %v", i, v, got[i])
		}
	}
}

func TestBinaryVectorSizeSavings(t *testing.T) {
	// Verify binary format is smaller than JSON for a typical GLM iteration
	// Use realistic float64 values (15+ significant digits as JSON)
	n := 500
	mu := make([]float64, n)
	w := make([]float64, n)
	v := make([]float64, n)
	for i := 0; i < n; i++ {
		mu[i] = 0.123456789012345 + float64(i)*0.001
		w[i] = 1.987654321098765 + float64(i)*0.0001
		v[i] = -0.567890123456789 + float64(i)*0.002
	}
	vectors := map[string][]float64{"mu": mu, "w": w, "v": v}

	binaryData, err := marshalBinaryVectors(vectors)
	if err != nil {
		t.Fatal(err)
	}
	jsonData, err := json.Marshal(vectors)
	if err != nil {
		t.Fatal(err)
	}

	ratio := float64(len(jsonData)) / float64(len(binaryData))
	t.Logf("Binary: %d bytes, JSON: %d bytes, ratio: %.2fx", len(binaryData), len(jsonData), ratio)

	if ratio < 1.5 {
		t.Errorf("expected at least 1.5x size reduction, got %.2fx", ratio)
	}
}
