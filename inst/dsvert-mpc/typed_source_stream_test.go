package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteTypedSourceStreamIsBoundedAndCanonical(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "source.b64")
	raw := bytes.Repeat([]byte{0xfb, 0xff, 0x00, 0x01}, 257)
	result, err := writeTypedSourceStream(path, int64(len(raw)), bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.ContainsAny(encoded, "+/=") {
		t.Fatalf("payload is not canonical Base64url: %q", encoded[:16])
	}
	if result.Version != typedSourceStreamProtocol ||
		result.PayloadChars != int64(len(encoded)) {
		t.Fatalf("unexpected stream metadata: %+v", result)
	}
	hash := sha256.Sum256(encoded)
	if result.PayloadSHA256 != hex.EncodeToString(hash[:]) {
		t.Fatal("streamed SHA-256 mismatch")
	}
}

func TestWriteTypedSourceStreamRejectsUnsafePathsAndCleansPartialFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "partial.b64")
	if _, err := writeTypedSourceStream(path, 128, bytes.NewReader([]byte("short"))); err == nil {
		t.Fatal("expected truncated source to fail")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("partial streamed payload was retained")
	}
	if err := os.WriteFile(path, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := writeTypedSourceStream(path, 1, bytes.NewReader([]byte{1})); err == nil {
		t.Fatal("expected existing output path to fail")
	}
	if _, err := writeTypedSourceStream("relative.b64", 1, bytes.NewReader([]byte{1})); err == nil {
		t.Fatal("expected relative output path to fail")
	}
}
