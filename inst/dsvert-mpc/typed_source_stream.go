package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

const (
	typedSourceStreamProtocol        = "dsvert-typed-source-stream-v1"
	typedSourceMaxPayloadChars int64 = 512 * 1024 * 1024
)

type typedSourceStreamInput struct {
	OutputPath string `json:"output_path"`
	RawBytes   int64  `json:"raw_bytes"`
}

type typedSourceStreamOutput struct {
	Version       string `json:"version"`
	PayloadChars  int64  `json:"payload_chars"`
	PayloadSHA256 string `json:"payload_sha256"`
}

func validateTypedSourceOutputPath(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("output path must be canonical and absolute")
	}
	if _, err := os.Lstat(path); err == nil {
		return "", fmt.Errorf("output path already exists")
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("cannot inspect output path: %w", err)
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("output parent is not a regular directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("output parent is not private")
	}
	return path, nil
}

func writeTypedSourceStream(path string, rawBytes int64, source io.Reader) (
	typedSourceStreamOutput, error) {
	var empty typedSourceStreamOutput
	path, err := validateTypedSourceOutputPath(path)
	if err != nil {
		return empty, err
	}
	if rawBytes < 1 || rawBytes > typedSourceMaxPayloadChars*3/4 {
		return empty, fmt.Errorf("raw byte count exceeds the typed-source bound")
	}
	expectedChars := int64(base64.RawURLEncoding.EncodedLen(int(rawBytes)))
	if expectedChars < 1 || expectedChars > typedSourceMaxPayloadChars {
		return empty, fmt.Errorf("encoded payload exceeds the typed-source bound")
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return empty, fmt.Errorf("create private output: %w", err)
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(path)
		}
	}()

	hash := sha256.New()
	encoder := base64.NewEncoder(base64.RawURLEncoding, io.MultiWriter(file, hash))
	written, err := io.CopyN(encoder, source, rawBytes)
	if err != nil || written != rawBytes {
		_ = encoder.Close()
		return empty, fmt.Errorf("generate streamed payload: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return empty, fmt.Errorf("finalize streamed encoding: %w", err)
	}
	if err := file.Sync(); err != nil {
		return empty, fmt.Errorf("sync streamed payload: %w", err)
	}
	if err := file.Close(); err != nil {
		return empty, fmt.Errorf("close streamed payload: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != expectedChars {
		return empty, fmt.Errorf("streamed payload failed its final size check")
	}
	committed = true
	return typedSourceStreamOutput{
		Version:       typedSourceStreamProtocol,
		PayloadChars:  expectedChars,
		PayloadSHA256: hex.EncodeToString(hash.Sum(nil)),
	}, nil
}

func handleTypedSourceStreamProbe() {
	inputBytes, err := readInputBytes()
	if err != nil {
		outputError("Failed to read typed-source input")
		return
	}
	var input typedSourceStreamInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError("Failed to parse typed-source input")
		return
	}
	result, err := writeTypedSourceStream(input.OutputPath, input.RawBytes, rand.Reader)
	if err != nil {
		outputError("Typed-source stream failed: " + err.Error())
		return
	}
	output(result)
}
