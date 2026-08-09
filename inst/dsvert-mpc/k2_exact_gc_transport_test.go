package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/big"
	"strings"
	"testing"
)

func TestExactGCSecureRecordsRoundTripAndHidePlaintext(t *testing.T) {
	session := exactGCTestSession(exactGCCircuitSpec{
		Operation: exactGCCompareSigned, RingBits: 63,
		Threshold: bigZero(), VectorLen: 1,
	})
	plaintext := []byte("sensitive-share-pattern-that-must-not-cross-the-relay")
	raw := exactGCTestRecord(session, plaintext)
	if bytes.Contains(raw, plaintext) {
		t.Fatal("relay-visible record contains plaintext")
	}
	receiver, err := newExactGCSecureRecordRW(&readWriter{Reader: bytes.NewReader(raw)},
		session, exactGCRoleEvaluator)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(plaintext))
	if _, err := io.ReadFull(receiver, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %q want %q", got, plaintext)
	}
}

func TestExactGCSecureRecordsRejectReplay(t *testing.T) {
	session := exactGCTestSession(exactGCCircuitSpec{
		Operation: exactGCCompareSigned, RingBits: 63,
		Threshold: bigZero(), VectorLen: 1,
	})
	plaintext := []byte("one record")
	one := exactGCTestRecord(session, plaintext)
	raw := append(append([]byte{}, one...), one...)
	receiver, err := newExactGCSecureRecordRW(&readWriter{Reader: bytes.NewReader(raw)},
		session, exactGCRoleEvaluator)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(plaintext))
	if _, err := io.ReadFull(receiver, got); err != nil {
		t.Fatalf("first record: %v", err)
	}
	if _, err := io.ReadFull(receiver, got); err == nil ||
		!strings.Contains(err.Error(), "replayed or out-of-order") {
		t.Fatalf("expected replay rejection, got %v", err)
	}
}

func TestExactGCSecureRecordsRejectTamperContextAndRole(t *testing.T) {
	session := exactGCTestSession(exactGCCircuitSpec{
		Operation: exactGCTruncateFloor, RingBits: 127, FracBits: 19, VectorLen: 1,
	})
	raw := exactGCTestRecord(session, []byte("secret"))

	t.Run("ciphertext tamper", func(t *testing.T) {
		tampered := append([]byte{}, raw...)
		tampered[len(tampered)-1] ^= 0x80
		receiver, err := newExactGCSecureRecordRW(
			&readWriter{Reader: bytes.NewReader(tampered)}, session, exactGCRoleEvaluator)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(receiver); err == nil ||
			!strings.Contains(err.Error(), "authentication failed") {
			t.Fatalf("expected authentication failure, got %v", err)
		}
	})

	t.Run("context mismatch", func(t *testing.T) {
		mismatch := session
		mismatch.Purpose = "different-bound-purpose"
		receiver, err := newExactGCSecureRecordRW(
			&readWriter{Reader: bytes.NewReader(raw)}, mismatch, exactGCRoleEvaluator)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(receiver); err == nil ||
			!strings.Contains(err.Error(), "authentication failed") {
			t.Fatalf("expected context authentication failure, got %v", err)
		}
	})

	t.Run("wrong role", func(t *testing.T) {
		receiver, err := newExactGCSecureRecordRW(
			&readWriter{Reader: bytes.NewReader(raw)}, session, exactGCRoleGarbler)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(receiver); err == nil ||
			!strings.Contains(err.Error(), "invalid record header") {
			t.Fatalf("expected role rejection, got %v", err)
		}
	})
}

func TestExactGCSecureRecordsRejectMalformedHeaderAndOversize(t *testing.T) {
	session := exactGCTestSession(exactGCCircuitSpec{
		Operation: exactGCCountGuard, RingBits: 63,
		Threshold: bigOne(), VectorLen: 1,
	})
	raw := exactGCTestRecord(session, []byte("x"))
	cases := map[string]func([]byte){
		"magic":     func(b []byte) { b[0] ^= 1 },
		"version":   func(b []byte) { b[4]++ },
		"reserved":  func(b []byte) { b[6] = 1 },
		"oversize":  func(b []byte) { binary.BigEndian.PutUint32(b[16:20], exactGCRecordMaxPlain+1) },
		"zero size": func(b []byte) { binary.BigEndian.PutUint32(b[16:20], 0) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			malformed := append([]byte{}, raw...)
			mutate(malformed)
			receiver, err := newExactGCSecureRecordRW(
				&readWriter{Reader: bytes.NewReader(malformed)}, session, exactGCRoleEvaluator)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadAll(receiver); err == nil {
				t.Fatal("expected malformed record rejection")
			}
		})
	}
}

func TestExactGCSecureRecordsSplitLargeWrites(t *testing.T) {
	session := exactGCTestSession(exactGCCircuitSpec{
		Operation: exactGCCountGuard, RingBits: 127,
		Threshold: bigOne(), VectorLen: 1,
	})
	plaintext := bytes.Repeat([]byte{0xa5}, exactGCRecordMaxPlain+17)
	raw := exactGCTestRecord(session, plaintext)
	receiver, err := newExactGCSecureRecordRW(&readWriter{Reader: bytes.NewReader(raw)},
		session, exactGCRoleEvaluator)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(plaintext))
	if _, err := io.ReadFull(receiver, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("large split record did not round-trip")
	}
}

func TestExactGCSecureRecordsPublishWholeFrames(t *testing.T) {
	session := exactGCTestSession(exactGCCircuitSpec{
		Operation: exactGCTruncateFloor, RingBits: 127,
		FracBits: 50, VectorLen: 1,
	})
	w := new(countingWriter)
	sender, err := newExactGCSecureRecordRW(
		&readWriter{Writer: w}, session, exactGCRoleGarbler)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := bytes.Repeat([]byte{0x5a}, exactGCRecordMaxPlain+17)
	if _, err := sender.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 2 {
		t.Fatalf("published %d fragments, want one write per authenticated record", len(w.writes))
	}
	if got, want := len(w.writes[0]), exactGCRecordHeader+exactGCRecordMaxPlain+16; got != want {
		t.Fatalf("first record bytes=%d want=%d", got, want)
	}
	if got, want := len(w.writes[1]), exactGCRecordHeader+17+16; got != want {
		t.Fatalf("second record bytes=%d want=%d", got, want)
	}
}

func exactGCTestRecord(session exactGCSession, plaintext []byte) []byte {
	var raw bytes.Buffer
	sender, err := newExactGCSecureRecordRW(&readWriter{Writer: &raw},
		session, exactGCRoleGarbler)
	if err != nil {
		panic(err)
	}
	if _, err := sender.Write(plaintext); err != nil {
		panic(err)
	}
	return append([]byte{}, raw.Bytes()...)
}

type readWriter struct {
	io.Reader
	io.Writer
}

type countingWriter struct {
	writes [][]byte
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.writes = append(w.writes, append([]byte{}, p...))
	return len(p), nil
}

func (rw *readWriter) Read(p []byte) (int, error) {
	if rw.Reader == nil {
		return 0, io.EOF
	}
	return rw.Reader.Read(p)
}

func (rw *readWriter) Write(p []byte) (int, error) {
	if rw.Writer == nil {
		return 0, io.ErrClosedPipe
	}
	return rw.Writer.Write(p)
}

func bigZero() *big.Int { return new(big.Int) }
func bigOne() *big.Int  { return big.NewInt(1) }
