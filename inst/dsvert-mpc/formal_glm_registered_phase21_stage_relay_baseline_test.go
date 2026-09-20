package main

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func formalGLMRegisteredPhase21StageRelayBaselineFixture(t testing.TB) *formalGLMRegisteredPhase21StageRelayV1 {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	leftPublic, _ := formalGLMRegisteredPhase21StageRelayTestKeyV1(t)
	rightPublic, rightPrivate := formalGLMRegisteredPhase21StageRelayTestKeyV1(t)
	relay, err := newFormalGLMRegisteredPhase21StageRelayV1(
		formalGLMRegisteredPhase21StageRelayConfigV1{
			ArtifactID: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			LocalPeer:  "evaluator", Peer: "garbler",
			SpoolDir: formalGLMRegisteredPhase21StageRelayTestSpoolV1(t, root, "right"),
			Signing:  rightPrivate,
			Pins: map[string]ed25519.PublicKey{
				"garbler": leftPublic, "evaluator": rightPublic,
			},
		})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(relay.Close)
	return relay
}

func formalGLMRegisteredPhase21StageRelayBaselineChunk(
	relay *formalGLMRegisteredPhase21StageRelayV1, start int64, payload []byte,
) formalGLMRegisteredPhase21StageRelayChunkV1 {
	return formalGLMRegisteredPhase21StageRelayChunkV1{
		Version:    formalGLMRegisteredPhase21StageRelayVersionV1,
		Purpose:    formalGLMRegisteredPhase21StageRelayPurposeV1,
		ArtifactID: relay.artifactID, SenderPeer: "garbler", RecipientPeer: "evaluator",
		Start: start, End: start + int64(len(payload)),
		PayloadSHA256: formalGLMRegisteredPhase21StageRelayPayloadSHA256V1(payload),
		Payload:       payload,
	}
}

func TestFormalGLMRegisteredPhase21StageRelayAheadOfConsumption(t *testing.T) {
	relay := formalGLMRegisteredPhase21StageRelayBaselineFixture(t)

	var payload []byte
	for _, part := range [][]byte{[]byte("first"), []byte("second"), []byte("third")} {
		chunk := formalGLMRegisteredPhase21StageRelayBaselineChunk(relay, int64(len(payload)), part)
		// Hold the consumer until all receipts have been issued. This is the
		// deterministic schedule of a relay outrunning its sampler.
		ack, err := relay.RelayV1(chunk)
		if err != nil || ack.Start != chunk.Start || ack.End != chunk.End {
			t.Fatalf("contiguous chunk [%d,%d) before consumption: ack=%+v / %v",
				chunk.Start, chunk.End, ack, err)
		}
		if offset, err := exactGCReadOffset(filepath.Join(relay.spoolDir, "inbound.ack")); err != nil || offset != 0 {
			t.Fatalf("relay advanced the consumer cursor: %d / %v", offset, err)
		}
		if _, err := relay.RelayV1(chunk); err != nil {
			t.Fatalf("pending chunk retry: %v", err)
		}
		fork := chunk
		fork.Payload = bytes.Repeat([]byte{'x'}, len(part))
		fork.PayloadSHA256 = formalGLMRegisteredPhase21StageRelayPayloadSHA256V1(fork.Payload)
		if _, err := relay.RelayV1(fork); err == nil {
			t.Fatal("accepted a conflicting pending retry")
		}
		payload = append(payload, part...)
	}
	for _, invalid := range []struct {
		name  string
		start int64
	}{
		{"gap", int64(len(payload)) + 1},
		{"overlap", int64(len(payload)) - 1},
	} {
		chunk := formalGLMRegisteredPhase21StageRelayBaselineChunk(relay, invalid.start, []byte("invalid"))
		if _, err := relay.RelayV1(chunk); err == nil {
			t.Fatalf("accepted a pending %s", invalid.name)
		}
	}
	reader, err := newExactGCSpoolRW(relay.spoolDir, formalGLMRegisteredPhase21StageMaxSpoolV1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("reader got %q, want %q / %v", got, payload, err)
	}
	if offset, err := exactGCReadOffset(filepath.Join(relay.spoolDir, "inbound.ack")); err != nil || offset != int64(len(payload)) {
		t.Fatalf("consumer cursor after reading: %d / %v", offset, err)
	}
}

func TestFormalGLMRegisteredPhase21StageRelayPendingSpoolBound(t *testing.T) {
	relay := formalGLMRegisteredPhase21StageRelayBaselineFixture(t)
	payload := bytes.Repeat([]byte{0xa5}, formalGLMRegisteredPhase21StageRelayMaxPayloadV1)
	var last formalGLMRegisteredPhase21StageRelayChunkV1
	for offset := int64(0); offset < formalGLMRegisteredPhase21StageMaxSpoolV1; offset += int64(len(payload)) {
		last = formalGLMRegisteredPhase21StageRelayBaselineChunk(relay, offset, payload)
		if _, err := relay.RelayV1(last); err != nil {
			t.Fatalf("fill bounded spool at %d: %v", offset, err)
		}
	}
	if _, err := relay.RelayV1(last); err != nil {
		t.Fatalf("retry at spool bound: %v", err)
	}
	next := formalGLMRegisteredPhase21StageRelayBaselineChunk(relay, last.End, payload)
	if _, err := relay.RelayV1(next); err == nil {
		t.Fatal("accepted bytes beyond the pending spool bound")
	}
	reader, err := newExactGCSpoolRW(relay.spoolDir, formalGLMRegisteredPhase21StageMaxSpoolV1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("consume first bounded segment: %v", err)
	}
	if _, err := relay.RelayV1(next); err != nil {
		t.Fatalf("consumption did not release capacity: %v", err)
	}
}

func TestFormalGLMRegisteredPhase21StageRelayConcurrentConsumption(t *testing.T) {
	relay := formalGLMRegisteredPhase21StageRelayBaselineFixture(t)
	reader, err := newExactGCSpoolRW(relay.spoolDir, formalGLMRegisteredPhase21StageMaxSpoolV1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("encrypted-stream"), 64)
	got := make([]byte, len(payload))
	var readErr error
	done := make(chan struct{})
	go func() {
		_, readErr = io.ReadFull(reader, got)
		close(done)
	}()
	t.Cleanup(func() {
		_ = os.WriteFile(filepath.Join(relay.spoolDir, "abort"), []byte("."), 0o600)
		<-done
		_ = reader.Close()
	})
	for start := 0; start < len(payload); start += 32 {
		chunk := formalGLMRegisteredPhase21StageRelayBaselineChunk(relay, int64(start), payload[start:start+32])
		if _, err := relay.RelayV1(chunk); err != nil {
			t.Fatalf("concurrent chunk at %d: %v", start, err)
		}
		if _, err := relay.RelayV1(chunk); err != nil {
			t.Fatalf("concurrent retry at %d: %v", start, err)
		}
	}
	<-done
	if readErr != nil || !bytes.Equal(got, payload) {
		t.Fatalf("concurrent consumer changed bytes: %v", readErr)
	}
}
