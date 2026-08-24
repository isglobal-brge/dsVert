package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func formalGLMRegisteredPhase21StageRelayTestKeyV1(t testing.TB) (
	ed25519.PublicKey, ed25519.PrivateKey,
) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func formalGLMRegisteredPhase21StageRelayTestSpoolV1(t testing.TB, root, name string) string {
	t.Helper()
	spool := filepath.Join(root, name)
	formalGLMPhase21RockTestPrepareSpool(t, spool)
	if err := exactGCPrepareWorkerSpool(spool); err != nil {
		t.Fatal(err)
	}
	return spool
}

func TestFormalGLMRegisteredPhase21StageRelayK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			leftPublic, leftPrivate := formalGLMRegisteredPhase21StageRelayTestKeyV1(t)
			rightPublic, rightPrivate := formalGLMRegisteredPhase21StageRelayTestKeyV1(t)
			pins := map[string]ed25519.PublicKey{
				"garbler": leftPublic, "evaluator": rightPublic,
			}
			artifact := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			left, err := newFormalGLMRegisteredPhase21StageRelayV1(
				formalGLMRegisteredPhase21StageRelayConfigV1{
					ArtifactID: artifact, LocalPeer: "garbler", Peer: "evaluator",
					SpoolDir: formalGLMRegisteredPhase21StageRelayTestSpoolV1(t, root, "left"),
					Signing:  leftPrivate, Pins: pins,
				})
			if err != nil {
				t.Fatal(err)
			}
			defer left.Close()
			right, err := newFormalGLMRegisteredPhase21StageRelayV1(
				formalGLMRegisteredPhase21StageRelayConfigV1{
					ArtifactID: artifact, LocalPeer: "evaluator", Peer: "garbler",
					SpoolDir: formalGLMRegisteredPhase21StageRelayTestSpoolV1(t, root, "right"),
					Signing:  rightPrivate, Pins: pins,
				})
			if err != nil {
				t.Fatal(err)
			}
			defer right.Close()

			payload := bytes.Repeat([]byte{byte(custodians), 0xa5},
				(formalGLMRegisteredPhase21StageRelayMaxPayloadV1/2)+31)
			if err := os.WriteFile(filepath.Join(left.spoolDir, "exchange.hb"), []byte("."), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := exactGCPublishSegment(
				filepath.Join(left.spoolDir, "outbound.segments"), 0, payload); err != nil {
				t.Fatal(err)
			}
			if err := exactGCWriteOffset(filepath.Join(left.spoolDir, "outbound.head"), int64(len(payload))); err != nil {
				t.Fatal(err)
			}

			var acknowledged *formalGLMRegisteredPhase21StageRelayAckV1
			var reconstructed []byte
			for {
				chunk, pollErr := left.PollV1(acknowledged)
				if pollErr != nil {
					t.Fatal(pollErr)
				}
				if chunk == nil {
					break
				}
				ack, relayErr := right.RelayV1(*chunk)
				if relayErr != nil {
					t.Fatal(relayErr)
				}
				reconstructed = append(reconstructed, chunk.Payload...)
				// The live exact-GC reader advances this cursor and reclaims the
				// authenticated inbound segment before the next peer range arrives.
				if err := exactGCWriteOffset(filepath.Join(right.spoolDir, "inbound.ack"), ack.End); err != nil {
					t.Fatal(err)
				}
				inbound, err := exactGCListSegments(filepath.Join(right.spoolDir, "inbound.segments"))
				if err != nil {
					t.Fatal(err)
				}
				for _, segment := range inbound {
					if segment.end <= ack.End {
						if err := os.Remove(segment.path); err != nil {
							t.Fatal(err)
						}
					}
				}
				acknowledged = &ack
			}
			if !bytes.Equal(reconstructed, payload) {
				t.Fatal("relay changed the encrypted stage payload")
			}
			if head, err := exactGCReadOffset(filepath.Join(left.spoolDir, "outbound.head")); err != nil ||
				head != int64(len(payload)) {
				t.Fatalf("outbound head=%d / %v", head, err)
			}
			if ack, err := exactGCReadOffset(filepath.Join(left.spoolDir, "outbound.ack")); err != nil ||
				ack != int64(len(payload)) {
				t.Fatalf("outbound ack=%d / %v", ack, err)
			}
			segments, err := exactGCListSegments(filepath.Join(left.spoolDir, "outbound.segments"))
			if err != nil || len(segments) != 0 {
				t.Fatalf("acknowledged segments remain: %#v / %v", segments, err)
			}

			forged := *acknowledged
			forged.Signature = append([]byte(nil), acknowledged.Signature...)
			forged.Signature[0] ^= 1
			if _, err := left.PollV1(&forged); err == nil {
				t.Fatal("accepted a forged peer acknowledgement")
			}
			crossed := formalGLMRegisteredPhase21StageRelayChunkV1{
				Version:    formalGLMRegisteredPhase21StageRelayVersionV1,
				Purpose:    formalGLMRegisteredPhase21StageRelayPurposeV1,
				ArtifactID: artifact, SenderPeer: "garbler", RecipientPeer: "evaluator",
				Start: int64(len(payload)) - 1, End: int64(len(payload)) + 1,
				PayloadSHA256: formalGLMRegisteredPhase21StageRelayPayloadSHA256V1([]byte{1, 2}),
				Payload:       []byte{1, 2}, ProductionReady: false,
			}
			if _, err := right.RelayV1(crossed); err == nil {
				t.Fatal("accepted a non-contiguous stage relay chunk")
			}
		})
	}
}
