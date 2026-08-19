package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func formalGLMRegisteredPhase20JobTransportTestSHA256V1(label string) string {
	digest := sha256.Sum256([]byte(label))
	return hex.EncodeToString(digest[:])
}

func formalGLMRegisteredPhase20JobTransportTestBindingV1(
	label string,
) formalGLMRegisteredPhase20JobTransportBindingV1 {
	return formalGLMRegisteredPhase20JobTransportBindingV1{
		ArtifactID:          formalGLMRegisteredPhase20JobTransportTestSHA256V1(label + "/artifact"),
		ReceiptSetSHA256:    formalGLMRegisteredPhase20JobTransportTestSHA256V1(label + "/receipts"),
		SemanticRootSHA256:  formalGLMRegisteredPhase20JobTransportTestSHA256V1(label + "/semantic"),
		BindingRecordSHA256: formalGLMRegisteredPhase20JobTransportTestSHA256V1(label + "/binding"),
		AttemptID:           formalGLMRegisteredPhase20JobTransportTestSHA256V1(label + "/attempt"),
		ScheduleRootSHA256:  formalGLMRegisteredPhase20JobTransportTestSHA256V1(label + "/schedule"),
		ProductionReady:     false,
	}
}

func formalGLMRegisteredPhase20JobTransportTestRootV1(
	t testing.TB,
) (*os.Root, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rock")
	root, err := formalGLMRegisteredPhase19OpenRockRootV1(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root, path
}

func formalGLMRegisteredPhase20JobTransportTestOpenV1(
	t testing.TB,
	root *os.Root,
	binding formalGLMRegisteredPhase20JobTransportBindingV1,
	peer string,
	epoch formalGLMRegisteredPhase20JobTransportEpochV1,
) *formalGLMRegisteredPhase20JobTransportV1 {
	t.Helper()
	relative := filepath.Join("job-transport-tests", peer, binding.AttemptID)
	transport, err := newFormalGLMRegisteredPhase20JobTransportV1(
		root, relative, binding, epoch)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = transport.Close() })
	return transport
}

func formalGLMRegisteredPhase20JobTransportTestEpochV1(
	mode, basis string,
) formalGLMRegisteredPhase20JobTransportEpochV1 {
	return formalGLMRegisteredPhase20JobTransportEpochV1{
		Mode: mode, BasisSHA256: formalGLMRegisteredPhase20JobTransportTestSHA256V1(basis),
	}
}

func formalGLMRegisteredPhase20JobTransportTestPayloadV1(index int) []byte {
	return bytes.Repeat([]byte{byte(0x41 + index)},
		formalGLMRegisteredPhase20JobRelayMaxPayloadV1+257)
}

func formalGLMRegisteredPhase20JobTransportTestChunkV1(
	ref formalGLMRegisteredPhase20JobRefV1, offset int64, payload []byte,
) formalGLMRegisteredPhase20RelayChunkV1 {
	digest := sha256.Sum256(payload)
	return formalGLMRegisteredPhase20RelayChunkV1{
		JobSHA256: ref.JobSHA256, TransportSHA256: ref.TransportSHA256,
		Offset:        offset,
		PayloadSHA256: hex.EncodeToString(digest[:]),
		Payload:       append([]byte(nil), payload...),
	}
}

func formalGLMRegisteredPhase20JobTransportTestWaitForBlockedIOV1(
	t *testing.T,
	transport *formalGLMRegisteredPhase20JobTransportV1,
	operation string,
) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		transport.mu.Lock()
		active := transport.activeOps
		spool := transport.spool
		transport.mu.Unlock()
		if spool == nil {
			t.Fatal("transport closed before I/O became observable")
		}
		writeLockAvailable := spool.writeMu.TryLock()
		readWaiting := false
		if writeLockAvailable {
			readWaiting = spool.readWaiting
			spool.writeMu.Unlock()
		}
		if operation == "read" && active == 1 &&
			writeLockAvailable && readWaiting {
			return
		}
		if operation == "write" && active == 1 && !writeLockAvailable {
			head, err := exactGCReadOffset(
				filepath.Join(transport.scratchPath, "outbound.head"))
			if err == nil && head == 1 {
				return
			}
		}
		runtime.Gosched()
	}
	t.Fatalf("%s I/O lease did not become observably blocked", operation)
}

func TestFormalGLMRegisteredPhase20JobTransportDTOBurnAndAsymmetricEpoch(
	t *testing.T,
) {
	root, _ := formalGLMRegisteredPhase20JobTransportTestRootV1(t)
	binding := formalGLMRegisteredPhase20JobTransportTestBindingV1("epoch")
	runEpoch := formalGLMRegisteredPhase20JobTransportTestEpochV1(
		formalGLMRegisteredPhase20JobRunTransportV1, "epoch/run-signed-basis")
	run := formalGLMRegisteredPhase20JobTransportTestOpenV1(
		t, root, binding, "local-peer-0", runEpoch)
	preBind := formalGLMRegisteredPhase20JobTransportTestChunkV1(
		run.ref, 0, []byte("pre-bind"))
	if _, err := run.Write([]byte("pre-bind")); err == nil {
		t.Fatal("worker bytes were accepted before peer-epoch binding")
	}
	if _, err := run.Relay(preBind); err == nil {
		t.Fatal("Relay bytes were accepted before peer-epoch binding")
	}
	if _, err := run.Poll(0); err == nil {
		t.Fatal("Poll was accepted before peer-epoch binding")
	}
	if run.ref.ProductionReady || run.ref.ArtifactID != binding.ArtifactID ||
		run.ref.AttemptID != binding.AttemptID {
		t.Fatalf("invalid non-production JobRef: %+v", run.ref)
	}
	burned, err := formalGLMRegisteredPhase20JobTransportBurnedV1(
		root, filepath.Join("job-transport-tests", "local-peer-0", binding.AttemptID),
		binding, runEpoch)
	if err != nil || !burned {
		t.Fatalf("durable run slot was not burned: %v", err)
	}
	if _, err := newFormalGLMRegisteredPhase20JobTransportV1(
		root, filepath.Join("job-transport-tests", "local-peer-0", binding.AttemptID),
		binding, runEpoch); err == nil {
		t.Fatal("same burned transport epoch was reopened")
	}

	// One peer may restart first. Its recovery ref remains the common stable
	// job identity, but its authenticated epoch and spool inode are distinct.
	recoveryEpoch := formalGLMRegisteredPhase20JobTransportTestEpochV1(
		formalGLMRegisteredPhase20JobAbandonTransportV1,
		"epoch/common-signed-abandon-basis")
	recovery := formalGLMRegisteredPhase20JobTransportTestOpenV1(
		t, root, binding, "local-peer-0", recoveryEpoch)
	if recovery.ref.JobSHA256 != run.ref.JobSHA256 ||
		recovery.ref.AttemptID != run.ref.AttemptID ||
		recovery.ref.TransportSHA256 == run.ref.TransportSHA256 ||
		recovery.epochSHA256 == run.epochSHA256 ||
		recovery.scratchPath == run.scratchPath {
		t.Fatalf("asymmetric restart mixed identity/epoch: run=%+v recovery=%+v",
			run.ref, recovery.ref)
	}
	if err := recovery.validatePeerEpochV1(run.epochSHA256); err == nil {
		t.Fatal("recovery accepted the still-running peer epoch")
	}
	failedPoll, err := recovery.Poll(0)
	if err != nil || failedPoll.State != formalGLMRegisteredPhase20JobFailedClosedV1 {
		t.Fatalf("mismatched recovery did not fail closed: %+v / %v", failedPoll, err)
	}
	cleanRecovery := formalGLMRegisteredPhase20JobTransportTestOpenV1(
		t, root, binding, "local-peer-1", recoveryEpoch)
	if err := cleanRecovery.BindPeerEpochV1(cleanRecovery.epochSHA256); err != nil {
		t.Fatal(err)
	}
	poll, err := cleanRecovery.Poll(0)
	if err != nil || poll.RelayChunk != nil {
		t.Fatalf("clean recovery spool observed stale run bytes: %+v / %v", poll, err)
	}
	if err := run.BindPeerEpochV1(run.epochSHA256); err != nil {
		t.Fatal(err)
	}
	if _, err := run.Write([]byte("stale-run-bytes")); err != nil {
		t.Fatal(err)
	}
	if err := run.Flush(); err != nil {
		t.Fatal(err)
	}
	stale, err := run.Poll(0)
	if err != nil || stale.RelayChunk == nil {
		t.Fatalf("missing stale run offer: %+v / %v", stale, err)
	}
	if _, err := cleanRecovery.Relay(*stale.RelayChunk); err == nil ||
		cleanRecovery.inboundAccepted != 0 {
		t.Fatal("recovery accepted bytes from a different transport epoch")
	}

	start := formalGLMRegisteredPhase20JobStartV1{
		ArtifactID: binding.ArtifactID, ReceiptSetSHA256: binding.ReceiptSetSHA256,
	}
	chunk := formalGLMRegisteredPhase20JobTransportTestChunkV1(
		run.ref, 0, []byte("opaque"))
	poll = formalGLMRegisteredPhase20JobPollResultV1{
		State:      formalGLMRegisteredPhase20JobNegotiatingV1,
		RelayChunk: &chunk,
	}
	for name, value := range map[string]any{
		"start": start, "ref": run.ref, "chunk": chunk, "poll": poll,
	} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(encoded, &fields) != nil {
			t.Fatalf("invalid %s JSON", name)
		}
		for _, forbidden := range []string{"peer", "path", "key", "action"} {
			if _, found := fields[forbidden]; found {
				t.Fatalf("%s DTO exposed %s", name, forbidden)
			}
		}
	}
	if encoded, _ := json.Marshal(run); string(encoded) != "{}" {
		t.Fatalf("transport exposed private state: %s", encoded)
	}
	tampered := binding
	tampered.ProductionReady = true
	if _, err := newFormalGLMRegisteredPhase20JobTransportV1(
		root, filepath.Join("job-transport-tests", "invalid-production"), tampered,
		formalGLMRegisteredPhase20JobTransportTestEpochV1(
			formalGLMRegisteredPhase20JobRunTransportV1,
			"invalid-production/signed-basis")); err == nil {
		t.Fatal("ProductionReady=true binding was accepted")
	}
}

func TestFormalGLMRegisteredPhase20JobTransportPollUnblocksFullWriter(
	t *testing.T,
) {
	root, _ := formalGLMRegisteredPhase20JobTransportTestRootV1(t)
	binding := formalGLMRegisteredPhase20JobTransportTestBindingV1("poll-full-writer")
	transport := formalGLMRegisteredPhase20JobTransportTestOpenV1(
		t, root, binding, "local-peer-0",
		formalGLMRegisteredPhase20JobTransportTestEpochV1(
			formalGLMRegisteredPhase20JobRunTransportV1,
			"poll-full-writer/signed-basis"))
	if err := transport.BindPeerEpochV1(transport.epochSHA256); err != nil {
		t.Fatal(err)
	}
	transport.spool.maxBytes = 1
	if _, err := transport.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := transport.Write([]byte("b"))
		writeDone <- err
	}()
	formalGLMRegisteredPhase20JobTransportTestWaitForBlockedIOV1(
		t, transport, "write")

	type pollOutcome struct {
		result formalGLMRegisteredPhase20JobPollResultV1
		err    error
	}
	pollDone := make(chan pollOutcome, 1)
	go func() {
		result, err := transport.Poll(0)
		pollDone <- pollOutcome{result: result, err: err}
	}()
	var outcome pollOutcome
	select {
	case outcome = <-pollDone:
	case <-time.After(2 * time.Second):
		_ = formalGLMRegisteredPhase20JobTransportSignalAbortV1(transport.scratch)
		<-pollDone
		<-writeDone
		t.Fatal("Poll blocked behind the full writer")
	}
	if outcome.err != nil || outcome.result.RelayChunk == nil ||
		outcome.result.RelayChunk.Offset != 0 ||
		!bytes.Equal(outcome.result.RelayChunk.Payload, []byte("a")) {
		t.Fatalf("Poll did not offer the durable first byte: %+v / %v",
			outcome.result, outcome.err)
	}
	if _, err := transport.Poll(1); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("acknowledging the first byte did not unblock the writer")
	}
	if err := transport.Flush(); err != nil {
		t.Fatal(err)
	}
	second, err := transport.Poll(1)
	if err != nil || second.RelayChunk == nil ||
		second.RelayChunk.Offset != 1 ||
		!bytes.Equal(second.RelayChunk.Payload, []byte("b")) {
		t.Fatalf("writer did not continue with the second byte: %+v / %v", second, err)
	}
}

func TestFormalGLMRegisteredPhase20JobTransportFailedStateAbortsRead(
	t *testing.T,
) {
	root, _ := formalGLMRegisteredPhase20JobTransportTestRootV1(t)
	binding := formalGLMRegisteredPhase20JobTransportTestBindingV1("failed-read")
	transport := formalGLMRegisteredPhase20JobTransportTestOpenV1(
		t, root, binding, "local-peer-0",
		formalGLMRegisteredPhase20JobTransportTestEpochV1(
			formalGLMRegisteredPhase20JobRunTransportV1,
			"failed-read/signed-basis"))
	if err := transport.BindPeerEpochV1(transport.epochSHA256); err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() {
		var one [1]byte
		_, err := transport.Read(one[:])
		readDone <- err
	}()
	formalGLMRegisteredPhase20JobTransportTestWaitForBlockedIOV1(
		t, transport, "read")
	if err := transport.setStateV1(
		formalGLMRegisteredPhase20JobFailedClosedV1); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("failed_closed did not abort the blocked read")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("failed_closed stranded the blocked read")
	}
}

func TestFormalGLMRegisteredPhase20JobTransportOpaqueReplayAndChunkBound(
	t *testing.T,
) {
	root, _ := formalGLMRegisteredPhase20JobTransportTestRootV1(t)
	binding := formalGLMRegisteredPhase20JobTransportTestBindingV1("relay")
	transports := [2]*formalGLMRegisteredPhase20JobTransportV1{
		formalGLMRegisteredPhase20JobTransportTestOpenV1(
			t, root, binding, "local-peer-0",
			formalGLMRegisteredPhase20JobTransportTestEpochV1(
				formalGLMRegisteredPhase20JobRunTransportV1, "relay/common-signed-basis")),
		formalGLMRegisteredPhase20JobTransportTestOpenV1(
			t, root, binding, "local-peer-1",
			formalGLMRegisteredPhase20JobTransportTestEpochV1(
				formalGLMRegisteredPhase20JobRunTransportV1, "relay/common-signed-basis")),
	}
	for _, transport := range transports {
		if err := transport.BindPeerEpochV1(transport.epochSHA256); err != nil {
			t.Fatal(err)
		}
	}
	results := make(chan error, 2)
	for index := range transports {
		go func(index int) {
			local := formalGLMRegisteredPhase20JobTransportTestPayloadV1(index)
			if _, err := transports[index].Write(local); err != nil {
				results <- err
				return
			}
			want := formalGLMRegisteredPhase20JobTransportTestPayloadV1(1 - index)
			got := make([]byte, len(want))
			_, err := io.ReadFull(transports[index], got)
			if err == nil && !bytes.Equal(got, want) {
				err = fmt.Errorf("opaque relay changed payload")
			}
			results <- err
		}(index)
	}
	acks := [2]int64{}
	done, replayChecked, sawLimit := 0, false, false
	deadline := time.Now().Add(15 * time.Second)
	for done < 2 && time.Now().Before(deadline) {
		for from := range transports {
			poll, err := transports[from].Poll(acks[from])
			if err != nil {
				t.Fatalf("poll %d: %v", from, err)
			}
			if poll.ProductionReady {
				t.Fatal("transport emitted ProductionReady=true")
			}
			chunk := poll.RelayChunk
			if chunk == nil {
				continue
			}
			if len(chunk.Payload) == 0 ||
				len(chunk.Payload) > formalGLMRegisteredPhase20JobRelayMaxPayloadV1 {
				t.Fatalf("invalid Poll chunk length %d", len(chunk.Payload))
			}
			sawLimit = sawLimit || len(chunk.Payload) ==
				formalGLMRegisteredPhase20JobRelayMaxPayloadV1
			if !replayChecked {
				again, err := transports[from].Poll(acks[from])
				if err != nil || !reflect.DeepEqual(again.RelayChunk, chunk) {
					t.Fatalf("Poll replay changed: %+v / %v", again, err)
				}
				replayChecked = true
			}
			accepted, err := transports[1-from].Relay(*chunk)
			if err != nil {
				t.Fatalf("relay %d: %v", from, err)
			}
			if duplicate, err := transports[1-from].Relay(*chunk); err != nil ||
				duplicate != accepted {
				t.Fatalf("exact Relay retry changed: %d / %v", duplicate, err)
			}
			acks[from] = chunk.Offset + int64(len(chunk.Payload))
		}
		for {
			select {
			case err := <-results:
				if err != nil {
					t.Fatal(err)
				}
				done++
			default:
				goto drained
			}
		}
	drained:
		time.Sleep(time.Millisecond)
	}
	if done != 2 || !replayChecked || !sawLimit {
		t.Fatalf("incomplete bounded relay: done=%d replay=%t limit=%t",
			done, replayChecked, sawLimit)
	}
	for index := range transports {
		if _, err := transports[index].Poll(acks[index]); err != nil {
			t.Fatal(err)
		}
		if _, err := transports[index].Poll(acks[index] - 1); err == nil {
			t.Fatalf("transport %d accepted ack rollback", index)
		}
	}
}

func TestFormalGLMRegisteredPhase20JobTransportRejectsGapOverlapForkAndUnsafeReopen(
	t *testing.T,
) {
	root, _ := formalGLMRegisteredPhase20JobTransportTestRootV1(t)
	for _, test := range []string{"gap", "overlap", "fork"} {
		t.Run(test, func(t *testing.T) {
			binding := formalGLMRegisteredPhase20JobTransportTestBindingV1(test)
			transport := formalGLMRegisteredPhase20JobTransportTestOpenV1(
				t, root, binding, "local-peer-0",
				formalGLMRegisteredPhase20JobTransportTestEpochV1(
					formalGLMRegisteredPhase20JobRunTransportV1, test+"/signed-basis"))
			if err := transport.BindPeerEpochV1(transport.epochSHA256); err != nil {
				t.Fatal(err)
			}
			first := formalGLMRegisteredPhase20JobTransportTestChunkV1(
				transport.ref, 0, []byte("abc"))
			if test != "gap" {
				if _, err := transport.Relay(first); err != nil {
					t.Fatal(err)
				}
			}
			candidate := first
			switch test {
			case "gap":
				candidate.Offset = 1
			case "overlap":
				candidate.Offset = 1
			case "fork":
				candidate = formalGLMRegisteredPhase20JobTransportTestChunkV1(
					transport.ref, 0, []byte("abd"))
			}
			if _, err := transport.Relay(candidate); err == nil {
				t.Fatalf("%s was accepted", test)
			}
			if err := transport.setStateV1(
				formalGLMRegisteredPhase20JobRunningV1); err == nil {
				t.Fatal("failed_closed transport was resurrected")
			}
			poll, err := transport.Poll(0)
			if err != nil || poll.State != formalGLMRegisteredPhase20JobFailedClosedV1 {
				t.Fatalf("%s did not fail closed: %+v / %v", test, poll, err)
			}
		})
	}

	t.Run("mode", func(t *testing.T) {
		binding := formalGLMRegisteredPhase20JobTransportTestBindingV1("mode")
		transport := formalGLMRegisteredPhase20JobTransportTestOpenV1(
			t, root, binding, "local-peer-0",
			formalGLMRegisteredPhase20JobTransportTestEpochV1(
				formalGLMRegisteredPhase20JobRunTransportV1, "mode/signed-basis"))
		if err := transport.BindPeerEpochV1(transport.epochSHA256); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(transport.scratchPath, 0o755); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(transport.scratchPath, 0o700)
		if _, err := transport.Poll(0); err == nil {
			t.Fatal("unsafe reopened scratch mode was accepted")
		}
	})

	t.Run("hardlink", func(t *testing.T) {
		binding := formalGLMRegisteredPhase20JobTransportTestBindingV1("hardlink")
		transport := formalGLMRegisteredPhase20JobTransportTestOpenV1(
			t, root, binding, "local-peer-0",
			formalGLMRegisteredPhase20JobTransportTestEpochV1(
				formalGLMRegisteredPhase20JobRunTransportV1, "hardlink/signed-basis"))
		if err := transport.BindPeerEpochV1(transport.epochSHA256); err != nil {
			t.Fatal(err)
		}
		head := filepath.Join(transport.scratchPath, "outbound.head")
		linked := filepath.Join(transport.scratchPath, "outbound-head-link")
		if err := os.Link(head, linked); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(linked)
		if _, err := transport.Poll(0); err == nil {
			t.Fatal("multiply linked spool state was accepted")
		}
	})

	t.Run("burn-mode", func(t *testing.T) {
		binding := formalGLMRegisteredPhase20JobTransportTestBindingV1("burn-mode")
		transport := formalGLMRegisteredPhase20JobTransportTestOpenV1(
			t, root, binding, "local-peer-0",
			formalGLMRegisteredPhase20JobTransportTestEpochV1(
				formalGLMRegisteredPhase20JobRunTransportV1, "burn-mode/signed-basis"))
		if err := transport.BindPeerEpochV1(transport.epochSHA256); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(transport.scratchPath,
			formalGLMRegisteredPhase20JobTransportBurnV1)
		if err := os.Chmod(marker, 0o400); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(marker, 0o600)
		if _, err := transport.Poll(0); err == nil {
			t.Fatal("non-0600 burn marker was accepted")
		}
	})

	t.Run("segment-mode", func(t *testing.T) {
		binding := formalGLMRegisteredPhase20JobTransportTestBindingV1("segment-mode")
		transport := formalGLMRegisteredPhase20JobTransportTestOpenV1(
			t, root, binding, "local-peer-0",
			formalGLMRegisteredPhase20JobTransportTestEpochV1(
				formalGLMRegisteredPhase20JobRunTransportV1, "segment-mode/signed-basis"))
		if err := transport.BindPeerEpochV1(transport.epochSHA256); err != nil {
			t.Fatal(err)
		}
		if _, err := transport.Write([]byte("segment")); err != nil {
			t.Fatal(err)
		}
		if err := transport.Flush(); err != nil {
			t.Fatal(err)
		}
		segments, err := exactGCListSegments(
			filepath.Join(transport.scratchPath, "outbound.segments"))
		if err != nil || len(segments) != 1 {
			t.Fatalf("missing test segment: %+v / %v", segments, err)
		}
		if err := os.Chmod(segments[0].path, 0o400); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(segments[0].path, 0o600)
		if _, err := transport.Poll(0); err == nil {
			t.Fatal("non-0600 segment was accepted")
		}
	})

	t.Run("segment-dir-swap", func(t *testing.T) {
		binding := formalGLMRegisteredPhase20JobTransportTestBindingV1("dir-swap")
		transport := formalGLMRegisteredPhase20JobTransportTestOpenV1(
			t, root, binding, "local-peer-0",
			formalGLMRegisteredPhase20JobTransportTestEpochV1(
				formalGLMRegisteredPhase20JobRunTransportV1, "dir-swap/signed-basis"))
		if err := transport.BindPeerEpochV1(transport.epochSHA256); err != nil {
			t.Fatal(err)
		}
		original := filepath.Join(transport.scratchPath, "inbound.segments")
		moved := filepath.Join(transport.scratchPath, "inbound.segments-moved")
		if err := os.Rename(original, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(original, 0o700); err != nil {
			_ = os.Rename(moved, original)
			t.Fatal(err)
		}
		defer func() {
			_ = os.Remove(original)
			_ = os.Rename(moved, original)
		}()
		if _, err := transport.Poll(0); err == nil {
			t.Fatal("replacement segment directory inode was accepted")
		}
	})

	t.Run("abort-hardlink", func(t *testing.T) {
		binding := formalGLMRegisteredPhase20JobTransportTestBindingV1("abort-hardlink")
		transport := formalGLMRegisteredPhase20JobTransportTestOpenV1(
			t, root, binding, "local-peer-0",
			formalGLMRegisteredPhase20JobTransportTestEpochV1(
				formalGLMRegisteredPhase20JobRunTransportV1, "abort-hardlink/signed-basis"))
		head := filepath.Join(transport.scratchPath, "outbound.head")
		abort := filepath.Join(transport.scratchPath, "abort")
		if err := os.Link(head, abort); err != nil {
			t.Fatal(err)
		}
		if err := transport.Close(); err != nil {
			t.Fatal(err)
		}
		abortInfo, abortErr := os.Lstat(abort)
		headInfo, headErr := os.Lstat(head)
		abortBytes, readAbortErr := os.ReadFile(abort)
		headBytes, readHeadErr := os.ReadFile(head)
		if abortErr != nil || headErr != nil || readAbortErr != nil || readHeadErr != nil ||
			abortInfo.Mode().Perm() != 0o600 || !exactGCPrivateOwnedRegular(abortInfo) ||
			!exactGCPrivateOwnedRegular(headInfo) || !bytes.Equal(abortBytes, []byte("1")) ||
			!bytes.Equal(headBytes, []byte("0")) {
			t.Fatal("Close wrote through an attacker-controlled abort hardlink")
		}
	})

	t.Run("symlink-swap", func(t *testing.T) {
		binding := formalGLMRegisteredPhase20JobTransportTestBindingV1("swap")
		transport := formalGLMRegisteredPhase20JobTransportTestOpenV1(
			t, root, binding, "local-peer-0",
			formalGLMRegisteredPhase20JobTransportTestEpochV1(
				formalGLMRegisteredPhase20JobRunTransportV1, "swap/signed-basis"))
		if err := transport.BindPeerEpochV1(transport.epochSHA256); err != nil {
			t.Fatal(err)
		}
		original, moved := transport.scratchPath, transport.scratchPath+"-moved"
		if err := os.Rename(original, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(moved, original); err != nil {
			_ = os.Rename(moved, original)
			t.Fatal(err)
		}
		defer func() {
			_ = os.Remove(original)
			_ = os.Rename(moved, original)
		}()
		if _, err := transport.Poll(0); err == nil {
			t.Fatal("symlink-swapped scratch path was accepted")
		}
	})
}

func TestFormalGLMRegisteredPhase20JobTransportCloseWaitsForInflightIO(
	t *testing.T,
) {
	root, _ := formalGLMRegisteredPhase20JobTransportTestRootV1(t)
	for _, operation := range []string{"read", "write"} {
		t.Run(operation, func(t *testing.T) {
			binding := formalGLMRegisteredPhase20JobTransportTestBindingV1(
				"close-" + operation)
			transport := formalGLMRegisteredPhase20JobTransportTestOpenV1(
				t, root, binding, "local-peer-0",
				formalGLMRegisteredPhase20JobTransportTestEpochV1(
					formalGLMRegisteredPhase20JobRunTransportV1,
					"close-"+operation+"/signed-basis"))
			if err := transport.BindPeerEpochV1(transport.epochSHA256); err != nil {
				t.Fatal(err)
			}
			ioDone := make(chan error, 1)
			if operation == "write" {
				transport.spool.maxBytes = 1
				if _, err := transport.Write([]byte("a")); err != nil {
					t.Fatal(err)
				}
			}
			go func() {
				if operation == "read" {
					var one [1]byte
					_, err := transport.Read(one[:])
					ioDone <- err
					return
				}
				_, err := transport.Write([]byte("b"))
				ioDone <- err
			}()
			formalGLMRegisteredPhase20JobTransportTestWaitForBlockedIOV1(
				t, transport, operation)
			closeDone := make(chan error, 1)
			go func() { closeDone <- transport.Close() }()
			select {
			case err := <-ioDone:
				if err == nil {
					t.Fatal("in-flight I/O succeeded after Close")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Close did not abort in-flight I/O")
			}
			select {
			case err := <-closeDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Close did not wait for its I/O lease")
			}
		})
	}
}
