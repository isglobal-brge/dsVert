package main

// A live-only duplex transport for one already-bound Cox worker attempt.
// The lease owns the only exact-GC spool; this type can exchange immutable
// segmented ciphertext while that owner is alive, but intentionally has no
// reopen path. A worker crash burns the lease and requires a fresh attempt.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	formalCoxBlockwiseExchangeTransportMaxPayload = 1 << 20
	formalCoxBlockwiseExchangeTransportSpoolBytes = int64(16 << 20)
	formalCoxBlockwiseExchangeTransportTTL        = 2 * time.Minute
)

// All fields are private: a later authenticated command adapter may carry an
// opaque projection, but never a path, key, lease, or worker handle.
type formalCoxBlockwiseExchangeChunk struct {
	Sender        string
	Offset        int64
	PayloadSHA256 string
	Payload       []byte
}

type formalCoxBlockwiseExchangeTransport struct {
	mu  sync.Mutex
	ops sync.WaitGroup

	lease        *formalCoxBlockwiseExchangeLease
	root         *os.Root
	segmentRoots [2]*os.Root
	rootPath     string
	spool        *exactGCSpoolRW
	plan         formalCoxBlockwisePlan
	peer         string
	remotePeer   string
	peerBound    bool

	inboundAccepted int64
	lastInbound     *formalCoxBlockwiseExchangeChunk
	outboundAck     int64
	lastOffer       *formalCoxBlockwiseExchangeChunk
	closed          bool
	failed          bool
}

func formalCoxBlockwiseExchangeTransportWriteInitial(root *os.Root,
	name string, data []byte,
) error {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if err := exactGCWriteFull(file, data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	opened, openErr := file.Stat()
	closeErr := file.Close()
	current, pathErr := root.Lstat(name)
	if openErr != nil || closeErr != nil || pathErr != nil ||
		!current.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 ||
		current.Mode().Perm() != 0o600 || !exactGCPrivateOwnedRegular(current) ||
		!os.SameFile(opened, current) {
		return fmt.Errorf("formal-cox: exchange transport created unsafe record")
	}
	return nil
}

func formalCoxBlockwiseExchangeTransportValidate(root *os.Root, path string,
	segmentRoots [2]*os.Root,
) error {
	if formalCoxBlockwiseExchangeLeaseValidateDir(root, path) != nil {
		return fmt.Errorf("formal-cox: exchange transport root is unsafe")
	}
	for _, file := range []struct {
		name string
		size int64
	}{
		{"inbound.bin", 0}, {"outbound.bin", 0},
		{"exchange.hb", 1}, {"worker.hb", 1},
		{"inbound.state", int64(len(exactGCInboundStateInitial))},
	} {
		info, err := root.Lstat(file.name)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm() != 0o600 || info.Size() != file.size ||
			!exactGCPrivateOwnedRegular(info) {
			return fmt.Errorf("formal-cox: exchange transport record is unsafe")
		}
	}
	for _, name := range []string{"inbound.ack", "outbound.head", "outbound.ack"} {
		if _, err := exactGCReadOffset(filepath.Join(path, name)); err != nil {
			return err
		}
	}
	for index, name := range []string{"inbound.segments", "outbound.segments"} {
		if segmentRoots[index] == nil {
			return fmt.Errorf("formal-cox: exchange transport segment root is unavailable")
		}
		info, err := root.Lstat(name)
		opened, openErr := segmentRoots[index].Stat(".")
		if err != nil || openErr != nil || !info.IsDir() ||
			info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 ||
			!formalFinalizerHandoffPrivateOwnedDirectory(info) || !os.SameFile(info, opened) {
			return fmt.Errorf("formal-cox: exchange transport segment directory is unsafe")
		}
		if _, err := exactGCListSegments(segmentRoots[index].Name()); err != nil {
			return err
		}
	}
	if info, err := root.Lstat("abort"); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm() != 0o600 || info.Size() != 1 ||
			!exactGCPrivateOwnedRegular(info) {
			return fmt.Errorf("formal-cox: exchange transport abort record is unsafe")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func newFormalCoxBlockwiseExchangeTransport(lease *formalCoxBlockwiseExchangeLease,
	plan formalCoxBlockwisePlan, peer string,
) (*formalCoxBlockwiseExchangeTransport, error) {
	if _, err := formalCoxBlockwiseValidateShape(plan); err != nil ||
		(peer != plan.Policy.ComputePeers[0] && peer != plan.Policy.ComputePeers[1]) {
		return nil, fmt.Errorf("formal-cox: invalid exchange transport policy")
	}
	root, path, err := lease.claimTransportRoot()
	if err != nil {
		return nil, err
	}
	transport := &formalCoxBlockwiseExchangeTransport{
		lease: lease, root: root, rootPath: path, plan: plan, peer: peer,
	}
	fail := func(cause error) (*formalCoxBlockwiseExchangeTransport, error) {
		for _, child := range transport.segmentRoots {
			if child != nil {
				_ = child.Close()
			}
		}
		_ = root.Close()
		_ = lease.releaseTransportClaim()
		return nil, cause
	}
	files := []struct {
		name string
		data []byte
	}{
		{"inbound.bin", nil}, {"outbound.bin", nil},
		{"exchange.hb", []byte(".")}, {"worker.hb", []byte(".")},
		{"inbound.state", []byte(exactGCInboundStateInitial)},
		{"inbound.ack", []byte("0")}, {"outbound.head", []byte("0")},
		{"outbound.ack", []byte("0")},
	}
	for _, file := range files {
		if err := formalCoxBlockwiseExchangeTransportWriteInitial(
			root, file.name, file.data); err != nil {
			return fail(err)
		}
	}
	for _, name := range []string{"inbound.segments", "outbound.segments"} {
		if err := root.Mkdir(name, 0o700); err != nil {
			return fail(err)
		}
		if err := root.Chmod(name, 0o700); err != nil {
			return fail(err)
		}
	}
	for index, name := range []string{"inbound.segments", "outbound.segments"} {
		transport.segmentRoots[index], err = root.OpenRoot(name)
		if err != nil {
			return fail(err)
		}
	}
	if err := formalCoxBlockwiseExchangeLeaseSyncRoot(root); err != nil ||
		formalCoxBlockwiseExchangeTransportValidate(root, path, transport.segmentRoots) != nil ||
		exactGCPrepareWorkerSpool(path) != nil {
		if err != nil {
			return fail(err)
		}
		return fail(fmt.Errorf("formal-cox: exchange transport initialization is unsafe"))
	}
	transport.spool, err = newExactGCSpoolRW(path,
		formalCoxBlockwiseExchangeTransportSpoolBytes,
		formalCoxBlockwiseExchangeTransportTTL)
	if err != nil {
		return fail(err)
	}
	return transport, nil
}

func formalCoxBlockwiseExchangeTransportCloneChunk(
	chunk *formalCoxBlockwiseExchangeChunk,
) *formalCoxBlockwiseExchangeChunk {
	if chunk == nil {
		return nil
	}
	cloned := *chunk
	cloned.Payload = append([]byte(nil), chunk.Payload...)
	return &cloned
}

func (transport *formalCoxBlockwiseExchangeTransport) failLocked() {
	if transport == nil || transport.failed || transport.root == nil {
		return
	}
	transport.failed = true
	if _, err := transport.root.Lstat("abort"); os.IsNotExist(err) {
		_ = formalCoxBlockwiseExchangeTransportWriteInitial(transport.root, "abort", []byte("1"))
		_ = formalCoxBlockwiseExchangeLeaseSyncRoot(transport.root)
	}
}

func (transport *formalCoxBlockwiseExchangeTransport) validateLocked() error {
	if transport == nil || transport.closed || transport.root == nil ||
		transport.spool == nil || !transport.lease.validTransportClaim() ||
		formalCoxBlockwiseExchangeTransportValidate(
			transport.root, transport.rootPath, transport.segmentRoots) != nil {
		transport.failLocked()
		return fmt.Errorf("formal-cox: exchange transport is unavailable")
	}
	return nil
}

func (transport *formalCoxBlockwiseExchangeTransport) BindPeer(peer string) error {
	if transport == nil {
		return fmt.Errorf("formal-cox: exchange transport is unavailable")
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.validateLocked() != nil || transport.failed ||
		(peer != transport.plan.Policy.ComputePeers[0] &&
			peer != transport.plan.Policy.ComputePeers[1]) || peer == transport.peer ||
		transport.peerBound && transport.remotePeer != peer {
		transport.failLocked()
		return fmt.Errorf("formal-cox: exchange transport peer binding failed")
	}
	transport.remotePeer, transport.peerBound = peer, true
	return nil
}

func (transport *formalCoxBlockwiseExchangeTransport) beginOp() error {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.validateLocked() != nil || transport.failed || !transport.peerBound {
		return fmt.Errorf("formal-cox: exchange transport is not bound")
	}
	transport.ops.Add(1)
	return nil
}

func (transport *formalCoxBlockwiseExchangeTransport) endOp() { transport.ops.Done() }

func (transport *formalCoxBlockwiseExchangeTransport) Read(p []byte) (int, error) {
	if err := transport.beginOp(); err != nil {
		return 0, err
	}
	defer transport.endOp()
	n, err := transport.spool.Read(p)
	transport.mu.Lock()
	valid := transport.validateLocked()
	transport.mu.Unlock()
	if err != nil {
		return n, err
	}
	return n, valid
}

func (transport *formalCoxBlockwiseExchangeTransport) Write(p []byte) (int, error) {
	if err := transport.beginOp(); err != nil {
		return 0, err
	}
	defer transport.endOp()
	n, err := transport.spool.Write(p)
	transport.mu.Lock()
	valid := transport.validateLocked()
	transport.mu.Unlock()
	if err != nil {
		return n, err
	}
	return n, valid
}

func (transport *formalCoxBlockwiseExchangeTransport) touchLocked() error {
	if err := transport.validateLocked(); err != nil {
		return err
	}
	now := time.Now()
	if err := transport.root.Chtimes("exchange.hb", now, now); err != nil {
		transport.failLocked()
		return err
	}
	return transport.validateLocked()
}

func (transport *formalCoxBlockwiseExchangeTransport) tryFlushLocked() error {
	if !transport.spool.writeMu.TryLock() {
		return nil
	}
	err := transport.spool.flushOutboundLocked()
	transport.spool.writeMu.Unlock()
	return err
}

func (transport *formalCoxBlockwiseExchangeTransport) cleanupOutboundLocked(through int64) error {
	segments, err := exactGCListSegments(transport.segmentRoots[1].Name())
	if err != nil {
		return err
	}
	changed := false
	for _, segment := range segments {
		if segment.end <= through {
			if err := transport.segmentRoots[1].Remove(segment.name); err != nil && !os.IsNotExist(err) {
				return err
			}
			changed = true
		}
	}
	if changed {
		return formalCoxBlockwiseExchangeLeaseSyncRoot(transport.segmentRoots[1])
	}
	return nil
}

func (transport *formalCoxBlockwiseExchangeTransport) Poll(ack int64) (
	*formalCoxBlockwiseExchangeChunk, int64, error,
) {
	if transport == nil {
		return nil, 0, fmt.Errorf("formal-cox: exchange transport is unavailable")
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.validateLocked() != nil || transport.failed || !transport.peerBound {
		return nil, 0, fmt.Errorf("formal-cox: exchange transport is not bound")
	}
	if ack != transport.outboundAck {
		if transport.lastOffer == nil || ack != transport.lastOffer.Offset+int64(len(transport.lastOffer.Payload)) {
			transport.failLocked()
			return nil, 0, fmt.Errorf("formal-cox: non-exact exchange acknowledgement")
		}
		if err := exactGCWriteOffset(filepath.Join(transport.rootPath, "outbound.ack"), ack); err != nil ||
			transport.cleanupOutboundLocked(ack) != nil {
			transport.failLocked()
			return nil, 0, fmt.Errorf("formal-cox: exchange acknowledgement failed")
		}
		transport.outboundAck, transport.lastOffer = ack, nil
	}
	if transport.lastOffer != nil {
		return formalCoxBlockwiseExchangeTransportCloneChunk(transport.lastOffer),
			transport.inboundAccepted, nil
	}
	if err := transport.touchLocked(); err != nil || transport.tryFlushLocked() != nil {
		transport.failLocked()
		return nil, 0, fmt.Errorf("formal-cox: exchange poll failed")
	}
	head, err := exactGCReadOffset(filepath.Join(transport.rootPath, "outbound.head"))
	if err != nil || head < transport.outboundAck {
		transport.failLocked()
		return nil, 0, fmt.Errorf("formal-cox: exchange outbound head is invalid")
	}
	if head == transport.outboundAck {
		return nil, transport.inboundAccepted, nil
	}
	segments, err := exactGCListSegments(transport.segmentRoots[1].Name())
	if err != nil {
		transport.failLocked()
		return nil, 0, err
	}
	var selected *exactGCSegment
	for index := range segments {
		if segments[index].start <= transport.outboundAck &&
			segments[index].end > transport.outboundAck {
			selected = &segments[index]
			break
		}
	}
	if selected == nil {
		transport.failLocked()
		return nil, 0, fmt.Errorf("formal-cox: exchange outbound segment gap")
	}
	end := selected.end
	if end > head {
		end = head
	}
	if end-transport.outboundAck > formalCoxBlockwiseExchangeTransportMaxPayload {
		end = transport.outboundAck + formalCoxBlockwiseExchangeTransportMaxPayload
	}
	file, err := exactGCOpenVerifiedSegment(*selected)
	if err != nil {
		transport.failLocked()
		return nil, 0, err
	}
	payload := make([]byte, end-transport.outboundAck)
	n, readErr := file.ReadAt(payload, transport.outboundAck-selected.start)
	closeErr := file.Close()
	if n != len(payload) || readErr != nil && readErr != io.EOF || closeErr != nil {
		clear(payload)
		transport.failLocked()
		return nil, 0, fmt.Errorf("formal-cox: exchange outbound segment is truncated")
	}
	digest := sha256.Sum256(payload)
	transport.lastOffer = &formalCoxBlockwiseExchangeChunk{
		Sender: transport.peer, Offset: transport.outboundAck,
		PayloadSHA256: hex.EncodeToString(digest[:]), Payload: payload,
	}
	return formalCoxBlockwiseExchangeTransportCloneChunk(transport.lastOffer),
		transport.inboundAccepted, nil
}

func (transport *formalCoxBlockwiseExchangeTransport) Relay(
	chunk formalCoxBlockwiseExchangeChunk,
) (int64, error) {
	if transport == nil {
		return 0, fmt.Errorf("formal-cox: exchange transport is unavailable")
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	digest := sha256.Sum256(chunk.Payload)
	end := chunk.Offset + int64(len(chunk.Payload))
	if transport.validateLocked() != nil || transport.failed || !transport.peerBound ||
		chunk.Sender != transport.remotePeer || chunk.Offset < 0 || len(chunk.Payload) == 0 ||
		len(chunk.Payload) > formalCoxBlockwiseExchangeTransportMaxPayload ||
		end < chunk.Offset || end > exactGCMaxAbsoluteOffset ||
		chunk.PayloadSHA256 != hex.EncodeToString(digest[:]) {
		transport.failLocked()
		return 0, fmt.Errorf("formal-cox: invalid exchange relay chunk")
	}
	if chunk.Offset < transport.inboundAccepted {
		if transport.lastInbound != nil && chunk.Offset == transport.lastInbound.Offset &&
			end == transport.lastInbound.Offset+int64(len(transport.lastInbound.Payload)) &&
			chunk.PayloadSHA256 == transport.lastInbound.PayloadSHA256 {
			return transport.inboundAccepted, nil
		}
		transport.failLocked()
		return 0, fmt.Errorf("formal-cox: exchange relay overlap or fork")
	}
	if chunk.Offset != transport.inboundAccepted {
		transport.failLocked()
		return 0, fmt.Errorf("formal-cox: exchange relay gap")
	}
	if err := transport.touchLocked(); err != nil {
		return 0, err
	}
	segments, err := exactGCListSegments(transport.segmentRoots[0].Name())
	retained, sizeErr := exactGCSegmentBytes(segments)
	if err != nil || sizeErr != nil || int64(len(chunk.Payload)) >
		formalCoxBlockwiseExchangeTransportSpoolBytes-retained {
		return 0, fmt.Errorf("formal-cox: exchange relay backpressure")
	}
	if _, err := exactGCPublishSegment(transport.segmentRoots[0].Name(), chunk.Offset, chunk.Payload); err != nil {
		transport.failLocked()
		return 0, err
	}
	transport.lastInbound = formalCoxBlockwiseExchangeTransportCloneChunk(&chunk)
	transport.inboundAccepted = end
	return end, nil
}

func (transport *formalCoxBlockwiseExchangeTransport) Close() error {
	if transport == nil {
		return nil
	}
	transport.mu.Lock()
	if transport.closed {
		transport.mu.Unlock()
		return nil
	}
	transport.closed = true
	transport.failLocked()
	transport.mu.Unlock()
	transport.ops.Wait()
	if transport.spool != nil {
		transport.spool.writeMu.Lock()
		clear(transport.spool.pending)
		transport.spool.pending = nil
		transport.spool.writeMu.Unlock()
		if transport.spool.currentFile != nil {
			_ = transport.spool.currentFile.Close()
			transport.spool.currentFile = nil
			transport.spool.current = nil
		}
	}
	for _, root := range transport.segmentRoots {
		if root != nil {
			_ = root.Close()
		}
	}
	if transport.root != nil {
		_ = transport.root.Close()
	}
	transport.mu.Lock()
	transport.root, transport.spool = nil, nil
	if transport.lastOffer != nil {
		clear(transport.lastOffer.Payload)
	}
	if transport.lastInbound != nil {
		clear(transport.lastInbound.Payload)
	}
	transport.lastOffer, transport.lastInbound = nil, nil
	transport.mu.Unlock()
	return transport.lease.releaseTransportClaim()
}
