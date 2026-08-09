package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	exactGCSegmentSpoolVersion = "dsvert-exact-gc-segment-spool-v1"
	exactGCInboundStateInitial = "dsvert-exact-gc-inbound-state-v1|0|-|-|-"
	exactGCMaxAbsoluteOffset   = int64(1 << 53)
)

var exactGCSegmentNameRE = regexp.MustCompile(
	`^segment-([0-9]{16})-([0-9]{16})-([0-9a-f]{64})\.bin$`)

var errExactGCSegmentChanged = errors.New("exact-gc segment changed concurrently")

type exactGCSegment struct {
	name  string
	path  string
	start int64
	end   int64
	hash  string
	size  int64
}

func exactGCSegmentName(start, end int64, hash string) (string, error) {
	if start < 0 || end <= start || end > exactGCMaxAbsoluteOffset ||
		len(hash) != 64 {
		return "", fmt.Errorf("invalid exact-gc segment descriptor")
	}
	if _, err := hex.DecodeString(hash); err != nil || hash != strings.ToLower(hash) {
		return "", fmt.Errorf("invalid exact-gc segment hash")
	}
	return fmt.Sprintf("segment-%016d-%016d-%s.bin", start, end, hash), nil
}

func exactGCListSegments(dir string) ([]exactGCSegment, error) {
	for attempt := 0; attempt < 3; attempt++ {
		segments, changed, err := exactGCListSegmentsSnapshot(dir)
		if err != nil {
			return nil, err
		}
		if !changed {
			return segments, nil
		}
	}
	return nil, fmt.Errorf("exact-gc segment spool changed continuously")
}

func exactGCListSegmentsSnapshot(dir string) ([]exactGCSegment, bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, false, fmt.Errorf("inspect exact-gc segment spool: %w", err)
	}
	segments := make([]exactGCSegment, 0, len(entries))
	changed := false
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".exact-gc-segment-") ||
			strings.HasPrefix(name, ".exact-gc-state-") {
			continue
		}
		match := exactGCSegmentNameRE.FindStringSubmatch(name)
		if len(match) != 4 {
			return nil, false, fmt.Errorf("unexpected exact-gc segment artifact")
		}
		start, err := strconv.ParseInt(match[1], 10, 64)
		if err != nil {
			return nil, false, fmt.Errorf("invalid exact-gc segment offset")
		}
		end, err := strconv.ParseInt(match[2], 10, 64)
		if err != nil {
			return nil, false, fmt.Errorf("invalid exact-gc segment end")
		}
		canonical, err := exactGCSegmentName(start, end, match[3])
		if err != nil || canonical != name {
			return nil, false, fmt.Errorf("non-canonical exact-gc segment name")
		}
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			// The R relay may have just reclaimed an acknowledged outbound
			// segment. Retry one coherent directory snapshot instead of turning
			// safe concurrent compaction into a worker failure.
			changed = true
			continue
		}
		if err != nil || !info.Mode().IsRegular() ||
			info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
			info.Size() != end-start {
			return nil, false, fmt.Errorf("unsafe or truncated exact-gc segment")
		}
		if !exactGCPrivateOwnedRegular(info) {
			// Atomic consumption can unlink the inode between ReadDir and
			// Lstat, yielding a safe nlink=0 snapshot. A persistently unowned
			// or multiply-linked artifact still fails after bounded retries.
			changed = true
			continue
		}
		segments = append(segments, exactGCSegment{
			name: name, path: path, start: start, end: end,
			hash: match[3], size: info.Size(),
		})
	}
	sort.Slice(segments, func(i, j int) bool {
		if segments[i].start != segments[j].start {
			return segments[i].start < segments[j].start
		}
		return segments[i].end < segments[j].end
	})
	for i := 1; i < len(segments); i++ {
		if segments[i].start < segments[i-1].end {
			return nil, false, fmt.Errorf("overlapping exact-gc segments")
		}
	}
	return segments, changed, nil
}

func exactGCSegmentBytes(segments []exactGCSegment) (int64, error) {
	var total int64
	for _, segment := range segments {
		if segment.size < 0 || total > exactGCMaxAbsoluteOffset-segment.size {
			return 0, fmt.Errorf("invalid exact-gc retained segment size")
		}
		total += segment.size
	}
	return total, nil
}

func exactGCOpenVerifiedSegment(segment exactGCSegment) (*os.File, error) {
	before, err := os.Lstat(segment.path)
	if os.IsNotExist(err) {
		return nil, errExactGCSegmentChanged
	}
	if err != nil || !before.Mode().IsRegular() ||
		before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0o077 != 0 ||
		!exactGCPrivateOwnedRegular(before) || before.Size() != segment.size {
		return nil, fmt.Errorf("unsafe or truncated exact-gc segment")
	}
	file, err := os.Open(segment.path)
	if os.IsNotExist(err) {
		return nil, errExactGCSegmentChanged
	}
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, errExactGCSegmentChanged
	}
	// `before` authenticated this exact inode while it was linked. It may now
	// have nlink=0 because the consumer reclaimed it, but the open descriptor
	// remains an immutable, coherent snapshot until Close.
	hash := sha256.New()
	written, copyErr := io.Copy(hash, file)
	if copyErr != nil {
		_ = file.Close()
		return nil, copyErr
	}
	if written != segment.size || hex.EncodeToString(hash.Sum(nil)) != segment.hash {
		_ = file.Close()
		return nil, fmt.Errorf("exact-gc segment hash mismatch")
	}
	return file, nil
}

func exactGCVerifySegment(segment exactGCSegment) error {
	file, err := exactGCOpenVerifiedSegment(segment)
	if err != nil {
		return err
	}
	return file.Close()
}

func exactGCSyncDir(dir string) error {
	// Windows does not provide portable directory fsync semantics. Atomic
	// rename still prevents partial files; payload hashes fail closed if storage
	// loses a rename across a machine crash.
	if runtime.GOOS == "windows" {
		return nil
	}
	file, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = file.Sync()
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func exactGCAtomicReplace(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".exact-gc-state-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := exactGCWriteFull(tmp, data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return exactGCSyncDir(dir)
}

func exactGCReadOffset(path string) (int64, error) {
	name := filepath.Base(path)
	for attempt := 0; attempt < 8; attempt++ {
		before, err := os.Lstat(path)
		if os.IsNotExist(err) {
			runtime.Gosched()
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("unsafe exact-gc offset state %s: %w", name, err)
		}
		if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
			before.Mode().Perm()&0o077 != 0 || before.Size() < 1 ||
			before.Size() > 32 {
			return 0, fmt.Errorf(
				"unsafe exact-gc offset state %s: mode=%s size=%d",
				name, before.Mode(), before.Size())
		}
		if !exactGCPrivateOwnedRegular(before) {
			// A concurrent atomic replacement can make the old inode appear
			// unlinked. Never accept it by pathname; retry a fresh snapshot.
			runtime.Gosched()
			continue
		}
		file, err := os.Open(path)
		if os.IsNotExist(err) {
			runtime.Gosched()
			continue
		}
		if err != nil {
			return 0, err
		}
		opened, statErr := file.Stat()
		if statErr != nil {
			_ = file.Close()
			return 0, statErr
		}
		if !os.SameFile(before, opened) {
			_ = file.Close()
			runtime.Gosched()
			continue
		}
		data := make([]byte, opened.Size())
		_, readErr := io.ReadFull(file, data)
		closeErr := file.Close()
		if readErr != nil {
			return 0, readErr
		}
		if closeErr != nil {
			return 0, closeErr
		}
		value, parseErr := strconv.ParseInt(string(data), 10, 64)
		if parseErr != nil || value < 0 || value > exactGCMaxAbsoluteOffset ||
			strconv.FormatInt(value, 10) != string(data) {
			return 0, fmt.Errorf("invalid exact-gc offset state")
		}
		return value, nil
	}
	return 0, fmt.Errorf("exact-gc offset state %s changed continuously", name)
}

func exactGCWriteOffset(path string, value int64) error {
	if value < 0 || value > exactGCMaxAbsoluteOffset {
		return fmt.Errorf("invalid exact-gc offset state")
	}
	return exactGCAtomicReplace(path, []byte(strconv.FormatInt(value, 10)))
}

func exactGCPublishSegment(dir string, start int64, data []byte) (exactGCSegment, error) {
	if len(data) == 0 || start < 0 || int64(len(data)) > exactGCMaxAbsoluteOffset-start {
		return exactGCSegment{}, fmt.Errorf("invalid exact-gc segment payload")
	}
	end := start + int64(len(data))
	digest := sha256.Sum256(data)
	hash := hex.EncodeToString(digest[:])
	name, err := exactGCSegmentName(start, end, hash)
	if err != nil {
		return exactGCSegment{}, err
	}
	target := filepath.Join(dir, name)
	segments, err := exactGCListSegments(dir)
	if err != nil {
		return exactGCSegment{}, err
	}
	for _, segment := range segments {
		if segment.start == start && segment.end == end {
			if segment.name != name {
				return exactGCSegment{}, fmt.Errorf("conflicting exact-gc segment retry")
			}
			if err := exactGCVerifySegment(segment); err != nil &&
				!errors.Is(err, errExactGCSegmentChanged) {
				return exactGCSegment{}, err
			}
			return segment, nil
		}
		if segment.start < end && segment.end > start {
			return exactGCSegment{}, fmt.Errorf("conflicting exact-gc segment overlap")
		}
	}
	tmp, err := os.CreateTemp(dir, ".exact-gc-segment-")
	if err != nil {
		return exactGCSegment{}, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return exactGCSegment{}, err
	}
	if err := exactGCWriteFull(tmp, data); err != nil {
		_ = tmp.Close()
		return exactGCSegment{}, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return exactGCSegment{}, err
	}
	if err := tmp.Close(); err != nil {
		return exactGCSegment{}, err
	}
	if _, err := os.Lstat(target); err == nil {
		return exactGCSegment{}, fmt.Errorf("exact-gc segment appeared concurrently")
	} else if !os.IsNotExist(err) {
		return exactGCSegment{}, err
	}
	if err := os.Rename(tmpName, target); err != nil {
		return exactGCSegment{}, err
	}
	// Rename preserves the 0600 mode already applied to the private temporary
	// inode. Do not chmod by pathname after publication: the peer may consume
	// and unlink the segment immediately after the atomic rename, and that safe
	// race must not turn a completed write into a false failure.
	if err := exactGCSyncDir(dir); err != nil {
		return exactGCSegment{}, err
	}
	segment := exactGCSegment{
		name: name, path: target, start: start, end: end,
		hash: hash, size: int64(len(data)),
	}
	// Ownership transfers at the atomic rename. The consumer verifies the
	// hash through its already-open descriptor and may legitimately reclaim
	// the segment immediately, before this publisher returns.
	return segment, nil
}

type exactGCSpoolRW struct {
	dir         string
	inboundDir  string
	outboundDir string
	readAt      int64
	writeAt     int64
	// Conservative between scans: this worker only adds segments, while the
	// relay can only remove acknowledged ones. The hot Write path is therefore
	// O(1); it rescans only at publication or on backpressure.
	outboundRetained int64
	maxBytes         int64
	ttl              time.Duration
	writeMu          sync.Mutex
	pending          []byte
	current          *exactGCSegment
	currentFile      *os.File
	// readWaiting is public protocol-flow state. A writer arriving while the
	// local party is waiting for its peer must be published immediately.
	readWaiting bool
}

func newExactGCSpoolRW(dir string, maxBytes int64, ttl time.Duration) (*exactGCSpoolRW, error) {
	readAt, err := exactGCReadOffset(filepath.Join(dir, "inbound.ack"))
	if err != nil {
		return nil, err
	}
	writeAt, err := exactGCReadOffset(filepath.Join(dir, "outbound.head"))
	if err != nil {
		return nil, err
	}
	outboundDir := filepath.Join(dir, "outbound.segments")
	segments, err := exactGCListSegments(outboundDir)
	if err != nil {
		return nil, err
	}
	retained, err := exactGCSegmentBytes(segments)
	if err != nil || retained > maxBytes {
		return nil, fmt.Errorf("exact-gc outbound spool limit exceeded")
	}
	return &exactGCSpoolRW{
		dir: dir, inboundDir: filepath.Join(dir, "inbound.segments"),
		outboundDir: outboundDir, readAt: readAt, writeAt: writeAt,
		outboundRetained: retained, maxBytes: maxBytes, ttl: ttl,
	}, nil
}

func (s *exactGCSpoolRW) Close() error {
	flushErr := s.Flush()
	var closeErr error
	if s.currentFile != nil {
		closeErr = s.currentFile.Close()
		s.currentFile = nil
		s.current = nil
	}
	if flushErr != nil {
		return flushErr
	}
	return closeErr
}

func (s *exactGCSpoolRW) loadInboundSegment(segments []exactGCSegment) error {
	for _, segment := range segments {
		if segment.end <= s.readAt {
			if err := os.Remove(segment.path); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		if segment.start > s.readAt {
			return fmt.Errorf("exact-gc inbound segment gap")
		}
		if segment.start <= s.readAt && segment.end > s.readAt {
			file, err := exactGCOpenVerifiedSegment(segment)
			if errors.Is(err, errExactGCSegmentChanged) {
				return errExactGCSegmentChanged
			}
			if err != nil {
				return err
			}
			s.current = &segment
			s.currentFile = file
			return nil
		}
	}
	return nil
}

func (s *exactGCSpoolRW) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// p2p writes asynchronously. Mark the read dependency before checking the
	// inbound spool so a concurrent writer flushes instead of leaving the peer
	// blocked behind a sub-chunk buffer.
	s.writeMu.Lock()
	s.readWaiting = true
	flushErr := s.flushOutboundLocked()
	s.writeMu.Unlock()
	if flushErr != nil {
		return 0, flushErr
	}
	defer func() {
		s.writeMu.Lock()
		s.readWaiting = false
		s.writeMu.Unlock()
	}()
	for {
		if _, err := os.Stat(filepath.Join(s.dir, "abort")); err == nil {
			return 0, fmt.Errorf("exact-gc worker aborted")
		}
		if err := s.checkHeartbeat(); err != nil {
			return 0, err
		}
		if s.current == nil {
			segments, err := exactGCListSegments(s.inboundDir)
			if err != nil {
				return 0, err
			}
			retained, err := exactGCSegmentBytes(segments)
			if err != nil || retained > s.maxBytes {
				return 0, fmt.Errorf("exact-gc inbound spool limit exceeded")
			}
			if err := s.loadInboundSegment(segments); err != nil {
				if errors.Is(err, errExactGCSegmentChanged) {
					continue
				}
				return 0, err
			}
		}
		if s.current != nil {
			want := int64(len(p))
			if available := s.current.end - s.readAt; available < want {
				want = available
			}
			n, err := s.currentFile.ReadAt(p[:want], s.readAt-s.current.start)
			if n > 0 {
				s.readAt += int64(n)
				if s.readAt == s.current.end {
					if err := exactGCWriteOffset(
						filepath.Join(s.dir, "inbound.ack"), s.readAt); err != nil {
						return 0, err
					}
					path := s.current.path
					if err := s.currentFile.Close(); err != nil {
						return 0, err
					}
					s.currentFile = nil
					s.current = nil
					if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
						return 0, err
					}
					if err := exactGCSyncDir(s.inboundDir); err != nil {
						return 0, err
					}
				}
				return n, nil
			}
			if err != nil && err != io.EOF {
				return 0, err
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (s *exactGCSpoolRW) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	for {
		additional := int64(len(s.pending)) + int64(len(p))
		if additional <= s.maxBytes-s.outboundRetained {
			break
		}
		// Publish already accepted pending bytes before waiting. This lets the
		// relay acknowledge them and turns the byte bound into actual TCP-like
		// backpressure instead of a fatal cumulative transcript limit.
		if len(s.pending) > 0 {
			if err := s.flushOutboundLocked(); err != nil {
				return 0, err
			}
			continue
		}
		if int64(len(p)) > s.maxBytes {
			return 0, fmt.Errorf("exact-gc outbound write exceeds spool capacity")
		}
		segments, err := exactGCListSegments(s.outboundDir)
		if err != nil {
			return 0, err
		}
		retained, err := exactGCSegmentBytes(segments)
		if err != nil || retained > s.maxBytes {
			return 0, fmt.Errorf("exact-gc outbound spool limit exceeded")
		}
		s.outboundRetained = retained
		if int64(len(p)) <= s.maxBytes-s.outboundRetained {
			continue
		}
		if _, err := os.Stat(filepath.Join(s.dir, "abort")); err == nil {
			return 0, fmt.Errorf("exact-gc worker aborted")
		}
		if err := s.checkHeartbeat(); err != nil {
			return 0, err
		}
		time.Sleep(2 * time.Millisecond)
	}
	s.pending = append(s.pending, p...)
	if len(s.pending) >= exactGCSpoolWriteBuffer || s.readWaiting {
		if err := s.flushOutboundLocked(); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Flush publishes all pending authenticated records in their original order.
// A segment is visible only after its complete content is synced and renamed;
// the absolute head advances in a second atomic commit.
func (s *exactGCSpoolRW) Flush() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.flushOutboundLocked()
}

func (s *exactGCSpoolRW) flushOutboundLocked() error {
	if len(s.pending) == 0 {
		return nil
	}
	end := s.writeAt + int64(len(s.pending))
	if end > exactGCMaxAbsoluteOffset {
		return fmt.Errorf("exact-gc outbound offset overflow")
	}
	if _, err := exactGCPublishSegment(s.outboundDir, s.writeAt, s.pending); err != nil {
		return err
	}
	segments, err := exactGCListSegments(s.outboundDir)
	if err != nil {
		return err
	}
	retained, err := exactGCSegmentBytes(segments)
	if err != nil || retained > s.maxBytes {
		return fmt.Errorf("exact-gc outbound spool limit exceeded")
	}
	s.outboundRetained = retained
	if err := exactGCWriteOffset(filepath.Join(s.dir, "outbound.head"), end); err != nil {
		return err
	}
	s.writeAt = end
	s.pending = s.pending[:0]
	return nil
}

func (s *exactGCSpoolRW) checkHeartbeat() error {
	info, err := os.Stat(filepath.Join(s.dir, "exchange.hb"))
	if err != nil {
		return fmt.Errorf("exact-gc relay heartbeat missing")
	}
	if time.Since(info.ModTime()) > s.ttl {
		return fmt.Errorf("exact-gc relay heartbeat expired")
	}
	return nil
}
