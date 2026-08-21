package main

// One exact-GC transcript may have only one live owner.  This lease burns a
// private, attempt-scoped slot before the caller creates its spool.  A crash
// therefore requires a fresh worker attempt; it must never resume a partially
// exchanged GC transcript from a second process.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
)

const formalCoxBlockwiseExchangeLeaseDomain = "dsVert/formal-cox/blockwise-exchange-lease/v1"

var (
	errFormalCoxBlockwiseExchangeLeaseBurned = errors.New("formal-cox: exact-gc exchange attempt is already burned")
	errFormalCoxBlockwiseExchangeLeaseBusy   = errors.New("formal-cox: exact-gc exchange attempt already has a live owner")
)

type formalCoxBlockwiseExchangeLease struct {
	mu       sync.Mutex
	root     *os.Root
	rootPath string
	lock     *os.File
	claimed  bool
	closed   bool
}

func formalCoxBlockwiseExchangeLeaseLockSupported() bool {
	switch runtime.GOOS {
	case "aix", "darwin", "dragonfly", "freebsd", "linux", "netbsd", "openbsd", "solaris":
		return true
	default:
		return false
	}
}

func formalCoxBlockwiseExchangeLeaseSlot(plan formalCoxBlockwisePlan,
	peer string, attempt [32]byte) (string, error) {
	if _, err := formalCoxBlockwiseValidateShape(plan); err != nil {
		return "", err
	}
	if peer != plan.Policy.ComputePeers[0] && peer != plan.Policy.ComputePeers[1] {
		return "", fmt.Errorf("formal-cox: exchange lease peer is not a compute role")
	}
	planSHA256, err := formalCoxBlockwisePlanSHA256(plan)
	if err != nil || !formalCoxIsSHA256(planSHA256) {
		return "", fmt.Errorf("formal-cox: exchange lease plan is invalid")
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(formalCoxBlockwiseExchangeLeaseDomain + "|"))
	_, _ = hash.Write([]byte(planSHA256))
	_, _ = hash.Write([]byte("|" + peer + "|"))
	_, _ = hash.Write(attempt[:])
	return "exact-gc-attempt-" + hex.EncodeToString(hash.Sum(nil)), nil
}

func formalCoxBlockwiseExchangeLeaseValidateDir(root *os.Root, path string) error {
	if root == nil || path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("formal-cox: exchange lease directory is unavailable")
	}
	opened, openErr := root.Stat(".")
	current, pathErr := os.Lstat(path)
	if openErr != nil || pathErr != nil || !opened.IsDir() || !current.IsDir() ||
		current.Mode()&os.ModeSymlink != 0 || current.Mode().Perm() != 0o700 ||
		!formalFinalizerHandoffPrivateOwnedDirectory(current) ||
		!os.SameFile(opened, current) {
		return fmt.Errorf("formal-cox: exchange lease directory changed or is unsafe")
	}
	return nil
}

func formalCoxBlockwiseExchangeLeaseSyncRoot(root *os.Root) error {
	if root == nil {
		return fmt.Errorf("formal-cox: exchange lease root is unavailable")
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func formalCoxBlockwiseExchangeLeaseInspectExisting(parent *os.Root, slot string) error {
	child, err := parent.OpenRoot(slot)
	if err != nil {
		return fmt.Errorf("formal-cox: exchange lease slot is unsafe")
	}
	defer child.Close()
	info, err := child.Stat(".")
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 ||
		!formalFinalizerHandoffPrivateOwnedDirectory(info) {
		return fmt.Errorf("formal-cox: exchange lease slot is unsafe")
	}
	lock, err := child.OpenFile("owner.lock", os.O_RDWR, 0o600)
	if os.IsNotExist(err) {
		return errFormalCoxBlockwiseExchangeLeaseBurned
	}
	if err != nil {
		return fmt.Errorf("formal-cox: exchange lease lock is unsafe")
	}
	defer lock.Close()
	opened, openErr := lock.Stat()
	current, pathErr := child.Lstat("owner.lock")
	if openErr != nil || pathErr != nil || !current.Mode().IsRegular() ||
		current.Mode()&os.ModeSymlink != 0 || current.Mode().Perm() != 0o600 ||
		!exactGCPrivateOwnedRegular(current) || !os.SameFile(opened, current) {
		return fmt.Errorf("formal-cox: exchange lease lock is unsafe")
	}
	if err := formalFinalizerHandoffTryAuthorityLock(lock); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return errFormalCoxBlockwiseExchangeLeaseBusy
		}
		return fmt.Errorf("formal-cox: exchange lease lock failed: %w", err)
	}
	_ = formalFinalizerHandoffUnlockAuthority(lock)
	return errFormalCoxBlockwiseExchangeLeaseBurned
}

// openFormalCoxBlockwiseExchangeLease creates the only legal spool owner for
// one pending worker attempt.  It intentionally never reopens a prior slot:
// the checkpoint layer will mint a fresh attempt after an interrupted GC run.
func openFormalCoxBlockwiseExchangeLease(parentPath string,
	plan formalCoxBlockwisePlan, peer string, attempt [32]byte,
) (*formalCoxBlockwiseExchangeLease, error) {
	if !formalCoxBlockwiseExchangeLeaseLockSupported() ||
		formalCoxBlockwiseSourceEnsurePrivateDir(parentPath) != nil {
		return nil, fmt.Errorf("formal-cox: exchange lease requires a private lock-capable Rock directory")
	}
	slot, err := formalCoxBlockwiseExchangeLeaseSlot(plan, peer, attempt)
	if err != nil {
		return nil, err
	}
	parent, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*formalCoxBlockwiseExchangeLease, error) {
		_ = parent.Close()
		return nil, cause
	}
	if err := formalCoxBlockwiseExchangeLeaseValidateDir(parent, parentPath); err != nil {
		return fail(err)
	}
	if err := parent.Mkdir(slot, 0o700); err != nil {
		if os.IsExist(err) {
			inspectErr := formalCoxBlockwiseExchangeLeaseInspectExisting(parent, slot)
			return fail(inspectErr)
		}
		return fail(err)
	}
	if err := formalCoxBlockwiseExchangeLeaseSyncRoot(parent); err != nil {
		return fail(err)
	}
	child, err := parent.OpenRoot(slot)
	if err != nil {
		return fail(err)
	}
	_ = parent.Close()
	path := child.Name()
	lease := &formalCoxBlockwiseExchangeLease{root: child, rootPath: path}
	failLease := func(cause error) (*formalCoxBlockwiseExchangeLease, error) {
		_ = child.Close()
		return nil, cause
	}
	if err := formalCoxBlockwiseExchangeLeaseValidateDir(child, path); err != nil {
		return failLease(err)
	}
	lock, err := child.OpenFile("owner.lock", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return failLease(err)
	}
	if err := lock.Chmod(0o600); err != nil {
		_ = lock.Close()
		return failLease(err)
	}
	if err := lock.Sync(); err != nil {
		_ = lock.Close()
		return failLease(err)
	}
	opened, openErr := lock.Stat()
	current, pathErr := child.Lstat("owner.lock")
	if openErr != nil || pathErr != nil || !current.Mode().IsRegular() ||
		current.Mode().Perm() != 0o600 || !exactGCPrivateOwnedRegular(current) ||
		!os.SameFile(opened, current) {
		_ = lock.Close()
		return failLease(fmt.Errorf("formal-cox: exchange lease lock changed"))
	}
	if err := formalFinalizerHandoffTryAuthorityLock(lock); err != nil {
		_ = lock.Close()
		return failLease(fmt.Errorf("formal-cox: exchange lease lock failed: %w", err))
	}
	if err := formalCoxBlockwiseExchangeLeaseSyncRoot(child); err != nil {
		formalCoxBlockwiseExchangeLeaseRelease(lock)
		return failLease(err)
	}
	lease.lock = lock
	return lease, nil
}

func formalCoxBlockwiseExchangeLeaseRelease(lock *os.File) {
	if lock != nil {
		_ = formalFinalizerHandoffUnlockAuthority(lock)
		_ = lock.Close()
	}
}

// Dir is package-private on purpose: it supplies the owner-only spool path to
// the future worker controller, never to a command or a client DTO.
func (lease *formalCoxBlockwiseExchangeLease) Dir() (string, error) {
	if lease == nil {
		return "", fmt.Errorf("formal-cox: exchange lease is closed")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.root == nil || lease.lock == nil || lease.closed ||
		formalCoxBlockwiseExchangeLeaseValidateDir(lease.root, lease.rootPath) != nil {
		return "", fmt.Errorf("formal-cox: exchange lease is closed")
	}
	return lease.rootPath, nil
}

// claimTransportRoot transfers the sole live lease to the in-process spool
// owner. It is deliberately private: a command may relay immutable segments,
// but must never obtain an os.Root capable of creating a second spool.
func (lease *formalCoxBlockwiseExchangeLease) claimTransportRoot() (*os.Root, string, error) {
	if lease == nil {
		return nil, "", fmt.Errorf("formal-cox: exchange lease is closed")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.root == nil || lease.lock == nil || lease.closed || lease.claimed ||
		formalCoxBlockwiseExchangeLeaseValidateDir(lease.root, lease.rootPath) != nil {
		return nil, "", fmt.Errorf("formal-cox: exchange lease is unavailable")
	}
	child, err := os.OpenRoot(lease.rootPath)
	if err != nil {
		return nil, "", err
	}
	owned, ownedErr := lease.root.Stat(".")
	opened, openedErr := child.Stat(".")
	if ownedErr != nil || openedErr != nil || !os.SameFile(owned, opened) ||
		formalCoxBlockwiseExchangeLeaseValidateDir(child, lease.rootPath) != nil {
		_ = child.Close()
		return nil, "", fmt.Errorf("formal-cox: exchange lease directory changed")
	}
	lease.claimed = true
	return child, lease.rootPath, nil
}

func (lease *formalCoxBlockwiseExchangeLease) releaseTransportClaim() error {
	if lease == nil {
		return nil
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return nil
	}
	lease.claimed = false
	lease.closed = true
	formalCoxBlockwiseExchangeLeaseRelease(lease.lock)
	lease.lock = nil
	if lease.root != nil {
		err := lease.root.Close()
		lease.root = nil
		return err
	}
	return nil
}

func (lease *formalCoxBlockwiseExchangeLease) validTransportClaim() bool {
	if lease == nil {
		return false
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.root == nil || lease.lock == nil || lease.closed || !lease.claimed ||
		formalCoxBlockwiseExchangeLeaseValidateDir(lease.root, lease.rootPath) != nil {
		return false
	}
	opened, openErr := lease.lock.Stat()
	current, pathErr := lease.root.Lstat("owner.lock")
	return openErr == nil && pathErr == nil && current.Mode().IsRegular() &&
		current.Mode()&os.ModeSymlink == 0 && current.Mode().Perm() == 0o600 &&
		exactGCPrivateOwnedRegular(current) && os.SameFile(opened, current)
}

func (lease *formalCoxBlockwiseExchangeLease) Close() error {
	if lease == nil {
		return nil
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return nil
	}
	if lease.claimed {
		return fmt.Errorf("formal-cox: exchange lease is owned by a live spool")
	}
	lease.closed = true
	formalCoxBlockwiseExchangeLeaseRelease(lease.lock)
	lease.lock = nil
	if lease.root != nil {
		err := lease.root.Close()
		lease.root = nil
		return err
	}
	return nil
}
