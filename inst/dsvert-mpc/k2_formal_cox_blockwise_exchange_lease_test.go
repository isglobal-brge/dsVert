package main

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func formalCoxBlockwiseExchangeLeaseTestAttempt(label string) [32]byte {
	return sha256.Sum256([]byte("formal-cox-exchange-lease-test/" + label))
}

func TestFormalCoxBlockwiseExchangeLeaseBurnsAttemptsK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+string(rune('0'+custodians)), func(t *testing.T) {
			plan, _, _ := formalCoxBlockwiseWorkerTestPlan(t, custodians, 2)
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			attempt := formalCoxBlockwiseExchangeLeaseTestAttempt(t.Name())
			lease, err := openFormalCoxBlockwiseExchangeLease(
				root, plan, plan.Policy.ComputePeers[0], attempt)
			if err != nil {
				t.Fatal(err)
			}
			dir, err := lease.Dir()
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(dir)
			if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 ||
				!formalFinalizerHandoffPrivateOwnedDirectory(info) {
				t.Fatal("exchange attempt slot is not private")
			}
			lock, err := os.Lstat(filepath.Join(dir, "owner.lock"))
			if err != nil || !lock.Mode().IsRegular() || lock.Mode().Perm() != 0o600 ||
				!exactGCPrivateOwnedRegular(lock) {
				t.Fatal("exchange attempt lock is not private")
			}
			if _, err := openFormalCoxBlockwiseExchangeLease(
				root, plan, plan.Policy.ComputePeers[0], attempt); !errors.Is(
				err, errFormalCoxBlockwiseExchangeLeaseBusy) {
				t.Fatalf("second live owner error = %v, want busy", err)
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := openFormalCoxBlockwiseExchangeLease(
				root, plan, plan.Policy.ComputePeers[0], attempt); !errors.Is(
				err, errFormalCoxBlockwiseExchangeLeaseBurned) {
				t.Fatalf("reused attempt error = %v, want burned", err)
			}
			fresh := formalCoxBlockwiseExchangeLeaseTestAttempt(t.Name() + "/fresh")
			freshLease, err := openFormalCoxBlockwiseExchangeLease(
				root, plan, plan.Policy.ComputePeers[0], fresh)
			if err != nil {
				t.Fatal(err)
			}
			if err := freshLease.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFormalCoxBlockwiseExchangeLeaseRacesAndFailsClosed(t *testing.T) {
	plan, _, _ := formalCoxBlockwiseWorkerTestPlan(t, 2, 2)
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	attempt := formalCoxBlockwiseExchangeLeaseTestAttempt(t.Name())
	start := make(chan struct{})
	var group sync.WaitGroup
	type result struct {
		lease *formalCoxBlockwiseExchangeLease
		err   error
	}
	results := make(chan result, 2)
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			lease, err := openFormalCoxBlockwiseExchangeLease(
				root, plan, plan.Policy.ComputePeers[0], attempt)
			results <- result{lease: lease, err: err}
		}()
	}
	close(start)
	group.Wait()
	close(results)
	var winner *formalCoxBlockwiseExchangeLease
	for result := range results {
		if result.lease != nil {
			if winner != nil {
				t.Fatal("two owners acquired one exact-GC attempt")
			}
			winner = result.lease
			continue
		}
		if !errors.Is(result.err, errFormalCoxBlockwiseExchangeLeaseBusy) &&
			!errors.Is(result.err, errFormalCoxBlockwiseExchangeLeaseBurned) {
			t.Fatalf("racing owner error = %v", result.err)
		}
	}
	if winner == nil {
		t.Fatal("no owner acquired the fresh exact-GC attempt")
	}
	dir, err := winner.Dir()
	if err != nil {
		t.Fatal(err)
	}
	if err := winner.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "owner.lock"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := openFormalCoxBlockwiseExchangeLease(
		root, plan, plan.Policy.ComputePeers[0], attempt); err == nil ||
		errors.Is(err, errFormalCoxBlockwiseExchangeLeaseBurned) ||
		errors.Is(err, errFormalCoxBlockwiseExchangeLeaseBusy) {
		t.Fatalf("unsafe old lock error = %v, want fail closed", err)
	}
	if _, err := openFormalCoxBlockwiseExchangeLease(
		root, plan, "not-a-compute-peer", formalCoxBlockwiseExchangeLeaseTestAttempt("other")); err == nil {
		t.Fatal("non-compute peer acquired exchange lease")
	}
	link := filepath.Join(t.TempDir(), "unsafe-root")
	if err := os.Symlink(root, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := openFormalCoxBlockwiseExchangeLease(
		link, plan, plan.Policy.ComputePeers[0], formalCoxBlockwiseExchangeLeaseTestAttempt("link")); err == nil {
		t.Fatal("symbolic-link exchange root was accepted")
	}
}
