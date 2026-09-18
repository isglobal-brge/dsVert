package main

import (
	"bytes"
	"encoding/base64"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCrossGridAuthenticatedCircuitCache(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		t.Run(family, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			cache := &crossGridCircuitCache{Directory: dir, Key: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{37}, 32))}
			p := crossGridKernelTestPlan(family)
			before := time.Now()
			cold, err := crossGridKernelPrepareCached(p, cache)
			if err != nil {
				t.Fatal(err)
			}
			coldTime := time.Since(before)
			entries, _ := os.ReadDir(dir)
			if len(entries) != 1 {
				t.Fatal("cache shape rejected")
			}
			path := filepath.Join(dir, entries[0].Name())
			old, _ := os.Stat(path)
			p.Beta[0][0] = "0" // Private multiplication changes, public topology does not.
			before = time.Now()
			hot, err := crossGridKernelPrepareCached(p, cache)
			if err != nil {
				t.Fatal(err)
			}
			hotTime := time.Since(before)
			current, _ := os.Stat(path)
			if !current.ModTime().Equal(old.ModTime()) || hot.plan.Beta[0][0] != "0" || cold.plan.Beta[0][0] == "0" {
				t.Fatal("cache did not preserve the admitted plan")
			}
			var first, second bytes.Buffer
			if cold.circuit.Marshal(&first) != nil || hot.circuit.Marshal(&second) != nil || !bytes.Equal(first.Bytes(), second.Bytes()) {
				t.Fatal("cached topology changed")
			}
			x := crossGridKernelTestSource(p, rand.New(rand.NewSource(170)))
			crossGridKernelProtocolTest(t, hot, x, "authenticated-cache/"+family)
			t.Logf("cold_seconds=%.6f hot_seconds=%.6f bytes=%d", coldTime.Seconds(), hotTime.Seconds(), current.Size())
			saved, _ := os.ReadFile(path)
			wrong := *cache
			wrong.Key = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{38}, 32))
			if _, err = crossGridKernelPrepareCached(p, &wrong); err != errCrossGridKernel {
				t.Fatal("changed cache authority accepted")
			}
			corrupted := append([]byte(nil), saved...)
			corrupted[len(corrupted)-1] ^= 1
			if os.WriteFile(path, corrupted, 0600) != nil {
				t.Fatal("test cache write rejected")
			}
			if _, err = crossGridKernelPrepareCached(p, cache); err != errCrossGridKernel {
				t.Fatal("cache tamper accepted")
			}
			if os.WriteFile(path, saved[:16], 0600) != nil {
				t.Fatal("test cache write rejected")
			}
			if _, err = crossGridKernelPrepareCached(p, cache); err != errCrossGridKernel {
				t.Fatal("truncated cache accepted")
			}
			if os.Remove(path) != nil || os.Symlink("missing", path) != nil {
				t.Fatal("test cache link rejected")
			}
			if _, err = crossGridKernelPrepareCached(p, cache); err != errCrossGridKernel {
				t.Fatal("cache symlink accepted")
			}
			if os.Remove(path) != nil || os.Chmod(dir, 0755) != nil {
				t.Fatal("test cache mode rejected")
			}
			if _, err = crossGridKernelPrepareCached(p, cache); err != errCrossGridKernel {
				t.Fatal("public cache directory accepted")
			}
		})
	}
}
