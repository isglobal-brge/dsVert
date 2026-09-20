//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExactGCOffsetSnapshotPinsReplacedInode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "offset")
	if err := os.WriteFile(path, []byte("12"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := exactGCOpenOffsetSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := exactGCWriteOffset(path, 34); err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil || !exactGCPrivateOwnedOffsetSnapshot(info) {
		t.Fatalf("replaced private inode lost snapshot validity: %v", err)
	}
	data, err := io.ReadAll(file)
	if err != nil || string(data) != "12" {
		t.Fatalf("pinned snapshot changed: %q / %v", data, err)
	}
	if value, err := exactGCReadOffset(path); err != nil || value != 34 {
		t.Fatalf("new snapshot: %d / %v", value, err)
	}
}

func TestExactGCOffsetSnapshotRejectsUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "public", "empty", "noncanonical", "negative", "oversized", "out-of-range"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "offset")
			value := "0"
			switch kind {
			case "empty":
				value = ""
			case "noncanonical":
				value = "01"
			case "negative":
				value = "-1"
			case "oversized":
				value = strings.Repeat("0", 33)
			case "out-of-range":
				value = "9007199254740993"
			}
			if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				if err := os.Symlink(path, path+"-link"); err != nil {
					t.Fatal(err)
				}
				path += "-link"
			case "hardlink":
				if err := os.Link(path, path+"-link"); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if value, err := exactGCReadOffset(path); err == nil {
				t.Fatalf("accepted unsafe %s offset: %d", kind, value)
			}
		})
	}
}
