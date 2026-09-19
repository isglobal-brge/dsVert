//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package main

import (
	"os"
	"syscall"
)

func exactGCOpenOffsetSnapshot(path string) (*os.File, error) {
	// Pin one inode without following a terminal symlink. Atomic replacement
	// may unlink this inode after open; its complete contents remain readable.
	// NONBLOCK lets the caller reject a FIFO instead of blocking in open.
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

func exactGCPrivateOwnedOffsetSnapshot(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink <= 1
}
