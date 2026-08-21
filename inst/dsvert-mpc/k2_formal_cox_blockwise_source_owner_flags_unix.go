//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package main

import (
	"os"
	"syscall"
)

// Keep the no-follow guarantee on supported production platforms. The source
// owner lock is opened only after Lstat, then rechecked by SameFile.
func formalCoxBlockwiseSourceOwnerOpenFlags() int {
	return os.O_RDWR | syscall.O_NOFOLLOW
}
