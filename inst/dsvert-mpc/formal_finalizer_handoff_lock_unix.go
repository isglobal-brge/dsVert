//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package main

import (
	"os"
	"syscall"
)

func formalFinalizerHandoffTryAuthorityLock(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

func formalFinalizerHandoffUnlockAuthority(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
