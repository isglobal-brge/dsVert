//go:build !(aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris)

package main

import (
	"fmt"
	"os"
)

func formalFinalizerHandoffTryAuthorityLock(file *os.File) error {
	return fmt.Errorf("typed-finalizer-handoff: authority lock is unavailable")
}

func formalFinalizerHandoffAuthorityLockBusyV1(err error) bool {
	return false
}

func formalFinalizerHandoffUnlockAuthority(file *os.File) error {
	return nil
}
