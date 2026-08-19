//go:build !(aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris)

package main

import (
	"fmt"
	"os"
)

func formalFinalizerHandoffTryAuthorityLock(file *os.File) error {
	return fmt.Errorf("typed-finalizer-handoff: authority lock is unavailable")
}

func formalFinalizerHandoffUnlockAuthority(file *os.File) error {
	return nil
}
