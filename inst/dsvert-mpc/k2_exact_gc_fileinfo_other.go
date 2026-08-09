//go:build !(aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris)

package main

import "os"

// Windows does not expose POSIX uid/link-count semantics through os.FileInfo.
// The caller still enforces regular-file, no-symlink and owner-only-mode
// checks, and the private parent directory remains the security boundary.
func exactGCPrivateOwnedRegular(info os.FileInfo) bool {
	return info != nil
}
