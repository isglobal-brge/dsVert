//go:build !(aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris)

package main

import "os"

func formalFinalizerHandoffPrivateOwnedDirectory(info os.FileInfo) bool {
	return info != nil
}
