//go:build !(aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris)

package main

import (
	"fmt"
	"os"
	"runtime"
)

func exactGCOpenOffsetSnapshot(path string) (*os.File, error) {
	// Platforms without O_NOFOLLOW retain pathname/descriptor identity checks.
	for attempt := 0; attempt < 8; attempt++ {
		before, err := os.Lstat(path)
		if os.IsNotExist(err) {
			runtime.Gosched()
			continue
		}
		if err != nil {
			return nil, err
		}
		if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("unsafe exact-gc offset state")
		}
		file, err := os.Open(path)
		if os.IsNotExist(err) {
			runtime.Gosched()
			continue
		}
		if err != nil {
			return nil, err
		}
		opened, err := file.Stat()
		if err == nil && os.SameFile(before, opened) {
			return file, nil
		}
		_ = file.Close()
		runtime.Gosched()
	}
	return nil, fmt.Errorf("exact-gc offset state changed continuously")
}

func exactGCPrivateOwnedOffsetSnapshot(info os.FileInfo) bool {
	return exactGCPrivateOwnedRegular(info)
}
