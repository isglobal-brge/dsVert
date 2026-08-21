//go:build !(aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris)

package main

import "os"

// Non-Unix platforms have no O_NOFOLLOW equivalent in the standard library.
// They fail closed at formalFinalizerHandoffTryAuthorityLock before the source
// producer can publish anything; the post-open SameFile validation still
// rejects a replacement or link.
func formalCoxBlockwiseSourceOwnerOpenFlags() int {
	return os.O_RDWR
}
