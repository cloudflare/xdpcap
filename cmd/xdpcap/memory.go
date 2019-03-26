package main

import (
	// syscall has a wonky RLIM_INFINITY, and no RLIMIT_MEMLOCK
	"golang.org/x/sys/unix"
)

// unlimitLockedMemory removes any locked memory limits
func unlimitLockedMemory() error {
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})
}
