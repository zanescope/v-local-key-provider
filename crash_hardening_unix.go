//go:build darwin || linux

package provider

import "golang.org/x/sys/unix"

func hardenPlatformCrashReporting() error {
	return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}

func platformExcludeSensitiveMemory(_ []byte) func() { return nil }
