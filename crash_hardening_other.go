//go:build !darwin && !linux && !windows

package provider

func hardenPlatformCrashReporting() error { return nil }

func platformExcludeSensitiveMemory(_ []byte) func() { return nil }
