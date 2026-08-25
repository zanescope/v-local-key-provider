package provider

import "runtime/debug"

func hardenSensitiveProcess() error {
	// Protocol errors are deliberately redacted; a panic must not override that
	// policy with a full goroutine dump containing request buffers.
	debug.SetTraceback("none")
	return hardenPlatformCrashReporting()
}
