//go:build !darwin || !cgo

package provider

import "errors"

func preparePlatformAcquisitionSession(targets databaseTargets, options acquireOptions) acquisitionPlatformSession {
	return nil
}

func runPlatformHookWatchdog(args []string) error {
	return errors.New("platform hook watchdog is unavailable on this build")
}
