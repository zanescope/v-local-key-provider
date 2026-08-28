//go:build darwin && cgo

package provider

import (
	daemonmodel "github.com/zanescope/v-local-key-provider/internal/daemon"
	darwinmodel "github.com/zanescope/v-local-key-provider/internal/platform/darwin"
)

type darwinPlatformRuntime struct {
	native darwinmodel.NativeDriver
	hook   *darwinmodel.HookDriver
}

func newDarwinPlatformRuntime() darwinPlatformRuntime {
	evidence := darwinmodel.NewEvidenceCollector(darwinmodel.EvidenceRuntime{
		RunOutput:             runBoundedDarwinOutput,
		RunCombinedOutput:     runBoundedDarwinCombinedOutput,
		ProcessExecutablePath: daemonmodel.ProcessExecutablePath,
		ExecutableSHA256:      executableSHA256,
		PathIsLinkOrReparse:   pathIsLinkOrReparse,
		SameCanonicalPath:     sameCanonicalPath,
		ClearSensitive:        zeroBytes,
	})
	native := darwinmodel.NewNativeDriver(darwinmodel.NativeRuntime{
		RunOutput:        runBoundedDarwinOutput,
		MarkSensitive:    markSensitiveBytes,
		ClearSensitive:   zeroBytes,
		CollectEvidence:  evidence.CollectEvidence,
		PrelaunchProcess: evidence.PrelaunchProcess,
	})
	hook := darwinmodel.NewHookDriver(darwinmodel.HookRuntime{
		Native:           native,
		Evidence:         evidence,
		Registry:         darwinCompatibilityRegistry,
		Policy:           darwinRoutePolicy(),
		SecurityPosture:  defaultSecurityPostureStatus,
		CleanEnvironment: darwinCleanEnvironment,
		RunCommand:       runDarwinCommand,
		MarkSensitive:    markSensitiveBytes,
		ClearSensitive:   zeroBytes,
		CloneSensitive:   cloneSensitiveBytes,
		AppendSensitive:  appendSensitiveBytesLimited,
	})
	return darwinPlatformRuntime{native: native, hook: hook}
}

func platformAcquire(targets databaseTargets, media mediaEvidence, options acquireOptions) (response, diagnostics, error) {
	runtime := newDarwinPlatformRuntime()
	driver := darwinmodel.NewDriver(darwinmodel.DriverRuntime{
		Acquisition:     candidateRuntime(),
		Registry:        darwinCompatibilityRegistry,
		Policy:          darwinRoutePolicy(),
		Native:          runtime.native,
		CaptureHook:     runtime.hook.Capture,
		SecurityPosture: defaultSecurityPostureStatus,
	})
	return driver.Acquire(targets, media, options.PlatformRequest())
}

func preparePlatformAcquisitionSession(targets databaseTargets, options acquireOptions) acquisitionPlatformSession {
	runtime := newDarwinPlatformRuntime()
	return runtime.hook.PrepareSession(targets, options.PlatformRequest())
}

func runPlatformHookWatchdog(args []string) error {
	runtime := newDarwinPlatformRuntime()
	return runtime.hook.RunWatchdog(args)
}

func platformProcessInstanceID() string {
	runtime := newDarwinPlatformRuntime()
	return runtime.hook.ProcessInstanceID()
}
