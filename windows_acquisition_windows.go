//go:build windows

package provider

import windowsmodel "github.com/zanescope/v-local-key-provider/internal/platform/windows"

func windowsNativeDriver() windowsmodel.NativeDriver {
	return windowsmodel.NewNativeDriver(windowsmodel.NativeRuntime{
		Evidence: windowsmodel.EvidenceRuntime{
			ExecutableSHA256:     executableSHA256,
			AuthenticodeEvidence: windowsAuthenticodeEvidence,
		},
		Sensitive: windowsConfigSensitiveRuntime(),
	})
}

func platformAcquire(targets databaseTargets, media mediaEvidence, options acquireOptions) (response, diagnostics, error) {
	driver := windowsmodel.NewDriver(windowsmodel.DriverRuntime{
		Acquisition: candidateRuntime(),
		Registry:    windowsCompatibilityRegistry,
		Policy:      windowsRoutePolicy(),
		Native:      windowsNativeDriver(),
	})
	return driver.Acquire(targets, media, options.PlatformRequest())
}

func platformProcessInstanceID() string {
	return windowsmodel.ProcessInventoryID(windowsNativeDriver())
}
