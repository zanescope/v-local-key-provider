//go:build darwin && cgo

package provider

import (
	"path/filepath"

	darwinmodel "github.com/zanescope/v-local-key-provider/internal/platform/darwin"
	"github.com/zanescope/v-local-key-provider/internal/workbudget"
)

func darwinNativeDriver() darwinmodel.NativeDriver {
	return darwinmodel.NewNativeDriver(darwinmodel.NativeRuntime{
		RunOutput:      runBoundedDarwinOutput,
		MarkSensitive:  markSensitiveBytes,
		ClearSensitive: zeroBytes,
		CollectEvidence: func(process darwinmodel.Process) darwinmodel.BinaryEvidence {
			return darwinCollectBinaryEvidence(darwinProcessFromModel(process))
		},
		PrelaunchProcess: func() darwinmodel.Process {
			process := darwinProcess{}
			process.command = darwinWeChatExecutable(process)
			process.name = filepath.Base(process.command)
			return darwinProcessToModel(process)
		},
	})
}

func darwinTargetProcesses() ([]darwinProcess, string, error) {
	processes, method, err := darwinNativeDriver().ListProcesses()
	result := make([]darwinProcess, 0, len(processes))
	for _, process := range processes {
		result = append(result, darwinProcessFromModel(process))
	}
	return result, method, err
}

func platformAcquire(targets databaseTargets, media mediaEvidence, options acquireOptions) (response, diagnostics, error) {
	driver := darwinmodel.NewDriver(darwinmodel.DriverRuntime{
		Acquisition: candidateRuntime(),
		Registry:    darwinCompatibilityRegistry,
		Policy:      darwinRoutePolicy(),
		Native:      darwinNativeDriver(),
		CaptureHook: func(
			process darwinmodel.Process,
			collector *candidateCollector,
			remaining workbudget.Budget,
			waitFor bool,
			securityPosture string,
		) platformHookSnapshot {
			return captureDarwinHookMode(
				darwinProcessFromModel(process), collector, budget{value: remaining}, waitFor, securityPosture,
			)
		},
		SecurityPosture: defaultSecurityPostureStatus,
	})
	return driver.Acquire(targets, media, platformRequestFromOptions(options))
}
