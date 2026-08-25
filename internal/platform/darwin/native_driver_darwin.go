//go:build darwin && cgo

package darwin

import (
	"os"
	"runtime"
)

type nativeDriver struct {
	runtime NativeRuntime
}

func NewNativeDriver(runtimeConfig NativeRuntime) NativeDriver {
	if runtimeConfig.UID == nil {
		runtimeConfig.UID = os.Getuid
	}
	return &nativeDriver{runtime: runtimeConfig}
}

func (driver *nativeDriver) mark(value []byte) {
	if driver.runtime.MarkSensitive != nil {
		driver.runtime.MarkSensitive(value)
	}
}

func (driver *nativeDriver) clear(value []byte) {
	if driver.runtime.ClearSensitive != nil {
		driver.runtime.ClearSensitive(value)
		return
	}
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}

func (driver *nativeDriver) CollectEvidence(process Process) BinaryEvidence {
	if driver.runtime.CollectEvidence == nil {
		return BinaryEvidence{
			BinaryFingerprintStatus:   FingerprintNotEvaluated,
			BinarySigningStatus:       SigningNotEvaluated,
			ProcessArchitecture:       "unknown",
			ProcessArchitectureStatus: ArchitectureNotEvaluated,
			ProcessTranslationStatus:  "not_evaluated",
		}
	}
	return driver.runtime.CollectEvidence(process)
}

func (driver *nativeDriver) PrelaunchProcess() Process {
	if driver.runtime.PrelaunchProcess == nil {
		return Process{}
	}
	return driver.runtime.PrelaunchProcess()
}
