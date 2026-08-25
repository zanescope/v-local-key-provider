package darwin

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"unsafe"

	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	platformmodel "github.com/zanescope/v-local-key-provider/internal/platform"
)

type CommandRunner func(context.Context, *exec.Cmd) error

type AppendSensitiveBytesFunc func([]byte, []byte, int) ([]byte, bool)

// HookRuntime contains only process-bound mechanisms. Hook selection,
// identity revalidation, capture validation and lifecycle are package-owned.
type HookRuntime struct {
	Native           NativeDriver
	Evidence         *EvidenceCollector
	Registry         []CompatibilityEntry
	Policy           EvaluationPolicy
	SecurityPosture  func() string
	CleanEnvironment func() []string
	RunCommand       CommandRunner
	Executable       func() (string, error)
	MarkSensitive    func([]byte)
	ClearSensitive   func([]byte)
	CloneSensitive   func([]byte) []byte
	AppendSensitive  AppendSensitiveBytesFunc
}

type HookDriver struct {
	runtime HookRuntime
}

func NewHookDriver(runtimeConfig HookRuntime) *HookDriver {
	runtimeConfig.Registry = cloneCompatibilityRegistry(runtimeConfig.Registry)
	if runtimeConfig.Evidence == nil {
		runtimeConfig.Evidence = NewEvidenceCollector(EvidenceRuntime{})
	}
	if runtimeConfig.Executable == nil {
		runtimeConfig.Executable = os.Executable
	}
	return &HookDriver{runtime: runtimeConfig}
}

func (driver *HookDriver) mark(value []byte) {
	if len(value) > 0 && driver != nil && driver.runtime.MarkSensitive != nil {
		driver.runtime.MarkSensitive(value)
	}
}

func (driver *HookDriver) clear(value []byte) {
	if len(value) == 0 {
		return
	}
	if driver != nil && driver.runtime.ClearSensitive != nil {
		driver.runtime.ClearSensitive(value)
		return
	}
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}

func (driver *HookDriver) clone(value []byte) []byte {
	if driver != nil && driver.runtime.CloneSensitive != nil {
		return driver.runtime.CloneSensitive(value)
	}
	result := append([]byte(nil), value...)
	driver.mark(result)
	return result
}

func (driver *HookDriver) appendLimited(current, incoming []byte, limit int) ([]byte, bool) {
	if driver != nil && driver.runtime.AppendSensitive != nil {
		return driver.runtime.AppendSensitive(current, incoming, limit)
	}
	if len(incoming) == 0 {
		return current, false
	}
	remaining := limit - len(current)
	if remaining <= 0 {
		return current, true
	}
	chunk := incoming
	over := false
	if len(chunk) > remaining {
		chunk = chunk[:remaining]
		over = true
	}
	next := make([]byte, len(current)+len(chunk))
	copy(next, current)
	copy(next[len(current):], chunk)
	driver.clear(current)
	driver.mark(next)
	return next, over
}

func sensitiveView(value []byte) string {
	if len(value) == 0 {
		return ""
	}
	result := unsafe.String(unsafe.SliceData(value), len(value))
	runtime.KeepAlive(value)
	return result
}

func (driver *HookDriver) cleanEnvironment() []string {
	if driver != nil && driver.runtime.CleanEnvironment != nil {
		return driver.runtime.CleanEnvironment()
	}
	return []string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"LC_ALL=C",
		"LANG=C",
		"HOME=/var/empty",
		"TMPDIR=/tmp",
	}
}

func (driver *HookDriver) securityPosture() string {
	if driver != nil && driver.runtime.SecurityPosture != nil {
		return driver.runtime.SecurityPosture()
	}
	return ""
}

func (driver *HookDriver) captureIdentityMatches(output string, expected BinaryEvidence, directPID int) bool {
	if !HasKeyOrPBKDFCapture(output) {
		return true
	}
	pids := CapturedPIDs(output)
	if len(pids) == 0 || driver == nil || driver.runtime.Native == nil {
		return false
	}
	processes, _, err := driver.runtime.Native.ListProcesses()
	if err != nil {
		return false
	}
	byPID := make(map[int]Process, len(processes))
	for _, process := range processes {
		byPID[process.PID] = process
	}
	for _, pid := range pids {
		if directPID > 0 && pid != directPID {
			return false
		}
		process, found := byPID[pid]
		if !found {
			return false
		}
		current := driver.runtime.Evidence.CollectEvidence(process)
		decision := EvaluateRoute(current, driver.runtime.Registry, driver.runtime.Policy)
		if !StandardRouteEligible(decision, !driver.runtime.Policy.ReleaseBuild) {
			return false
		}
		if expected.ExecutableSHA256 == "" || current.ExecutableSHA256 != expected.ExecutableSHA256 ||
			current.Version != expected.Version || current.Build != expected.Build ||
			current.SigningTeamID != expected.SigningTeamID ||
			current.DesignatedRequirementSHA256 != expected.DesignatedRequirementSHA256 {
			return false
		}
		if expected.ProcessArchitectureStatus == ArchitectureVerified &&
			current.ProcessArchitecture != expected.ProcessArchitecture {
			return false
		}
	}
	return true
}

func (driver *HookDriver) consumeCaptures(output string, collector *acquisitionmodel.Collector) int {
	if collector == nil {
		return 0
	}
	captures := 0
	for _, candidate := range ParseHookPythonKeys(output) {
		if collector.ConsiderCapturedDatabaseKey(candidate) {
			captures++
		}
		driver.clear(candidate)
	}
	for _, capture := range ParsePBKDFCaptures(output) {
		accepted := false
		switch {
		case capture.Algorithm == 2 && capture.PRF == 5 && capture.Rounds == acquisitionmodel.V4KDFIterations &&
			capture.OutputLength == 32 && len(capture.Password) == 32 && collector.TargetSaltMatches(capture.Salt):
			accepted = collector.ConsiderGlobalPassphrase(capture.Password)
		case capture.Algorithm == 2 && capture.PRF == 5 && capture.Rounds == 2 &&
			capture.OutputLength == 32 && len(capture.Password) == 32:
			accepted = collector.ConsiderCapturedHMACKey(capture.Password, capture.Salt, "raw_enc_key")
		}
		if accepted {
			captures++
		}
		driver.clear(capture.Password)
		driver.clear(capture.Salt)
	}
	return captures
}

func mergeHookSnapshots(values ...platformmodel.HookSnapshot) platformmodel.HookSnapshot {
	result := platformmodel.HookSnapshot{}
	for _, value := range values {
		result.TargetFound += value.TargetFound
		result.Installed = result.Installed || value.Installed
		result.TimedOut = result.TimedOut || value.TimedOut
		result.TriggerNeeded = result.TriggerNeeded || value.TriggerNeeded
		result.RestartNeeded = result.RestartNeeded || value.RestartNeeded
		result.Captures += value.Captures
		result.Used = result.Used || value.Used
		result.IdentityRejected = result.IdentityRejected || value.IdentityRejected
		routes := appendUnique(strings.Split(result.RouteHistory, "\x00"), strings.Split(value.RouteHistory, "\x00")...)
		routes = appendUnique(routes, value.Route)
		filtered := routes[:0]
		for _, route := range routes {
			if route != "" {
				filtered = append(filtered, route)
			}
		}
		result.RouteHistory = strings.Join(filtered, "\x00")
		if result.Route == "" {
			result.Route = value.Route
		}
	}
	if result.Used {
		result.TriggerNeeded = false
	}
	return result
}

func (driver *HookDriver) ProcessInstanceID() string {
	if driver == nil {
		return "darwin:process-list-unavailable"
	}
	return driver.runtime.Evidence.ProcessInstanceID(driver.runtime.Native)
}
