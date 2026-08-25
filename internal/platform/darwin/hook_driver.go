package darwin

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	platformmodel "github.com/zanescope/v-local-key-provider/internal/platform"
	"github.com/zanescope/v-local-key-provider/internal/workbudget"
)

const hookWait = 12 * time.Second
const hookWaitFor = 60 * time.Second
const hookOutputMax = 4 * 1024 * 1024
const hookDiagnosticMax = 256 * 1024

type hookOutputBuffer struct {
	mu     sync.Mutex
	driver *HookDriver
	limit  int
	data   []byte
}

func (buffer *hookOutputBuffer) Write(data []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	buffer.data, _ = buffer.driver.appendLimited(buffer.data, data, buffer.limit)
	return len(data), nil
}

func (buffer *hookOutputBuffer) snapshot() []byte {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.driver.clone(buffer.data)
}

func (buffer *hookOutputBuffer) zero() {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	buffer.driver.clear(buffer.data)
	buffer.data = nil
}

// RunWatchdog is the internal subprocess entry. The parent keeps descriptor 3
// open for the acquisition lifetime; EOF terminates LLDB and its process group.
func (driver *HookDriver) RunWatchdog(args []string) error {
	if len(args) != 3 && len(args) != 5 {
		return errors.New("invalid hook watchdog arguments")
	}
	if args[0] != "-b" || args[len(args)-2] != "-s" || strings.TrimSpace(args[len(args)-1]) == "" {
		return errors.New("invalid hook watchdog arguments")
	}
	if len(args) == 5 {
		if args[1] != "-p" {
			return errors.New("invalid hook watchdog arguments")
		}
		pid, err := strconv.Atoi(args[2])
		if err != nil || pid <= 0 {
			return errors.New("invalid hook watchdog pid")
		}
	}
	liveness := os.NewFile(uintptr(3), "provider-liveness")
	if liveness == nil {
		return errors.New("hook watchdog liveness descriptor is unavailable")
	}
	defer liveness.Close()
	lldb := driver.runtime.Evidence.LLDBPath()
	if lldb == "" {
		return errors.New("lldb is unavailable")
	}
	command := exec.Command(lldb, args...)
	command.Env = driver.cleanEnvironment()
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		return err
	}
	finished := make(chan error, 1)
	go func() { finished <- command.Wait() }()
	parentClosed := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, liveness)
		close(parentClosed)
	}()
	select {
	case err := <-finished:
		return err
	case <-parentClosed:
		signalProcessTerminate(command)
		select {
		case <-finished:
			return nil
		case <-time.After(time.Second):
			killCurrentProcessGroup()
			return errors.New("hook watchdog cleanup timed out")
		}
	}
}

func (driver *HookDriver) writeHookFiles(architecture string, waitFor bool, executable string) (string, string, error) {
	python, err := os.CreateTemp("", "v_local_key_provider_lldb_*.py")
	if err != nil {
		return "", "", err
	}
	pythonPath := python.Name()
	removePython := true
	defer func() {
		_ = python.Close()
		if removePython {
			_ = os.Remove(pythonPath)
		}
	}()
	_ = python.Chmod(0o600)
	if _, err := python.WriteString(HookPythonSource(architecture)); err != nil {
		return "", "", err
	}
	if err := python.Close(); err != nil {
		return "", "", err
	}
	script, err := os.CreateTemp("", "v-local-key-provider-lldb-*.cmd")
	if err != nil {
		return "", "", err
	}
	scriptPath := script.Name()
	removeScript := true
	defer func() {
		_ = script.Close()
		if removeScript {
			_ = os.Remove(scriptPath)
		}
	}()
	_ = script.Chmod(0o600)
	commands := HookCommandFileWithPython(waitFor, executable, pythonPath, WaitForProcessName(executable))
	if _, err := script.WriteString(commands); err != nil {
		return "", "", err
	}
	if err := script.Close(); err != nil {
		return "", "", err
	}
	removePython = false
	removeScript = false
	return pythonPath, scriptPath, nil
}

type persistentHook struct {
	driver     *HookDriver
	command    *exec.Cmd
	output     *hookOutputBuffer
	done       chan struct{}
	liveness   *os.File
	pythonPath string
	scriptPath string
	directPID  int
	route      string
	expected   BinaryEvidence
}

func (driver *HookDriver) startPersistentHook(
	process Process,
	remaining workbudget.Budget,
	waitFor bool,
	route string,
) *persistentHook {
	if remaining.Expired() || driver.runtime.Evidence.LLDBPath() == "" {
		return nil
	}
	executable := driver.runtime.Evidence.WeChatExecutable(process)
	if waitFor && executable == "" || !waitFor && process.PID <= 0 {
		return nil
	}
	expectedProcess := process
	if expectedProcess.Command == "" {
		expectedProcess.Command = executable
		expectedProcess.Name = processBase(executable)
	}
	expected := driver.runtime.Evidence.CollectEvidence(expectedProcess)
	if waitFor && !PrelaunchHookEligible(expected) {
		return nil
	}
	architecture := "auto"
	if !waitFor {
		var architectureStatus string
		architecture, architectureStatus, _ = driver.runtime.Evidence.ProcessArchitectureEvidence(process)
		if architectureStatus != ArchitectureVerified {
			return nil
		}
	}
	pythonPath, scriptPath, err := driver.writeHookFiles(architecture, waitFor, executable)
	if err != nil {
		return nil
	}
	args := []string{"-b", "-s", scriptPath}
	directPID := 0
	if !waitFor {
		directPID = process.PID
		args = []string{"-b", "-p", strconv.Itoa(process.PID), "-s", scriptPath}
	}
	executablePath, err := driver.runtime.Executable()
	if err != nil {
		_ = os.Remove(pythonPath)
		_ = os.Remove(scriptPath)
		return nil
	}
	livenessReader, livenessWriter, err := os.Pipe()
	if err != nil {
		_ = os.Remove(pythonPath)
		_ = os.Remove(scriptPath)
		return nil
	}
	output := &hookOutputBuffer{driver: driver, limit: hookOutputMax}
	watchdogArgs := append([]string{"internal-hook-watchdog"}, args...)
	command := exec.Command(executablePath, watchdogArgs...)
	command.Env = driver.cleanEnvironment()
	command.Stdout = output
	command.Stderr = output
	configureProcessGroup(command)
	command.ExtraFiles = []*os.File{livenessReader}
	if err := command.Start(); err != nil {
		_ = livenessReader.Close()
		_ = livenessWriter.Close()
		_ = os.Remove(pythonPath)
		_ = os.Remove(scriptPath)
		return nil
	}
	_ = livenessReader.Close()
	hook := &persistentHook{
		driver: driver, command: command, output: output, done: make(chan struct{}), liveness: livenessWriter,
		pythonPath: pythonPath, scriptPath: scriptPath, directPID: directPID, route: route, expected: expected,
	}
	go func() {
		_ = command.Wait()
		_ = livenessWriter.Close()
		close(hook.done)
	}()
	readyDeadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(readyDeadline) && !remaining.Expired() {
		snapshot := output.snapshot()
		ready := HookPythonCount(sensitiveView(snapshot)) > 0
		driver.clear(snapshot)
		if ready {
			break
		}
		select {
		case <-hook.done:
			return hook
		case <-time.After(25 * time.Millisecond):
		}
	}
	return hook
}

func (hook *persistentHook) status(collector *acquisitionmodel.Collector) platformmodel.HookSnapshot {
	if hook == nil {
		return platformmodel.HookSnapshot{}
	}
	outputBytes := hook.output.snapshot()
	defer hook.driver.clear(outputBytes)
	output := sensitiveView(outputBytes)
	installedCount := HookPythonCount(output)
	captures := 0
	identityRejected := !hook.driver.captureIdentityMatches(output, hook.expected, hook.directPID)
	if collector != nil && !identityRejected {
		captures = hook.driver.consumeCaptures(output, collector)
	}
	return platformmodel.HookSnapshot{
		TargetFound: installedCount, Installed: installedCount > 0, Captures: captures,
		Used: captures > 0, TriggerNeeded: installedCount > 0 && captures == 0 && !identityRejected,
		Route: hook.route, RouteHistory: hook.route, IdentityRejected: identityRejected,
	}
}

func (hook *persistentHook) close() {
	if hook == nil {
		return
	}
	select {
	case <-hook.done:
	default:
		if hook.liveness != nil {
			_ = hook.liveness.Close()
		}
		if hook.command != nil && hook.command.Process != nil {
			select {
			case <-hook.done:
			case <-time.After(2 * time.Second):
				killProcessGroup(hook.command)
				<-hook.done
			}
		}
	}
	outputBytes := hook.output.snapshot()
	output := sensitiveView(outputBytes)
	if hook.directPID > 0 {
		hook.driver.resumeAfterHook(hook.directPID)
	}
	for _, pid := range CapturedPIDs(output) {
		hook.driver.resumeAfterHook(pid)
	}
	hook.driver.clear(outputBytes)
	hook.output.zero()
	_ = os.Remove(hook.pythonPath)
	_ = os.Remove(hook.scriptPath)
}

func (driver *HookDriver) PrepareSession(
	targets acquisitionmodel.Targets,
	request acquisitionmodel.PlatformRequest,
) acquisitionmodel.PlatformSession {
	if !request.Database || len(targets.Pages) == 0 || request.Budget.Expired() || driver == nil || driver.runtime.Native == nil {
		return nil
	}
	processes, _, err := driver.runtime.Native.ListProcesses()
	if err != nil {
		return nil
	}
	securityPosture := driver.securityPosture()
	var hooks []*persistentHook
	var waitTarget Process
	for _, target := range processes {
		evidence := driver.runtime.Evidence.CollectEvidence(target)
		decision := EvaluateRoute(evidence, driver.runtime.Registry, driver.runtime.Policy)
		if !StandardRouteEligible(decision, !driver.runtime.Policy.ReleaseBuild) {
			continue
		}
		route := DynamicRouteID(evidence.ProcessArchitecture, securityPosture)
		if route == "" {
			continue
		}
		if hook := driver.startPersistentHook(target, request.Budget, false, route); hook != nil {
			hooks = append(hooks, hook)
		}
		if waitTarget.PID == 0 {
			waitTarget = target
		}
	}
	if len(processes) == 0 {
		waitTarget = driver.runtime.Evidence.PrelaunchProcess()
		if !PrelaunchHookEligible(driver.runtime.Evidence.CollectEvidence(waitTarget)) {
			return nil
		}
	}
	if waitTarget.Command != "" {
		waitRoute := "darwin_standard_dynamic_waitfor"
		if securityPosture == "sip_disabled_verified" {
			waitRoute = "darwin_sip_disabled_waitfor"
		}
		if hook := driver.startPersistentHook(waitTarget, request.Budget, true, waitRoute); hook != nil {
			hooks = append(hooks, hook)
		}
	}
	if len(hooks) == 0 {
		return nil
	}
	status := func(collector *acquisitionmodel.Collector) platformmodel.HookSnapshot {
		values := make([]platformmodel.HookSnapshot, 0, len(hooks))
		for _, hook := range hooks {
			if collector == nil {
				values = append(values, hook.status(nil))
				continue
			}
			isolated := collector.NewIsolated()
			values = append(values, hook.status(isolated))
			collector.MergeValidatedFrom(isolated)
			isolated.ClearSensitiveBuffers()
		}
		return mergeHookSnapshots(values...)
	}
	return acquisitionmodel.NewSynchronizedPlatformSession(
		func(collector *acquisitionmodel.Collector) platformmodel.HookSnapshot { return status(collector) },
		func() platformmodel.HookSnapshot { return status(nil) },
		func() {
			for _, hook := range hooks {
				hook.close()
			}
		},
	)
}

func (driver *HookDriver) resumeAfterHook(pid int) {
	if driver == nil || driver.runtime.Evidence == nil || driver.runtime.Evidence.runtime.RunOutput == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	output, _ := driver.runtime.Evidence.runtime.RunOutput(
		ctx, "/bin/kill", []string{"-CONT", strconv.Itoa(pid)}, 1024,
	)
	driver.clear(output)
}

func (driver *HookDriver) Capture(
	process Process,
	collector *acquisitionmodel.Collector,
	remaining workbudget.Budget,
	waitFor bool,
	securityPosture string,
) platformmodel.HookSnapshot {
	result := platformmodel.HookSnapshot{}
	architecture := "auto"
	if !waitFor {
		var architectureStatus string
		architecture, architectureStatus, _ = driver.runtime.Evidence.ProcessArchitectureEvidence(process)
		if architectureStatus != ArchitectureVerified {
			return result
		}
	}
	if remaining.Expired() || driver == nil || driver.runtime.RunCommand == nil {
		return result
	}
	lldb := driver.runtime.Evidence.LLDBPath()
	if lldb == "" {
		return result
	}
	if waitFor {
		result.Route = "darwin_standard_dynamic_waitfor"
		if securityPosture == "sip_disabled_verified" {
			result.Route = "darwin_sip_disabled_waitfor"
		}
	} else {
		result.Route = DynamicRouteID(architecture, securityPosture)
	}
	expectedProcess := process
	if expectedProcess.Command == "" {
		expectedProcess.Command = driver.runtime.Evidence.WeChatExecutable(process)
		expectedProcess.Name = processBase(expectedProcess.Command)
	}
	expected := driver.runtime.Evidence.CollectEvidence(expectedProcess)
	if waitFor && !PrelaunchHookEligible(expected) {
		return platformmodel.HookSnapshot{}
	}
	executable := driver.runtime.Evidence.WeChatExecutable(process)
	pythonPath, scriptPath, err := driver.writeHookFiles(architecture, waitFor, executable)
	if err != nil {
		return result
	}
	defer os.Remove(pythonPath)
	defer os.Remove(scriptPath)
	wait := hookWait
	if waitFor {
		wait = hookWaitFor
	}
	if deadline, bounded := remaining.Deadline(); bounded {
		available := time.Until(deadline) - 250*time.Millisecond
		if available < wait {
			wait = available
		}
	}
	if wait <= 0 {
		return result
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	args := []string{"-b", "-s", scriptPath}
	if !waitFor {
		args = []string{"-b", "-p", strconv.Itoa(process.PID), "-s", scriptPath}
	}
	command := exec.Command(lldb, args...)
	stdout := &hookOutputBuffer{driver: driver, limit: hookOutputMax}
	stderr := &hookOutputBuffer{driver: driver, limit: hookDiagnosticMax}
	defer stdout.zero()
	defer stderr.zero()
	command.Stdout = stdout
	command.Stderr = stderr
	err = driver.runtime.RunCommand(ctx, command)
	if ctx.Err() != nil {
		result.TimedOut = true
		if !waitFor {
			driver.resumeAfterHook(process.PID)
		}
	} else if err != nil && !waitFor {
		driver.resumeAfterHook(process.PID)
	}
	captureBytes := stdout.snapshot()
	defer driver.clear(captureBytes)
	captureOutput := sensitiveView(captureBytes)
	for _, pid := range CapturedPIDs(captureOutput) {
		driver.resumeAfterHook(pid)
	}
	result.TargetFound = HookPythonCount(captureOutput)
	if result.TargetFound == 0 {
		result.TargetFound = LLDBBreakpointCount(captureOutput)
	}
	result.Installed = result.TargetFound > 0
	expectedPID := process.PID
	if waitFor {
		expectedPID = 0
	}
	result.IdentityRejected = !driver.captureIdentityMatches(captureOutput, expected, expectedPID)
	if !result.IdentityRejected {
		result.Captures = driver.consumeCaptures(captureOutput, collector)
	}
	result.Used = result.Captures > 0
	result.TriggerNeeded = result.Installed && !result.Used
	result.RestartNeeded = waitFor && !result.Used
	return result
}
