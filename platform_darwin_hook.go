//go:build darwin && cgo

package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	daemonmodel "github.com/zanescope/v-local-key-provider/internal/daemon"
)

const darwinHookWait = 12 * time.Second
const darwinHookWaitFor = 60 * time.Second
const darwinHookOutputMax = 4 * 1024 * 1024

type darwinHookOutputBuffer struct {
	mu   sync.Mutex
	data []byte
}

func (buffer *darwinHookOutputBuffer) Write(data []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	buffer.data, _ = appendSensitiveBytesLimited(buffer.data, data, darwinHookOutputMax)
	return len(data), nil
}

func (buffer *darwinHookOutputBuffer) snapshot() []byte {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return cloneSensitiveBytes(buffer.data)
}

func (buffer *darwinHookOutputBuffer) zero() {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	zeroBytes(buffer.data)
	buffer.data = nil
}

func darwinProcessExecutable(process darwinProcess) string {
	if process.pid > 0 {
		if executable, err := daemonmodel.ProcessExecutablePath(uint32(process.pid)); err == nil && filepath.IsAbs(executable) {
			return filepath.Clean(executable)
		}
	}
	command := strings.TrimSpace(process.command)
	if command == "" {
		command = process.name
	}
	for _, suffix := range []string{"/Contents/MacOS/WeChat", "/Contents/MacOS/Weixin", "/Contents/MacOS/微信"} {
		if marker := strings.Index(command, suffix); marker >= 0 {
			candidate := strings.Trim(strings.TrimSpace(command[:marker+len(suffix)]), "'\"")
			if filepath.IsAbs(candidate) {
				return filepath.Clean(candidate)
			}
		}
	}
	if fields := strings.Fields(command); len(fields) > 0 {
		candidate := strings.Trim(fields[0], "'\"")
		if filepath.IsAbs(candidate) {
			return filepath.Clean(candidate)
		}
	}
	if filepath.IsAbs(process.name) {
		return filepath.Clean(process.name)
	}
	return ""
}

func darwinProcessVersion(process darwinProcess) string {
	return darwinProcessPlistValue(process, "CFBundleShortVersionString")
}

func darwinProcessBuild(process darwinProcess) string {
	return darwinProcessPlistValue(process, "CFBundleVersion")
}

func darwinProcessPlistValue(process darwinProcess, key string) string {
	executable := darwinProcessExecutable(process)
	marker := strings.Index(executable, ".app/Contents/")
	if marker < 0 {
		return ""
	}
	appPath := executable[:marker+len(".app")]
	plist := filepath.Join(appPath, "Contents", "Info.plist")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := runBoundedDarwinOutput(ctx, "/usr/libexec/PlistBuddy", []string{"-c", "Print:" + key, plist}, 16*1024)
	defer zeroBytes(output)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func darwinProcessArchitecture(process darwinProcess) string {
	architecture, _, _ := darwinProcessArchitectureEvidence(process)
	return architecture
}

func darwinProcessArchitectureEvidence(process darwinProcess) (string, string, string) {
	if process.pid <= 0 {
		return "unknown", darwinArchitectureNotEvaluated, "not_evaluated"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	output, err := runBoundedDarwinOutput(ctx, "/bin/ps", []string{"-p", strconv.Itoa(process.pid), "-o", "arch="}, 4*1024)
	defer zeroBytes(output)
	if err != nil {
		return "unknown", darwinArchitectureUnavailable, "unknown"
	}
	architecture := normalizeDarwinArchitecture(string(output))
	if architecture == "unknown" {
		return architecture, darwinArchitectureUnavailable, "unknown"
	}
	machineOutput, machineErr := runBoundedDarwinOutput(ctx, "/usr/bin/uname", []string{"-m"}, 4*1024)
	defer zeroBytes(machineOutput)
	translation := "unknown"
	if machineErr == nil {
		translation = darwinTranslationStatus(architecture, string(machineOutput))
	}
	return architecture, darwinArchitectureVerified, translation
}

func darwinMacOSVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := runBoundedDarwinOutput(ctx, "/usr/bin/sw_vers", []string{"-productVersion"}, 4*1024)
	defer zeroBytes(output)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func darwinCodeSigningEvidence(executable string) (string, string, string) {
	if executable == "" {
		return darwinSigningNotEvaluated, "", ""
	}
	info, err := os.Lstat(executable)
	unsafePath := false
	if err == nil {
		unsafePath, err = pathIsLinkOrReparse(executable, info.Mode())
	}
	if err != nil || unsafePath || !info.Mode().IsRegular() {
		return darwinSigningUnavailable, "", ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	verification, verifyErr := runBoundedDarwinCombinedOutput(
		ctx, "/usr/bin/codesign", []string{"--verify", "--strict", "--verbose=4", executable}, 64*1024,
	)
	zeroBytes(verification)
	if verifyErr != nil || ctx.Err() != nil {
		return darwinSigningInvalid, "", ""
	}
	details, detailsErr := runBoundedDarwinCombinedOutput(
		ctx, "/usr/bin/codesign", []string{"-dv", "--verbose=4", executable}, 64*1024,
	)
	defer zeroBytes(details)
	if detailsErr != nil || ctx.Err() != nil {
		return darwinSigningUnavailable, "", ""
	}
	teamID := ""
	for _, line := range strings.Split(string(details), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "TeamIdentifier=") {
			teamID = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "TeamIdentifier="))
			break
		}
	}
	if teamID == "" || len(teamID) > 64 || strings.ContainsAny(teamID, " \t\r\n") {
		return darwinSigningInvalid, "", ""
	}
	requirement, requirementErr := runBoundedDarwinCombinedOutput(
		ctx, "/usr/bin/codesign", []string{"-dr", "-", executable}, 64*1024,
	)
	defer zeroBytes(requirement)
	if requirementErr != nil || ctx.Err() != nil {
		return darwinSigningUnavailable, "", ""
	}
	designated := ""
	for _, line := range strings.Split(string(requirement), "\n") {
		line = strings.TrimSpace(line)
		if marker := strings.Index(line, "designated =>"); marker >= 0 {
			designated = strings.TrimSpace(line[marker+len("designated =>"):])
			break
		}
	}
	if designated == "" {
		return darwinSigningInvalid, "", ""
	}
	digest := sha256.Sum256([]byte(designated))
	return darwinSigningVerified, teamID, hex.EncodeToString(digest[:])
}

func darwinCollectBinaryEvidence(process darwinProcess) darwinBinaryEvidence {
	evidence := darwinBinaryEvidence{
		Version: process.name, BinaryFingerprintStatus: darwinFingerprintNotEvaluated,
		BinarySigningStatus: darwinSigningNotEvaluated, ProcessArchitecture: "unknown",
		ProcessArchitectureStatus: darwinArchitectureNotEvaluated, ProcessTranslationStatus: "not_evaluated",
	}
	evidence.Version = darwinProcessVersion(process)
	evidence.Build = darwinProcessBuild(process)
	evidence.MacOSVersion = darwinMacOSVersion()
	evidence.MacOSMajorMinor = darwinMajorMinor(evidence.MacOSVersion)
	evidence.ProcessArchitecture, evidence.ProcessArchitectureStatus, evidence.ProcessTranslationStatus = darwinProcessArchitectureEvidence(process)
	executable := darwinProcessExecutable(process)
	if executable != "" {
		evidence.ExecutableSHA256 = executableSHA256(executable)
		if validDarwinSHA256(evidence.ExecutableSHA256) {
			evidence.BinaryFingerprintStatus = darwinFingerprintVerified
		} else {
			evidence.ExecutableSHA256 = ""
			evidence.BinaryFingerprintStatus = darwinFingerprintUnavailable
		}
		evidence.BinarySigningStatus, evidence.SigningTeamID, evidence.DesignatedRequirementSHA256 = darwinCodeSigningEvidence(executable)
	}
	return evidence
}

func darwinPrelaunchHookEligible(evidence darwinBinaryEvidence) bool {
	return evidence.Version != "" && evidence.Build != "" && evidence.MacOSMajorMinor != "" &&
		evidence.BinaryFingerprintStatus == darwinFingerprintVerified && validDarwinSHA256(evidence.ExecutableSHA256) &&
		evidence.BinarySigningStatus == darwinSigningVerified && evidence.SigningTeamID != "" &&
		validDarwinSHA256(evidence.DesignatedRequirementSHA256)
}

func applyDarwinRouteEvidence(diag *diagnostics, evidence darwinBinaryEvidence) darwinRouteDecision {
	decision := evaluateDarwinRoute(evidence, darwinCompatibilityRegistry)
	diag.WeChatVersion = evidence.Version
	diag.WeChatBuild = evidence.Build
	diag.ExecutableSHA256 = evidence.ExecutableSHA256
	diag.BinaryFingerprintStatus = evidence.BinaryFingerprintStatus
	diag.BinarySigningStatus = evidence.BinarySigningStatus
	diag.SigningTeamID = evidence.SigningTeamID
	diag.DesignatedRequirementSHA256 = evidence.DesignatedRequirementSHA256
	diag.ProcessArchitecture = evidence.ProcessArchitecture
	diag.ProcessArchitectureStatus = evidence.ProcessArchitectureStatus
	diag.ProcessTranslationStatus = evidence.ProcessTranslationStatus
	diag.MacOSVersion = evidence.MacOSVersion
	diag.CompatibilityRegistryStatus = decision.CompatibilityRegistryStatus
	diag.StandardRouteStatus = decision.StandardRouteStatus
	diag.StandardRouteEvidence = append([]string(nil), decision.Evidence...)
	return decision
}

func darwinWeChatExecutable(process darwinProcess) string {
	if executable := darwinProcessExecutable(process); executable != "" {
		return executable
	}
	candidates := []string{
		"/Applications/WeChat.app/Contents/MacOS/WeChat",
		"/Applications/Weixin.app/Contents/MacOS/Weixin",
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, "Applications", "WeChat.app", "Contents", "MacOS", "WeChat"),
			filepath.Join(home, "Applications", "Weixin.app", "Contents", "MacOS", "Weixin"),
		)
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

func darwinWaitForProcessName(executable string) string {
	if strings.EqualFold(filepath.Base(executable), "weixin") || strings.Contains(strings.ToLower(executable), "weixin.app") {
		return "Weixin"
	}
	return "WeChat"
}

func darwinVersionSupport(version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		return "unknown"
	}
	parts := strings.Split(version, ".")
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return "unknown"
	}
	minor := 0
	if len(parts) > 1 {
		minor, _ = strconv.Atoi(parts[1])
	}
	if major > 4 || (major == 4 && minor >= 1) {
		return "commoncrypto_dynamic"
	}
	if major == 4 {
		return "static_then_commoncrypto"
	}
	return "static_memory"
}

func darwinPreferDynamicHook(version string) bool {
	return darwinVersionSupport(version) == "commoncrypto_dynamic"
}

func darwinLLDBPath() string {
	const path = "/usr/bin/lldb"
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&0o111 == 0 {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !sameCanonicalPath(path, resolved) {
		return ""
	}
	return path
}

func darwinHookCaptureIdentityMatches(output string, expected darwinBinaryEvidence, directPID int) bool {
	if !darwinHookHasKeyOrPBKDFCapture(output) {
		return true
	}
	pids := darwinCapturedPIDs(output)
	if len(pids) == 0 {
		return false
	}
	processes, _, err := darwinTargetProcesses()
	if err != nil {
		return false
	}
	byPID := make(map[int]darwinProcess, len(processes))
	for _, process := range processes {
		byPID[process.pid] = process
	}
	for _, pid := range pids {
		if directPID > 0 && pid != directPID {
			return false
		}
		process, found := byPID[pid]
		if !found {
			return false
		}
		current := darwinCollectBinaryEvidence(process)
		decision := evaluateDarwinRoute(current, darwinCompatibilityRegistry)
		if !darwinStandardRouteEligible(decision) {
			return false
		}
		if expected.ExecutableSHA256 == "" || current.ExecutableSHA256 != expected.ExecutableSHA256 ||
			current.Version != expected.Version || current.Build != expected.Build ||
			current.SigningTeamID != expected.SigningTeamID ||
			current.DesignatedRequirementSHA256 != expected.DesignatedRequirementSHA256 {
			return false
		}
		if expected.ProcessArchitectureStatus == darwinArchitectureVerified && current.ProcessArchitecture != expected.ProcessArchitecture {
			return false
		}
	}
	return true
}

func darwinPBKDFCaptureMatchesTargetSalt(capture darwinPBKDFCapture, targets databaseTargets) bool {
	if len(capture.Salt) != 16 {
		return false
	}
	for _, target := range targets.Pages {
		salt, err := hex.DecodeString(target.Salt)
		if err == nil && bytes.Equal(salt, capture.Salt) {
			return true
		}
	}
	return false
}

func consumeDarwinHookCaptures(output string, collector *candidateCollector) int {
	captures := 0
	for _, candidate := range parseDarwinHookPythonKeys(output) {
		if collector.ConsiderCapturedDatabaseKey(candidate) {
			captures++
		}
		zeroBytes(candidate)
	}
	for _, capture := range parseDarwinPBKDFCaptures(output) {
		accepted := false
		switch {
		case capture.Algorithm == 2 && capture.PRF == 5 && capture.Rounds == v4KDFIterations &&
			capture.OutputLength == 32 && len(capture.Password) == 32 && collector.TargetSaltMatches(capture.Salt):
			accepted = collector.ConsiderGlobalPassphrase(capture.Password)
		case capture.Algorithm == 2 && capture.PRF == 5 && capture.Rounds == 2 && capture.OutputLength == 32 && len(capture.Password) == 32:
			accepted = collector.ConsiderCapturedHMACKey(capture.Password, capture.Salt, "raw_enc_key")
		}
		if accepted {
			captures++
		}
		zeroBytes(capture.Password)
		zeroBytes(capture.Salt)
	}
	return captures
}

type darwinPersistentHook struct {
	command    *exec.Cmd
	output     *darwinHookOutputBuffer
	done       chan struct{}
	liveness   *os.File
	pythonPath string
	scriptPath string
	directPID  int
	route      string
	expected   darwinBinaryEvidence
}

// runPlatformHookWatchdog 是内部子进程入口。守护进程会在获取会话的整个生命周期内
// 保持文件描述符 3 打开。如果守护进程被取消、超时或崩溃，该描述符上的 EOF 会终止
// LLDB，确保调试器不会比创建它的进程存活更久。
func runPlatformHookWatchdog(args []string) error {
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
	lldb := darwinLLDBPath()
	if lldb == "" {
		return errors.New("lldb is unavailable")
	}
	command := exec.Command(lldb, args...)
	command.Env = darwinCleanEnvironment()
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
		if command.Process != nil {
			_ = command.Process.Signal(syscall.SIGTERM)
		}
		select {
		case <-finished:
			return nil
		case <-time.After(time.Second):
			// 看门狗是进程组组长，LLDB 会继承该进程组。如果正常终止卡住，终止整个
			// 进程组就是最后一道有界清理措施。
			_ = syscall.Kill(-syscall.Getpgrp(), syscall.SIGKILL)
			return errors.New("hook watchdog cleanup timed out")
		}
	}
}

func writeDarwinHookFiles(architecture string, waitFor bool, executable string) (string, string, error) {
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
	if _, err := python.WriteString(darwinHookPythonSource(architecture)); err != nil {
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
	if _, err := script.WriteString(darwinHookCommandFileWithPython(waitFor, executable, pythonPath)); err != nil {
		return "", "", err
	}
	if err := script.Close(); err != nil {
		return "", "", err
	}
	removePython = false
	removeScript = false
	return pythonPath, scriptPath, nil
}

func startDarwinPersistentHook(process darwinProcess, remaining budget, waitFor bool, route string) *darwinPersistentHook {
	if remaining.expired() {
		return nil
	}
	lldb := darwinLLDBPath()
	if lldb == "" {
		return nil
	}
	executable := darwinWeChatExecutable(process)
	if waitFor && executable == "" || !waitFor && process.pid <= 0 {
		return nil
	}
	expectedProcess := process
	if expectedProcess.command == "" {
		expectedProcess.command = executable
		expectedProcess.name = filepath.Base(executable)
	}
	expected := darwinCollectBinaryEvidence(expectedProcess)
	if waitFor && !darwinPrelaunchHookEligible(expected) {
		return nil
	}
	architecture := "auto"
	if !waitFor {
		var architectureStatus string
		architecture, architectureStatus, _ = darwinProcessArchitectureEvidence(process)
		if architectureStatus != darwinArchitectureVerified {
			return nil
		}
	}
	pythonPath, scriptPath, err := writeDarwinHookFiles(architecture, waitFor, executable)
	if err != nil {
		return nil
	}
	args := []string{"-b", "-s", scriptPath}
	directPID := 0
	if !waitFor {
		directPID = process.pid
		args = []string{"-b", "-p", strconv.Itoa(process.pid), "-s", scriptPath}
	}
	executablePath, err := os.Executable()
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
	output := &darwinHookOutputBuffer{}
	watchdogArgs := append([]string{"internal-hook-watchdog"}, args...)
	command := exec.Command(executablePath, watchdogArgs...)
	command.Env = darwinCleanEnvironment()
	command.Stdout = output
	command.Stderr = output
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.ExtraFiles = []*os.File{livenessReader}
	if err := command.Start(); err != nil {
		_ = livenessReader.Close()
		_ = livenessWriter.Close()
		_ = os.Remove(pythonPath)
		_ = os.Remove(scriptPath)
		return nil
	}
	_ = livenessReader.Close()
	hook := &darwinPersistentHook{
		command: command, output: output, done: make(chan struct{}), liveness: livenessWriter, pythonPath: pythonPath,
		scriptPath: scriptPath, directPID: directPID, route: route, expected: expected,
	}
	go func() {
		_ = command.Wait()
		_ = livenessWriter.Close()
		close(hook.done)
	}()
	readyDeadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(readyDeadline) && !remaining.expired() {
		snapshot := output.snapshot()
		ready := darwinHookPythonCount(sensitiveBytesView(snapshot)) > 0
		zeroBytes(snapshot)
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

func (hook *darwinPersistentHook) status(collector *candidateCollector) platformHookSnapshot {
	if hook == nil {
		return platformHookSnapshot{}
	}
	outputBytes := hook.output.snapshot()
	defer zeroBytes(outputBytes)
	output := sensitiveBytesView(outputBytes)
	installedCount := darwinHookPythonCount(output)
	captures := 0
	identityRejected := !darwinHookCaptureIdentityMatches(output, hook.expected, hook.directPID)
	if collector != nil && !identityRejected {
		captures = consumeDarwinHookCaptures(output, collector)
	}
	return platformHookSnapshot{
		TargetFound: installedCount, Installed: installedCount > 0, Captures: captures,
		Used: captures > 0, TriggerNeeded: installedCount > 0 && captures == 0 && !identityRejected,
		Route: hook.route, RouteHistory: hook.route,
		IdentityRejected: identityRejected,
	}
}

func mergePlatformHookSnapshots(values ...platformHookSnapshot) platformHookSnapshot {
	result := platformHookSnapshot{}
	for _, value := range values {
		result.TargetFound += value.TargetFound
		result.Installed = result.Installed || value.Installed
		result.TimedOut = result.TimedOut || value.TimedOut
		result.TriggerNeeded = result.TriggerNeeded || value.TriggerNeeded
		result.RestartNeeded = result.RestartNeeded || value.RestartNeeded
		result.Captures += value.Captures
		result.Used = result.Used || value.Used
		result.IdentityRejected = result.IdentityRejected || value.IdentityRejected
		routes := appendUniqueStrings(strings.Split(result.RouteHistory, "\x00"), strings.Split(value.RouteHistory, "\x00")...)
		routes = appendUniqueStrings(routes, value.Route)
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

func (hook *darwinPersistentHook) close() {
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
				_ = syscall.Kill(-hook.command.Process.Pid, syscall.SIGKILL)
				<-hook.done
			}
		}
	}
	outputBytes := hook.output.snapshot()
	output := sensitiveBytesView(outputBytes)
	if hook.directPID > 0 {
		darwinResumeAfterHook(hook.directPID)
	}
	for _, pid := range darwinCapturedPIDs(output) {
		darwinResumeAfterHook(pid)
	}
	zeroBytes(outputBytes)
	hook.output.zero()
	_ = os.Remove(hook.pythonPath)
	_ = os.Remove(hook.scriptPath)
}

func preparePlatformAcquisitionSession(targets databaseTargets, options acquireOptions) acquisitionPlatformSession {
	if !options.database || len(targets.Pages) == 0 || options.budget.expired() {
		return nil
	}
	processes, _, err := darwinTargetProcesses()
	if err != nil {
		return nil
	}
	securityPosture := defaultSecurityPostureStatus()
	var hooks []*darwinPersistentHook
	var waitTarget darwinProcess
	for _, target := range processes {
		evidence := darwinCollectBinaryEvidence(target)
		decision := evaluateDarwinRoute(evidence, darwinCompatibilityRegistry)
		if !darwinStandardRouteEligible(decision) {
			continue
		}
		route := darwinDynamicRouteID(evidence.ProcessArchitecture, securityPosture)
		if route == "" {
			continue
		}
		if hook := startDarwinPersistentHook(target, options.budget, false, route); hook != nil {
			hooks = append(hooks, hook)
		}
		if waitTarget.pid == 0 {
			waitTarget = target
		}
	}
	if len(processes) == 0 {
		waitTarget.command = darwinWeChatExecutable(darwinProcess{})
		waitTarget.name = filepath.Base(waitTarget.command)
		if !darwinPrelaunchHookEligible(darwinCollectBinaryEvidence(waitTarget)) {
			return nil
		}
	}
	if waitTarget.command != "" {
		waitRoute := "darwin_standard_dynamic_waitfor"
		if securityPosture == "sip_disabled_verified" {
			waitRoute = "darwin_sip_disabled_waitfor"
		}
		if hook := startDarwinPersistentHook(waitTarget, options.budget, true, waitRoute); hook != nil {
			hooks = append(hooks, hook)
		}
	}
	if len(hooks) == 0 {
		return nil
	}
	status := func(collector *candidateCollector) platformHookSnapshot {
		values := make([]platformHookSnapshot, 0, len(hooks))
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
		return mergePlatformHookSnapshots(values...)
	}
	return newSynchronizedPlatformSession(
		func(collector *candidateCollector) platformHookSnapshot { return status(collector) },
		func() platformHookSnapshot { return status(nil) },
		func() {
			for _, hook := range hooks {
				hook.close()
			}
		},
	)
}

func darwinResumeAfterHook(pid int) {
	// 若目标停在断点时 LLDB 因提供器超时而终止，SIGCONT 可避免微信一直冻结。
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stdout, stderr, _ := runBoundedDarwinCommand(
		ctx, "/bin/kill", []string{"-CONT", strconv.Itoa(pid)}, nil, "", 1024, 1024,
	)
	zeroBytes(stdout)
	zeroBytes(stderr)
}

func captureDarwinHookMode(process darwinProcess, collector *candidateCollector, remaining budget, waitFor bool, securityPosture string) platformHookSnapshot {
	result := platformHookSnapshot{}
	architecture := "auto"
	if !waitFor {
		var architectureStatus string
		architecture, architectureStatus, _ = darwinProcessArchitectureEvidence(process)
		if architectureStatus != darwinArchitectureVerified {
			return result
		}
	}
	if remaining.expired() {
		return result
	}
	lldb := darwinLLDBPath()
	if lldb == "" {
		return result
	}
	if waitFor {
		result.Route = "darwin_standard_dynamic_waitfor"
		if securityPosture == "sip_disabled_verified" {
			result.Route = "darwin_sip_disabled_waitfor"
		}
	} else {
		result.Route = darwinDynamicRouteID(architecture, securityPosture)
	}
	expectedProcess := process
	if expectedProcess.command == "" {
		expectedProcess.command = darwinWeChatExecutable(process)
		expectedProcess.name = filepath.Base(expectedProcess.command)
	}
	expected := darwinCollectBinaryEvidence(expectedProcess)
	if waitFor && !darwinPrelaunchHookEligible(expected) {
		return platformHookSnapshot{}
	}
	python, err := os.CreateTemp("", "v_local_key_provider_lldb_*.py")
	if err != nil {
		return result
	}
	pythonPath := python.Name()
	defer os.Remove(pythonPath)
	_ = python.Chmod(0o600)
	if _, err := python.WriteString(darwinHookPythonSource(architecture)); err != nil {
		_ = python.Close()
		return result
	}
	if err := python.Close(); err != nil {
		return result
	}
	script, err := os.CreateTemp("", "v-local-key-provider-lldb-*.cmd")
	if err != nil {
		return result
	}
	scriptPath := script.Name()
	defer os.Remove(scriptPath)
	_ = script.Chmod(0o600)
	executable := darwinWeChatExecutable(process)
	if _, err := script.WriteString(darwinHookCommandFileWithPython(waitFor, executable, pythonPath)); err != nil {
		_ = script.Close()
		return result
	}
	if err := script.Close(); err != nil {
		return result
	}
	wait := darwinHookWait
	if waitFor {
		wait = darwinHookWaitFor
	}
	if deadline, bounded := remaining.deadline(); bounded {
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
		args = []string{"-b", "-p", strconv.Itoa(process.pid), "-s", scriptPath}
	}
	command := exec.Command(lldb, args...)
	var stdout darwinHookOutputBuffer
	stderr := sensitiveOutputBuffer{limit: darwinHelperDiagnosticMax}
	defer stdout.zero()
	defer stderr.Clear()
	command.Stdout = &stdout
	command.Stderr = &stderr
	err = runDarwinCommand(ctx, command)
	if ctx.Err() != nil {
		result.TimedOut = true
		if !waitFor {
			darwinResumeAfterHook(process.pid)
		}
	} else if err != nil {
		// 目标退出或分离后 LLDB 可能以非零码退出；抓到的内存仍然有效，
		// 且下面总会独立验证。
		if !waitFor {
			darwinResumeAfterHook(process.pid)
		}
	}
	captureBytes := stdout.snapshot()
	defer zeroBytes(captureBytes)
	captureOutput := sensitiveBytesView(captureBytes)
	for _, pid := range darwinCapturedPIDs(captureOutput) {
		darwinResumeAfterHook(pid)
	}
	result.TargetFound = darwinHookPythonCount(captureOutput)
	if result.TargetFound == 0 {
		result.TargetFound = darwinLLDBBreakpointCount(captureOutput)
	}
	result.Installed = result.TargetFound > 0
	expectedPID := process.pid
	if waitFor {
		expectedPID = 0
	}
	result.IdentityRejected = !darwinHookCaptureIdentityMatches(captureOutput, expected, expectedPID)
	if !result.IdentityRejected {
		result.Captures = consumeDarwinHookCaptures(captureOutput, collector)
	}
	result.Used = result.Captures > 0
	result.TriggerNeeded = result.Installed && !result.Used
	result.RestartNeeded = waitFor && !result.Used
	return result
}
