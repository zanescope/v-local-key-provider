//go:build darwin && cgo

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const darwinHookWait = 12 * time.Second
const darwinHookWaitFor = 60 * time.Second
const darwinHookOutputMax = 4 * 1024 * 1024

type darwinHookOutputBuffer struct {
	bytes.Buffer
}

func (buffer *darwinHookOutputBuffer) Write(data []byte) (int, error) {
	remaining := darwinHookOutputMax - buffer.Len()
	if remaining > 0 {
		chunk := data
		if len(chunk) > remaining {
			chunk = chunk[:remaining]
		}
		_, _ = buffer.Buffer.Write(chunk)
	}
	return len(data), nil
}

type darwinHookResult struct {
	targetFound   int
	installed     bool
	timedOut      bool
	triggerNeeded bool
	restartNeeded bool
	captures      int
	used          bool
}

var darwinLLDBBreakpointPattern = regexp.MustCompile(`(?m)^Breakpoint [0-9]+:`)

func darwinLLDBBreakpointCount(output string) int {
	count := 0
	for _, line := range strings.Split(output, "\n") {
		if !darwinLLDBBreakpointPattern.MatchString(line) || strings.Contains(strings.ToLower(line), "no locations") {
			continue
		}
		count++
	}
	return count
}

func darwinProcessExecutable(process darwinProcess) string {
	command := strings.TrimSpace(process.command)
	if command == "" {
		command = process.name
	}
	if fields := strings.Fields(command); len(fields) > 0 {
		candidate := strings.Trim(fields[0], "'\"")
		if filepath.IsAbs(candidate) {
			return candidate
		}
	}
	if filepath.IsAbs(process.name) {
		return process.name
	}
	return ""
}

func darwinProcessVersion(process darwinProcess) string {
	executable := darwinProcessExecutable(process)
	marker := strings.Index(executable, ".app/Contents/")
	if marker < 0 {
		return ""
	}
	appPath := executable[:marker+len(".app")]
	plist := filepath.Join(appPath, "Contents", "Info.plist")
	output, err := exec.Command("/usr/libexec/PlistBuddy", "-c", "Print:CFBundleShortVersionString", plist).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func darwinProcessArchitecture(process darwinProcess) string {
	executable := darwinProcessExecutable(process)
	if executable == "" {
		return runtime.GOARCH
	}
	output, err := exec.Command("/usr/bin/file", "-b", executable).Output()
	if err != nil {
		return runtime.GOARCH
	}
	value := strings.ToLower(string(output))
	hasX8664 := strings.Contains(value, "x86_64")
	hasArm64 := strings.Contains(value, "arm64")
	switch {
	case hasX8664 && !hasArm64:
		return "amd64"
	case hasArm64 && !hasX8664:
		return "arm64"
	case runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64":
		// 通用二进制通常以与 helper 相同的架构启动；这也涵盖 Rosetta 下的 Intel helper。
		return runtime.GOARCH
	default:
		return "unknown"
	}
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
	if path, err := exec.LookPath("lldb"); err == nil {
		return path
	}
	if _, err := os.Stat("/usr/bin/lldb"); err == nil {
		return "/usr/bin/lldb"
	}
	return ""
}

// darwinHookPythonSource 使用 LLDB 的 Python 回调 API。x86_64 上
// CCCryptorCreateWithMode 的 key 长度是第 7 个参数，因此落在 [rsp+8]；
// 若把 r8/r9 当作 key/keyLength 会读到 IV。
func darwinHookPythonSource(architecture, capturePath string) string {
	keyRegister, lengthRegister := "r8", "r9"
	if architecture == "arm64" {
		keyRegister, lengthRegister = "x5", "x6"
	}
	return fmt.Sprintf(`import lldb

_seen = set()
_architecture = %q
_capture_path = %q

def _append(line):
    with open(_capture_path, "a") as output:
        output.write(line + "\n")
        output.flush()

def _register(frame, name):
    value = frame.FindRegister(name)
    return value.GetValueAsUnsigned() if value.IsValid() else 0

def _read(process, address, length):
    if address == 0 or length <= 0 or length > 256:
        return None
    error = lldb.SBError()
    data = process.ReadMemory(address, length, error)
    if not error.Success() or len(data) != length:
        return None
    return data.hex()

def _read_uint(process, address):
    raw = _read(process, address, 8)
    return int.from_bytes(bytes.fromhex(raw), "little") if raw else 0

def _emit(frame, key_address, key_length):
    if key_length != 32:
        return False
    key = _read(frame.GetThread().GetProcess(), key_address, 32)
    if key is not None and key not in _seen:
        _seen.add(key)
        _append("VLOCALKEY32=" + key)
    return False

def _create_bp(target, name, callback):
    breakpoint = target.BreakpointCreateByName(name)
    breakpoint.SetScriptCallbackFunction(__name__ + "." + callback)
    return breakpoint

def cryptor_bp(frame, breakpoint_location, internal_dict):
    if _architecture == "arm64":
        return _emit(frame, _register(frame, "x3"), _register(frame, "x4"))
    return _emit(frame, _register(frame, "rcx"), _register(frame, "r8"))

def with_mode_bp(frame, breakpoint_location, internal_dict):
    if _architecture == "arm64":
        return _emit(frame, _register(frame, %q), _register(frame, %q))
    process = frame.GetThread().GetProcess()
    stack = _register(frame, "rsp")
    return _emit(frame, _register(frame, "r9"), _read_uint(process, stack + 8))

def __lldb_init_module(debugger, internal_dict):
    target = debugger.GetSelectedTarget()
    if not target.IsValid():
        return
    breakpoints = [
        _create_bp(target, "CCCrypt", "cryptor_bp"),
        _create_bp(target, "CCCryptorCreate", "cryptor_bp"),
        _create_bp(target, "CCCryptorCreateWithMode", "with_mode_bp"),
    ]
    installed = sum(1 for breakpoint in breakpoints if breakpoint.IsValid())
    _append("VLOCALHOOKS=" + str(installed))
`, architecture, capturePath, keyRegister, lengthRegister)
}

func darwinHookCommandFileWithPython(waitFor bool, executable, pythonPath string) string {
	commands := []string{
		"settings set auto-confirm true",
		"settings set target.process.stop-on-sharedlibrary-events false",
		"settings set stop-disassembly-display never",
	}
	if waitFor {
		if executable != "" {
			commands = append(commands, fmt.Sprintf("target create %q", executable))
		}
		commands = append(commands,
			fmt.Sprintf("command script import %q", pythonPath),
			fmt.Sprintf("process attach --name %s --waitfor", darwinWaitForProcessName(executable)),
			"process continue",
		)
		return strings.Join(commands, "\n") + "\n"
	}
	commands = append(commands,
		fmt.Sprintf("command script import %q", pythonPath),
		"process continue",
	)
	return strings.Join(commands, "\n") + "\n"
}

var darwinHookPythonKeyPattern = regexp.MustCompile(`(?m)^VLOCALKEY32=([0-9a-fA-F]{64})\s*$`)
var darwinHookPythonCountPattern = regexp.MustCompile(`(?m)^VLOCALHOOKS=([0-9]+)\s*$`)

func parseDarwinHookPythonKeys(output string) [][]byte {
	var captures [][]byte
	for _, match := range darwinHookPythonKeyPattern.FindAllStringSubmatch(output, -1) {
		candidate, err := hex.DecodeString(match[1])
		if err == nil && len(candidate) == 32 {
			captures = append(captures, candidate)
		}
	}
	return captures
}

func darwinHookPythonCount(output string) int {
	match := darwinHookPythonCountPattern.FindStringSubmatch(output)
	if len(match) != 2 {
		return 0
	}
	count, _ := strconv.Atoi(match[1])
	return count
}

func darwinResumeAfterHook(pid int) {
	// 若目标停在断点时 lldb 被提供器时限终止，SIGCONT 可避免微信一直冻结。
	_ = exec.Command("/bin/kill", "-CONT", strconv.Itoa(pid)).Run()
}

func darwinResumeWaitForHook(processName string) {
	// wait-for 调试器可能附加到刚重启的微信进程；若提供器时限终止了 lldb，
	// 就恢复该命名目标。
	_ = exec.Command("/usr/bin/killall", "-CONT", processName).Run()
}

func captureDarwinHookMode(process darwinProcess, collector *candidateCollector, remaining budget, waitFor bool) darwinHookResult {
	result := darwinHookResult{}
	architecture := darwinProcessArchitecture(process)
	if remaining.expired() {
		return result
	}
	lldb := darwinLLDBPath()
	if lldb == "" {
		return result
	}
	capture, err := os.CreateTemp("", "v-local-key-provider-hook-*.capture")
	if err != nil {
		return result
	}
	capturePath := capture.Name()
	defer os.Remove(capturePath)
	_ = capture.Chmod(0o600)
	if err := capture.Close(); err != nil {
		return result
	}
	python, err := os.CreateTemp("", "v_local_key_provider_lldb_*.py")
	if err != nil {
		return result
	}
	pythonPath := python.Name()
	defer os.Remove(pythonPath)
	_ = python.Chmod(0o600)
	if _, err := python.WriteString(darwinHookPythonSource(architecture, capturePath)); err != nil {
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
	processName := darwinWaitForProcessName(executable)
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
	if !remaining.unlimited {
		available := time.Until(remaining.deadline) - 250*time.Millisecond
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
	command := exec.CommandContext(ctx, lldb, args...)
	var stdout darwinHookOutputBuffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err = command.Run()
	if ctx.Err() != nil {
		result.timedOut = true
		if waitFor {
			darwinResumeWaitForHook(processName)
		} else {
			darwinResumeAfterHook(process.pid)
		}
	} else if err != nil {
		// 目标退出或分离后 lldb 可能以非零码退出；抓到的内存仍然有效，
		// 且下面总会独立验证。
		if waitFor {
			darwinResumeWaitForHook(processName)
		} else {
			darwinResumeAfterHook(process.pid)
		}
	}
	captureData, _ := os.ReadFile(capturePath)
	captureOutput := string(captureData)
	result.targetFound = darwinHookPythonCount(captureOutput)
	if result.targetFound == 0 {
		result.targetFound = darwinLLDBBreakpointCount(stdout.String())
	}
	result.installed = result.targetFound > 0
	candidates := parseDarwinHookPythonKeys(captureOutput)
	for _, candidate := range candidates {
		result.captures++
		collector.considerBinaryDatabaseKey(candidate, true)
	}
	result.used = result.captures > 0
	result.triggerNeeded = result.installed && !result.used
	result.restartNeeded = waitFor && !result.used
	return result
}
