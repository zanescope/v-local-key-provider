//go:build darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const darwinHelperEnvironment = "V_LOCAL_KEY_PROVIDER_HELPER"
const darwinHelperModeEnvironment = "V_LOCAL_KEY_PROVIDER_MACOS_HELPER_MODE"
const darwinHelperName = "v-local-key-provider-helper"
const darwinHelperOutputMax = maxRequestBytes

func canonicalDarwinHelper(candidate, executable string) string {
	if candidate == "" {
		return ""
	}
	absolute, err := filepath.Abs(candidate)
	if err != nil {
		return ""
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return ""
	}
	current, _ := filepath.EvalSymlinks(executable)
	if current != "" && resolved == current {
		return ""
	}
	return resolved
}

func darwinHelperExecutable() string {
	executable, err := os.Executable()
	if err != nil {
		return ""
	}
	if configured := os.Getenv(darwinHelperEnvironment); configured != "" {
		return canonicalDarwinHelper(configured, executable)
	}
	return canonicalDarwinHelper(filepath.Join(filepath.Dir(executable), darwinHelperName), executable)
}

func darwinHelperMode() string {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv(darwinHelperModeEnvironment)))
	switch mode {
	case "direct", "elevated", "auto":
		return mode
	default:
		return "auto"
	}
}

func darwinShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func darwinHelperAccessDenied(output []byte) bool {
	var result response
	if json.Unmarshal(output, &result) != nil {
		return false
	}
	return result.Diagnostics.ProcessAccessStatus == "denied" ||
		result.Diagnostics.ProcessAccessError == "task_for_pid_denied"
}

func markDarwinHelperStatus(output []byte, helperStatus, processAccessError string) []byte {
	var result response
	if json.Unmarshal(output, &result) != nil {
		return output
	}
	result.Diagnostics.HelperStatus = helperStatus
	if processAccessError != "" {
		result.Diagnostics.ProcessAccessError = processAccessError
	}
	updated, err := json.Marshal(result)
	if err != nil {
		return output
	}
	return append(updated, '\n')
}

func darwinSIPEnabled() (bool, bool) {
	output, err := exec.Command("/usr/bin/csrutil", "status").CombinedOutput()
	if err != nil {
		return false, false
	}
	return strings.Contains(strings.ToLower(string(output)), "status: enabled"), true
}

func helperContext(remaining budget) (context.Context, context.CancelFunc) {
	if remaining.unlimited {
		return context.Background(), func() {}
	}
	return context.WithDeadline(context.Background(), remaining.deadline)
}

// runDarwinCommand 独占 helper 的进程组，这样时限到点后不会把 lldb 或
// AppleScript 拉起的 shell 遗留成孤儿进程。
func runDarwinCommand(ctx context.Context, command *exec.Cmd) error {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return err
	}
	finished := make(chan error, 1)
	go func() { finished <- command.Wait() }()
	select {
	case err := <-finished:
		return err
	case <-ctx.Done():
		if command.Process != nil {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		}
		<-finished
		return ctx.Err()
	}
}

func runDarwinHelperDirect(helper string, payload []byte, remaining budget) ([]byte, string) {
	if helper == "" {
		return nil, "not_installed"
	}
	ctx, cancel := helperContext(remaining)
	defer cancel()
	command := exec.Command(helper, "helper-acquire")
	command.Dir = filepath.Dir(helper)
	command.Stdin = bytes.NewReader(payload)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := runDarwinCommand(ctx, command); err != nil || stdout.Len() == 0 || stdout.Len() > darwinHelperOutputMax {
		if ctx.Err() != nil {
			return nil, "deadline_exhausted"
		}
		return nil, "launch_failed"
	}
	return stdout.Bytes(), "used"
}

// runDarwinHelperElevated 沿用 WeFlow 的兼容路径：helper 通过管理员鉴权的
// AppleScript 运行。请求与响应都留在 0600 临时文件里，两者都不落日志。
func runDarwinHelperElevated(helper string, payload []byte, remaining budget) ([]byte, string) {
	requestFile, err := os.CreateTemp("", "v-local-key-provider-request-*.json")
	if err != nil {
		return nil, "launch_failed"
	}
	requestPath := requestFile.Name()
	defer os.Remove(requestPath)
	_ = requestFile.Chmod(0o600)
	if _, err := requestFile.Write(payload); err != nil {
		_ = requestFile.Close()
		return nil, "launch_failed"
	}
	if err := requestFile.Close(); err != nil {
		return nil, "launch_failed"
	}

	outputFile, err := os.CreateTemp("", "v-local-key-provider-response-*.json")
	if err != nil {
		return nil, "launch_failed"
	}
	outputPath := outputFile.Name()
	defer os.Remove(outputPath)
	_ = outputFile.Chmod(0o600)
	if err := outputFile.Close(); err != nil {
		return nil, "launch_failed"
	}

	shellCommand := darwinShellQuote(helper) + " helper-acquire < " + darwinShellQuote(requestPath) +
		" > " + darwinShellQuote(outputPath) + " 2>/dev/null; rc=$?; /bin/echo VLP_RC:$rc"
	appleScript := "set cmd to " + strconv.Quote(shellCommand) + "\n" +
		"try\n" +
		"with timeout of 120 seconds\n" +
		"set marker to do shell script cmd with administrator privileges\n" +
		"end timeout\n" +
		"return marker\n" +
		"on error errMsg number errNum\n" +
		"return \"VLP_ERR::\" & errNum & \"::\" & errMsg\n" +
		"end try"
	ctx, cancel := helperContext(remaining)
	defer cancel()
	command := exec.Command("/usr/bin/osascript", "-e", appleScript)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err = runDarwinCommand(ctx, command)
	marker := append(stdout.Bytes(), stderr.Bytes()...)
	if err != nil || !strings.Contains(string(marker), "VLP_RC:0") {
		if ctx.Err() != nil {
			return nil, "deadline_exhausted"
		}
		return nil, "launch_failed"
	}
	output, err := os.ReadFile(outputPath)
	if err != nil || len(output) == 0 || len(output) > darwinHelperOutputMax {
		return nil, "launch_failed"
	}
	return output, "elevated"
}

// delegateToPlatformHelper 让面向用户的入口保持为单条命令。auto 模式下先尝试
// 普通伴随组件，只有在 task_for_pid 被拒时才回退到管理员鉴权的兼容路径。
func delegateToPlatformHelper(payload []byte, remaining budget) (bool, string) {
	helper := darwinHelperExecutable()
	if helper == "" {
		return false, "not_installed"
	}
	mode := darwinHelperMode()
	var directOutput []byte
	var directStatus string
	if mode != "elevated" {
		directOutput, directStatus = runDarwinHelperDirect(helper, payload, remaining)
		if directStatus == "used" && !darwinHelperAccessDenied(directOutput) {
			if _, err := os.Stdout.Write(directOutput); err != nil {
				return false, "response_failed"
			}
			return true, "used"
		}
		if mode == "direct" {
			if len(directOutput) > 0 {
				if _, err := os.Stdout.Write(directOutput); err != nil {
					return false, "response_failed"
				}
				return true, directStatus
			}
			return false, directStatus
		}
	}
	if !remaining.unlimited && remaining.expired() {
		return false, "deadline_exhausted"
	}

	if sipEnabled, known := darwinSIPEnabled(); known && sipEnabled {
		if len(directOutput) > 0 {
			directOutput = markDarwinHelperStatus(directOutput, "sip_enabled", "sip_enabled")
			if _, err := os.Stdout.Write(directOutput); err != nil {
				return false, "response_failed"
			}
			return true, "sip_enabled"
		}
		return false, "sip_enabled"
	}

	elevatedOutput, elevatedStatus := runDarwinHelperElevated(helper, payload, remaining)
	if elevatedStatus == "elevated" {
		elevatedOutput = markDarwinHelperStatus(elevatedOutput, "elevated", "")
		if _, err := os.Stdout.Write(elevatedOutput); err != nil {
			return false, "response_failed"
		}
		return true, "elevated"
	}
	if len(directOutput) > 0 {
		if _, err := os.Stdout.Write(directOutput); err != nil {
			return false, "response_failed"
		}
		return true, directStatus
	}
	return false, elevatedStatus
}
