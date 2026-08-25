//go:build darwin

package provider

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const darwinHelperEnvironment = "V_LOCAL_KEY_PROVIDER_HELPER"
const darwinAllowUnverifiedHelperEnvironment = "V_LOCAL_KEY_PROVIDER_ALLOW_UNVERIFIED_HELPER"
const darwinHelperModeEnvironment = "V_LOCAL_KEY_PROVIDER_MACOS_HELPER_MODE"
const darwinHelperName = "v-local-key-provider-helper"
const darwinHelperOutputMax = maxResponseBytes
const darwinHelperDiagnosticMax = 256 * 1024
const darwinHelperLoopbackTimeout = 2 * time.Minute

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
	path, _ := darwinHelperExecutableWithStatus()
	return path
}

func darwinHelperExecutableWithStatus() (string, string) {
	executable, err := os.Executable()
	if err != nil {
		return "", "untrusted"
	}
	executable, err = filepathEvalCanonical(executable)
	if err != nil {
		return "", "untrusted"
	}
	if configured := os.Getenv(darwinHelperEnvironment); configured != "" {
		if releaseBuild() || os.Getenv(darwinAllowUnverifiedHelperEnvironment) != "1" {
			return "", "untrusted"
		}
		path := canonicalDarwinHelper(configured, executable)
		if path == "" {
			return "", "untrusted"
		}
		return path, "development_override"
	}
	helper := canonicalDarwinHelper(filepath.Join(filepath.Dir(executable), darwinHelperName), executable)
	if helper == "" {
		return "", "not_installed"
	}
	if err := validateDarwinComponentPair(executable, helper); err != nil {
		return "", "untrusted"
	}
	if releaseBuild() {
		return helper, "trusted"
	}
	return helper, "development"
}

func darwinHelperMode() string {
	// The AppleScript compatibility path executes the companion as root without
	// a privilege-separated service boundary. Signed releases therefore use
	// only the ordinary, same-user companion until such a service exists.
	if releaseBuild() {
		return "direct"
	}
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
	var result struct {
		Diagnostics struct {
			ProcessAccessStatus string `json:"process_access_status"`
			ProcessAccessError  string `json:"process_access_error"`
		} `json:"diagnostics"`
	}
	if json.Unmarshal(output, &result) != nil {
		return false
	}
	return result.Diagnostics.ProcessAccessStatus == "denied" ||
		result.Diagnostics.ProcessAccessError == "task_for_pid_denied"
}

func replaceDarwinRawMessage(values map[string]json.RawMessage, key string, replacement json.RawMessage) {
	if previous := values[key]; len(previous) > 0 {
		zeroBytes(previous)
	}
	values[key] = replacement
}

func markDarwinHelperStatus(output []byte, helperStatus, processAccessError string) []byte {
	var envelope map[string]json.RawMessage
	if json.Unmarshal(output, &envelope) != nil {
		return output
	}
	defer func() {
		for _, value := range envelope {
			zeroBytes(value)
		}
	}()
	var values map[string]json.RawMessage
	if json.Unmarshal(envelope["diagnostics"], &values) != nil {
		return output
	}
	defer func() {
		for _, value := range values {
			zeroBytes(value)
		}
	}()
	statusJSON, _ := json.Marshal(helperStatus)
	replaceDarwinRawMessage(values, "helper_status", statusJSON)
	if processAccessError != "" {
		errorJSON, _ := json.Marshal(processAccessError)
		replaceDarwinRawMessage(values, "process_access_error", errorJSON)
	}
	diagnosticsJSON, err := json.Marshal(values)
	if err != nil {
		return output
	}
	defer zeroBytes(diagnosticsJSON)
	replaceDarwinRawMessage(envelope, "diagnostics", diagnosticsJSON)
	updated, err := json.Marshal(envelope)
	if err != nil {
		return output
	}
	framed := make([]byte, len(updated)+1)
	copy(framed, updated)
	framed[len(framed)-1] = '\n'
	zeroBytes(updated)
	markSensitiveBytes(framed)
	zeroBytes(output)
	return framed
}

func darwinSIPEnabled() (bool, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := runBoundedDarwinCombinedOutput(ctx, "/usr/bin/csrutil", []string{"status"}, 16*1024)
	defer zeroBytes(output)
	if err != nil {
		return false, false
	}
	return parseDarwinSIPStatus(string(output))
}

func parseDarwinSIPStatus(output string) (bool, bool) {
	status := strings.TrimSpace(strings.ReplaceAll(output, "\r\n", "\n"))
	switch status {
	case "System Integrity Protection status: enabled.":
		return true, true
	case "System Integrity Protection status: disabled.":
		return false, true
	}
	return false, false
}

func helperContext(remaining budget) (context.Context, context.CancelFunc) {
	deadline, bounded := remaining.deadline()
	if !bounded {
		return context.WithTimeout(context.Background(), darwinHelperLoopbackTimeout)
	}
	return context.WithDeadline(context.Background(), deadline)
}

func runDarwinHelperDirect(helper string, payload []byte, remaining budget) ([]byte, string) {
	if helper == "" {
		return nil, "not_installed"
	}
	ctx, cancel := helperContext(remaining)
	defer cancel()
	stdout, stderr, err := runBoundedDarwinCommand(
		ctx, helper, []string{"helper-acquire"}, bytes.NewReader(payload), filepath.Dir(helper),
		darwinHelperOutputMax+1, darwinHelperDiagnosticMax,
	)
	defer zeroBytes(stdout)
	defer zeroBytes(stderr)
	if err != nil || len(stdout) == 0 || len(stdout) > darwinHelperOutputMax {
		if ctx.Err() != nil {
			return nil, "deadline_exhausted"
		}
		return nil, "launch_failed"
	}
	return cloneSensitiveBytes(stdout), "used"
}

type darwinHelperExchange struct {
	output []byte
	err    error
}

func darwinHelperDeadline(remaining budget) time.Time {
	if deadline, bounded := remaining.deadline(); bounded {
		return deadline
	}
	return time.Now().Add(darwinHelperLoopbackTimeout)
}

func readDarwinHelperLine(reader *bufio.Reader, limit int) ([]byte, error) {
	payload, err := reader.ReadSlice('\n')
	if len(payload) > 0 {
		defer zeroBytes(payload)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(payload) == 0 || len(payload) > limit+1 {
		return nil, errors.New("helper frame is empty or too large")
	}
	return cloneSensitiveBytes(bytes.TrimSpace(payload)), nil
}

func exchangeDarwinElevatedHelper(listener *net.TCPListener, token string, payload []byte, deadline time.Time) darwinHelperExchange {
	_ = listener.SetDeadline(deadline)
	for attempts := 0; attempts < 8; attempts++ {
		connection, err := listener.AcceptTCP()
		if err != nil {
			return darwinHelperExchange{err: err}
		}
		_ = connection.SetDeadline(deadline)
		reader := bufio.NewReaderSize(connection, darwinHelperOutputMax+2)
		presented, readErr := readDarwinHelperLine(reader, 64)
		authenticated := readErr == nil && len(presented) == 64 && subtle.ConstantTimeCompare(presented, []byte(token)) == 1
		zeroBytes(presented)
		if !authenticated {
			_ = connection.Close()
			continue
		}
		var compact bytes.Buffer
		compact.Grow(len(payload))
		defer func() { zeroBytes(compact.Bytes()) }()
		if err := json.Compact(&compact, payload); err != nil {
			_ = connection.Close()
			return darwinHelperExchange{err: err}
		}
		if _, err := io.Copy(connection, bytes.NewReader(compact.Bytes())); err != nil {
			_ = connection.Close()
			return darwinHelperExchange{err: err}
		}
		if _, err := io.WriteString(connection, "\n"); err != nil {
			_ = connection.Close()
			return darwinHelperExchange{err: err}
		}
		output, err := readDarwinHelperLine(reader, darwinHelperOutputMax)
		_ = connection.Close()
		if err != nil {
			return darwinHelperExchange{err: err}
		}
		return darwinHelperExchange{output: output}
	}
	return darwinHelperExchange{err: errors.New("helper authentication failed")}
}

// runDarwinHelperElevated 请求 macOS 授权随附的辅助程序，但获取请求和响应均不落盘。
// 除回环地址外，命令行只携带一个短生命周期的随机传输令牌。
func runDarwinHelperElevated(helper string, payload []byte, remaining budget) ([]byte, string) {
	if releaseBuild() {
		return nil, "elevation_disabled_in_release"
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		return nil, "launch_failed"
	}
	defer listener.Close()
	token, err := randomDaemonToken()
	if err != nil {
		return nil, "launch_failed"
	}
	deadline := darwinHelperDeadline(remaining)
	exchange := make(chan darwinHelperExchange, 1)
	go func() { exchange <- exchangeDarwinElevatedHelper(listener, token, payload, deadline) }()

	shellCommand := darwinShellQuote(helper) + " helper-acquire-loopback " +
		darwinShellQuote(listener.Addr().String()) + " " + darwinShellQuote(token) +
		" 2>/dev/null; rc=$?; /bin/echo VLP_RC:$rc"
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
	stdout, stderr, err := runBoundedDarwinCommand(
		ctx, "/usr/bin/osascript", []string{"-e", appleScript}, nil, "",
		darwinHelperDiagnosticMax, darwinHelperDiagnosticMax,
	)
	defer zeroBytes(stdout)
	defer zeroBytes(stderr)
	_ = listener.Close()
	result := <-exchange
	marker := sensitiveOutputBuffer{limit: 2 * darwinHelperDiagnosticMax}
	_, _ = marker.Write(stdout)
	_, _ = marker.Write(stderr)
	defer marker.Clear()
	if err != nil || result.err != nil || marker.over || !bytes.Contains(marker.Bytes(), []byte("VLP_RC:0")) {
		if ctx.Err() != nil {
			return nil, "deadline_exhausted"
		}
		return nil, "launch_failed"
	}
	if len(result.output) == 0 || len(result.output) > darwinHelperOutputMax {
		return nil, "launch_failed"
	}
	return result.output, "elevated"
}

func runPlatformElevatedHelperClient(address, token string) error {
	if releaseBuild() {
		return errors.New("elevated helper transport is disabled in release builds")
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("elevated helper address is invalid")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || len(token) != 64 {
		return errors.New("elevated helper endpoint is invalid")
	}
	connection, err := net.DialTimeout("tcp4", address, 10*time.Second)
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(darwinHelperLoopbackTimeout))
	if _, err := io.WriteString(connection, token+"\n"); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(connection, maxRequestBytes+2)
	payload, err := readDarwinHelperLine(reader, maxRequestBytes)
	if err != nil {
		return err
	}
	markSensitiveBytes(payload)
	defer zeroBytes(payload)
	request, err := decodeRequestData(payload)
	if err != nil {
		return err
	}
	result, err := executeOneShotAcquire(request, true, "elevated")
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > darwinHelperOutputMax {
		return errors.New("elevated helper response is invalid")
	}
	markSensitiveBytes(encoded)
	defer zeroBytes(encoded)
	if _, err = io.Copy(connection, bytes.NewReader(encoded)); err != nil {
		return err
	}
	_, err = io.WriteString(connection, "\n")
	return err
}

// delegateToPlatformHelper 让面向用户的入口保持为单条命令。自动模式下先尝试
// 普通伴随组件；管理员鉴权的兼容路径严格限于 development 构建。
func delegateToPlatformHelper(payload []byte, remaining budget) (bool, string) {
	helper, trustStatus := darwinHelperExecutableWithStatus()
	if helper == "" {
		return false, trustStatus
	}
	mode := darwinHelperMode()
	var directOutput []byte
	var directStatus string
	if mode != "elevated" {
		directOutput, directStatus = runDarwinHelperDirect(helper, payload, remaining)
		defer func() { zeroBytes(directOutput) }()
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
	if !remaining.isUnlimited() && remaining.expired() {
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
	defer func() { zeroBytes(elevatedOutput) }()
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
