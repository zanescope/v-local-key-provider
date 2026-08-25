//go:build darwin

package provider

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDarwinHelperExecutableUsesExplicitRegularExecutable(t *testing.T) {
	helper := filepath.Join(t.TempDir(), darwinHelperName)
	if err := os.WriteFile(helper, []byte("helper"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(darwinHelperEnvironment, helper)
	t.Setenv(darwinAllowUnverifiedHelperEnvironment, "1")
	expected, err := filepath.EvalSymlinks(helper)
	if err != nil {
		t.Fatal(err)
	}
	if actual := darwinHelperExecutable(); actual != expected {
		t.Fatalf("helper path mismatch: got %q want %q", actual, expected)
	}
}

func TestDarwinHelperExecutableRejectsNonExecutableFile(t *testing.T) {
	helper := filepath.Join(t.TempDir(), darwinHelperName)
	if err := os.WriteFile(helper, []byte("helper"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(darwinHelperEnvironment, helper)
	t.Setenv(darwinAllowUnverifiedHelperEnvironment, "1")
	if actual := darwinHelperExecutable(); actual != "" {
		t.Fatalf("non-executable helper should be rejected: %q", actual)
	}
}

func TestPhase5DarwinHelperPathOverrideRequiresExplicitDevelopmentOptIn(t *testing.T) {
	helper := filepath.Join(t.TempDir(), darwinHelperName)
	if err := os.WriteFile(helper, []byte("helper"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(darwinHelperEnvironment, helper)
	t.Setenv(darwinAllowUnverifiedHelperEnvironment, "")
	if actual := darwinHelperExecutable(); actual != "" {
		t.Fatalf("unverified helper override was accepted without development opt-in: %q", actual)
	}
}

func TestPhase5DarwinReleaseRejectsHelperOverrideDespiteDevelopmentOptIn(t *testing.T) {
	previous := buildMode
	buildMode = "release"
	t.Cleanup(func() { buildMode = previous })

	helper := filepath.Join(t.TempDir(), darwinHelperName)
	if err := os.WriteFile(helper, []byte("helper"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(darwinHelperEnvironment, helper)
	t.Setenv(darwinAllowUnverifiedHelperEnvironment, "1")
	path, status := darwinHelperExecutableWithStatus()
	if path != "" || status != "untrusted" {
		t.Fatalf("release build accepted helper override: path=%q status=%q", path, status)
	}
}

func TestDarwinHelperModeDefaultsToAuto(t *testing.T) {
	t.Setenv(darwinHelperModeEnvironment, "")
	if got := darwinHelperMode(); got != "auto" {
		t.Fatalf("default helper mode = %q, want auto", got)
	}
}

func TestDarwinHelperModeRejectsUnknownValue(t *testing.T) {
	t.Setenv(darwinHelperModeEnvironment, "unexpected")
	if got := darwinHelperMode(); got != "auto" {
		t.Fatalf("unknown helper mode = %q, want auto", got)
	}
}

func TestPhase5DarwinReleaseDisablesElevatedCompatibilityPath(t *testing.T) {
	previous := buildMode
	buildMode = "release"
	t.Cleanup(func() { buildMode = previous })
	t.Setenv(darwinHelperModeEnvironment, "elevated")

	if got := darwinHelperMode(); got != "direct" {
		t.Fatalf("release helper mode = %q, want direct", got)
	}
	output, status := runDarwinHelperElevated("/untrusted/helper", []byte("secret"), unlimitedBudget())
	defer zeroBytes(output)
	if len(output) != 0 || status != "elevation_disabled_in_release" {
		t.Fatalf("release elevation was not fail closed: output=%q status=%q", output, status)
	}
	if err := runPlatformElevatedHelperClient("127.0.0.1:1", strings.Repeat("a", 64)); err == nil {
		t.Fatal("release elevated-helper client was unexpectedly enabled")
	}
}

func TestDarwinHelperAccessDeniedUsesDiagnostics(t *testing.T) {
	denied := []byte(`{"diagnostics":{"process_access_status":"denied"}}`)
	if !darwinHelperAccessDenied(denied) {
		t.Fatal("denied diagnostics were not detected")
	}
	allowed := []byte(`{"diagnostics":{"process_access_status":"helper_opened"}}`)
	if darwinHelperAccessDenied(allowed) {
		t.Fatal("opened diagnostics were incorrectly treated as denied")
	}
}

func TestMarkDarwinHelperStatusPreservesProtocolAndStatus(t *testing.T) {
	input := []byte(`{"database_keys":{"db":"0123456789abcdef"},"diagnostics":{"platform":"darwin"}}`)
	output := markDarwinHelperStatus(input, "elevated", "")
	defer zeroBytes(output)
	var result response
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("marked response is invalid JSON: %v", err)
	}
	if result.Diagnostics.HelperStatus != "elevated" {
		t.Fatalf("helper status = %q, want elevated", result.Diagnostics.HelperStatus)
	}
	for index, value := range input {
		if value != 0 {
			t.Fatalf("input contained sensitive data after replacement at byte %d", index)
		}
	}
}

func TestRunDarwinCommandStopsAtDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := runDarwinCommand(ctx, exec.Command("/bin/sh", "-c", "sleep 5"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline error = %v, want context deadline", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("deadline command took too long: %v", elapsed)
	}
}

func TestRunBoundedDarwinCommandStopsOnOutputLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	stdout, stderr, err := runBoundedDarwinCommand(ctx, "/usr/bin/yes", nil, nil, "", 1024, 1024)
	defer zeroBytes(stdout)
	defer zeroBytes(stderr)
	if !errors.Is(err, errDarwinCommandOutputLimit) {
		t.Fatalf("output-limit error = %v, want %v", err, errDarwinCommandOutputLimit)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("output-limited command took too long: %v", elapsed)
	}
}

func TestParseDarwinSIPStatusRejectsCustomOrUnknownConfigurations(t *testing.T) {
	if enabled, known := parseDarwinSIPStatus("System Integrity Protection status: enabled."); !known || !enabled {
		t.Fatalf("enabled SIP was not recognized: enabled=%v known=%v", enabled, known)
	}
	if enabled, known := parseDarwinSIPStatus("System Integrity Protection status: disabled."); !known || enabled {
		t.Fatalf("disabled SIP was not recognized: enabled=%v known=%v", enabled, known)
	}
	if _, known := parseDarwinSIPStatus("System Integrity Protection status: unknown (Custom Configuration)."); known {
		t.Fatal("custom SIP configuration was treated as verified enabled/disabled")
	}
	for _, injected := range []string{
		"prefix System Integrity Protection status: enabled.",
		"System Integrity Protection status: enabled. suffix",
		"System Integrity Protection status: enabled.\nSystem Integrity Protection status: disabled.",
		"system integrity protection status: enabled.",
	} {
		if _, known := parseDarwinSIPStatus(injected); known {
			t.Fatalf("non-canonical SIP output was accepted: %q", injected)
		}
	}
	if enabled, known := parseDarwinSIPStatus("System Integrity Protection status: enabled.\r\n"); !known || !enabled {
		t.Fatal("canonical CRLF-terminated SIP output was rejected")
	}
}

func TestExchangeDarwinElevatedHelperKeepsPayloadOnLoopback(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	token := strings.Repeat("a", 64)
	request := []byte(`{"protocol":"v-local-key-provider/v1","request_id":"test"}`)
	done := make(chan darwinHelperExchange, 1)
	go func() {
		done <- exchangeDarwinElevatedHelper(listener, token, request, time.Now().Add(2*time.Second))
	}()
	connection, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	if _, err := connection.Write([]byte(token + "\n")); err != nil {
		t.Fatal(err)
	}
	payload, err := reader.ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	if string(bytes.TrimSpace(payload)) != string(request) {
		t.Fatalf("request mismatch: %s", payload)
	}
	if _, err := connection.Write([]byte(`{"diagnostics":{"platform":"darwin"}}` + "\n")); err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	result := <-done
	defer zeroBytes(result.output)
	if result.err != nil || !bytes.Contains(result.output, []byte(`"platform":"darwin"`)) {
		t.Fatalf("exchange failed: output=%s err=%v", result.output, result.err)
	}
}
