//go:build darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestDarwinHelperExecutableUsesExplicitRegularExecutable(t *testing.T) {
	helper := filepath.Join(t.TempDir(), darwinHelperName)
	if err := os.WriteFile(helper, []byte("helper"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(darwinHelperEnvironment, helper)
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
	if actual := darwinHelperExecutable(); actual != "" {
		t.Fatalf("non-executable helper should be rejected: %q", actual)
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
	var result response
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("marked response is invalid JSON: %v", err)
	}
	if result.Diagnostics.HelperStatus != "elevated" {
		t.Fatalf("helper status = %q, want elevated", result.Diagnostics.HelperStatus)
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
