package provider

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDaemonImplementationStaysBehindInternalBoundary(t *testing.T) {
	allowedRoot := map[string]bool{
		"daemon_adapter.go":       true,
		"daemon_launch_darwin.go": true,
		"daemon_launch_other.go":  true,
	}
	rootEntries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range rootEntries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "daemon_") || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if !allowedRoot[name] {
			t.Errorf("daemon implementation returned to the Provider root: %s", name)
		}
	}

	requiredInternal := []string{
		"server.go", "stdio.go", "transport.go", "transport_darwin.go", "transport_other.go", "transport_windows.go",
		"security_unix.go", "security_windows.go",
	}
	for _, name := range requiredInternal {
		if _, err := os.Stat(filepath.Join("internal", "daemon", name)); err != nil {
			t.Errorf("internal daemon implementation is missing %s: %v", name, err)
		}
	}

	entries, err := os.ReadDir(filepath.Join("internal", "daemon"))
	if err != nil {
		t.Fatal(err)
	}
	files := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join("internal", "daemon", name)
		parsed, err := parser.ParseFile(files, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Errorf("cannot parse %s: %v", path, err)
			continue
		}
		for _, imported := range parsed.Imports {
			value, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Errorf("cannot decode import in %s: %v", path, err)
				continue
			}
			if value == "github.com/zanescope/v-local-key-provider" {
				t.Errorf("%s imports the Provider composition root", path)
			}
		}
	}
}

func TestWindowsAcquisitionImplementationStaysBehindInternalBoundary(t *testing.T) {
	legacyRoot := []string{
		"windows_binary_evidence_windows.go",
		"windows_config_cipher_windows.go",
		"windows_memory_policy_adapter_windows.go",
		"windows_memory_scan_windows.go",
		"windows_process_binding_adapter_windows.go",
		"windows_process_binding_windows.go",
		"session_process_windows.go",
	}
	for _, name := range legacyRoot {
		if _, err := os.Stat(name); err == nil || !os.IsNotExist(err) {
			t.Errorf("Windows implementation returned to the Provider root: %s", name)
		}
	}

	requiredInternal := []string{
		"driver.go", "process.go", "native_process_windows.go", "native_evidence_windows.go",
		"native_binding_windows.go", "native_config_windows.go", "native_memory_windows.go",
	}
	for _, name := range requiredInternal {
		if _, err := os.Stat(filepath.Join("internal", "platform", "windows", name)); err != nil {
			t.Errorf("internal Windows acquisition implementation is missing %s: %v", name, err)
		}
	}

	adapter, err := os.ReadFile("windows_acquisition_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"syscall", "unsafe", "OpenProcess", "ReadProcessMemory", "CreateToolhelp32Snapshot"} {
		if strings.Contains(string(adapter), forbidden) {
			t.Errorf("Windows composition adapter contains native implementation primitive %q", forbidden)
		}
	}

	entries, err := os.ReadDir(filepath.Join("internal", "platform", "windows"))
	if err != nil {
		t.Fatal(err)
	}
	files := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join("internal", "platform", "windows", name)
		parsed, err := parser.ParseFile(files, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Errorf("cannot parse %s: %v", path, err)
			continue
		}
		for _, imported := range parsed.Imports {
			value, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Errorf("cannot decode import in %s: %v", path, err)
				continue
			}
			if value == "github.com/zanescope/v-local-key-provider" {
				t.Errorf("%s imports the Provider composition root", path)
			}
		}
	}
}

func TestDarwinAcquisitionAndHookImplementationStayBehindInternalBoundary(t *testing.T) {
	requiredInternal := []string{
		"driver.go", "process.go", "process_discovery.go", "native_driver_darwin.go",
		"native_process_darwin.go", "native_memory_darwin.go", "evidence.go", "hook.go",
		"hook_driver.go", "hook_protocol.go", "hook_process_darwin.go",
	}
	for _, name := range requiredInternal {
		if _, err := os.Stat(filepath.Join("internal", "platform", "darwin", name)); err != nil {
			t.Errorf("internal Darwin acquisition implementation is missing %s: %v", name, err)
		}
	}

	adapter, err := os.ReadFile("platform_darwin.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		`import "C"`, "task_for_pid", "mach_vm_region", "mach_vm_read_overwrite", "unsafe",
		"darwinAcquisitionPipeline", "runStaticScanStage", "scanDarwinProcess", "exec.Command",
		"os.CreateTemp", "VLOCALPBKDF", "HookPythonSource", "ProcessInstanceID(driver",
	} {
		if strings.Contains(string(adapter), forbidden) {
			t.Errorf("Darwin composition adapter contains native implementation primitive %q", forbidden)
		}
	}
	for _, legacyRoot := range []string{
		"platform_darwin_hook.go", "session_process_darwin.go", "darwin_hook_protocol_adapter.go",
		"darwin_process_policy_adapter.go",
	} {
		if _, err := os.Stat(legacyRoot); !os.IsNotExist(err) {
			t.Errorf("legacy root Darwin implementation remains at %s", legacyRoot)
		}
	}
	nativeMemory, err := os.ReadFile(filepath.Join("internal", "platform", "darwin", "native_memory_darwin.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"tailStorage :=", "driver.mark(tailStorage)", "defer driver.clear(tailStorage)", "defer driver.clear(combined)",
	} {
		if !strings.Contains(string(nativeMemory), required) {
			t.Errorf("Darwin native memory scanner is missing sensitive-buffer contract %q", required)
		}
	}

	entries, err := os.ReadDir(filepath.Join("internal", "platform", "darwin"))
	if err != nil {
		t.Fatal(err)
	}
	files := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join("internal", "platform", "darwin", name)
		parsed, err := parser.ParseFile(files, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Errorf("cannot parse %s: %v", path, err)
			continue
		}
		for _, imported := range parsed.Imports {
			value, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Errorf("cannot decode import in %s: %v", path, err)
				continue
			}
			if value == "github.com/zanescope/v-local-key-provider" {
				t.Errorf("%s imports the Provider composition root", path)
			}
		}
	}
}

func TestSessionWorkflowImplementationStaysBehindInternalBoundary(t *testing.T) {
	allowedRoot := map[string]bool{
		"session_adapter.go":              true,
		"session_store.go":                true,
		"session_process_darwin_nocgo.go": true,
		"session_process_other.go":        true,
	}
	rootEntries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range rootEntries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "session_") || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if !allowedRoot[name] {
			t.Errorf("session workflow implementation returned to the Provider root: %s", name)
		}
	}
	for _, name := range []string{"session_workflow.go", "session_response.go", "session_acquire.go"} {
		if _, err := os.Stat(name); err == nil || !os.IsNotExist(err) {
			t.Errorf("session workflow implementation returned to the Provider root: %s", name)
		}
	}
	for _, name := range []string{"coordinator.go", "response.go", "incremental.go", "runtime.go", "store.go", "policy.go"} {
		if _, err := os.Stat(filepath.Join("internal", "session", name)); err != nil {
			t.Errorf("internal session implementation is missing %s: %v", name, err)
		}
	}

	entries, err := os.ReadDir(filepath.Join("internal", "session"))
	if err != nil {
		t.Fatal(err)
	}
	files := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join("internal", "session", name)
		parsed, err := parser.ParseFile(files, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Errorf("cannot parse %s: %v", path, err)
			continue
		}
		for _, imported := range parsed.Imports {
			value, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Errorf("cannot decode import in %s: %v", path, err)
				continue
			}
			if value == "github.com/zanescope/v-local-key-provider" {
				t.Errorf("%s imports the Provider composition root", path)
			}
		}
	}
}

func TestDiagnosticFinalizationStaysBehindInternalBoundary(t *testing.T) {
	for _, name := range []string{"diagnostic_finalize.go", "diagnostic_outcome.go"} {
		if _, err := os.Stat(name); err == nil || !os.IsNotExist(err) {
			t.Errorf("diagnostic finalization implementation returned to the Provider root: %s", name)
		}
	}
	for _, name := range []string{"schema.go", "outcome.go", "finalize.go"} {
		if _, err := os.Stat(filepath.Join("internal", "diagnostics", name)); err != nil {
			t.Errorf("internal diagnostic implementation is missing %s: %v", name, err)
		}
	}
	adapter, err := os.ReadFile("diagnostics_adapter.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"func finalizeDiagnostics", "func applyFixedDiagnosticOutcome"} {
		if strings.Contains(string(adapter), forbidden) {
			t.Errorf("diagnostic adapter retained test-only legacy facade %q", forbidden)
		}
	}

	entries, err := os.ReadDir(filepath.Join("internal", "diagnostics"))
	if err != nil {
		t.Fatal(err)
	}
	files := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join("internal", "diagnostics", name)
		parsed, err := parser.ParseFile(files, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Errorf("cannot parse %s: %v", path, err)
			continue
		}
		for _, imported := range parsed.Imports {
			value, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Errorf("cannot decode import in %s: %v", path, err)
				continue
			}
			switch value {
			case "github.com/zanescope/v-local-key-provider",
				"github.com/zanescope/v-local-key-provider/internal/acquisition",
				"github.com/zanescope/v-local-key-provider/internal/protocol",
				"github.com/zanescope/v-local-key-provider/internal/session":
				t.Errorf("%s imports orchestration layer %q", path, value)
			}
		}
	}
}

func TestAcquisitionWorkflowImplementationStaysBehindInternalBoundary(t *testing.T) {
	if _, err := os.Stat("acquisition.go"); err == nil || !os.IsNotExist(err) {
		t.Error("one-shot acquisition workflow returned to acquisition.go in the Provider root")
	}
	for _, name := range []string{"model.go", "options.go", "workflow.go"} {
		if _, err := os.Stat(filepath.Join("internal", "acquisition", name)); err != nil {
			t.Errorf("internal acquisition workflow is missing %s: %v", name, err)
		}
	}

	adapter, err := os.ReadFile("acquisition_adapter.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"os.Lstat", "filepath.EvalSymlinks", "diagnosticmodel.Finalize", "time.Since", "PhaseTimingsMS[",
		"func runAcquire", "func runPreparedAcquire", "ParseSecurityPostureOptions",
	} {
		if strings.Contains(string(adapter), forbidden) {
			t.Errorf("acquisition composition adapter contains workflow implementation %q", forbidden)
		}
	}

	sessionRuntime, err := os.ReadFile(filepath.Join("internal", "session", "runtime.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sessionRuntime), "type Options = acquisitionmodel.Options") {
		t.Error("session workflow defines a parallel acquisition Options DTO")
	}

	entries, err := os.ReadDir(filepath.Join("internal", "acquisition"))
	if err != nil {
		t.Fatal(err)
	}
	files := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join("internal", "acquisition", name)
		parsed, err := parser.ParseFile(files, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Errorf("cannot parse %s: %v", path, err)
			continue
		}
		for _, imported := range parsed.Imports {
			value, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Errorf("cannot decode import in %s: %v", path, err)
				continue
			}
			if value == "github.com/zanescope/v-local-key-provider" || value == "github.com/zanescope/v-local-key-provider/internal/session" {
				t.Errorf("%s imports outer workflow layer %q", path, value)
			}
		}
	}
}

func TestGenericCommandAndSecretPublicationStayBehindInternalBoundaries(t *testing.T) {
	for _, path := range []string{
		filepath.Join("internal", "command", "workflow.go"),
		filepath.Join("internal", "protocol", "secret_policy.go"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("internal command/publication implementation is missing %s: %v", path, err)
		}
	}

	rootCommand, err := os.ReadFile("command.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"acquisitionmodel.ParseOptions", "diagnosticmodel.ApplyOutcome", "DiagnosticsPermitSecrets(",
		"DatabaseCredential = nil", "ImageKeys = nil", "func securityPostureRevalidationResponse",
	} {
		if strings.Contains(string(rootCommand), forbidden) {
			t.Errorf("root command contains generic workflow/publication implementation %q", forbidden)
		}
	}

	sessionPolicy, err := os.ReadFile(filepath.Join("internal", "session", "policy.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"func EnforceSecretPolicy", "func DiagnosticsPermitSecrets", "func WithoutSecrets"} {
		if strings.Contains(string(sessionPolicy), forbidden) {
			t.Errorf("session package redefined protocol publication policy %q", forbidden)
		}
	}

	entries, err := os.ReadDir(filepath.Join("internal", "command"))
	if err != nil {
		t.Fatal(err)
	}
	files := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join("internal", "command", name)
		parsed, err := parser.ParseFile(files, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Errorf("cannot parse %s: %v", path, err)
			continue
		}
		for _, imported := range parsed.Imports {
			value, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Errorf("cannot decode import in %s: %v", path, err)
				continue
			}
			switch value {
			case "github.com/zanescope/v-local-key-provider",
				"github.com/zanescope/v-local-key-provider/internal/daemon",
				"github.com/zanescope/v-local-key-provider/internal/session":
				t.Errorf("%s imports composition/session layer %q", path, value)
			}
		}
	}
}
