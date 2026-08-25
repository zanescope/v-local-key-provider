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
