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
