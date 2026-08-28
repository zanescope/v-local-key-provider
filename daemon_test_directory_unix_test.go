//go:build !windows

package provider

import (
	"os"
	"testing"
)

func secureDaemonTestDirectory(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatalf("cannot make daemon test directory private: %v", err)
	}
	return path
}
