//go:build !windows

package daemon

import (
	"os"
	"testing"
)

func TestValidateDirectorySecurityRequiresPrivateCurrentUserDirectory(t *testing.T) {
	path := t.TempDir()
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validateDirectorySecurity(path); err == nil {
		t.Fatal("group/world-readable daemon directory should be rejected")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateDirectorySecurity(path); err != nil {
		t.Fatalf("private current-user daemon directory rejected: %v", err)
	}
}
