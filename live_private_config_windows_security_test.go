//go:build windows

package provider

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func setWindowsLiveTestDACL(t *testing.T, path, sddl string, protected bool) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	information := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if protected {
		information |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		information |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, information, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsLivePrivateConfigRequiresExclusiveProtectedACL(t *testing.T) {
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || currentUser == nil || currentUser.User.Sid == nil {
		t.Fatal("current Windows user SID is unavailable")
	}
	private := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	account := t.TempDir()
	database := t.TempDir()
	payload, err := json.Marshal(map[string]any{
		"schema_version": 1,
		"account_dir":    account,
		"db_dir":         database,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(private, "config.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	exclusive := "D:P(A;;FA;;;" + currentUser.User.Sid.String() + ")(A;;FA;;;SY)"
	setWindowsLiveTestDACL(t, private, exclusive, true)
	setWindowsLiveTestDACL(t, path, exclusive, true)
	if _, err := readWindowsLivePrivateConfig(path); err != nil {
		t.Fatalf("exclusive protected live config was rejected: %v", err)
	}

	t.Run("普通 Users 可写", func(t *testing.T) {
		broad := "D:P(A;;FA;;;" + currentUser.User.Sid.String() + ")(A;;FA;;;SY)(A;;FW;;;BU)"
		setWindowsLiveTestDACL(t, path, broad, true)
		if _, err := readWindowsLivePrivateConfig(path); err == nil {
			t.Fatal("live config writable by BUILTIN\\Users was accepted")
		}
		setWindowsLiveTestDACL(t, path, exclusive, true)
	})

	t.Run("DACL 仍继承", func(t *testing.T) {
		setWindowsLiveTestDACL(t, path, exclusive, false)
		if _, err := readWindowsLivePrivateConfig(path); err == nil {
			t.Fatal("live config with an unprotected DACL was accepted")
		}
		setWindowsLiveTestDACL(t, path, exclusive, true)
	})

	t.Run("私有目录包含额外主体", func(t *testing.T) {
		broad := "D:P(A;;FA;;;" + currentUser.User.Sid.String() + ")(A;;FA;;;SY)(A;;FR;;;BU)"
		setWindowsLiveTestDACL(t, private, broad, true)
		if _, err := readWindowsLivePrivateConfig(path); err == nil {
			t.Fatal("live config directory readable by an extra principal was accepted")
		}
		setWindowsLiveTestDACL(t, private, exclusive, true)
	})
}
