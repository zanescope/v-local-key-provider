//go:build windows

package provider

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

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

func windowsLiveTestSecurityAttributes(t *testing.T, sddl string) *windows.SecurityAttributes {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
}

func createWindowsLiveTestDirectory(t *testing.T, path, sddl string) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.CreateDirectory(name, windowsLiveTestSecurityAttributes(t, sddl)); err != nil {
		t.Fatal(err)
	}
}

func createWindowsLiveTestFile(t *testing.T, path, sddl string, payload []byte) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL,
		windows.FILE_SHARE_READ, windowsLiveTestSecurityAttributes(t, sddl), windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(handle), "live-private-config-fixture")
	if file == nil {
		_ = windows.CloseHandle(handle)
		t.Fatal("live config fixture handle is unavailable")
	}
	if _, err := file.Write(payload); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsLivePrivateConfigRequiresExclusiveProtectedACL(t *testing.T) {
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || currentUser == nil || currentUser.User.Sid == nil {
		t.Fatal("current Windows user SID is unavailable")
	}
	private := filepath.Join(t.TempDir(), "private")
	exclusive := "D:P(A;;FA;;;" + currentUser.User.Sid.String() + ")(A;;FA;;;SY)"
	createWindowsLiveTestDirectory(t, private, "O:"+currentUser.User.Sid.String()+exclusive)
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
	createWindowsLiveTestFile(t, path, "O:"+currentUser.User.Sid.String()+exclusive, payload)
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
