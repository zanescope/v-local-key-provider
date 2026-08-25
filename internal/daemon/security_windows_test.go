//go:build windows

package daemon

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestValidateDirectorySecurityRejectsWorldAccessibleDACL(t *testing.T) {
	path := t.TempDir()
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		t.Fatal(err)
	}
	if err := validateDirectorySecurity(path); err == nil {
		t.Fatal("world-accessible daemon directory should be rejected")
	}
}
