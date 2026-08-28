//go:build windows

package windows

import (
	"os"
	"runtime"
	"testing"
)

func TestWindowsReportsActualCurrentProcessArchitecture(t *testing.T) {
	handleValue, _, _ := procOpenProcess.Call(processQueryInformation, 0, uintptr(os.Getpid()))
	if handleValue == 0 {
		t.Skip("current process architecture cannot be queried with the available token")
	}
	handle := Handle(handleValue)
	defer closeNativeHandle(handle)
	got := processArchitecture(handle)
	if got == "unknown" {
		t.Fatal("IsWow64Process2 did not return a supported architecture for the current process")
	}
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		if got != runtime.GOARCH {
			t.Fatalf("actual process architecture = %q, Go target = %q", got, runtime.GOARCH)
		}
	}
}
