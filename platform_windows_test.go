//go:build windows

package provider

import (
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestPhase4WindowsProcessInstanceRequiresStartPathArchitectureAndFingerprint(t *testing.T) {
	evidence := windowsProcessEvidence{
		Process: targetProcess{pid: 42, parentID: 7, name: "Weixin.exe"},
		Path:    `C:\Program Files\Tencent\Weixin.exe`, Started: 12345, Architecture: "amd64",
		Binary: windowsBinaryEvidence{
			ExecutableSHA256: strings.Repeat("a", 64), BinarySigningStatus: windowsSigningVerified,
			BinarySignerSHA256: strings.Repeat("b", 64), ProductIdentity: "weixin.exe",
		},
	}
	first := windowsStableProcessInstanceID(evidence)
	if !strings.HasPrefix(first, "windows-process:") || len(first) != len("windows-process:")+64 {
		t.Fatalf("stable Windows process evidence did not produce an opaque instance ID: %q", first)
	}
	evidence.Started++
	if second := windowsStableProcessInstanceID(evidence); second == first || second == "" {
		t.Fatalf("process restart did not change the process instance ID: first=%q second=%q", first, second)
	}
	evidence.Started = 0
	if id := windowsStableProcessInstanceID(evidence); id != "" {
		t.Fatalf("PID-only Windows process evidence produced an instance ID: %q", id)
	}
}

func TestPrimaryTargetProcessesKeepsWeixinRootAndWechat(t *testing.T) {
	processes := []targetProcess{
		{pid: 10, parentID: 1, name: "Weixin.exe"},
		{pid: 11, parentID: 10, name: "Weixin.exe"},
		{pid: 12, parentID: 10, name: "Weixin.exe"},
		{pid: 20, parentID: 1, name: "WeChat.exe"},
	}
	selected := primaryTargetProcesses(processes)
	if len(selected) != 2 || selected[0].pid != 10 || selected[1].pid != 20 {
		t.Fatalf("unexpected primary processes: %#v", selected)
	}
}

func TestReadableRegionIncludesCommittedImageMemory(t *testing.T) {
	info := memoryBasicInformation{
		State: memCommit, Protect: pageReadOnly, Type: memImage, RegionSize: 4096,
	}
	if !readableRegion(info) {
		t.Fatal("committed readable image memory was excluded")
	}
}

func TestPhase4WindowsReportsActualCurrentProcessArchitecture(t *testing.T) {
	handleValue, _, _ := procOpenProcess.Call(processQueryInformation, 0, uintptr(os.Getpid()))
	if handleValue == 0 {
		t.Skip("current process architecture cannot be queried with the available token")
	}
	handle := syscall.Handle(handleValue)
	defer closeHandle(handle)
	got := windowsProcessArchitecture(handle)
	if got == "unknown" {
		t.Fatal("IsWow64Process2 did not return a supported architecture for the current process")
	}
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		if got != runtime.GOARCH {
			t.Fatalf("actual process architecture = %q, Go target = %q", got, runtime.GOARCH)
		}
	}
}

func TestPhase4WindowsObservedPathsBindTargetAndOtherAccounts(t *testing.T) {
	target := `C:\Users\tester\Documents\xwechat_files\account-a`
	database := target + `\db_storage`
	if got := classifyWindowsObservedPaths([]string{database + `\message\message_0.db`}, target, database); got != "target" {
		t.Fatalf("target database handle binding=%q", got)
	}
	other := `C:\Users\tester\Documents\xwechat_files\account-b\db_storage\message\message_0.db`
	if got := classifyWindowsObservedPaths([]string{other}, target, database); got != "other" {
		t.Fatalf("other-account database handle binding=%q", got)
	}
	if got := classifyWindowsObservedPaths([]string{database + `\message\message_0.db`, other}, target, database); got != "unknown" {
		t.Fatalf("mixed target/other handles must not claim a live target binding: %q", got)
	}
	if got := classifyWindowsObservedPaths([]string{`C:\Windows\System32\kernel32.dll`}, target, database); got != "unknown" {
		t.Fatalf("unrelated handle binding=%q", got)
	}
	for _, nonDatabase := range []string{
		target + `\logs\session.log`,
		target + `\config\settings.db`,
		`C:\Users\tester\Documents\xwechat_files\account-b\db_storage\logs\trace.log`,
	} {
		if got := classifyWindowsObservedPaths([]string{nonDatabase}, target, database); got != "unknown" {
			t.Fatalf("non-target-database handle %q promoted account binding to %q", nonDatabase, got)
		}
	}
}

func TestPhase4WindowsObservedPathNormalizationHandlesDevicePrefixAndCase(t *testing.T) {
	target := `c:\users\tester\documents\xwechat_files\account-a`
	database := target + `\db_storage`
	observed := `\\?\C:\Users\Tester\Documents\xwechat_files\ACCOUNT-A\db_storage\contact\contact.db`
	if got := classifyWindowsObservedPaths([]string{observed}, target, database); got != "target" {
		t.Fatalf("device-prefixed target binding=%q", got)
	}
}

func TestPhase4WindowsTargetEvidenceIsScannedBeforeUnknownProcesses(t *testing.T) {
	values := []windowsProcessEvidence{
		{Process: targetProcess{pid: 1}, Binding: "unknown"},
		{Process: targetProcess{pid: 2}, Binding: "target"},
		{Process: targetProcess{pid: 3}, Binding: "other"},
		{Process: targetProcess{pid: 4}, Binding: "unknown"},
	}
	ordered := orderedWindowsProcessEvidence(values)
	if ordered[0].Process.pid != 2 || ordered[1].Process.pid != 1 || ordered[2].Process.pid != 4 || ordered[3].Process.pid != 3 {
		t.Fatalf("binding-aware scan order is unstable: %+v", ordered)
	}
}
