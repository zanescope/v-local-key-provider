//go:build windows

package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

var (
	procGetProcessTimes            = kernel32.NewProc("GetProcessTimes")
	procQueryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW")
	procIsWow64Process2            = kernel32.NewProc("IsWow64Process2")
)

const processQueryLimitedInformation = 0x1000

type windowsFiletime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

func windowsProcessArchitecture(handle syscall.Handle) string {
	var processMachine, nativeMachine uint16
	if result, _, _ := procIsWow64Process2.Call(
		uintptr(handle), uintptr(unsafe.Pointer(&processMachine)), uintptr(unsafe.Pointer(&nativeMachine)),
	); result != 0 {
		machine := processMachine
		if machine == 0 {
			machine = nativeMachine
		}
		switch machine {
		case 0x014c:
			return "x86"
		case 0x8664:
			return "amd64"
		case 0xaa64, 0xa641: // IMAGE_FILE_MACHINE_ARM64 / ARM64EC
			return "arm64"
		}
	}
	return "unknown"
}

func windowsProcessIdentity(process targetProcess) string {
	evidence := windowsCollectProcessEvidence(process)
	if evidence.InstanceID == "" {
		// Do not turn PID-only inventory into a trusted process instance. Keeping
		// an explicit unverified marker makes restart receipts fail closed when
		// start time or executable identity cannot be read.
		return "windows-process:unverified:" + strings.ToLower(process.name)
	}
	return evidence.InstanceID
}

func platformProcessInstanceID() string {
	processes, err := targetProcesses()
	if err != nil {
		return "windows:process-list-unavailable"
	}
	processes = orderedWindowsTargetProcesses(processes)
	identities := make([]string, 0, len(processes))
	for _, process := range processes {
		identities = append(identities, windowsProcessIdentity(process))
	}
	sort.Strings(identities)
	sum := sha256.Sum256([]byte(strings.Join(identities, "\x00")))
	return "windows:" + hex.EncodeToString(sum[:16])
}
