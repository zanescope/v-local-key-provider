//go:build windows

package windows

import (
	"errors"
	"strings"
	"syscall"
	"unsafe"
)

const (
	toolhelpSnapshotProcess        = 0x00000002
	processVMRead                  = 0x0010
	processQueryInformation        = 0x0400
	processQueryLimitedInformation = 0x1000
)

var (
	processKernel32                = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelpSnapshot     = processKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW            = processKernel32.NewProc("Process32FirstW")
	procProcess32NextW             = processKernel32.NewProc("Process32NextW")
	procOpenProcess                = processKernel32.NewProc("OpenProcess")
	procCloseHandle                = processKernel32.NewProc("CloseHandle")
	procGetProcessTimes            = processKernel32.NewProc("GetProcessTimes")
	procQueryFullProcessImageNameW = processKernel32.NewProc("QueryFullProcessImageNameW")
	procIsWow64Process2            = processKernel32.NewProc("IsWow64Process2")
)

type processEntry32 struct {
	Size              uint32
	Usage             uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	Threads           uint32
	ParentProcessID   uint32
	PriorityClassBase int32
	Flags             uint32
	ExeFile           [260]uint16
}

type windowsFiletime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

type nativeDriver struct {
	runtime NativeRuntime
}

func NewNativeDriver(runtime NativeRuntime) NativeDriver {
	return &nativeDriver{runtime: runtime}
}

func closeNativeHandle(handle Handle) {
	if handle != 0 && uintptr(handle) != ^uintptr(0) {
		procCloseHandle.Call(uintptr(handle))
	}
}

func (driver *nativeDriver) Close(handle Handle) {
	closeNativeHandle(handle)
}

func (driver *nativeDriver) ListProcesses() ([]Process, error) {
	handleValue, _, _ := procCreateToolhelpSnapshot.Call(toolhelpSnapshotProcess, 0)
	if handleValue == ^uintptr(0) {
		return nil, errors.New("CreateToolhelp32Snapshot failed")
	}
	handle := Handle(handleValue)
	defer closeNativeHandle(handle)
	entry := processEntry32{Size: uint32(unsafe.Sizeof(processEntry32{}))}
	result, _, _ := procProcess32FirstW.Call(uintptr(handle), uintptr(unsafe.Pointer(&entry)))
	if result == 0 {
		return nil, errors.New("Process32FirstW failed")
	}
	allowed := map[string]bool{"weixin.exe": true, "wechat.exe": true}
	var processes []Process
	for {
		name := syscall.UTF16ToString(entry.ExeFile[:])
		if allowed[strings.ToLower(name)] {
			processes = append(processes, Process{
				PID: entry.ProcessID, ParentID: entry.ParentProcessID, Name: name,
			})
		}
		entry.Size = uint32(unsafe.Sizeof(processEntry32{}))
		result, _, _ = procProcess32NextW.Call(uintptr(handle), uintptr(unsafe.Pointer(&entry)))
		if result == 0 {
			break
		}
	}
	return processes, nil
}

func processArchitecture(handle Handle) string {
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
		case 0xaa64, 0xa641:
			return "arm64"
		}
	}
	return "unknown"
}

func processStartTime(handle Handle) uint64 {
	var created, exited, kernel, user windowsFiletime
	if result, _, _ := procGetProcessTimes.Call(
		uintptr(handle), uintptr(unsafe.Pointer(&created)), uintptr(unsafe.Pointer(&exited)),
		uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)),
	); result != 0 {
		return uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
	}
	return 0
}

func processExecutablePath(handle Handle) string {
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if result, _, _ := procQueryFullProcessImageNameW.Call(
		uintptr(handle), 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)),
	); result != 0 && size > 0 && size <= uint32(len(buffer)) {
		return syscall.UTF16ToString(buffer[:size])
	}
	return ""
}

func (driver *nativeDriver) CollectEvidence(process Process) ProcessEvidence {
	handleValue, _, _ := procOpenProcess.Call(processQueryLimitedInformation, 0, uintptr(process.PID))
	if handleValue == 0 {
		return driver.collectEvidenceFromHandle(process, 0)
	}
	handle := Handle(handleValue)
	defer closeNativeHandle(handle)
	return driver.collectEvidenceFromHandle(process, handle)
}

func (driver *nativeDriver) OpenForScan(process Process) Handle {
	handleValue, _, _ := procOpenProcess.Call(processVMRead|processQueryInformation, 0, uintptr(process.PID))
	return Handle(handleValue)
}

func (driver *nativeDriver) Revalidate(process Process, handle Handle) ProcessEvidence {
	return driver.collectEvidenceFromHandle(process, handle)
}
