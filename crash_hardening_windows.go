//go:build windows

package provider

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32SensitiveMemory          = windows.NewLazySystemDLL("kernel32.dll")
	werGetFlags                      = kernel32SensitiveMemory.NewProc("WerGetFlags")
	werSetFlags                      = kernel32SensitiveMemory.NewProc("WerSetFlags")
	werRegisterExcludedMemoryBlock   = kernel32SensitiveMemory.NewProc("WerRegisterExcludedMemoryBlock")
	werUnregisterExcludedMemoryBlock = kernel32SensitiveMemory.NewProc("WerUnregisterExcludedMemoryBlock")
)

const werFaultReportingFlagNoHeap = 0x00000001

func hardenPlatformCrashReporting() error {
	windows.SetErrorMode(windows.SEM_FAILCRITICALERRORS | windows.SEM_NOGPFAULTERRORBOX | windows.SEM_NOOPENFILEERRORBOX)
	if werGetFlags.Find() != nil || werSetFlags.Find() != nil {
		return errors.New("Windows Error Reporting hardening is unavailable")
	}
	var flags uint32
	result, _, _ := werGetFlags.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&flags)))
	if int32(result) < 0 {
		return errors.New("Windows Error Reporting flags are unavailable")
	}
	result, _, _ = werSetFlags.Call(uintptr(flags | werFaultReportingFlagNoHeap))
	if int32(result) < 0 {
		return errors.New("Windows Error Reporting heap collection could not be disabled")
	}
	return nil
}

func platformExcludeSensitiveMemory(value []byte) func() {
	if len(value) == 0 || werRegisterExcludedMemoryBlock.Find() != nil || werUnregisterExcludedMemoryBlock.Find() != nil {
		return nil
	}
	address := unsafe.Pointer(unsafe.SliceData(value))
	result, _, _ := werRegisterExcludedMemoryBlock.Call(uintptr(address), uintptr(len(value)))
	runtime.KeepAlive(value)
	if int32(result) < 0 {
		return nil
	}
	return func() {
		_, _, _ = werUnregisterExcludedMemoryBlock.Call(uintptr(address))
		runtime.KeepAlive(value)
	}
}
