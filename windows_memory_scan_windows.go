//go:build windows

package provider

import (
	"errors"
	"strings"
	"syscall"
	"unsafe"

	windowsmodel "github.com/zanescope/v-local-key-provider/internal/platform/windows"
)

const (
	th32csSnapProcess       = 0x00000002
	processVMRead           = 0x0010
	processQueryInformation = 0x0400
)

var (
	kernel32                   = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelpSnapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW        = kernel32.NewProc("Process32FirstW")
	procProcess32NextW         = kernel32.NewProc("Process32NextW")
	procOpenProcess            = kernel32.NewProc("OpenProcess")
	procCloseHandle            = kernel32.NewProc("CloseHandle")
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

type targetProcess struct {
	pid      uint32
	parentID uint32
	name     string
}

func closeHandle(handle syscall.Handle) {
	if handle != 0 && uintptr(handle) != ^uintptr(0) {
		procCloseHandle.Call(uintptr(handle))
	}
}

func targetProcesses() ([]targetProcess, error) {
	handleValue, _, _ := procCreateToolhelpSnapshot.Call(th32csSnapProcess, 0)
	if handleValue == ^uintptr(0) {
		return nil, errors.New("CreateToolhelp32Snapshot failed")
	}
	handle := syscall.Handle(handleValue)
	defer closeHandle(handle)
	entry := processEntry32{Size: uint32(unsafe.Sizeof(processEntry32{}))}
	result, _, _ := procProcess32FirstW.Call(uintptr(handle), uintptr(unsafe.Pointer(&entry)))
	if result == 0 {
		return nil, errors.New("Process32FirstW failed")
	}
	allowed := map[string]bool{"weixin.exe": true, "wechat.exe": true}
	var processes []targetProcess
	for {
		name := syscall.UTF16ToString(entry.ExeFile[:])
		if allowed[strings.ToLower(name)] {
			processes = append(processes, targetProcess{
				pid: entry.ProcessID, parentID: entry.ParentProcessID, name: name,
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

// scanProcessStage performs exactly one ordered fallback detector pass. A new
// process-local collector is used for every stage by platformAcquire, so raw
// candidates cannot leak into a later stage or another process.
func scanProcessStage(handle syscall.Handle, collector *candidateCollector, limit uint64, allowKeyObjects bool, stage string, remaining budget) (uint64, bool) {
	seenPointers := map[uint64]bool{}
	return windowsmodel.ScanProcessStage(
		handle, limit, stage, windowsStageTailLength(stage), maxScanRegionBytes,
		windowsmodel.ScanStageCallbacks{
			Expired: remaining.expired, MarkSensitive: markSensitiveBytes, ClearSensitive: zeroBytes,
			ScanChunk: func(stage string, regionType uint32, combined []byte, reader windowsmodel.MemoryReader) {
				switch stage {
				case "structured_key_object":
					if regionType == memImage {
						collector.scanInternalXORKeys(combined)
					}
					if allowKeyObjects {
						collector.collectKeyObjects(combined, seenPointers, func(pointer uint64, buffer []byte) int {
							return reader(pointer, buffer)
						})
					}
				case "salt_neighborhood":
					collector.scanSaltNeighborhood(combined)
				case "bounded_writable_heap":
					collector.scanDatabasePatternsFrom(combined, "bounded_heap")
					collector.scanMediaPatterns(combined)
				case "bounded_readonly":
					collector.scanDatabasePatternsFrom(combined, "bounded_readonly")
					collector.scanMediaPatterns(combined)
				case "bounded_hex":
					collector.scanDatabasePatternsFrom(combined, "bounded_hex")
					collector.scanMediaPatterns(combined)
				}
			},
		},
	)
}

// scanProcess retains the historical helper for focused scanner tests. The
// production Windows route calls scanProcessStage with a fresh isolated
// collector and a recomputed missing-only catalog between every pass.
func scanProcess(handle syscall.Handle, collector *candidateCollector, limit uint64, allowKeyObjects bool, remaining budget) (uint64, bool) {
	var scanned uint64
	limited := false
	for _, stage := range windowsFallbackStages {
		if scanned >= limit || remaining.expired() || collector.hasAllDatabaseCandidates() {
			break
		}
		stageLimit := stage.PerProcessLimit
		if stageLimit > limit-scanned {
			stageLimit = limit - scanned
		}
		value, stageLimited := scanProcessStage(handle, collector, stageLimit, allowKeyObjects, stage.Name, remaining.cappedFor(stage.Window))
		scanned += value
		limited = limited || stageLimited
	}
	return scanned, limited
}
