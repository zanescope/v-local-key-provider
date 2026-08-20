//go:build windows

package main

import (
	"errors"
	"strings"
	"syscall"
	"unsafe"
)

const (
	th32csSnapProcess       = 0x00000002
	processVMRead           = 0x0010
	processQueryInformation = 0x0400
	memCommit               = 0x1000
	memPrivate              = 0x20000
	memMapped               = 0x40000
	memImage                = 0x1000000
	pageNoAccess            = 0x01
	pageReadOnly            = 0x02
	pageReadWrite           = 0x04
	pageWriteCopy           = 0x08
	pageExecuteRead         = 0x20
	pageExecuteReadWrite    = 0x40
	pageExecuteWriteCopy    = 0x80
	pageGuard               = 0x100
	readChunkSize           = 1024 * 1024
	perProcessScanLimit     = uint64(2 * 1024 * 1024 * 1024)
	totalScanLimit          = uint64(6 * 1024 * 1024 * 1024)
)

var (
	kernel32                   = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelpSnapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW        = kernel32.NewProc("Process32FirstW")
	procProcess32NextW         = kernel32.NewProc("Process32NextW")
	procOpenProcess            = kernel32.NewProc("OpenProcess")
	procCloseHandle            = kernel32.NewProc("CloseHandle")
	procVirtualQueryEx         = kernel32.NewProc("VirtualQueryEx")
	procReadProcessMemory      = kernel32.NewProc("ReadProcessMemory")
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

type memoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionID       uint16
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
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

func primaryTargetProcesses(processes []targetProcess) []targetProcess {
	v4PIDs := map[uint32]bool{}
	for _, process := range processes {
		if strings.EqualFold(process.name, "weixin.exe") {
			v4PIDs[process.pid] = true
		}
	}
	var selected []targetProcess
	for _, process := range processes {
		if !strings.EqualFold(process.name, "weixin.exe") || !v4PIDs[process.parentID] {
			selected = append(selected, process)
		}
	}
	if len(selected) == 0 {
		return processes
	}
	return selected
}

func readableRegion(info memoryBasicInformation) bool {
	if info.State != memCommit || info.Protect&pageGuard != 0 || info.Protect&pageNoAccess != 0 {
		return false
	}
	base := info.Protect & 0xff
	return base == pageReadOnly || base == pageReadWrite || base == pageWriteCopy ||
		base == pageExecuteRead || base == pageExecuteReadWrite || base == pageExecuteWriteCopy
}

func readMemory(handle syscall.Handle, address uintptr, buffer []byte) int {
	if len(buffer) == 0 {
		return 0
	}
	var bytesRead uintptr
	procReadProcessMemory.Call(
		uintptr(handle), address, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if bytesRead > uintptr(len(buffer)) {
		return 0
	}
	return int(bytesRead)
}

// scanProcess 每读完一个分块就检查时限；分块为 1 MiB，实测约 18 毫秒，
// 因此超出时限的幅度被限制在一个分块以内。
func scanProcess(handle syscall.Handle, collector *candidateCollector, limit uint64, allowKeyObjects bool, remaining budget) (uint64, bool) {
	var address uintptr
	var scanned uint64
	limited := false
	buffer := make([]byte, readChunkSize)
	tail := make([]byte, 0, scanTailLength)
	seenPointers := map[uint64]bool{}
	for scanned < limit {
		if remaining.expired() {
			return scanned, true
		}
		var info memoryBasicInformation
		result, _, _ := procVirtualQueryEx.Call(
			uintptr(handle), address, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info),
		)
		if result == 0 || info.RegionSize == 0 {
			break
		}
		next := info.BaseAddress + info.RegionSize
		if next <= address {
			break
		}
		if readableRegion(info) && uint64(info.RegionSize) <= maxScanRegionBytes {
			tail = tail[:0]
			regionEnd := next
			scanInternalXORKeys := info.Type == memImage
			for cursor := info.BaseAddress; cursor < regionEnd && scanned < limit; {
				if remaining.expired() {
					return scanned, true
				}
				regionRemaining := regionEnd - cursor
				wanted := uintptr(readChunkSize)
				if regionRemaining < wanted {
					wanted = regionRemaining
				}
				if uint64(wanted) > limit-scanned {
					wanted = uintptr(limit - scanned)
					limited = true
				}
				read := readMemory(handle, cursor, buffer[:int(wanted)])
				if read > 0 {
					combined := make([]byte, 0, len(tail)+read)
					combined = append(combined, tail...)
					combined = append(combined, buffer[:read]...)
					collector.scan(combined)
					if scanInternalXORKeys {
						collector.scanInternalXORKeys(combined)
					}
					if allowKeyObjects {
						collector.collectKeyObjects(combined, seenPointers, func(pointer uint64, buffer []byte) int {
							return readMemory(handle, uintptr(pointer), buffer)
						})
					}
					collector.scanSaltNeighborhood(combined)
					keep := scanTailLength
					if len(combined) < keep {
						keep = len(combined)
					}
					tail = append(tail[:0], combined[len(combined)-keep:]...)
					scanned += uint64(read)
				} else {
					tail = tail[:0]
				}
				cursor += wanted
			}
		}
		address = next
	}
	if scanned >= limit {
		limited = true
	}
	return scanned, limited
}

func platformAcquire(targets databaseTargets, media mediaEvidence, options acquireOptions) (response, diagnostics, error) {
	diag := diagnostics{
		Platform:                  "windows",
		DatabaseCount:             targets.count,
		V2SampleCount:             len(media.v2Blocks),
		XORDistinctCandidateCount: len(media.xorCandidates),
	}
	for _, count := range media.xorCandidates {
		diag.XORSampleCount += count
	}
	selectedMedia, xorResolved, leading, second := selectDominantXOR(media)
	diag.XORLeadingSampleCount = leading
	diag.XORSecondSampleCount = second
	derivedMedia, codeCandidates, verifiedCodes := resolveKVCommMedia(options.accountDir, selectedMedia)
	diag.KVCommCodeCandidateCount = codeCandidates
	diag.KVCommVerifiedCandidateCount = verifiedCodes
	needDatabaseScan := options.database && len(targets.bySalt) > 0
	needMediaScan := options.media && derivedMedia == nil && len(media.v2Blocks) > 0 && xorResolved
	if !needDatabaseScan && !needMediaScan && derivedMedia == nil {
		return response{}, diag, nil
	}
	if !needDatabaseScan && derivedMedia != nil {
		diag.MediaCandidateMethod = "kvcomm_formula_v2_sample"
		return response{ImageKeys: derivedMedia}, diag, nil
	}
	scanMedia := selectedMedia
	if !needMediaScan {
		scanMedia = mediaEvidence{xorCandidates: map[byte]int{}}
	}
	processes, err := targetProcesses()
	if err != nil {
		return response{}, diag, err
	}
	diag.ProcessCount = len(processes)
	collector := newCandidateCollector(targets, scanMedia)
	for _, process := range processes {
		if diag.ScannedBytes >= totalScanLimit || options.budget.expired() {
			diag.ScanLimited = true
			break
		}
		handleValue, _, _ := procOpenProcess.Call(
			processVMRead|processQueryInformation, 0, uintptr(process.pid),
		)
		if handleValue == 0 {
			diag.AccessDeniedCount++
			continue
		}
		handle := syscall.Handle(handleValue)
		diag.OpenedProcessCount++
		remaining := totalScanLimit - diag.ScannedBytes
		if remaining > perProcessScanLimit {
			remaining = perProcessScanLimit
		}
		scanned, limited := scanProcess(handle, collector, remaining, true, options.budget)
		closeHandle(handle)
		diag.ScannedBytes += scanned
		diag.ScanLimited = diag.ScanLimited || limited
	}
	if !collector.hasAllDatabaseCandidates() {
		collector.resolveDatabasePassphrase(options.budget)
	}
	keys, ambiguous := collector.databaseKeys(targets)
	switch {
	case diag.OpenedProcessCount > 0 && diag.AccessDeniedCount > 0:
		diag.ProcessAccessStatus = "partial"
	case diag.OpenedProcessCount > 0:
		diag.ProcessAccessStatus = "direct_opened"
	case diag.AccessDeniedCount > 0:
		diag.ProcessAccessStatus = "denied"
		diag.ProcessAccessError = "process_open_denied"
	case diag.ProcessCount == 0:
		diag.ProcessAccessStatus = "wechat_not_running"
	case options.budget.expired():
		diag.ProcessAccessStatus = "deadline_exhausted"
	default:
		diag.ProcessAccessStatus = "unavailable"
	}
	imageCandidate := collector.applyScanDiagnostics(&diag, keys, ambiguous, derivedMedia, scanMedia)
	return response{DatabaseKeys: keys, ImageKeys: imageCandidate}, diag, nil
}
