//go:build windows

package provider

import (
	"sort"
	"syscall"

	windowsmodel "github.com/zanescope/v-local-key-provider/internal/platform/windows"
)

const (
	memCommit            = windowsmodel.MemCommit
	memPrivate           = windowsmodel.MemPrivate
	memMapped            = windowsmodel.MemMapped
	memImage             = windowsmodel.MemImage
	pageNoAccess         = windowsmodel.PageNoAccess
	pageReadOnly         = windowsmodel.PageReadOnly
	pageReadWrite        = windowsmodel.PageReadWrite
	pageWriteCopy        = windowsmodel.PageWriteCopy
	pageExecuteRead      = windowsmodel.PageExecuteRead
	pageExecuteReadWrite = windowsmodel.PageExecuteReadWrite
	pageExecuteWriteCopy = windowsmodel.PageExecuteWriteCopy
	pageGuard            = windowsmodel.PageGuard
	readChunkSize        = windowsmodel.ReadChunkSize
	perProcessScanLimit  = windowsmodel.PerProcessScanLimit
	totalScanLimit       = windowsmodel.TotalScanLimit
)

type windowsFallbackStageSpec = windowsmodel.FallbackStageSpec
type memoryBasicInformation = windowsmodel.NativeMemoryRegion

var windowsFallbackStages = windowsmodel.FallbackStages()

func windowsProcessModel(process targetProcess) windowsmodel.Process {
	return windowsmodel.Process{PID: process.pid, ParentID: process.parentID, Name: process.name}
}

func targetProcessFromModel(process windowsmodel.Process) targetProcess {
	return targetProcess{pid: process.PID, parentID: process.ParentID, name: process.Name}
}

func primaryTargetProcesses(processes []targetProcess) []targetProcess {
	models := make([]windowsmodel.Process, 0, len(processes))
	for _, process := range processes {
		models = append(models, windowsProcessModel(process))
	}
	selected := windowsmodel.PrimaryProcesses(models)
	result := make([]targetProcess, 0, len(selected))
	for _, process := range selected {
		result = append(result, targetProcessFromModel(process))
	}
	return result
}

func orderedWindowsTargetProcesses(processes []targetProcess) []targetProcess {
	models := make([]windowsmodel.Process, 0, len(processes))
	for _, process := range processes {
		models = append(models, windowsProcessModel(process))
	}
	ordered := windowsmodel.OrderedProcesses(models)
	result := make([]targetProcess, 0, len(ordered))
	for _, process := range ordered {
		result = append(result, targetProcessFromModel(process))
	}
	return result
}

func orderedWindowsProcessEvidence(processes []windowsProcessEvidence) []windowsProcessEvidence {
	ordered := append([]windowsProcessEvidence(nil), processes...)
	sort.SliceStable(ordered, func(left, right int) bool {
		return windowsmodel.BindingRank(ordered[left].Binding) < windowsmodel.BindingRank(ordered[right].Binding)
	})
	return ordered
}

func windowsMemoryRegion(info memoryBasicInformation) windowsmodel.MemoryRegion {
	return windowsmodel.MemoryRegion{State: info.State, Protect: info.Protect, Type: info.Type}
}

func queryMemoryRegion(handle syscall.Handle, address uintptr) (memoryBasicInformation, bool) {
	return windowsmodel.QueryMemoryRegion(handle, address)
}

func readMemory(handle syscall.Handle, address uintptr, buffer []byte) int {
	return windowsmodel.ReadProcessMemory(handle, address, buffer)
}

func readableRegion(info memoryBasicInformation) bool {
	return windowsmodel.ReadableRegion(windowsMemoryRegion(info))
}

func writableWindowsRegion(info memoryBasicInformation) bool {
	return windowsmodel.WritableRegion(windowsMemoryRegion(info))
}

func windowsStageReadsRegion(stage string, info memoryBasicInformation) bool {
	return windowsmodel.StageReadsRegion(stage, windowsMemoryRegion(info))
}

func windowsStageTailLength(stage string) int {
	return windowsmodel.StageTailLength(stage, saltNeighborhoodWindow, scanTailLength)
}
