package windows

import (
	"strings"
	"time"
)

const (
	MemCommit            = 0x1000
	MemPrivate           = 0x20000
	MemMapped            = 0x40000
	MemImage             = 0x1000000
	PageNoAccess         = 0x01
	PageReadOnly         = 0x02
	PageReadWrite        = 0x04
	PageWriteCopy        = 0x08
	PageExecuteRead      = 0x20
	PageExecuteReadWrite = 0x40
	PageExecuteWriteCopy = 0x80
	PageGuard            = 0x100

	ReadChunkSize       = 1024 * 1024
	PerProcessScanLimit = uint64(2 * 1024 * 1024 * 1024)
	TotalScanLimit      = uint64(6 * 1024 * 1024 * 1024)
)

type FallbackStageSpec struct {
	Name            string
	PerProcessLimit uint64
	Window          time.Duration
}

var fallbackStages = []FallbackStageSpec{
	{Name: "structured_key_object", PerProcessLimit: 384 * 1024 * 1024, Window: 8 * time.Second},
	{Name: "salt_neighborhood", PerProcessLimit: 384 * 1024 * 1024, Window: 8 * time.Second},
	{Name: "bounded_writable_heap", PerProcessLimit: 768 * 1024 * 1024, Window: 12 * time.Second},
	{Name: "bounded_readonly", PerProcessLimit: 320 * 1024 * 1024, Window: 8 * time.Second},
	{Name: "bounded_hex", PerProcessLimit: 192 * 1024 * 1024, Window: 6 * time.Second},
}

func FallbackStages() []FallbackStageSpec {
	return append([]FallbackStageSpec(nil), fallbackStages...)
}

type Process struct {
	PID      uint32
	ParentID uint32
	Name     string
}

func PrimaryProcesses(processes []Process) []Process {
	v4PIDs := map[uint32]bool{}
	for _, process := range processes {
		if strings.EqualFold(process.Name, "weixin.exe") {
			v4PIDs[process.PID] = true
		}
	}
	selected := make([]Process, 0, len(processes))
	for _, process := range processes {
		if !strings.EqualFold(process.Name, "weixin.exe") || !v4PIDs[process.ParentID] {
			selected = append(selected, process)
		}
	}
	if len(selected) == 0 {
		return append([]Process(nil), processes...)
	}
	return selected
}

func OrderedProcesses(processes []Process) []Process {
	primary := PrimaryProcesses(processes)
	seen := map[uint32]bool{}
	ordered := make([]Process, 0, len(processes))
	for _, process := range primary {
		if !seen[process.PID] {
			seen[process.PID] = true
			ordered = append(ordered, process)
		}
	}
	for _, process := range processes {
		if !seen[process.PID] {
			seen[process.PID] = true
			ordered = append(ordered, process)
		}
	}
	return ordered
}

func BindingRank(binding string) int {
	switch binding {
	case "target":
		return 0
	case "unknown":
		return 1
	default:
		return 2
	}
}

type MemoryRegion struct {
	State   uint32
	Protect uint32
	Type    uint32
}

func ReadableRegion(region MemoryRegion) bool {
	if region.State != MemCommit || region.Protect&PageGuard != 0 || region.Protect&PageNoAccess != 0 {
		return false
	}
	base := region.Protect & 0xff
	return base == PageReadOnly || base == PageReadWrite || base == PageWriteCopy ||
		base == PageExecuteRead || base == PageExecuteReadWrite || base == PageExecuteWriteCopy
}

func WritableRegion(region MemoryRegion) bool {
	base := region.Protect & 0xff
	return base == PageReadWrite || base == PageWriteCopy || base == PageExecuteReadWrite || base == PageExecuteWriteCopy
}

func StageReadsRegion(stage string, region MemoryRegion) bool {
	if !ReadableRegion(region) {
		return false
	}
	switch stage {
	case "bounded_writable_heap":
		return WritableRegion(region) && (region.Type == MemPrivate || region.Type == MemMapped)
	case "bounded_readonly":
		return !WritableRegion(region) && (region.Type == MemPrivate || region.Type == MemMapped || region.Type == MemImage)
	default:
		return true
	}
}

func StageTailLength(stage string, saltNeighborhoodWindow, defaultTailLength int) int {
	if stage == "salt_neighborhood" {
		return saltNeighborhoodWindow + 64
	}
	return defaultTailLength
}
