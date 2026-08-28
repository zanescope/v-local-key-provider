//go:build windows

package windows

import (
	"runtime"
	"syscall"
	"unsafe"

	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	"github.com/zanescope/v-local-key-provider/internal/workbudget"
)

var (
	memoryKernel32              = syscall.NewLazyDLL("kernel32.dll")
	procNativeVirtualQueryEx    = memoryKernel32.NewProc("VirtualQueryEx")
	procNativeReadProcessMemory = memoryKernel32.NewProc("ReadProcessMemory")
)

type NativeMemoryRegion struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionID       uint16
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

func QueryMemoryRegion(handle syscall.Handle, address uintptr) (NativeMemoryRegion, bool) {
	var region NativeMemoryRegion
	result, _, _ := procNativeVirtualQueryEx.Call(
		uintptr(handle), address, uintptr(unsafe.Pointer(&region)), unsafe.Sizeof(region),
	)
	return region, result != 0 && region.RegionSize != 0
}

func ReadProcessMemory(handle syscall.Handle, address uintptr, buffer []byte) int {
	if len(buffer) == 0 {
		return 0
	}
	var bytesRead uintptr
	procNativeReadProcessMemory.Call(
		uintptr(handle), address, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if bytesRead > uintptr(len(buffer)) {
		return 0
	}
	return int(bytesRead)
}

type MemoryReader func(uint64, []byte) int

type ScanStageCallbacks struct {
	Expired        func() bool
	MarkSensitive  func([]byte)
	ClearSensitive func([]byte)
	ScanChunk      func(stage string, regionType uint32, data []byte, reader MemoryReader)
}

func (callbacks ScanStageCallbacks) expired() bool {
	return callbacks.Expired != nil && callbacks.Expired()
}

func (callbacks ScanStageCallbacks) mark(value []byte) {
	if callbacks.MarkSensitive != nil {
		callbacks.MarkSensitive(value)
	}
}

func (callbacks ScanStageCallbacks) clear(value []byte) {
	if callbacks.ClearSensitive != nil {
		callbacks.ClearSensitive(value)
		return
	}
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}

// ScanProcessStage 持有 Windows 虚拟内存遍历和有界读取。ScanChunk 必须同步消费数据，
// 且不得保留该 slice。
func ScanProcessStage(
	handle syscall.Handle,
	limit uint64,
	stage string,
	tailLength int,
	maxRegionBytes uint64,
	callbacks ScanStageCallbacks,
) (uint64, bool) {
	if limit == 0 || tailLength < 0 || tailLength > ReadChunkSize || maxRegionBytes == 0 {
		return 0, true
	}
	var address uintptr
	var scanned uint64
	limited := false
	buffer := make([]byte, ReadChunkSize)
	tailStorage := make([]byte, tailLength)
	tail := tailStorage[:0]
	callbacks.mark(buffer)
	callbacks.mark(tailStorage)
	defer callbacks.clear(buffer)
	defer callbacks.clear(tailStorage)
	reader := func(pointer uint64, destination []byte) int {
		return ReadProcessMemory(handle, uintptr(pointer), destination)
	}
	for scanned < limit {
		if callbacks.expired() {
			return scanned, true
		}
		region, ok := QueryMemoryRegion(handle, address)
		if !ok {
			break
		}
		next := region.BaseAddress + region.RegionSize
		if next <= address {
			break
		}
		policyRegion := MemoryRegion{State: region.State, Protect: region.Protect, Type: region.Type}
		if StageReadsRegion(stage, policyRegion) && uint64(region.RegionSize) <= maxRegionBytes {
			tail = tail[:0]
			regionEnd := next
			for cursor := region.BaseAddress; cursor < regionEnd && scanned < limit; {
				if callbacks.expired() {
					return scanned, true
				}
				regionRemaining := regionEnd - cursor
				wanted := uintptr(ReadChunkSize)
				if regionRemaining < wanted {
					wanted = regionRemaining
				}
				if uint64(wanted) > limit-scanned {
					wanted = uintptr(limit - scanned)
					limited = true
				}
				read := ReadProcessMemory(handle, cursor, buffer[:int(wanted)])
				if read > 0 {
					combined := make([]byte, 0, len(tail)+read)
					combined = append(combined, tail...)
					combined = append(combined, buffer[:read]...)
					func() {
						callbacks.mark(combined)
						defer callbacks.clear(combined)
						if callbacks.ScanChunk != nil {
							callbacks.ScanChunk(stage, region.Type, combined, reader)
						}
						keep := tailLength
						if len(combined) < keep {
							keep = len(combined)
						}
						tail = append(tail[:0], combined[len(combined)-keep:]...)
					}()
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

func (driver *nativeDriver) ScanStage(handle Handle, collector *acquisitionmodel.Collector, limit uint64, stage string, remaining workbudget.Budget) (uint64, bool) {
	seenPointers := map[uint64]bool{}
	return ScanProcessStage(
		syscall.Handle(handle), limit, stage,
		StageTailLength(stage, acquisitionmodel.SaltNeighborhoodWindow, acquisitionmodel.ScanTailLength),
		acquisitionmodel.MaxScanRegionBytes,
		ScanStageCallbacks{
			Expired:        remaining.Expired,
			MarkSensitive:  driver.runtime.Sensitive.mark,
			ClearSensitive: driver.runtime.Sensitive.clear,
			ScanChunk: func(stage string, regionType uint32, combined []byte, reader MemoryReader) {
				switch stage {
				case "structured_key_object":
					if regionType == MemImage {
						collector.ScanInternalXORKeys(combined)
					}
					collector.CollectKeyObjects(combined, seenPointers, func(pointer uint64, buffer []byte) int {
						return reader(pointer, buffer)
					})
				case "salt_neighborhood":
					collector.ScanSaltNeighborhood(combined)
				case "bounded_writable_heap":
					collector.ScanDatabasePatternsFrom(combined, "bounded_heap")
					collector.ScanMediaPatterns(combined)
				case "bounded_readonly":
					collector.ScanDatabasePatternsFrom(combined, "bounded_readonly")
					collector.ScanMediaPatterns(combined)
				case "bounded_hex":
					collector.ScanDatabasePatternsFrom(combined, "bounded_hex")
					collector.ScanMediaPatterns(combined)
				}
			},
		},
	)
}
