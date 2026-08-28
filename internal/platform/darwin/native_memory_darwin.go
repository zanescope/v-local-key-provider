//go:build darwin && cgo

package darwin

/*
#cgo CFLAGS: -D_DARWIN_C_SOURCE
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <sys/types.h>

static kern_return_t z_task_for_pid(pid_t pid, mach_port_t *task) {
	return task_for_pid(mach_task_self(), pid, task);
}

static kern_return_t z_mach_vm_region(
	mach_port_t task,
	mach_vm_address_t *address,
	mach_vm_size_t *size,
	vm_prot_t *protection
) {
	vm_region_basic_info_data_64_t info;
	mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
	mach_port_t object = MACH_PORT_NULL;
	kern_return_t result = mach_vm_region(
		task,
		address,
		size,
		VM_REGION_BASIC_INFO_64,
		(vm_region_info_t)&info,
		&count,
		&object
	);
	if (result == KERN_SUCCESS && protection != 0) {
		*protection = info.protection;
	}
	if (object != MACH_PORT_NULL) {
		mach_port_deallocate(mach_task_self(), object);
	}
	return result;
}

static kern_return_t z_mach_vm_read_overwrite(
	mach_port_t task,
	mach_vm_address_t address,
	mach_vm_size_t size,
	void *buffer,
	mach_vm_size_t *read_size
) {
	return mach_vm_read_overwrite(task, address, size, (mach_vm_address_t)buffer, read_size);
}

static kern_return_t z_mach_port_deallocate(mach_port_t port) {
	return mach_port_deallocate(mach_task_self(), port);
}
*/
import "C"

import (
	"fmt"
	"unsafe"

	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	"github.com/zanescope/v-local-key-provider/internal/workbudget"
)

const (
	kernSuccess = 0
	vmProtRead  = 0x1
)

func taskForPID(pid int) (C.mach_port_t, error) {
	var task C.mach_port_t
	result := C.z_task_for_pid(C.pid_t(pid), &task)
	if int(result) != kernSuccess || task == C.MACH_PORT_NULL {
		return C.MACH_PORT_NULL, fmt.Errorf("task_for_pid failed: kern_return=%d", int(result))
	}
	return task, nil
}

func closeTask(task C.mach_port_t) {
	if task != C.MACH_PORT_NULL {
		_ = C.z_mach_port_deallocate(task)
	}
}

func memoryRegion(task C.mach_port_t, address uint64) (uint64, uint64, uint32, bool) {
	base := C.mach_vm_address_t(address)
	size := C.mach_vm_size_t(0)
	protection := C.vm_prot_t(0)
	result := C.z_mach_vm_region(task, &base, &size, &protection)
	if int(result) != kernSuccess || size == 0 {
		return 0, 0, 0, false
	}
	return uint64(base), uint64(size), uint32(protection), true
}

func readMemory(task C.mach_port_t, address uint64, buffer []byte) int {
	if len(buffer) == 0 {
		return 0
	}
	readSize := C.mach_vm_size_t(0)
	result := C.z_mach_vm_read_overwrite(
		task,
		C.mach_vm_address_t(address),
		C.mach_vm_size_t(len(buffer)),
		unsafe.Pointer(&buffer[0]),
		&readSize,
	)
	if int(result) != kernSuccess || readSize == 0 || readSize > C.mach_vm_size_t(len(buffer)) {
		return 0
	}
	return int(readSize)
}

func (driver *nativeDriver) scanTask(
	task C.mach_port_t,
	collector *acquisitionmodel.Collector,
	limit uint64,
	remaining workbudget.Budget,
) (uint64, bool) {
	var address uint64
	var scanned uint64
	var visited uint64
	limited := false
	buffer := make([]byte, ReadChunkSize)
	tailStorage := make([]byte, acquisitionmodel.ScanTailLength)
	tail := tailStorage[:0]
	seenPointers := map[uint64]bool{}
	driver.mark(buffer)
	driver.mark(tailStorage)
	defer driver.clear(buffer)
	defer driver.clear(tailStorage)

	for visited < limit {
		if remaining.Expired() {
			return scanned, true
		}
		base, size, protection, ok := memoryRegion(task, address)
		if !ok {
			break
		}
		next := base + size
		if next <= address {
			break
		}
		if protection&vmProtRead != 0 && size <= acquisitionmodel.MaxScanRegionBytes {
			tail = tail[:0]
			regionEnd := next
			for cursor := base; cursor < regionEnd && visited < limit; {
				if remaining.Expired() {
					return scanned, true
				}
				wanted := uint64(ReadChunkSize)
				if regionRemaining := regionEnd - cursor; regionRemaining < wanted {
					wanted = regionRemaining
				}
				if wanted > limit-visited {
					wanted = limit - visited
					limited = true
				}
				if wanted == 0 {
					break
				}
				read := readMemory(task, cursor, buffer[:int(wanted)])
				visited += wanted
				if read > 0 {
					combined := make([]byte, 0, len(tail)+read)
					combined = append(combined, tail...)
					combined = append(combined, buffer[:read]...)
					func() {
						driver.mark(combined)
						defer driver.clear(combined)
						collector.Scan(combined)
						collector.ScanInternalXORKeys(combined)
						collector.CollectKeyObjects(combined, seenPointers, func(pointer uint64, destination []byte) int {
							return readMemory(task, pointer, destination)
						})
						collector.ScanSaltNeighborhood(combined)
						keep := acquisitionmodel.ScanTailLength
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
	if visited >= limit {
		limited = true
	}
	return scanned, limited
}

func (driver *nativeDriver) ScanProcess(
	process Process,
	collector *acquisitionmodel.Collector,
	limit uint64,
	remaining workbudget.Budget,
) ScanResult {
	task, err := taskForPID(process.PID)
	if err != nil {
		return ScanResult{}
	}
	defer closeTask(task)
	scanned, limited := driver.scanTask(task, collector, limit, remaining)
	return ScanResult{Scanned: scanned, Limited: limited, Opened: true}
}
