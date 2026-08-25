//go:build windows

package provider

import (
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	maxWindowsSystemHandleBuffer = 64 * 1024 * 1024
	maxWindowsHandlesPerProcess  = 16_384
	maxWindowsObservedFilePaths  = 4_096
)

type windowsSystemHandleEntry struct {
	Object                uintptr
	UniqueProcessID       uintptr
	HandleValue           uintptr
	GrantedAccess         uint32
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       uint16
	HandleAttributes      uint32
	Reserved              uint32
}

func windowsTargetHandleValues(processes []windowsProcessEvidence, remaining budget) map[uint32][]windows.Handle {
	targets := map[uint32]bool{}
	for _, process := range processes {
		targets[process.Process.pid] = true
	}
	if len(targets) == 0 || remaining.expired() {
		return nil
	}
	size := uint32(1024 * 1024)
	var buffer []byte
	for size <= maxWindowsSystemHandleBuffer && !remaining.expired() {
		buffer = make([]byte, size)
		var needed uint32
		err := windows.NtQuerySystemInformation(
			windows.SystemExtendedHandleInformation, unsafe.Pointer(&buffer[0]), size, &needed,
		)
		if err == nil {
			break
		}
		if err != windows.STATUS_INFO_LENGTH_MISMATCH {
			return nil
		}
		if needed > size && needed <= maxWindowsSystemHandleBuffer {
			size = needed
		} else {
			size *= 2
		}
		buffer = nil
	}
	if len(buffer) < int(2*unsafe.Sizeof(uintptr(0))) {
		return nil
	}
	headerSize := 2 * unsafe.Sizeof(uintptr(0))
	entrySize := unsafe.Sizeof(windowsSystemHandleEntry{})
	count := *(*uintptr)(unsafe.Pointer(&buffer[0]))
	available := uintptr((len(buffer) - int(headerSize)) / int(entrySize))
	if count > available {
		count = available
	}
	result := map[uint32][]windows.Handle{}
	for index := uintptr(0); index < count && !remaining.expired(); index++ {
		offset := headerSize + index*entrySize
		entry := *(*windowsSystemHandleEntry)(unsafe.Pointer(&buffer[offset]))
		pid := uint32(entry.UniqueProcessID)
		if !targets[pid] || len(result[pid]) >= maxWindowsHandlesPerProcess {
			continue
		}
		result[pid] = append(result[pid], windows.Handle(entry.HandleValue))
	}
	return result
}

func windowsObservedProcessPaths(pid uint32, handles []windows.Handle, remaining budget) []string {
	if len(handles) == 0 || remaining.expired() {
		return nil
	}
	process, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, pid)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(process) //nolint:errcheck -- best-effort read-only binding cleanup
	paths := make([]string, 0, 16)
	seen := map[string]bool{}
	for _, source := range handles {
		if remaining.expired() || len(paths) >= maxWindowsObservedFilePaths {
			break
		}
		var duplicated windows.Handle
		if err := windows.DuplicateHandle(
			process, source, windows.CurrentProcess(), &duplicated, 0, false, windows.DUPLICATE_SAME_ACCESS,
		); err != nil {
			continue
		}
		fileType, typeErr := windows.GetFileType(duplicated)
		if typeErr != nil || fileType != windows.FILE_TYPE_DISK {
			windows.CloseHandle(duplicated) //nolint:errcheck
			continue
		}
		buffer := make([]uint16, 32768)
		length, pathErr := windows.GetFinalPathNameByHandle(duplicated, &buffer[0], uint32(len(buffer)), 0)
		windows.CloseHandle(duplicated) //nolint:errcheck
		if pathErr != nil || length == 0 || length >= uint32(len(buffer)) {
			continue
		}
		path := normalizeWindowsObservedPath(syscall.UTF16ToString(buffer[:length]))
		key := strings.ToLower(path)
		if path == "." || seen[key] {
			continue
		}
		seen[key] = true
		paths = append(paths, path)
	}
	return paths
}

func windowsBindProcessEvidence(processes []windowsProcessEvidence, accountDir, dbDir string, remaining budget) []windowsProcessEvidence {
	bindingBudget := remaining.cappedFor(2 * time.Second)
	handles := windowsTargetHandleValues(processes, bindingBudget)
	for index := range processes {
		paths := windowsObservedProcessPaths(processes[index].Process.pid, handles[processes[index].Process.pid], bindingBudget)
		processes[index].Binding = classifyWindowsObservedPaths(paths, accountDir, dbDir)
		for pathIndex := range paths {
			paths[pathIndex] = ""
		}
	}
	return processes
}
