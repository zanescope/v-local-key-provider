//go:build windows

package provider

import (
	"bytes"
	"errors"
	"strings"
	"syscall"
	"unsafe"
)

const (
	th32csSnapModule         = 0x00000008
	th32csSnapModule32       = 0x00000010
	maxWindowsConfigModule   = uint64(1024 * 1024 * 1024)
	windowsConfigSearchChunk = 1024 * 1024
)

var (
	procModule32FirstW = kernel32.NewProc("Module32FirstW")
	procModule32NextW  = kernel32.NewProc("Module32NextW")
)

type windowsModuleEntry32 struct {
	Size         uint32
	ModuleID     uint32
	ProcessID    uint32
	GlobalUsage  uint32
	ProcessUsage uint32
	BaseAddress  uintptr
	BaseSize     uint32
	ModuleHandle uintptr
	Module       [256]uint16
	ExePath      [260]uint16
}

type windowsProcessModule struct {
	Base uintptr
	Size uint32
	Path string
	Name string
}

type windowsProcessMemoryReader struct {
	handle syscall.Handle
}

func (reader windowsProcessMemoryReader) ReadMemory(address uint64, size int) ([]byte, error) {
	if size <= 0 || size > 4096 || uint64(uintptr(address)) != address {
		return nil, errors.New("invalid process-memory read")
	}
	buffer := make([]byte, size)
	markSensitiveBytes(buffer)
	if readMemory(reader.handle, uintptr(address), buffer) != size {
		zeroBytes(buffer)
		return nil, errors.New("short process-memory read")
	}
	return buffer, nil
}

func windowsPrimaryProcessModule(process targetProcess, executablePath string) (windowsProcessModule, bool) {
	handleValue, _, _ := procCreateToolhelpSnapshot.Call(th32csSnapModule|th32csSnapModule32, uintptr(process.pid))
	if handleValue == ^uintptr(0) {
		return windowsProcessModule{}, false
	}
	handle := syscall.Handle(handleValue)
	defer closeHandle(handle)
	entry := windowsModuleEntry32{Size: uint32(unsafe.Sizeof(windowsModuleEntry32{}))}
	result, _, _ := procModule32FirstW.Call(uintptr(handle), uintptr(unsafe.Pointer(&entry)))
	if result == 0 {
		return windowsProcessModule{}, false
	}
	var fallback windowsProcessModule
	for {
		module := windowsProcessModule{
			Base: entry.BaseAddress, Size: entry.BaseSize,
			Path: syscall.UTF16ToString(entry.ExePath[:]), Name: syscall.UTF16ToString(entry.Module[:]),
		}
		if fallback.Base == 0 {
			fallback = module
		}
		if executablePath != "" && strings.EqualFold(module.Path, executablePath) ||
			strings.EqualFold(module.Name, process.name) {
			return module, module.Base != 0 && module.Size > 0
		}
		entry.Size = uint32(unsafe.Sizeof(windowsModuleEntry32{}))
		result, _, _ = procModule32NextW.Call(uintptr(handle), uintptr(unsafe.Pointer(&entry)))
		if result == 0 {
			break
		}
	}
	return fallback, fallback.Base != 0 && fallback.Size > 0
}

func windowsConfigNeedleAddresses(handle syscall.Handle, module windowsProcessModule, recipe windowsConfigCipherRecipe, scanLimit uint64, remaining budget) ([]uint64, uint64) {
	if !recipe.Valid() || module.Base == 0 || module.Size == 0 || uint64(module.Size) > maxWindowsConfigModule || scanLimit == 0 {
		return nil, 0
	}
	moduleEnd := module.Base + uintptr(module.Size)
	if moduleEnd <= module.Base {
		return nil, 0
	}
	buffer := make([]byte, windowsConfigSearchChunk)
	tail := make([]byte, 0, len(recipe.Needle)-1)
	markSensitiveBytes(buffer)
	markSensitiveBytes(tail)
	defer zeroBytes(buffer)
	defer zeroBytes(tail)
	seen := map[uint64]bool{}
	addresses := make([]uint64, 0, recipe.MaxMatches)
	var scanned uint64
	scanRange := func(start, end uintptr) {
		tail = tail[:0]
		for cursor := start; cursor < end && scanned < scanLimit && len(addresses) < recipe.MaxMatches && !remaining.expired(); {
			wanted := uintptr(len(buffer))
			if end-cursor < wanted {
				wanted = end - cursor
			}
			if available := scanLimit - scanned; uint64(wanted) > available {
				wanted = uintptr(available)
			}
			read := readMemory(handle, cursor, buffer[:int(wanted)])
			if read > 0 {
				scanned += uint64(read)
				combined := make([]byte, 0, len(tail)+read)
				combined = append(combined, tail...)
				combined = append(combined, buffer[:read]...)
				markSensitiveBytes(combined)
				combinedBase := uint64(cursor) - uint64(len(tail))
				for search := 0; search < len(combined) && len(addresses) < recipe.MaxMatches; {
					relative := bytes.Index(combined[search:], recipe.Needle)
					if relative < 0 {
						break
					}
					position := search + relative
					address := combinedBase + uint64(position)
					if !seen[address] {
						seen[address] = true
						addresses = append(addresses, address)
					}
					search = position + 1
				}
				keep := len(recipe.Needle) - 1
				if keep > len(combined) {
					keep = len(combined)
				}
				tail = append(tail[:0], combined[len(combined)-keep:]...)
				zeroBytes(combined)
			} else {
				tail = tail[:0]
			}
			cursor += wanted
		}
	}
	for cursor := module.Base; cursor < moduleEnd && len(addresses) < recipe.MaxMatches && !remaining.expired(); {
		info, ok := queryMemoryRegion(handle, cursor)
		if !ok {
			break
		}
		next := info.BaseAddress + info.RegionSize
		if next <= cursor {
			break
		}
		start := info.BaseAddress
		if start < module.Base {
			start = module.Base
		}
		end := next
		if end > moduleEnd {
			end = moduleEnd
		}
		if start < end && readableRegion(info) {
			scanRange(start, end)
		}
		cursor = next
	}
	return addresses, scanned
}

type windowsConfigCipherAttempt struct {
	Status             string
	StructureCount     int
	InvalidStructures  int
	CandidateCount     int
	VerifiedCandidates int
	ScannedBytes       uint64
}

func scanWindowsConfigCipherProcess(handle syscall.Handle, process windowsProcessEvidence, recipe windowsConfigCipherRecipe, collector *candidateCollector, scanLimit uint64, remaining budget) windowsConfigCipherAttempt {
	attempt := windowsConfigCipherAttempt{Status: windowsConfigCipherNoStructure}
	module, found := windowsPrimaryProcessModule(process.Process, process.Path)
	if !found {
		return attempt
	}
	addresses, scanned := windowsConfigNeedleAddresses(handle, module, recipe, scanLimit, remaining)
	attempt.ScannedBytes = scanned
	attempt.StructureCount = len(addresses)
	if len(addresses) == 0 {
		return attempt
	}
	pointerSize := 8
	if process.Architecture == "x86" {
		pointerSize = 4
	}
	reader := windowsProcessMemoryReader{handle: handle}
	for _, address := range addresses {
		if remaining.expired() {
			break
		}
		candidate, err := extractWindowsConfigCipherCandidate(reader, address, pointerSize, recipe)
		if err != nil {
			attempt.InvalidStructures++
			continue
		}
		attempt.CandidateCount++
		accepted := false
		switch recipe.CandidateKind {
		case "raw_enc_key":
			accepted = collector.ConsiderCapturedDatabaseKeyFrom(candidate, "windows_config_cipher")
		case "passphrase":
			// A fixed memory layout is not complete KDF call evidence. It may be
			// used to derive current effective keys, but cannot promote a root.
			accepted = collector.RecordGlobalPassphrase(candidate, "windows_config_cipher", false)
		}
		zeroBytes(candidate)
		if accepted {
			attempt.VerifiedCandidates++
		}
	}
	switch {
	case attempt.CandidateCount == 0 && attempt.InvalidStructures > 0:
		attempt.Status = windowsConfigCipherInvalidStructure
	case attempt.VerifiedCandidates == 0:
		attempt.Status = windowsConfigCipherNoVerifiedCandidate
	case collector.HasAllDatabaseCandidates():
		attempt.Status = windowsConfigCipherSucceeded
	default:
		attempt.Status = windowsConfigCipherPartial
	}
	return attempt
}
