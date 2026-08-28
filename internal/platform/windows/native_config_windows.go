//go:build windows

package windows

import (
	"bytes"
	"errors"
	"strings"
	"syscall"
	"unsafe"

	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	"github.com/zanescope/v-local-key-provider/internal/workbudget"
)

const (
	toolhelpSnapshotModule   = 0x00000008
	toolhelpSnapshotModule32 = 0x00000010
	maxConfigModule          = uint64(1024 * 1024 * 1024)
	configSearchChunk        = 1024 * 1024
)

var (
	procModule32FirstW = processKernel32.NewProc("Module32FirstW")
	procModule32NextW  = processKernel32.NewProc("Module32NextW")
)

type moduleEntry32 struct {
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

type processModule struct {
	Base uintptr
	Size uint32
	Path string
	Name string
}

type processMemoryReader struct {
	handle    Handle
	sensitive SensitiveRuntime
}

func (reader processMemoryReader) ReadMemory(address uint64, size int) ([]byte, error) {
	if size <= 0 || size > 4096 || uint64(uintptr(address)) != address {
		return nil, errors.New("invalid process-memory read")
	}
	buffer := make([]byte, size)
	reader.sensitive.mark(buffer)
	if ReadProcessMemory(syscall.Handle(reader.handle), uintptr(address), buffer) != size {
		reader.sensitive.clear(buffer)
		return nil, errors.New("short process-memory read")
	}
	return buffer, nil
}

func primaryProcessModule(process Process, executablePath string) (processModule, bool) {
	handleValue, _, _ := procCreateToolhelpSnapshot.Call(
		toolhelpSnapshotModule|toolhelpSnapshotModule32, uintptr(process.PID),
	)
	if handleValue == ^uintptr(0) {
		return processModule{}, false
	}
	handle := Handle(handleValue)
	defer closeNativeHandle(handle)
	entry := moduleEntry32{Size: uint32(unsafe.Sizeof(moduleEntry32{}))}
	result, _, _ := procModule32FirstW.Call(uintptr(handle), uintptr(unsafe.Pointer(&entry)))
	if result == 0 {
		return processModule{}, false
	}
	var fallback processModule
	for {
		module := processModule{
			Base: entry.BaseAddress, Size: entry.BaseSize,
			Path: syscall.UTF16ToString(entry.ExePath[:]), Name: syscall.UTF16ToString(entry.Module[:]),
		}
		if fallback.Base == 0 {
			fallback = module
		}
		if executablePath != "" && strings.EqualFold(module.Path, executablePath) ||
			strings.EqualFold(module.Name, process.Name) {
			return module, module.Base != 0 && module.Size > 0
		}
		entry.Size = uint32(unsafe.Sizeof(moduleEntry32{}))
		result, _, _ = procModule32NextW.Call(uintptr(handle), uintptr(unsafe.Pointer(&entry)))
		if result == 0 {
			break
		}
	}
	return fallback, fallback.Base != 0 && fallback.Size > 0
}

func configNeedleAddresses(handle Handle, module processModule, recipe ConfigCipherRecipe, scanLimit uint64, remaining workbudget.Budget, sensitive SensitiveRuntime) ([]uint64, uint64) {
	if !recipe.Valid() || module.Base == 0 || module.Size == 0 || uint64(module.Size) > maxConfigModule || scanLimit == 0 {
		return nil, 0
	}
	moduleEnd := module.Base + uintptr(module.Size)
	if moduleEnd <= module.Base {
		return nil, 0
	}
	buffer := make([]byte, configSearchChunk)
	tailStorage := make([]byte, len(recipe.Needle)-1)
	tail := tailStorage[:0]
	sensitive.mark(buffer)
	sensitive.mark(tailStorage)
	defer sensitive.clear(buffer)
	defer sensitive.clear(tailStorage)
	seen := map[uint64]bool{}
	addresses := make([]uint64, 0, recipe.MaxMatches)
	var scanned uint64
	scanRange := func(start, end uintptr) {
		tail = tail[:0]
		for cursor := start; cursor < end && scanned < scanLimit && len(addresses) < recipe.MaxMatches && !remaining.Expired(); {
			wanted := uintptr(len(buffer))
			if end-cursor < wanted {
				wanted = end - cursor
			}
			if available := scanLimit - scanned; uint64(wanted) > available {
				wanted = uintptr(available)
			}
			read := ReadProcessMemory(syscall.Handle(handle), cursor, buffer[:int(wanted)])
			if read > 0 {
				scanned += uint64(read)
				combined := make([]byte, 0, len(tail)+read)
				combined = append(combined, tail...)
				combined = append(combined, buffer[:read]...)
				sensitive.mark(combined)
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
				sensitive.clear(combined)
			} else {
				tail = tail[:0]
			}
			cursor += wanted
		}
	}
	for cursor := module.Base; cursor < moduleEnd && len(addresses) < recipe.MaxMatches && !remaining.Expired(); {
		info, ok := QueryMemoryRegion(syscall.Handle(handle), cursor)
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
		if start < end && ReadableRegion(MemoryRegion{State: info.State, Protect: info.Protect, Type: info.Type}) {
			scanRange(start, end)
		}
		cursor = next
	}
	return addresses, scanned
}

func (driver *nativeDriver) ScanConfig(handle Handle, process ProcessEvidence, recipe ConfigCipherRecipe, collector *acquisitionmodel.Collector, scanLimit uint64, remaining workbudget.Budget) ConfigCipherAttempt {
	attempt := ConfigCipherAttempt{Status: ConfigCipherNoStructure}
	module, found := primaryProcessModule(process.Process, process.Path)
	if !found {
		return attempt
	}
	addresses, scanned := configNeedleAddresses(handle, module, recipe, scanLimit, remaining, driver.runtime.Sensitive)
	attempt.ScannedBytes = scanned
	attempt.StructureCount = len(addresses)
	if len(addresses) == 0 {
		return attempt
	}
	pointerSize := 8
	if process.Architecture == "x86" {
		pointerSize = 4
	}
	reader := processMemoryReader{handle: handle, sensitive: driver.runtime.Sensitive}
	for _, address := range addresses {
		if remaining.Expired() {
			break
		}
		candidate, err := ExtractConfigCipherCandidate(reader, address, pointerSize, recipe, driver.runtime.Sensitive)
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
			accepted = collector.RecordGlobalPassphrase(candidate, "windows_config_cipher", false)
		}
		driver.runtime.Sensitive.clear(candidate)
		if accepted {
			attempt.VerifiedCandidates++
		}
	}
	switch {
	case attempt.CandidateCount == 0 && attempt.InvalidStructures > 0:
		attempt.Status = ConfigCipherInvalidStructure
	case attempt.VerifiedCandidates == 0:
		attempt.Status = ConfigCipherNoVerifiedCandidate
	case collector.HasAllDatabaseCandidates():
		attempt.Status = ConfigCipherSucceeded
	default:
		attempt.Status = ConfigCipherPartial
	}
	return attempt
}
