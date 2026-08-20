//go:build darwin && cgo

package main

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
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unsafe"
)

const (
	darwinKernSuccess       = 0
	darwinVMProtRead        = 0x1
	darwinReadChunkSize     = 1024 * 1024
	darwinPerProcessScanMax = uint64(2 * 1024 * 1024 * 1024)
	darwinTotalScanMax      = uint64(6 * 1024 * 1024 * 1024)
)

type darwinProcess struct {
	pid     int
	name    string
	command string
}

func parseDarwinProcessList(output string) []darwinProcess {
	seen := map[int]bool{}
	var processes []darwinProcess
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil || pid <= 0 || seen[pid] {
			continue
		}
		name := fields[1]
		command := strings.Join(fields[2:], " ")
		if !isDarwinWeChatProcess(name, command) {
			continue
		}
		seen[pid] = true
		processes = append(processes, darwinProcess{pid: pid, name: name, command: command})
	}
	return processes
}

func isDarwinWeChatProcess(name, command string) bool {
	baseName := strings.ToLower(filepath.Base(name))
	lowerCommand := strings.ToLower(command)
	if baseName == "wechatappex" || strings.Contains(lowerCommand, "wechatappex") ||
		strings.Contains(lowerCommand, "crashpad_handler") || strings.Contains(lowerCommand, "helper") {
		return false
	}
	if baseName == "wechat" || baseName == "weixin" || baseName == "微信" {
		return true
	}
	return strings.Contains(lowerCommand, "/contents/macos/wechat") ||
		strings.Contains(lowerCommand, "/contents/macos/weixin") ||
		strings.Contains(lowerCommand, "/contents/macos/微信")
}

func darwinTargetProcesses() ([]darwinProcess, error) {
	output, err := exec.Command("/bin/ps", "-axo", "pid=,comm=,args=").Output()
	if err != nil {
		return nil, fmt.Errorf("读取微信进程列表失败：%w", err)
	}
	return parseDarwinProcessList(string(output)), nil
}

func darwinTaskForPID(pid int) (C.mach_port_t, error) {
	var task C.mach_port_t
	result := C.z_task_for_pid(C.pid_t(pid), &task)
	if int(result) != darwinKernSuccess || task == C.MACH_PORT_NULL {
		return C.MACH_PORT_NULL, fmt.Errorf("task_for_pid failed: kern_return=%d", int(result))
	}
	return task, nil
}

func darwinCloseTask(task C.mach_port_t) {
	if task != C.MACH_PORT_NULL {
		_ = C.z_mach_port_deallocate(task)
	}
}

func darwinRegion(task C.mach_port_t, address uint64) (uint64, uint64, uint32, bool) {
	base := C.mach_vm_address_t(address)
	size := C.mach_vm_size_t(0)
	protection := C.vm_prot_t(0)
	result := C.z_mach_vm_region(task, &base, &size, &protection)
	if int(result) != darwinKernSuccess || size == 0 {
		return 0, 0, 0, false
	}
	return uint64(base), uint64(size), uint32(protection), true
}

func darwinRead(task C.mach_port_t, address uint64, buffer []byte) (int, bool) {
	if len(buffer) == 0 {
		return 0, true
	}
	readSize := C.mach_vm_size_t(0)
	result := C.z_mach_vm_read_overwrite(
		task,
		C.mach_vm_address_t(address),
		C.mach_vm_size_t(len(buffer)),
		unsafe.Pointer(&buffer[0]),
		&readSize,
	)
	if int(result) != darwinKernSuccess || readSize == 0 || readSize > C.mach_vm_size_t(len(buffer)) {
		return 0, false
	}
	return int(readSize), true
}

func scanDarwinProcess(task C.mach_port_t, collector *candidateCollector, limit uint64, allowKeyObjects bool, remaining budget) (uint64, bool) {
	var address uint64
	var scanned uint64
	var visited uint64
	limited := false
	buffer := make([]byte, darwinReadChunkSize)
	seenPointers := map[uint64]bool{}

	for visited < limit {
		if remaining.expired() {
			return scanned, true
		}
		base, size, protection, ok := darwinRegion(task, address)
		if !ok {
			break
		}
		next := base + size
		if next <= address {
			break
		}
		if protection&darwinVMProtRead != 0 && size <= maxScanRegionBytes {
			regionEnd := next
			cursor := base
			tail := make([]byte, 0, scanTailLength)
			for cursor < regionEnd && visited < limit {
				if remaining.expired() {
					return scanned, true
				}
				wanted := uint64(darwinReadChunkSize)
				if remainingRegion := regionEnd - cursor; remainingRegion < wanted {
					wanted = remainingRegion
				}
				if wanted > limit-visited {
					wanted = limit - visited
					limited = true
				}
				if wanted == 0 {
					break
				}
				read, readOK := darwinRead(task, cursor, buffer[:int(wanted)])
				visited += wanted
				if readOK && read > 0 {
					combined := make([]byte, 0, len(tail)+read)
					combined = append(combined, tail...)
					combined = append(combined, buffer[:read]...)
					collector.scan(combined)
					// 指令形态的 XOR 兜底在 image 和 heap 区域同样有用，
					// 因此对所有可读页都保持启用。
					collector.scanInternalXORKeys(combined)
					if allowKeyObjects {
						collector.collectKeyObjects(combined, seenPointers, func(pointer uint64, buffer []byte) int {
							if read, ok := darwinRead(task, pointer, buffer); ok {
								return read
							}
							return 0
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
	if visited >= limit {
		limited = true
	}
	return scanned, limited
}

func platformAcquire(targets databaseTargets, media mediaEvidence, options acquireOptions) (response, diagnostics, error) {
	helperStatus := options.helperStatus
	if options.helperMode {
		helperStatus = "used"
	}
	diag := diagnostics{
		Platform:                  "darwin",
		HelperStatus:              helperStatus,
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
		diag.ProcessAccessStatus = "not_needed"
		return response{}, diag, nil
	}
	if !needDatabaseScan && derivedMedia != nil {
		diag.ProcessAccessStatus = "not_needed"
		diag.MediaCandidateMethod = "kvcomm_formula_v2_sample"
		return response{ImageKeys: derivedMedia}, diag, nil
	}
	if options.budget.expired() {
		diag.ProcessAccessStatus = "deadline_exhausted"
		return response{}, diag, nil
	}

	processes, err := darwinTargetProcesses()
	if err != nil {
		return response{}, diag, err
	}
	diag.ProcessCount = len(processes)
	if len(processes) > 0 {
		diag.WeChatVersion = darwinProcessVersion(processes[0])
		diag.ProcessArchitecture = darwinProcessArchitecture(processes[0])
	} else {
		// 全新初始化可能正好赶在微信进程切换的空档启动。4.1.x 的密钥只在数据库
		// 初始化时可见，因此即便当前没有可附加的 PID，也必须武装 wait-for。
		diag.ProcessArchitecture = runtime.GOARCH
	}
	diag.VersionSupport = darwinVersionSupport(diag.WeChatVersion)
	scanMedia := selectedMedia
	if !needMediaScan {
		scanMedia = mediaEvidence{xorCandidates: map[byte]int{}}
	}
	collector := newCandidateCollector(targets, scanMedia)
	dynamicHookAttempted := false
	dynamicWaitForAttempted := false
	recordHook := func(hook darwinHookResult) {
		diag.HookTargetFound += hook.targetFound
		diag.HookInstalled = diag.HookInstalled || hook.installed
		diag.HookTimeout = diag.HookTimeout || hook.timedOut
		diag.HookCaptureCount += hook.captures
		diag.DynamicHookUsed = diag.DynamicHookUsed || hook.used
		diag.HookTriggerRequired = diag.HookTriggerRequired || hook.triggerNeeded
		diag.HookRestartRequired = diag.HookRestartRequired || hook.restartNeeded
	}
	tryDynamicHook := func(waitFor bool) {
		if !options.database || options.budget.expired() {
			return
		}
		if waitFor {
			if dynamicWaitForAttempted {
				return
			}
			dynamicWaitForAttempted = true
		} else {
			if dynamicHookAttempted {
				return
			}
			dynamicHookAttempted = true
		}
		if waitFor && len(processes) == 0 {
			recordHook(captureDarwinHookMode(darwinProcess{}, collector, options.budget, true))
			return
		}
		for _, process := range processes {
			if options.budget.expired() || collector.hasAllDatabaseCandidates() {
				break
			}
			hook := captureDarwinHookMode(process, collector, options.budget, waitFor)
			recordHook(hook)
		}
	}
	if len(processes) == 0 {
		// 让 lldb 等待新的微信进程，而不是在装上数据库打开钩子之前就失败。
		tryDynamicHook(true)
		diag.StaticScanFallback = !collector.hasAllDatabaseCandidates()
	} else if darwinPreferDynamicHook(diag.WeChatVersion) {
		tryDynamicHook(false)
		if !collector.hasAllDatabaseCandidates() {
			tryDynamicHook(true)
		}
		diag.StaticScanFallback = !collector.hasAllDatabaseCandidates()
	}
	if len(processes) == 0 {
		// wait-for 的目标此刻可能已经起来了。刷新进程列表，以便钩子没抓到时
		// 常规的静态兜底能检查它。
		if refreshed, refreshErr := darwinTargetProcesses(); refreshErr == nil {
			processes = refreshed
			diag.ProcessCount = len(processes)
			if len(processes) > 0 {
				diag.WeChatVersion = darwinProcessVersion(processes[0])
				diag.ProcessArchitecture = darwinProcessArchitecture(processes[0])
				diag.VersionSupport = darwinVersionSupport(diag.WeChatVersion)
			}
		}
	}
	for _, process := range processes {
		if diag.ScannedBytes >= darwinTotalScanMax || options.budget.expired() {
			diag.ScanLimited = true
			break
		}
		task, taskErr := darwinTaskForPID(process.pid)
		if taskErr != nil {
			diag.AccessDeniedCount++
			continue
		}
		diag.OpenedProcessCount++
		remaining := darwinTotalScanMax - diag.ScannedBytes
		if remaining > darwinPerProcessScanMax {
			remaining = darwinPerProcessScanMax
		}
		scanned, limited := scanDarwinProcess(task, collector, remaining, true, options.budget)
		darwinCloseTask(task)
		diag.ScannedBytes += scanned
		diag.ScanLimited = diag.ScanLimited || limited
	}
	if !collector.hasAllDatabaseCandidates() {
		tryDynamicHook(false)
	}
	switch {
	case diag.OpenedProcessCount > 0 && diag.AccessDeniedCount > 0:
		diag.ProcessAccessStatus = "partial"
	case diag.HookInstalled && diag.OpenedProcessCount == 0:
		diag.ProcessAccessStatus = "dynamic_hook_opened"
	case diag.OpenedProcessCount > 0 && options.helperMode:
		diag.ProcessAccessStatus = "helper_opened"
	case diag.OpenedProcessCount > 0:
		diag.ProcessAccessStatus = "direct_opened"
	case diag.AccessDeniedCount > 0:
		diag.ProcessAccessStatus = "denied"
		if options.helperStatus == "sip_enabled" {
			diag.ProcessAccessError = "sip_enabled"
		} else {
			diag.ProcessAccessError = "task_for_pid_denied"
		}
	case diag.ProcessCount == 0:
		diag.ProcessAccessStatus = "wechat_not_running"
	case options.budget.expired():
		diag.ProcessAccessStatus = "deadline_exhausted"
	default:
		diag.ProcessAccessStatus = "unavailable"
	}
	if !collector.hasAllDatabaseCandidates() {
		collector.resolveDatabasePassphrase(options.budget)
	}
	keys, ambiguous := collector.databaseKeys(targets)
	if diag.HookRestartRequired && len(keys) == 0 {
		diag.ProcessAccessError = "hook_restart_required"
	} else if diag.HookTriggerRequired && len(keys) == 0 {
		diag.ProcessAccessError = "hook_trigger_required"
	} else if len(keys) > 0 {
		diag.HookTriggerRequired = false
		diag.HookRestartRequired = false
	}
	imageCandidate := collector.applyScanDiagnostics(&diag, keys, ambiguous, derivedMedia, scanMedia)
	return response{DatabaseKeys: keys, ImageKeys: imageCandidate}, diag, nil
}
