//go:build darwin && cgo

package provider

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
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

const (
	darwinKernSuccess       = 0
	darwinVMProtRead        = 0x1
	darwinReadChunkSize     = 1024 * 1024
	darwinPerProcessScanMax = uint64(2 * 1024 * 1024 * 1024)
	darwinTotalScanMax      = uint64(6 * 1024 * 1024 * 1024)
)

type darwinProcessDiscoveryError struct {
	PS        error
	Launchctl error
}

func (err *darwinProcessDiscoveryError) Error() string {
	return fmt.Sprintf("读取微信进程列表失败：ps=%v；launchctl=%v", err.PS, err.Launchctl)
}

func darwinTargetProcesses() ([]darwinProcess, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	output, err := runBoundedDarwinOutput(ctx, "/bin/ps", []string{"-axo", "pid=,comm=,args="}, 8*1024*1024)
	defer zeroBytes(output)
	if err == nil {
		return parseDarwinProcessList(string(output)), "ps", nil
	}
	uid := strconv.Itoa(os.Getuid())
	launchOutput, launchErr := runBoundedDarwinOutput(ctx, "/bin/launchctl", []string{"print", "gui/" + uid}, 8*1024*1024)
	defer zeroBytes(launchOutput)
	if launchErr == nil {
		processes := parseLaunchctlProcessList(string(launchOutput))
		seen := map[int]bool{}
		for _, process := range processes {
			seen[process.pid] = true
		}
		refs := parseLaunchctlProcessRefs(string(launchOutput))
		var detailErr error
		for _, ref := range refs {
			if seen[ref.pid] {
				continue
			}
			detail, commandErr := runBoundedDarwinOutput(
				ctx, "/bin/launchctl", []string{"print", "gui/" + uid + "/" + ref.label}, 1024*1024,
			)
			if commandErr != nil {
				if detailErr == nil {
					// 保留首个详细错误，供下方的部分发现诊断使用。
					detailErr = commandErr
				}
				continue
			}
			parsed := parseLaunchctlProcessList(string(detail))
			zeroBytes(detail)
			for _, process := range parsed {
				if process.pid != ref.pid || seen[process.pid] {
					continue
				}
				seen[process.pid] = true
				processes = append(processes, process)
			}
		}
		if len(processes) == 0 && len(refs) > 0 {
			if detailErr == nil {
				detailErr = errors.New("微信应用服务详情不可读")
			}
			return nil, "launchctl", &darwinProcessDiscoveryError{PS: err, Launchctl: detailErr}
		}
		return processes, "launchctl", nil
	}
	return nil, "ps_then_launchctl", &darwinProcessDiscoveryError{PS: err, Launchctl: launchErr}
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
					// 指令形态的 XOR 兜底在映像和堆区域同样有用，
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

func recordDarwinHookDiagnostics(diag *diagnostics, hook platformHookSnapshot) {
	diag.HookTargetFound += hook.TargetFound
	diag.HookInstalled = diag.HookInstalled || hook.Installed
	diag.HookTimeout = diag.HookTimeout || hook.TimedOut
	diag.HookCaptureCount += hook.Captures
	diag.DynamicHookUsed = diag.DynamicHookUsed || hook.Used
	diag.HookTriggerRequired = diag.HookTriggerRequired || hook.TriggerNeeded
	diag.HookRestartRequired = diag.HookRestartRequired || hook.RestartNeeded
	if hook.IdentityRejected {
		diag.StandardRouteEvidence = appendUniqueStrings(diag.StandardRouteEvidence, "hook_target_revalidation_failed")
	}
	routes := strings.Split(hook.RouteHistory, "\x00")
	if hook.RouteHistory == "" {
		routes = []string{hook.Route}
	}
	for _, route := range routes {
		if route == "" {
			continue
		}
		diag.RouteSelected = route
		diag.RoutesAttempted = appendUniqueStrings(diag.RoutesAttempted, route)
	}
}

type darwinAcquisitionPipeline struct {
	targets                 databaseTargets
	scanMedia               mediaEvidence
	options                 acquireOptions
	diag                    diagnostics
	processes               []darwinProcess
	evidence                darwinBinaryEvidence
	decision                darwinRouteDecision
	collector               *candidateCollector
	derivedMedia            *imageKeys
	needDatabaseScan        bool
	needMediaScan           bool
	persistentHook          bool
	deferFallback           bool
	dynamicHookAttempted    bool
	dynamicWaitForAttempted bool
	staticRouteAttempted    bool
}

func (pipeline *darwinAcquisitionPipeline) databaseSatisfied() bool {
	return !pipeline.needDatabaseScan || pipeline.collector.hasAllDatabaseCandidates()
}

func (pipeline *darwinAcquisitionPipeline) mediaSatisfied() bool {
	return !pipeline.needMediaScan || pipeline.collector.resolvedMedia(pipeline.scanMedia) != nil
}

func (pipeline *darwinAcquisitionPipeline) satisfied() bool {
	return pipeline.databaseSatisfied() && pipeline.mediaSatisfied()
}

func (pipeline *darwinAcquisitionPipeline) tryDynamicHook(waitFor bool) {
	if pipeline.persistentHook || !pipeline.needDatabaseScan || pipeline.options.budget.expired() || pipeline.databaseSatisfied() {
		return
	}
	if waitFor {
		if pipeline.dynamicWaitForAttempted {
			return
		}
		pipeline.dynamicWaitForAttempted = true
	} else {
		if pipeline.dynamicHookAttempted {
			return
		}
		pipeline.dynamicHookAttempted = true
	}
	if waitFor && len(pipeline.processes) == 0 {
		if !darwinPrelaunchHookEligible(pipeline.evidence) {
			return
		}
		recordDarwinHookDiagnostics(&pipeline.diag, captureDarwinHookMode(
			darwinProcess{}, pipeline.collector, pipeline.options.budget, true, pipeline.diag.SecurityPostureStatus,
		))
		return
	}
	for _, process := range pipeline.processes {
		if pipeline.options.budget.expired() || pipeline.databaseSatisfied() {
			break
		}
		processEvidence := darwinCollectBinaryEvidence(process)
		processDecision := evaluateDarwinRoute(processEvidence, darwinCompatibilityRegistry)
		if !darwinStandardRouteEligible(processDecision) {
			continue
		}
		isolated := newCandidateCollector(pipeline.targets, pipeline.scanMedia, pipeline.options.budget)
		hook := captureDarwinHookMode(
			process, isolated, pipeline.options.budget, waitFor, pipeline.diag.SecurityPostureStatus,
		)
		pipeline.collector.mergeValidatedFrom(isolated)
		isolated.clearSensitiveBuffers()
		recordDarwinHookDiagnostics(&pipeline.diag, hook)
	}
}

func (pipeline *darwinAcquisitionPipeline) runHookStage() {
	if pipeline.persistentHook {
		recordDarwinHookDiagnostics(&pipeline.diag, pipeline.options.platformSession.collect(pipeline.collector))
	}
	pipeline.deferFallback = pipeline.persistentHook && !pipeline.satisfied() &&
		pipeline.options.actionReceipt != "restart_wechat" && pipeline.options.actionReceipt != "relogin_wechat"
	if pipeline.deferFallback && !pipeline.diag.DynamicHookUsed {
		if pipeline.options.actionReceipt == "trigger_database" {
			pipeline.diag.HookRestartRequired = true
			pipeline.diag.HookTriggerRequired = false
		} else {
			pipeline.diag.HookTriggerRequired = true
		}
	}
	if pipeline.persistentHook {
		return
	}
	if len(pipeline.processes) == 0 {
		// Install before a fresh WeChat process initializes its database.
		pipeline.tryDynamicHook(true)
		pipeline.diag.StaticScanFallback = !pipeline.satisfied()
		return
	}
	if darwinStandardRouteEligible(pipeline.decision) {
		pipeline.tryDynamicHook(false)
		pipeline.tryDynamicHook(true)
		pipeline.diag.StaticScanFallback = !pipeline.satisfied()
	}
}

func (pipeline *darwinAcquisitionPipeline) refreshProcessStage() {
	if pipeline.deferFallback || len(pipeline.processes) != 0 {
		return
	}
	refreshed, method, err := darwinTargetProcesses()
	if err != nil {
		return
	}
	pipeline.processes = refreshed
	pipeline.diag.ProcessDiscoveryMethod = method
	pipeline.diag.ProcessCount = len(refreshed)
	if len(refreshed) == 0 {
		return
	}
	pipeline.evidence = darwinCollectBinaryEvidence(refreshed[0])
	pipeline.decision = applyDarwinRouteEvidence(&pipeline.diag, pipeline.evidence)
	pipeline.diag.VersionSupport = darwinVersionSupport(pipeline.diag.WeChatVersion)
}

func (pipeline *darwinAcquisitionPipeline) runStaticScanStage() {
	for _, process := range pipeline.processes {
		if pipeline.deferFallback || pipeline.satisfied() {
			break
		}
		processEvidence := darwinCollectBinaryEvidence(process)
		processDecision := evaluateDarwinRoute(processEvidence, darwinCompatibilityRegistry)
		if !darwinStandardRouteEligible(processDecision) {
			continue
		}
		if !pipeline.staticRouteAttempted {
			pipeline.evidence = processEvidence
			pipeline.decision = applyDarwinRouteEvidence(&pipeline.diag, processEvidence)
			pipeline.diag.VersionSupport = darwinVersionSupport(pipeline.diag.WeChatVersion)
		}
		pipeline.staticRouteAttempted = true
		if pipeline.diag.SecurityPostureStatus == "sip_disabled_verified" {
			route := darwinDynamicRouteID(processEvidence.ProcessArchitecture, pipeline.diag.SecurityPostureStatus)
			pipeline.diag.RouteSelected = route
			pipeline.diag.RoutesAttempted = appendUniqueStrings(pipeline.diag.RoutesAttempted, route)
		}
		if pipeline.diag.ScannedBytes >= darwinTotalScanMax || pipeline.options.budget.expired() {
			pipeline.diag.ScanLimited = true
			break
		}
		task, err := darwinTaskForPID(process.pid)
		if err != nil {
			pipeline.diag.AccessDeniedCount++
			continue
		}
		pipeline.diag.OpenedProcessCount++
		remaining := darwinTotalScanMax - pipeline.diag.ScannedBytes
		if remaining > darwinPerProcessScanMax {
			remaining = darwinPerProcessScanMax
		}
		isolated := newCandidateCollector(pipeline.targets, pipeline.scanMedia, pipeline.options.budget)
		scanned, limited := scanDarwinProcess(task, isolated, remaining, true, pipeline.options.budget)
		darwinCloseTask(task)
		if pipeline.needDatabaseScan && !isolated.hasAllDatabaseCandidates() {
			isolated.resolveDatabasePassphrase(pipeline.options.budget)
		}
		pipeline.collector.mergeValidatedFrom(isolated)
		isolated.clearSensitiveBuffers()
		pipeline.diag.ScannedBytes += scanned
		pipeline.diag.ScanLimited = pipeline.diag.ScanLimited || limited
	}
	if !pipeline.persistentHook && !pipeline.databaseSatisfied() {
		pipeline.tryDynamicHook(false)
	}
	if !pipeline.deferFallback && pipeline.staticRouteAttempted && !pipeline.satisfied() &&
		pipeline.diag.SecurityPostureStatus != "sip_disabled_verified" {
		pipeline.diag.StaticScanFallback = true
		pipeline.diag.RouteSelected = "darwin_static_fallback"
		pipeline.diag.RoutesAttempted = appendUniqueStrings(pipeline.diag.RoutesAttempted, pipeline.diag.RouteSelected)
	}
}

func (pipeline *darwinAcquisitionPipeline) finalizeProcessAccessStatus() {
	switch {
	case pipeline.diag.OpenedProcessCount > 0 && pipeline.diag.AccessDeniedCount > 0:
		pipeline.diag.ProcessAccessStatus = "partial"
	case pipeline.diag.HookInstalled && pipeline.diag.OpenedProcessCount == 0:
		pipeline.diag.ProcessAccessStatus = "dynamic_hook_opened"
	case pipeline.diag.OpenedProcessCount > 0 && pipeline.options.helperMode:
		pipeline.diag.ProcessAccessStatus = "helper_opened"
	case pipeline.diag.OpenedProcessCount > 0:
		pipeline.diag.ProcessAccessStatus = "direct_opened"
	case pipeline.diag.AccessDeniedCount > 0:
		pipeline.diag.ProcessAccessStatus = "denied"
		pipeline.diag.ProcessAccessError = darwinDeniedAccessError(
			pipeline.options.helperMode, pipeline.options.helperStatus, pipeline.diag.SecurityPostureStatus,
		)
	case pipeline.diag.ProcessCount == 0:
		pipeline.diag.ProcessAccessStatus = "wechat_not_running"
	case pipeline.options.budget.expired():
		pipeline.diag.ProcessAccessStatus = "deadline_exhausted"
	default:
		pipeline.diag.ProcessAccessStatus = "unavailable"
	}
}

func (pipeline *darwinAcquisitionPipeline) assemble() (response, diagnostics, error) {
	pipeline.finalizeProcessAccessStatus()
	if pipeline.needDatabaseScan && !pipeline.databaseSatisfied() {
		pipeline.collector.resolveDatabasePassphrase(pipeline.options.budget)
	}
	keys, ambiguous := pipeline.collector.databaseKeys(pipeline.targets)
	if pipeline.options.database && len(keys) == 0 && pipeline.options.actionReceipt == "restart_wechat" &&
		pipeline.diag.HookInstalled && !pipeline.diag.DynamicHookUsed {
		pipeline.diag.HookReloginRequired = true
		pipeline.diag.HookTriggerRequired = false
		pipeline.diag.HookRestartRequired = false
	} else if pipeline.options.database && len(keys) == 0 && pipeline.options.actionReceipt == "relogin_wechat" {
		pipeline.diag.HookTriggerRequired = false
		pipeline.diag.HookRestartRequired = false
		pipeline.diag.HookReloginRequired = false
		pipeline.diag.ProcessAccessError = "relogin_no_verified_candidate"
	}
	if pipeline.diag.HookReloginRequired && len(keys) == 0 {
		pipeline.diag.ProcessAccessError = "hook_relogin_required"
	} else if pipeline.diag.HookRestartRequired && len(keys) == 0 {
		pipeline.diag.ProcessAccessError = "hook_restart_required"
	} else if pipeline.diag.HookTriggerRequired && len(keys) == 0 {
		pipeline.diag.ProcessAccessError = "hook_trigger_required"
	} else if len(keys) > 0 {
		pipeline.diag.HookTriggerRequired = false
		pipeline.diag.HookRestartRequired = false
		pipeline.diag.HookReloginRequired = false
	}
	imageCandidate := pipeline.collector.applyScanDiagnostics(
		&pipeline.diag, keys, ambiguous, pipeline.derivedMedia, pipeline.scanMedia,
	)
	credential, err := pipeline.collector.databaseCredential(keys, pipeline.targets)
	if err != nil {
		return response{}, pipeline.diag, err
	}
	return response{
		DatabaseKeys: keys, DatabaseProfiles: pipeline.collector.profilesForKeys(keys),
		DatabaseCredential: credential, ImageKeys: imageCandidate,
	}, pipeline.diag, nil
}

func platformAcquire(targets databaseTargets, media mediaEvidence, options acquireOptions) (response, diagnostics, error) {
	helperStatus := options.helperStatus
	if options.helperMode {
		helperStatus = "used"
	}
	diag := newDiagnostics("darwin", requestedScopes(options.database, options.media))
	diag.HelperStatus = helperStatus
	diag.DatabaseCount = targets.count
	diag.V2SampleCount = len(media.v2Blocks)
	diag.XORDistinctCandidateCount = len(media.xorCandidates)
	if options.helperStatus == "untrusted" {
		diag.ProcessAccessStatus = "denied"
		diag.ProcessAccessError = "helper_untrusted"
		return response{}, diag, nil
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

	processes, discoveryMethod, err := darwinTargetProcesses()
	if err != nil {
		var discoveryErr *darwinProcessDiscoveryError
		if errors.As(err, &discoveryErr) {
			diag.ProcessAccessStatus = "process_list_unavailable"
			diag.ProcessAccessError = "process_list_unavailable"
			diag.ProcessDiscoveryMethod = discoveryMethod
			return response{}, diag, nil
		}
		return response{}, diag, err
	}
	diag.ProcessDiscoveryMethod = discoveryMethod
	diag.ProcessCount = len(processes)
	var evidenceProcess darwinProcess
	if len(processes) > 0 {
		evidenceProcess = processes[0]
	} else {
		// 全新初始化可能正好赶在微信进程切换的空档启动。4.1.x 的密钥只在数据库
		// 初始化时可见。这里只能读取待启动二进制身份；实际 slice 必须等进程出现后重检。
		evidenceProcess.command = darwinWeChatExecutable(darwinProcess{})
		evidenceProcess.name = filepath.Base(evidenceProcess.command)
	}
	evidence := darwinCollectBinaryEvidence(evidenceProcess)
	decision := applyDarwinRouteEvidence(&diag, evidence)
	diag.VersionSupport = darwinVersionSupport(diag.WeChatVersion)
	scanMedia := selectedMedia
	if !needMediaScan {
		scanMedia = mediaEvidence{xorCandidates: map[byte]int{}}
	}
	collector := newCandidateCollector(targets, scanMedia, options.budget)
	pipeline := &darwinAcquisitionPipeline{
		targets: targets, scanMedia: scanMedia, options: options, diag: diag,
		processes: processes, evidence: evidence, decision: decision, collector: collector,
		derivedMedia: derivedMedia, needDatabaseScan: needDatabaseScan, needMediaScan: needMediaScan,
		persistentHook: options.platformSession != nil,
	}
	defer pipeline.collector.clearSensitiveBuffers()
	pipeline.runHookStage()
	pipeline.refreshProcessStage()
	pipeline.runStaticScanStage()
	return pipeline.assemble()
}
