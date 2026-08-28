package darwin

import (
	"errors"
	"strings"

	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
	platformmodel "github.com/zanescope/v-local-key-provider/internal/platform"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
)

type DriverRuntime struct {
	Acquisition     acquisitionmodel.Runtime
	Registry        []CompatibilityEntry
	Policy          EvaluationPolicy
	Native          NativeDriver
	CaptureHook     CaptureHookFunc
	SecurityPosture func() string
}

type Driver struct {
	runtime DriverRuntime
}

func cloneCompatibilityRegistry(source []CompatibilityEntry) []CompatibilityEntry {
	result := make([]CompatibilityEntry, len(source))
	for index, entry := range source {
		entry.ValidatedCipherProfiles = append([]string(nil), entry.ValidatedCipherProfiles...)
		result[index] = entry
	}
	return result
}

func NewDriver(runtime DriverRuntime) *Driver {
	runtime.Registry = cloneCompatibilityRegistry(runtime.Registry)
	return &Driver{runtime: runtime}
}

func requestedScopes(database, media bool) []string {
	result := make([]string, 0, 2)
	if database {
		result = append(result, "database")
	}
	if media {
		result = append(result, "media")
	}
	return result
}

func (driver *Driver) newDiagnostics(database, media bool) diagnosticmodel.Diagnostics {
	securityPosture := ""
	if driver != nil && driver.runtime.SecurityPosture != nil {
		securityPosture = driver.runtime.SecurityPosture()
	}
	diag := diagnosticmodel.New("darwin", requestedScopes(database, media), securityPosture)
	diag.ShadowRouteStatus = "unavailable_in_build"
	diag.RoutePriority = []string{"standard", "shadow", "sip_disabled"}
	diag.BinaryFingerprintStatus = FingerprintNotEvaluated
	diag.BinarySigningStatus = SigningNotEvaluated
	diag.ProcessArchitecture = "unknown"
	diag.ProcessArchitectureStatus = ArchitectureNotEvaluated
	diag.ProcessTranslationStatus = "not_evaluated"
	diag.CompatibilityRegistryStatus = RegistryNotEvaluated
	diag.StandardRouteStatus = StandardNotEvaluated
	diag.StandardRouteEvidence = []string{}
	diag.ConfigCipherRouteStatus = "not_applicable"
	diag.WindowsRouteEvidence = []string{}
	return diag
}

func appendUnique(values []string, additions ...string) []string {
	seen := make(map[string]bool, len(values)+len(additions))
	for _, value := range values {
		seen[value] = true
	}
	for _, value := range additions {
		if value != "" && !seen[value] {
			seen[value] = true
			values = append(values, value)
		}
	}
	return values
}

func recordHookDiagnostics(diag *diagnosticmodel.Diagnostics, hook platformmodel.HookSnapshot) {
	diag.HookTargetFound += hook.TargetFound
	diag.HookInstalled = diag.HookInstalled || hook.Installed
	diag.HookTimeout = diag.HookTimeout || hook.TimedOut
	diag.HookCaptureCount += hook.Captures
	diag.DynamicHookUsed = diag.DynamicHookUsed || hook.Used
	diag.HookTriggerRequired = diag.HookTriggerRequired || hook.TriggerNeeded
	diag.HookRestartRequired = diag.HookRestartRequired || hook.RestartNeeded
	if hook.IdentityRejected {
		diag.StandardRouteEvidence = appendUnique(diag.StandardRouteEvidence, "hook_target_revalidation_failed")
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
		diag.RoutesAttempted = appendUnique(diag.RoutesAttempted, route)
	}
}

func (driver *Driver) applyRouteEvidence(diag *diagnosticmodel.Diagnostics, evidence BinaryEvidence) RouteDecision {
	decision := EvaluateRoute(evidence, driver.runtime.Registry, driver.runtime.Policy)
	diag.WeChatVersion = evidence.Version
	diag.WeChatBuild = evidence.Build
	diag.ExecutableSHA256 = evidence.ExecutableSHA256
	diag.BinaryFingerprintStatus = evidence.BinaryFingerprintStatus
	diag.BinarySigningStatus = evidence.BinarySigningStatus
	diag.SigningTeamID = evidence.SigningTeamID
	diag.DesignatedRequirementSHA256 = evidence.DesignatedRequirementSHA256
	diag.ProcessArchitecture = evidence.ProcessArchitecture
	diag.ProcessArchitectureStatus = evidence.ProcessArchitectureStatus
	diag.ProcessTranslationStatus = evidence.ProcessTranslationStatus
	diag.MacOSVersion = evidence.MacOSVersion
	diag.CompatibilityRegistryStatus = decision.CompatibilityRegistryStatus
	diag.StandardRouteStatus = decision.StandardRouteStatus
	diag.StandardRouteEvidence = append([]string(nil), decision.Evidence...)
	return decision
}

func (driver *Driver) standardRouteEligible(decision RouteDecision) bool {
	return StandardRouteEligible(decision, !driver.runtime.Policy.ReleaseBuild)
}

type acquisitionPipeline struct {
	driver                  *Driver
	targets                 acquisitionmodel.Targets
	scanMedia               acquisitionmodel.MediaEvidence
	request                 acquisitionmodel.PlatformRequest
	diag                    diagnosticmodel.Diagnostics
	processes               []Process
	evidence                BinaryEvidence
	decision                RouteDecision
	collector               *acquisitionmodel.Collector
	derivedMedia            *protocolmodel.ImageKeys
	needDatabaseScan        bool
	needMediaScan           bool
	persistentHook          bool
	deferFallback           bool
	dynamicHookAttempted    bool
	dynamicWaitForAttempted bool
	staticRouteAttempted    bool
}

func (pipeline *acquisitionPipeline) databaseSatisfied() bool {
	return !pipeline.needDatabaseScan || pipeline.collector.HasAllDatabaseCandidates()
}

func (pipeline *acquisitionPipeline) mediaSatisfied() bool {
	return !pipeline.needMediaScan || pipeline.collector.ResolvedMedia(pipeline.scanMedia) != nil
}

func (pipeline *acquisitionPipeline) satisfied() bool {
	return pipeline.databaseSatisfied() && pipeline.mediaSatisfied()
}

func (pipeline *acquisitionPipeline) tryDynamicHook(waitFor bool) {
	if pipeline.driver.runtime.CaptureHook == nil || pipeline.persistentHook || !pipeline.needDatabaseScan ||
		pipeline.request.Budget.Expired() || pipeline.databaseSatisfied() {
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
		if !PrelaunchHookEligible(pipeline.evidence) {
			return
		}
		process := pipeline.driver.runtime.Native.PrelaunchProcess()
		recordHookDiagnostics(&pipeline.diag, pipeline.driver.runtime.CaptureHook(
			process, pipeline.collector, pipeline.request.Budget, true, pipeline.diag.SecurityPostureStatus,
		))
		return
	}
	for _, process := range pipeline.processes {
		if pipeline.request.Budget.Expired() || pipeline.databaseSatisfied() {
			break
		}
		processEvidence := pipeline.driver.runtime.Native.CollectEvidence(process)
		processDecision := EvaluateRoute(processEvidence, pipeline.driver.runtime.Registry, pipeline.driver.runtime.Policy)
		if !pipeline.driver.standardRouteEligible(processDecision) {
			continue
		}
		isolated := acquisitionmodel.NewCollector(
			pipeline.targets, pipeline.scanMedia, pipeline.driver.runtime.Acquisition, pipeline.request.Budget,
		)
		hook := pipeline.driver.runtime.CaptureHook(
			process, isolated, pipeline.request.Budget, waitFor, pipeline.diag.SecurityPostureStatus,
		)
		pipeline.collector.MergeValidatedFrom(isolated)
		isolated.ClearSensitiveBuffers()
		recordHookDiagnostics(&pipeline.diag, hook)
	}
}

func (pipeline *acquisitionPipeline) runHookStage() {
	if pipeline.persistentHook {
		recordHookDiagnostics(&pipeline.diag, pipeline.request.PlatformSession.Collect(pipeline.collector))
	}
	pipeline.deferFallback = pipeline.persistentHook && !pipeline.satisfied() &&
		pipeline.request.ActionReceipt != "restart_wechat" && pipeline.request.ActionReceipt != "relogin_wechat"
	if pipeline.deferFallback && !pipeline.diag.DynamicHookUsed {
		if pipeline.request.ActionReceipt == "trigger_database" {
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
		pipeline.tryDynamicHook(true)
		pipeline.diag.StaticScanFallback = !pipeline.satisfied()
		return
	}
	if pipeline.driver.standardRouteEligible(pipeline.decision) {
		pipeline.tryDynamicHook(false)
		pipeline.tryDynamicHook(true)
		pipeline.diag.StaticScanFallback = !pipeline.satisfied()
	}
}

func (pipeline *acquisitionPipeline) refreshProcessStage() {
	if pipeline.deferFallback || len(pipeline.processes) != 0 {
		return
	}
	refreshed, method, err := pipeline.driver.runtime.Native.ListProcesses()
	if err != nil {
		return
	}
	pipeline.processes = refreshed
	pipeline.diag.ProcessDiscoveryMethod = method
	pipeline.diag.ProcessCount = len(refreshed)
	if len(refreshed) == 0 {
		return
	}
	pipeline.evidence = pipeline.driver.runtime.Native.CollectEvidence(refreshed[0])
	pipeline.decision = pipeline.driver.applyRouteEvidence(&pipeline.diag, pipeline.evidence)
	pipeline.diag.VersionSupport = VersionSupport(pipeline.diag.WeChatVersion)
}

func (pipeline *acquisitionPipeline) runStaticScanStage() {
	for _, process := range pipeline.processes {
		if pipeline.deferFallback || pipeline.satisfied() {
			break
		}
		processEvidence := pipeline.driver.runtime.Native.CollectEvidence(process)
		processDecision := EvaluateRoute(processEvidence, pipeline.driver.runtime.Registry, pipeline.driver.runtime.Policy)
		if !pipeline.driver.standardRouteEligible(processDecision) {
			continue
		}
		if !pipeline.staticRouteAttempted {
			pipeline.evidence = processEvidence
			pipeline.decision = pipeline.driver.applyRouteEvidence(&pipeline.diag, processEvidence)
			pipeline.diag.VersionSupport = VersionSupport(pipeline.diag.WeChatVersion)
		}
		pipeline.staticRouteAttempted = true
		if pipeline.diag.SecurityPostureStatus == "sip_disabled_verified" {
			route := DynamicRouteID(processEvidence.ProcessArchitecture, pipeline.diag.SecurityPostureStatus)
			pipeline.diag.RouteSelected = route
			pipeline.diag.RoutesAttempted = appendUnique(pipeline.diag.RoutesAttempted, route)
		}
		if pipeline.diag.ScannedBytes >= TotalScanMax || pipeline.request.Budget.Expired() {
			pipeline.diag.ScanLimited = true
			break
		}
		remaining := TotalScanMax - pipeline.diag.ScannedBytes
		if remaining > PerProcessScanMax {
			remaining = PerProcessScanMax
		}
		isolated := acquisitionmodel.NewCollector(
			pipeline.targets, pipeline.scanMedia, pipeline.driver.runtime.Acquisition, pipeline.request.Budget,
		)
		result := pipeline.driver.runtime.Native.ScanProcess(process, isolated, remaining, pipeline.request.Budget)
		if !result.Opened {
			isolated.ClearSensitiveBuffers()
			pipeline.diag.AccessDeniedCount++
			continue
		}
		pipeline.diag.OpenedProcessCount++
		if pipeline.needDatabaseScan && !isolated.HasAllDatabaseCandidates() {
			isolated.ResolveDatabasePassphrase(pipeline.request.Budget)
		}
		pipeline.collector.MergeValidatedFrom(isolated)
		isolated.ClearSensitiveBuffers()
		pipeline.diag.ScannedBytes += result.Scanned
		pipeline.diag.ScanLimited = pipeline.diag.ScanLimited || result.Limited
	}
	if !pipeline.persistentHook && !pipeline.databaseSatisfied() {
		pipeline.tryDynamicHook(false)
	}
	if !pipeline.deferFallback && pipeline.staticRouteAttempted && !pipeline.satisfied() &&
		pipeline.diag.SecurityPostureStatus != "sip_disabled_verified" {
		pipeline.diag.StaticScanFallback = true
		pipeline.diag.RouteSelected = "darwin_static_fallback"
		pipeline.diag.RoutesAttempted = appendUnique(pipeline.diag.RoutesAttempted, pipeline.diag.RouteSelected)
	}
}

func (pipeline *acquisitionPipeline) finalizeProcessAccessStatus() {
	switch {
	case pipeline.diag.OpenedProcessCount > 0 && pipeline.diag.AccessDeniedCount > 0:
		pipeline.diag.ProcessAccessStatus = "partial"
	case pipeline.diag.HookInstalled && pipeline.diag.OpenedProcessCount == 0:
		pipeline.diag.ProcessAccessStatus = "dynamic_hook_opened"
	case pipeline.diag.OpenedProcessCount > 0 && pipeline.request.HelperMode:
		pipeline.diag.ProcessAccessStatus = "helper_opened"
	case pipeline.diag.OpenedProcessCount > 0:
		pipeline.diag.ProcessAccessStatus = "direct_opened"
	case pipeline.diag.AccessDeniedCount > 0:
		pipeline.diag.ProcessAccessStatus = "denied"
		pipeline.diag.ProcessAccessError = DeniedAccessError(
			pipeline.request.HelperMode, pipeline.request.HelperStatus, pipeline.diag.SecurityPostureStatus,
		)
	case pipeline.diag.ProcessCount == 0:
		pipeline.diag.ProcessAccessStatus = "wechat_not_running"
	case pipeline.request.Budget.Expired():
		pipeline.diag.ProcessAccessStatus = "deadline_exhausted"
	default:
		pipeline.diag.ProcessAccessStatus = "unavailable"
	}
}

func (pipeline *acquisitionPipeline) assemble() (protocolmodel.Response, diagnosticmodel.Diagnostics, error) {
	pipeline.finalizeProcessAccessStatus()
	if pipeline.needDatabaseScan && !pipeline.databaseSatisfied() {
		pipeline.collector.ResolveDatabasePassphrase(pipeline.request.Budget)
	}
	keys, ambiguous := pipeline.collector.DatabaseKeys(pipeline.targets)
	if pipeline.request.Database && len(keys) == 0 && pipeline.request.ActionReceipt == "restart_wechat" &&
		pipeline.diag.HookInstalled && !pipeline.diag.DynamicHookUsed {
		pipeline.diag.HookReloginRequired = true
		pipeline.diag.HookTriggerRequired = false
		pipeline.diag.HookRestartRequired = false
	} else if pipeline.request.Database && len(keys) == 0 && pipeline.request.ActionReceipt == "relogin_wechat" {
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
	imageCandidate := pipeline.collector.ApplyScanDiagnostics(
		&pipeline.diag, keys, ambiguous, pipeline.derivedMedia, pipeline.scanMedia,
	)
	credential, err := pipeline.collector.DatabaseCredential(keys, pipeline.targets)
	if err != nil {
		return protocolmodel.Response{}, pipeline.diag, err
	}
	return protocolmodel.Response{
		DatabaseKeys: keys, DatabaseProfiles: pipeline.collector.ProfilesForKeys(keys),
		DatabaseCredential: credential, ImageKeys: imageCandidate,
	}, pipeline.diag, nil
}

func (driver *Driver) Acquire(
	targets acquisitionmodel.Targets,
	media acquisitionmodel.MediaEvidence,
	request acquisitionmodel.PlatformRequest,
) (protocolmodel.Response, diagnosticmodel.Diagnostics, error) {
	diag := driver.newDiagnostics(request.Database, request.Media)
	helperStatus := request.HelperStatus
	if request.HelperMode {
		helperStatus = "used"
	}
	diag.HelperStatus = helperStatus
	diag.DatabaseCount = targets.Count
	diag.V2SampleCount = len(media.V2Blocks)
	diag.XORDistinctCandidateCount = len(media.XORCandidates)
	if request.HelperStatus == "untrusted" {
		diag.ProcessAccessStatus = "denied"
		diag.ProcessAccessError = "helper_untrusted"
		return protocolmodel.Response{}, diag, nil
	}
	for _, count := range media.XORCandidates {
		diag.XORSampleCount += count
	}
	selectedMedia, xorResolved, leading, second := acquisitionmodel.SelectDominantXOR(media)
	diag.XORLeadingSampleCount = leading
	diag.XORSecondSampleCount = second
	derivedMedia, codeCandidates, verifiedCodes := acquisitionmodel.ResolveKVCommMedia(request.AccountDir, selectedMedia)
	diag.KVCommCodeCandidateCount = codeCandidates
	diag.KVCommVerifiedCandidateCount = verifiedCodes
	needDatabaseScan := request.Database && len(targets.BySalt) > 0
	needMediaScan := request.Media && derivedMedia == nil && len(media.V2Blocks) > 0 && xorResolved
	if !needDatabaseScan && !needMediaScan && derivedMedia == nil {
		diag.ProcessAccessStatus = "not_needed"
		return protocolmodel.Response{}, diag, nil
	}
	if !needDatabaseScan && derivedMedia != nil {
		diag.ProcessAccessStatus = "not_needed"
		diag.MediaCandidateMethod = "kvcomm_formula_v2_sample"
		return protocolmodel.Response{ImageKeys: derivedMedia}, diag, nil
	}
	if request.Budget.Expired() {
		diag.ProcessAccessStatus = "deadline_exhausted"
		return protocolmodel.Response{}, diag, nil
	}
	if driver == nil || driver.runtime.Native == nil {
		return protocolmodel.Response{}, diag, errors.New("Darwin process driver is unavailable")
	}

	processes, discoveryMethod, err := driver.runtime.Native.ListProcesses()
	if err != nil {
		var discoveryErr *ProcessDiscoveryError
		if errors.As(err, &discoveryErr) {
			diag.ProcessAccessStatus = "process_list_unavailable"
			diag.ProcessAccessError = "process_list_unavailable"
			diag.ProcessDiscoveryMethod = discoveryMethod
			return protocolmodel.Response{}, diag, nil
		}
		return protocolmodel.Response{}, diag, err
	}
	diag.ProcessDiscoveryMethod = discoveryMethod
	diag.ProcessCount = len(processes)
	evidenceProcess := driver.runtime.Native.PrelaunchProcess()
	if len(processes) > 0 {
		evidenceProcess = processes[0]
	}
	evidence := driver.runtime.Native.CollectEvidence(evidenceProcess)
	decision := driver.applyRouteEvidence(&diag, evidence)
	diag.VersionSupport = VersionSupport(diag.WeChatVersion)
	scanMedia := selectedMedia
	if !needMediaScan {
		scanMedia = acquisitionmodel.MediaEvidence{XORCandidates: map[byte]int{}}
	}
	collector := acquisitionmodel.NewCollector(targets, scanMedia, driver.runtime.Acquisition, request.Budget)
	pipeline := &acquisitionPipeline{
		driver: driver, targets: targets, scanMedia: scanMedia, request: request, diag: diag,
		processes: processes, evidence: evidence, decision: decision, collector: collector,
		derivedMedia: derivedMedia, needDatabaseScan: needDatabaseScan, needMediaScan: needMediaScan,
		persistentHook: request.PlatformSession != nil,
	}
	defer pipeline.collector.ClearSensitiveBuffers()
	pipeline.runHookStage()
	pipeline.refreshProcessStage()
	pipeline.runStaticScanStage()
	return pipeline.assemble()
}
