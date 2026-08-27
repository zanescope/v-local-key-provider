package windows

import (
	"errors"
	"time"

	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
)

// DriverRuntime 包含 Windows 采集 driver 所需且归进程持有的策略。原生进程访问隔离在
// NativeDriver 之后。
type DriverRuntime struct {
	Acquisition acquisitionmodel.Runtime
	Registry    []CompatibilityEntry
	Policy      EvaluationPolicy
	Native      NativeDriver
}

type Driver struct {
	runtime DriverRuntime
}

func cloneCompatibilityRegistry(source []CompatibilityEntry) []CompatibilityEntry {
	result := make([]CompatibilityEntry, len(source))
	for index, entry := range source {
		entry.ValidatedProfiles = append([]string(nil), entry.ValidatedProfiles...)
		entry.Recipe.Needle = append([]byte(nil), entry.Recipe.Needle...)
		entry.Recipe.PointerOffsets = append([]int64(nil), entry.Recipe.PointerOffsets...)
		entry.Recipe.XORMask = append([]byte(nil), entry.Recipe.XORMask...)
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

func newDiagnostics(database, media bool) diagnosticmodel.Diagnostics {
	diag := diagnosticmodel.New("windows", requestedScopes(database, media), "not_applicable")
	diag.ShadowRouteStatus = "not_applicable"
	diag.RoutePriority = []string{}
	diag.ProcessArchitecture = "unknown"
	diag.ProcessArchitectureStatus = ArchitectureUnavailable
	diag.BinaryFingerprintStatus = FingerprintUnavailable
	diag.BinarySigningStatus = SigningUnavailable
	diag.CompatibilityRegistryStatus = RegistryNotEvaluated
	diag.ConfigCipherRouteStatus = ConfigCipherNotEvaluated
	diag.WindowsRouteEvidence = []string{}
	diag.StandardRouteEvidence = []string{}
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

func chooseConfigStatus(current, next string) string {
	if ConfigStatusRank(next) > ConfigStatusRank(current) {
		return next
	}
	return current
}

type openedProcess struct {
	evidence ProcessEvidence
	decision RouteDecision
	handle   Handle
}

func (driver *Driver) Acquire(targets acquisitionmodel.Targets, media acquisitionmodel.MediaEvidence, request acquisitionmodel.PlatformRequest) (protocolmodel.Response, diagnosticmodel.Diagnostics, error) {
	diag := newDiagnostics(request.Database, request.Media)
	diag.DatabaseCount = targets.Count
	diag.V2SampleCount = len(media.V2Blocks)
	diag.XORDistinctCandidateCount = len(media.XORCandidates)
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
		return protocolmodel.Response{}, diag, nil
	}
	if !needDatabaseScan && derivedMedia != nil {
		diag.MediaCandidateMethod = "kvcomm_formula_v2_sample"
		return protocolmodel.Response{ImageKeys: derivedMedia}, diag, nil
	}
	if driver == nil || driver.runtime.Native == nil {
		return protocolmodel.Response{}, diag, errors.New("Windows process driver is unavailable")
	}
	scanMedia := selectedMedia
	if !needMediaScan {
		scanMedia = acquisitionmodel.MediaEvidence{XORCandidates: map[byte]int{}}
	}

	processes, err := driver.runtime.Native.ListProcesses()
	if err != nil {
		return protocolmodel.Response{}, diag, err
	}
	processes = OrderedProcesses(processes)
	diag.ProcessDiscoveryMethod = "toolhelp_snapshot"
	diag.ProcessCount = len(processes)
	evidence := make([]ProcessEvidence, 0, len(processes))
	for _, process := range processes {
		evidence = append(evidence, driver.runtime.Native.CollectEvidence(process))
	}
	evidence = driver.runtime.Native.BindEvidence(evidence, request.AccountDir, request.DBDir, request.Budget)
	evidence = OrderedProcessEvidence(evidence)
	for _, process := range evidence {
		switch process.Binding {
		case "target":
			diag.TargetBoundProcessCount++
		case "other":
			diag.OtherAccountProcessCount++
		default:
			diag.UnknownAccountProcessCount++
		}
	}
	switch {
	case diag.TargetBoundProcessCount > 0:
		diag.TargetBindingStatus = "path_verified"
		diag.SessionAccountStatus = "known_target"
	case diag.OtherAccountProcessCount > 0 && diag.UnknownAccountProcessCount == 0:
		diag.TargetBindingStatus = "mismatch"
		diag.SessionAccountStatus = "known_other"
	default:
		diag.TargetBindingStatus = "unknown"
		diag.SessionAccountStatus = "unknown"
	}

	opened := make([]openedProcess, 0, len(evidence))
	representative := -1
	registeredRepresentative := -1
	identityRejectedCount := 0
	architectureSet := map[string]bool{}
	for index, process := range evidence {
		if process.Binding == "other" {
			continue
		}
		diag.SelectedProcessCount++
		decision := EvaluateRoute(process.Binary, driver.runtime.Registry, driver.runtime.Policy)
		diag.WindowsRouteEvidence = appendUnique(diag.WindowsRouteEvidence, decision.Evidence...)
		if process.Binary.ProcessArchitectureStatus == ArchitectureVerified {
			architectureSet[process.Binary.ProcessArchitecture] = true
		}
		if representative < 0 {
			representative = index
		}
		if decision.CompatibilityRegistryStatus == RegistryRegisteredSupported && registeredRepresentative < 0 {
			registeredRepresentative = index
		}
		if process.InstanceID == "" {
			diag.WindowsRouteEvidence = appendUnique(diag.WindowsRouteEvidence, "process_instance_not_verified")
			diag.AccessDeniedCount++
			identityRejectedCount++
			continue
		}
		if !FallbackIdentityEligible(process.Binary, driver.runtime.Registry, driver.runtime.Policy) {
			diag.WindowsRouteEvidence = appendUnique(diag.WindowsRouteEvidence, "process_publisher_not_registry_anchored")
			diag.AccessDeniedCount++
			identityRejectedCount++
			continue
		}
		handle := driver.runtime.Native.OpenForScan(process.Process)
		if handle == 0 {
			diag.AccessDeniedCount++
			continue
		}
		revalidated := driver.runtime.Native.Revalidate(process.Process, handle)
		if revalidated.InstanceID == "" || revalidated.InstanceID != process.InstanceID {
			driver.runtime.Native.Close(handle)
			diag.WindowsRouteEvidence = appendUnique(diag.WindowsRouteEvidence, "process_instance_changed_before_scan")
			diag.AccessDeniedCount++
			identityRejectedCount++
			continue
		}
		revalidated.Binding = process.Binding
		decision = EvaluateRoute(revalidated.Binary, driver.runtime.Registry, driver.runtime.Policy)
		opened = append(opened, openedProcess{evidence: revalidated, decision: decision, handle: handle})
	}
	defer func() {
		for _, process := range opened {
			driver.runtime.Native.Close(process.handle)
		}
	}()
	diag.OpenedProcessCount = len(opened)
	if registeredRepresentative >= 0 {
		representative = registeredRepresentative
	}
	if representative >= 0 {
		selected := evidence[representative]
		decision := EvaluateRoute(selected.Binary, driver.runtime.Registry, driver.runtime.Policy)
		diag.WeChatVersion = selected.Binary.Version
		diag.WeChatBuild = selected.Binary.Build
		diag.ExecutableSHA256 = selected.Binary.ExecutableSHA256
		diag.BinaryFingerprintStatus = selected.Binary.BinaryFingerprintStatus
		diag.BinarySigningStatus = selected.Binary.BinarySigningStatus
		diag.BinarySignerSHA256 = selected.Binary.BinarySignerSHA256
		diag.BinaryProductIdentity = selected.Binary.ProductIdentity
		diag.ProcessArchitecture = selected.Binary.ProcessArchitecture
		diag.ProcessArchitectureStatus = selected.Binary.ProcessArchitectureStatus
		diag.ProcessTranslationStatus = "not_applicable"
		diag.CompatibilityRegistryStatus = decision.CompatibilityRegistryStatus
		diag.ConfigCipherRouteStatus = decision.ConfigCipherRouteStatus
	}
	if len(architectureSet) > 1 {
		if registeredRepresentative >= 0 {
			diag.WindowsRouteEvidence = appendUnique(diag.WindowsRouteEvidence, "multiple_process_architectures_observed")
		} else {
			diag.ProcessArchitecture = "mixed"
			diag.ProcessArchitectureStatus = ArchitectureVerified
		}
	}

	aggregate := acquisitionmodel.NewCollector(targets, scanMedia, driver.runtime.Acquisition, request.Budget)
	defer aggregate.ClearSensitiveBuffers()
	configStarted := time.Now()
	configAttempted := false
	for _, process := range opened {
		if request.Budget.Expired() || !needDatabaseScan || diag.ScannedBytes >= TotalScanLimit {
			if diag.ScannedBytes >= TotalScanLimit {
				diag.ScanLimited = true
			}
			break
		}
		keys, _ := aggregate.DatabaseKeys(targets)
		missing := acquisitionmodel.MissingTargets(targets, keys)
		if missing.Count == 0 {
			break
		}
		if process.decision.ConfigCipherRouteStatus != ConfigCipherEligible || process.decision.EntryIndex < 0 ||
			process.decision.EntryIndex >= len(driver.runtime.Registry) {
			continue
		}
		entry := driver.runtime.Registry[process.decision.EntryIndex]
		eligibleTargets := acquisitionmodel.TargetsForProfiles(missing, entry.ValidatedProfiles)
		if eligibleTargets.Count == 0 {
			diag.WindowsRouteEvidence = appendUnique(diag.WindowsRouteEvidence, "registered_profiles_do_not_cover_missing_catalog")
			continue
		}
		configAttempted = true
		diag.PerProcessCollectorCount++
		configBudget := request.Budget.CappedFor(10 * time.Second)
		isolated := acquisitionmodel.NewCollector(eligibleTargets, acquisitionmodel.MediaEvidence{}, driver.runtime.Acquisition, configBudget)
		isolated.SetProcessInstanceID(process.evidence.InstanceID)
		attempt := driver.runtime.Native.ScanConfig(
			process.handle, process.evidence, entry.Recipe, isolated, TotalScanLimit-diag.ScannedBytes, configBudget,
		)
		diag.ConfigCipherStructureCount += attempt.StructureCount
		diag.ConfigCipherInvalidCount += attempt.InvalidStructures
		diag.ConfigCipherCandidateCount += attempt.CandidateCount
		diag.ConfigCipherVerifiedCount += attempt.VerifiedCandidates
		if attempt.VerifiedCandidates > 0 {
			diag.CandidateSources = appendUnique(diag.CandidateSources, "windows_config_cipher")
		}
		diag.ScannedBytes += attempt.ScannedBytes
		aggregate.MergeValidatedFrom(isolated)
		attemptStatus := attempt.Status
		if attemptStatus == ConfigCipherSucceeded {
			keysAfterAttempt, _ := aggregate.DatabaseKeys(targets)
			if acquisitionmodel.MissingTargets(targets, keysAfterAttempt).Count > 0 {
				attemptStatus = ConfigCipherPartial
			}
		}
		diag.ConfigCipherRouteStatus = chooseConfigStatus(diag.ConfigCipherRouteStatus, attemptStatus)
		isolated.ClearSensitiveBuffers()
	}
	diag.PhaseTimingsMS = map[string]int64{"config_cipher": time.Since(configStarted).Milliseconds()}
	if configAttempted {
		diag.RouteSelected = "windows_config_cipher"
		diag.RoutesAttempted = appendUnique(diag.RoutesAttempted, "windows_config_cipher")
	}

	fallbackStarted := time.Now()
	fallbackAttempted := false
	for _, stage := range FallbackStages() {
		if request.Budget.Expired() || diag.ScannedBytes >= TotalScanLimit {
			diag.ScanLimited = true
			break
		}
		for _, process := range opened {
			if request.Budget.Expired() || diag.ScannedBytes >= TotalScanLimit {
				diag.ScanLimited = true
				break
			}
			processBudget := request.Budget.CappedFor(stage.Window)
			keys, _ := aggregate.DatabaseKeys(targets)
			missing := acquisitionmodel.MissingTargets(targets, keys)
			mediaResolved := !needMediaScan || derivedMedia != nil || aggregate.ResolvedMedia(scanMedia) != nil
			if missing.Count == 0 && mediaResolved {
				break
			}
			if missing.Count == 0 && (stage.Name == "structured_key_object" || stage.Name == "salt_neighborhood") {
				continue
			}
			stageMedia := scanMedia
			if mediaResolved {
				stageMedia = acquisitionmodel.MediaEvidence{XORCandidates: map[byte]int{}}
			}
			isolated := acquisitionmodel.NewCollector(missing, stageMedia, driver.runtime.Acquisition, processBudget)
			isolated.SetProcessInstanceID(process.evidence.InstanceID)
			diag.PerProcessCollectorCount++
			limit := stage.PerProcessLimit
			if remaining := TotalScanLimit - diag.ScannedBytes; limit > remaining {
				limit = remaining
			}
			scanned, limited := driver.runtime.Native.ScanStage(process.handle, isolated, limit, stage.Name, processBudget)
			if missing.Count > 0 && !isolated.HasAllDatabaseCandidates() {
				isolated.ResolveDatabasePassphrase(processBudget)
			}
			diag.FallbackCandidateCount += isolated.CandidateObservationCount()
			diag.FallbackStageCounts[stage.Name]++
			diag.ScannedBytes += scanned
			diag.ScanLimited = diag.ScanLimited || limited
			aggregate.MergeValidatedFrom(isolated)
			isolated.ClearSensitiveBuffers()
			fallbackAttempted = true
		}
		keys, _ := aggregate.DatabaseKeys(targets)
		if acquisitionmodel.MissingTargets(targets, keys).Count == 0 &&
			(!needMediaScan || derivedMedia != nil || aggregate.ResolvedMedia(scanMedia) != nil) {
			break
		}
	}
	diag.PhaseTimingsMS["memory_scan"] = time.Since(fallbackStarted).Milliseconds()
	if fallbackAttempted {
		diag.StaticScanFallback = true
		diag.RouteSelected = "windows_memory_fallback"
		diag.RoutesAttempted = appendUnique(diag.RoutesAttempted, "windows_memory_fallback")
	}

	keys, ambiguous := aggregate.DatabaseKeys(targets)
	switch {
	case diag.TargetBindingStatus == "mismatch":
		diag.ProcessAccessStatus = "not_attempted_account_mismatch"
	case diag.OpenedProcessCount > 0 && diag.AccessDeniedCount > 0:
		diag.ProcessAccessStatus = "partial"
	case diag.OpenedProcessCount > 0:
		diag.ProcessAccessStatus = "direct_opened"
	case diag.AccessDeniedCount > 0:
		diag.ProcessAccessStatus = "denied"
		if identityRejectedCount > 0 {
			diag.ProcessAccessError = "process_identity_untrusted"
		} else {
			diag.ProcessAccessError = "process_open_denied"
		}
	case diag.ProcessCount == 0:
		diag.ProcessAccessStatus = "wechat_not_running"
	case request.Budget.Expired():
		diag.ProcessAccessStatus = "deadline_exhausted"
	default:
		diag.ProcessAccessStatus = "unavailable"
	}
	imageCandidate := aggregate.ApplyScanDiagnostics(&diag, keys, ambiguous, derivedMedia, scanMedia)
	credential, err := aggregate.DatabaseCredential(keys, targets)
	if err != nil {
		return protocolmodel.Response{}, diag, err
	}
	return protocolmodel.Response{
		DatabaseKeys: keys, DatabaseProfiles: aggregate.ProfilesForKeys(keys),
		DatabaseCredential: credential, ImageKeys: imageCandidate,
	}, diag, nil
}
