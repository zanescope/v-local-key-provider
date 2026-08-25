//go:build windows

package provider

import (
	"syscall"
	"time"
)

func windowsTargetsForProfiles(targets databaseTargets, profiles []string) databaseTargets {
	allowedProfiles := map[string]bool{}
	for _, profile := range profiles {
		allowedProfiles[profile] = true
	}
	allowedPaths := map[string]bool{}
	pages := make([]databasePage, 0, len(targets.pages))
	for _, page := range targets.pages {
		if page.profileID == "" && len(allowedProfiles) > 0 || allowedProfiles[page.profileID] {
			allowedPaths[page.path] = true
			pages = append(pages, page)
		}
	}
	subset := databaseCatalog{CatalogID: targets.catalog.CatalogID, DiscoveryErrors: append([]string(nil), targets.catalog.DiscoveryErrors...)}
	for _, database := range targets.catalog.Databases {
		if allowedPaths[database.RelativePath] {
			subset.Databases = append(subset.Databases, database)
		}
	}
	return targetsFromCatalog(subset, pages)
}

func chooseWindowsConfigStatus(current, next string) string {
	if windowsConfigStatusRank(next) > windowsConfigStatusRank(current) {
		return next
	}
	return current
}

func platformAcquire(targets databaseTargets, media mediaEvidence, options acquireOptions) (response, diagnostics, error) {
	diag := newDiagnostics("windows", requestedScopes(options.database, options.media))
	diag.DatabaseCount = targets.count
	diag.V2SampleCount = len(media.v2Blocks)
	diag.XORDistinctCandidateCount = len(media.xorCandidates)
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
		return response{}, diag, nil
	}
	if !needDatabaseScan && derivedMedia != nil {
		diag.MediaCandidateMethod = "kvcomm_formula_v2_sample"
		return response{ImageKeys: derivedMedia}, diag, nil
	}
	scanMedia := selectedMedia
	if !needMediaScan {
		scanMedia = mediaEvidence{xorCandidates: map[byte]int{}}
	}

	processes, err := targetProcesses()
	if err != nil {
		return response{}, diag, err
	}
	processes = orderedWindowsTargetProcesses(processes)
	diag.ProcessDiscoveryMethod = "toolhelp_snapshot"
	diag.ProcessCount = len(processes)
	evidence := make([]windowsProcessEvidence, 0, len(processes))
	for _, process := range processes {
		evidence = append(evidence, windowsCollectProcessEvidence(process))
	}
	evidence = windowsBindProcessEvidence(evidence, options.accountDir, options.dbDir, options.budget)
	evidence = orderedWindowsProcessEvidence(evidence)
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

	type openWindowsProcess struct {
		evidence windowsProcessEvidence
		decision windowsRouteDecision
		handle   syscall.Handle
	}
	opened := make([]openWindowsProcess, 0, len(evidence))
	representative := -1
	registeredRepresentative := -1
	identityRejectedCount := 0
	architectureSet := map[string]bool{}
	for index, process := range evidence {
		if process.Binding == "other" {
			continue
		}
		diag.SelectedProcessCount++
		decision := evaluateWindowsRoute(process.Binary, windowsCompatibilityRegistry)
		for _, item := range decision.Evidence {
			diag.WindowsRouteEvidence = appendUniqueStrings(diag.WindowsRouteEvidence, item)
		}
		if process.Binary.ProcessArchitectureStatus == windowsArchitectureVerified {
			architectureSet[process.Binary.ProcessArchitecture] = true
		}
		if representative < 0 {
			representative = index
		}
		if decision.CompatibilityRegistryStatus == windowsRegistryRegisteredSupported && registeredRepresentative < 0 {
			registeredRepresentative = index
		}
		if process.InstanceID == "" {
			diag.WindowsRouteEvidence = appendUniqueStrings(diag.WindowsRouteEvidence, "process_instance_not_verified")
			diag.AccessDeniedCount++
			identityRejectedCount++
			continue
		}
		if !windowsFallbackIdentityEligible(process.Binary, windowsCompatibilityRegistry) {
			// WinVerifyTrust by itself does not authorize memory access. The signed
			// product metadata and signer must be anchored by live registry evidence.
			diag.WindowsRouteEvidence = appendUniqueStrings(diag.WindowsRouteEvidence, "process_publisher_not_registry_anchored")
			diag.AccessDeniedCount++
			identityRejectedCount++
			continue
		}
		handleValue, _, _ := procOpenProcess.Call(processVMRead|processQueryInformation, 0, uintptr(process.Process.pid))
		if handleValue == 0 {
			diag.AccessDeniedCount++
			continue
		}
		handle := syscall.Handle(handleValue)
		revalidated := windowsCollectProcessEvidenceFromHandle(process.Process, handle)
		if revalidated.InstanceID == "" || revalidated.InstanceID != process.InstanceID {
			closeHandle(handle)
			diag.WindowsRouteEvidence = appendUniqueStrings(diag.WindowsRouteEvidence, "process_instance_changed_before_scan")
			diag.AccessDeniedCount++
			identityRejectedCount++
			continue
		}
		revalidated.Binding = process.Binding
		decision = evaluateWindowsRoute(revalidated.Binary, windowsCompatibilityRegistry)
		opened = append(opened, openWindowsProcess{evidence: revalidated, decision: decision, handle: handle})
	}
	defer func() {
		for _, process := range opened {
			closeHandle(process.handle)
		}
	}()
	diag.OpenedProcessCount = len(opened)
	if registeredRepresentative >= 0 {
		representative = registeredRepresentative
	}
	if representative >= 0 {
		selected := evidence[representative]
		decision := evaluateWindowsRoute(selected.Binary, windowsCompatibilityRegistry)
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
			// Keep the registered representative's exact ABI in the fixed-layout
			// evidence tuple; "mixed" is not itself a registry architecture.
			diag.WindowsRouteEvidence = appendUniqueStrings(diag.WindowsRouteEvidence, "multiple_process_architectures_observed")
		} else {
			diag.ProcessArchitecture = "mixed"
			diag.ProcessArchitectureStatus = windowsArchitectureVerified
		}
	}

	aggregate := newCandidateCollector(targets, scanMedia, options.budget)
	defer aggregate.clearSensitiveBuffers()
	configStarted := time.Now()
	configAttempted := false
	for _, process := range opened {
		if options.budget.expired() || !needDatabaseScan || diag.ScannedBytes >= totalScanLimit {
			if diag.ScannedBytes >= totalScanLimit {
				diag.ScanLimited = true
			}
			break
		}
		keys, _ := aggregate.databaseKeys(targets)
		missing := missingOnlyTargets(targets, keys)
		if missing.count == 0 {
			break
		}
		if process.decision.ConfigCipherRouteStatus != windowsConfigCipherEligible || process.decision.EntryIndex < 0 ||
			process.decision.EntryIndex >= len(windowsCompatibilityRegistry) {
			continue
		}
		entry := windowsCompatibilityRegistry[process.decision.EntryIndex]
		eligibleTargets := windowsTargetsForProfiles(missing, entry.ValidatedProfiles)
		if eligibleTargets.count == 0 {
			diag.WindowsRouteEvidence = appendUniqueStrings(diag.WindowsRouteEvidence, "registered_profiles_do_not_cover_missing_catalog")
			continue
		}
		configAttempted = true
		diag.PerProcessCollectorCount++
		configBudget := options.budget.cappedFor(10 * time.Second)
		isolated := newCandidateCollector(eligibleTargets, mediaEvidence{}, configBudget)
		isolated.processInstanceID = process.evidence.InstanceID
		attempt := scanWindowsConfigCipherProcess(
			process.handle, process.evidence, entry.Recipe, isolated, totalScanLimit-diag.ScannedBytes,
			configBudget,
		)
		diag.ConfigCipherStructureCount += attempt.StructureCount
		diag.ConfigCipherInvalidCount += attempt.InvalidStructures
		diag.ConfigCipherCandidateCount += attempt.CandidateCount
		diag.ConfigCipherVerifiedCount += attempt.VerifiedCandidates
		if attempt.VerifiedCandidates > 0 {
			diag.CandidateSources = appendUniqueStrings(diag.CandidateSources, "windows_config_cipher")
		}
		diag.ScannedBytes += attempt.ScannedBytes
		aggregate.mergeValidatedFrom(isolated)
		attemptStatus := attempt.Status
		if attemptStatus == windowsConfigCipherSucceeded {
			keysAfterAttempt, _ := aggregate.databaseKeys(targets)
			if missingOnlyTargets(targets, keysAfterAttempt).count > 0 {
				// The registered recipe may intentionally cover only a subset of
				// profiles. Success is reserved for the complete requested catalog.
				attemptStatus = windowsConfigCipherPartial
			}
		}
		diag.ConfigCipherRouteStatus = chooseWindowsConfigStatus(diag.ConfigCipherRouteStatus, attemptStatus)
		isolated.clearSensitiveBuffers()
	}
	diag.PhaseTimingsMS = map[string]int64{"config_cipher": time.Since(configStarted).Milliseconds()}
	if configAttempted {
		diag.RouteSelected = "windows_config_cipher"
		diag.RoutesAttempted = appendUniqueStrings(diag.RoutesAttempted, "windows_config_cipher")
	}

	fallbackStarted := time.Now()
	fallbackAttempted := false
	for _, stage := range windowsFallbackStages {
		if options.budget.expired() || diag.ScannedBytes >= totalScanLimit {
			diag.ScanLimited = true
			break
		}
		for _, process := range opened {
			if options.budget.expired() || diag.ScannedBytes >= totalScanLimit {
				diag.ScanLimited = true
				break
			}
			processBudget := options.budget.cappedFor(stage.Window)
			keys, _ := aggregate.databaseKeys(targets)
			missing := missingOnlyTargets(targets, keys)
			mediaResolved := !needMediaScan || derivedMedia != nil || aggregate.resolvedMedia(scanMedia) != nil
			if missing.count == 0 && mediaResolved {
				break
			}
			if missing.count == 0 && (stage.Name == "structured_key_object" || stage.Name == "salt_neighborhood") {
				continue
			}
			stageMedia := scanMedia
			if mediaResolved {
				stageMedia = mediaEvidence{xorCandidates: map[byte]int{}}
			}
			isolated := newCandidateCollector(missing, stageMedia, processBudget)
			isolated.processInstanceID = process.evidence.InstanceID
			diag.PerProcessCollectorCount++
			limit := stage.PerProcessLimit
			if remaining := totalScanLimit - diag.ScannedBytes; limit > remaining {
				limit = remaining
			}
			scanned, limited := scanProcessStage(process.handle, isolated, limit, true, stage.Name, processBudget)
			if missing.count > 0 && !isolated.hasAllDatabaseCandidates() {
				isolated.resolveDatabasePassphrase(processBudget)
			}
			diag.FallbackCandidateCount += len(isolated.seenDatabase) + isolated.candidateObservationCount
			diag.FallbackStageCounts[stage.Name]++
			diag.ScannedBytes += scanned
			diag.ScanLimited = diag.ScanLimited || limited
			aggregate.mergeValidatedFrom(isolated)
			isolated.clearSensitiveBuffers()
			fallbackAttempted = true
		}
		keys, _ := aggregate.databaseKeys(targets)
		if missingOnlyTargets(targets, keys).count == 0 && (!needMediaScan || derivedMedia != nil || aggregate.resolvedMedia(scanMedia) != nil) {
			break
		}
	}
	diag.PhaseTimingsMS["memory_scan"] = time.Since(fallbackStarted).Milliseconds()
	if fallbackAttempted {
		diag.StaticScanFallback = true
		diag.RouteSelected = "windows_memory_fallback"
		diag.RoutesAttempted = appendUniqueStrings(diag.RoutesAttempted, "windows_memory_fallback")
	}

	keys, ambiguous := aggregate.databaseKeys(targets)
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
	case options.budget.expired():
		diag.ProcessAccessStatus = "deadline_exhausted"
	default:
		diag.ProcessAccessStatus = "unavailable"
	}
	imageCandidate := aggregate.applyScanDiagnostics(&diag, keys, ambiguous, derivedMedia, scanMedia)
	credential, err := aggregate.databaseCredential(keys, targets)
	if err != nil {
		return response{}, diag, err
	}
	return response{DatabaseKeys: keys, DatabaseProfiles: aggregate.profilesForKeys(keys), DatabaseCredential: credential, ImageKeys: imageCandidate}, diag, nil
}
