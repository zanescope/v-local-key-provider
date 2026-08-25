package provider

import "time"

func missingOnlyTargets(targets databaseTargets, existing map[string]string) databaseTargets {
	if len(existing) == 0 {
		return targets
	}
	subsetCatalog, missingPaths := missingCatalog(targets.Catalog, existing)
	pages := make([]databasePage, 0, len(missingPaths))
	for _, page := range targets.Pages {
		if missingPaths[page.Path] {
			pages = append(pages, page)
		}
	}
	return targetsFromCatalog(subsetCatalog, pages)
}

func mergeSessionDiagnosticEvidence(existing *response, next *diagnostics) {
	if existing == nil {
		return
	}
	previous := existing.Diagnostics
	if next.Platform == "" {
		next.Platform = previous.Platform
	}
	windowsCurrentSnapshot := next.Platform == "windows" && next.ProcessDiscoveryMethod != ""
	if next.Platform == "windows" && !windowsCurrentSnapshot {
		// No platform pass ran (for example every requested ID was already
		// covered). Preserve one complete snapshot rather than independently
		// defaulting or maximizing fields that must describe the same inventory.
		copyWindowsProcessSnapshot(next, previous)
	}
	if next.Platform == "windows" &&
		windowsConfigStatusRank(previous.ConfigCipherRouteStatus) > windowsConfigStatusRank(next.ConfigCipherRouteStatus) {
		// Config.Cipher counters and verified keys are cumulative for the
		// session. Keep the exact binary identity that produced the strongest
		// retained fixed-layout result.
		copyWindowsRouteIdentity(next, previous)
	}
	mergeSessionDiagnosticFields(previous, next)
}

func runIncrementalSessionAcquire(options acquireOptions, fullTargets databaseTargets, media mediaEvidence, existing *response, started time.Time) (response, error) {
	previousKeys := map[string]string(nil)
	if existing != nil {
		previousKeys = existing.DatabaseKeys
	}
	scanTargets := missingOnlyTargets(fullTargets, previousKeys)
	scanOptions := options
	scanOptions.database = options.database && scanTargets.Count > 0
	if existing != nil && existing.ImageKeys != nil {
		scanOptions.media = false
	}
	var next response
	var diag diagnostics
	var err error
	if scanOptions.database || scanOptions.media {
		phaseStarted := time.Now()
		next, diag, err = platformDriver.Acquire(scanTargets, media, platformRequestFromOptions(scanOptions))
		if diag.PhaseTimingsMS == nil {
			diag.PhaseTimingsMS = map[string]int64{}
		}
		diag.PhaseTimingsMS["primary_acquire"] = time.Since(phaseStarted).Milliseconds()
		if err != nil {
			return response{}, err
		}
	} else {
		diag = newDiagnostics(platformNameForDiagnostics(), requestedScopes(options.database, options.media))
	}
	merged := mergeSessionResults(existing, next)
	mergeSessionDiagnosticEvidence(existing, &diag)
	diag.ElapsedMS = time.Since(started).Milliseconds()
	if diag.PhaseTimingsMS == nil {
		diag.PhaseTimingsMS = map[string]int64{}
	}
	diag.PhaseTimingsMS["total"] = diag.ElapsedMS
	diag.BudgetExhausted = options.budget.expired()
	finalizeDiagnostics(&diag, fullTargets, merged, options)
	merged.CatalogID = fullTargets.Catalog.CatalogID
	merged.CatalogEntries = append([]catalogDatabase(nil), fullTargets.Catalog.Databases...)
	if merged.DatabaseCredential != nil {
		merged.DatabaseCredential.AccountBindingID = catalogHMAC(options.catalogKey, "account", options.accountDir)
	}
	merged.Profiles = profileSummaries()
	merged.Diagnostics = diag
	return merged, nil
}
