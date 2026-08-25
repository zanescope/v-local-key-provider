package provider

import "sort"

func shadowRouteFallbackReason(status string) string {
	switch status {
	case "unavailable_in_build":
		return "shadow_route_unavailable_in_build"
	case "unsupported_for_target":
		return "shadow_route_unsupported_for_target"
	case "attempted_failed":
		return "shadow_route_failed"
	default:
		return ""
	}
}

func darwinSIPDisabledRouteAttempted(routes []string) bool {
	for _, route := range routes {
		switch route {
		case "darwin_arm64_sip_disabled", "darwin_amd64_sip_disabled", "darwin_sip_disabled_waitfor":
			return true
		}
	}
	return false
}

func applyPlatformDiagnosticDefaults(diag *diagnostics) {
	if diag.PhaseTimingsMS == nil {
		diag.PhaseTimingsMS = map[string]int64{}
	}
	if diag.Platform == "darwin" {
		if diag.ShadowRouteStatus == "" {
			// Shadow remains higher priority than the SIP-disabled fallback, but an
			// implementation slot that is absent in this build is terminal rather
			// than a hard dependency that blocks every lower-priority route.
			diag.ShadowRouteStatus = "unavailable_in_build"
		}
		if diag.RoutePriority == nil {
			diag.RoutePriority = []string{"standard", "shadow", "sip_disabled"}
		}
		if diag.BinaryFingerprintStatus == "" {
			diag.BinaryFingerprintStatus = darwinFingerprintNotEvaluated
		}
		if diag.BinarySigningStatus == "" {
			diag.BinarySigningStatus = darwinSigningNotEvaluated
		}
		if diag.ProcessArchitecture == "" {
			diag.ProcessArchitecture = "unknown"
		}
		if diag.ProcessArchitectureStatus == "" {
			diag.ProcessArchitectureStatus = darwinArchitectureNotEvaluated
		}
		if diag.ProcessTranslationStatus == "" {
			diag.ProcessTranslationStatus = "not_evaluated"
		}
		if diag.CompatibilityRegistryStatus == "" {
			diag.CompatibilityRegistryStatus = darwinRegistryNotEvaluated
		}
		if diag.StandardRouteStatus == "" {
			diag.StandardRouteStatus = darwinStandardNotEvaluated
		}
		if diag.StandardRouteEvidence == nil {
			diag.StandardRouteEvidence = []string{}
		}
		diag.ConfigCipherRouteStatus = "not_applicable"
		diag.WindowsRouteEvidence = []string{}
	} else if diag.Platform == "windows" {
		if diag.ShadowRouteStatus == "" {
			diag.ShadowRouteStatus = "not_applicable"
		}
		if diag.RoutePriority == nil {
			diag.RoutePriority = []string{}
		}
		if diag.ProcessArchitecture == "" {
			diag.ProcessArchitecture = "unknown"
		}
		if diag.ProcessArchitectureStatus == "" {
			diag.ProcessArchitectureStatus = windowsArchitectureUnavailable
		}
		if diag.BinaryFingerprintStatus == "" {
			diag.BinaryFingerprintStatus = windowsFingerprintUnavailable
		}
		if diag.BinarySigningStatus == "" {
			diag.BinarySigningStatus = windowsSigningUnavailable
		}
		if diag.CompatibilityRegistryStatus == "" {
			diag.CompatibilityRegistryStatus = windowsRegistryNotEvaluated
		}
		if diag.ConfigCipherRouteStatus == "" {
			diag.ConfigCipherRouteStatus = windowsConfigCipherNotEvaluated
		}
		if diag.WindowsRouteEvidence == nil {
			diag.WindowsRouteEvidence = []string{}
		}
	} else {
		diag.ShadowRouteStatus = "not_applicable"
		diag.RoutePriority = []string{}
		diag.ConfigCipherRouteStatus = "not_applicable"
		diag.WindowsRouteEvidence = []string{}
	}
	if diag.StandardRouteEvidence == nil {
		diag.StandardRouteEvidence = []string{}
	}
	if diag.FallbackStageCounts == nil {
		diag.FallbackStageCounts = map[string]int{}
	}
}

func newDiagnostics(platform string, scopes []string) diagnostics {
	diag := newDiagnosticSchema(platform, scopes)
	applyPlatformDiagnosticDefaults(&diag)
	return diag
}

func finalizeDiagnostics(diag *diagnostics, targets databaseTargets, result response, options acquireOptions) {
	applyPlatformDiagnosticDefaults(diag)
	diag.DatabaseCount = len(targets.catalog.Databases)
	diag.RequiredDatabaseCount = targets.count
	diag.PlaintextDatabaseCount = 0
	diag.UnreadableDatabaseCount = 0
	diag.UnstableDatabaseCount = 0
	diag.TruncatedDatabaseCount = 0
	for _, database := range targets.catalog.Databases {
		switch database.Classification {
		case classificationPlaintext:
			diag.PlaintextDatabaseCount++
		case classificationUnreadable:
			diag.UnreadableDatabaseCount++
		case classificationUnstable:
			diag.UnstableDatabaseCount++
		case classificationTruncated:
			diag.TruncatedDatabaseCount++
		}
	}
	diag.MatchedDatabaseCount = len(result.DatabaseKeys)
	diag.MissingDatabaseIDs = missingDatabaseIDs(targets, result.DatabaseKeys)
	diag.MissingDatabaseCount = len(diag.MissingDatabaseIDs)
	if diag.SecurityPostureStatus == "" {
		diag.SecurityPostureStatus = defaultSecurityPostureStatus()
	}
	if diag.TargetBindingStatus == "" {
		diag.TargetBindingStatus = "unknown"
	}
	if diag.TargetBindingStatus == "unknown" && diag.MatchedDatabaseCount > 0 {
		// 候选若能独立通过目标目录数据库的页面 HMAC，就证明它已与目标数据绑定；但这不能
		// 证明当前微信进程正在使用哪个账号，因此 session_account_status 必须单独保留。
		diag.TargetBindingStatus = "hmac_verified"
	}
	if diag.SessionAccountStatus == "" {
		diag.SessionAccountStatus = "unknown"
	}
	diag.CandidateMode = "none"
	if len(result.DatabaseKeys) > 0 {
		diag.CandidateMode = "per_database_enc_key"
	}
	if result.DatabaseCredential != nil {
		switch result.DatabaseCredential.Mode {
		case "global_passphrase", "mixed":
			diag.CandidateMode = result.DatabaseCredential.Mode
		}
		sources := map[string]bool{}
		for _, source := range diag.CandidateSources {
			sources[source] = true
		}
		for _, root := range result.DatabaseCredential.Roots {
			for _, source := range root.SourceEvidence {
				sources[source] = true
			}
		}
		for _, override := range result.DatabaseCredential.Overrides {
			for _, source := range override.SourceEvidence {
				sources[source] = true
			}
		}
		diag.CandidateSources = diag.CandidateSources[:0]
		for source := range sources {
			diag.CandidateSources = append(diag.CandidateSources, source)
		}
		sort.Strings(diag.CandidateSources)
	}
	diag.RequestedScopes = requestedScopes(options.database, options.media)
	diag.DatabaseTargetStatus = "not_requested"
	diag.MediaCoverageStatus = "not_requested"
	mediaComplete := true
	if options.media {
		diag.MediaCoverageStatus = "none"
		mediaComplete = result.ImageKeys != nil
		if mediaComplete {
			diag.MediaCoverageStatus = "complete"
		}
	}
	databaseComplete := true
	diag.DatabaseCoverageStatus = "not_requested"
	if options.database {
		diag.DatabaseTargetStatus = "none"
		if diag.DatabaseCount > 0 {
			diag.DatabaseTargetStatus = "present"
		}
		// An empty target set is not successful database coverage. Plaintext-only
		// catalogs remain complete because they contain proven catalog entries even
		// though required_database_count is zero.
		databaseComplete = diag.DatabaseCount > 0 && diag.MissingDatabaseCount == 0 && len(targets.catalog.DiscoveryErrors) == 0
		switch {
		case databaseComplete:
			diag.DatabaseCoverageStatus = "complete"
		case diag.MatchedDatabaseCount > 0:
			diag.DatabaseCoverageStatus = "partial"
		default:
			diag.DatabaseCoverageStatus = "none"
		}
	}
	applyDiagnosticOutcome(diag, resolveDiagnosticOutcome(*diag, databaseComplete, mediaComplete, options))
	if len(diag.BlockingReasons) == 0 {
		diag.BlockingReasons = []string{}
	}
	if diag.CandidateSources == nil {
		diag.CandidateSources = []string{}
	}
	if diag.RoutesAttempted == nil {
		diag.RoutesAttempted = []string{}
	}
	if diag.FallbackStageCounts == nil {
		diag.FallbackStageCounts = map[string]int{}
	}
}
