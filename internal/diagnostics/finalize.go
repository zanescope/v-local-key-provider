package diagnostics

import (
	"sort"

	catalogmodel "github.com/zanescope/v-local-key-provider/internal/catalog"
	credentialmodel "github.com/zanescope/v-local-key-provider/internal/credential"
)

// PlatformDefaults 包含 diagnostics 无法从 wire schema 推断、且由 composition 持有的
// 事实，例如当前机器安全状态以及本构建是否存在 Darwin Shadow route。
type PlatformDefaults struct {
	SecurityPostureStatus   string
	DarwinShadowRouteStatus string
}

// FinalizeInput 有意与 protocol 和 acquisition 解耦，使 diagnostics 保持为没有 import
// cycle 的叶级 schema package。
type FinalizeInput struct {
	Catalog               catalogmodel.Catalog
	RequiredDatabaseCount int
	DatabaseKeys          map[string]string
	DatabaseCredential    *credentialmodel.DatabaseCredential
	ImageKeysPresent      bool
	DatabaseRequested     bool
	MediaRequested        bool
	BudgetExpired         bool
	PlatformDefaults      PlatformDefaults
}

func RequestedScopes(database, media bool) []string {
	result := make([]string, 0, 2)
	if database {
		result = append(result, "database")
	}
	if media {
		result = append(result, "media")
	}
	return result
}

func MissingDatabaseIDs(catalog catalogmodel.Catalog, keys map[string]string) []string {
	missing := []string{}
	for _, database := range catalog.Databases {
		if !database.RequiredForKeyCoverage {
			continue
		}
		if _, found := keys[database.RelativePath]; !found {
			missing = append(missing, database.DatabaseID)
		}
	}
	return missing
}

func ApplyPlatformDefaults(diag *Diagnostics, defaults PlatformDefaults) {
	if diag == nil {
		return
	}
	if diag.SecurityPostureStatus == "" {
		diag.SecurityPostureStatus = defaults.SecurityPostureStatus
	}
	if diag.PhaseTimingsMS == nil {
		diag.PhaseTimingsMS = map[string]int64{}
	}
	switch diag.Platform {
	case "darwin":
		if diag.ShadowRouteStatus == "" {
			diag.ShadowRouteStatus = defaults.DarwinShadowRouteStatus
			if diag.ShadowRouteStatus == "" {
				diag.ShadowRouteStatus = "unavailable_in_build"
			}
		}
		if diag.RoutePriority == nil {
			diag.RoutePriority = []string{"standard", "shadow", "sip_disabled"}
		}
		if diag.BinaryFingerprintStatus == "" {
			diag.BinaryFingerprintStatus = "not_evaluated"
		}
		if diag.BinarySigningStatus == "" {
			diag.BinarySigningStatus = "not_evaluated"
		}
		if diag.ProcessArchitecture == "" {
			diag.ProcessArchitecture = "unknown"
		}
		if diag.ProcessArchitectureStatus == "" {
			diag.ProcessArchitectureStatus = "not_evaluated"
		}
		if diag.ProcessTranslationStatus == "" {
			diag.ProcessTranslationStatus = "not_evaluated"
		}
		if diag.CompatibilityRegistryStatus == "" {
			diag.CompatibilityRegistryStatus = "not_evaluated"
		}
		if diag.StandardRouteStatus == "" {
			diag.StandardRouteStatus = "not_evaluated"
		}
		if diag.StandardRouteEvidence == nil {
			diag.StandardRouteEvidence = []string{}
		}
		diag.ConfigCipherRouteStatus = "not_applicable"
		diag.WindowsRouteEvidence = []string{}
	case "windows":
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
			diag.ProcessArchitectureStatus = "unavailable"
		}
		if diag.BinaryFingerprintStatus == "" {
			diag.BinaryFingerprintStatus = "unavailable"
		}
		if diag.BinarySigningStatus == "" {
			diag.BinarySigningStatus = "unavailable"
		}
		if diag.CompatibilityRegistryStatus == "" {
			diag.CompatibilityRegistryStatus = "not_evaluated"
		}
		if diag.ConfigCipherRouteStatus == "" {
			diag.ConfigCipherRouteStatus = "not_evaluated"
		}
		if diag.WindowsRouteEvidence == nil {
			diag.WindowsRouteEvidence = []string{}
		}
	default:
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

func NewWithPlatformDefaults(platform string, scopes []string, defaults PlatformDefaults) Diagnostics {
	diag := New(platform, scopes, defaults.SecurityPostureStatus)
	ApplyPlatformDefaults(&diag, defaults)
	return diag
}

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

// Finalize 根据累积的采集证据推导 coverage 和唯一协议结果。调用方之后不得修改
// result_code。
func Finalize(diag *Diagnostics, input FinalizeInput) {
	if diag == nil {
		return
	}
	ApplyPlatformDefaults(diag, input.PlatformDefaults)
	diag.DatabaseCount = len(input.Catalog.Databases)
	diag.RequiredDatabaseCount = input.RequiredDatabaseCount
	diag.PlaintextDatabaseCount = 0
	diag.UnreadableDatabaseCount = 0
	diag.UnstableDatabaseCount = 0
	diag.TruncatedDatabaseCount = 0
	for _, database := range input.Catalog.Databases {
		switch database.Classification {
		case catalogmodel.ClassificationPlaintext:
			diag.PlaintextDatabaseCount++
		case catalogmodel.ClassificationUnreadable:
			diag.UnreadableDatabaseCount++
		case catalogmodel.ClassificationUnstable:
			diag.UnstableDatabaseCount++
		case catalogmodel.ClassificationTruncated:
			diag.TruncatedDatabaseCount++
		}
	}
	diag.MatchedDatabaseCount = len(input.DatabaseKeys)
	diag.MissingDatabaseIDs = MissingDatabaseIDs(input.Catalog, input.DatabaseKeys)
	diag.MissingDatabaseCount = len(diag.MissingDatabaseIDs)
	if diag.TargetBindingStatus == "" {
		diag.TargetBindingStatus = "unknown"
	}
	if diag.TargetBindingStatus == "unknown" && diag.MatchedDatabaseCount > 0 {
		// 逐文件 page HMAC 能证明 target 与数据绑定，但不能证明当前运行进程选择了哪个账号。
		diag.TargetBindingStatus = "hmac_verified"
	}
	if diag.SessionAccountStatus == "" {
		diag.SessionAccountStatus = "unknown"
	}
	diag.CandidateMode = "none"
	if len(input.DatabaseKeys) > 0 {
		diag.CandidateMode = "per_database_enc_key"
	}
	if input.DatabaseCredential != nil {
		switch input.DatabaseCredential.Mode {
		case "global_passphrase", "mixed":
			diag.CandidateMode = input.DatabaseCredential.Mode
		}
		sources := map[string]bool{}
		for _, source := range diag.CandidateSources {
			sources[source] = true
		}
		for _, root := range input.DatabaseCredential.Roots {
			for _, source := range root.SourceEvidence {
				sources[source] = true
			}
		}
		for _, override := range input.DatabaseCredential.Overrides {
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

	diag.RequestedScopes = RequestedScopes(input.DatabaseRequested, input.MediaRequested)
	diag.DatabaseTargetStatus = "not_requested"
	diag.MediaCoverageStatus = "not_requested"
	mediaComplete := true
	if input.MediaRequested {
		diag.MediaCoverageStatus = "none"
		mediaComplete = input.ImageKeysPresent
		if mediaComplete {
			diag.MediaCoverageStatus = "complete"
		}
	}
	databaseComplete := true
	diag.DatabaseCoverageStatus = "not_requested"
	if input.DatabaseRequested {
		diag.DatabaseTargetStatus = "none"
		if diag.DatabaseCount > 0 {
			diag.DatabaseTargetStatus = "present"
		}
		// 空 target 集合不代表成功覆盖。仅含明文数据库的 catalog 仍是完整的，因为它依然
		// 包含经过证明的 catalog 条目。
		databaseComplete = diag.DatabaseCount > 0 && diag.MissingDatabaseCount == 0 && len(input.Catalog.DiscoveryErrors) == 0
		switch {
		case databaseComplete:
			diag.DatabaseCoverageStatus = "complete"
		case diag.MatchedDatabaseCount > 0:
			diag.DatabaseCoverageStatus = "partial"
		default:
			diag.DatabaseCoverageStatus = "none"
		}
	}
	ApplyOutcome(diag, ResolveOutcome(DecisionContext{
		Diagnostics: *diag, DatabaseComplete: databaseComplete, MediaComplete: mediaComplete,
		BudgetExpired: input.BudgetExpired, DatabaseRequested: input.DatabaseRequested,
		ShadowFallbackReason:      shadowRouteFallbackReason(diag.ShadowRouteStatus),
		SIPDisabledRouteAttempted: diag.Platform == "darwin" && darwinSIPDisabledRouteAttempted(diag.RoutesAttempted),
	}))
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
