package diagnostics

import shadowmodel "github.com/zanescope/v-local-key-provider/internal/shadowcontract"

// Diagnostics 是采集证据唯一的 wire-schema 来源。platform 和 session package 可以填充
// 或合并字段，但不得定义平行 DTO。
type Diagnostics struct {
	ResultCode                    string              `json:"result_code"`
	WorkflowStatus                string              `json:"workflow_status"`
	RequestedScopes               []string            `json:"requested_scopes"`
	DatabaseTargetStatus          string              `json:"database_target_status"`
	DatabaseCoverageStatus        string              `json:"database_coverage_status"`
	SecurityPostureStatus         string              `json:"security_posture_status"`
	MediaCoverageStatus           string              `json:"media_coverage_status"`
	ShadowRouteStatus             string              `json:"shadow_route_status"`
	ShadowAttempt                 *shadowmodel.Result `json:"shadow_attempt,omitempty"`
	RoutePriority                 []string            `json:"route_priority"`
	NextAction                    string              `json:"next_action"`
	BlockingReasons               []string            `json:"blocking_reasons"`
	CandidateMode                 string              `json:"candidate_mode"`
	CandidateSources              []string            `json:"candidate_sources"`
	MissingDatabaseCount          int                 `json:"missing_database_count"`
	MissingDatabaseIDs            []string            `json:"missing_database_ids"`
	TargetBindingStatus           string              `json:"target_binding_status"`
	SessionAccountStatus          string              `json:"session_account_status"`
	RouteSelected                 string              `json:"route_selected,omitempty"`
	RoutesAttempted               []string            `json:"routes_attempted"`
	SessionID                     string              `json:"session_id,omitempty"`
	SessionExpiresAt              string              `json:"session_expires_at,omitempty"`
	ProcessInstanceID             string              `json:"process_instance_id,omitempty"`
	ActionStage                   string              `json:"action_stage,omitempty"`
	PhaseTimingsMS                map[string]int64    `json:"phase_timings_ms"`
	Platform                      string              `json:"platform"`
	WeChatVersion                 string              `json:"wechat_version,omitempty"`
	WeChatBuild                   string              `json:"wechat_build,omitempty"`
	ExecutableSHA256              string              `json:"executable_sha256,omitempty"`
	BinaryFingerprintStatus       string              `json:"binary_fingerprint_status,omitempty"`
	BinarySigningStatus           string              `json:"binary_signing_status,omitempty"`
	BinarySignerSHA256            string              `json:"binary_signer_sha256,omitempty"`
	BinaryProductIdentity         string              `json:"binary_product_identity,omitempty"`
	SigningTeamID                 string              `json:"signing_team_id,omitempty"`
	DesignatedRequirementSHA256   string              `json:"designated_requirement_sha256,omitempty"`
	ProcessArchitecture           string              `json:"process_architecture,omitempty"`
	ProcessArchitectureStatus     string              `json:"process_architecture_status,omitempty"`
	ProcessTranslationStatus      string              `json:"process_translation_status,omitempty"`
	MacOSVersion                  string              `json:"macos_version,omitempty"`
	CompatibilityRegistryStatus   string              `json:"compatibility_registry_status,omitempty"`
	StandardRouteStatus           string              `json:"standard_route_status,omitempty"`
	StandardRouteEvidence         []string            `json:"standard_route_evidence"`
	ConfigCipherRouteStatus       string              `json:"config_cipher_route_status"`
	WindowsRouteEvidence          []string            `json:"windows_route_evidence"`
	ProcessAccessStatus           string              `json:"process_access_status,omitempty"`
	ProcessAccessError            string              `json:"process_access_error,omitempty"`
	HelperStatus                  string              `json:"helper_status,omitempty"`
	HookTargetFound               int                 `json:"hook_target_found"`
	HookInstalled                 bool                `json:"hook_installed"`
	HookTimeout                   bool                `json:"hook_timeout"`
	HookTriggerRequired           bool                `json:"hook_trigger_required"`
	HookRestartRequired           bool                `json:"hook_restart_required"`
	HookReloginRequired           bool                `json:"hook_relogin_required"`
	HookCaptureCount              int                 `json:"hook_capture_count"`
	DynamicHookUsed               bool                `json:"dynamic_hook_used"`
	StaticScanFallback            bool                `json:"static_scan_fallback"`
	VersionSupport                string              `json:"version_support,omitempty"`
	ProcessCount                  int                 `json:"process_count"`
	OpenedProcessCount            int                 `json:"opened_process_count"`
	AccessDeniedCount             int                 `json:"access_denied_count"`
	SelectedProcessCount          int                 `json:"selected_process_count"`
	TargetBoundProcessCount       int                 `json:"target_bound_process_count"`
	OtherAccountProcessCount      int                 `json:"other_account_process_count"`
	UnknownAccountProcessCount    int                 `json:"unknown_account_process_count"`
	PerProcessCollectorCount      int                 `json:"per_process_collector_count"`
	DatabaseCount                 int                 `json:"database_count"`
	RequiredDatabaseCount         int                 `json:"required_database_count"`
	PlaintextDatabaseCount        int                 `json:"plaintext_database_count"`
	UnreadableDatabaseCount       int                 `json:"unreadable_database_count"`
	UnstableDatabaseCount         int                 `json:"unstable_database_count"`
	TruncatedDatabaseCount        int                 `json:"truncated_database_count"`
	MatchedDatabaseCount          int                 `json:"matched_database_count"`
	AmbiguousDatabaseKeys         int                 `json:"ambiguous_database_keys"`
	ValidatorConflictCount        int                 `json:"validator_conflict_count"`
	CandidateCount                int                 `json:"candidate_count"`
	PassphraseCandidateCount      int                 `json:"passphrase_candidate_count"`
	KDFBudgetExhausted            bool                `json:"kdf_budget_exhausted"`
	HexPatternCount               int                 `json:"hex_pattern_count"`
	RawKeyCandidateCount          int                 `json:"raw_key_candidate_count"`
	ValidatedCandidateCount       int                 `json:"validated_database_candidate_count"`
	KeyObjectPatternCount         int                 `json:"key_object_pattern_count"`
	DereferencedKeyCandidateCount int                 `json:"dereferenced_key_candidate_count"`
	PassphraseValidationCount     int                 `json:"passphrase_validation_count"`
	KeyObjectStructuralCount      int                 `json:"key_object_structural_count"`
	KeyObjectCapacity32Count      int                 `json:"key_object_capacity_32_count"`
	KeyObjectCapacity47Count      int                 `json:"key_object_capacity_47_count"`
	KeyObjectCapacity63Count      int                 `json:"key_object_capacity_63_count"`
	KeyObjectOtherCapacityCount   int                 `json:"key_object_other_capacity_count"`
	InternalXORKeyCandidateCount  int                 `json:"internal_xor_key_candidate_count"`
	ConfigCipherStructureCount    int                 `json:"config_cipher_structure_count"`
	ConfigCipherInvalidCount      int                 `json:"config_cipher_invalid_structure_count"`
	ConfigCipherCandidateCount    int                 `json:"config_cipher_candidate_count"`
	ConfigCipherVerifiedCount     int                 `json:"config_cipher_verified_candidate_count"`
	FallbackCandidateCount        int                 `json:"fallback_candidate_count"`
	FallbackStageCounts           map[string]int      `json:"fallback_stage_counts"`
	V2SampleCount                 int                 `json:"v2_sample_count"`
	XORSampleCount                int                 `json:"xor_sample_count"`
	XORDistinctCandidateCount     int                 `json:"xor_distinct_candidate_count"`
	XORLeadingSampleCount         int                 `json:"xor_leading_sample_count"`
	XORSecondSampleCount          int                 `json:"xor_second_sample_count"`
	MediaAESCandidateCount        int                 `json:"media_aes_candidate_count"`
	KVCommCodeCandidateCount      int                 `json:"kvcomm_code_candidate_count"`
	KVCommVerifiedCandidateCount  int                 `json:"kvcomm_verified_candidate_count"`
	MediaCandidateMethod          string              `json:"media_candidate_method,omitempty"`
	ProcessDiscoveryMethod        string              `json:"process_discovery_method,omitempty"`
	ScannedBytes                  uint64              `json:"scanned_bytes"`
	ScanLimited                   bool                `json:"scan_limited"`
	// BudgetExhausted 表示 Provider 在 deadline 前返回了经验证的部分结果，因此
	// database_keys 可能不完整。
	BudgetExhausted bool  `json:"budget_exhausted"`
	ElapsedMS       int64 `json:"elapsed_ms"`
}

func CanonicalScopes(scopes []string) []string {
	database := false
	media := false
	for _, scope := range scopes {
		database = database || scope == "database"
		media = media || scope == "media"
	}
	result := make([]string, 0, 2)
	if database {
		result = append(result, "database")
	}
	if media {
		result = append(result, "media")
	}
	return result
}

// New 建立所有平台共享的 collection/map invariant。存在由 composition 持有的平台事实时，
// 使用 NewWithPlatformDefaults。
func New(platform string, scopes []string, securityPostureStatus string) Diagnostics {
	return Diagnostics{
		Platform: platform, RequestedScopes: CanonicalScopes(scopes),
		DatabaseTargetStatus: "not_requested", DatabaseCoverageStatus: "not_requested",
		SecurityPostureStatus: securityPostureStatus, MediaCoverageStatus: "not_requested",
		NextAction: "none", BlockingReasons: []string{}, CandidateMode: "none", CandidateSources: []string{},
		TargetBindingStatus: "unknown", SessionAccountStatus: "unknown", RoutesAttempted: []string{},
		PhaseTimingsMS: map[string]int64{}, FallbackStageCounts: map[string]int{},
	}
}
