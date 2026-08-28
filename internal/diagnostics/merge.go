package diagnostics

import (
	"fmt"
	"reflect"
)

type SessionMergePolicy uint8

const (
	SessionMergeCurrent SessionMergePolicy = iota
	SessionMergeStickyString
	SessionMergeStickyStringSlice
	SessionMergeUniqueStringSlice
	SessionMergePhaseTimings
	SessionMergeFallbackCounts
	SessionMergeBoolOR
	SessionMergeIntMax
	SessionMergeIntSum
	SessionMergeProcessSnapshotInt
	SessionMergeUint64Sum
)

func ValidateSessionMergePolicies(policies map[string]SessionMergePolicy) error {
	diagnosticType := reflect.TypeOf(Diagnostics{})
	if len(policies) != diagnosticType.NumField() {
		return fmt.Errorf("diagnostic merge policy covers %d of %d fields", len(policies), diagnosticType.NumField())
	}
	for index := 0; index < diagnosticType.NumField(); index++ {
		field := diagnosticType.Field(index)
		policy, found := policies[field.Name]
		if !found {
			return fmt.Errorf("diagnostic field %s has no session merge policy", field.Name)
		}
		validKind := false
		switch policy {
		case SessionMergeCurrent:
			validKind = true
		case SessionMergeStickyString:
			validKind = field.Type.Kind() == reflect.String
		case SessionMergeStickyStringSlice, SessionMergeUniqueStringSlice:
			validKind = field.Type == reflect.TypeOf([]string{})
		case SessionMergePhaseTimings:
			validKind = field.Type == reflect.TypeOf(map[string]int64{})
		case SessionMergeFallbackCounts:
			validKind = field.Type == reflect.TypeOf(map[string]int{})
		case SessionMergeBoolOR:
			validKind = field.Type.Kind() == reflect.Bool
		case SessionMergeIntMax, SessionMergeIntSum, SessionMergeProcessSnapshotInt:
			validKind = field.Type.Kind() == reflect.Int
		case SessionMergeUint64Sum:
			validKind = field.Type.Kind() == reflect.Uint64
		}
		if !validKind {
			return fmt.Errorf("diagnostic field %s has incompatible session merge policy %d", field.Name, policy)
		}
	}
	return nil
}

func NewSessionMergePolicies() map[string]SessionMergePolicy {
	policies := map[string]SessionMergePolicy{}
	assign := func(policy SessionMergePolicy, fields ...string) {
		for _, field := range fields {
			if _, exists := policies[field]; exists {
				panic("duplicate diagnostic session merge policy for " + field)
			}
			policies[field] = policy
		}
	}
	assign(SessionMergeCurrent,
		"ResultCode", "WorkflowStatus", "RequestedScopes", "DatabaseTargetStatus", "DatabaseCoverageStatus",
		"MediaCoverageStatus", "NextAction", "BlockingReasons", "CandidateMode", "MissingDatabaseCount",
		"MissingDatabaseIDs", "SessionID", "SessionExpiresAt", "ProcessInstanceID", "ActionStage",
		"HookTriggerRequired", "HookRestartRequired", "HookReloginRequired", "DatabaseCount",
		"RequiredDatabaseCount", "PlaintextDatabaseCount", "UnreadableDatabaseCount", "UnstableDatabaseCount",
		"TruncatedDatabaseCount", "MatchedDatabaseCount", "BudgetExhausted", "ElapsedMS")
	assign(SessionMergeStickyString,
		"SecurityPostureStatus", "ShadowRouteStatus", "TargetBindingStatus", "SessionAccountStatus", "RouteSelected",
		"Platform", "WeChatVersion", "WeChatBuild", "ExecutableSHA256", "BinaryFingerprintStatus",
		"BinarySigningStatus", "BinarySignerSHA256", "BinaryProductIdentity", "SigningTeamID",
		"DesignatedRequirementSHA256", "ProcessArchitecture", "ProcessArchitectureStatus",
		"ProcessTranslationStatus", "MacOSVersion", "CompatibilityRegistryStatus", "StandardRouteStatus",
		"ConfigCipherRouteStatus", "ProcessAccessStatus", "ProcessAccessError", "HelperStatus", "VersionSupport",
		"MediaCandidateMethod", "ProcessDiscoveryMethod")
	assign(SessionMergeStickyStringSlice, "RoutePriority")
	assign(SessionMergeUniqueStringSlice, "CandidateSources", "RoutesAttempted", "StandardRouteEvidence", "WindowsRouteEvidence")
	assign(SessionMergePhaseTimings, "PhaseTimingsMS")
	assign(SessionMergeFallbackCounts, "FallbackStageCounts")
	assign(SessionMergeBoolOR,
		"HookInstalled", "HookTimeout", "DynamicHookUsed", "StaticScanFallback", "KDFBudgetExhausted", "ScanLimited")
	assign(SessionMergeIntMax,
		"HookTargetFound", "HookCaptureCount", "AmbiguousDatabaseKeys", "ValidatorConflictCount", "V2SampleCount",
		"XORSampleCount", "XORDistinctCandidateCount", "XORLeadingSampleCount", "XORSecondSampleCount",
		"MediaAESCandidateCount", "KVCommCodeCandidateCount", "KVCommVerifiedCandidateCount")
	assign(SessionMergeIntSum,
		"PerProcessCollectorCount", "CandidateCount", "PassphraseCandidateCount", "HexPatternCount",
		"RawKeyCandidateCount", "ValidatedCandidateCount", "KeyObjectPatternCount", "DereferencedKeyCandidateCount",
		"PassphraseValidationCount", "KeyObjectStructuralCount", "KeyObjectCapacity32Count", "KeyObjectCapacity47Count",
		"KeyObjectCapacity63Count", "KeyObjectOtherCapacityCount", "InternalXORKeyCandidateCount",
		"ConfigCipherStructureCount", "ConfigCipherInvalidCount", "ConfigCipherCandidateCount",
		"ConfigCipherVerifiedCount", "FallbackCandidateCount")
	assign(SessionMergeProcessSnapshotInt,
		"ProcessCount", "OpenedProcessCount", "AccessDeniedCount", "SelectedProcessCount", "TargetBoundProcessCount",
		"OtherAccountProcessCount", "UnknownAccountProcessCount")
	assign(SessionMergeUint64Sum, "ScannedBytes")
	if err := ValidateSessionMergePolicies(policies); err != nil {
		panic(err)
	}
	return policies
}

func saturatingAddInt(left, right int) int {
	maximum := int(^uint(0) >> 1)
	if right > 0 && left > maximum-right {
		return maximum
	}
	return left + right
}

func appendUniqueStrings(values []string, additions ...string) []string {
	seen := make(map[string]bool, len(values)+len(additions))
	result := make([]string, 0, len(values)+len(additions))
	for _, value := range append(values, additions...) {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func CopyWindowsProcessSnapshot(destination *Diagnostics, source Diagnostics) {
	destination.TargetBindingStatus = source.TargetBindingStatus
	destination.SessionAccountStatus = source.SessionAccountStatus
	destination.WeChatVersion = source.WeChatVersion
	destination.WeChatBuild = source.WeChatBuild
	destination.ExecutableSHA256 = source.ExecutableSHA256
	destination.BinaryFingerprintStatus = source.BinaryFingerprintStatus
	destination.BinarySigningStatus = source.BinarySigningStatus
	destination.BinarySignerSHA256 = source.BinarySignerSHA256
	destination.BinaryProductIdentity = source.BinaryProductIdentity
	destination.ProcessArchitecture = source.ProcessArchitecture
	destination.ProcessArchitectureStatus = source.ProcessArchitectureStatus
	destination.ProcessTranslationStatus = source.ProcessTranslationStatus
	destination.CompatibilityRegistryStatus = source.CompatibilityRegistryStatus
	destination.ConfigCipherRouteStatus = source.ConfigCipherRouteStatus
	destination.ProcessAccessStatus = source.ProcessAccessStatus
	destination.ProcessAccessError = source.ProcessAccessError
	destination.ProcessDiscoveryMethod = source.ProcessDiscoveryMethod
	destination.ProcessCount = source.ProcessCount
	destination.OpenedProcessCount = source.OpenedProcessCount
	destination.AccessDeniedCount = source.AccessDeniedCount
	destination.SelectedProcessCount = source.SelectedProcessCount
	destination.TargetBoundProcessCount = source.TargetBoundProcessCount
	destination.OtherAccountProcessCount = source.OtherAccountProcessCount
	destination.UnknownAccountProcessCount = source.UnknownAccountProcessCount
}

func CopyWindowsRouteIdentity(destination *Diagnostics, source Diagnostics) {
	destination.WeChatVersion = source.WeChatVersion
	destination.WeChatBuild = source.WeChatBuild
	destination.ExecutableSHA256 = source.ExecutableSHA256
	destination.BinaryFingerprintStatus = source.BinaryFingerprintStatus
	destination.BinarySigningStatus = source.BinarySigningStatus
	destination.BinarySignerSHA256 = source.BinarySignerSHA256
	destination.BinaryProductIdentity = source.BinaryProductIdentity
	destination.ProcessArchitecture = source.ProcessArchitecture
	destination.ProcessArchitectureStatus = source.ProcessArchitectureStatus
	destination.ProcessTranslationStatus = source.ProcessTranslationStatus
	destination.CompatibilityRegistryStatus = source.CompatibilityRegistryStatus
	destination.ConfigCipherRouteStatus = source.ConfigCipherRouteStatus
}

func MergeSessionFields(previous Diagnostics, next *Diagnostics, policies map[string]SessionMergePolicy) {
	previousValue := reflect.ValueOf(previous)
	nextValue := reflect.ValueOf(next).Elem()
	diagnosticType := previousValue.Type()
	for index := 0; index < diagnosticType.NumField(); index++ {
		field := diagnosticType.Field(index)
		policy := policies[field.Name]
		prior := previousValue.Field(index)
		current := nextValue.Field(index)
		switch policy {
		case SessionMergeCurrent:
			continue
		case SessionMergeStickyString:
			if current.String() == "" {
				current.SetString(prior.String())
			}
		case SessionMergeStickyStringSlice:
			if current.Len() == 0 && prior.Len() > 0 {
				current.Set(reflect.ValueOf(append([]string(nil), prior.Interface().([]string)...)))
			}
		case SessionMergeUniqueStringSlice:
			merged := appendUniqueStrings(
				append([]string(nil), prior.Interface().([]string)...),
				current.Interface().([]string)...,
			)
			current.Set(reflect.ValueOf(merged))
		case SessionMergePhaseTimings:
			merged := current.Interface().(map[string]int64)
			if merged == nil {
				merged = map[string]int64{}
			}
			for phase, elapsed := range prior.Interface().(map[string]int64) {
				if _, found := merged[phase]; !found {
					merged[phase] = elapsed
				}
			}
			current.Set(reflect.ValueOf(merged))
		case SessionMergeFallbackCounts:
			merged := current.Interface().(map[string]int)
			if merged == nil {
				merged = map[string]int{}
			}
			for stage, count := range prior.Interface().(map[string]int) {
				merged[stage] = saturatingAddInt(merged[stage], count)
			}
			current.Set(reflect.ValueOf(merged))
		case SessionMergeBoolOR:
			current.SetBool(current.Bool() || prior.Bool())
		case SessionMergeIntMax:
			if prior.Int() > current.Int() {
				current.SetInt(prior.Int())
			}
		case SessionMergeIntSum:
			current.SetInt(int64(saturatingAddInt(int(current.Int()), int(prior.Int()))))
		case SessionMergeProcessSnapshotInt:
			if next.Platform != "windows" && prior.Int() > current.Int() {
				current.SetInt(prior.Int())
			}
		case SessionMergeUint64Sum:
			if ^uint64(0)-current.Uint() < prior.Uint() {
				current.SetUint(^uint64(0))
				next.ScanLimited = true
			} else {
				current.SetUint(current.Uint() + prior.Uint())
			}
		}
	}
}
