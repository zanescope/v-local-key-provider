package darwin

import (
	"regexp"
	"sort"
	"strings"
)

const (
	ArchitectureNotEvaluated = "not_evaluated"
	ArchitectureVerified     = "verified_running_process"
	ArchitectureUnavailable  = "unavailable"

	FingerprintNotEvaluated = "not_evaluated"
	FingerprintVerified     = "verified"
	FingerprintUnavailable  = "unavailable"

	SigningNotEvaluated = "not_evaluated"
	SigningVerified     = "verified"
	SigningInvalid      = "invalid"
	SigningUnavailable  = "unavailable"

	RegistryNotEvaluated        = "not_evaluated"
	RegistryRegisteredSupported = "registered_supported"
	RegistryRegisteredRejected  = "registered_unsupported"
	RegistryUnregistered        = "unregistered"
	RegistryUntrustedBinary     = "rejected_untrusted_binary"

	StandardNotEvaluated     = "not_evaluated"
	StandardEligibleRegistry = "eligible_registered"
	StandardEligibleGeneric  = "eligible_generic_dynamic"
	StandardUnsupported      = "unsupported_for_target"
)

// BinaryEvidence contains only machine-verifiable routing inputs. Paths,
// secrets and user-provided descriptions deliberately do not participate in
// the decision or appear in diagnostics.
type BinaryEvidence struct {
	Version                     string
	Build                       string
	ExecutableSHA256            string
	BinaryFingerprintStatus     string
	BinarySigningStatus         string
	SigningTeamID               string
	DesignatedRequirementSHA256 string
	ProcessArchitecture         string
	ProcessArchitectureStatus   string
	ProcessTranslationStatus    string
	MacOSVersion                string
	MacOSMajorMinor             string
}

// CompatibilityEntry is an exact candidate description. Real-device evidence
// is bound externally after this candidate has run; evidence digests are never
// compiled back into the candidate binary.
type CompatibilityEntry struct {
	Version                     string
	Build                       string
	ExecutableSHA256            string
	SigningTeamID               string
	DesignatedRequirementSHA256 string
	ProcessArchitecture         string
	MacOSMajorMinor             string
	RouteSupportState           string
	ValidatedCipherProfiles     []string
}

type RouteDecision struct {
	CompatibilityRegistryStatus string
	StandardRouteStatus         string
	Evidence                    []string
}

// EvaluationPolicy supplies the application-owned trust state without making
// the routing package depend on the main package or its linker-injected values.
type EvaluationPolicy struct {
	ReleaseBuild      bool
	PromotionReady    bool
	ProfileRegistered func(string) bool
}

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func NormalizeArchitecture(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	hasAMD64 := strings.Contains(value, "x86_64") || strings.Contains(value, "amd64")
	hasARM64 := strings.Contains(value, "arm64") || strings.Contains(value, "aarch64")
	switch {
	case hasAMD64 && !hasARM64:
		return "amd64"
	case hasARM64 && !hasAMD64:
		return "arm64"
	default:
		return "unknown"
	}
}

func TranslationStatus(processArchitecture, machineArchitecture string) string {
	processArchitecture = NormalizeArchitecture(processArchitecture)
	machineArchitecture = NormalizeArchitecture(machineArchitecture)
	if processArchitecture == "unknown" || machineArchitecture == "unknown" {
		return "unknown"
	}
	if machineArchitecture == "arm64" && processArchitecture == "amd64" {
		return "translated"
	}
	if processArchitecture == machineArchitecture {
		return "native"
	}
	return "unknown"
}

func MajorMinor(version string) string {
	parts := strings.Split(strings.TrimSpace(version), ".")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	for _, value := range parts[:2] {
		for _, character := range value {
			if character < '0' || character > '9' {
				return ""
			}
		}
	}
	return parts[0] + "." + parts[1]
}

func ValidSHA256(value string) bool {
	return sha256Pattern.MatchString(strings.TrimSpace(value))
}

func StandardRouteEligible(decision RouteDecision, allowGeneric bool) bool {
	if decision.StandardRouteStatus == StandardEligibleRegistry {
		return true
	}
	return allowGeneric && decision.StandardRouteStatus == StandardEligibleGeneric
}

func RegistryEntryEligible(entry CompatibilityEntry, profileRegistered func(string) bool) bool {
	if entry.RouteSupportState != "supported" || entry.Version == "" || entry.Build == "" ||
		!ValidSHA256(entry.ExecutableSHA256) || entry.SigningTeamID == "" ||
		!ValidSHA256(entry.DesignatedRequirementSHA256) ||
		(entry.ProcessArchitecture != "amd64" && entry.ProcessArchitecture != "arm64") ||
		MajorMinor(entry.MacOSMajorMinor) != entry.MacOSMajorMinor ||
		len(entry.ValidatedCipherProfiles) == 0 || profileRegistered == nil {
		return false
	}
	profiles := map[string]bool{}
	for _, profileID := range entry.ValidatedCipherProfiles {
		if strings.TrimSpace(profileID) != profileID || profiles[profileID] || !profileRegistered(profileID) {
			return false
		}
		profiles[profileID] = true
	}
	return true
}

func RegistryEntryRuntimeEligible(entry CompatibilityEntry, policy EvaluationPolicy) bool {
	return RegistryEntryEligible(entry, policy.ProfileRegistered) &&
		(!policy.ReleaseBuild || policy.PromotionReady)
}

// ProcessAccessFailure converts only machine-verified SIP evidence into the
// special failure consumed by the external, user-operated SIP workflow.
func ProcessAccessFailure(securityPosture string) string {
	if securityPosture == "sip_enabled_verified" {
		return "sip_enabled"
	}
	return "task_for_pid_denied"
}

func DeniedAccessError(helperMode bool, helperStatus, securityPosture string) string {
	if helperMode || helperStatus == "sip_enabled" {
		return ProcessAccessFailure(securityPosture)
	}
	return "task_for_pid_denied"
}

func DynamicRouteID(architecture, securityPosture string) string {
	architecture = NormalizeArchitecture(architecture)
	if architecture != "arm64" && architecture != "amd64" {
		return ""
	}
	if securityPosture == "sip_disabled_verified" {
		return "darwin_" + architecture + "_sip_disabled"
	}
	return "darwin_" + architecture + "_standard_dynamic"
}

func RegistryEntryMatches(entry CompatibilityEntry, evidence BinaryEvidence) bool {
	return entry.Version == evidence.Version &&
		entry.Build == evidence.Build &&
		entry.ExecutableSHA256 == evidence.ExecutableSHA256 &&
		entry.SigningTeamID == evidence.SigningTeamID &&
		entry.DesignatedRequirementSHA256 == evidence.DesignatedRequirementSHA256 &&
		entry.ProcessArchitecture == evidence.ProcessArchitecture &&
		entry.MacOSMajorMinor == evidence.MacOSMajorMinor
}

func EvaluateRoute(evidence BinaryEvidence, registry []CompatibilityEntry, policy EvaluationPolicy) RouteDecision {
	decision := RouteDecision{
		CompatibilityRegistryStatus: RegistryNotEvaluated,
		StandardRouteStatus:         StandardNotEvaluated,
	}
	addEvidence := func(value string) {
		decision.Evidence = append(decision.Evidence, value)
	}
	if evidence.ProcessArchitectureStatus != ArchitectureVerified ||
		(evidence.ProcessArchitecture != "amd64" && evidence.ProcessArchitecture != "arm64") {
		addEvidence("process_architecture_not_verified")
	}
	if evidence.BinaryFingerprintStatus != FingerprintVerified || !ValidSHA256(evidence.ExecutableSHA256) {
		addEvidence("binary_fingerprint_not_verified")
	}
	if evidence.Version == "" {
		addEvidence("wechat_version_not_verified")
	}
	if evidence.Build == "" {
		addEvidence("wechat_build_not_verified")
	}
	if evidence.MacOSMajorMinor == "" {
		addEvidence("macos_version_not_verified")
	}
	if evidence.BinarySigningStatus == SigningInvalid {
		decision.CompatibilityRegistryStatus = RegistryUntrustedBinary
		decision.StandardRouteStatus = StandardUnsupported
		addEvidence("binary_signing_invalid")
		sort.Strings(decision.Evidence)
		return decision
	}
	if evidence.BinarySigningStatus != SigningVerified || evidence.SigningTeamID == "" ||
		!ValidSHA256(evidence.DesignatedRequirementSHA256) {
		addEvidence("binary_signing_not_verified")
	}
	if len(decision.Evidence) > 0 {
		sort.Strings(decision.Evidence)
		return decision
	}

	for _, entry := range registry {
		if !RegistryEntryMatches(entry, evidence) {
			continue
		}
		if RegistryEntryRuntimeEligible(entry, policy) {
			decision.CompatibilityRegistryStatus = RegistryRegisteredSupported
			decision.StandardRouteStatus = StandardEligibleRegistry
			decision.Evidence = []string{"registry_candidate_entry", "registry_exact_match"}
			if policy.ReleaseBuild {
				decision.Evidence = []string{"real_device_evidence_present", "registry_exact_match", "release_promotion_verified"}
			}
			return decision
		}
		decision.CompatibilityRegistryStatus = RegistryRegisteredRejected
		decision.StandardRouteStatus = StandardUnsupported
		decision.Evidence = []string{"registry_entry_not_supported"}
		return decision
	}

	decision.CompatibilityRegistryStatus = RegistryUnregistered
	if policy.ReleaseBuild {
		decision.StandardRouteStatus = StandardUnsupported
		decision.Evidence = []string{"release_requires_registry_exact_match", "registry_no_exact_match"}
	} else {
		decision.StandardRouteStatus = StandardEligibleGeneric
		decision.Evidence = []string{"generic_symbol_route_only", "registry_no_exact_match"}
	}
	return decision
}
