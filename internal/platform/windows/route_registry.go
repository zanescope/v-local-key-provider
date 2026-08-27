package windows

import (
	"encoding/hex"
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

	ConfigCipherNotEvaluated         = "not_evaluated"
	ConfigCipherUnavailableUnknown   = "unavailable_unregistered"
	ConfigCipherUnavailableUntrusted = "unavailable_untrusted_binary"
	ConfigCipherEligible             = "eligible_registered"
	ConfigCipherNoStructure          = "attempted_no_structure"
	ConfigCipherInvalidStructure     = "attempted_invalid_structure"
	ConfigCipherNoVerifiedCandidate  = "attempted_no_verified_candidate"
	ConfigCipherPartial              = "partial"
	ConfigCipherSucceeded            = "succeeded"
)

// BinaryEvidence 只包含由机器推导的 routing 输入。可执行文件路径仅供进程内使用，不能进入
// diagnostics 或真机证据。
type BinaryEvidence struct {
	Version                   string
	Build                     string
	ExecutableSHA256          string
	BinaryFingerprintStatus   string
	BinarySigningStatus       string
	BinarySignerSHA256        string
	ProcessArchitecture       string
	ProcessArchitectureStatus string
	ProductIdentity           string
}

// ConfigCipherRecipe 是精确且有界的 layout recipe。
type ConfigCipherRecipe struct {
	Needle            []byte
	PointerOffsets    []int64
	DataOffset        int64
	EncodedLength     int
	CandidateEncoding string
	CandidateKind     string
	XORMask           []byte
	MaxMatches        int
}

func (recipe ConfigCipherRecipe) Valid() bool {
	if len(recipe.Needle) == 0 || len(recipe.Needle) > 256 || len(recipe.PointerOffsets) > 4 {
		return false
	}
	if recipe.EncodedLength <= 0 || recipe.EncodedLength > 4096 || len(recipe.XORMask) > 64 {
		return false
	}
	if recipe.CandidateEncoding != "raw32" && recipe.CandidateEncoding != "hex64" {
		return false
	}
	if recipe.CandidateKind != "raw_enc_key" && recipe.CandidateKind != "passphrase" {
		return false
	}
	if recipe.CandidateEncoding == "raw32" && recipe.EncodedLength != 32 {
		return false
	}
	if recipe.CandidateEncoding == "hex64" && recipe.EncodedLength != 64 {
		return false
	}
	return recipe.MaxMatches > 0 && recipe.MaxMatches <= 64
}

type CompatibilityEntry struct {
	Version             string
	Build               string
	ExecutableSHA256    string
	BinarySignerSHA256  string
	ProcessArchitecture string
	ProductIdentity     string
	RouteSupportState   string
	ValidatedProfiles   []string
	Recipe              ConfigCipherRecipe
}

type RouteDecision struct {
	CompatibilityRegistryStatus string
	ConfigCipherRouteStatus     string
	Evidence                    []string
	EntryIndex                  int
}

type EvaluationPolicy struct {
	ReleaseBuild      bool
	PromotionReady    bool
	ProfileRegistered func(string) bool
}

func ValidSHA256(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func RegistryEntryMatches(entry CompatibilityEntry, evidence BinaryEvidence) bool {
	return entry.Version == evidence.Version &&
		entry.Build == evidence.Build &&
		entry.ExecutableSHA256 == evidence.ExecutableSHA256 &&
		entry.BinarySignerSHA256 == evidence.BinarySignerSHA256 &&
		entry.ProcessArchitecture == evidence.ProcessArchitecture &&
		entry.ProductIdentity == evidence.ProductIdentity
}

func RegistryEntryEligible(entry CompatibilityEntry, profileRegistered func(string) bool) bool {
	if entry.RouteSupportState != "supported" || !entry.Recipe.Valid() ||
		entry.Version == "" || entry.Build == "" ||
		!ValidSHA256(entry.ExecutableSHA256) || !ValidSHA256(entry.BinarySignerSHA256) ||
		(entry.ProcessArchitecture != "amd64" && entry.ProcessArchitecture != "arm64") ||
		(entry.ProductIdentity != "weixin.exe" && entry.ProductIdentity != "wechat.exe") ||
		len(entry.ValidatedProfiles) == 0 || profileRegistered == nil {
		return false
	}
	profiles := map[string]bool{}
	for _, profileID := range entry.ValidatedProfiles {
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

func TrustedFallbackSigner(signer, architecture string, registry []CompatibilityEntry, policy EvaluationPolicy) bool {
	if !ValidSHA256(signer) || (architecture != "amd64" && architecture != "arm64") {
		return false
	}
	for _, entry := range registry {
		if RegistryEntryRuntimeEligible(entry, policy) && entry.BinarySignerSHA256 == signer &&
			entry.ProcessArchitecture == architecture {
			return true
		}
	}
	return false
}

func FallbackIdentityEligible(evidence BinaryEvidence, registry []CompatibilityEntry, policy EvaluationPolicy) bool {
	return evidence.BinarySigningStatus == SigningVerified &&
		(evidence.ProductIdentity == "weixin.exe" || evidence.ProductIdentity == "wechat.exe") &&
		TrustedFallbackSigner(evidence.BinarySignerSHA256, evidence.ProcessArchitecture, registry, policy)
}

func NormalizeProductIdentity(currentName, originalFilename, productName, companyName string) string {
	current := strings.ToLower(strings.TrimSpace(currentName))
	original := strings.ToLower(strings.TrimSpace(originalFilename))
	product := strings.ToLower(strings.TrimSpace(productName))
	company := strings.ToLower(strings.TrimSpace(companyName))
	if current != original || (original != "weixin.exe" && original != "wechat.exe") {
		return ""
	}
	if !strings.Contains(product, "weixin") && !strings.Contains(product, "wechat") &&
		!strings.Contains(productName, "微信") {
		return ""
	}
	if !strings.Contains(company, "tencent") && !strings.Contains(companyName, "腾讯") {
		return ""
	}
	return original
}

func EvaluateRoute(evidence BinaryEvidence, registry []CompatibilityEntry, policy EvaluationPolicy) RouteDecision {
	decision := RouteDecision{
		CompatibilityRegistryStatus: RegistryNotEvaluated,
		ConfigCipherRouteStatus:     ConfigCipherNotEvaluated,
		EntryIndex:                  -1,
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
	if evidence.ProductIdentity == "" {
		addEvidence("product_identity_not_verified")
	}
	if evidence.BinarySigningStatus == SigningInvalid {
		decision.CompatibilityRegistryStatus = RegistryUntrustedBinary
		decision.ConfigCipherRouteStatus = ConfigCipherUnavailableUntrusted
		addEvidence("binary_signing_invalid")
		sort.Strings(decision.Evidence)
		return decision
	}
	if evidence.BinarySigningStatus != SigningVerified || !ValidSHA256(evidence.BinarySignerSHA256) {
		addEvidence("binary_signing_not_verified")
	}
	if len(decision.Evidence) > 0 {
		sort.Strings(decision.Evidence)
		return decision
	}

	for index := range registry {
		entry := registry[index]
		if !RegistryEntryMatches(entry, evidence) {
			continue
		}
		decision.EntryIndex = index
		if RegistryEntryRuntimeEligible(entry, policy) {
			decision.CompatibilityRegistryStatus = RegistryRegisteredSupported
			decision.ConfigCipherRouteStatus = ConfigCipherEligible
			decision.Evidence = []string{"registry_candidate_entry", "registry_exact_match"}
			if policy.ReleaseBuild {
				decision.Evidence = []string{"real_device_evidence_present", "registry_exact_match", "release_promotion_verified"}
			}
			return decision
		}
		decision.CompatibilityRegistryStatus = RegistryRegisteredRejected
		decision.ConfigCipherRouteStatus = ConfigCipherUnavailableUnknown
		decision.Evidence = []string{"registry_entry_not_supported"}
		return decision
	}

	decision.CompatibilityRegistryStatus = RegistryUnregistered
	decision.ConfigCipherRouteStatus = ConfigCipherUnavailableUnknown
	decision.Evidence = []string{"registry_no_exact_match"}
	return decision
}

func ConfigStatusRank(status string) int {
	switch status {
	case ConfigCipherSucceeded:
		return 9
	case ConfigCipherPartial:
		return 8
	case ConfigCipherNoVerifiedCandidate:
		return 7
	case ConfigCipherInvalidStructure:
		return 6
	case ConfigCipherNoStructure:
		return 5
	case ConfigCipherEligible:
		return 4
	case ConfigCipherUnavailableUntrusted:
		return 3
	case ConfigCipherUnavailableUnknown:
		return 2
	case ConfigCipherNotEvaluated:
		return 1
	default:
		return 0
	}
}
