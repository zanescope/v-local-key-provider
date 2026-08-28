package provider

import windowsroute "github.com/zanescope/v-local-key-provider/internal/platform/windows"

type windowsBinaryEvidence = windowsroute.BinaryEvidence
type windowsConfigCipherRecipe = windowsroute.ConfigCipherRecipe
type windowsCompatibilityEntry = windowsroute.CompatibilityEntry
type windowsRouteDecision = windowsroute.RouteDecision

// 精确 compatibility 条目只描述已完成本机 qualification 的单一目标；正式发布仍需独立 promotion。
var windowsCompatibilityRegistry = []windowsCompatibilityEntry{
	{
		Version:                    "4.1.12.55",
		Build:                      "12.55",
		ExecutableSHA256:           "bb301eb25b9748d471d8a7e5fb142f6e63b4bf2ecc2d39346e73a902eba5c135",
		BinarySignerSHA256:         "857a8b11ffee5b0d81a7dcf923287bbe3c44245c43433dd249f829d621e4aea1",
		ProcessArchitecture:        "amd64",
		ProductIdentity:            "weixin.exe",
		RouteSupportState:          "supported",
		ConfigCipherSupportState:   "reviewed_no_structure",
		MemoryFallbackSupportState: "supported",
		ValidatedProfiles:          []string{"wcdb-v4-sha512-256000-r80"},
	},
}

func windowsRoutePolicy() windowsroute.EvaluationPolicy {
	return windowsroute.EvaluationPolicy{
		ReleaseBuild:      releaseBuild(),
		PromotionReady:    releasePromotionReady(),
		QualificationOnly: qualificationRegistryEnabled(),
		ProfileRegistered: func(profileID string) bool {
			_, ok := registeredProfile(profileID)
			return ok
		},
	}
}

func validWindowsSHA256(value string) bool {
	return windowsroute.ValidSHA256(value)
}

func windowsRegistryEntryEligible(entry windowsCompatibilityEntry) bool {
	return windowsroute.RegistryEntryEligible(entry, windowsRoutePolicy().ProfileRegistered)
}

func windowsFallbackIdentityEligible(evidence windowsBinaryEvidence, registry []windowsCompatibilityEntry) bool {
	return windowsroute.FallbackIdentityEligible(evidence, registry, windowsRoutePolicy())
}

func normalizeWindowsProductIdentity(currentName, originalFilename, productName, companyName string) string {
	return windowsroute.NormalizeProductIdentity(currentName, originalFilename, productName, companyName)
}

func evaluateWindowsRoute(evidence windowsBinaryEvidence, registry []windowsCompatibilityEntry) windowsRouteDecision {
	return windowsroute.EvaluateRoute(evidence, registry, windowsRoutePolicy())
}

func windowsConfigStatusRank(status string) int {
	return windowsroute.ConfigStatusRank(status)
}
