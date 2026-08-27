package provider

import windowsroute "github.com/zanescope/v-local-key-provider/internal/platform/windows"

type windowsBinaryEvidence = windowsroute.BinaryEvidence
type windowsConfigCipherRecipe = windowsroute.ConfigCipherRecipe
type windowsCompatibilityEntry = windowsroute.CompatibilityEntry
type windowsRouteDecision = windowsroute.RouteDecision

// 在独立 promotion 的真机证据覆盖每个精确候选及目标架构前，production registry 保持为空。
var windowsCompatibilityRegistry = []windowsCompatibilityEntry{}

func windowsRoutePolicy() windowsroute.EvaluationPolicy {
	return windowsroute.EvaluationPolicy{
		ReleaseBuild:   releaseBuild(),
		PromotionReady: releasePromotionReady(),
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
