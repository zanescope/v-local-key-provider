package provider

import windowsroute "github.com/zanescope/v-local-key-provider/internal/platform/windows"

const (
	windowsArchitectureNotEvaluated = windowsroute.ArchitectureNotEvaluated
	windowsArchitectureVerified     = windowsroute.ArchitectureVerified
	windowsArchitectureUnavailable  = windowsroute.ArchitectureUnavailable

	windowsFingerprintNotEvaluated = windowsroute.FingerprintNotEvaluated
	windowsFingerprintVerified     = windowsroute.FingerprintVerified
	windowsFingerprintUnavailable  = windowsroute.FingerprintUnavailable

	windowsSigningNotEvaluated = windowsroute.SigningNotEvaluated
	windowsSigningVerified     = windowsroute.SigningVerified
	windowsSigningInvalid      = windowsroute.SigningInvalid
	windowsSigningUnavailable  = windowsroute.SigningUnavailable

	windowsRegistryNotEvaluated        = windowsroute.RegistryNotEvaluated
	windowsRegistryRegisteredSupported = windowsroute.RegistryRegisteredSupported
	windowsRegistryRegisteredRejected  = windowsroute.RegistryRegisteredRejected
	windowsRegistryUnregistered        = windowsroute.RegistryUnregistered
	windowsRegistryUntrustedBinary     = windowsroute.RegistryUntrustedBinary

	windowsConfigCipherNotEvaluated         = windowsroute.ConfigCipherNotEvaluated
	windowsConfigCipherUnavailableUnknown   = windowsroute.ConfigCipherUnavailableUnknown
	windowsConfigCipherUnavailableUntrusted = windowsroute.ConfigCipherUnavailableUntrusted
	windowsConfigCipherEligible             = windowsroute.ConfigCipherEligible
	windowsConfigCipherNoStructure          = windowsroute.ConfigCipherNoStructure
	windowsConfigCipherInvalidStructure     = windowsroute.ConfigCipherInvalidStructure
	windowsConfigCipherNoVerifiedCandidate  = windowsroute.ConfigCipherNoVerifiedCandidate
	windowsConfigCipherPartial              = windowsroute.ConfigCipherPartial
	windowsConfigCipherSucceeded            = windowsroute.ConfigCipherSucceeded
)

type windowsBinaryEvidence = windowsroute.BinaryEvidence
type windowsConfigCipherRecipe = windowsroute.ConfigCipherRecipe
type windowsCompatibilityEntry = windowsroute.CompatibilityEntry
type windowsRouteDecision = windowsroute.RouteDecision

// The production registry remains empty until independently promoted live
// evidence covers each exact candidate and target architecture.
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

func windowsRegistryEntryMatches(entry windowsCompatibilityEntry, evidence windowsBinaryEvidence) bool {
	return windowsroute.RegistryEntryMatches(entry, evidence)
}

func windowsRegistryEntryEligible(entry windowsCompatibilityEntry) bool {
	return windowsroute.RegistryEntryEligible(entry, windowsRoutePolicy().ProfileRegistered)
}

func windowsRegistryEntryRuntimeEligible(entry windowsCompatibilityEntry) bool {
	return windowsroute.RegistryEntryRuntimeEligible(entry, windowsRoutePolicy())
}

func windowsTrustedFallbackSigner(signer, architecture string, registry []windowsCompatibilityEntry) bool {
	return windowsroute.TrustedFallbackSigner(signer, architecture, registry, windowsRoutePolicy())
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
