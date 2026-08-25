package provider

import darwinroute "github.com/zanescope/v-local-key-provider/internal/platform/darwin"

const (
	darwinArchitectureNotEvaluated = darwinroute.ArchitectureNotEvaluated
	darwinArchitectureVerified     = darwinroute.ArchitectureVerified
	darwinArchitectureUnavailable  = darwinroute.ArchitectureUnavailable

	darwinFingerprintNotEvaluated = darwinroute.FingerprintNotEvaluated
	darwinFingerprintVerified     = darwinroute.FingerprintVerified
	darwinFingerprintUnavailable  = darwinroute.FingerprintUnavailable

	darwinSigningNotEvaluated = darwinroute.SigningNotEvaluated
	darwinSigningVerified     = darwinroute.SigningVerified
	darwinSigningInvalid      = darwinroute.SigningInvalid
	darwinSigningUnavailable  = darwinroute.SigningUnavailable

	darwinRegistryNotEvaluated        = darwinroute.RegistryNotEvaluated
	darwinRegistryRegisteredSupported = darwinroute.RegistryRegisteredSupported
	darwinRegistryRegisteredRejected  = darwinroute.RegistryRegisteredRejected
	darwinRegistryUnregistered        = darwinroute.RegistryUnregistered
	darwinRegistryUntrustedBinary     = darwinroute.RegistryUntrustedBinary

	darwinStandardNotEvaluated     = darwinroute.StandardNotEvaluated
	darwinStandardEligibleRegistry = darwinroute.StandardEligibleRegistry
	darwinStandardEligibleGeneric  = darwinroute.StandardEligibleGeneric
	darwinStandardUnsupported      = darwinroute.StandardUnsupported
)

type darwinBinaryEvidence = darwinroute.BinaryEvidence
type darwinCompatibilityEntry = darwinroute.CompatibilityEntry
type darwinRouteDecision = darwinroute.RouteDecision

// Exact candidate entries are added before live acceptance. The production
// registry remains empty until independently promoted evidence exists.
var darwinCompatibilityRegistry = []darwinCompatibilityEntry{}

func darwinRoutePolicy() darwinroute.EvaluationPolicy {
	return darwinroute.EvaluationPolicy{
		ReleaseBuild:   releaseBuild(),
		PromotionReady: releasePromotionReady(),
		ProfileRegistered: func(profileID string) bool {
			_, ok := registeredProfile(profileID)
			return ok
		},
	}
}

func normalizeDarwinArchitecture(value string) string {
	return darwinroute.NormalizeArchitecture(value)
}

func darwinTranslationStatus(processArchitecture, machineArchitecture string) string {
	return darwinroute.TranslationStatus(processArchitecture, machineArchitecture)
}

func darwinMajorMinor(version string) string {
	return darwinroute.MajorMinor(version)
}

func validDarwinSHA256(value string) bool {
	return darwinroute.ValidSHA256(value)
}

func darwinStandardRouteEligible(decision darwinRouteDecision) bool {
	return darwinroute.StandardRouteEligible(decision, !releaseBuild())
}

func darwinRegistryEntryEligible(entry darwinCompatibilityEntry) bool {
	return darwinroute.RegistryEntryEligible(entry, darwinRoutePolicy().ProfileRegistered)
}

func darwinRegistryEntryRuntimeEligible(entry darwinCompatibilityEntry) bool {
	return darwinroute.RegistryEntryRuntimeEligible(entry, darwinRoutePolicy())
}

func darwinProcessAccessFailure(securityPosture string) string {
	return darwinroute.ProcessAccessFailure(securityPosture)
}

func darwinDeniedAccessError(helperMode bool, helperStatus, securityPosture string) string {
	return darwinroute.DeniedAccessError(helperMode, helperStatus, securityPosture)
}

func darwinDynamicRouteID(architecture, securityPosture string) string {
	return darwinroute.DynamicRouteID(architecture, securityPosture)
}

func darwinRegistryEntryMatches(entry darwinCompatibilityEntry, evidence darwinBinaryEvidence) bool {
	return darwinroute.RegistryEntryMatches(entry, evidence)
}

func evaluateDarwinRoute(evidence darwinBinaryEvidence, registry []darwinCompatibilityEntry) darwinRouteDecision {
	return darwinroute.EvaluateRoute(evidence, registry, darwinRoutePolicy())
}
