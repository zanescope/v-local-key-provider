package provider

import darwinroute "github.com/zanescope/v-local-key-provider/internal/platform/darwin"

type darwinBinaryEvidence = darwinroute.BinaryEvidence
type darwinCompatibilityEntry = darwinroute.CompatibilityEntry
type darwinRouteDecision = darwinroute.RouteDecision

// 精确候选条目会在真机验收前加入；在存在独立 promotion 的证据前，production registry
// 保持为空。
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

func validDarwinSHA256(value string) bool {
	return darwinroute.ValidSHA256(value)
}

func darwinStandardRouteEligible(decision darwinRouteDecision) bool {
	return darwinroute.StandardRouteEligible(decision, !releaseBuild())
}

func darwinRegistryEntryEligible(entry darwinCompatibilityEntry) bool {
	return darwinroute.RegistryEntryEligible(entry, darwinRoutePolicy().ProfileRegistered)
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

func evaluateDarwinRoute(evidence darwinBinaryEvidence, registry []darwinCompatibilityEntry) darwinRouteDecision {
	return darwinroute.EvaluateRoute(evidence, registry, darwinRoutePolicy())
}
