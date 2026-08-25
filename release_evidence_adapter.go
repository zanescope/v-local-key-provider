package provider

import releaseevidence "github.com/zanescope/v-local-key-provider/internal/releaseevidence"

const releaseCandidateAttestationWorkflow = releaseevidence.CandidateAttestationWorkflow

type releasePromotionTarget = releaseevidence.PromotionTarget
type releasePromotionManifest = releaseevidence.PromotionManifest
type releaseEvidenceArtifact = releaseevidence.EvidenceArtifact

func validReleaseSourceCommit(value string) bool {
	return releaseevidence.ValidSourceCommit(value)
}

func validReleaseRunID(value string) bool {
	return releaseevidence.ValidRunID(value)
}

func validHex(value string) bool {
	return releaseevidence.ValidHex(value)
}

func releaseCandidateProviderAsset(platform, architecture string) string {
	return releaseevidence.CandidateProviderAsset(platform, architecture)
}

func releaseCandidateHelperAsset(platform, architecture string) string {
	return releaseevidence.CandidateHelperAsset(platform, architecture)
}

func releaseEvidenceFile(root, digest string) (releaseEvidenceArtifact, error) {
	return releaseevidence.ReadEvidenceFile(root, digest, version)
}

func sameReleaseProfiles(actual, expected []string) bool {
	return releaseevidence.SameProfiles(actual, expected)
}

func releaseDarwinRouteMatches(architecture, route string) bool {
	return route == darwinDynamicRouteID(architecture, "") || route == "darwin_standard_dynamic_waitfor"
}

func releasePromotionFile(root, path string) (releasePromotionManifest, string, error) {
	return releaseevidence.ReadPromotionFile(root, path, version)
}

func releasePromotionTargetFor(promotion releasePromotionManifest, platform, architecture string) (releasePromotionTarget, error) {
	return releaseevidence.PromotionTargetFor(promotion, platform, architecture)
}

func releaseEvidenceMatchesPromotion(evidence releaseEvidenceArtifact, promotion releasePromotionManifest, target releasePromotionTarget) bool {
	return releaseevidence.EvidenceMatchesPromotion(evidence, promotion, target)
}

func releaseEvidenceRegistryEntries(platform, architecture string) []releaseevidence.RegistryEntry {
	entries := []releaseevidence.RegistryEntry{}
	switch platform {
	case "windows":
		for _, entry := range windowsCompatibilityRegistry {
			if entry.ProcessArchitecture != architecture || !windowsRegistryEntryEligible(entry) {
				continue
			}
			entries = append(entries, releaseevidence.RegistryEntry{
				Platform:                        "windows",
				Architecture:                    entry.ProcessArchitecture,
				WeChatVersion:                   entry.Version,
				WeChatBuild:                     entry.Build,
				TargetExecutableSHA256:          entry.ExecutableSHA256,
				BinarySignerSHA256:              entry.BinarySignerSHA256,
				BinaryProductIdentity:           entry.ProductIdentity,
				AllowedTargetBindingStatuses:    []string{"hmac_verified", "path_verified"},
				RequiredConfigCipherRouteStatus: windowsConfigCipherSucceeded,
				AllowedRoutes:                   []string{"windows_config_cipher"},
				RequiredRouteEvidence:           "registry_candidate_entry",
				ValidatedCipherProfiles:         append([]string(nil), entry.ValidatedProfiles...),
			})
		}
	case "darwin":
		for _, entry := range darwinCompatibilityRegistry {
			if entry.ProcessArchitecture != architecture || !darwinRegistryEntryEligible(entry) {
				continue
			}
			entries = append(entries, releaseevidence.RegistryEntry{
				Platform:                     "darwin",
				Architecture:                 entry.ProcessArchitecture,
				WeChatVersion:                entry.Version,
				WeChatBuild:                  entry.Build,
				TargetExecutableSHA256:       entry.ExecutableSHA256,
				SigningTeamID:                entry.SigningTeamID,
				DesignatedRequirementSHA256:  entry.DesignatedRequirementSHA256,
				AllowedTargetBindingStatuses: []string{"hmac_verified", "path_verified"},
				RequiredStandardRouteStatus:  darwinStandardEligibleRegistry,
				AllowedRoutes:                []string{darwinDynamicRouteID(entry.ProcessArchitecture, ""), "darwin_standard_dynamic_waitfor"},
				RequiredRouteEvidence:        "registry_candidate_entry",
				ValidatedCipherProfiles:      append([]string(nil), entry.ValidatedCipherProfiles...),
			})
		}
	}
	return entries
}

func validateReleaseEvidenceArtifacts(root, promotionPath, platform, architecture string) error {
	return releaseevidence.ValidateArtifacts(releaseevidence.ValidationInput{
		Root:            root,
		PromotionPath:   promotionPath,
		Platform:        platform,
		Architecture:    architecture,
		ProviderVersion: version,
		RegistryEntries: releaseEvidenceRegistryEntries(platform, architecture),
	})
}
