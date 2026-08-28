package releaseevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtureProviderVersion = "0.0.0-test"

func fixtureBoolean(value bool) *bool { return &value }

func writeJSONArtifact(t *testing.T, path string, value any) ([]byte, string) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	digestBytes := sha256.Sum256(payload)
	digest := hex.EncodeToString(digestBytes[:])
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return payload, digest
}

func fixtureWindowsEvidence() EvidenceArtifact {
	return EvidenceArtifact{
		SchemaVersion: 1, QualificationOnly: fixtureBoolean(false), FormalReleaseEvidence: fixtureBoolean(true),
		CandidateSourceCommit: strings.Repeat("a", 40), CandidateWorkflowRunID: "12345",
		CandidateAttestationWorkflow: CandidateAttestationWorkflow, CandidateAttestationVerified: true,
		PromotionVerified:     fixtureBoolean(false),
		CandidateArtifactName: CandidateProviderAsset("windows", "amd64"), RunnerOS: "windows", RunnerArch: "amd64",
		RecordedAt:      "2026-01-01T00:00:00Z",
		ProviderVersion: fixtureProviderVersion, ProviderBinarySHA256: strings.Repeat("b", 64),
		WeChatVersion: "4.0.0", WeChatBuild: "fixture", TargetExecutableSHA256: strings.Repeat("c", 64),
		BinaryFingerprintStatus: "verified", BinarySigningStatus: "verified", BinarySignerSHA256: strings.Repeat("d", 64),
		BinaryProductIdentity: "wechat.exe", ProcessArchitecture: "amd64",
		ProcessArchitectureStatus: "verified_running_process", CompatibilityRegistryStatus: "registered_supported",
		ProcessInventoryStable:  fixtureBoolean(true),
		ConfigCipherRouteStatus: "succeeded", WindowsRouteEvidence: []string{"registry_candidate_entry", "registry_exact_match"},
		RouteSelected: "windows_config_cipher", TargetBindingStatus: "path_verified", ResultCode: "complete",
		RequestedScopes: []string{"database", "media"}, DatabaseCoverageStatus: "complete", MediaCoverageStatus: "complete",
		DatabaseCount: 1, RequiredDatabaseCount: 1, MatchedDatabaseCount: 1, ValidatedCipherProfiles: []string{"sqlcipher-v4"},
		SecretsIncluded: fixtureBoolean(false), PathsIncluded: fixtureBoolean(false),
		AccountIdentityIncluded: fixtureBoolean(false), ChatContentIncluded: fixtureBoolean(false),
	}
}

func fixtureWindowsEntry() RegistryEntry {
	return RegistryEntry{
		Platform: "windows", Architecture: "amd64", WeChatVersion: "4.0.0", WeChatBuild: "fixture",
		TargetExecutableSHA256: strings.Repeat("c", 64), BinarySignerSHA256: strings.Repeat("d", 64),
		BinaryProductIdentity:           "wechat.exe",
		AllowedTargetBindingStatuses:    []string{"hmac_verified", "path_verified"},
		RequiredConfigCipherRouteStatus: "succeeded", AllowedRoutes: []string{"windows_config_cipher"},
		RequiredRouteEvidence: "registry_candidate_entry", ValidatedCipherProfiles: []string{"sqlcipher-v4"},
	}
}

func writeFixtureSet(t *testing.T, evidence EvidenceArtifact) (string, string) {
	t.Helper()
	root := t.TempDir()
	payload, digest := writeJSONArtifact(t, filepath.Join(root, "pending.json"), evidence)
	if err := os.Rename(filepath.Join(root, "pending.json"), filepath.Join(root, digest+".json")); err != nil {
		t.Fatal(err)
	}
	if len(payload) == 0 {
		t.Fatal("empty fixture payload")
	}
	promotion := PromotionManifest{
		SchemaVersion: 1, ProviderVersion: fixtureProviderVersion,
		CandidateSourceCommit: evidence.CandidateSourceCommit, CandidateWorkflowRunID: evidence.CandidateWorkflowRunID,
		CandidateAttestationWorkflow: CandidateAttestationWorkflow,
		Targets: []PromotionTarget{{
			Platform: "windows", Architecture: "amd64", ProviderArtifactName: evidence.CandidateArtifactName,
			ProviderSHA256: evidence.ProviderBinarySHA256, EvidenceSHA256: []string{digest},
		}},
	}
	promotions := filepath.Join(root, "promotions")
	if err := os.Mkdir(promotions, 0o700); err != nil {
		t.Fatal(err)
	}
	promotionPath := filepath.Join(promotions, "fixture.json")
	writeJSONArtifact(t, promotionPath, promotion)
	return root, promotionPath
}

func TestValidateArtifactsBindsPromotionEvidenceAndRegistry(t *testing.T) {
	root, promotionPath := writeFixtureSet(t, fixtureWindowsEvidence())
	input := ValidationInput{
		Root: root, PromotionPath: promotionPath, Platform: "windows", Architecture: "amd64",
		ProviderVersion: fixtureProviderVersion, RegistryEntries: []RegistryEntry{fixtureWindowsEntry()},
	}
	if err := ValidateArtifacts(input); err != nil {
		t.Fatalf("valid externally promoted evidence was rejected: %v", err)
	}
	input.RegistryEntries = nil
	if err := ValidateArtifacts(input); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty eligible registry error = %v, want os.ErrNotExist", err)
	}
}

func TestValidateArtifactsRejectsRouteMismatchAndPromotionEscape(t *testing.T) {
	evidence := fixtureWindowsEvidence()
	evidence.RouteSelected = "windows_memory_fallback"
	root, promotionPath := writeFixtureSet(t, evidence)
	input := ValidationInput{
		Root: root, PromotionPath: promotionPath, Platform: "windows", Architecture: "amd64",
		ProviderVersion: fixtureProviderVersion, RegistryEntries: []RegistryEntry{fixtureWindowsEntry()},
	}
	if err := ValidateArtifacts(input); err == nil {
		t.Fatal("route-mismatched evidence was accepted")
	}
	input.PromotionPath = filepath.Join(root, "outside.json")
	writeJSONArtifact(t, input.PromotionPath, PromotionManifest{})
	if err := ValidateArtifacts(input); err == nil {
		t.Fatal("promotion outside the promotions directory was accepted")
	}
}

func TestValidateArtifactsRequiresCompleteMediaAndRedaction(t *testing.T) {
	variants := []struct {
		name   string
		mutate func(*EvidenceArtifact)
	}{
		{name: "media scope", mutate: func(value *EvidenceArtifact) { value.RequestedScopes = []string{"database"} }},
		{name: "media coverage", mutate: func(value *EvidenceArtifact) { value.MediaCoverageStatus = "none" }},
		{name: "database count", mutate: func(value *EvidenceArtifact) { value.DatabaseCount = 0 }},
		{name: "candidate asset", mutate: func(value *EvidenceArtifact) { value.CandidateArtifactName = "other.exe" }},
		{name: "target fingerprint", mutate: func(value *EvidenceArtifact) { value.TargetExecutableSHA256 = "" }},
		{name: "secrets", mutate: func(value *EvidenceArtifact) { value.SecretsIncluded = fixtureBoolean(true) }},
		{name: "paths", mutate: func(value *EvidenceArtifact) { value.PathsIncluded = fixtureBoolean(true) }},
		{name: "account", mutate: func(value *EvidenceArtifact) { value.AccountIdentityIncluded = fixtureBoolean(true) }},
		{name: "chat", mutate: func(value *EvidenceArtifact) { value.ChatContentIncluded = fixtureBoolean(true) }},
	}
	for _, test := range variants {
		t.Run(test.name, func(t *testing.T) {
			evidence := fixtureWindowsEvidence()
			test.mutate(&evidence)
			root, promotionPath := writeFixtureSet(t, evidence)
			input := ValidationInput{
				Root: root, PromotionPath: promotionPath, Platform: "windows", Architecture: "amd64",
				ProviderVersion: fixtureProviderVersion, RegistryEntries: []RegistryEntry{fixtureWindowsEntry()},
			}
			if err := ValidateArtifacts(input); err == nil {
				t.Fatal("incomplete or unredacted live evidence was accepted")
			}
		})
	}
}

func TestValidateArtifactsBindsReviewedNoStructureFallbackEvidence(t *testing.T) {
	evidence := fixtureWindowsEvidence()
	evidence.ConfigCipherRouteStatus = "reviewed_no_structure"
	evidence.RouteSelected = "windows_memory_fallback"
	evidence.StaticScanFallback = true
	evidence.FallbackStageCounts = map[string]int{"readonly_private": 1}
	evidence.PerProcessCollectorCount = 1
	evidence.FallbackCandidateCount = 1
	entry := fixtureWindowsEntry()
	entry.RequiredConfigCipherRouteStatus = "reviewed_no_structure"
	entry.AllowedRoutes = []string{"windows_memory_fallback"}
	root, promotionPath := writeFixtureSet(t, evidence)
	input := ValidationInput{
		Root: root, PromotionPath: promotionPath, Platform: "windows", Architecture: "amd64",
		ProviderVersion: fixtureProviderVersion, RegistryEntries: []RegistryEntry{entry},
	}
	if err := ValidateArtifacts(input); err != nil {
		t.Fatalf("bounded reviewed-no-structure fallback evidence was rejected: %v", err)
	}

	for _, mutate := range []func(*EvidenceArtifact){
		func(value *EvidenceArtifact) { value.StaticScanFallback = false },
		func(value *EvidenceArtifact) { value.FallbackStageCounts = nil },
		func(value *EvidenceArtifact) { value.ConfigCipherCandidateCount = 1 },
	} {
		invalid := evidence
		mutate(&invalid)
		variantRoot, variantPromotion := writeFixtureSet(t, invalid)
		input.Root = variantRoot
		input.PromotionPath = variantPromotion
		if err := ValidateArtifacts(input); err == nil {
			t.Fatal("unbounded or contradictory fallback evidence was accepted")
		}
	}
}

func TestReleaseIdentifiersAreCanonical(t *testing.T) {
	if !ValidSourceCommit(strings.Repeat("a", 40)) || ValidSourceCommit(strings.Repeat("A", 40)) {
		t.Fatal("source commit canonicalization is incorrect")
	}
	if !ValidRunID("12345") || ValidRunID("0123") || ValidRunID("12x") {
		t.Fatal("workflow run id validation is incorrect")
	}
	if !SameProfiles([]string{"b", "a"}, []string{"a", "b"}) || SameProfiles([]string{"a", "a"}, []string{"a", "a"}) {
		t.Fatal("profile set validation is incorrect")
	}
}
