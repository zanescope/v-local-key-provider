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
		SchemaVersion: 2, CandidateSourceCommit: strings.Repeat("a", 40), CandidateWorkflowRunID: "12345",
		CandidateAttestationWorkflow: CandidateAttestationWorkflow, CandidateAttestationVerified: true,
		CandidateArtifactName: CandidateProviderAsset("windows", "amd64"), RunnerOS: "windows", RunnerArch: "amd64",
		ProviderVersion: fixtureProviderVersion, ProviderBinarySHA256: strings.Repeat("b", 64),
		WeChatVersion: "4.0.0", WeChatBuild: "fixture", TargetExecutableSHA256: strings.Repeat("c", 64),
		BinaryFingerprintStatus: "verified", BinarySigningStatus: "verified", BinarySignerSHA256: strings.Repeat("d", 64),
		BinaryProductIdentity: "wechat.exe|wechat.exe|wechat|tencent", ProcessArchitecture: "amd64",
		ProcessArchitectureStatus: "verified_running_process", CompatibilityRegistryStatus: "registered_supported",
		ConfigCipherRouteStatus: "succeeded", WindowsRouteEvidence: []string{"registry_candidate_entry", "registry_exact_match"},
		RouteSelected: "windows_config_cipher", TargetBindingStatus: "path_verified", ResultCode: "complete",
		DatabaseCoverageStatus: "complete", ValidatedCipherProfiles: []string{"sqlcipher-v4"},
	}
}

func fixtureWindowsEntry() RegistryEntry {
	return RegistryEntry{
		Platform: "windows", Architecture: "amd64", WeChatVersion: "4.0.0", WeChatBuild: "fixture",
		TargetExecutableSHA256: strings.Repeat("c", 64), BinarySignerSHA256: strings.Repeat("d", 64),
		BinaryProductIdentity:           "wechat.exe|wechat.exe|wechat|tencent",
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
