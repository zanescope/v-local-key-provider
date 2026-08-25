// Package releaseevidence validates content-addressed live-regression evidence
// and its external release promotion manifest.
package releaseevidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	MaxArtifactBytes             = 1024 * 1024
	CandidateAttestationWorkflow = "zanescope/v-local-key-provider/.github/workflows/release-candidate.yml"
)

type PromotionTarget struct {
	Platform             string   `json:"platform"`
	Architecture         string   `json:"architecture"`
	ProviderArtifactName string   `json:"provider_artifact_name"`
	ProviderSHA256       string   `json:"provider_sha256"`
	HelperArtifactName   string   `json:"helper_artifact_name,omitempty"`
	HelperSHA256         string   `json:"helper_sha256,omitempty"`
	EvidenceSHA256       []string `json:"evidence_sha256"`
}

type PromotionManifest struct {
	SchemaVersion                int               `json:"schema_version"`
	ProviderVersion              string            `json:"provider_version"`
	CandidateSourceCommit        string            `json:"candidate_source_commit"`
	CandidateWorkflowRunID       string            `json:"candidate_workflow_run_id"`
	CandidateAttestationWorkflow string            `json:"candidate_attestation_workflow"`
	Targets                      []PromotionTarget `json:"targets"`
}

type EvidenceArtifact struct {
	SchemaVersion                int      `json:"schema_version"`
	CandidateSourceCommit        string   `json:"candidate_source_commit"`
	CandidateWorkflowRunID       string   `json:"candidate_workflow_run_id"`
	CandidateAttestationWorkflow string   `json:"candidate_attestation_workflow"`
	CandidateAttestationVerified bool     `json:"candidate_attestation_verified"`
	CandidateArtifactName        string   `json:"candidate_artifact_name"`
	RunnerOS                     string   `json:"runner_os"`
	RunnerArch                   string   `json:"runner_arch"`
	ProviderVersion              string   `json:"provider_version"`
	ProviderBinarySHA256         string   `json:"provider_binary_sha256"`
	ProviderHelperSHA256         string   `json:"provider_helper_sha256"`
	WeChatVersion                string   `json:"wechat_version"`
	WeChatBuild                  string   `json:"wechat_build"`
	TargetExecutableSHA256       string   `json:"target_executable_sha256"`
	BinaryFingerprintStatus      string   `json:"binary_fingerprint_status"`
	BinarySigningStatus          string   `json:"binary_signing_status"`
	BinarySignerSHA256           string   `json:"binary_signer_sha256"`
	BinaryProductIdentity        string   `json:"binary_product_identity"`
	SigningTeamID                string   `json:"signing_team_id"`
	DesignatedRequirementSHA256  string   `json:"designated_requirement_sha256"`
	ProcessArchitecture          string   `json:"process_architecture"`
	ProcessArchitectureStatus    string   `json:"process_architecture_status"`
	CompatibilityRegistryStatus  string   `json:"compatibility_registry_status"`
	ConfigCipherRouteStatus      string   `json:"config_cipher_route_status"`
	StandardRouteStatus          string   `json:"standard_route_status"`
	StandardRouteEvidence        []string `json:"standard_route_evidence"`
	WindowsRouteEvidence         []string `json:"windows_route_evidence"`
	RouteSelected                string   `json:"route_selected"`
	TargetBindingStatus          string   `json:"target_binding_status"`
	ResultCode                   string   `json:"result_code"`
	DatabaseCoverageStatus       string   `json:"database_coverage_status"`
	ValidatedCipherProfiles      []string `json:"validated_cipher_profiles"`
}

// RegistryEntry is the release-evidence projection of one runtime registry
// entry. The command layer supplies only entries already eligible under its
// platform and profile policy.
type RegistryEntry struct {
	Platform                        string
	Architecture                    string
	WeChatVersion                   string
	WeChatBuild                     string
	TargetExecutableSHA256          string
	BinarySignerSHA256              string
	BinaryProductIdentity           string
	SigningTeamID                   string
	DesignatedRequirementSHA256     string
	AllowedTargetBindingStatuses    []string
	RequiredConfigCipherRouteStatus string
	RequiredStandardRouteStatus     string
	AllowedRoutes                   []string
	RequiredRouteEvidence           string
	ValidatedCipherProfiles         []string
}

type ValidationInput struct {
	Root            string
	PromotionPath   string
	Platform        string
	Architecture    string
	ProviderVersion string
	RegistryEntries []RegistryEntry
}

func invalid(reason string) error {
	return fmt.Errorf("release evidence %s: %w", reason, os.ErrInvalid)
}

func ValidSourceCommit(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	return value == strings.ToLower(value) && ValidHex(value)
}

func ValidRunID(value string) bool {
	if value == "" || value[0] == '0' {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func ValidHex(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil
}

func ValidSHA256(value string) bool {
	if len(value) != 64 || value != strings.TrimSpace(value) || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func CandidateProviderAsset(platform, architecture string) string {
	switch platform {
	case "windows":
		return "v-local-key-provider-windows-" + architecture + ".exe"
	case "darwin":
		return "v-local-key-provider-darwin-" + architecture
	default:
		return ""
	}
}

func CandidateHelperAsset(platform, architecture string) string {
	if platform == "darwin" {
		return "v-local-key-provider-helper-darwin-" + architecture
	}
	return ""
}

func readRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > MaxArtifactBytes {
		return nil, invalid("artifact is not a bounded regular file")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 || len(payload) > MaxArtifactBytes {
		return nil, invalid("artifact size is outside the allowed range")
	}
	return payload, nil
}

func decodeStrict(payload []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return invalid("artifact contains trailing JSON")
	}
	return nil
}

func ReadEvidenceFile(root, digest, providerVersion string) (EvidenceArtifact, error) {
	if !ValidSHA256(digest) {
		return EvidenceArtifact{}, invalid("digest is not a canonical SHA-256")
	}
	payload, err := readRegularFile(filepath.Join(root, digest+".json"))
	if err != nil {
		return EvidenceArtifact{}, err
	}
	actual := sha256.Sum256(payload)
	if hex.EncodeToString(actual[:]) != digest {
		return EvidenceArtifact{}, invalid("content digest does not match filename")
	}
	var evidence EvidenceArtifact
	if err := decodeStrict(payload, &evidence); err != nil {
		return EvidenceArtifact{}, err
	}
	if evidence.SchemaVersion != 2 || evidence.ProviderVersion != providerVersion ||
		!ValidSourceCommit(evidence.CandidateSourceCommit) ||
		!ValidRunID(evidence.CandidateWorkflowRunID) ||
		evidence.CandidateAttestationWorkflow != CandidateAttestationWorkflow ||
		!evidence.CandidateAttestationVerified || evidence.CandidateArtifactName == "" ||
		!ValidSHA256(evidence.ProviderBinarySHA256) ||
		evidence.BinaryFingerprintStatus != "verified" || evidence.BinarySigningStatus != "verified" ||
		evidence.ProcessArchitectureStatus != "verified_running_process" ||
		evidence.CompatibilityRegistryStatus != "registered_supported" ||
		evidence.RouteSelected == "" || evidence.ResultCode != "complete" ||
		evidence.DatabaseCoverageStatus != "complete" || len(evidence.ValidatedCipherProfiles) == 0 {
		return EvidenceArtifact{}, invalid("artifact does not satisfy the live evidence schema")
	}
	return evidence, nil
}

func SameProfiles(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	values := make(map[string]bool, len(actual))
	for _, value := range actual {
		if strings.TrimSpace(value) != value || value == "" || values[value] {
			return false
		}
		values[value] = true
	}
	for _, value := range expected {
		if !values[value] {
			return false
		}
	}
	return true
}

func ReadPromotionFile(root, path, providerVersion string) (PromotionManifest, string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return PromotionManifest{}, "", err
	}
	promotionsRoot := filepath.Join(root, "promotions")
	path, err = filepath.Abs(path)
	if err != nil {
		return PromotionManifest{}, "", err
	}
	relative, err := filepath.Rel(promotionsRoot, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return PromotionManifest{}, "", invalid("promotion path escapes the promotions directory")
	}
	payload, err := readRegularFile(path)
	if err != nil {
		return PromotionManifest{}, "", err
	}
	var promotion PromotionManifest
	if err := decodeStrict(payload, &promotion); err != nil {
		return PromotionManifest{}, "", err
	}
	if promotion.SchemaVersion != 1 || promotion.ProviderVersion != providerVersion ||
		!ValidSourceCommit(promotion.CandidateSourceCommit) ||
		!ValidRunID(promotion.CandidateWorkflowRunID) ||
		promotion.CandidateAttestationWorkflow != CandidateAttestationWorkflow || len(promotion.Targets) == 0 {
		return PromotionManifest{}, "", invalid("promotion manifest is incomplete")
	}
	targets := make(map[string]bool, len(promotion.Targets))
	evidenceDigests := map[string]bool{}
	for _, target := range promotion.Targets {
		key := target.Platform + "/" + target.Architecture
		if targets[key] || (target.Platform != "windows" && target.Platform != "darwin") ||
			(target.Architecture != "amd64" && target.Architecture != "arm64") ||
			target.ProviderArtifactName != CandidateProviderAsset(target.Platform, target.Architecture) ||
			!ValidSHA256(target.ProviderSHA256) || len(target.EvidenceSHA256) == 0 {
			return PromotionManifest{}, "", invalid("promotion target is invalid or duplicated")
		}
		expectedHelper := CandidateHelperAsset(target.Platform, target.Architecture)
		if target.HelperArtifactName != expectedHelper ||
			(expectedHelper == "" && target.HelperSHA256 != "") ||
			(expectedHelper != "" && !ValidSHA256(target.HelperSHA256)) {
			return PromotionManifest{}, "", invalid("promotion helper binding is invalid")
		}
		targets[key] = true
		perTargetEvidence := map[string]bool{}
		for _, digest := range target.EvidenceSHA256 {
			if !ValidSHA256(digest) || perTargetEvidence[digest] || evidenceDigests[digest] {
				return PromotionManifest{}, "", invalid("promotion evidence digest is invalid or duplicated")
			}
			perTargetEvidence[digest] = true
			evidenceDigests[digest] = true
		}
	}
	digest := sha256.Sum256(payload)
	return promotion, hex.EncodeToString(digest[:]), nil
}

func PromotionTargetFor(promotion PromotionManifest, platform, architecture string) (PromotionTarget, error) {
	var selected *PromotionTarget
	for index := range promotion.Targets {
		target := &promotion.Targets[index]
		if target.Platform == platform && target.Architecture == architecture {
			if selected != nil {
				return PromotionTarget{}, invalid("promotion contains duplicate target")
			}
			selected = target
		}
	}
	if selected == nil {
		return PromotionTarget{}, os.ErrNotExist
	}
	return *selected, nil
}

func EvidenceMatchesPromotion(evidence EvidenceArtifact, promotion PromotionManifest, target PromotionTarget) bool {
	return evidence.CandidateSourceCommit == promotion.CandidateSourceCommit &&
		evidence.CandidateWorkflowRunID == promotion.CandidateWorkflowRunID &&
		evidence.CandidateAttestationWorkflow == promotion.CandidateAttestationWorkflow &&
		evidence.CandidateArtifactName == target.ProviderArtifactName &&
		evidence.RunnerOS == target.Platform && evidence.RunnerArch == target.Architecture &&
		evidence.ProviderBinarySHA256 == target.ProviderSHA256 &&
		evidence.ProviderHelperSHA256 == target.HelperSHA256
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func validRegistryEntry(entry RegistryEntry, platform, architecture string) bool {
	if entry.Platform != platform || entry.Architecture != architecture ||
		entry.WeChatVersion == "" || entry.WeChatBuild == "" ||
		!ValidSHA256(entry.TargetExecutableSHA256) || len(entry.ValidatedCipherProfiles) == 0 ||
		len(entry.AllowedTargetBindingStatuses) == 0 || len(entry.AllowedRoutes) == 0 ||
		entry.RequiredRouteEvidence == "" || !SameProfiles(entry.ValidatedCipherProfiles, entry.ValidatedCipherProfiles) {
		return false
	}
	switch platform {
	case "windows":
		return ValidSHA256(entry.BinarySignerSHA256) && entry.BinaryProductIdentity != "" &&
			entry.RequiredConfigCipherRouteStatus != "" && entry.RequiredStandardRouteStatus == ""
	case "darwin":
		return entry.SigningTeamID != "" && ValidSHA256(entry.DesignatedRequirementSHA256) &&
			entry.RequiredStandardRouteStatus != "" && entry.RequiredConfigCipherRouteStatus == ""
	default:
		return false
	}
}

func evidenceMatchesRegistryEntry(evidence EvidenceArtifact, entry RegistryEntry) bool {
	if evidence.RunnerOS != entry.Platform || evidence.RunnerArch != entry.Architecture ||
		evidence.ProcessArchitecture != entry.Architecture ||
		evidence.WeChatVersion != entry.WeChatVersion || evidence.WeChatBuild != entry.WeChatBuild ||
		evidence.TargetExecutableSHA256 != entry.TargetExecutableSHA256 ||
		!contains(entry.AllowedTargetBindingStatuses, evidence.TargetBindingStatus) ||
		!contains(entry.AllowedRoutes, evidence.RouteSelected) ||
		!SameProfiles(evidence.ValidatedCipherProfiles, entry.ValidatedCipherProfiles) {
		return false
	}
	switch entry.Platform {
	case "windows":
		return evidence.BinarySignerSHA256 == entry.BinarySignerSHA256 &&
			evidence.BinaryProductIdentity == entry.BinaryProductIdentity &&
			evidence.ConfigCipherRouteStatus == entry.RequiredConfigCipherRouteStatus &&
			contains(evidence.WindowsRouteEvidence, entry.RequiredRouteEvidence)
	case "darwin":
		return evidence.SigningTeamID == entry.SigningTeamID &&
			evidence.DesignatedRequirementSHA256 == entry.DesignatedRequirementSHA256 &&
			evidence.StandardRouteStatus == entry.RequiredStandardRouteStatus &&
			contains(evidence.StandardRouteEvidence, entry.RequiredRouteEvidence)
	default:
		return false
	}
}

func ValidateArtifacts(input ValidationInput) error {
	if input.Platform != strings.ToLower(strings.TrimSpace(input.Platform)) ||
		input.Architecture != strings.ToLower(strings.TrimSpace(input.Architecture)) ||
		(input.Platform != "windows" && input.Platform != "darwin") ||
		(input.Architecture != "amd64" && input.Architecture != "arm64") || input.ProviderVersion == "" {
		return invalid("validation target is invalid")
	}
	promotion, _, err := ReadPromotionFile(input.Root, input.PromotionPath, input.ProviderVersion)
	if err != nil {
		return err
	}
	target, err := PromotionTargetFor(promotion, input.Platform, input.Architecture)
	if err != nil {
		return err
	}
	if len(input.RegistryEntries) == 0 {
		return os.ErrNotExist
	}
	for _, entry := range input.RegistryEntries {
		if !validRegistryEntry(entry, input.Platform, input.Architecture) {
			return invalid("eligible registry projection is invalid")
		}
	}
	coveredEntries := map[int]bool{}
	for _, digest := range target.EvidenceSHA256 {
		evidence, err := ReadEvidenceFile(input.Root, digest, input.ProviderVersion)
		if err != nil {
			return err
		}
		if !EvidenceMatchesPromotion(evidence, promotion, target) {
			return invalid("artifact does not match its external promotion")
		}
		matchedEntry := -1
		for index, entry := range input.RegistryEntries {
			if !evidenceMatchesRegistryEntry(evidence, entry) {
				continue
			}
			if matchedEntry >= 0 {
				return invalid("artifact ambiguously matches multiple registry entries")
			}
			matchedEntry = index
		}
		if matchedEntry < 0 || coveredEntries[matchedEntry] {
			return invalid("artifact does not uniquely cover one registry entry")
		}
		coveredEntries[matchedEntry] = true
	}
	if len(coveredEntries) != len(input.RegistryEntries) {
		return invalid("promotion does not cover every eligible registry entry")
	}
	return nil
}
