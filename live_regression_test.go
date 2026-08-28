//go:build live_regression && ((darwin && cgo) || windows)

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	darwinroute "github.com/zanescope/v-local-key-provider/internal/platform/darwin"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const liveRegressionConsent = "I_HAVE_EXPLICIT_AUTHORIZATION"

func liveRequiredEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Fatalf("live regression requires %s", name)
	}
	return value
}

func clearLiveResponse(result *response) {
	if result == nil {
		return
	}
	for path := range result.DatabaseKeys {
		result.DatabaseKeys[path] = ""
	}
	if result.DatabaseCredential != nil {
		for index := range result.DatabaseCredential.Roots {
			result.DatabaseCredential.Roots[index].Secret = ""
		}
		for id, override := range result.DatabaseCredential.Overrides {
			override.Secret = ""
			result.DatabaseCredential.Overrides[id] = override
		}
	}
	if result.ImageKeys != nil {
		result.ImageKeys.AES = ""
		result.ImageKeys.XOR = 0
	}
}

func runLiveAcquisition(t *testing.T) response {
	t.Helper()
	if os.Getenv("V_LOCAL_KEY_PROVIDER_LIVE_CONSENT") != liveRegressionConsent {
		t.Fatal("live regression requires an explicit authorization acknowledgement")
	}
	privateConfig := loadLivePrivateConfig(t)
	binary := liveRequiredEnvironment(t, "V_LOCAL_KEY_PROVIDER_LIVE_BINARY")
	binary, err := filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(binary)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("live Provider binary is not a regular file: %v", err)
	}
	deadlineMS := int64(75_000)
	if configured := strings.TrimSpace(os.Getenv("V_LOCAL_KEY_PROVIDER_LIVE_DEADLINE_MS")); configured != "" {
		parsed, parseErr := strconv.ParseInt(configured, 10, 64)
		if parseErr != nil || parsed < 1_000 || parsed > maxBudgetMilliseconds {
			t.Fatalf("invalid live deadline %q", configured)
		}
		deadlineMS = parsed
	}
	scopes := []string{"database"}
	if configured := strings.TrimSpace(os.Getenv("V_LOCAL_KEY_PROVIDER_LIVE_SCOPES")); configured != "" {
		scopes = strings.Split(configured, ",")
	}
	request := acquireRequest{
		Protocol: protocolName, RequestID: "live-regression", Action: "acquire",
		CatalogKey: strings.Repeat("42", 32),
		AccountDir: privateConfig.AccountDir,
		DBDir:      privateConfig.DBDir,
		Scopes:     scopes, DeadlineMS: deadlineMS,
		Workflow: workflowRequest{Operation: "finalize"},
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	defer wipeLiveBytes(payload)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(deadlineMS)*time.Millisecond+30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "acquire")
	command.Dir = filepath.Dir(binary)
	command.Stdin = bytes.NewReader(payload)
	stdout := &limitedLiveBuffer{limit: maxResponseBytes}
	defer stdout.wipe()
	command.Stdout = stdout
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			t.Fatal("live Provider exceeded its regression deadline")
		}
		t.Fatalf("live Provider failed without exposing stderr: %v", err)
	}
	if stdout.over {
		t.Fatal("live Provider response exceeded the protocol limit")
	}
	var result response
	decoder := json.NewDecoder(bytes.NewReader(stdout.data.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatal("live Provider emitted trailing protocol data")
	}
	if result.Protocol != protocolName || result.RequestID != request.RequestID {
		t.Fatalf("live response binding mismatch: protocol=%q request_id=%q", result.Protocol, result.RequestID)
	}
	return result
}

type limitedLiveBuffer struct {
	data  bytes.Buffer
	limit int
	over  bool
}

func wipeLiveBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func (buffer *limitedLiveBuffer) wipe() {
	value := buffer.data.Bytes()
	wipeLiveBytes(value)
	buffer.data.Reset()
}

func (buffer *limitedLiveBuffer) Write(value []byte) (int, error) {
	remaining := buffer.limit - buffer.data.Len()
	if remaining > 0 {
		part := value
		if len(part) > remaining {
			part = part[:remaining]
		}
		_, _ = buffer.data.Write(part)
	}
	if len(value) > remaining {
		buffer.over = true
	}
	return len(value), nil
}

func assertLiveAcquisition(t *testing.T, result response) {
	t.Helper()
	defer clearLiveResponse(&result)
	if result.Diagnostics.Platform != runtime.GOOS {
		t.Fatalf("diagnostic platform=%q, runner=%q", result.Diagnostics.Platform, runtime.GOOS)
	}
	if result.CatalogID == "" || len(result.CatalogEntries) == 0 {
		t.Fatal("live response did not bind a database catalog")
	}
	expectedResult := liveRequiredEnvironment(t, "V_LOCAL_KEY_PROVIDER_LIVE_EXPECT_RESULT")
	expectedDatabaseCoverage := liveRequiredEnvironment(t, "V_LOCAL_KEY_PROVIDER_LIVE_EXPECT_DATABASE_COVERAGE")
	if result.Diagnostics.ResultCode != expectedResult || result.Diagnostics.DatabaseCoverageStatus != expectedDatabaseCoverage {
		t.Fatalf("live result=%s/%s, want %s/%s; next_action=%s route=%s",
			result.Diagnostics.ResultCode, result.Diagnostics.DatabaseCoverageStatus,
			expectedResult, expectedDatabaseCoverage, result.Diagnostics.NextAction, result.Diagnostics.RouteSelected)
	}
	if strings.Join(result.Diagnostics.RequestedScopes, ",") != "database,media" ||
		result.Diagnostics.MediaCoverageStatus != "complete" || result.ImageKeys == nil {
		t.Fatal("live regression requires complete database and media coverage")
	}
	if expected := strings.TrimSpace(os.Getenv("V_LOCAL_KEY_PROVIDER_LIVE_EXPECT_ROUTE")); expected != "" && result.Diagnostics.RouteSelected != expected {
		t.Fatalf("live route=%q, want %q", result.Diagnostics.RouteSelected, expected)
	}
	if expected := strings.TrimSpace(os.Getenv("V_LOCAL_KEY_PROVIDER_LIVE_EXPECT_PROCESS_ARCH")); expected != "" && result.Diagnostics.ProcessArchitecture != expected {
		t.Fatalf("target process architecture=%q, want %q", result.Diagnostics.ProcessArchitecture, expected)
	}
	if expected := strings.TrimSpace(os.Getenv("V_LOCAL_KEY_PROVIDER_LIVE_EXPECT_NEXT_ACTION")); expected != "" && result.Diagnostics.NextAction != expected {
		t.Fatalf("next_action=%q, want %q", result.Diagnostics.NextAction, expected)
	}
	entries := map[string]catalogDatabase{}
	for _, entry := range result.CatalogEntries {
		entries[entry.RelativePath] = entry
	}
	for path, key := range result.DatabaseKeys {
		entry, found := entries[path]
		if !found || entry.Classification != classificationEncrypted || len(key) != 64 {
			t.Fatal("a verified key is not bound to an eligible catalog entry")
		}
	}
	missing := map[string]bool{}
	for _, id := range result.Diagnostics.MissingDatabaseIDs {
		if len(id) != 64 || missing[id] {
			t.Fatal("live diagnostics contain a non-opaque or duplicate missing database ID")
		}
		missing[id] = true
	}
}

func writeLiveEvidence(t *testing.T, result response, processInventoryStable *bool) {
	t.Helper()
	path := strings.TrimSpace(os.Getenv("V_LOCAL_KEY_PROVIDER_LIVE_EVIDENCE_PATH"))
	if path == "" {
		return
	}
	binary := liveRequiredEnvironment(t, "V_LOCAL_KEY_PROVIDER_LIVE_BINARY")
	candidateSourceCommit := liveRequiredEnvironment(t, "V_LOCAL_KEY_PROVIDER_LIVE_CANDIDATE_SOURCE_COMMIT")
	candidateWorkflowRunID := liveRequiredEnvironment(t, "V_LOCAL_KEY_PROVIDER_LIVE_CANDIDATE_RUN_ID")
	candidateArtifactName := liveRequiredEnvironment(t, "V_LOCAL_KEY_PROVIDER_LIVE_CANDIDATE_ARTIFACT")
	candidateAttestationWorkflow := liveRequiredEnvironment(t, "V_LOCAL_KEY_PROVIDER_LIVE_CANDIDATE_ATTESTATION_WORKFLOW")
	if !validReleaseSourceCommit(candidateSourceCommit) || !validReleaseRunID(candidateWorkflowRunID) ||
		candidateAttestationWorkflow != releaseCandidateAttestationWorkflow ||
		strings.TrimSpace(os.Getenv("V_LOCAL_KEY_PROVIDER_LIVE_CANDIDATE_ATTESTATION_VERIFIED")) != "true" {
		t.Fatal("live evidence candidate provenance is incomplete or untrusted")
	}
	helperSHA256 := ""
	if runtime.GOOS == "darwin" {
		helper := liveRequiredEnvironment(t, "V_LOCAL_KEY_PROVIDER_LIVE_HELPER_BINARY")
		helperInfo, err := os.Lstat(helper)
		if err != nil || !helperInfo.Mode().IsRegular() {
			t.Fatalf("live Provider helper is not a regular file: %v", err)
		}
		helperSHA256 = executableSHA256(helper)
		if !validDarwinSHA256(helperSHA256) {
			t.Fatal("live Provider helper digest is unavailable")
		}
	}
	credentialProcessInstances := map[string]bool{}
	validatedProfileSet := map[string]bool{}
	for _, profileID := range result.DatabaseProfiles {
		if profileID != "" {
			validatedProfileSet[profileID] = true
		}
	}
	validatedProfiles := make([]string, 0, len(validatedProfileSet))
	for profileID := range validatedProfileSet {
		validatedProfiles = append(validatedProfiles, profileID)
	}
	sort.Strings(validatedProfiles)
	if result.DatabaseCredential != nil {
		for _, root := range result.DatabaseCredential.Roots {
			for _, instanceID := range root.ProcessInstanceIDs {
				credentialProcessInstances[instanceID] = true
			}
		}
		for _, override := range result.DatabaseCredential.Overrides {
			for _, instanceID := range override.ProcessInstanceIDs {
				credentialProcessInstances[instanceID] = true
			}
		}
	}
	falseValue := false
	trueValue := true
	evidence := releaseEvidenceArtifact{
		SchemaVersion:         1,
		QualificationOnly:     &falseValue,
		FormalReleaseEvidence: &trueValue,
		CandidateSourceCommit: candidateSourceCommit, CandidateWorkflowRunID: candidateWorkflowRunID,
		CandidateAttestationWorkflow: candidateAttestationWorkflow, CandidateAttestationVerified: true,
		PromotionVerified:     &falseValue,
		CandidateArtifactName: candidateArtifactName,
		RecordedAt:            time.Now().UTC().Format(time.RFC3339Nano),
		RunnerOS:              runtime.GOOS, RunnerArch: runtime.GOARCH, ProviderVersion: version,
		ProviderBinarySHA256: executableSHA256(binary), ProviderHelperSHA256: helperSHA256,
		WeChatVersion: result.Diagnostics.WeChatVersion, WeChatBuild: result.Diagnostics.WeChatBuild,
		TargetExecutableSHA256:       result.Diagnostics.ExecutableSHA256,
		BinaryFingerprintStatus:      result.Diagnostics.BinaryFingerprintStatus,
		BinarySigningStatus:          result.Diagnostics.BinarySigningStatus,
		BinarySignerSHA256:           result.Diagnostics.BinarySignerSHA256,
		BinaryProductIdentity:        result.Diagnostics.BinaryProductIdentity,
		SigningTeamID:                result.Diagnostics.SigningTeamID,
		DesignatedRequirementSHA256:  result.Diagnostics.DesignatedRequirementSHA256,
		ProcessArchitecture:          result.Diagnostics.ProcessArchitecture,
		ProcessArchitectureStatus:    result.Diagnostics.ProcessArchitectureStatus,
		ProcessInventoryStable:       processInventoryStable,
		CompatibilityRegistryStatus:  result.Diagnostics.CompatibilityRegistryStatus,
		ConfigCipherRouteStatus:      result.Diagnostics.ConfigCipherRouteStatus,
		StandardRouteStatus:          result.Diagnostics.StandardRouteStatus,
		StandardRouteEvidence:        append([]string(nil), result.Diagnostics.StandardRouteEvidence...),
		WindowsRouteEvidence:         append([]string(nil), result.Diagnostics.WindowsRouteEvidence...),
		RouteSelected:                result.Diagnostics.RouteSelected,
		RoutesAttempted:              append([]string(nil), result.Diagnostics.RoutesAttempted...),
		TargetBindingStatus:          result.Diagnostics.TargetBindingStatus,
		SessionAccountStatus:         result.Diagnostics.SessionAccountStatus,
		ResultCode:                   result.Diagnostics.ResultCode,
		RequestedScopes:              append([]string(nil), result.Diagnostics.RequestedScopes...),
		DatabaseCoverageStatus:       result.Diagnostics.DatabaseCoverageStatus,
		MediaCoverageStatus:          result.Diagnostics.MediaCoverageStatus,
		DatabaseCount:                result.Diagnostics.DatabaseCount,
		RequiredDatabaseCount:        result.Diagnostics.RequiredDatabaseCount,
		PlaintextDatabaseCount:       result.Diagnostics.PlaintextDatabaseCount,
		UnreadableDatabaseCount:      result.Diagnostics.UnreadableDatabaseCount,
		UnstableDatabaseCount:        result.Diagnostics.UnstableDatabaseCount,
		TruncatedDatabaseCount:       result.Diagnostics.TruncatedDatabaseCount,
		MatchedDatabaseCount:         result.Diagnostics.MatchedDatabaseCount,
		MissingDatabaseCount:         result.Diagnostics.MissingDatabaseCount,
		ProcessCount:                 result.Diagnostics.ProcessCount,
		SelectedProcessCount:         result.Diagnostics.SelectedProcessCount,
		TargetBoundProcessCount:      result.Diagnostics.TargetBoundProcessCount,
		OtherAccountProcessCount:     result.Diagnostics.OtherAccountProcessCount,
		UnknownAccountProcessCount:   result.Diagnostics.UnknownAccountProcessCount,
		OpenedProcessCount:           result.Diagnostics.OpenedProcessCount,
		AccessDeniedCount:            result.Diagnostics.AccessDeniedCount,
		PerProcessCollectorCount:     result.Diagnostics.PerProcessCollectorCount,
		CredentialProcessCount:       len(credentialProcessInstances),
		ConfigCipherStructureCount:   result.Diagnostics.ConfigCipherStructureCount,
		ConfigCipherInvalidCount:     result.Diagnostics.ConfigCipherInvalidCount,
		ConfigCipherCandidateCount:   result.Diagnostics.ConfigCipherCandidateCount,
		ConfigCipherVerifiedCount:    result.Diagnostics.ConfigCipherVerifiedCount,
		FallbackCandidateCount:       result.Diagnostics.FallbackCandidateCount,
		FallbackStageCounts:          result.Diagnostics.FallbackStageCounts,
		StaticScanFallback:           result.Diagnostics.StaticScanFallback,
		V2SampleCount:                result.Diagnostics.V2SampleCount,
		XORSampleCount:               result.Diagnostics.XORSampleCount,
		XORDistinctCandidateCount:    result.Diagnostics.XORDistinctCandidateCount,
		MediaAESCandidateCount:       result.Diagnostics.MediaAESCandidateCount,
		KVCommCodeCandidateCount:     result.Diagnostics.KVCommCodeCandidateCount,
		KVCommVerifiedCandidateCount: result.Diagnostics.KVCommVerifiedCandidateCount,
		MediaCandidateMethod:         result.Diagnostics.MediaCandidateMethod,
		PhaseTimingsMS:               result.Diagnostics.PhaseTimingsMS,
		ValidatedCipherProfiles:      validatedProfiles,
		SecretsIncluded:              &falseValue,
		PathsIncluded:                &falseValue,
		AccountIdentityIncluded:      &falseValue,
		ChatContentIncluded:          &falseValue,
	}
	if err := validateReleaseEvidenceArtifact(evidence); err != nil {
		t.Fatal("live evidence failed the release schema gate")
	}
	payload, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
		t.Fatal(err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(absolute, payload, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMacOSLiveAcquisition(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Phase 3 live regression only runs on macOS")
	}
	result := runLiveAcquisition(t)
	defer clearLiveResponse(&result)
	assertLiveAcquisition(t, result)
	diag := result.Diagnostics
	if diag.ProcessArchitectureStatus != darwinroute.ArchitectureVerified ||
		diag.ProcessArchitecture != liveRequiredEnvironment(t, "V_LOCAL_KEY_PROVIDER_LIVE_EXPECT_PROCESS_ARCH") {
		t.Fatal("Darwin live route lacks a verified target-process architecture")
	}
	if diag.BinaryFingerprintStatus != darwinroute.FingerprintVerified || !validDarwinSHA256(diag.ExecutableSHA256) ||
		diag.BinarySigningStatus != darwinroute.SigningVerified || diag.SigningTeamID == "" ||
		!validDarwinSHA256(diag.DesignatedRequirementSHA256) {
		t.Fatal("Darwin live route lacks a verified binary and signing identity")
	}
	if diag.CompatibilityRegistryStatus != darwinroute.RegistryRegisteredSupported ||
		diag.StandardRouteStatus != darwinroute.StandardEligibleRegistry ||
		!containsString(diag.StandardRouteEvidence, "registry_exact_match") ||
		!containsString(diag.StandardRouteEvidence, "registry_candidate_entry") {
		t.Fatal("Darwin live route is not bound to the exact candidate registry entry")
	}
	writeLiveEvidence(t, result, nil)
}
