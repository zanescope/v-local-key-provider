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

const liveDiagnosticKind = "live_regression_diagnostic"

type liveCandidateProvenance struct {
	SourceCommit        string
	WorkflowRunID       string
	AttestationWorkflow string
	AttestationVerified bool
}

type liveDiagnosticArtifact struct {
	SchemaVersion                int              `json:"schema_version"`
	ArtifactKind                 string           `json:"artifact_kind"`
	QualificationOnly            bool             `json:"qualification_only"`
	FormalReleaseEvidence        bool             `json:"formal_release_evidence"`
	CandidateSourceCommit        string           `json:"candidate_source_commit"`
	CandidateWorkflowRunID       string           `json:"candidate_workflow_run_id"`
	CandidateAttestationWorkflow string           `json:"candidate_attestation_workflow"`
	CandidateAttestationVerified bool             `json:"candidate_attestation_verified"`
	PromotionVerified            bool             `json:"promotion_verified"`
	RecordedAt                   string           `json:"recorded_at"`
	RunnerOS                     string           `json:"runner_os"`
	RunnerArch                   string           `json:"runner_arch"`
	ResultCode                   string           `json:"result_code"`
	WorkflowStatus               string           `json:"workflow_status"`
	NextAction                   string           `json:"next_action"`
	RequestedScopes              []string         `json:"requested_scopes"`
	DatabaseCoverageStatus       string           `json:"database_coverage_status"`
	MediaCoverageStatus          string           `json:"media_coverage_status"`
	RouteSelected                string           `json:"route_selected"`
	RoutesAttempted              []string         `json:"routes_attempted"`
	CompatibilityRegistryStatus  string           `json:"compatibility_registry_status"`
	ConfigCipherRouteStatus      string           `json:"config_cipher_route_status"`
	TargetBindingStatus          string           `json:"target_binding_status"`
	ProcessArchitecture          string           `json:"process_architecture"`
	ProcessArchitectureStatus    string           `json:"process_architecture_status"`
	ProcessInventoryStable       *bool            `json:"process_inventory_stable"`
	ProcessCount                 int              `json:"process_count"`
	SelectedProcessCount         int              `json:"selected_process_count"`
	TargetBoundProcessCount      int              `json:"target_bound_process_count"`
	OtherAccountProcessCount     int              `json:"other_account_process_count"`
	UnknownAccountProcessCount   int              `json:"unknown_account_process_count"`
	OpenedProcessCount           int              `json:"opened_process_count"`
	AccessDeniedCount            int              `json:"access_denied_count"`
	PerProcessCollectorCount     int              `json:"per_process_collector_count"`
	DatabaseCount                int              `json:"database_count"`
	RequiredDatabaseCount        int              `json:"required_database_count"`
	PlaintextDatabaseCount       int              `json:"plaintext_database_count"`
	MatchedDatabaseCount         int              `json:"matched_database_count"`
	MissingDatabaseCount         int              `json:"missing_database_count"`
	ConfigCipherStructureCount   int              `json:"config_cipher_structure_count"`
	ConfigCipherInvalidCount     int              `json:"config_cipher_invalid_structure_count"`
	ConfigCipherCandidateCount   int              `json:"config_cipher_candidate_count"`
	ConfigCipherVerifiedCount    int              `json:"config_cipher_verified_candidate_count"`
	FallbackCandidateCount       int              `json:"fallback_candidate_count"`
	FallbackStageCounts          map[string]int   `json:"fallback_stage_counts"`
	StaticScanFallback           bool             `json:"static_scan_fallback"`
	KDFBudgetExhausted           bool             `json:"kdf_budget_exhausted"`
	ScannedBytes                 uint64           `json:"scanned_bytes"`
	ScanLimited                  bool             `json:"scan_limited"`
	BudgetExhausted              bool             `json:"budget_exhausted"`
	PhaseTimingsMS               map[string]int64 `json:"phase_timings_ms"`
	SecretsIncluded              bool             `json:"secrets_included"`
	PathsIncluded                bool             `json:"paths_included"`
	AccountIdentityIncluded      bool             `json:"account_identity_included"`
	ChatContentIncluded          bool             `json:"chat_content_included"`
	RawProviderResponseIncluded  bool             `json:"raw_provider_response_included"`
}

func liveDiagnosticProvenance() (liveCandidateProvenance, error) {
	provenance := liveCandidateProvenance{
		SourceCommit:        strings.TrimSpace(os.Getenv("V_LOCAL_KEY_PROVIDER_LIVE_CANDIDATE_SOURCE_COMMIT")),
		WorkflowRunID:       strings.TrimSpace(os.Getenv("V_LOCAL_KEY_PROVIDER_LIVE_CANDIDATE_RUN_ID")),
		AttestationWorkflow: strings.TrimSpace(os.Getenv("V_LOCAL_KEY_PROVIDER_LIVE_CANDIDATE_ATTESTATION_WORKFLOW")),
		AttestationVerified: strings.TrimSpace(os.Getenv("V_LOCAL_KEY_PROVIDER_LIVE_CANDIDATE_ATTESTATION_VERIFIED")) == "true",
	}
	if !validReleaseSourceCommit(provenance.SourceCommit) || !validReleaseRunID(provenance.WorkflowRunID) ||
		provenance.AttestationWorkflow != releaseCandidateAttestationWorkflow || !provenance.AttestationVerified {
		return liveCandidateProvenance{}, errors.New("live diagnostic candidate provenance is incomplete or untrusted")
	}
	return provenance, nil
}

func validLiveDiagnosticToken(value string, allowEmpty bool) bool {
	if value == "" {
		return allowEmpty
	}
	if len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func copyLiveDiagnosticTokens(values []string) ([]string, error) {
	if len(values) > 16 {
		return nil, errors.New("live diagnostic token list is too large")
	}
	result := make([]string, len(values))
	for index, value := range values {
		if !validLiveDiagnosticToken(value, false) {
			return nil, errors.New("live diagnostic contains an unsafe token")
		}
		result[index] = value
	}
	return result, nil
}

func copyLiveDiagnosticTimings(values map[string]int64) (map[string]int64, error) {
	allowed := map[string]bool{
		"target_database_discovery": true,
		"media_discovery":           true,
		"config_cipher":             true,
		"memory_scan":               true,
		"primary_acquire":           true,
		"catalog_refresh":           true,
		"total":                     true,
	}
	result := make(map[string]int64, len(values))
	for name, elapsed := range values {
		if !allowed[name] || elapsed < 0 || elapsed > maxBudgetMilliseconds {
			return nil, errors.New("live diagnostic contains an invalid phase timing")
		}
		result[name] = elapsed
	}
	return result, nil
}

func copyLiveDiagnosticStageCounts(values map[string]int) (map[string]int, error) {
	allowed := map[string]bool{
		"structured_key_object": true,
		"salt_neighborhood":     true,
		"bounded_writable_heap": true,
		"bounded_readonly":      true,
		"bounded_hex":           true,
	}
	result := make(map[string]int, len(values))
	for name, count := range values {
		if !allowed[name] || count < 0 || count > 1024 {
			return nil, errors.New("live diagnostic contains an invalid fallback count")
		}
		result[name] = count
	}
	return result, nil
}

func makeLiveDiagnosticArtifact(
	result response,
	processInventoryStable *bool,
	provenance liveCandidateProvenance,
	recordedAt time.Time,
) (liveDiagnosticArtifact, error) {
	if !validReleaseSourceCommit(provenance.SourceCommit) || !validReleaseRunID(provenance.WorkflowRunID) ||
		provenance.AttestationWorkflow != releaseCandidateAttestationWorkflow || !provenance.AttestationVerified {
		return liveDiagnosticArtifact{}, errors.New("live diagnostic candidate provenance is incomplete or untrusted")
	}
	diag := result.Diagnostics
	for _, value := range []string{
		diag.ResultCode, diag.WorkflowStatus, diag.NextAction, diag.DatabaseCoverageStatus,
		diag.MediaCoverageStatus, diag.RouteSelected, diag.CompatibilityRegistryStatus,
		diag.ConfigCipherRouteStatus, diag.TargetBindingStatus, diag.ProcessArchitecture,
		diag.ProcessArchitectureStatus,
	} {
		if !validLiveDiagnosticToken(value, true) {
			return liveDiagnosticArtifact{}, errors.New("live diagnostic contains an unsafe status")
		}
	}
	scopes, err := copyLiveDiagnosticTokens(diag.RequestedScopes)
	if err != nil {
		return liveDiagnosticArtifact{}, err
	}
	routes, err := copyLiveDiagnosticTokens(diag.RoutesAttempted)
	if err != nil {
		return liveDiagnosticArtifact{}, err
	}
	timings, err := copyLiveDiagnosticTimings(diag.PhaseTimingsMS)
	if err != nil {
		return liveDiagnosticArtifact{}, err
	}
	stages, err := copyLiveDiagnosticStageCounts(diag.FallbackStageCounts)
	if err != nil {
		return liveDiagnosticArtifact{}, err
	}
	var stable *bool
	if processInventoryStable != nil {
		value := *processInventoryStable
		stable = &value
	}
	return liveDiagnosticArtifact{
		SchemaVersion: 1, ArtifactKind: liveDiagnosticKind,
		QualificationOnly: true, FormalReleaseEvidence: false,
		CandidateSourceCommit: provenance.SourceCommit, CandidateWorkflowRunID: provenance.WorkflowRunID,
		CandidateAttestationWorkflow: provenance.AttestationWorkflow,
		CandidateAttestationVerified: provenance.AttestationVerified, PromotionVerified: false,
		RecordedAt: recordedAt.UTC().Format(time.RFC3339Nano), RunnerOS: runtime.GOOS, RunnerArch: runtime.GOARCH,
		ResultCode: diag.ResultCode, WorkflowStatus: diag.WorkflowStatus, NextAction: diag.NextAction,
		RequestedScopes: scopes, DatabaseCoverageStatus: diag.DatabaseCoverageStatus,
		MediaCoverageStatus: diag.MediaCoverageStatus, RouteSelected: diag.RouteSelected, RoutesAttempted: routes,
		CompatibilityRegistryStatus: diag.CompatibilityRegistryStatus,
		ConfigCipherRouteStatus:     diag.ConfigCipherRouteStatus, TargetBindingStatus: diag.TargetBindingStatus,
		ProcessArchitecture: diag.ProcessArchitecture, ProcessArchitectureStatus: diag.ProcessArchitectureStatus,
		ProcessInventoryStable: stable, ProcessCount: diag.ProcessCount, SelectedProcessCount: diag.SelectedProcessCount,
		TargetBoundProcessCount: diag.TargetBoundProcessCount, OtherAccountProcessCount: diag.OtherAccountProcessCount,
		UnknownAccountProcessCount: diag.UnknownAccountProcessCount, OpenedProcessCount: diag.OpenedProcessCount,
		AccessDeniedCount: diag.AccessDeniedCount, PerProcessCollectorCount: diag.PerProcessCollectorCount,
		DatabaseCount: diag.DatabaseCount, RequiredDatabaseCount: diag.RequiredDatabaseCount,
		PlaintextDatabaseCount: diag.PlaintextDatabaseCount, MatchedDatabaseCount: diag.MatchedDatabaseCount,
		MissingDatabaseCount: diag.MissingDatabaseCount, ConfigCipherStructureCount: diag.ConfigCipherStructureCount,
		ConfigCipherInvalidCount: diag.ConfigCipherInvalidCount, ConfigCipherCandidateCount: diag.ConfigCipherCandidateCount,
		ConfigCipherVerifiedCount: diag.ConfigCipherVerifiedCount, FallbackCandidateCount: diag.FallbackCandidateCount,
		FallbackStageCounts: stages, StaticScanFallback: diag.StaticScanFallback,
		KDFBudgetExhausted: diag.KDFBudgetExhausted, ScannedBytes: diag.ScannedBytes,
		ScanLimited: diag.ScanLimited, BudgetExhausted: diag.BudgetExhausted, PhaseTimingsMS: timings,
		SecretsIncluded: false, PathsIncluded: false, AccountIdentityIncluded: false,
		ChatContentIncluded: false, RawProviderResponseIncluded: false,
	}, nil
}

func writeLiveDiagnostic(t *testing.T, result response, processInventoryStable *bool) {
	t.Helper()
	path := strings.TrimSpace(os.Getenv("V_LOCAL_KEY_PROVIDER_LIVE_DIAGNOSTIC_PATH"))
	if path == "" {
		return
	}
	provenance, err := liveDiagnosticProvenance()
	if err != nil {
		t.Fatal("live diagnostic candidate provenance is incomplete or untrusted")
	}
	artifact, err := makeLiveDiagnosticArtifact(result, processInventoryStable, provenance, time.Now())
	if err != nil {
		t.Fatal("live diagnostic contains unsafe data")
	}
	payload, err := json.MarshalIndent(artifact, "", "  ")
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
	defer wipeLiveBytes(payload)
	file, err := os.OpenFile(absolute, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("live diagnostic output path is unsafe or already exists")
	}
	if _, err := file.Write(payload); err != nil {
		_ = file.Close()
		t.Fatal("live diagnostic write failed")
	}
	if err := file.Close(); err != nil {
		t.Fatal("live diagnostic close failed")
	}
}

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
	writeLiveDiagnostic(t, result, nil)
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

func TestLiveDiagnosticIsRedactedAndReleaseIneligible(t *testing.T) {
	stable := true
	result := response{
		DatabaseKeys: map[string]string{"private-database-path": "database-secret-marker"},
		ImageKeys:    &imageKeys{AES: "media-secret-marker", XOR: 42},
		Diagnostics: diagnostics{
			ResultCode: "deadline_exhausted", WorkflowStatus: "terminal", NextAction: "stop_and_report",
			RequestedScopes: []string{"database", "media"}, DatabaseCoverageStatus: "none",
			MediaCoverageStatus: "none", RouteSelected: "windows_memory_fallback",
			RoutesAttempted:             []string{"windows_memory_fallback"},
			CompatibilityRegistryStatus: "registered_supported", ConfigCipherRouteStatus: "reviewed_no_structure",
			TargetBindingStatus: "path_verified", ProcessArchitecture: "amd64",
			ProcessArchitectureStatus: "verified_running_process", ProcessCount: 5,
			SelectedProcessCount: 5, TargetBoundProcessCount: 1, UnknownAccountProcessCount: 4,
			OpenedProcessCount: 5, PerProcessCollectorCount: 9, DatabaseCount: 19,
			RequiredDatabaseCount: 19, MissingDatabaseCount: 19, StaticScanFallback: true,
			KDFBudgetExhausted: true, ScannedBytes: 1024, ScanLimited: true, BudgetExhausted: true,
			FallbackStageCounts: map[string]int{"structured_key_object": 5, "salt_neighborhood": 4},
			PhaseTimingsMS: map[string]int64{
				"target_database_discovery": 10, "media_discovery": 20,
				"config_cipher": 0, "memory_scan": 180000, "primary_acquire": 180000, "total": 180030,
			},
		},
	}
	provenance := liveCandidateProvenance{
		SourceCommit: strings.Repeat("a", 40), WorkflowRunID: "12345",
		AttestationWorkflow: releaseCandidateAttestationWorkflow, AttestationVerified: true,
	}
	artifact, err := makeLiveDiagnosticArtifact(result, &stable, provenance, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"private-database-path", "database-secret-marker", "media-secret-marker",
	} {
		if bytes.Contains(payload, []byte(forbidden)) {
			t.Fatalf("live diagnostic included forbidden raw data %q", forbidden)
		}
	}
	if artifact.SchemaVersion != 1 || artifact.ArtifactKind != liveDiagnosticKind ||
		!artifact.QualificationOnly || artifact.FormalReleaseEvidence || artifact.PromotionVerified ||
		artifact.SecretsIncluded || artifact.PathsIncluded || artifact.AccountIdentityIncluded ||
		artifact.ChatContentIncluded || artifact.RawProviderResponseIncluded ||
		artifact.ProcessInventoryStable == nil || !*artifact.ProcessInventoryStable {
		t.Fatal("live diagnostic lost its non-promotable redaction boundary")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var formal releaseEvidenceArtifact
	if err := decoder.Decode(&formal); err == nil {
		t.Fatal("qualification-only live diagnostic decoded as formal release evidence")
	}
}

func TestLiveDiagnosticRejectsUnboundedFields(t *testing.T) {
	provenance := liveCandidateProvenance{
		SourceCommit: strings.Repeat("a", 40), WorkflowRunID: "12345",
		AttestationWorkflow: releaseCandidateAttestationWorkflow, AttestationVerified: true,
	}
	result := response{Diagnostics: diagnostics{
		ResultCode: "deadline_exhausted", RequestedScopes: []string{"database", "media"},
		PhaseTimingsMS: map[string]int64{"private_path": 1}, FallbackStageCounts: map[string]int{},
	}}
	if _, err := makeLiveDiagnosticArtifact(result, nil, provenance, time.Unix(1, 0)); err == nil {
		t.Fatal("live diagnostic accepted an unregistered timing field")
	}
	result.Diagnostics.PhaseTimingsMS = map[string]int64{}
	result.Diagnostics.FallbackStageCounts = map[string]int{"private_path": 1}
	if _, err := makeLiveDiagnosticArtifact(result, nil, provenance, time.Unix(1, 0)); err == nil {
		t.Fatal("live diagnostic accepted an unregistered fallback stage")
	}
	provenance.AttestationVerified = false
	result.Diagnostics.FallbackStageCounts = map[string]int{}
	if _, err := makeLiveDiagnosticArtifact(result, nil, provenance, time.Unix(1, 0)); err == nil {
		t.Fatal("live diagnostic accepted unverified candidate provenance")
	}
}
