package provider

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPackageVersionMatchesRuntimeVersion(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("npm", "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(payload, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Version != version {
		t.Fatalf("npm 版本 %q 与运行时版本 %q 不一致", metadata.Version, version)
	}
}

func TestDecodeRequest(t *testing.T) {
	payload, err := json.Marshal(acquireRequest{
		Protocol:   protocolName,
		RequestID:  "request-1",
		Action:     "acquire",
		AccountDir: "account",
		DBDir:      "db",
		Scopes:     []string{"database", "media"},
		DeadlineMS: 75_000,
		Workflow:   workflowRequest{Operation: "finalize"},
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := decodeRequest(strings.NewReader(string(payload)))
	if err != nil {
		t.Fatal(err)
	}
	if request.Protocol != protocolName || request.RequestID != "request-1" {
		t.Fatalf("请求字段未保留：%+v", request)
	}
}

func TestDecodeRequestRejectsUnknownFields(t *testing.T) {
	_, err := decodeRequest(strings.NewReader(`{"protocol":"v-local-key-provider/v1","request_id":"1","action":"acquire","account_dir":"a","db_dir":"b","scopes":["database"],"deadline_ms":1000,"workflow":{"operation":"finalize"},"secret":"x"}`))
	if err == nil {
		t.Fatal("包含未知字段的请求不应通过")
	}
}

func TestDecodeSecurityPostureRevalidationRequiresAFreshRequest(t *testing.T) {
	base := acquireRequest{
		Protocol: protocolName, RequestID: "posture-1", Action: "acquire",
		AccountDir: "account", DBDir: "db", Scopes: []string{"database"}, DeadlineMS: 1_000,
		Workflow: workflowRequest{Operation: "revalidate_security_posture"},
	}
	payload, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRequestData(payload); err != nil {
		t.Fatalf("fresh security posture revalidation was rejected: %v", err)
	}
	base.Workflow.SessionID = "old-session"
	payload, _ = json.Marshal(base)
	if _, err := decodeRequestData(payload); err == nil {
		t.Fatal("security posture revalidation accepted an old acquisition session")
	}
}

func TestSecurityPostureRevalidationNeverAcquiresCredentials(t *testing.T) {
	request := acquireRequest{Protocol: protocolName, RequestID: "posture-1"}
	options := acquireOptions{database: true, media: true}
	enabled := securityPostureRevalidationResponse(request, options, "darwin", "sip_enabled_verified")
	if enabled.Diagnostics.ResultCode != "complete" || enabled.Diagnostics.WorkflowStatus != "terminal" ||
		enabled.Diagnostics.NextAction != "none" || enabled.Diagnostics.ActionStage != "security_posture_revalidation" ||
		len(enabled.DatabaseKeys) != 0 || enabled.DatabaseCredential != nil || enabled.ImageKeys != nil || len(enabled.CatalogEntries) != 0 {
		t.Fatalf("enabled SIP revalidation performed acquisition work: %+v", enabled)
	}
	disabled := securityPostureRevalidationResponse(request, options, "darwin", "sip_disabled_verified")
	if disabled.Diagnostics.ResultCode != "action_required" || disabled.Diagnostics.WorkflowStatus != "waiting_action" ||
		disabled.Diagnostics.NextAction != "reenable_sip" || disabled.Diagnostics.SecurityPostureStatus != "restoration_required" {
		t.Fatalf("disabled SIP revalidation did not preserve the user action: %+v", disabled.Diagnostics)
	}
}

func TestSecurityPostureRevalidationDoesNotRequireAcquisitionPathsToExist(t *testing.T) {
	root := t.TempDir()
	missingAccount := filepath.Join(root, "removed-account")
	missingDatabase := filepath.Join(missingAccount, "removed-database")
	result, err := executeSecurityPostureRevalidation(acquireRequest{
		Protocol: protocolName, RequestID: "posture-with-removed-paths", Action: "acquire",
		AccountDir: missingAccount, DBDir: missingDatabase, Scopes: []string{"database"}, DeadlineMS: 1_000,
		Workflow: workflowRequest{Operation: "revalidate_security_posture"},
	})
	if err != nil {
		t.Fatalf("posture-only revalidation depended on removed acquisition paths: %v", err)
	}
	if result.Diagnostics.ActionStage != "security_posture_revalidation" || len(result.DatabaseKeys) != 0 ||
		result.DatabaseCredential != nil || result.ImageKeys != nil {
		t.Fatalf("path-independent posture check performed acquisition work: %+v", result)
	}
	if _, err := os.Lstat(missingAccount); !os.IsNotExist(err) {
		t.Fatalf("posture-only revalidation created or touched the removed account path: %v", err)
	}
}

func TestOptionsFromRequest(t *testing.T) {
	root := t.TempDir()
	account := filepath.Join(root, "account")
	db := filepath.Join(account, "db_storage")
	if err := os.MkdirAll(db, 0o700); err != nil {
		t.Fatal(err)
	}
	options, err := optionsFromRequest(acquireRequest{
		CatalogKey: strings.Repeat("ab", 32),
		AccountDir: account,
		DBDir:      db,
		Scopes:     []string{"database", "media"},
		DeadlineMS: 75_000,
		Workflow:   workflowRequest{Operation: "finalize"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !options.database || !options.media {
		t.Fatalf("scope 未正确解析：%+v", options)
	}
	if got := string(options.catalogKey); got != string(bytes.Repeat([]byte{0xab}, 32)) {
		t.Fatal("请求携带的 catalog key 未被原样使用")
	}
}

func TestOptionsFromRequestRejectsMalformedCatalogKey(t *testing.T) {
	root := t.TempDir()
	account := filepath.Join(root, "account")
	db := filepath.Join(account, "db_storage")
	if err := os.MkdirAll(db, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := optionsFromRequest(acquireRequest{
		CatalogKey: "short", AccountDir: account, DBDir: db,
		Scopes: []string{"database"}, DeadlineMS: 75_000,
		Workflow: workflowRequest{Operation: "finalize"},
	})
	if err == nil {
		t.Fatal("长度错误的 catalog key 不应通过")
	}
}

func TestOptionsFromRequestRejectsDuplicateScopes(t *testing.T) {
	root := t.TempDir()
	account := filepath.Join(root, "account")
	db := filepath.Join(account, "db_storage")
	if err := os.MkdirAll(db, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := optionsFromRequest(acquireRequest{
		AccountDir: account, DBDir: db, Scopes: []string{"media", "media"}, DeadlineMS: 75_000,
		Workflow: workflowRequest{Operation: "finalize"},
	})
	if err == nil || !strings.Contains(err.Error(), "不能重复") {
		t.Fatalf("重复 scope 未被 Provider 拒绝：%v", err)
	}
}

func TestVersionHasDevelopmentDefault(t *testing.T) {
	if version == "" {
		t.Fatal("版本号不能为空")
	}
}

func TestNewDiagnosticsProvidesStableProtocolDefaults(t *testing.T) {
	diag := newDiagnostics("windows", []string{"media", "database", "media"})
	if got, want := strings.Join(diag.RequestedScopes, ","), "database,media"; got != want {
		t.Fatalf("requested scopes were not canonicalized: got %q want %q", got, want)
	}
	if diag.Platform != "windows" || diag.DatabaseTargetStatus != "not_requested" ||
		diag.DatabaseCoverageStatus != "not_requested" || diag.MediaCoverageStatus != "not_requested" ||
		diag.NextAction != "none" || diag.CandidateMode != "none" ||
		diag.TargetBindingStatus != "unknown" || diag.SessionAccountStatus != "unknown" {
		t.Fatalf("stable diagnostic defaults were not initialized: %+v", diag)
	}
	if diag.BlockingReasons == nil || diag.CandidateSources == nil || diag.RoutesAttempted == nil ||
		diag.PhaseTimingsMS == nil || diag.FallbackStageCounts == nil || diag.WindowsRouteEvidence == nil ||
		diag.StandardRouteEvidence == nil || diag.RoutePriority == nil {
		t.Fatalf("stable collection diagnostics must be non-nil: %+v", diag)
	}
}

func TestApplyFixedDiagnosticOutcomePreservesStableProtocolState(t *testing.T) {
	diag := newDiagnostics("darwin", []string{"database"})
	diag.SecurityPostureStatus = "sip_enabled_verified"
	diag.ShadowRouteStatus = "unavailable_in_build"

	applyFixedDiagnosticOutcome(&diag, "complete", "terminal", "none")

	if diag.ResultCode != "complete" || diag.WorkflowStatus != "terminal" || diag.NextAction != "none" {
		t.Fatalf("fixed diagnostic outcome was not applied: %+v", diag)
	}
	if diag.SecurityPostureStatus != "sip_enabled_verified" || diag.ShadowRouteStatus != "unavailable_in_build" {
		t.Fatalf("fixed diagnostic outcome discarded platform state: %+v", diag)
	}
	if diag.BlockingReasons == nil || len(diag.BlockingReasons) != 0 {
		t.Fatalf("empty blocking reasons must remain a non-nil protocol collection: %#v", diag.BlockingReasons)
	}
}

func TestRunAcquireReturnsDeadlineDiagnosticsAfterDiscoveryBudget(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("platform acquisition is unsupported")
	}
	root := t.TempDir()
	account := filepath.Join(root, "account")
	db := filepath.Join(root, "db")
	if err := os.MkdirAll(account, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(db, 0o700); err != nil {
		t.Fatal(err)
	}
	result, err := runAcquire(acquireOptions{
		accountDir: account, dbDir: db, database: true,
		budget: newBudget(time.Now().Add(-time.Second), 1),
	})
	if err != nil {
		t.Fatalf("expired discovery should return diagnostics, got error: %v", err)
	}
	if !result.Diagnostics.BudgetExhausted || result.Diagnostics.ResultCode != "deadline_exhausted" ||
		result.Diagnostics.ProcessAccessStatus == "deadline_exhausted" {
		t.Fatalf("expired discovery diagnostics missing: %+v", result.Diagnostics)
	}
	if result.Diagnostics.PhaseTimingsMS == nil {
		t.Fatal("stable phase timing diagnostics were omitted")
	}
}
