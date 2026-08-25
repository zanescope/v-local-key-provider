package provider

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPhase0CatalogProofChangesWhenPhysicalFileChanges(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "message.db")
	key := bytes.Repeat([]byte{0x73}, 32)
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x11}, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	first, _, err := discoverDatabaseCatalog(root, unlimitedBudget(), key)
	if err != nil {
		t.Fatal(err)
	}
	// Preserve the size while changing the proof. Some filesystems have coarse timestamp
	// granularity, so force a distinct mtime as well.
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x22}, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	changedAt := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, changedAt, changedAt); err != nil {
		t.Fatal(err)
	}
	second, _, err := discoverDatabaseCatalog(root, unlimitedBudget(), key)
	if err != nil {
		t.Fatal(err)
	}
	if first.CatalogID == second.CatalogID {
		t.Fatal("catalog ID did not bind the changed physical-file proof")
	}
	if first.Databases[0].DatabaseID != second.Databases[0].DatabaseID {
		t.Fatal("opaque database ID should remain stable for the same normalized path and machine key")
	}
	if first.Databases[0].FirstPageSHA256 == second.Databases[0].FirstPageSHA256 {
		t.Fatal("first-page proof did not change with file contents")
	}
}

func TestPhase0SameEffectiveKeyFromMultipleSourcesIsDeduplicated(t *testing.T) {
	targets := databaseTargets{
		pages: []databasePage{{path: "message.db", profileID: defaultProfileID}},
		count: 1,
		catalog: databaseCatalog{Databases: []catalogDatabase{{
			DatabaseID: "db", RelativePath: "message.db", RequiredForKeyCoverage: true,
		}}},
	}
	collector := newCandidateCollector(targets, mediaEvidence{})
	key := strings.Repeat("a1", 32)
	collector.addDatabaseCandidate("message.db", key, defaultProfileID, "commoncrypto_cccrypt")
	collector.addDatabaseCandidate("message.db", key, defaultProfileID, "macos_pbkdf_hook")

	keys, ambiguous := collector.databaseKeys(targets)
	if ambiguous != 0 || keys["message.db"] != key {
		t.Fatalf("the same verified key from two sources became ambiguous: keys=%v ambiguous=%d", keys, ambiguous)
	}
	origins := collector.databaseCandidates["message.db"][key].origins
	if !reflect.DeepEqual(origins, map[string]bool{
		"commoncrypto_cccrypt": true,
		"macos_pbkdf_hook":     true,
	}) {
		t.Fatalf("candidate provenance was not preserved during deduplication: %v", origins)
	}
}

func TestPhase2ResultStatePriorityRegression(t *testing.T) {
	baseTargets := databaseTargets{
		count: 1,
		catalog: databaseCatalog{Databases: []catalogDatabase{{
			DatabaseID: strings.Repeat("ab", 32), RelativePath: "message.db",
			Classification: classificationEncrypted, RequiredForKeyCoverage: true,
		}}},
	}
	validKey := strings.Repeat("11", 32)
	tests := []struct {
		name        string
		diagnostics diagnostics
		result      response
		options     acquireOptions
		wantCode    string
		wantFlow    string
		wantAction  string
	}{
		{
			name:        "account mismatch outranks complete coverage",
			diagnostics: diagnostics{TargetBindingStatus: "mismatch", SessionAccountStatus: "known_other"},
			result:      response{DatabaseKeys: map[string]string{"message.db": validKey}},
			options:     acquireOptions{database: true, budget: unlimitedBudget()},
			wantCode:    "action_required", wantFlow: "waiting_action", wantAction: "switch_to_target_account",
		},
		{
			name:     "complete",
			result:   response{DatabaseKeys: map[string]string{"message.db": validKey}},
			options:  acquireOptions{database: true, budget: unlimitedBudget()},
			wantCode: "complete", wantFlow: "terminal", wantAction: "none",
		},
		{
			name:        "trigger required",
			diagnostics: diagnostics{HookTriggerRequired: true},
			options:     acquireOptions{database: true, budget: unlimitedBudget()},
			wantCode:    "action_required", wantFlow: "waiting_action", wantAction: "trigger_database",
		},
		{
			name:        "restart required",
			diagnostics: diagnostics{HookRestartRequired: true},
			options:     acquireOptions{database: true, budget: unlimitedBudget()},
			wantCode:    "action_required", wantFlow: "waiting_action", wantAction: "restart_wechat",
		},
		{
			name:        "relogin required",
			diagnostics: diagnostics{HookReloginRequired: true},
			options:     acquireOptions{database: true, budget: unlimitedBudget()},
			wantCode:    "action_required", wantFlow: "waiting_action", wantAction: "relogin_wechat",
		},
		{
			name:        "permission denied",
			diagnostics: diagnostics{ProcessAccessStatus: "denied"},
			options:     acquireOptions{database: true, budget: unlimitedBudget()},
			wantCode:    "permission_required", wantFlow: "blocked", wantAction: "fix_permission",
		},
		{
			name:        "untrusted process identity is not a permission error",
			diagnostics: diagnostics{ProcessAccessStatus: "denied", ProcessAccessError: "process_identity_untrusted"},
			options:     acquireOptions{database: true, budget: unlimitedBudget()},
			wantCode:    "unsupported", wantFlow: "blocked", wantAction: "stop_and_report",
		},
		{
			name:        "wechat not running remains resumable",
			diagnostics: diagnostics{ProcessAccessStatus: "wechat_not_running"},
			options:     acquireOptions{database: true, budget: unlimitedBudget()},
			wantCode:    "action_required", wantFlow: "waiting_action", wantAction: "restart_wechat",
		},
		{
			name:        "validator conflict",
			diagnostics: diagnostics{ValidatorConflictCount: 1},
			options:     acquireOptions{database: true, budget: unlimitedBudget()},
			wantCode:    "failed", wantFlow: "blocked", wantAction: "stop_and_report",
		},
		{
			name:        "candidate ambiguity",
			diagnostics: diagnostics{AmbiguousDatabaseKeys: 1},
			options:     acquireOptions{database: true, budget: unlimitedBudget()},
			wantCode:    "ambiguous", wantFlow: "blocked", wantAction: "stop_and_report",
		},
		{
			name:     "deadline exhausted",
			options:  acquireOptions{database: true, budget: newBudget(time.Now().Add(-time.Second), 1)},
			wantCode: "deadline_exhausted", wantFlow: "terminal", wantAction: "stop_and_report",
		},
		{
			name:     "terminal partial",
			options:  acquireOptions{database: true, budget: unlimitedBudget()},
			wantCode: "partial", wantFlow: "terminal", wantAction: "stop_and_report",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			diag := test.diagnostics
			finalizeDiagnostics(&diag, baseTargets, test.result, test.options)
			if diag.ResultCode != test.wantCode || diag.WorkflowStatus != test.wantFlow || diag.NextAction != test.wantAction {
				t.Fatalf("state = %s/%s/%s, want %s/%s/%s; diagnostics=%+v",
					diag.ResultCode, diag.WorkflowStatus, diag.NextAction,
					test.wantCode, test.wantFlow, test.wantAction, diag)
			}
		})
	}
}

func TestDiagnosticOutcomeRulePriorityIsExplicitAndUnique(t *testing.T) {
	expected := []string{
		"helper_untrusted", "process_identity_untrusted", "sip_restoration", "account_mismatch",
		"wechat_not_running", "complete", "hook_trigger_required", "hook_restart_required",
		"hook_relogin_required", "sip_fallback_available", "sip_posture_unverified", "shadow_approval",
		"sip_route_unresolved", "process_access_denied", "validator_conflict", "candidate_ambiguous",
		"deadline_exhausted", "database_targets_not_found", "partial_default",
	}
	if len(diagnosticOutcomeRules) != len(expected) {
		t.Fatalf("diagnostic rule count changed without updating the priority contract: %d", len(diagnosticOutcomeRules))
	}
	seen := map[string]bool{}
	for index, rule := range diagnosticOutcomeRules {
		if rule.name != expected[index] || rule.name == "" || seen[rule.name] {
			t.Fatalf("diagnostic rule priority/name is invalid at %d: %q", index, rule.name)
		}
		seen[rule.name] = true
	}
	context := diagnosticDecisionContext{options: acquireOptions{budget: unlimitedBudget()}}
	if !diagnosticOutcomeRules[len(diagnosticOutcomeRules)-1].matches(context) {
		t.Fatal("diagnostic rule list has no unconditional final rule")
	}
}
