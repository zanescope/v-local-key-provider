package diagnostics

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	catalogmodel "github.com/zanescope/v-local-key-provider/internal/catalog"
	credentialmodel "github.com/zanescope/v-local-key-provider/internal/credential"
)

func encryptedCatalogFixture() catalogmodel.Catalog {
	return catalogmodel.Catalog{Databases: []catalogmodel.Database{{
		DatabaseID: "db-1", RelativePath: "message.db",
		Classification: catalogmodel.ClassificationEncrypted, RequiredForKeyCoverage: true,
	}}}
}

func finalizeFixture(
	diag *Diagnostics,
	catalog catalogmodel.Catalog,
	requiredDatabaseCount int,
	databaseKeys map[string]string,
	imageKeysPresent bool,
	databaseRequested bool,
	mediaRequested bool,
	budgetExpired bool,
) {
	Finalize(diag, FinalizeInput{
		Catalog: catalog, RequiredDatabaseCount: requiredDatabaseCount,
		DatabaseKeys: databaseKeys, ImageKeysPresent: imageKeysPresent,
		DatabaseRequested: databaseRequested, MediaRequested: mediaRequested,
		BudgetExpired: budgetExpired,
		PlatformDefaults: PlatformDefaults{
			SecurityPostureStatus: "not_applicable", DarwinShadowRouteStatus: "unavailable_in_build",
		},
	})
}

func TestFinalizeRequiresSIPRestoration(t *testing.T) {
	validKey := strings.Repeat("a", 64)
	tests := []struct {
		name           string
		diag           Diagnostics
		keys           map[string]string
		wantReason     string
		wantCoverage   string
		wantBinding    string
		wantRouteCount int
	}{
		{
			name: "verified acquisition",
			diag: Diagnostics{
				Platform: "darwin", SecurityPostureStatus: "sip_disabled_verified", SessionAccountStatus: "known_target",
			},
			keys: validDatabaseKeys(validKey), wantCoverage: "complete", wantBinding: "hmac_verified",
		},
		{
			name: "failed dynamic route",
			diag: Diagnostics{
				Platform: "darwin", SecurityPostureStatus: "sip_disabled_verified",
				RoutesAttempted: []string{"darwin_arm64_sip_disabled"},
			},
			wantReason: "sip_route_failed", wantCoverage: "none", wantBinding: "unknown", wantRouteCount: 1,
		},
		{
			name: "failed wait route",
			diag: Diagnostics{
				Platform: "darwin", SecurityPostureStatus: "sip_disabled_verified",
				RoutesAttempted: []string{"darwin_sip_disabled_waitfor"},
			},
			wantReason: "sip_route_failed", wantCoverage: "none", wantBinding: "unknown", wantRouteCount: 1,
		},
		{
			name:       "route not attempted",
			diag:       Diagnostics{Platform: "darwin", SecurityPostureStatus: "sip_disabled_verified"},
			wantReason: "sip_disabled_route_not_attempted", wantCoverage: "none", wantBinding: "unknown",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			diag := test.diag
			finalizeFixture(&diag, encryptedCatalogFixture(), 1, test.keys, false, true, false, false)
			if diag.ResultCode != "action_required" || diag.WorkflowStatus != "waiting_action" || diag.NextAction != "reenable_sip" ||
				diag.SecurityPostureStatus != "restoration_required" || diag.DatabaseCoverageStatus != test.wantCoverage ||
				diag.TargetBindingStatus != test.wantBinding || len(diag.RoutesAttempted) != test.wantRouteCount {
				t.Fatalf("unexpected SIP restoration state: %+v", diag)
			}
			if test.wantReason == "" {
				if len(diag.BlockingReasons) != 0 {
					t.Fatalf("successful SIP-disabled acquisition retained blockers: %+v", diag)
				}
			} else if !reflect.DeepEqual(diag.BlockingReasons, []string{test.wantReason}) {
				t.Fatalf("blocking reasons = %#v, want %q", diag.BlockingReasons, test.wantReason)
			}
		})
	}
}

func validDatabaseKeys(key string) map[string]string {
	return map[string]string{"message.db": key}
}

func TestFinalizeCompletesWithVerifiedSIPEnabledPosture(t *testing.T) {
	diag := Diagnostics{Platform: "darwin", SecurityPostureStatus: "sip_enabled_verified"}
	finalizeFixture(&diag, encryptedCatalogFixture(), 1, validDatabaseKeys(strings.Repeat("a", 64)), false, true, false, false)
	if diag.ResultCode != "complete" || diag.WorkflowStatus != "terminal" || diag.NextAction != "none" {
		t.Fatalf("verified SIP-enabled posture did not complete: %+v", diag)
	}
}

func TestFinalizeDarwinShadowFallbackPolicy(t *testing.T) {
	tests := []struct {
		name       string
		status     string
		posture    string
		wantCode   string
		wantAction string
		wantStatus string
		wantReason string
	}{
		{
			name: "build unavailable", posture: "sip_enabled_verified",
			wantCode: "action_required", wantAction: "disable_sip", wantStatus: "unavailable_in_build",
			wantReason: "shadow_route_unavailable_in_build",
		},
		{
			name: "target unsupported", status: "unsupported_for_target", posture: "sip_enabled_verified",
			wantCode: "action_required", wantAction: "disable_sip", wantStatus: "unsupported_for_target",
			wantReason: "shadow_route_unsupported_for_target",
		},
		{
			name: "attempt failed", status: "attempted_failed", posture: "sip_enabled_verified",
			wantCode: "action_required", wantAction: "disable_sip", wantStatus: "attempted_failed",
			wantReason: "shadow_route_failed",
		},
		{
			name: "available", status: "available", posture: "sip_enabled_verified",
			wantCode: "action_required", wantAction: "approve_shadow_mode", wantStatus: "awaiting_approval",
		},
		{
			name: "unevaluated", status: "not_evaluated", posture: "sip_enabled_verified",
			wantCode: "unsupported", wantAction: "stop_and_report", wantStatus: "not_evaluated",
			wantReason: "shadow_route_not_evaluated",
		},
		{
			name: "security posture unverified", status: "unavailable_in_build", posture: "not_evaluated",
			wantCode: "unsupported", wantAction: "stop_and_report", wantStatus: "unavailable_in_build",
			wantReason: "security_posture_not_verified",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			diag := Diagnostics{
				Platform: "darwin", SecurityPostureStatus: test.posture, ShadowRouteStatus: test.status,
				ProcessAccessStatus: "denied", ProcessAccessError: "sip_enabled",
				RoutesAttempted: []string{"darwin_static_fallback"},
			}
			finalizeFixture(&diag, encryptedCatalogFixture(), 1, nil, false, true, false, false)
			if diag.ResultCode != test.wantCode || diag.NextAction != test.wantAction || diag.ShadowRouteStatus != test.wantStatus {
				t.Fatalf("unexpected Darwin fallback state: %+v", diag)
			}
			if len(diag.RoutePriority) != 3 || diag.RoutePriority[0] != "standard" || diag.RoutePriority[1] != "shadow" || diag.RoutePriority[2] != "sip_disabled" {
				t.Fatalf("Darwin route priority changed: %+v", diag.RoutePriority)
			}
			if test.wantReason != "" && (len(diag.BlockingReasons) != 2 || diag.BlockingReasons[1] != test.wantReason) {
				t.Fatalf("unexpected Darwin fallback reasons: %+v", diag.BlockingReasons)
			}
		})
	}
}

func TestFinalizeKeepsCoverageOrthogonalAndScopeExplicit(t *testing.T) {
	key := validDatabaseKeys(strings.Repeat("a", 64))
	tests := []struct {
		name          string
		catalog       catalogmodel.Catalog
		required      int
		keys          map[string]string
		image         bool
		database      bool
		media         bool
		wantCode      string
		wantDatabase  string
		wantMedia     string
		wantTarget    string
		wantScopes    []string
		wantReason    string
		wantPlaintext int
	}{
		{
			name: "database complete and media missing", catalog: encryptedCatalogFixture(), required: 1, keys: key,
			database: true, media: true, wantCode: "partial", wantDatabase: "complete", wantMedia: "none",
			wantTarget: "present", wantScopes: []string{"database", "media"},
		},
		{
			name: "empty database catalog", database: true, wantCode: "partial", wantDatabase: "none",
			wantMedia: "not_requested", wantTarget: "none", wantScopes: []string{"database"}, wantReason: "database_targets_not_found",
		},
		{
			name: "plaintext database", catalog: catalogmodel.Catalog{Databases: []catalogmodel.Database{{
				DatabaseID: "db-plain", RelativePath: "plain.db", Classification: catalogmodel.ClassificationPlaintext,
			}}},
			database: true, wantCode: "complete", wantDatabase: "complete", wantMedia: "not_requested",
			wantTarget: "present", wantScopes: []string{"database"}, wantPlaintext: 1,
		},
		{
			name: "media only", image: true, media: true, wantCode: "complete", wantDatabase: "not_requested",
			wantMedia: "complete", wantTarget: "not_requested", wantScopes: []string{"media"},
		},
		{
			name: "all scopes complete", catalog: encryptedCatalogFixture(), required: 1, keys: key, image: true,
			database: true, media: true, wantCode: "complete", wantDatabase: "complete", wantMedia: "complete",
			wantTarget: "present", wantScopes: []string{"database", "media"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var diag Diagnostics
			finalizeFixture(&diag, test.catalog, test.required, test.keys, test.image, test.database, test.media, false)
			if diag.ResultCode != test.wantCode || diag.DatabaseCoverageStatus != test.wantDatabase ||
				diag.MediaCoverageStatus != test.wantMedia || diag.DatabaseTargetStatus != test.wantTarget ||
				!reflect.DeepEqual(diag.RequestedScopes, test.wantScopes) || diag.PlaintextDatabaseCount != test.wantPlaintext {
				t.Fatalf("scope coverage changed: %+v", diag)
			}
			if test.wantReason != "" && !reflect.DeepEqual(diag.BlockingReasons, []string{test.wantReason}) {
				t.Fatalf("blocking reasons = %#v, want %q", diag.BlockingReasons, test.wantReason)
			}
		})
	}
}

func TestFinalizeCountsCatalogClassificationsAndMissingIDs(t *testing.T) {
	catalog := catalogmodel.Catalog{
		Databases: []catalogmodel.Database{
			{DatabaseID: "encrypted", RelativePath: "encrypted.db", Classification: catalogmodel.ClassificationEncrypted, RequiredForKeyCoverage: true},
			{DatabaseID: "plaintext", RelativePath: "plaintext.db", Classification: catalogmodel.ClassificationPlaintext},
			{DatabaseID: "unreadable", RelativePath: "unreadable.db", Classification: catalogmodel.ClassificationUnreadable},
			{DatabaseID: "unstable", RelativePath: "unstable.db", Classification: catalogmodel.ClassificationUnstable},
			{DatabaseID: "truncated", RelativePath: "truncated.db", Classification: catalogmodel.ClassificationTruncated},
		},
		DiscoveryErrors: []string{"walk_failed"},
	}
	var diag Diagnostics
	finalizeFixture(&diag, catalog, 1, nil, false, true, false, false)
	if diag.DatabaseCount != 5 || diag.RequiredDatabaseCount != 1 || diag.PlaintextDatabaseCount != 1 ||
		diag.UnreadableDatabaseCount != 1 || diag.UnstableDatabaseCount != 1 || diag.TruncatedDatabaseCount != 1 ||
		!reflect.DeepEqual(diag.MissingDatabaseIDs, []string{"encrypted"}) || diag.DatabaseCoverageStatus != "none" {
		t.Fatalf("catalog evidence was finalized incorrectly: %+v", diag)
	}
}

func TestFinalizePromotesCredentialModeAndSortedSources(t *testing.T) {
	diag := Diagnostics{CandidateSources: []string{"z-source"}}
	Finalize(&diag, FinalizeInput{
		Catalog: encryptedCatalogFixture(), RequiredDatabaseCount: 1,
		DatabaseKeys: validDatabaseKeys(strings.Repeat("a", 64)), DatabaseRequested: true,
		DatabaseCredential: &credentialmodel.DatabaseCredential{
			Mode:  "mixed",
			Roots: []credentialmodel.Root{{SourceEvidence: []string{"b-source", "a-source"}}},
			Overrides: map[string]credentialmodel.Override{
				"message.db": {SourceEvidence: []string{"c-source", "a-source"}},
			},
		},
	})
	if diag.CandidateMode != "mixed" || !reflect.DeepEqual(diag.CandidateSources, []string{"a-source", "b-source", "c-source", "z-source"}) {
		t.Fatalf("credential evidence was not normalized: %+v", diag)
	}
}

func TestFinalizeOutcomePriorityRegression(t *testing.T) {
	validKey := validDatabaseKeys(strings.Repeat("11", 32))
	tests := []struct {
		name          string
		diag          Diagnostics
		keys          map[string]string
		budgetExpired bool
		wantCode      string
		wantFlow      string
		wantAction    string
	}{
		{"account mismatch outranks complete coverage", Diagnostics{TargetBindingStatus: "mismatch", SessionAccountStatus: "known_other"}, validKey, false, "action_required", "waiting_action", "switch_to_target_account"},
		{"complete", Diagnostics{}, validKey, false, "complete", "terminal", "none"},
		{"trigger required", Diagnostics{HookTriggerRequired: true}, nil, false, "action_required", "waiting_action", "trigger_database"},
		{"restart required", Diagnostics{HookRestartRequired: true}, nil, false, "action_required", "waiting_action", "restart_wechat"},
		{"relogin required", Diagnostics{HookReloginRequired: true}, nil, false, "action_required", "waiting_action", "relogin_wechat"},
		{"permission denied", Diagnostics{ProcessAccessStatus: "denied"}, nil, false, "permission_required", "blocked", "fix_permission"},
		{"untrusted process identity", Diagnostics{ProcessAccessStatus: "denied", ProcessAccessError: "process_identity_untrusted"}, nil, false, "unsupported", "blocked", "stop_and_report"},
		{"wechat not running", Diagnostics{ProcessAccessStatus: "wechat_not_running"}, nil, false, "action_required", "waiting_action", "restart_wechat"},
		{"validator conflict", Diagnostics{ValidatorConflictCount: 1}, nil, false, "failed", "blocked", "stop_and_report"},
		{"candidate ambiguity", Diagnostics{AmbiguousDatabaseKeys: 1}, nil, false, "ambiguous", "blocked", "stop_and_report"},
		{"deadline exhausted", Diagnostics{}, nil, true, "deadline_exhausted", "terminal", "stop_and_report"},
		{"terminal partial", Diagnostics{}, nil, false, "partial", "terminal", "stop_and_report"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			diag := test.diag
			finalizeFixture(&diag, encryptedCatalogFixture(), 1, test.keys, false, true, false, test.budgetExpired)
			if diag.ResultCode != test.wantCode || diag.WorkflowStatus != test.wantFlow || diag.NextAction != test.wantAction {
				t.Fatalf("state = %s/%s/%s, want %s/%s/%s; diagnostics=%+v",
					diag.ResultCode, diag.WorkflowStatus, diag.NextAction,
					test.wantCode, test.wantFlow, test.wantAction, diag)
			}
		})
	}
}

func TestFinalizeBudgetCannotOverwriteHigherPriorityOutcome(t *testing.T) {
	tests := []struct {
		name       string
		diag       Diagnostics
		wantResult string
		wantAction string
	}{
		{"helper untrusted", Diagnostics{HelperStatus: "untrusted", ProcessAccessStatus: "denied", BudgetExhausted: true}, "unsupported", "stop_and_report"},
		{"permission", Diagnostics{ProcessAccessStatus: "denied", BudgetExhausted: true}, "permission_required", "fix_permission"},
		{"validator conflict", Diagnostics{ValidatorConflictCount: 1, BudgetExhausted: true}, "failed", "stop_and_report"},
		{"ambiguous", Diagnostics{AmbiguousDatabaseKeys: 1, BudgetExhausted: true}, "ambiguous", "stop_and_report"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			diag := test.diag
			finalizeFixture(&diag, encryptedCatalogFixture(), 1, nil, false, true, false, false)
			if diag.ResultCode != test.wantResult || diag.NextAction != test.wantAction {
				t.Fatalf("budget overwrote a higher-priority outcome: %+v", diag)
			}
		})
	}

	diag := Diagnostics{BudgetExhausted: true, ProcessAccessStatus: "opened"}
	finalizeFixture(&diag, encryptedCatalogFixture(), 1, nil, false, true, false, false)
	if diag.ResultCode != "deadline_exhausted" || diag.WorkflowStatus != "terminal" || diag.NextAction != "stop_and_report" || diag.ProcessAccessStatus != "opened" {
		t.Fatalf("budget outcome was not authoritative: %+v", diag)
	}
}

func TestPlatformDefaultsKeepStableCollections(t *testing.T) {
	for _, test := range []struct {
		platform   string
		shadow     string
		config     string
		routeCount int
	}{
		{"darwin", "unavailable_in_build", "not_applicable", 3},
		{"windows", "not_applicable", "not_evaluated", 0},
		{"unsupported", "not_applicable", "not_applicable", 0},
	} {
		diag := NewWithPlatformDefaults(test.platform, []string{"media", "database"}, PlatformDefaults{
			SecurityPostureStatus: "not_applicable", DarwinShadowRouteStatus: "unavailable_in_build",
		})
		if diag.ShadowRouteStatus != test.shadow || diag.ConfigCipherRouteStatus != test.config || len(diag.RoutePriority) != test.routeCount ||
			diag.StandardRouteEvidence == nil || diag.WindowsRouteEvidence == nil || diag.PhaseTimingsMS == nil || diag.FallbackStageCounts == nil {
			t.Fatalf("unstable %s defaults: %+v", test.platform, diag)
		}
	}
}

func TestCoverageDiagnosticsJSONUsesOnlyScopeQualifiedFields(t *testing.T) {
	payload, err := json.Marshal(Diagnostics{
		RequestedScopes: []string{"database", "media"}, DatabaseCoverageStatus: "complete", MediaCoverageStatus: "none",
		ShadowRouteStatus: "not_applicable", RoutePriority: []string{}, RoutesAttempted: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["database_coverage_status"] != "complete" || fields["media_coverage_status"] != "none" ||
		fields["shadow_route_status"] != "not_applicable" || fields["coverage_status"] != nil || fields["media_status"] != nil {
		t.Fatalf("coverage diagnostics JSON retained an ambiguous field: %s", payload)
	}
}
