package session

import (
	"testing"

	catalogmodel "github.com/zanescope/v-local-key-provider/internal/catalog"
	credentialmodel "github.com/zanescope/v-local-key-provider/internal/credential"
	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
)

func TestReceiptFingerprintBindsMachineObservedTransition(t *testing.T) {
	state := ReceiptState{CatalogID: "catalog", ProcessInstanceID: "before", LastRoute: "standard", LastActionStage: "restart_wechat"}
	receipt := &protocolmodel.ActionReceipt{
		Action: "restart_wechat", UserConfirmed: true, ProcessInstanceID: "before",
		Route: "standard", ObservedProcessTransition: "process_changed",
	}
	if fingerprint, err := ReceiptFingerprint(receipt, state, "after"); err != nil || fingerprint == "" {
		t.Fatalf("valid transition was rejected: fingerprint=%q err=%v", fingerprint, err)
	}
	if _, err := ReceiptFingerprint(receipt, state, "before"); err == nil {
		t.Fatal("restart receipt without observed process change was accepted")
	}
}

func TestMergeResultsPreservesEvidenceAndOverridesCurrentValues(t *testing.T) {
	existing := &protocolmodel.Response{
		DatabaseKeys: map[string]string{"a.db": "old", "b.db": "old-b"},
		DatabaseCredential: &credentialmodel.DatabaseCredential{
			Roots: []credentialmodel.Root{{Kind: "global_passphrase", ProfileID: "p", Secret: "s", VerifiedDatabaseIDs: []string{"a"}}},
		},
	}
	next := protocolmodel.Response{
		DatabaseKeys: map[string]string{"a.db": "new"},
		DatabaseCredential: &credentialmodel.DatabaseCredential{
			Roots: []credentialmodel.Root{{Kind: "global_passphrase", ProfileID: "p", Secret: "s", VerifiedDatabaseIDs: []string{"b"}}},
		},
	}
	merged := MergeResults(existing, next)
	if merged.DatabaseKeys["a.db"] != "new" || merged.DatabaseKeys["b.db"] != "old-b" || len(merged.DatabaseCredential.Roots[0].VerifiedDatabaseIDs) != 2 {
		t.Fatalf("unexpected merged response: %+v", merged)
	}
}

func TestSecretPolicyFailsClosedAndAllowsCompleteTerminal(t *testing.T) {
	value := protocolmodel.Response{
		DatabaseKeys: map[string]string{"a": "secret"},
		ImageKeys:    &protocolmodel.ImageKeys{AES: "secret"},
		Diagnostics: diagnosticmodel.Diagnostics{
			RequestedScopes: []string{"database"}, DatabaseCoverageStatus: "complete",
			ResultCode: "action_required", WorkflowStatus: "blocked", BlockingReasons: []string{"catalog_drift"},
		},
	}
	if filtered := EnforceSecretPolicy(value); filtered.DatabaseKeys != nil || filtered.ImageKeys != nil {
		t.Fatalf("blocked response leaked secrets: %+v", filtered)
	}
	value.Diagnostics.ResultCode = "complete"
	value.Diagnostics.WorkflowStatus = "terminal"
	value.Diagnostics.BlockingReasons = nil
	if filtered := EnforceSecretPolicy(value); filtered.DatabaseKeys == nil || filtered.ImageKeys == nil {
		t.Fatalf("complete terminal response lost secrets: %+v", filtered)
	}
}

func TestActionRetryLimitsRemainBounded(t *testing.T) {
	if ActionRetryLimit("trigger_database") != 2 || ActionRetryLimit("restart_wechat") != 1 || ActionRetryLimit("disable_sip") != 0 {
		t.Fatal("action retry limits changed")
	}
}

func TestMissingCatalogKeepsOnlyUncoveredRequiredTargets(t *testing.T) {
	catalog := catalogmodel.Catalog{CatalogID: "catalog", DiscoveryErrors: []string{"evidence"}, Databases: []catalogmodel.Database{
		{RelativePath: "covered.db", RequiredForKeyCoverage: true},
		{RelativePath: "missing.db", RequiredForKeyCoverage: true},
		{RelativePath: "plain.db", RequiredForKeyCoverage: false},
	}}
	subset, paths := MissingCatalog(catalog, map[string]string{"covered.db": "key"})
	if subset.CatalogID != catalog.CatalogID || len(subset.Databases) != 1 || subset.Databases[0].RelativePath != "missing.db" || !paths["missing.db"] {
		t.Fatalf("unexpected missing catalog: subset=%+v paths=%v", subset, paths)
	}
}
