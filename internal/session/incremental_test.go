package session

import (
	"testing"

	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
	windowsmodel "github.com/zanescope/v-local-key-provider/internal/platform/windows"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
)

func TestWindowsSessionMergeKeepsCurrentProcessSnapshotCoherent(t *testing.T) {
	existing := &protocolmodel.Response{Diagnostics: diagnosticmodel.Diagnostics{
		Platform: "windows", ProcessDiscoveryMethod: "toolhelp_snapshot",
		ProcessCount: 1, OtherAccountProcessCount: 1,
		TargetBindingStatus: "mismatch", SessionAccountStatus: "known_other",
		ProcessAccessStatus:     "not_attempted_account_mismatch",
		ConfigCipherRouteStatus: windowsmodel.ConfigCipherNotEvaluated,
		ScannedBytes:            11,
	}}
	next := diagnosticmodel.Diagnostics{
		Platform: "windows", ProcessDiscoveryMethod: "toolhelp_snapshot",
		ProcessCount: 1, SelectedProcessCount: 1, TargetBoundProcessCount: 1, OpenedProcessCount: 1,
		TargetBindingStatus: "path_verified", SessionAccountStatus: "known_target",
		ProcessAccessStatus: "direct_opened", ConfigCipherRouteStatus: windowsmodel.ConfigCipherUnavailableUnknown,
		ScannedBytes: 7,
	}
	MergeDiagnosticEvidence(existing, &next, windowsmodel.ConfigStatusRank)
	if next.ProcessCount != 1 || next.SelectedProcessCount != 1 || next.TargetBoundProcessCount != 1 ||
		next.OtherAccountProcessCount != 0 || next.UnknownAccountProcessCount != 0 || next.OpenedProcessCount != 1 ||
		next.TargetBindingStatus != "path_verified" || next.SessionAccountStatus != "known_target" {
		t.Fatalf("Windows process snapshots were merged field-by-field: %+v", next)
	}
	if next.ScannedBytes != 18 {
		t.Fatalf("Windows session scan bytes were not accumulated: %d", next.ScannedBytes)
	}
}

func TestWindowsSessionMergeReusesWholeSnapshotWhenNoScanRuns(t *testing.T) {
	existing := &protocolmodel.Response{Diagnostics: diagnosticmodel.Diagnostics{
		Platform: "windows", ProcessDiscoveryMethod: "toolhelp_snapshot",
		ProcessCount: 2, SelectedProcessCount: 1, TargetBoundProcessCount: 1,
		OtherAccountProcessCount: 1, OpenedProcessCount: 1,
		TargetBindingStatus: "path_verified", SessionAccountStatus: "known_target",
		ProcessAccessStatus: "direct_opened", ProcessArchitecture: "amd64",
		ProcessArchitectureStatus: windowsmodel.ArchitectureVerified,
		ConfigCipherRouteStatus:   windowsmodel.ConfigCipherUnavailableUnknown,
	}}
	next := diagnosticmodel.Diagnostics{Platform: "windows"}
	MergeDiagnosticEvidence(existing, &next, windowsmodel.ConfigStatusRank)
	if next.ProcessDiscoveryMethod != "toolhelp_snapshot" || next.ProcessCount != 2 || next.SelectedProcessCount != 1 ||
		next.TargetBoundProcessCount != 1 || next.OtherAccountProcessCount != 1 || next.OpenedProcessCount != 1 ||
		next.ProcessArchitecture != "amd64" || next.ProcessArchitectureStatus != windowsmodel.ArchitectureVerified {
		t.Fatalf("Windows process snapshot was not preserved as a unit: %+v", next)
	}
}

func TestCoordinatorDiagnosticMergePoliciesRemainExhaustiveAndTyped(t *testing.T) {
	if err := diagnosticmodel.ValidateSessionMergePolicies(diagnosticMergePolicies); err != nil {
		t.Fatal(err)
	}
	existing := &protocolmodel.Response{Diagnostics: diagnosticmodel.Diagnostics{
		Platform: "darwin", CandidateCount: 2, RawKeyCandidateCount: 3,
		AmbiguousDatabaseKeys: 1, V2SampleCount: 4, ScanLimited: true,
		VersionSupport: "verified", HookTriggerRequired: true, HookReloginRequired: true,
	}}
	next := diagnosticmodel.Diagnostics{
		Platform: "darwin", CandidateCount: 5, RawKeyCandidateCount: 7,
		V2SampleCount: 2,
	}
	MergeDiagnosticEvidence(existing, &next, windowsmodel.ConfigStatusRank)
	if next.CandidateCount != 7 || next.RawKeyCandidateCount != 10 {
		t.Fatalf("scan observations were not accumulated: %+v", next)
	}
	if next.AmbiguousDatabaseKeys != 1 || next.V2SampleCount != 4 || !next.ScanLimited || next.VersionSupport != "verified" {
		t.Fatalf("monotonic diagnostic evidence was lost: %+v", next)
	}
	if next.HookTriggerRequired || next.HookReloginRequired {
		t.Fatalf("prior action flags leaked into the current pass: %+v", next)
	}
}

func TestSessionMergePreservesDarwinMachineEvidence(t *testing.T) {
	existing := &protocolmodel.Response{Diagnostics: diagnosticmodel.Diagnostics{
		BinaryFingerprintStatus: "verified", BinarySigningStatus: "verified",
		ProcessArchitecture: "arm64", ProcessArchitectureStatus: "verified_running_process",
		ProcessTranslationStatus: "native", CompatibilityRegistryStatus: "unregistered",
		StandardRouteStatus: "eligible_generic_dynamic", ShadowRouteStatus: "unavailable_in_build",
		RoutePriority: []string{"standard", "shadow", "sip_disabled"}, HelperStatus: "used",
	}}
	next := diagnosticmodel.Diagnostics{}
	MergeDiagnosticEvidence(existing, &next, windowsmodel.ConfigStatusRank)
	if next.BinaryFingerprintStatus != "verified" || next.BinarySigningStatus != "verified" ||
		next.ProcessArchitecture != "arm64" || next.ProcessArchitectureStatus != "verified_running_process" ||
		next.ProcessTranslationStatus != "native" || next.CompatibilityRegistryStatus != "unregistered" ||
		next.StandardRouteStatus != "eligible_generic_dynamic" || next.ShadowRouteStatus != "unavailable_in_build" ||
		len(next.RoutePriority) != 3 || next.HelperStatus != "used" {
		t.Fatalf("incremental session lost Darwin evidence: %+v", next)
	}
}
