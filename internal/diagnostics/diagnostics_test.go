package diagnostics

import (
	"reflect"
	"testing"
)

func TestNewDiagnosticsKeepsStableCollectionsAndScopeOrder(t *testing.T) {
	value := New("windows", []string{"media", "database", "media"}, "not_applicable")
	if !reflect.DeepEqual(value.RequestedScopes, []string{"database", "media"}) ||
		value.BlockingReasons == nil || value.CandidateSources == nil || value.RoutesAttempted == nil ||
		value.PhaseTimingsMS == nil || value.FallbackStageCounts == nil {
		t.Fatalf("diagnostic defaults are unstable: %+v", value)
	}
}

func TestSessionMergePoliciesAreExhaustiveAndTyped(t *testing.T) {
	policies := NewSessionMergePolicies()
	if err := ValidateSessionMergePolicies(policies); err != nil {
		t.Fatal(err)
	}
	delete(policies, "ResultCode")
	if err := ValidateSessionMergePolicies(policies); err == nil {
		t.Fatal("incomplete diagnostic merge policy was accepted")
	}
}

func TestMergeSessionFieldsPreservesPolicySemantics(t *testing.T) {
	maximumInt := int(^uint(0) >> 1)
	previous := Diagnostics{
		Platform: "darwin", WeChatVersion: "4.1", CandidateSources: []string{"first"},
		FallbackStageCounts: map[string]int{"scan": maximumInt}, CandidateCount: maximumInt,
		ScannedBytes: ^uint64(0) - 1, HookInstalled: true, HookCaptureCount: 7,
	}
	next := Diagnostics{
		CandidateSources: []string{"first", "second"}, FallbackStageCounts: map[string]int{"scan": 1},
		CandidateCount: 1, ScannedBytes: 2, HookCaptureCount: 2,
	}
	MergeSessionFields(previous, &next, NewSessionMergePolicies())
	if next.Platform != "darwin" || next.WeChatVersion != "4.1" ||
		!reflect.DeepEqual(next.CandidateSources, []string{"first", "second"}) ||
		next.FallbackStageCounts["scan"] != maximumInt || next.CandidateCount != maximumInt ||
		next.ScannedBytes != ^uint64(0) || !next.ScanLimited || !next.HookInstalled || next.HookCaptureCount != 7 {
		t.Fatalf("diagnostic merge semantics changed: %+v", next)
	}
}

func TestWindowsSnapshotCopiesOneCoherentInventory(t *testing.T) {
	source := Diagnostics{
		TargetBindingStatus: "path_verified", WeChatVersion: "4.1", ProcessArchitecture: "arm64",
		ProcessDiscoveryMethod: "toolhelp32", ProcessCount: 3, OpenedProcessCount: 2,
	}
	var destination Diagnostics
	CopyWindowsProcessSnapshot(&destination, source)
	if destination.TargetBindingStatus != source.TargetBindingStatus || destination.WeChatVersion != source.WeChatVersion ||
		destination.ProcessArchitecture != source.ProcessArchitecture || destination.ProcessDiscoveryMethod != source.ProcessDiscoveryMethod ||
		destination.ProcessCount != 3 || destination.OpenedProcessCount != 2 {
		t.Fatalf("Windows process snapshot was not copied coherently: %+v", destination)
	}
}
