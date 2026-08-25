package session

import (
	"context"
	"errors"
	"testing"

	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	catalogmodel "github.com/zanescope/v-local-key-provider/internal/catalog"
	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
	"github.com/zanescope/v-local-key-provider/internal/workbudget"
)

type coordinatorFixture struct {
	catalogID           string
	processID           string
	acquireCalls        int
	acquireErr          error
	preparedHelperMode  bool
	preparedHelperState string
	acquireHelperMode   bool
	acquireHelperState  string
}

func (fixture *coordinatorFixture) runtime() Runtime {
	return Runtime{
		Protocol: protocolmodel.Name,
		ParseOptions: func(request protocolmodel.AcquireRequest) (Options, error) {
			return Options{
				AccountDir: request.AccountDir,
				DBDir:      request.DBDir,
				Database:   true,
				Budget:     workbudget.Unlimited(),
				CatalogKey: append([]byte(nil), make([]byte, 32)...),
			}, nil
		},
		DiscoverTargets: func(string, workbudget.Budget, []byte) (acquisitionmodel.Targets, error) {
			return acquisitionmodel.Targets{
				Count: 1,
				Catalog: catalogmodel.Catalog{
					CatalogID: fixture.catalogID,
					Databases: []catalogmodel.Database{{
						DatabaseID: "db-1", RelativePath: "message.db",
						Classification:         catalogmodel.ClassificationEncrypted,
						RequiredForKeyCoverage: true,
					}},
				},
			}, nil
		},
		ProcessInstanceID: func() string { return fixture.processID },
		NewOpaqueID:       func() (string, error) { return "session-1", nil },
		PreparePlatformSession: func(_ acquisitionmodel.Targets, options Options) acquisitionmodel.PlatformSession {
			fixture.preparedHelperMode = options.HelperMode
			fixture.preparedHelperState = options.HelperStatus
			return nil
		},
		NewDiagnostics: func(scopes []string) diagnosticmodel.Diagnostics {
			return diagnosticmodel.New("test", scopes, "verified")
		},
		Driver: acquisitionmodel.PlatformDriverFunc(func(
			_ acquisitionmodel.Targets,
			_ acquisitionmodel.MediaEvidence,
			request acquisitionmodel.PlatformRequest,
		) (protocolmodel.Response, diagnosticmodel.Diagnostics, error) {
			fixture.acquireCalls++
			fixture.acquireHelperMode = request.HelperMode
			fixture.acquireHelperState = request.HelperStatus
			if fixture.acquireErr != nil {
				return protocolmodel.Response{}, diagnosticmodel.Diagnostics{}, fixture.acquireErr
			}
			return protocolmodel.Response{
				DatabaseKeys: map[string]string{"message.db": "secret"},
			}, diagnosticmodel.New("test", []string{"database"}, "verified"), nil
		}),
		CatalogHMAC:      func([]byte, ...string) string { return "binding" },
		ClearSensitive:   clearBytes,
		ConfigStatusRank: func(string) int { return 0 },
	}
}

func workflowRequest(operation string) protocolmodel.AcquireRequest {
	return protocolmodel.AcquireRequest{
		Protocol:     protocolmodel.Name,
		RequestID:    "request-1",
		Action:       "acquire",
		AccountDir:   "/account",
		DBDir:        "/account/db",
		Scopes:       []string{"database"},
		DeadlineMS:   30_000,
		PeerIdentity: "test-client",
		Workflow:     protocolmodel.WorkflowRequest{Operation: operation},
	}
}

func prepareFixture(t *testing.T, coordinator *Coordinator) (protocolmodel.AcquireRequest, protocolmodel.Response) {
	t.Helper()
	request := workflowRequest("prepare")
	prepared, err := coordinator.Handle(context.Background(), request, Environment{})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Diagnostics.SessionID == "" || prepared.CatalogID == "" {
		t.Fatalf("prepare did not bind the workflow: %+v", prepared)
	}
	return request, prepared
}

func TestCoordinatorOwnsObserveFinalizeSecretLifecycle(t *testing.T) {
	fixture := &coordinatorFixture{catalogID: "catalog-1", processID: "process-1"}
	store := NewStore(StoreHooks{})
	coordinator := NewCoordinator(store, fixture.runtime())
	request, prepared := prepareFixture(t, coordinator)

	observe := request
	observe.RequestID = "request-observe"
	observe.Workflow = protocolmodel.WorkflowRequest{
		Operation: "observe", SessionID: prepared.Diagnostics.SessionID,
		ExpectedCatalogID: prepared.CatalogID,
	}
	observed, err := coordinator.Handle(context.Background(), observe, Environment{})
	if err != nil {
		t.Fatal(err)
	}
	if observed.DatabaseKeys != nil || fixture.acquireCalls != 1 {
		t.Fatalf("observe leaked secrets or skipped acquisition: response=%+v calls=%d", observed, fixture.acquireCalls)
	}
	snapshot := store.Snapshot(prepared.Diagnostics.SessionID)
	if snapshot == nil || snapshot.Latest == nil || snapshot.Latest.DatabaseKeys["message.db"] != "secret" {
		t.Fatalf("observe did not retain the verified result for finalize: %+v", snapshot)
	}
	store.ReleaseSnapshot(snapshot)

	finalize := observe
	finalize.RequestID = "request-finalize"
	finalize.Workflow.Operation = "finalize"
	finalized, err := coordinator.Handle(context.Background(), finalize, Environment{})
	if err != nil {
		t.Fatal(err)
	}
	if finalized.DatabaseKeys["message.db"] != "secret" || fixture.acquireCalls != 1 {
		t.Fatalf("finalize lost or reacquired the cached secret: response=%+v calls=%d", finalized, fixture.acquireCalls)
	}
	if store.Has(prepared.Diagnostics.SessionID) {
		t.Fatal("finalize left the session active")
	}
}

func TestCoordinatorBlocksCatalogDriftBeforePlatformAcquire(t *testing.T) {
	fixture := &coordinatorFixture{catalogID: "catalog-1", processID: "process-1"}
	store := NewStore(StoreHooks{})
	coordinator := NewCoordinator(store, fixture.runtime())
	request, prepared := prepareFixture(t, coordinator)
	fixture.catalogID = "catalog-2"

	request.RequestID = "request-observe"
	request.Workflow = protocolmodel.WorkflowRequest{
		Operation: "observe", SessionID: prepared.Diagnostics.SessionID,
		ExpectedCatalogID: prepared.CatalogID,
	}
	result, err := coordinator.Handle(context.Background(), request, Environment{})
	if err != nil {
		t.Fatal(err)
	}
	if fixture.acquireCalls != 0 || result.Diagnostics.WorkflowStatus != "blocked" ||
		len(result.Diagnostics.BlockingReasons) != 1 || result.Diagnostics.BlockingReasons[0] != "catalog_drift" {
		t.Fatalf("catalog drift reached acquisition or was not blocked: response=%+v calls=%d", result, fixture.acquireCalls)
	}
	snapshot := store.Snapshot(prepared.Diagnostics.SessionID)
	if snapshot == nil || snapshot.InFlight {
		t.Fatalf("catalog drift removed or wedged the actionable session: %+v", snapshot)
	}
	store.ReleaseSnapshot(snapshot)
}

func TestCoordinatorReleasesInFlightAfterAcquireError(t *testing.T) {
	fixture := &coordinatorFixture{
		catalogID: "catalog-1", processID: "process-1", acquireErr: errors.New("acquire failed"),
	}
	store := NewStore(StoreHooks{})
	coordinator := NewCoordinator(store, fixture.runtime())
	request, prepared := prepareFixture(t, coordinator)

	request.Workflow = protocolmodel.WorkflowRequest{
		Operation: "observe", SessionID: prepared.Diagnostics.SessionID,
		ExpectedCatalogID: prepared.CatalogID,
	}
	if _, err := coordinator.Handle(context.Background(), request, Environment{}); !errors.Is(err, fixture.acquireErr) {
		t.Fatalf("platform error was not returned: %v", err)
	}
	snapshot := store.Snapshot(prepared.Diagnostics.SessionID)
	if snapshot == nil || snapshot.InFlight {
		t.Fatalf("failed acquisition left a partial state transition: %+v", snapshot)
	}
	store.ReleaseSnapshot(snapshot)
}

func TestCoordinatorInjectsDaemonEnvironmentIntoPlatformBoundaries(t *testing.T) {
	fixture := &coordinatorFixture{catalogID: "catalog-1", processID: "process-1"}
	store := NewStore(StoreHooks{})
	coordinator := NewCoordinator(store, fixture.runtime())
	environment := Environment{HelperMode: true, HelperStatus: "used"}
	request := workflowRequest("prepare")
	prepared, err := coordinator.Handle(context.Background(), request, environment)
	if err != nil {
		t.Fatal(err)
	}
	request.Workflow = protocolmodel.WorkflowRequest{
		Operation: "observe", SessionID: prepared.Diagnostics.SessionID,
		ExpectedCatalogID: prepared.CatalogID,
	}
	if _, err := coordinator.Handle(context.Background(), request, environment); err != nil {
		t.Fatal(err)
	}
	if !fixture.preparedHelperMode || fixture.preparedHelperState != "used" ||
		!fixture.acquireHelperMode || fixture.acquireHelperState != "used" {
		t.Fatalf("daemon environment did not reach platform boundaries: %+v", fixture)
	}
}

func TestCoordinatorClearsPartiallyParsedCatalogKeyOnError(t *testing.T) {
	parseErr := errors.New("parse failed")
	secret := []byte{1, 2, 3}
	cleared := false
	runtime := Runtime{
		ParseOptions: func(protocolmodel.AcquireRequest) (Options, error) {
			return Options{CatalogKey: secret}, parseErr
		},
		NewOpaqueID: func() (string, error) { return "unused", nil },
		ClearSensitive: func(value []byte) {
			clearBytes(value)
			cleared = true
		},
	}
	coordinator := NewCoordinator(NewStore(StoreHooks{}), runtime)
	if _, err := coordinator.Handle(context.Background(), workflowRequest("prepare"), Environment{}); !errors.Is(err, parseErr) {
		t.Fatalf("parse error was not returned: %v", err)
	}
	if !cleared || secret[0] != 0 || secret[1] != 0 || secret[2] != 0 {
		t.Fatalf("partially parsed catalog key was not cleared: %v", secret)
	}
}

func TestMergeDiagnosticEvidencePreservesCoherentWindowsSnapshot(t *testing.T) {
	existing := &protocolmodel.Response{Diagnostics: diagnosticmodel.Diagnostics{
		Platform: "windows", ProcessDiscoveryMethod: "toolhelp_snapshot",
		ProcessCount: 2, SelectedProcessCount: 1,
		TargetBindingStatus: "mismatch", SessionAccountStatus: "known_other",
		ConfigCipherRouteStatus: "succeeded", ExecutableSHA256: "strong",
	}}
	next := diagnosticmodel.Diagnostics{Platform: "windows", ConfigCipherRouteStatus: "not_evaluated"}
	rank := func(status string) int {
		if status == "succeeded" {
			return 2
		}
		if status == "not_evaluated" {
			return 1
		}
		return 0
	}
	MergeDiagnosticEvidence(existing, &next, rank)
	if next.ProcessCount != 2 || next.SelectedProcessCount != 1 || next.TargetBindingStatus != "mismatch" ||
		next.SessionAccountStatus != "known_other" || next.ExecutableSHA256 != "strong" {
		t.Fatalf("Windows session evidence lost snapshot coherence: %+v", next)
	}
}
