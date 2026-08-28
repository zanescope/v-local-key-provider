package session

import (
	"errors"
	"testing"
	"time"

	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
)

func testStore(closed *int) *Store {
	return NewStore(StoreHooks{
		SamePath: func(left, right string) bool { return left == right },
		ClosePlatform: func(any) {
			(*closed)++
		},
	})
}

func testRecord(store *Store, id string) *Record {
	record := store.NewRecord(RecordInput{
		ID: id, AccountDir: "/account", DBDir: "/account/db", CatalogKey: []byte{1, 2, 3},
		CatalogID: "catalog", Scopes: []string{"database"}, ProcessInstanceID: "process",
		LastActionStage: "prepare", PlatformSession: "platform", ClientIdentity: "client",
	})
	record.Latest = &protocolmodel.Response{
		DatabaseKeys: map[string]string{"message.db": "secret"},
		Diagnostics: diagnosticmodel.Diagnostics{
			BlockingReasons: []string{"fixture"}, PhaseTimingsMS: map[string]int64{"total": 1},
		},
	}
	return record
}

func TestStoreBeginReturnsDetachedSnapshotAndCancelCannotClearIt(t *testing.T) {
	closed := 0
	store := testStore(&closed)
	record := testRecord(store, "session")
	liveKey := record.CatalogKey
	if err := store.Insert(record); err != nil {
		t.Fatal(err)
	}
	begin, err := store.Begin(BeginInput{
		SessionID: "session", AccountDir: "/account", DBDir: "/account/db", Scopes: []string{"database"},
		ClientIdentity: "client", Operation: "observe", ExpectedCatalogID: "catalog",
		CurrentProcessInstanceID: "process",
	})
	if err != nil || begin.Status != BeginReady || begin.Session == nil {
		t.Fatalf("begin = %+v, err=%v", begin, err)
	}
	if &begin.Session.CatalogKey[0] == &liveKey[0] {
		t.Fatal("ready snapshot aliases the live catalog key")
	}
	store.Mutate("session", func(current *Record) {
		current.CatalogKey[0] = 9
		current.Latest.DatabaseKeys["message.db"] = "changed"
		current.Latest.Diagnostics.BlockingReasons[0] = "changed"
		current.Latest.Diagnostics.PhaseTimingsMS["total"] = 9
	})
	if begin.Session.CatalogKey[0] != 1 || begin.Session.Latest.DatabaseKeys["message.db"] != "secret" ||
		begin.Session.Latest.Diagnostics.BlockingReasons[0] != "fixture" || begin.Session.Latest.Diagnostics.PhaseTimingsMS["total"] != 1 {
		t.Fatalf("ready snapshot changed with live record: %+v", begin.Session)
	}
	cancelled, err := store.Begin(BeginInput{
		SessionID: "session", AccountDir: "/account", DBDir: "/account/db", Scopes: []string{"database"},
		ClientIdentity: "client", Operation: "cancel", CurrentProcessInstanceID: "process",
	})
	if err != nil || cancelled.Status != BeginCancelled || store.Has("session") {
		t.Fatalf("cancel = %+v, err=%v", cancelled, err)
	}
	if closed != 1 || liveKey[0] != 0 || begin.Session.CatalogKey[0] != 1 {
		t.Fatalf("cleanup crossed snapshot boundary: closed=%d live=%v snapshot=%v", closed, liveKey, begin.Session.CatalogKey)
	}
	if store.Commit("session", CommitInput{}) {
		t.Fatal("cancelled in-flight session accepted a stale commit")
	}
	snapshotKey := begin.Session.CatalogKey
	store.ReleaseSnapshot(begin.Session)
	for _, value := range snapshotKey {
		if value != 0 {
			t.Fatalf("released snapshot retained catalog key bytes: %v", snapshotKey)
		}
	}
	store.ReleaseSnapshot(cancelled.Session)
}

func TestStoreRejectsDuplicateAccountAndExpiresRecords(t *testing.T) {
	closed := 0
	store := testStore(&closed)
	base := time.Now()
	store.SetClock(func() time.Time { return base })
	first := testRecord(store, "first")
	if err := store.Insert(first); err != nil {
		t.Fatal(err)
	}
	second := testRecord(store, "second")
	if err := store.Insert(second); !errors.Is(err, ErrAccountActive) {
		t.Fatalf("duplicate account error = %v", err)
	}
	store.Discard(second)
	store.SetClock(func() time.Time { return base.Add(MaxLifetime + time.Second) })
	if count := store.ActiveCount(); count != 0 {
		t.Fatalf("expired session count = %d", count)
	}
	if closed != 2 {
		t.Fatalf("platform cleanup count = %d, want 2", closed)
	}
}

func TestCloneResponsePreservesExplicitEmptyDiagnosticCollections(t *testing.T) {
	response := &protocolmodel.Response{Diagnostics: diagnosticmodel.Diagnostics{
		RequestedScopes:       []string{},
		RoutePriority:         []string{},
		BlockingReasons:       []string{},
		CandidateSources:      []string{},
		MissingDatabaseIDs:    []string{},
		RoutesAttempted:       []string{},
		StandardRouteEvidence: []string{},
		WindowsRouteEvidence:  []string{},
	}}
	clone := CloneResponse(response)
	if clone == nil {
		t.Fatal("response clone 为空")
	}
	collections := map[string][]string{
		"requested_scopes":        clone.Diagnostics.RequestedScopes,
		"route_priority":          clone.Diagnostics.RoutePriority,
		"blocking_reasons":        clone.Diagnostics.BlockingReasons,
		"candidate_sources":       clone.Diagnostics.CandidateSources,
		"missing_database_ids":    clone.Diagnostics.MissingDatabaseIDs,
		"routes_attempted":        clone.Diagnostics.RoutesAttempted,
		"standard_route_evidence": clone.Diagnostics.StandardRouteEvidence,
		"windows_route_evidence":  clone.Diagnostics.WindowsRouteEvidence,
	}
	for name, values := range collections {
		if values == nil || len(values) != 0 {
			t.Fatalf("%s 未保留显式空数组: %#v", name, values)
		}
	}
}
