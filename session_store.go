package provider

import (
	"strings"
	"time"

	sessionmodel "github.com/zanescope/v-local-key-provider/internal/session"
)

const acquisitionSessionMaxLifetime = sessionmodel.MaxLifetime

type acquisitionSession = sessionmodel.Record

type acquisitionSessionStore struct {
	core         *sessionmodel.Store
	helperMode   bool
	helperStatus string
}

func newAcquisitionSessionStore() *acquisitionSessionStore {
	return &acquisitionSessionStore{core: sessionmodel.NewStore(sessionmodel.StoreHooks{
		SamePath:    sameCanonicalPath,
		CloneSecret: cloneSensitiveBytes,
		ClearSecret: zeroBytes,
		ClosePlatform: func(value any) {
			if session, ok := value.(acquisitionPlatformSession); ok && session != nil {
				session.close()
			}
		},
	})}
}

func (store *acquisitionSessionStore) activeCount() int {
	return store.core.ActiveCount()
}

func (store *acquisitionSessionStore) closeAll() {
	store.core.CloseAll()
}

func (store *acquisitionSessionStore) cancelSession(id string) {
	store.core.Delete(id)
}

func (store *acquisitionSessionStore) sessionSnapshot(id string) *acquisitionSession {
	return store.core.Snapshot(id)
}

func (store *acquisitionSessionStore) hasSession(id string) bool {
	return store.core.Has(id)
}

func (store *acquisitionSessionStore) mutateSession(id string, mutate func(*acquisitionSession)) bool {
	return store.core.Mutate(id, mutate)
}

func (store *acquisitionSessionStore) setClock(now func() time.Time) {
	store.core.SetClock(now)
}

func (store *acquisitionSessionStore) prepare(request acquireRequest) (response, error) {
	if !store.core.Accepting() {
		return response{}, sessionmodel.ErrStoreClosing
	}
	prepareStarted := time.Now()
	options, err := optionsFromRequest(request)
	if err != nil {
		return response{}, err
	}
	defer zeroBytes(options.catalogKey)
	options.helperMode = store.helperMode
	options.helperStatus = store.helperStatus
	targets := databaseTargets{catalog: databaseCatalog{}}
	discoveryStarted := time.Now()
	if options.database {
		targets, err = discoverDatabaseTargetsWithKey(options.dbDir, options.budget, options.catalogKey)
		if err != nil {
			return response{}, err
		}
	}
	discoveryElapsed := time.Since(discoveryStarted).Milliseconds()
	id, err := randomOpaqueID()
	if err != nil {
		return response{}, err
	}
	processInstanceID := platformProcessInstanceID()
	session := store.core.NewRecord(sessionmodel.RecordInput{
		ID: id, AccountDir: options.accountDir, DBDir: options.dbDir,
		CatalogKey: options.catalogKey, CatalogID: targets.catalog.CatalogID,
		Scopes: request.Scopes, ProcessInstanceID: processInstanceID,
		LastActionStage: "prepare", ClientIdentity: request.PeerIdentity,
	})
	routeStarted := time.Now()
	session.PlatformSession = preparePlatformAcquisitionSession(targets, options)
	routeElapsed := time.Since(routeStarted).Milliseconds()
	if err := store.core.Insert(session); err != nil {
		store.core.Discard(session)
		return response{}, err
	}
	diag := newDiagnostics(platformNameForDiagnostics(), requestedScopes(options.database, options.media))
	applyFixedDiagnosticOutcome(&diag, "partial", "running", "none")
	diag.MissingDatabaseCount = targets.count
	diag.MissingDatabaseIDs = missingDatabaseIDs(targets, nil)
	diag.DatabaseCount = len(targets.catalog.Databases)
	diag.RequiredDatabaseCount = targets.count
	diag.SessionID = id
	diag.ProcessInstanceID = processInstanceID
	diag.SessionExpiresAt = session.ExpiresAt.UTC().Format(time.RFC3339Nano)
	diag.ActionStage = "prepare"
	diag.PhaseTimingsMS = map[string]int64{
		"target_database_discovery": discoveryElapsed, "route_prepare": routeElapsed,
		"prepare_total": time.Since(prepareStarted).Milliseconds(), "total": time.Since(prepareStarted).Milliseconds(),
	}
	if options.database {
		diag.DatabaseTargetStatus = "none"
		if len(targets.catalog.Databases) > 0 {
			diag.DatabaseTargetStatus = "present"
		}
		diag.DatabaseCoverageStatus = "none"
	}
	for _, database := range targets.catalog.Databases {
		switch database.Classification {
		case classificationPlaintext:
			diag.PlaintextDatabaseCount++
		case classificationUnreadable:
			diag.UnreadableDatabaseCount++
		case classificationUnstable:
			diag.UnstableDatabaseCount++
		case classificationTruncated:
			diag.TruncatedDatabaseCount++
		}
	}
	if options.media {
		diag.MediaCoverageStatus = "pending"
	}
	if platformSession, ok := session.PlatformSession.(acquisitionPlatformSession); ok && platformSession != nil {
		hook := platformSession.status()
		diag.HookTargetFound = hook.TargetFound
		diag.HookInstalled = hook.Installed
		diag.RouteSelected = hook.Route
		if hook.RouteHistory != "" {
			diag.RoutesAttempted = strings.Split(hook.RouteHistory, "\x00")
		} else if hook.Route != "" {
			diag.RoutesAttempted = []string{hook.Route}
		}
	}
	applyPlatformDiagnosticDefaults(&diag)
	return response{
		Protocol: protocolName, RequestID: request.RequestID, CatalogID: targets.catalog.CatalogID,
		CatalogEntries: append([]catalogDatabase(nil), targets.catalog.Databases...),
		Profiles:       profileSummaries(), Diagnostics: diag,
	}, nil
}
