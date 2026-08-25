package provider

import (
	"context"
	"time"

	sessionmodel "github.com/zanescope/v-local-key-provider/internal/session"
)

const acquisitionSessionMaxLifetime = sessionmodel.MaxLifetime

type acquisitionSession = sessionmodel.Record

type acquisitionSessionStore struct {
	core         *sessionmodel.Store
	coordinator  *sessionmodel.Coordinator
	helperMode   bool
	helperStatus string
}

func newAcquisitionSessionStore() *acquisitionSessionStore {
	core := sessionmodel.NewStore(sessionmodel.StoreHooks{
		SamePath:    sameCanonicalPath,
		CloneSecret: cloneSensitiveBytes,
		ClearSecret: zeroBytes,
		ClosePlatform: func(value any) {
			if session, ok := value.(acquisitionPlatformSession); ok && session != nil {
				session.Close()
			}
		},
	})
	return &acquisitionSessionStore{
		core: core, coordinator: sessionmodel.NewCoordinator(core, acquisitionSessionRuntime()),
	}
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

func (store *acquisitionSessionStore) handleContext(ctx context.Context, request acquireRequest) (response, error) {
	return store.coordinator.Handle(ctx, request, sessionmodel.Environment{
		HelperMode: store.helperMode, HelperStatus: store.helperStatus,
	})
}

func (store *acquisitionSessionStore) handle(request acquireRequest) (response, error) {
	return store.handleContext(context.Background(), request)
}
