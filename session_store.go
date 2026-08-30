package provider

import (
	"context"
	"time"

	commandmodel "github.com/zanescope/v-local-key-provider/internal/command"
	sessionmodel "github.com/zanescope/v-local-key-provider/internal/session"
	shadowmodel "github.com/zanescope/v-local-key-provider/internal/shadow"
	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
	shadowfixture "github.com/zanescope/v-local-key-provider/internal/shadowfixture"
)

const acquisitionSessionMaxLifetime = sessionmodel.MaxLifetime

type acquisitionSession = sessionmodel.Record

type acquisitionSessionStore struct {
	core         *sessionmodel.Store
	coordinator  *sessionmodel.Coordinator
	helperMode   bool
	helperStatus string
	shadow       commandmodel.ShadowRunner
}

type shadowRunnerMux struct {
	synthetic       commandmodel.ShadowRunner
	production      commandmodel.ShadowRunner
	productionBuild string
}

func (value shadowRunnerMux) Qualify(ctx context.Context, request contract.Request) (shadowmodel.Output, error) {
	if value.production != nil && request.BuildSetDigest == value.productionBuild {
		return value.production.Qualify(ctx, request)
	}
	if value.synthetic == nil {
		return shadowmodel.Output{Result: contract.Result{
			Version: contract.Version, RequestID: request.RequestID, Status: "failed", ErrorCode: contract.ErrorBuildSetMismatch,
		}}, nil
	}
	return value.synthetic.Qualify(ctx, request)
}

func (value shadowRunnerMux) Execute(ctx context.Context, request contract.Request) (shadowmodel.Output, error) {
	if request.Operation == "execute" && value.production != nil && request.BuildSetDigest == value.productionBuild {
		return value.production.Execute(ctx, request)
	}
	if value.synthetic == nil {
		return shadowmodel.Output{Result: contract.Result{
			Version: contract.Version, RequestID: request.RequestID, Status: "failed", ErrorCode: contract.ErrorBuildSetMismatch,
		}}, nil
	}
	return value.synthetic.Execute(ctx, request)
}

func newShadowRunner() commandmodel.ShadowRunner {
	synthetic := shadowfixture.NewRunner()
	production, digest := productionQualificationRunner()
	if synthetic == nil && production == nil {
		return nil
	}
	return shadowRunnerMux{synthetic: synthetic, production: production, productionBuild: digest}
}

func newAcquisitionSessionStoreWithRuntime(runtime sessionmodel.Runtime) *acquisitionSessionStore {
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
		core: core, coordinator: sessionmodel.NewCoordinator(core, runtime),
		shadow: newShadowRunner(),
	}
}

func newAcquisitionSessionStore() *acquisitionSessionStore {
	return newAcquisitionSessionStoreWithRuntime(acquisitionSessionRuntime())
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
	if request.Workflow.Operation == "shadow" {
		return commandmodel.ExecuteShadow(ctx, request, store.shadow)
	}
	return store.coordinator.Handle(ctx, request, sessionmodel.Environment{
		HelperMode: store.helperMode, HelperStatus: store.helperStatus,
	})
}

func (store *acquisitionSessionStore) handle(request acquireRequest) (response, error) {
	return store.handleContext(context.Background(), request)
}
