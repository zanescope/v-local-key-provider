package session

import (
	"errors"

	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	providercrypto "github.com/zanescope/v-local-key-provider/internal/crypto"
	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
	"github.com/zanescope/v-local-key-provider/internal/workbudget"
)

// Options is the validated workflow input shared by session orchestration and
// the platform acquisition boundary. Path validation and catalog-key creation
// remain injected because they depend on composition-root policy.
type Options struct {
	AccountDir      string
	DBDir           string
	Database        bool
	Media           bool
	Budget          workbudget.Budget
	HelperMode      bool
	HelperStatus    string
	CatalogKey      []byte
	PlatformSession acquisitionmodel.PlatformSession
	ActionReceipt   string
}

func (options Options) platformRequest() acquisitionmodel.PlatformRequest {
	return acquisitionmodel.PlatformRequest{
		AccountDir: options.AccountDir, DBDir: options.DBDir,
		Database: options.Database, Media: options.Media, Budget: options.Budget,
		HelperMode: options.HelperMode, HelperStatus: options.HelperStatus,
		PlatformSession: options.PlatformSession, ActionReceipt: options.ActionReceipt,
	}
}

// Environment contains daemon-owned context that is fixed before requests are
// served and must not be accepted from the wire request.
type Environment struct {
	HelperMode   bool
	HelperStatus string
}

// Runtime is the narrow composition seam for workflow orchestration. The
// coordinator owns state transitions and publication policy; callbacks own OS
// trust, path validation, target discovery, and platform-specific finalization.
type Runtime struct {
	Protocol string

	// ParseOptions transfers CatalogKey ownership to the coordinator even when
	// it returns an error, so partially constructed sensitive input is cleared.
	ParseOptions            func(protocolmodel.AcquireRequest) (Options, error)
	DiscoverTargets         func(string, workbudget.Budget, []byte) (acquisitionmodel.Targets, error)
	DiscoverMedia           func(string, workbudget.Budget) acquisitionmodel.MediaEvidence
	PreparePlatformSession  func(acquisitionmodel.Targets, Options) acquisitionmodel.PlatformSession
	ProcessInstanceID       func() string
	NewOpaqueID             func() (string, error)
	NewDiagnostics          func([]string) diagnosticmodel.Diagnostics
	ApplyDiagnosticDefaults func(*diagnosticmodel.Diagnostics)
	Driver                  acquisitionmodel.PlatformDriver
	CatalogHMAC             func([]byte, ...string) string
	ProfileSummaries        func() []providercrypto.Summary
	ClearSensitive          func([]byte)
	ConfigStatusRank        func(string) int
}

func (runtime Runtime) normalized() Runtime {
	if runtime.Protocol == "" {
		runtime.Protocol = protocolmodel.Name
	}
	if runtime.ProcessInstanceID == nil {
		runtime.ProcessInstanceID = func() string { return "" }
	}
	if runtime.NewDiagnostics == nil {
		runtime.NewDiagnostics = func(scopes []string) diagnosticmodel.Diagnostics {
			return diagnosticmodel.New("", scopes, "")
		}
	}
	if runtime.ApplyDiagnosticDefaults == nil {
		runtime.ApplyDiagnosticDefaults = func(*diagnosticmodel.Diagnostics) {}
	}
	if runtime.DiscoverMedia == nil {
		runtime.DiscoverMedia = func(string, workbudget.Budget) acquisitionmodel.MediaEvidence {
			return acquisitionmodel.MediaEvidence{}
		}
	}
	if runtime.PreparePlatformSession == nil {
		runtime.PreparePlatformSession = func(acquisitionmodel.Targets, Options) acquisitionmodel.PlatformSession {
			return nil
		}
	}
	if runtime.ProfileSummaries == nil {
		runtime.ProfileSummaries = func() []providercrypto.Summary { return nil }
	}
	if runtime.ClearSensitive == nil {
		runtime.ClearSensitive = clearBytes
	}
	if runtime.ConfigStatusRank == nil {
		runtime.ConfigStatusRank = func(string) int { return 0 }
	}
	return runtime
}

func (runtime Runtime) validatePrepare() error {
	if runtime.ParseOptions == nil {
		return errors.New("session runtime 缺少 options parser")
	}
	if runtime.NewOpaqueID == nil {
		return errors.New("session runtime 缺少 opaque id generator")
	}
	return nil
}

func (runtime Runtime) validateAcquire() error {
	if runtime.Driver == nil {
		return errors.New("session runtime 缺少 platform driver")
	}
	return nil
}

// Coordinator owns the prepare/observe/finalize/cancel workflow around Store.
type Coordinator struct {
	store   *Store
	runtime Runtime
}

func NewCoordinator(store *Store, runtime Runtime) *Coordinator {
	if store == nil {
		store = NewStore(StoreHooks{})
	}
	return &Coordinator{store: store, runtime: runtime.normalized()}
}
