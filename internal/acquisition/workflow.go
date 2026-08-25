package acquisition

import (
	"errors"
	"time"

	catalogmodel "github.com/zanescope/v-local-key-provider/internal/catalog"
	providercrypto "github.com/zanescope/v-local-key-provider/internal/crypto"
	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
	"github.com/zanescope/v-local-key-provider/internal/workbudget"
)

// WorkflowRuntime is the narrow composition seam for one-shot acquisition.
// Generic discovery, finalization, and response assembly remain package-owned;
// OS path identity and platform collection stay injected.
type WorkflowRuntime struct {
	DiscoverTargets         func(string, workbudget.Budget, []byte) (Targets, error)
	DiscoverMedia           func(string, workbudget.Budget) MediaEvidence
	Driver                  PlatformDriver
	ApplyDiagnosticDefaults func(*diagnosticmodel.Diagnostics)
	RandomCatalogKey        func() ([]byte, error)
	CatalogHMAC             func([]byte, ...string) string
	ProfileSummaries        func() []providercrypto.Summary
	ClearSensitive          func([]byte)
}

func (runtime WorkflowRuntime) normalized() WorkflowRuntime {
	if runtime.DiscoverMedia == nil {
		runtime.DiscoverMedia = DiscoverMediaEvidence
	}
	if runtime.ApplyDiagnosticDefaults == nil {
		runtime.ApplyDiagnosticDefaults = func(*diagnosticmodel.Diagnostics) {}
	}
	if runtime.RandomCatalogKey == nil {
		runtime.RandomCatalogKey = catalogmodel.RandomKey
	}
	if runtime.CatalogHMAC == nil {
		runtime.CatalogHMAC = catalogmodel.HMAC
	}
	if runtime.ProfileSummaries == nil {
		runtime.ProfileSummaries = func() []providercrypto.Summary {
			return providercrypto.ProfileSummaries(providercrypto.DefaultProfiles())
		}
	}
	if runtime.ClearSensitive == nil {
		runtime.ClearSensitive = clearBytes
	}
	return runtime
}

// Run performs target/media discovery and then delegates to RunPrepared. It
// owns and clears Options.CatalogKey, including keys generated for direct API
// callers that did not pass through ParseOptions.
func Run(options Options, runtime WorkflowRuntime) (protocolmodel.Response, error) {
	runtime = runtime.normalized()
	defer func() { runtime.ClearSensitive(options.CatalogKey) }()
	started := time.Now()
	targets := Targets{}
	var media MediaEvidence
	var err error
	phaseTimings := map[string]int64{}
	if options.Database {
		if len(options.CatalogKey) == 0 {
			options.CatalogKey, err = runtime.RandomCatalogKey()
			if err != nil {
				return protocolmodel.Response{}, err
			}
		}
		if runtime.DiscoverTargets == nil {
			return protocolmodel.Response{}, errors.New("acquisition workflow 缺少 target discovery")
		}
		phaseStarted := time.Now()
		targets, err = runtime.DiscoverTargets(options.DBDir, options.Budget, options.CatalogKey)
		phaseTimings["target_database_discovery"] = time.Since(phaseStarted).Milliseconds()
		if err != nil {
			return protocolmodel.Response{}, err
		}
	}
	if options.Media {
		phaseStarted := time.Now()
		media = runtime.DiscoverMedia(options.AccountDir, options.Budget)
		phaseTimings["media_discovery"] = time.Since(phaseStarted).Milliseconds()
	}
	result, err := RunPrepared(options, targets, media, started, runtime)
	if result.Diagnostics.PhaseTimingsMS == nil {
		result.Diagnostics.PhaseTimingsMS = map[string]int64{}
	}
	for phase, elapsed := range phaseTimings {
		result.Diagnostics.PhaseTimingsMS[phase] = elapsed
	}
	return result, err
}

// RunPrepared executes the platform collector and assembles one final protocol
// response from already discovered evidence. It does not take ownership of the
// catalog key; session orchestration also calls this boundary incrementally.
func RunPrepared(
	options Options,
	targets Targets,
	media MediaEvidence,
	started time.Time,
	runtime WorkflowRuntime,
) (protocolmodel.Response, error) {
	runtime = runtime.normalized()
	if runtime.Driver == nil {
		return protocolmodel.Response{}, errors.New("acquisition workflow 缺少 platform driver")
	}
	phaseStarted := time.Now()
	result, diag, err := runtime.Driver.Acquire(targets, media, options.PlatformRequest())
	if err != nil {
		return protocolmodel.Response{}, err
	}
	if diag.PhaseTimingsMS == nil {
		diag.PhaseTimingsMS = map[string]int64{}
	}
	diag.PhaseTimingsMS["primary_acquire"] = time.Since(phaseStarted).Milliseconds()
	diag.PhaseTimingsMS["total"] = time.Since(started).Milliseconds()
	diag.ElapsedMS = time.Since(started).Milliseconds()
	diag.BudgetExhausted = options.Budget.Expired()
	runtime.ApplyDiagnosticDefaults(&diag)
	diagnosticmodel.Finalize(&diag, diagnosticmodel.FinalizeInput{
		Catalog: targets.Catalog, RequiredDatabaseCount: targets.Count,
		DatabaseKeys: result.DatabaseKeys, DatabaseCredential: result.DatabaseCredential,
		ImageKeysPresent:  result.ImageKeys != nil,
		DatabaseRequested: options.Database, MediaRequested: options.Media,
		BudgetExpired: options.Budget.Expired(),
	})
	result.CatalogID = targets.Catalog.CatalogID
	result.CatalogEntries = append([]catalogmodel.Database(nil), targets.Catalog.Databases...)
	if result.DatabaseCredential != nil {
		result.DatabaseCredential.AccountBindingID = runtime.CatalogHMAC(options.CatalogKey, "account", options.AccountDir)
	}
	result.Profiles = runtime.ProfileSummaries()
	result.Diagnostics = diag
	return result, nil
}
