package provider

import (
	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	catalogmodel "github.com/zanescope/v-local-key-provider/internal/catalog"
	credentialmodel "github.com/zanescope/v-local-key-provider/internal/credential"
	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
)

type databaseTargets = acquisitionmodel.Targets
type databasePage = acquisitionmodel.DatabasePage
type mediaEvidence = acquisitionmodel.MediaEvidence
type candidateCollector = acquisitionmodel.Collector
type acquisitionPlatformSession = acquisitionmodel.PlatformSession

const (
	scanTailLength         = acquisitionmodel.ScanTailLength
	v4KDFIterations        = acquisitionmodel.V4KDFIterations
	maxScanRegionBytes     = acquisitionmodel.MaxScanRegionBytes
	saltNeighborhoodWindow = acquisitionmodel.SaltNeighborhoodWindow
)

func candidateRuntime() acquisitionmodel.Runtime {
	return acquisitionmodel.Runtime{
		Profiles:       profileRegistry,
		MarkSensitive:  markSensitiveBytes,
		ClearSensitive: zeroBytes,
		CloneSensitive: cloneSensitiveBytes,
		NewOpaqueID:    credentialmodel.RandomOpaqueID,
	}
}

func newCandidateCollector(targets databaseTargets, media mediaEvidence, budgets ...budget) *candidateCollector {
	if len(budgets) == 0 {
		return acquisitionmodel.NewCollector(targets, media, candidateRuntime())
	}
	return acquisitionmodel.NewCollector(targets, media, candidateRuntime(), budgets[0].value)
}

func databaseDiscoveryPolicy(remaining budget) catalogmodel.PlatformPolicy {
	return catalogmodel.PlatformPolicy{
		FileIdentity:       platformFileIdentity,
		IsLinkOrReparse:    pathIsLinkOrReparse,
		CanonicalPathKey:   catalogPathKey,
		AcquisitionExpired: remaining.expired,
	}
}

func discoverDatabaseTargetsWithKey(dbDir string, remaining budget, catalogKey []byte) (databaseTargets, error) {
	return acquisitionmodel.DiscoverDatabaseTargets(dbDir, remaining.value, catalogKey, databaseDiscoveryPolicy(remaining))
}

func discoverDatabaseTargets(dbDir string, remaining budget) (databaseTargets, error) {
	key, err := randomCatalogKey()
	if err != nil {
		return databaseTargets{}, err
	}
	defer zeroBytes(key)
	return discoverDatabaseTargetsWithKey(dbDir, remaining, key)
}

func discoverMediaEvidence(accountDir string, remaining budget) mediaEvidence {
	return acquisitionmodel.DiscoverMediaEvidence(accountDir, remaining.value)
}

type providerPlatformDriver struct{}

func (providerPlatformDriver) Acquire(targets acquisitionmodel.Targets, media acquisitionmodel.MediaEvidence, request acquisitionmodel.PlatformRequest) (protocolmodel.Response, diagnosticmodel.Diagnostics, error) {
	return platformAcquire(targets, media, acquireOptions{
		accountDir: request.AccountDir, dbDir: request.DBDir,
		database: request.Database, media: request.Media,
		budget: budget{value: request.Budget}, helperMode: request.HelperMode,
		helperStatus: request.HelperStatus, platformSession: request.PlatformSession,
		actionReceipt: request.ActionReceipt,
	})
}

var platformDriver acquisitionmodel.PlatformDriver = providerPlatformDriver{}

func platformRequestFromOptions(options acquireOptions) acquisitionmodel.PlatformRequest {
	return acquisitionmodel.PlatformRequest{
		AccountDir: options.accountDir, DBDir: options.dbDir,
		Database: options.database, Media: options.media, Budget: options.budget.value,
		HelperMode: options.helperMode, HelperStatus: options.helperStatus,
		PlatformSession: options.platformSession, ActionReceipt: options.actionReceipt,
	}
}
