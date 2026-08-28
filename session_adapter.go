package provider

import (
	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
	sessionmodel "github.com/zanescope/v-local-key-provider/internal/session"
	"github.com/zanescope/v-local-key-provider/internal/workbudget"
)

// sessionPlatformDriver 每次调用都解析当前 composition-root driver，使测试和平台构建
// 可以替换 driver，而无需重建已经创建的 session coordinator。
type sessionPlatformDriver struct{}

func (sessionPlatformDriver) Acquire(
	targets acquisitionmodel.Targets,
	media acquisitionmodel.MediaEvidence,
	request acquisitionmodel.PlatformRequest,
) (protocolmodel.Response, diagnosticmodel.Diagnostics, error) {
	return platformDriver.Acquire(targets, media, request)
}

func acquisitionSessionRuntime() sessionmodel.Runtime {
	return sessionmodel.Runtime{
		Protocol: protocolName,
		ParseOptions: func(request protocolmodel.AcquireRequest) (sessionmodel.Options, error) {
			return optionsFromRequest(request)
		},
		DiscoverTargets: func(dbDir string, remaining workbudget.Budget, catalogKey []byte) (acquisitionmodel.Targets, error) {
			return discoverDatabaseTargetsWithKey(dbDir, budget{value: remaining}, catalogKey)
		},
		DiscoverMedia: func(accountDir string, remaining workbudget.Budget) acquisitionmodel.MediaEvidence {
			return discoverMediaEvidence(accountDir, budget{value: remaining})
		},
		PreparePlatformSession: func(targets acquisitionmodel.Targets, options sessionmodel.Options) acquisitionmodel.PlatformSession {
			return preparePlatformAcquisitionSession(targets, options)
		},
		ProcessInstanceID: platformProcessInstanceID,
		NewOpaqueID:       randomOpaqueID,
		NewDiagnostics: func(scopes []string) diagnosticmodel.Diagnostics {
			return newDiagnostics(platformNameForDiagnostics(), scopes)
		},
		ApplyDiagnosticDefaults: applyPlatformDiagnosticDefaults,
		Driver:                  sessionPlatformDriver{},
		CatalogHMAC:             catalogHMAC,
		ProfileSummaries:        profileSummaries,
		ClearSensitive:          zeroBytes,
		ConfigStatusRank:        windowsConfigStatusRank,
	}
}
