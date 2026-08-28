package session

import (
	"errors"
	"time"

	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
)

var diagnosticMergePolicies = diagnosticmodel.NewSessionMergePolicies()

// MergeDiagnosticEvidence 合并重复的平台 pass，同时不混合必须共同描述同一份一致 Windows
// 进程 inventory 的字段。
func MergeDiagnosticEvidence(existing *protocolmodel.Response, next *diagnosticmodel.Diagnostics, configStatusRank func(string) int) {
	if existing == nil || next == nil {
		return
	}
	if configStatusRank == nil {
		configStatusRank = func(string) int { return 0 }
	}
	previous := existing.Diagnostics
	if next.Platform == "" {
		next.Platform = previous.Platform
	}
	windowsCurrentSnapshot := next.Platform == "windows" && next.ProcessDiscoveryMethod != ""
	if next.Platform == "windows" && !windowsCurrentSnapshot {
		// 没有执行平台 pass（例如请求的每个 ID 都已覆盖）。保留一份完整 snapshot，而非
		// 分别最大化那些必须描述同一 inventory 的字段。
		diagnosticmodel.CopyWindowsProcessSnapshot(next, previous)
	}
	if next.Platform == "windows" &&
		configStatusRank(previous.ConfigCipherRouteStatus) > configStatusRank(next.ConfigCipherRouteStatus) {
		// Config.Cipher 计数器和已验证密钥会累积。保留生成最强留存结果的精确二进制身份。
		diagnosticmodel.CopyWindowsRouteIdentity(next, previous)
	}
	diagnosticmodel.MergeSessionFields(previous, next, diagnosticMergePolicies)
}

func (coordinator *Coordinator) runIncremental(
	options Options,
	fullTargets acquisitionmodel.Targets,
	media acquisitionmodel.MediaEvidence,
	existing *protocolmodel.Response,
	started time.Time,
) (protocolmodel.Response, error) {
	previousKeys := map[string]string(nil)
	if existing != nil {
		previousKeys = existing.DatabaseKeys
	}
	scanTargets := acquisitionmodel.MissingTargets(fullTargets, previousKeys)
	scanOptions := options
	scanOptions.Database = options.Database && scanTargets.Count > 0
	if existing != nil && existing.ImageKeys != nil {
		scanOptions.Media = false
	}

	var next protocolmodel.Response
	var diag diagnosticmodel.Diagnostics
	var err error
	if scanOptions.Database || scanOptions.Media {
		if err := coordinator.runtime.validateAcquire(); err != nil {
			return protocolmodel.Response{}, err
		}
		phaseStarted := time.Now()
		next, diag, err = coordinator.runtime.Driver.Acquire(scanTargets, media, scanOptions.PlatformRequest())
		if diag.PhaseTimingsMS == nil {
			diag.PhaseTimingsMS = map[string]int64{}
		}
		diag.PhaseTimingsMS["primary_acquire"] = time.Since(phaseStarted).Milliseconds()
		if err != nil {
			return protocolmodel.Response{}, err
		}
	} else {
		diag = coordinator.runtime.NewDiagnostics(diagnosticmodel.RequestedScopes(options.Database, options.Media))
	}

	merged := MergeResults(existing, next)
	MergeDiagnosticEvidence(existing, &diag, coordinator.runtime.ConfigStatusRank)
	diag.ElapsedMS = time.Since(started).Milliseconds()
	if diag.PhaseTimingsMS == nil {
		diag.PhaseTimingsMS = map[string]int64{}
	}
	diag.PhaseTimingsMS["total"] = diag.ElapsedMS
	diag.BudgetExhausted = options.Budget.Expired()
	coordinator.runtime.ApplyDiagnosticDefaults(&diag)
	diagnosticmodel.Finalize(&diag, diagnosticmodel.FinalizeInput{
		Catalog: fullTargets.Catalog, RequiredDatabaseCount: fullTargets.Count,
		DatabaseKeys: merged.DatabaseKeys, DatabaseCredential: merged.DatabaseCredential,
		ImageKeysPresent:  merged.ImageKeys != nil,
		DatabaseRequested: options.Database, MediaRequested: options.Media,
		BudgetExpired: options.Budget.Expired(),
	})
	merged.CatalogID = fullTargets.Catalog.CatalogID
	merged.CatalogEntries = append(merged.CatalogEntries[:0:0], fullTargets.Catalog.Databases...)
	if merged.DatabaseCredential != nil {
		if coordinator.runtime.CatalogHMAC == nil {
			return protocolmodel.Response{}, errors.New("session runtime 缺少 account binding HMAC")
		}
		merged.DatabaseCredential.AccountBindingID = coordinator.runtime.CatalogHMAC(
			options.CatalogKey, "account", options.AccountDir,
		)
	}
	merged.Profiles = coordinator.runtime.ProfileSummaries()
	merged.Diagnostics = diag
	return merged, nil
}
