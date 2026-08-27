package session

import (
	"errors"

	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	providercrypto "github.com/zanescope/v-local-key-provider/internal/crypto"
	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
	"github.com/zanescope/v-local-key-provider/internal/workbudget"
)

// Options 是由 acquisition 持有、供 one-shot 与 session 编排共享的 DTO。该 alias 防止
// 任一工作流定义平行表示。
type Options = acquisitionmodel.Options

// Environment 包含由 daemon 持有且在服务请求前固定的 context，不得从 wire request 接受。
type Environment struct {
	HelperMode   bool
	HelperStatus string
}

// Runtime 是工作流编排的窄 composition 边界。coordinator 持有状态转换和发布策略；callback
// 持有 OS 信任、路径验证、target 发现和平台 diagnostic 默认值。
type Runtime struct {
	Protocol string

	// 即使 ParseOptions 返回错误，也会把 CatalogKey 所有权转移给 coordinator，从而清理
	// 只完成部分构造的敏感输入。
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

// Coordinator 持有围绕 Store 的 prepare/observe/finalize/cancel 工作流。
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
