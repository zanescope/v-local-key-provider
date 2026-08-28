// Package acquisition 持有 target 发现、候选收集和密码学验证。平台代码通过本 package
// 的窄接口提供 OS 策略和进程观察结果。
package acquisition

import (
	catalogmodel "github.com/zanescope/v-local-key-provider/internal/catalog"
	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
	platformmodel "github.com/zanescope/v-local-key-provider/internal/platform"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
	"github.com/zanescope/v-local-key-provider/internal/workbudget"
)

type DatabasePage = catalogmodel.Page

// Targets 是供平台 collector 以只读输入方式使用的发现结果。
type Targets struct {
	BySalt  map[string][]string
	Pages   []DatabasePage
	Count   int
	Catalog catalogmodel.Catalog
}

// MediaEvidence 包含用于验证媒体密钥候选的有界样本。
type MediaEvidence struct {
	V2Blocks      [][16]byte
	XORCandidates map[byte]int
}

// PlatformRequest 只包含 OS driver 所需的采集输入。catalog key 处理和最终响应组装仍位于
// 采集工作流边界。
type PlatformRequest struct {
	AccountDir      string
	DBDir           string
	Database        bool
	Media           bool
	Budget          workbudget.Budget
	HelperMode      bool
	HelperStatus    string
	PlatformSession PlatformSession
	ActionReceipt   string
}

// PlatformSession 是长期平台观察结果的有界同步来源。实现必须保证 Close 幂等。
type PlatformSession interface {
	Collect(*Collector) platformmodel.HookSnapshot
	Status() platformmodel.HookSnapshot
	Close()
}

// PlatformDriver 是命令到 OS 的采集边界。它有意只使用内部领域 model，因此没有内部
// package 需要导入 main。
type PlatformDriver interface {
	Acquire(Targets, MediaEvidence, PlatformRequest) (protocolmodel.Response, diagnosticmodel.Diagnostics, error)
}

type PlatformDriverFunc func(Targets, MediaEvidence, PlatformRequest) (protocolmodel.Response, diagnosticmodel.Diagnostics, error)

func (driver PlatformDriverFunc) Acquire(targets Targets, media MediaEvidence, request PlatformRequest) (protocolmodel.Response, diagnosticmodel.Diagnostics, error) {
	return driver(targets, media, request)
}

// 私有 alias 用于保持实现及 package 内测试简洁。
type databaseTargets = Targets
type databasePage = DatabasePage
type mediaEvidence = MediaEvidence
type imageKeys = protocolmodel.ImageKeys
type diagnostics = diagnosticmodel.Diagnostics
type databaseCatalog = catalogmodel.Catalog
type catalogDatabase = catalogmodel.Database
type budget = workbudget.Budget

func unlimitedBudget() budget { return workbudget.Unlimited() }
