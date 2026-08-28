package windows

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	"github.com/zanescope/v-local-key-provider/internal/workbudget"
)

// Handle 是由 NativeDriver 持有的不透明原生进程 handle。
type Handle uintptr

// ProcessEvidence 把一条 inventory 记录绑定到稳定的可执行文件和账号观察结果。Path 仅供
// 进程内使用，绝不能进入 diagnostics。
type ProcessEvidence struct {
	Process      Process
	Path         string
	Started      uint64
	Architecture string
	Binary       BinaryEvidence
	InstanceID   string
	Binding      string
}

// EvidenceRuntime 注入无法放入 platform package 的 composition-root 信任决策，包括
// 安全的可执行文件 hash 和 primary-signer 验证。
type EvidenceRuntime struct {
	ExecutableSHA256     func(string) string
	AuthenticodeEvidence func(string) (status, signerSHA256 string)
}

type NativeRuntime struct {
	Evidence  EvidenceRuntime
	Sensitive SensitiveRuntime
}

// ConfigCipherAttempt 是一次精确已注册 layout 的有界结果。
type ConfigCipherAttempt struct {
	Status             string
	StructureCount     int
	InvalidStructures  int
	CandidateCount     int
	VerifiedCandidates int
	ScannedBytes       uint64
}

// NativeDriver 是平台 orchestrator 使用的进程/内存边界。OpenForScan 返回的 handle 在
// Close 前仍归调用方所有。
type NativeDriver interface {
	ListProcesses() ([]Process, error)
	CollectEvidence(Process) ProcessEvidence
	BindEvidence([]ProcessEvidence, string, string, workbudget.Budget) []ProcessEvidence
	OpenForScan(Process) Handle
	Revalidate(Process, Handle) ProcessEvidence
	Close(Handle)
	ScanConfig(Handle, ProcessEvidence, ConfigCipherRecipe, *acquisitionmodel.Collector, uint64, workbudget.Budget) ConfigCipherAttempt
	ScanStage(Handle, *acquisitionmodel.Collector, uint64, string, workbudget.Budget) (uint64, bool)
}

func StableProcessInstanceID(result ProcessEvidence) string {
	product := result.Binary.ProductIdentity
	if result.Started == 0 || result.Path == "" ||
		(result.Architecture != "amd64" && result.Architecture != "arm64" && result.Architecture != "x86") ||
		!ValidSHA256(result.Binary.ExecutableSHA256) ||
		(product != "weixin.exe" && product != "wechat.exe") {
		return ""
	}
	identityMaterial := fmt.Sprintf("%d:%d:%s:%d:%s:%s:%s:%s:%s:%s:%s:%s",
		result.Process.PID, result.Process.ParentID, strings.ToLower(result.Process.Name), result.Started,
		strings.ToLower(result.Path), result.Architecture, result.Binary.ExecutableSHA256,
		result.Binary.BinarySigningStatus, result.Binary.BinarySignerSHA256,
		result.Binary.ProductIdentity, result.Binary.Version, result.Binary.Build,
	)
	sum := sha256.Sum256([]byte(identityMaterial))
	return "windows-process:" + hex.EncodeToString(sum[:])
}

func OrderedProcessEvidence(processes []ProcessEvidence) []ProcessEvidence {
	ordered := append([]ProcessEvidence(nil), processes...)
	sort.SliceStable(ordered, func(left, right int) bool {
		return BindingRank(ordered[left].Binding) < BindingRank(ordered[right].Binding)
	})
	return ordered
}

func processIdentity(native NativeDriver, process Process) string {
	evidence := native.CollectEvidence(process)
	if evidence.InstanceID == "" {
		return "windows-process:unverified:" + strings.ToLower(process.Name)
	}
	return evidence.InstanceID
}

// ProcessInventoryID 汇总当前有序的目标进程 inventory，同时不把只有 PID 的观察结果视为
// 可信进程实例。
func ProcessInventoryID(native NativeDriver) string {
	if native == nil {
		return "windows:process-driver-unavailable"
	}
	processes, err := native.ListProcesses()
	if err != nil {
		return "windows:process-list-unavailable"
	}
	processes = OrderedProcesses(processes)
	identities := make([]string, 0, len(processes))
	for _, process := range processes {
		identities = append(identities, processIdentity(native, process))
	}
	sort.Strings(identities)
	sum := sha256.Sum256([]byte(strings.Join(identities, "\x00")))
	return "windows:" + hex.EncodeToString(sum[:16])
}
