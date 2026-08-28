package darwin

import (
	"strconv"
	"strings"

	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	platformmodel "github.com/zanescope/v-local-key-provider/internal/platform"
	"github.com/zanescope/v-local-key-provider/internal/workbudget"
)

const (
	ReadChunkSize     = 1024 * 1024
	PerProcessScanMax = uint64(2 * 1024 * 1024 * 1024)
	TotalScanMax      = uint64(6 * 1024 * 1024 * 1024)
)

type NativeRuntime struct {
	RunOutput        OutputRunner
	UID              func() int
	MarkSensitive    func([]byte)
	ClearSensitive   func([]byte)
	CollectEvidence  func(Process) BinaryEvidence
	PrelaunchProcess func() Process
}

type ScanResult struct {
	Scanned uint64
	Limited bool
	Opened  bool
}

// NativeDriver 持有进程发现、证据收集、task-port 生命周期和 Mach 内存读取。平台 pipeline
// 只使用此边界，因此可在非 Darwin 测试 runner 上替换为 fake。
type NativeDriver interface {
	ListProcesses() ([]Process, string, error)
	CollectEvidence(Process) BinaryEvidence
	PrelaunchProcess() Process
	ScanProcess(Process, *acquisitionmodel.Collector, uint64, workbudget.Budget) ScanResult
}

type CaptureHookFunc func(
	Process,
	*acquisitionmodel.Collector,
	workbudget.Budget,
	bool,
	string,
) platformmodel.HookSnapshot

func PrelaunchHookEligible(evidence BinaryEvidence) bool {
	return evidence.Version != "" && evidence.Build != "" && evidence.MacOSMajorMinor != "" &&
		evidence.BinaryFingerprintStatus == FingerprintVerified && ValidSHA256(evidence.ExecutableSHA256) &&
		evidence.BinarySigningStatus == SigningVerified && evidence.SigningTeamID != "" &&
		ValidSHA256(evidence.DesignatedRequirementSHA256)
}

func VersionSupport(version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		return "unknown"
	}
	parts := strings.Split(version, ".")
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return "unknown"
	}
	minor := 0
	if len(parts) > 1 {
		minor, _ = strconv.Atoi(parts[1])
	}
	if major > 4 || major == 4 && minor >= 1 {
		return "commoncrypto_dynamic"
	}
	if major == 4 {
		return "static_then_commoncrypto"
	}
	return "static_memory"
}
