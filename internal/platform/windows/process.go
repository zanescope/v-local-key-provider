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

// Handle is an opaque native process handle owned by a NativeDriver.
type Handle uintptr

// ProcessEvidence binds one inventory entry to stable executable and account
// observations. Path is process-local and must never enter diagnostics.
type ProcessEvidence struct {
	Process      Process
	Path         string
	Started      uint64
	Architecture string
	Binary       BinaryEvidence
	InstanceID   string
	Binding      string
}

// EvidenceRuntime injects composition-root trust decisions that cannot live in
// the platform package, including safe executable hashing and primary-signer
// verification.
type EvidenceRuntime struct {
	ExecutableSHA256     func(string) string
	AuthenticodeEvidence func(string) (status, signerSHA256 string)
}

type NativeRuntime struct {
	Evidence  EvidenceRuntime
	Sensitive SensitiveRuntime
}

// ConfigCipherAttempt is the bounded result of one exact registered layout.
type ConfigCipherAttempt struct {
	Status             string
	StructureCount     int
	InvalidStructures  int
	CandidateCount     int
	VerifiedCandidates int
	ScannedBytes       uint64
}

// NativeDriver is the process/memory seam used by the platform orchestrator.
// Handles returned by OpenForScan remain owned by the caller until Close.
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

// ProcessInventoryID summarizes the current ordered target-process inventory
// without treating PID-only observations as trusted process instances.
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
