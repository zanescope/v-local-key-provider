package windows

import (
	"strings"
	"testing"
	"time"

	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	catalogmodel "github.com/zanescope/v-local-key-provider/internal/catalog"
	providercrypto "github.com/zanescope/v-local-key-provider/internal/crypto"
	"github.com/zanescope/v-local-key-provider/internal/workbudget"
)

func TestFallbackPassphraseBudgetIsIndependentFromScanStageWindow(t *testing.T) {
	overall := workbudget.New(time.Now(), 60_000)
	budget, ok := fallbackPassphraseBudget(overall, "structured_key_object")
	if !ok || budget.Expired() {
		t.Fatal("structured key-object KDF budget was not available")
	}
	deadline, limited := budget.Deadline()
	if !limited || time.Until(deadline) < 19*time.Second {
		t.Fatalf("structured key-object KDF did not receive an independent phase window: %v", time.Until(deadline))
	}
	for _, stage := range []string{"salt_neighborhood", "bounded_writable_heap", "bounded_readonly", "bounded_hex"} {
		if _, enabled := fallbackPassphraseBudget(overall, stage); enabled {
			t.Fatalf("stage %q unexpectedly enabled the structured-object KDF", stage)
		}
	}
}

type fixtureNativeDriver struct {
	listed bool
}

func (driver *fixtureNativeDriver) ListProcesses() ([]Process, error) {
	driver.listed = true
	return nil, nil
}

func (*fixtureNativeDriver) CollectEvidence(process Process) ProcessEvidence {
	return ProcessEvidence{Process: process, Binding: "unknown"}
}

func (*fixtureNativeDriver) BindEvidence(processes []ProcessEvidence, _, _ string, _ workbudget.Budget) []ProcessEvidence {
	return processes
}

func (*fixtureNativeDriver) OpenForScan(Process) Handle { return 0 }

func (*fixtureNativeDriver) Revalidate(process Process, _ Handle) ProcessEvidence {
	return ProcessEvidence{Process: process, Binding: "unknown"}
}

func (*fixtureNativeDriver) Close(Handle) {}

func (*fixtureNativeDriver) ScanConfig(Handle, ProcessEvidence, ConfigCipherRecipe, *acquisitionmodel.Collector, uint64, workbudget.Budget) ConfigCipherAttempt {
	return ConfigCipherAttempt{}
}

func (*fixtureNativeDriver) ScanStage(Handle, *acquisitionmodel.Collector, uint64, string, workbudget.Budget) (uint64, bool) {
	return 0, false
}

func TestDriverUsesNativeProcessSeam(t *testing.T) {
	native := &fixtureNativeDriver{}
	driver := NewDriver(DriverRuntime{
		Acquisition: acquisitionmodel.Runtime{Profiles: []providercrypto.Profile{}},
		Native:      native,
	})
	targets := acquisitionmodel.Targets{
		BySalt: map[string][]string{"aa": {"message.db"}},
		Pages:  []acquisitionmodel.DatabasePage{{Path: "message.db", Salt: "aa"}},
		Count:  1,
		Catalog: catalogmodel.Catalog{Databases: []catalogmodel.Database{{
			DatabaseID: "db", RelativePath: "message.db", Salt: "aa",
			Classification: catalogmodel.ClassificationEncrypted, RequiredForKeyCoverage: true,
		}}},
	}
	_, diag, err := driver.Acquire(targets, acquisitionmodel.MediaEvidence{}, acquisitionmodel.PlatformRequest{
		Database: true, Budget: workbudget.Unlimited(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !native.listed || diag.ProcessDiscoveryMethod != "toolhelp_snapshot" || diag.ProcessAccessStatus != "wechat_not_running" {
		t.Fatalf("driver bypassed or lost native process state: listed=%v diagnostics=%+v", native.listed, diag)
	}
}

type lifecycleNativeDriver struct {
	evidence     ProcessEvidence
	closed       int
	configScans  int
	memoryStages []string
}

func (driver *lifecycleNativeDriver) ListProcesses() ([]Process, error) {
	return []Process{driver.evidence.Process}, nil
}

func (driver *lifecycleNativeDriver) CollectEvidence(Process) ProcessEvidence {
	return driver.evidence
}

func (*lifecycleNativeDriver) BindEvidence(processes []ProcessEvidence, _, _ string, _ workbudget.Budget) []ProcessEvidence {
	return processes
}

func (*lifecycleNativeDriver) OpenForScan(Process) Handle { return 7 }

func (driver *lifecycleNativeDriver) Revalidate(Process, Handle) ProcessEvidence {
	return driver.evidence
}

func (driver *lifecycleNativeDriver) Close(Handle) { driver.closed++ }

func (driver *lifecycleNativeDriver) ScanConfig(Handle, ProcessEvidence, ConfigCipherRecipe, *acquisitionmodel.Collector, uint64, workbudget.Budget) ConfigCipherAttempt {
	driver.configScans++
	return ConfigCipherAttempt{Status: ConfigCipherNoStructure}
}

func (driver *lifecycleNativeDriver) ScanStage(_ Handle, _ *acquisitionmodel.Collector, _ uint64, stage string, _ workbudget.Budget) (uint64, bool) {
	driver.memoryStages = append(driver.memoryStages, stage)
	return 0, false
}

func TestDriverOwnsOpenedHandleAndRunsOrderedFallbackStages(t *testing.T) {
	binary := BinaryEvidence{
		Version: "4.1.11.17", Build: "11.17", ExecutableSHA256: strings.Repeat("a", 64),
		BinaryFingerprintStatus: FingerprintVerified, BinarySigningStatus: SigningVerified,
		BinarySignerSHA256: strings.Repeat("b", 64), ProcessArchitecture: "amd64",
		ProcessArchitectureStatus: ArchitectureVerified, ProductIdentity: "weixin.exe",
	}
	native := &lifecycleNativeDriver{evidence: ProcessEvidence{
		Process: Process{PID: 42, ParentID: 1, Name: "Weixin.exe"}, Binary: binary,
		Path: `C:\Program Files\Tencent\Weixin.exe`, Started: 1, Architecture: "amd64",
		InstanceID: "instance", Binding: "target",
	}}
	recipe := ConfigCipherRecipe{
		Needle: []byte("needle"), EncodedLength: 32, CandidateEncoding: "raw32",
		CandidateKind: "raw_enc_key", MaxMatches: 1,
	}
	driver := NewDriver(DriverRuntime{
		Acquisition: acquisitionmodel.Runtime{Profiles: []providercrypto.Profile{}},
		Registry: []CompatibilityEntry{{
			Version: binary.Version, Build: binary.Build, ExecutableSHA256: binary.ExecutableSHA256,
			BinarySignerSHA256: binary.BinarySignerSHA256, ProcessArchitecture: binary.ProcessArchitecture,
			ProductIdentity: binary.ProductIdentity, RouteSupportState: "supported",
			ConfigCipherSupportState: "verified", MemoryFallbackSupportState: "supported",
			ValidatedProfiles: []string{"profile"}, Recipe: recipe,
		}},
		Policy: EvaluationPolicy{ProfileRegistered: func(profile string) bool { return profile == "profile" }},
		Native: native,
	})
	targets := acquisitionmodel.Targets{
		BySalt: map[string][]string{"aa": {"message.db"}},
		Pages:  []acquisitionmodel.DatabasePage{{Path: "message.db", Salt: "aa", ProfileID: "profile"}},
		Count:  1,
		Catalog: catalogmodel.Catalog{Databases: []catalogmodel.Database{{
			DatabaseID: "db", RelativePath: "message.db", Salt: "aa",
			Classification: catalogmodel.ClassificationEncrypted, RequiredForKeyCoverage: true,
		}}},
	}
	_, diag, err := driver.Acquire(targets, acquisitionmodel.MediaEvidence{}, acquisitionmodel.PlatformRequest{
		Database: true, Budget: workbudget.Unlimited(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if native.closed != 1 || native.configScans != 1 || len(native.memoryStages) != len(FallbackStages()) {
		t.Fatalf("native lifecycle was not bounded: closed=%d config=%d stages=%v", native.closed, native.configScans, native.memoryStages)
	}
	if diag.OpenedProcessCount != 1 || diag.ProcessAccessStatus != "direct_opened" || !diag.StaticScanFallback {
		t.Fatalf("driver lost opened-process diagnostics: %+v", diag)
	}
}

func TestNewDriverDeepCopiesCompatibilityRegistry(t *testing.T) {
	registry := []CompatibilityEntry{{
		ValidatedProfiles: []string{"profile"},
		Recipe:            ConfigCipherRecipe{Needle: []byte("needle"), PointerOffsets: []int64{1}, XORMask: []byte{2}},
	}}
	driver := NewDriver(DriverRuntime{Registry: registry})
	registry[0].ValidatedProfiles[0] = "changed"
	registry[0].Recipe.Needle[0] = 'x'
	registry[0].Recipe.PointerOffsets[0] = 9
	registry[0].Recipe.XORMask[0] = 9
	got := driver.runtime.Registry[0]
	if got.ValidatedProfiles[0] != "profile" || string(got.Recipe.Needle) != "needle" ||
		got.Recipe.PointerOffsets[0] != 1 || got.Recipe.XORMask[0] != 2 {
		t.Fatalf("driver retained mutable registry aliases: %+v", got)
	}
}
