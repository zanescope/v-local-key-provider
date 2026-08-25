package darwin

import (
	"crypto/aes"
	"strings"
	"testing"

	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	catalogmodel "github.com/zanescope/v-local-key-provider/internal/catalog"
	providercrypto "github.com/zanescope/v-local-key-provider/internal/crypto"
	"github.com/zanescope/v-local-key-provider/internal/workbudget"
)

type fixtureNativeDriver struct {
	processes []Process
	evidence  BinaryEvidence
	listed    int
	scans     int
	scan      ScanResult
}

func (driver *fixtureNativeDriver) ListProcesses() ([]Process, string, error) {
	driver.listed++
	return append([]Process(nil), driver.processes...), "fixture", nil
}

func (driver *fixtureNativeDriver) CollectEvidence(Process) BinaryEvidence {
	return driver.evidence
}

func (*fixtureNativeDriver) PrelaunchProcess() Process { return Process{Name: "WeChat"} }

func (driver *fixtureNativeDriver) ScanProcess(
	Process,
	*acquisitionmodel.Collector,
	uint64,
	workbudget.Budget,
) ScanResult {
	driver.scans++
	return driver.scan
}

func fixtureTargets() acquisitionmodel.Targets {
	return acquisitionmodel.Targets{
		BySalt: map[string][]string{"aa": {"message.db"}},
		Pages:  []acquisitionmodel.DatabasePage{{Path: "message.db", Salt: "aa"}},
		Count:  1,
		Catalog: catalogmodel.Catalog{Databases: []catalogmodel.Database{{
			DatabaseID: "db", RelativePath: "message.db", Salt: "aa",
			Classification: catalogmodel.ClassificationEncrypted, RequiredForKeyCoverage: true,
		}}},
	}
}

func fixtureEvidence() BinaryEvidence {
	return BinaryEvidence{
		Version: "4.1.11.17", Build: "11.17", ExecutableSHA256: strings.Repeat("a", 64),
		BinaryFingerprintStatus: FingerprintVerified, BinarySigningStatus: SigningVerified,
		SigningTeamID: "TEAMID", DesignatedRequirementSHA256: strings.Repeat("b", 64),
		ProcessArchitecture: "arm64", ProcessArchitectureStatus: ArchitectureVerified,
		ProcessTranslationStatus: "native", MacOSVersion: "15.6.1", MacOSMajorMinor: "15.6",
	}
}

func fixtureDriver(native NativeDriver) *Driver {
	return NewDriver(DriverRuntime{
		Acquisition: acquisitionmodel.Runtime{Profiles: []providercrypto.Profile{}},
		Native:      native,
		SecurityPosture: func() string {
			return "sip_enabled_verified"
		},
	})
}

func TestDriverUsesNativeDiscoverySeam(t *testing.T) {
	native := &fixtureNativeDriver{}
	_, diag, err := fixtureDriver(native).Acquire(
		fixtureTargets(), acquisitionmodel.MediaEvidence{},
		acquisitionmodel.PlatformRequest{Database: true, Budget: workbudget.Unlimited()},
	)
	if err != nil {
		t.Fatal(err)
	}
	if native.listed != 2 || diag.ProcessDiscoveryMethod != "fixture" ||
		diag.ProcessAccessStatus != "wechat_not_running" {
		t.Fatalf("driver bypassed or lost native discovery: listed=%d diagnostics=%+v", native.listed, diag)
	}
}

func TestDriverOwnsStaticScanLifecycle(t *testing.T) {
	native := &fixtureNativeDriver{
		processes: []Process{{PID: 42, Name: "WeChat"}},
		evidence:  fixtureEvidence(),
		scan:      ScanResult{Opened: true, Scanned: 128},
	}
	_, diag, err := fixtureDriver(native).Acquire(
		fixtureTargets(), acquisitionmodel.MediaEvidence{},
		acquisitionmodel.PlatformRequest{Database: true, Budget: workbudget.Unlimited()},
	)
	if err != nil {
		t.Fatal(err)
	}
	if native.scans != 1 || diag.OpenedProcessCount != 1 || diag.ScannedBytes != 128 ||
		diag.ProcessAccessStatus != "direct_opened" || !diag.StaticScanFallback {
		t.Fatalf("static scan lifecycle was not preserved: scans=%d diagnostics=%+v", native.scans, diag)
	}
}

func TestPipelineDoesNotStopAfterDatabaseWhenMediaIsStillMissing(t *testing.T) {
	const mediaKey = "0123456789abcdef"
	block, err := aes.NewCipher([]byte(mediaKey))
	if err != nil {
		t.Fatal(err)
	}
	plain := [16]byte{0xff, 0xd8, 0xff}
	var encrypted [16]byte
	block.Encrypt(encrypted[:], plain[:])
	evidence := acquisitionmodel.MediaEvidence{
		V2Blocks: [][16]byte{encrypted}, XORCandidates: map[byte]int{0x2a: 1},
	}
	collector := acquisitionmodel.NewCollector(
		acquisitionmodel.Targets{}, evidence, acquisitionmodel.DefaultRuntime(), workbudget.Unlimited(),
	)
	pipeline := acquisitionPipeline{
		collector: collector, scanMedia: evidence, needDatabaseScan: false, needMediaScan: true,
	}
	if pipeline.satisfied() {
		t.Fatal("pipeline stopped with requested media evidence still unresolved")
	}
	collector.ScanMediaPatterns([]byte(mediaKey))
	if !pipeline.satisfied() {
		t.Fatal("pipeline did not stop after every requested scope was resolved")
	}
}

func TestNewDriverDeepCopiesCompatibilityRegistry(t *testing.T) {
	registry := []CompatibilityEntry{{ValidatedCipherProfiles: []string{"profile"}}}
	driver := NewDriver(DriverRuntime{Registry: registry})
	registry[0].ValidatedCipherProfiles[0] = "changed"
	if driver.runtime.Registry[0].ValidatedCipherProfiles[0] != "profile" {
		t.Fatalf("driver retained mutable registry aliases: %+v", driver.runtime.Registry)
	}
}
