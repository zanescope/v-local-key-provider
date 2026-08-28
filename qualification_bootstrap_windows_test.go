//go:build qualification && windows

package provider

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	windowsmodel "github.com/zanescope/v-local-key-provider/internal/platform/windows"
	"github.com/zanescope/v-local-key-provider/internal/workbudget"
)

type qualificationNativeFixture struct {
	listCalls int
	evidence  windowsmodel.ProcessEvidence
	binding   string
}

func (fixture *qualificationNativeFixture) ListProcesses() ([]windowsmodel.Process, error) {
	fixture.listCalls++
	return []windowsmodel.Process{fixture.evidence.Process}, nil
}

func (fixture *qualificationNativeFixture) CollectEvidence(windowsmodel.Process) windowsmodel.ProcessEvidence {
	return fixture.evidence
}

func (fixture *qualificationNativeFixture) BindEvidence(processes []windowsmodel.ProcessEvidence, _, _ string, _ workbudget.Budget) []windowsmodel.ProcessEvidence {
	binding := fixture.binding
	if binding == "" {
		binding = "target"
	}
	for index := range processes {
		processes[index].Binding = binding
	}
	return processes
}

func (*qualificationNativeFixture) OpenForScan(windowsmodel.Process) windowsmodel.Handle { return 0 }
func (*qualificationNativeFixture) Revalidate(windowsmodel.Process, windowsmodel.Handle) windowsmodel.ProcessEvidence {
	return windowsmodel.ProcessEvidence{}
}
func (*qualificationNativeFixture) Close(windowsmodel.Handle) {}
func (*qualificationNativeFixture) ScanConfig(windowsmodel.Handle, windowsmodel.ProcessEvidence, windowsmodel.ConfigCipherRecipe, *acquisitionmodel.Collector, uint64, workbudget.Budget) windowsmodel.ConfigCipherAttempt {
	return windowsmodel.ConfigCipherAttempt{}
}
func (*qualificationNativeFixture) ScanStage(windowsmodel.Handle, *acquisitionmodel.Collector, uint64, string, workbudget.Budget) (uint64, bool) {
	return 0, false
}

func qualificationConfigFixture() qualificationConfig {
	return qualificationConfig{
		SchemaVersion: 1, QualificationOnly: true,
		Target: qualificationTarget{
			Version: "4.1.11.17", Build: "11.17", ExecutableSHA256: strings.Repeat("a", 64),
			BinarySignerSHA256: strings.Repeat("b", 64), ProcessArchitecture: "amd64", ProductIdentity: "weixin.exe",
		},
		ValidatedProfiles: []string{defaultProfileID}, ConfigCipherStatus: "hypothesis",
		Recipe: qualificationRecipe{
			NeedleUTF8: "Config.Cipher", PointerOffsets: []int64{16}, DataOffset: 8,
			EncodedLength: 32, CandidateEncoding: "raw32", CandidateKind: "raw_enc_key", MaxMatches: 4,
		},
		AllowMemoryFallback: true,
	}
}

func writeQualificationConfigFixture(t *testing.T, config qualificationConfig) string {
	t.Helper()
	payload, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(secureDaemonTestDirectory(t), "qualification.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestQualificationConfigRejectsUnprotectedParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qualification.json")
	payload, err := json.Marshal(qualificationConfigFixture())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readQualificationConfig(path); err == nil {
		t.Fatal("qualification 配置接受了继承权限的父目录")
	}
}

func TestQualificationCandidateAndReleaseBuildsFailClosed(t *testing.T) {
	path := writeQualificationConfigFixture(t, qualificationConfigFixture())
	t.Setenv(qualificationConfigEnv, path)
	t.Setenv(qualificationConsentEnv, qualificationConsent)
	for _, mode := range []string{"candidate", "release"} {
		if err := applyQualificationBootstrap(mode); err == nil {
			t.Fatalf("%s 构建接受了 qualification override", mode)
		}
	}
}

func TestQualificationMissingConsentDoesNotReadProcess(t *testing.T) {
	fixture := &qualificationNativeFixture{}
	t.Setenv(qualificationConsentEnv, "")
	var output bytes.Buffer
	request := qualificationQ0Request{SchemaVersion: 1, Authorization: qualificationConsent, AccountDir: `C:\account`, DBDir: `C:\account\db`, DeadlineMS: 1000}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := qualificationIdentityAfterAuthorization(bytes.NewReader(payload), &output, fixture); err == nil {
		t.Fatal("缺少授权时 Q0 未失败")
	}
	if fixture.listCalls != 0 {
		t.Fatal("缺少授权时读取了微信进程")
	}
}

func TestQualificationRejectsWildcardOrIncompleteFingerprint(t *testing.T) {
	config := qualificationConfigFixture()
	mutations := []func(*qualificationConfig){
		func(value *qualificationConfig) { value.Target.Version = "4.1.*" },
		func(value *qualificationConfig) { value.Target.Build = "" },
		func(value *qualificationConfig) { value.Target.ExecutableSHA256 = "" },
		func(value *qualificationConfig) { value.Target.BinarySignerSHA256 = strings.Repeat("A", 64) },
		func(value *qualificationConfig) { value.Target.ProcessArchitecture = "arm64" },
		func(value *qualificationConfig) { value.Target.ProductIdentity = "*" },
	}
	for index, mutate := range mutations {
		changed := config
		mutate(&changed)
		if _, err := qualificationEntry(changed); err == nil {
			t.Fatalf("不精确 fingerprint 变体 %d 被接受", index)
		}
	}
}

func TestQualificationQ0OutputContainsNoPathPIDOrSecret(t *testing.T) {
	account := t.TempDir()
	db := filepath.Join(account, "db")
	if err := os.Mkdir(db, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture := &qualificationNativeFixture{evidence: windowsmodel.ProcessEvidence{
		Process: windowsmodel.Process{PID: 4242, ParentID: 1, Name: "Weixin.exe"},
		Path:    `C:\private\Weixin.exe`, Started: 10, Architecture: "amd64", InstanceID: "windows-process:" + strings.Repeat("c", 64),
		Binary: windowsmodel.BinaryEvidence{
			Version: "4.1.11.17", Build: "11.17", ExecutableSHA256: strings.Repeat("a", 64),
			BinaryFingerprintStatus: windowsmodel.FingerprintVerified, BinarySigningStatus: windowsmodel.SigningVerified,
			BinarySignerSHA256: strings.Repeat("b", 64), ProcessArchitecture: "amd64",
			ProcessArchitectureStatus: windowsmodel.ArchitectureVerified, ProductIdentity: "weixin.exe",
		},
	}}
	request := qualificationQ0Request{SchemaVersion: 1, Authorization: qualificationConsent, AccountDir: account, DBDir: db, DeadlineMS: 5000}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(qualificationConsentEnv, qualificationConsent)
	var output bytes.Buffer
	result, err := qualificationIdentityAfterAuthorization(bytes.NewReader(payload), &output, fixture)
	if err != nil {
		t.Fatal(err)
	}
	encoded := output.String()
	for _, forbidden := range []string{account, db, fixture.evidence.Path, "4242", "database_keys", "passphrase", "candidate"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("Q0 输出包含禁用内容 %q", forbidden)
		}
	}
	if !result.ProcessInventoryStable || result.PathsIncluded || result.SecretsIncluded || result.AccountIdentityIncluded {
		t.Fatalf("Q0 脱敏边界无效：%+v", result)
	}
}

func TestQualificationQ0RequiresTargetBoundProcess(t *testing.T) {
	fixture := &qualificationNativeFixture{
		binding: "unknown",
		evidence: windowsmodel.ProcessEvidence{
			Process: windowsmodel.Process{Name: "Weixin.exe"},
			Binary: windowsmodel.BinaryEvidence{
				Version: "4.1.11.17", Build: "11.17", ExecutableSHA256: strings.Repeat("a", 64),
				BinaryFingerprintStatus: windowsmodel.FingerprintVerified, BinarySigningStatus: windowsmodel.SigningVerified,
				BinarySignerSHA256: strings.Repeat("b", 64), ProcessArchitecture: "amd64",
				ProcessArchitectureStatus: windowsmodel.ArchitectureVerified, ProductIdentity: "weixin.exe",
			},
		},
	}
	if _, err := qualificationIdentity(fixture, `C:\account`, `C:\account\db`, workbudget.New(time.Now(), 1000)); err == nil {
		t.Fatal("Q0 在没有目标账号绑定进程时仍然成功")
	}
}

func TestQualificationOverrideNeverMarksPromotionReady(t *testing.T) {
	previousRegistry := windowsCompatibilityRegistry
	previousPromotion := releasePromotionSHA256
	previousLoaded := qualificationOverrideLoaded
	t.Cleanup(func() {
		windowsCompatibilityRegistry = previousRegistry
		releasePromotionSHA256 = previousPromotion
		qualificationOverrideLoaded = previousLoaded
	})
	releasePromotionSHA256 = ""
	path := writeQualificationConfigFixture(t, qualificationConfigFixture())
	t.Setenv(qualificationConfigEnv, path)
	t.Setenv(qualificationConsentEnv, qualificationConsent)
	if err := applyQualificationBootstrap("development"); err != nil {
		t.Fatal(err)
	}
	if !qualificationRegistryEnabled() || releasePromotionReady() {
		t.Fatal("qualification override 改变了正式 promotion 状态")
	}
}
