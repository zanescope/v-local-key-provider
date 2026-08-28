//go:build qualification && windows

package provider

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unsafe"

	windowsmodel "github.com/zanescope/v-local-key-provider/internal/platform/windows"
	"github.com/zanescope/v-local-key-provider/internal/workbudget"
	"golang.org/x/sys/windows"
)

const (
	qualificationConsent          = "I_HAVE_EXPLICIT_AUTHORIZATION_FOR_WINDOWS_QUALIFICATION"
	qualificationConsentEnv       = "V_LOCAL_KEY_PROVIDER_QUALIFICATION_CONSENT"
	qualificationConfigEnv        = "V_LOCAL_KEY_PROVIDER_QUALIFICATION_CONFIG"
	qualificationArtifactMaxBytes = 64 * 1024
)

var qualificationOverrideLoaded bool

type qualificationTarget struct {
	Version             string `json:"version"`
	Build               string `json:"build"`
	ExecutableSHA256    string `json:"executable_sha256"`
	BinarySignerSHA256  string `json:"binary_signer_sha256"`
	ProcessArchitecture string `json:"process_architecture"`
	ProductIdentity     string `json:"product_identity"`
}

type qualificationRecipe struct {
	NeedleUTF8        string  `json:"needle_utf8"`
	PointerOffsets    []int64 `json:"pointer_offsets"`
	DataOffset        int64   `json:"data_offset"`
	EncodedLength     int     `json:"encoded_length"`
	CandidateEncoding string  `json:"candidate_encoding"`
	CandidateKind     string  `json:"candidate_kind"`
	XORMaskHex        string  `json:"xor_mask_hex"`
	MaxMatches        int     `json:"max_matches"`
}

type qualificationConfig struct {
	SchemaVersion       int                 `json:"schema_version"`
	QualificationOnly   bool                `json:"qualification_only"`
	Target              qualificationTarget `json:"target"`
	ValidatedProfiles   []string            `json:"validated_profiles"`
	ConfigCipherStatus  string              `json:"config_cipher_status"`
	Recipe              qualificationRecipe `json:"recipe"`
	AllowMemoryFallback bool                `json:"allow_memory_fallback"`
}

type qualificationQ0Request struct {
	SchemaVersion int    `json:"schema_version"`
	Authorization string `json:"authorization"`
	AccountDir    string `json:"account_dir"`
	DBDir         string `json:"db_dir"`
	DeadlineMS    int64  `json:"deadline_ms"`
}

type qualificationQ0Evidence struct {
	SchemaVersion              int    `json:"schema_version"`
	QualificationOnly          bool   `json:"qualification_only"`
	FormalReleaseEvidence      bool   `json:"formal_release_evidence"`
	Version                    string `json:"version"`
	Build                      string `json:"build"`
	ExecutableSHA256           string `json:"executable_sha256"`
	BinaryFingerprintStatus    string `json:"binary_fingerprint_status"`
	BinarySigningStatus        string `json:"binary_signing_status"`
	BinarySignerSHA256         string `json:"binary_signer_sha256"`
	ProductIdentity            string `json:"product_identity"`
	ProcessArchitecture        string `json:"process_architecture"`
	ProcessArchitectureStatus  string `json:"process_architecture_status"`
	TargetBindingStatus        string `json:"target_binding_status"`
	ProcessCount               int    `json:"process_count"`
	TargetBoundProcessCount    int    `json:"target_bound_process_count"`
	UnknownAccountProcessCount int    `json:"unknown_account_process_count"`
	ProcessInventoryStable     bool   `json:"process_inventory_stable"`
	SecretsIncluded            bool   `json:"secrets_included"`
	PathsIncluded              bool   `json:"paths_included"`
	AccountIdentityIncluded    bool   `json:"account_identity_included"`
}

var exactVersionPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+)+$`)

func readQualificationJSON(reader io.Reader, destination any) error {
	payload, err := io.ReadAll(io.LimitReader(reader, qualificationArtifactMaxBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > qualificationArtifactMaxBytes {
		zeroBytes(payload)
		return errors.New("qualification JSON 大小无效")
	}
	defer zeroBytes(payload)
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("qualification JSON 无效")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("qualification JSON 含有尾随数据")
	}
	return nil
}

func readQualificationConfig(path string) (qualificationConfig, error) {
	absolute, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil || strings.TrimSpace(path) == "" {
		return qualificationConfig{}, errors.New("qualification 配置路径无效")
	}
	info, err := os.Lstat(absolute)
	unsafeFile := false
	if err == nil {
		unsafeFile, err = pathIsLinkOrReparse(absolute, info.Mode())
	}
	if err != nil || unsafeFile || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > qualificationArtifactMaxBytes {
		return qualificationConfig{}, errors.New("qualification 配置必须是有界普通文件")
	}
	parent := filepath.Dir(absolute)
	parentInfo, err := os.Lstat(parent)
	unsafeParent := false
	if err == nil {
		unsafeParent, err = pathIsLinkOrReparse(parent, parentInfo.Mode())
	}
	if err != nil || unsafeParent || !parentInfo.IsDir() {
		return qualificationConfig{}, errors.New("qualification 配置父目录不可信")
	}
	if err := validateQualificationDirectorySecurity(parent); err != nil {
		return qualificationConfig{}, errors.New("qualification 配置父目录权限不可信")
	}
	file, err := os.Open(absolute)
	if err != nil {
		return qualificationConfig{}, errors.New("qualification 配置不可读")
	}
	defer file.Close()
	var config qualificationConfig
	if err := readQualificationJSON(file, &config); err != nil {
		return qualificationConfig{}, err
	}
	return config, nil
}

func validateQualificationDirectorySecurity(path string) error {
	descriptor, err := windows.GetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return errors.New("qualification 私有目录安全描述符不可用")
	}
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil ||
		(!owner.Equals(currentUser.User.Sid) && !owner.Equals(localSystem) && !owner.Equals(administrators)) {
		return errors.New("qualification 私有目录 owner 不可信")
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("qualification 私有目录 DACL 仍在继承")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("qualification 私有目录 DACL 不可用")
	}
	currentUserAllowed := false
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil {
			return errors.New("qualification 私有目录 DACL 无法检查")
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if sid.Equals(currentUser.User.Sid) {
				currentUserAllowed = true
				continue
			}
			if sid.Equals(localSystem) || sid.Equals(administrators) {
				continue
			}
			return errors.New("qualification 私有目录向其他主体授予了访问权限")
		default:
			return errors.New("qualification 私有目录包含不支持的 allow 规则")
		}
	}
	if !currentUserAllowed {
		return errors.New("qualification 私有目录未向当前用户授予权限")
	}
	return nil
}

func exactQualificationTarget(target qualificationTarget) bool {
	return exactVersionPattern.MatchString(target.Version) && exactVersionPattern.MatchString(target.Build) &&
		windowsmodel.ValidSHA256(target.ExecutableSHA256) && windowsmodel.ValidSHA256(target.BinarySignerSHA256) &&
		target.ProcessArchitecture == "amd64" &&
		(target.ProductIdentity == "weixin.exe" || target.ProductIdentity == "wechat.exe")
}

func qualificationEntry(config qualificationConfig) (windowsCompatibilityEntry, error) {
	if config.SchemaVersion != 1 || !config.QualificationOnly || !exactQualificationTarget(config.Target) ||
		len(config.ValidatedProfiles) == 0 {
		return windowsCompatibilityEntry{}, errors.New("qualification 配置缺少精确目标绑定")
	}
	seenProfiles := map[string]bool{}
	for _, profileID := range config.ValidatedProfiles {
		if strings.TrimSpace(profileID) != profileID || seenProfiles[profileID] {
			return windowsCompatibilityEntry{}, errors.New("qualification profile 重复或不规范")
		}
		if _, found := registeredProfile(profileID); !found {
			return windowsCompatibilityEntry{}, errors.New("qualification profile 未登记")
		}
		seenProfiles[profileID] = true
	}
	entry := windowsCompatibilityEntry{
		Version: config.Target.Version, Build: config.Target.Build,
		ExecutableSHA256: config.Target.ExecutableSHA256, BinarySignerSHA256: config.Target.BinarySignerSHA256,
		ProcessArchitecture: config.Target.ProcessArchitecture, ProductIdentity: config.Target.ProductIdentity,
		RouteSupportState: "qualification_hypothesis", ValidatedProfiles: append([]string(nil), config.ValidatedProfiles...),
		MemoryFallbackSupportState: "unsupported",
	}
	if config.AllowMemoryFallback {
		entry.MemoryFallbackSupportState = "supported"
	}
	switch config.ConfigCipherStatus {
	case "hypothesis":
		mask, err := hex.DecodeString(config.Recipe.XORMaskHex)
		if err != nil {
			return windowsCompatibilityEntry{}, errors.New("qualification XOR mask 无效")
		}
		entry.ConfigCipherSupportState = "qualification_hypothesis"
		entry.Recipe = windowsConfigCipherRecipe{
			Needle: []byte(config.Recipe.NeedleUTF8), PointerOffsets: append([]int64(nil), config.Recipe.PointerOffsets...),
			DataOffset: config.Recipe.DataOffset, EncodedLength: config.Recipe.EncodedLength,
			CandidateEncoding: config.Recipe.CandidateEncoding, CandidateKind: config.Recipe.CandidateKind,
			XORMask: mask, MaxMatches: config.Recipe.MaxMatches,
		}
	case "reviewed_no_structure":
		entry.ConfigCipherSupportState = "reviewed_no_structure"
	default:
		return windowsCompatibilityEntry{}, errors.New("qualification Config.Cipher 状态无效")
	}
	policy := windowsRoutePolicy()
	policy.QualificationOnly = true
	if !windowsmodel.RegistryEntryRuntimeEligible(entry, policy) {
		return windowsCompatibilityEntry{}, errors.New("qualification registry 假设不完整")
	}
	return entry, nil
}

func applyQualificationBootstrap(mode string) error {
	configPath := strings.TrimSpace(os.Getenv(qualificationConfigEnv))
	if !strings.EqualFold(strings.TrimSpace(mode), "development") {
		return errors.New("candidate/release 构建禁止 qualification 能力")
	}
	if configPath == "" {
		return nil
	}
	if os.Getenv(qualificationConsentEnv) != qualificationConsent {
		return errors.New("qualification 配置缺少固定授权确认")
	}
	config, err := readQualificationConfig(configPath)
	if err != nil {
		return err
	}
	entry, err := qualificationEntry(config)
	if err != nil {
		return err
	}
	windowsCompatibilityRegistry = []windowsCompatibilityEntry{entry}
	qualificationOverrideLoaded = true
	return nil
}

func qualificationRegistryEnabled() bool {
	return qualificationOverrideLoaded
}

func qualificationIdentity(native windowsmodel.NativeDriver, accountDir, dbDir string, budget workbudget.Budget) (qualificationQ0Evidence, error) {
	if native == nil {
		return qualificationQ0Evidence{}, errors.New("Windows identity collector 不可用")
	}
	processes, err := native.ListProcesses()
	if err != nil || len(processes) == 0 {
		return qualificationQ0Evidence{}, errors.New("未发现运行中的微信进程")
	}
	processes = windowsmodel.OrderedProcesses(processes)
	evidence := make([]windowsmodel.ProcessEvidence, 0, len(processes))
	for _, process := range processes {
		evidence = append(evidence, native.CollectEvidence(process))
	}
	evidence = native.BindEvidence(evidence, accountDir, dbDir, budget)
	evidence = windowsmodel.OrderedProcessEvidence(evidence)
	result := qualificationQ0Evidence{
		SchemaVersion: 1, QualificationOnly: true, ProcessCount: len(evidence),
		SecretsIncluded: false, PathsIncluded: false, AccountIdentityIncluded: false,
	}
	identities := map[string]windowsmodel.ProcessEvidence{}
	for _, process := range evidence {
		switch process.Binding {
		case "target":
			result.TargetBoundProcessCount++
		case "other":
			return qualificationQ0Evidence{}, errors.New("qualification 发现账号身份冲突")
		default:
			result.UnknownAccountProcessCount++
		}
		if process.Binding == "target" || process.Binding == "unknown" {
			binary := process.Binary
			key := strings.Join([]string{binary.Version, binary.Build, binary.ExecutableSHA256,
				binary.BinarySignerSHA256, binary.ProcessArchitecture, binary.ProductIdentity}, "\x00")
			identities[key] = process
		}
	}
	if result.TargetBoundProcessCount == 0 {
		return qualificationQ0Evidence{}, errors.New("qualification 无法绑定目标账号进程")
	}
	if len(identities) != 1 {
		return qualificationQ0Evidence{}, errors.New("qualification 无法唯一绑定微信二进制身份")
	}
	var selected windowsmodel.ProcessEvidence
	for _, process := range identities {
		selected = process
	}
	binary := selected.Binary
	if binary.ProcessArchitecture != "amd64" || binary.ProcessArchitectureStatus != windowsmodel.ArchitectureVerified {
		return qualificationQ0Evidence{}, errors.New("qualification_identity_architecture_not_verified")
	}
	if binary.BinaryFingerprintStatus != windowsmodel.FingerprintVerified || !windowsmodel.ValidSHA256(binary.ExecutableSHA256) {
		return qualificationQ0Evidence{}, errors.New("qualification_identity_fingerprint_not_verified")
	}
	if binary.BinarySigningStatus != windowsmodel.SigningVerified || !windowsmodel.ValidSHA256(binary.BinarySignerSHA256) {
		return qualificationQ0Evidence{}, errors.New("qualification_identity_primary_signer_not_verified")
	}
	if binary.ProductIdentity != "weixin.exe" && binary.ProductIdentity != "wechat.exe" {
		return qualificationQ0Evidence{}, errors.New("qualification_identity_product_not_verified")
	}
	if !exactVersionPattern.MatchString(binary.Version) || !exactVersionPattern.MatchString(binary.Build) {
		return qualificationQ0Evidence{}, errors.New("qualification_identity_version_build_not_verified")
	}
	result.Version, result.Build = binary.Version, binary.Build
	result.ExecutableSHA256 = binary.ExecutableSHA256
	result.BinaryFingerprintStatus = binary.BinaryFingerprintStatus
	result.BinarySigningStatus = binary.BinarySigningStatus
	result.BinarySignerSHA256 = binary.BinarySignerSHA256
	result.ProductIdentity = binary.ProductIdentity
	result.ProcessArchitecture = binary.ProcessArchitecture
	result.ProcessArchitectureStatus = binary.ProcessArchitectureStatus
	result.TargetBindingStatus = "path_verified"
	return result, nil
}

func qualificationIdentityAfterAuthorization(reader io.Reader, writer io.Writer, native windowsmodel.NativeDriver) (qualificationQ0Evidence, error) {
	if os.Getenv(qualificationConsentEnv) != qualificationConsent {
		return qualificationQ0Evidence{}, errors.New("Q0 缺少固定授权确认")
	}
	var request qualificationQ0Request
	if err := readQualificationJSON(reader, &request); err != nil {
		return qualificationQ0Evidence{}, err
	}
	if request.SchemaVersion != 1 || request.Authorization != qualificationConsent {
		return qualificationQ0Evidence{}, errors.New("Q0 授权确认无效")
	}
	validated, err := optionsFromRequest(acquireRequest{
		AccountDir: request.AccountDir, DBDir: request.DBDir, Scopes: []string{"database"},
		DeadlineMS: request.DeadlineMS,
	})
	if err != nil {
		return qualificationQ0Evidence{}, err
	}
	defer zeroBytes(validated.CatalogKey)
	before := windowsmodel.ProcessInventoryID(native)
	result, err := qualificationIdentity(native, validated.AccountDir, validated.DBDir, validated.Budget)
	if err != nil {
		return qualificationQ0Evidence{}, err
	}
	after := windowsmodel.ProcessInventoryID(native)
	result.ProcessInventoryStable = before == after
	if !result.ProcessInventoryStable {
		return qualificationQ0Evidence{}, errors.New("Q0 进程 inventory 在采集期间发生变化")
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return qualificationQ0Evidence{}, errors.New("Q0 证据编码失败")
	}
	defer zeroBytes(payload)
	if _, err := writer.Write(append(payload, '\n')); err != nil {
		return qualificationQ0Evidence{}, errors.New("Q0 证据写入失败")
	}
	return result, nil

}

func runQualificationQ0(reader io.Reader, writer io.Writer) error {
	_, err := qualificationIdentityAfterAuthorization(reader, writer, windowsNativeDriver())
	return err
}

func runQualificationCommand(arguments []string, reader io.Reader, writer io.Writer) (bool, int) {
	if len(arguments) != 2 || arguments[1] != "qualification-q0" {
		return false, 0
	}
	if err := runQualificationQ0(reader, writer); err != nil {
		return true, writeError(err, 3)
	}
	return true, 0
}
