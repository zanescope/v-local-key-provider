//go:build windows

package provider

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wintrustRuntime                     = windows.NewLazySystemDLL("wintrust.dll")
	wtHelperProvDataFromStateData       = wintrustRuntime.NewProc("WTHelperProvDataFromStateData")
	wtHelperGetProvSignerFromChain      = wintrustRuntime.NewProc("WTHelperGetProvSignerFromChain")
	wtHelperGetProvCertificateFromChain = wintrustRuntime.NewProc("WTHelperGetProvCertFromChain")
)

type cryptProviderCertificate struct {
	Size        uint32
	Certificate *windows.CertContext
}

func pointerReturnedByWinTrust(address uintptr) unsafe.Pointer {
	// LazyProc.Call 会把原生指针返回值暴露为 uintptr。该内存在 WTD_STATEACTION_CLOSE
	// 之前归 WinTrust 所有，因此立即以指针类型保存其位模式，不对其做算术运算，也不让
	// 整数值超过原生生命周期继续存在。
	return *(*unsafe.Pointer)(unsafe.Pointer(&address))
}

func verifiedWindowsSignerSHA256(data *windows.WinTrustData) (string, error) {
	if data == nil || data.StateData == 0 || wtHelperProvDataFromStateData.Find() != nil ||
		wtHelperGetProvSignerFromChain.Find() != nil || wtHelperGetProvCertificateFromChain.Find() != nil {
		return "", errors.New("Authenticode signer chain is unavailable")
	}
	providerData, _, _ := wtHelperProvDataFromStateData.Call(uintptr(data.StateData))
	if providerData == 0 {
		return "", errors.New("Authenticode provider state is unavailable")
	}
	signer, _, _ := wtHelperGetProvSignerFromChain.Call(providerData, 0, 0, 0)
	if signer == 0 {
		return "", errors.New("Authenticode primary signer is unavailable")
	}
	certificatePointer, _, _ := wtHelperGetProvCertificateFromChain.Call(signer, 0)
	if certificatePointer == 0 {
		return "", errors.New("Authenticode signer certificate is unavailable")
	}
	providerCertificate := (*cryptProviderCertificate)(pointerReturnedByWinTrust(certificatePointer))
	if providerCertificate == nil || providerCertificate.Size < uint32(unsafe.Sizeof(cryptProviderCertificate{})) {
		return "", errors.New("Authenticode signer certificate is invalid")
	}
	certificate := providerCertificate.Certificate
	if certificate == nil || certificate.EncodedCert == nil || certificate.Length == 0 || certificate.Length > 16*1024*1024 {
		return "", errors.New("Authenticode signer certificate is invalid")
	}
	encoded := unsafe.Slice(certificate.EncodedCert, int(certificate.Length))
	digest := sha256.Sum256(encoded)
	runtime.KeepAlive(data)
	return hex.EncodeToString(digest[:]), nil
}

// windowsAuthenticodeEvidence 使用 WinTrust 验证文件，并把结果绑定到 WinTrust 实际的
// primary signer。由于 release 信任仍由 composition root 负责，它会被注入内部 Windows
// process driver。
func windowsAuthenticodeEvidence(path string) (string, string) {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windowsSigningUnavailable, ""
	}
	fileInfo := windows.WinTrustFileInfo{
		Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: pathPointer,
	}
	data := windows.WinTrustData{
		Size: uint32(unsafe.Sizeof(windows.WinTrustData{})), UIChoice: windows.WTD_UI_NONE,
		RevocationChecks: windows.WTD_REVOKE_NONE, UnionChoice: windows.WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&fileInfo), StateAction: windows.WTD_STATEACTION_VERIFY,
		ProvFlags: windows.WTD_CACHE_ONLY_URL_RETRIEVAL | windows.WTD_REVOCATION_CHECK_NONE,
		UIContext: windows.WTD_UICONTEXT_EXECUTE,
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	signer := ""
	var signerErr error
	if verifyErr == nil {
		signer, signerErr = verifiedWindowsSignerSHA256(&data)
	}
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	if verifyErr != nil {
		return windowsSigningInvalid, ""
	}
	if signerErr != nil || !validWindowsSHA256(signer) {
		return windowsSigningUnavailable, ""
	}
	return windowsSigningVerified, signer
}

func expectedWindowsSignerSHA256() (string, error) {
	expected := strings.ToLower(strings.TrimSpace(releaseSignerSHA256))
	decoded, err := hex.DecodeString(expected)
	if err != nil || len(decoded) != sha256.Size {
		return "", errors.New("release Authenticode signer identity is not embedded")
	}
	return expected, nil
}

func verifyWindowsAuthenticode(path string) error {
	expectedSigner, err := expectedWindowsSignerSHA256()
	if err != nil {
		return err
	}
	filePath, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	file := &windows.WinTrustFileInfo{
		Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: filePath,
	}
	data := &windows.WinTrustData{
		Size: uint32(unsafe.Sizeof(windows.WinTrustData{})), UIChoice: windows.WTD_UI_NONE,
		// Provider 运行时明确保持离线。发布流程负责依赖吊销状态的验证；此检查不获取 URL，
		// 只验证嵌入的 Authenticode 签名和已缓存的信任链。
		RevocationChecks: windows.WTD_REVOKE_NONE, UnionChoice: windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(file),
		ProvFlags: windows.WTD_REVOCATION_CHECK_NONE | windows.WTD_CACHE_ONLY_URL_RETRIEVAL |
			windows.WTD_DISABLE_MD2_MD4,
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	actualSigner := ""
	var signerErr error
	if verifyErr == nil {
		actualSigner, signerErr = verifiedWindowsSignerSHA256(data)
	}
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if verifyErr != nil {
		return errors.New("Authenticode verification failed")
	}
	if signerErr != nil {
		return signerErr
	}
	if subtle.ConstantTimeCompare([]byte(actualSigner), []byte(expectedSigner)) != 1 {
		return errors.New("Authenticode signer does not match the release identity")
	}
	return nil
}

func validateRuntimeComponent(role string) error {
	if role == "helper" {
		return errors.New("Windows builds do not expose a helper entry point")
	}
	if !releaseBuild() {
		return nil
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return err
	}
	return verifyWindowsAuthenticode(executable)
}

func validateAcquisitionClientPath(path string) (string, error) {
	absolute, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil || strings.TrimSpace(path) == "" {
		return "", errors.New("daemon client path is invalid")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", errors.New("daemon client path is unavailable")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("daemon client is not a regular executable")
	}
	if releaseBuild() {
		if !strings.EqualFold(filepath.Base(resolved), "v-local-cli.exe") {
			return "", errors.New("release daemon client name is not fixed")
		}
		if err := verifyWindowsAuthenticode(resolved); err != nil {
			return "", errors.New("release daemon client signature is invalid")
		}
	}
	return resolved, nil
}

func acquisitionDaemonRuntimeContext(advertisedProviderPath string) (bool, string, error) {
	if advertisedProviderPath != "" {
		return false, "", errors.New("Windows acquisition daemon cannot advertise a helper launcher")
	}
	return false, "", validateRuntimeComponent("provider")
}
