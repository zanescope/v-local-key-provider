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
	// LazyProc.Call exposes native pointer return values as uintptr. WinTrust
	// owns this memory until WTD_STATEACTION_CLOSE, so immediately preserve the
	// pointer bits in a pointer-typed value instead of performing arithmetic or
	// retaining the integer beyond that native lifetime.
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
		// The Provider is explicitly offline at runtime. Publication performs the
		// revocation-sensitive verification; this check validates the embedded
		// Authenticode signature and cached trust chain without URL retrieval.
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

func acquisitionDaemonRuntimeContext(advertisedProviderPath string) (bool, string, error) {
	if advertisedProviderPath != "" {
		return false, "", errors.New("Windows acquisition daemon cannot advertise a helper launcher")
	}
	return false, "", validateRuntimeComponent("provider")
}
