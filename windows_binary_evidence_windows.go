//go:build windows

package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsProcessEvidence struct {
	Process      targetProcess
	Path         string
	Started      uint64
	Architecture string
	Binary       windowsBinaryEvidence
	InstanceID   string
	Binding      string
}

type windowsFixedFileInfo struct {
	Signature        uint32
	StructVersion    uint32
	FileVersionMS    uint32
	FileVersionLS    uint32
	ProductVersionMS uint32
	ProductVersionLS uint32
	FileFlagsMask    uint32
	FileFlags        uint32
	FileOS           uint32
	FileType         uint32
	FileSubtype      uint32
	FileDateMS       uint32
	FileDateLS       uint32
}

type windowsVersionTranslation struct {
	Language uint16
	CodePage uint16
}

type windowsCachedBinaryEvidence struct {
	Version            string
	Build              string
	ProductIdentity    string
	SigningStatus      string
	BinarySignerSHA256 string
}

var windowsBinaryEvidenceCache sync.Map

func windowsProcessStartTime(handle syscall.Handle) uint64 {
	var created, exited, kernel, user windowsFiletime
	if result, _, _ := procGetProcessTimes.Call(
		uintptr(handle), uintptr(unsafe.Pointer(&created)), uintptr(unsafe.Pointer(&exited)),
		uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)),
	); result != 0 {
		return uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
	}
	return 0
}

func windowsProcessExecutablePath(handle syscall.Handle) string {
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if result, _, _ := procQueryFullProcessImageNameW.Call(
		uintptr(handle), 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)),
	); result != 0 && size > 0 && size <= uint32(len(buffer)) {
		return syscall.UTF16ToString(buffer[:size])
	}
	return ""
}

func windowsCanonicalExecutablePath(path string) string {
	if path == "" {
		return ""
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return ""
	}
	return filepath.Clean(resolved)
}

func windowsVersionResourceString(buffer []byte, translation windowsVersionTranslation, key string) string {
	block := fmt.Sprintf(`\StringFileInfo\%04x%04x\%s`, translation.Language, translation.CodePage, key)
	var value *uint16
	var length uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buffer[0]), block, unsafe.Pointer(&value), &length); err != nil || value == nil || length == 0 || length > 32768 {
		return ""
	}
	characters := unsafe.Slice(value, int(length))
	if len(characters) > 0 && characters[len(characters)-1] == 0 {
		characters = characters[:len(characters)-1]
	}
	return syscall.UTF16ToString(characters)
}

func windowsFileVersion(path string) (string, string, string) {
	if path == "" {
		return "", "", ""
	}
	var zero windows.Handle
	size, err := windows.GetFileVersionInfoSize(path, &zero)
	if err != nil || size == 0 || size > 16*1024*1024 {
		return "", "", ""
	}
	buffer := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buffer[0])); err != nil {
		return "", "", ""
	}
	var fixed *windowsFixedFileInfo
	var fixedSize uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buffer[0]), `\`, unsafe.Pointer(&fixed), &fixedSize); err != nil ||
		fixed == nil || fixedSize < uint32(unsafe.Sizeof(windowsFixedFileInfo{})) || fixed.Signature != 0xfeef04bd {
		return "", "", ""
	}
	major := fixed.FileVersionMS >> 16
	minor := fixed.FileVersionMS & 0xffff
	patch := fixed.FileVersionLS >> 16
	revision := fixed.FileVersionLS & 0xffff
	version := fmt.Sprintf("%d.%d.%d.%d", major, minor, patch, revision)
	build := fmt.Sprintf("%d.%d", patch, revision)
	translations := []windowsVersionTranslation{{Language: 0x0409, CodePage: 0x04b0}}
	var values *windowsVersionTranslation
	var valuesSize uint32
	if err := windows.VerQueryValue(
		unsafe.Pointer(&buffer[0]), `\VarFileInfo\Translation`, unsafe.Pointer(&values), &valuesSize,
	); err == nil && values != nil && valuesSize >= uint32(unsafe.Sizeof(windowsVersionTranslation{})) && valuesSize <= 4096 {
		translations = append([]windowsVersionTranslation(nil), unsafe.Slice(values, int(valuesSize)/int(unsafe.Sizeof(windowsVersionTranslation{})))...)
	}
	for _, translation := range translations {
		identity := normalizeWindowsProductIdentity(
			filepath.Base(path),
			windowsVersionResourceString(buffer, translation, "OriginalFilename"),
			windowsVersionResourceString(buffer, translation, "ProductName"),
			windowsVersionResourceString(buffer, translation, "CompanyName"),
		)
		if identity != "" {
			return version, build, identity
		}
	}
	return version, build, ""
}

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
		// Bind the registry identity to WinTrust's actual primary signer. A PKCS#7
		// certificate store may contain timestamp or unrelated extra certificates;
		// enumerating the first code-signing leaf is not signer evidence.
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

func windowsBinaryEvidenceForPath(path, executableHash string) windowsCachedBinaryEvidence {
	cacheKey := strings.ToLower(path) + "\x00" + executableHash
	if cached, found := windowsBinaryEvidenceCache.Load(cacheKey); found {
		return cached.(windowsCachedBinaryEvidence)
	}
	version, build, productIdentity := windowsFileVersion(path)
	signingStatus, signer := windowsAuthenticodeEvidence(path)
	value := windowsCachedBinaryEvidence{
		Version: version, Build: build, ProductIdentity: productIdentity,
		SigningStatus: signingStatus, BinarySignerSHA256: signer,
	}
	windowsBinaryEvidenceCache.Store(cacheKey, value)
	return value
}

func windowsStableProcessInstanceID(result windowsProcessEvidence) string {
	product := result.Binary.ProductIdentity
	if result.Started == 0 || result.Path == "" ||
		(result.Architecture != "amd64" && result.Architecture != "arm64" && result.Architecture != "x86") ||
		!validWindowsSHA256(result.Binary.ExecutableSHA256) ||
		(product != "weixin.exe" && product != "wechat.exe") {
		return ""
	}
	identityMaterial := fmt.Sprintf("%d:%d:%s:%d:%s:%s:%s:%s:%s:%s:%s:%s", result.Process.pid, result.Process.parentID,
		strings.ToLower(result.Process.name), result.Started, strings.ToLower(result.Path), result.Architecture,
		result.Binary.ExecutableSHA256, result.Binary.BinarySigningStatus, result.Binary.BinarySignerSHA256,
		result.Binary.ProductIdentity, result.Binary.Version, result.Binary.Build)
	sum := sha256.Sum256([]byte(identityMaterial))
	return "windows-process:" + hex.EncodeToString(sum[:])
}

func windowsCollectProcessEvidenceFromHandle(process targetProcess, handle syscall.Handle) windowsProcessEvidence {
	result := windowsProcessEvidence{Process: process, Binding: "unknown"}
	if handle == 0 {
		result.Binary = windowsBinaryEvidence{
			BinaryFingerprintStatus: windowsFingerprintUnavailable, BinarySigningStatus: windowsSigningUnavailable,
			ProcessArchitecture: "unknown", ProcessArchitectureStatus: windowsArchitectureUnavailable,
		}
		return result
	}
	result.Path = windowsCanonicalExecutablePath(windowsProcessExecutablePath(handle))
	result.Started = windowsProcessStartTime(handle)
	result.Architecture = windowsProcessArchitecture(handle)
	hash := executableSHA256(result.Path)
	cached := windowsCachedBinaryEvidence{SigningStatus: windowsSigningUnavailable}
	if result.Path != "" && validWindowsSHA256(hash) {
		cached = windowsBinaryEvidenceForPath(result.Path, hash)
	}
	result.Binary = windowsBinaryEvidence{
		Version: cached.Version, Build: cached.Build, ExecutableSHA256: hash,
		BinaryFingerprintStatus: windowsFingerprintUnavailable, BinarySigningStatus: cached.SigningStatus,
		BinarySignerSHA256: cached.BinarySignerSHA256, ProcessArchitecture: result.Architecture,
		ProcessArchitectureStatus: windowsArchitectureUnavailable, ProductIdentity: cached.ProductIdentity,
	}
	if validWindowsSHA256(hash) {
		result.Binary.BinaryFingerprintStatus = windowsFingerprintVerified
	}
	if result.Architecture == "amd64" || result.Architecture == "arm64" || result.Architecture == "x86" {
		result.Binary.ProcessArchitectureStatus = windowsArchitectureVerified
	}
	result.InstanceID = windowsStableProcessInstanceID(result)
	return result
}

func windowsCollectProcessEvidence(process targetProcess) windowsProcessEvidence {
	handleValue, _, _ := procOpenProcess.Call(processQueryLimitedInformation, 0, uintptr(process.pid))
	if handleValue == 0 {
		return windowsCollectProcessEvidenceFromHandle(process, 0)
	}
	handle := syscall.Handle(handleValue)
	defer closeHandle(handle)
	return windowsCollectProcessEvidenceFromHandle(process, handle)
}
