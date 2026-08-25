//go:build windows

package windows

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type fixedFileInfo struct {
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

type versionTranslation struct {
	Language uint16
	CodePage uint16
}

type cachedBinaryEvidence struct {
	Version            string
	Build              string
	ProductIdentity    string
	SigningStatus      string
	BinarySignerSHA256 string
}

var binaryEvidenceCache sync.Map

func canonicalExecutablePath(path string) string {
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

func versionResourceString(buffer []byte, translation versionTranslation, key string) string {
	block := fmt.Sprintf(`\StringFileInfo\%04x%04x\%s`, translation.Language, translation.CodePage, key)
	var value *uint16
	var length uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buffer[0]), block, unsafe.Pointer(&value), &length); err != nil ||
		value == nil || length == 0 || length > 32768 {
		return ""
	}
	characters := unsafe.Slice(value, int(length))
	if len(characters) > 0 && characters[len(characters)-1] == 0 {
		characters = characters[:len(characters)-1]
	}
	return syscall.UTF16ToString(characters)
}

func fileVersion(path string) (string, string, string) {
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
	var fixed *fixedFileInfo
	var fixedSize uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buffer[0]), `\`, unsafe.Pointer(&fixed), &fixedSize); err != nil ||
		fixed == nil || fixedSize < uint32(unsafe.Sizeof(fixedFileInfo{})) || fixed.Signature != 0xfeef04bd {
		return "", "", ""
	}
	major := fixed.FileVersionMS >> 16
	minor := fixed.FileVersionMS & 0xffff
	patch := fixed.FileVersionLS >> 16
	revision := fixed.FileVersionLS & 0xffff
	version := fmt.Sprintf("%d.%d.%d.%d", major, minor, patch, revision)
	build := fmt.Sprintf("%d.%d", patch, revision)
	translations := []versionTranslation{{Language: 0x0409, CodePage: 0x04b0}}
	var values *versionTranslation
	var valuesSize uint32
	if err := windows.VerQueryValue(
		unsafe.Pointer(&buffer[0]), `\VarFileInfo\Translation`, unsafe.Pointer(&values), &valuesSize,
	); err == nil && values != nil && valuesSize >= uint32(unsafe.Sizeof(versionTranslation{})) && valuesSize <= 4096 {
		translations = append([]versionTranslation(nil), unsafe.Slice(values, int(valuesSize)/int(unsafe.Sizeof(versionTranslation{})))...)
	}
	for _, translation := range translations {
		identity := NormalizeProductIdentity(
			filepath.Base(path),
			versionResourceString(buffer, translation, "OriginalFilename"),
			versionResourceString(buffer, translation, "ProductName"),
			versionResourceString(buffer, translation, "CompanyName"),
		)
		if identity != "" {
			return version, build, identity
		}
	}
	return version, build, ""
}

func binaryEvidenceForPath(path, executableHash string, runtime EvidenceRuntime) cachedBinaryEvidence {
	cacheKey := strings.ToLower(path) + "\x00" + executableHash
	if cached, found := binaryEvidenceCache.Load(cacheKey); found {
		return cached.(cachedBinaryEvidence)
	}
	version, build, productIdentity := fileVersion(path)
	signingStatus, signer := SigningUnavailable, ""
	if runtime.AuthenticodeEvidence != nil {
		signingStatus, signer = runtime.AuthenticodeEvidence(path)
	}
	value := cachedBinaryEvidence{
		Version: version, Build: build, ProductIdentity: productIdentity,
		SigningStatus: signingStatus, BinarySignerSHA256: signer,
	}
	binaryEvidenceCache.Store(cacheKey, value)
	return value
}

func (driver *nativeDriver) collectEvidenceFromHandle(process Process, handle Handle) ProcessEvidence {
	result := ProcessEvidence{Process: process, Binding: "unknown"}
	if handle == 0 {
		result.Binary = BinaryEvidence{
			BinaryFingerprintStatus: FingerprintUnavailable, BinarySigningStatus: SigningUnavailable,
			ProcessArchitecture: "unknown", ProcessArchitectureStatus: ArchitectureUnavailable,
		}
		return result
	}
	result.Path = canonicalExecutablePath(processExecutablePath(handle))
	result.Started = processStartTime(handle)
	result.Architecture = processArchitecture(handle)
	hash := "unavailable"
	if driver.runtime.Evidence.ExecutableSHA256 != nil {
		hash = driver.runtime.Evidence.ExecutableSHA256(result.Path)
	}
	cached := cachedBinaryEvidence{SigningStatus: SigningUnavailable}
	if result.Path != "" && ValidSHA256(hash) {
		cached = binaryEvidenceForPath(result.Path, hash, driver.runtime.Evidence)
	}
	result.Binary = BinaryEvidence{
		Version: cached.Version, Build: cached.Build, ExecutableSHA256: hash,
		BinaryFingerprintStatus: FingerprintUnavailable, BinarySigningStatus: cached.SigningStatus,
		BinarySignerSHA256: cached.BinarySignerSHA256, ProcessArchitecture: result.Architecture,
		ProcessArchitectureStatus: ArchitectureUnavailable, ProductIdentity: cached.ProductIdentity,
	}
	if ValidSHA256(hash) {
		result.Binary.BinaryFingerprintStatus = FingerprintVerified
	}
	if result.Architecture == "amd64" || result.Architecture == "arm64" || result.Architecture == "x86" {
		result.Binary.ProcessArchitectureStatus = ArchitectureVerified
	}
	result.InstanceID = StableProcessInstanceID(result)
	return result
}
