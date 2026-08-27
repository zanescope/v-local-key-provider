package provider

// 这些 facade 测试固定 main package 与 internal/platform/windows 的集成契约。

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"
)

func completeWindowsRouteEvidence() windowsBinaryEvidence {
	return windowsBinaryEvidence{
		Version: "4.1.11.17", Build: "11.17", ExecutableSHA256: strings.Repeat("a", 64),
		BinaryFingerprintStatus: windowsFingerprintVerified, BinarySigningStatus: windowsSigningVerified,
		BinarySignerSHA256: strings.Repeat("b", 64), ProcessArchitecture: "amd64",
		ProcessArchitectureStatus: windowsArchitectureVerified, ProductIdentity: "weixin.exe",
	}
}

func fixtureWindowsRegistryEntry(evidence windowsBinaryEvidence) windowsCompatibilityEntry {
	return windowsCompatibilityEntry{
		Version: evidence.Version, Build: evidence.Build, ExecutableSHA256: evidence.ExecutableSHA256,
		BinarySignerSHA256: evidence.BinarySignerSHA256, ProcessArchitecture: evidence.ProcessArchitecture,
		ProductIdentity: evidence.ProductIdentity, RouteSupportState: "supported",
		ValidatedProfiles: []string{defaultProfileID},
		Recipe: windowsConfigCipherRecipe{
			Needle: []byte("Config.Cipher"), PointerOffsets: []int64{16}, DataOffset: 8,
			EncodedLength: 32, CandidateEncoding: "raw32", CandidateKind: "raw_enc_key", MaxMatches: 4,
		},
	}
}

func TestPhase4WindowsRegistryRequiresExactMachineEvidence(t *testing.T) {
	evidence := completeWindowsRouteEvidence()
	entry := fixtureWindowsRegistryEntry(evidence)
	decision := evaluateWindowsRoute(evidence, []windowsCompatibilityEntry{entry})
	if decision.CompatibilityRegistryStatus != windowsRegistryRegisteredSupported ||
		decision.ConfigCipherRouteStatus != windowsConfigCipherEligible || decision.EntryIndex != 0 {
		t.Fatalf("exact Windows registry evidence was not accepted: %#v", decision)
	}
	evidence.ExecutableSHA256 = strings.Repeat("c", 64)
	decision = evaluateWindowsRoute(evidence, []windowsCompatibilityEntry{entry})
	if decision.CompatibilityRegistryStatus != windowsRegistryUnregistered ||
		decision.ConfigCipherRouteStatus != windowsConfigCipherUnavailableUnknown {
		t.Fatalf("different Windows fingerprint inherited fixed-layout support: %#v", decision)
	}
}

func TestPhase5WindowsReleaseRegistryRequiresPromotionDigest(t *testing.T) {
	previousMode, previousPromotion := buildMode, releasePromotionSHA256
	buildMode = "release"
	releasePromotionSHA256 = ""
	t.Cleanup(func() {
		buildMode = previousMode
		releasePromotionSHA256 = previousPromotion
	})
	evidence := completeWindowsRouteEvidence()
	entry := fixtureWindowsRegistryEntry(evidence)
	decision := evaluateWindowsRoute(evidence, []windowsCompatibilityEntry{entry})
	if decision.CompatibilityRegistryStatus != windowsRegistryRegisteredRejected {
		t.Fatalf("release accepted an unpromoted Windows candidate: %#v", decision)
	}
	releasePromotionSHA256 = strings.Repeat("d", 64)
	decision = evaluateWindowsRoute(evidence, []windowsCompatibilityEntry{entry})
	if decision.CompatibilityRegistryStatus != windowsRegistryRegisteredSupported ||
		!containsString(decision.Evidence, "release_promotion_verified") ||
		!containsString(decision.Evidence, "real_device_evidence_present") {
		t.Fatalf("promoted Windows release candidate was rejected: %#v", decision)
	}
}

func TestPhase4WindowsRegistryRejectsUntrustedOrIncompleteEntries(t *testing.T) {
	evidence := completeWindowsRouteEvidence()
	evidence.BinarySigningStatus = windowsSigningInvalid
	decision := evaluateWindowsRoute(evidence, nil)
	if decision.CompatibilityRegistryStatus != windowsRegistryUntrustedBinary ||
		decision.ConfigCipherRouteStatus != windowsConfigCipherUnavailableUntrusted {
		t.Fatalf("untrusted Windows binary was not rejected: %#v", decision)
	}
	evidence = completeWindowsRouteEvidence()
	entry := fixtureWindowsRegistryEntry(evidence)
	entry.ValidatedProfiles = nil
	decision = evaluateWindowsRoute(evidence, []windowsCompatibilityEntry{entry})
	if decision.CompatibilityRegistryStatus != windowsRegistryRegisteredRejected || decision.EntryIndex != 0 {
		t.Fatalf("profile-free Windows registry entry was accepted: %#v", decision)
	}
	entry = fixtureWindowsRegistryEntry(evidence)
	entry.RouteSupportState = "candidate"
	if decision = evaluateWindowsRoute(evidence, []windowsCompatibilityEntry{entry}); decision.CompatibilityRegistryStatus != windowsRegistryRegisteredRejected {
		t.Fatalf("non-supported Windows route state was accepted: %#v", decision)
	}
	entry = fixtureWindowsRegistryEntry(evidence)
	entry.ValidatedProfiles = []string{"unknown-profile"}
	if decision = evaluateWindowsRoute(evidence, []windowsCompatibilityEntry{entry}); decision.CompatibilityRegistryStatus != windowsRegistryRegisteredRejected {
		t.Fatalf("unregistered Windows cipher profile was accepted: %#v", decision)
	}
}

func TestPhase4WindowsFallbackRequiresRegistryAnchoredSigner(t *testing.T) {
	evidence := completeWindowsRouteEvidence()
	entry := fixtureWindowsRegistryEntry(evidence)
	if !windowsFallbackIdentityEligible(evidence, []windowsCompatibilityEntry{entry}) {
		t.Fatal("eligible registry signer did not authorize the generic fallback")
	}
	evidence.BinarySignerSHA256 = strings.Repeat("d", 64)
	if windowsFallbackIdentityEligible(evidence, []windowsCompatibilityEntry{entry}) {
		t.Fatal("arbitrary trusted Authenticode signer authorized process-memory scanning")
	}
	evidence = completeWindowsRouteEvidence()
	entry.ValidatedProfiles = nil
	if windowsFallbackIdentityEligible(evidence, []windowsCompatibilityEntry{entry}) {
		t.Fatal("incomplete registry entry anchored a fallback signer")
	}
}

func TestPhase4WindowsFallbackEvidenceIsArchitectureSpecific(t *testing.T) {
	evidence := completeWindowsRouteEvidence()
	x64Entry := fixtureWindowsRegistryEntry(evidence)
	evidence.ProcessArchitecture = "arm64"
	if windowsFallbackIdentityEligible(evidence, []windowsCompatibilityEntry{x64Entry}) {
		t.Fatal("x64 live evidence authorized ARM64 fallback scanning")
	}
	arm64Entry := fixtureWindowsRegistryEntry(evidence)
	arm64Entry.ExecutableSHA256 = strings.Repeat("d", 64)
	if !windowsFallbackIdentityEligible(evidence, []windowsCompatibilityEntry{x64Entry, arm64Entry}) {
		t.Fatal("matching ARM64 candidate entry did not authorize ARM64 fallback scanning")
	}
	evidence.ProcessArchitecture = "x86"
	if windowsFallbackIdentityEligible(evidence, []windowsCompatibilityEntry{x64Entry, arm64Entry}) {
		t.Fatal("unregistered x86 architecture inherited fallback authorization")
	}
}

func TestPhase4WindowsProductIdentityRequiresSignedVersionMetadata(t *testing.T) {
	if got := normalizeWindowsProductIdentity("Weixin.exe", "Weixin.exe", "Weixin", "Tencent Technology"); got != "weixin.exe" {
		t.Fatalf("valid signed product metadata was rejected: %q", got)
	}
	for _, test := range []struct {
		current, original, product, company string
	}{
		{current: "Weixin.exe", original: "other.exe", product: "Weixin", company: "Tencent"},
		{current: "Weixin.exe", original: "Weixin.exe", product: "Unrelated", company: "Tencent"},
		{current: "Weixin.exe", original: "Weixin.exe", product: "Weixin", company: "Unrelated"},
	} {
		if got := normalizeWindowsProductIdentity(test.current, test.original, test.product, test.company); got != "" {
			t.Fatalf("spoofable product metadata was accepted: %q", got)
		}
	}
}

func TestPhase4WindowsAuthenticodeEvidenceUsesVerifiedPrimarySigner(t *testing.T) {
	rootPayload, err := os.ReadFile("runtime_trust_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	nativePayload, err := os.ReadFile("internal/platform/windows/native_evidence_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	rootSource := string(rootPayload)
	nativeSource := string(nativePayload)
	if !strings.Contains(rootSource, "verifiedWindowsSignerSHA256(&data)") ||
		!strings.Contains(nativeSource, "runtime.AuthenticodeEvidence(path)") {
		t.Fatal("Windows process evidence is not bound to WinTrust's verified primary signer")
	}
	if strings.Contains(rootSource, "CertEnumCertificatesInStore") || strings.Contains(nativeSource, "CertEnumCertificatesInStore") {
		t.Fatal("Windows process evidence still selects an arbitrary certificate from the PKCS#7 store")
	}
}

func TestPhase4ProductionRegistryContainsOnlyCompleteCandidates(t *testing.T) {
	for index, entry := range windowsCompatibilityRegistry {
		evidence := windowsBinaryEvidence{
			Version: entry.Version, Build: entry.Build, ExecutableSHA256: entry.ExecutableSHA256,
			BinaryFingerprintStatus: windowsFingerprintVerified, BinarySigningStatus: windowsSigningVerified,
			BinarySignerSHA256: entry.BinarySignerSHA256, ProcessArchitecture: entry.ProcessArchitecture,
			ProcessArchitectureStatus: windowsArchitectureVerified, ProductIdentity: entry.ProductIdentity,
		}
		decision := evaluateWindowsRoute(evidence, windowsCompatibilityRegistry)
		if decision.CompatibilityRegistryStatus != windowsRegistryRegisteredSupported ||
			decision.ConfigCipherRouteStatus != windowsConfigCipherEligible ||
			decision.EntryIndex != index || !entry.Recipe.Valid() {
			t.Fatalf("production Windows registry entry %d is not a complete candidate", index)
		}
	}
}

type fixtureConfigMemory map[uint64][]byte

func (memory fixtureConfigMemory) ReadMemory(address uint64, size int) ([]byte, error) {
	value := memory[address]
	if len(value) != size {
		return nil, errors.New("short read")
	}
	return append([]byte(nil), value...), nil
}

func TestPhase4ConfigCipherExtractorFollowsBoundedLayoutAndDecodes(t *testing.T) {
	needleAddress := uint64(0x100000)
	objectAddress := uint64(0x200000)
	pointer := make([]byte, 8)
	binary.LittleEndian.PutUint64(pointer, objectAddress)
	want := bytes.Repeat([]byte{0x5a}, 32)
	mask := []byte{0x13, 0x37}
	encoded := append([]byte(nil), want...)
	for index := range encoded {
		encoded[index] ^= mask[index%len(mask)]
	}
	recipe := windowsConfigCipherRecipe{
		Needle: []byte("Config.Cipher"), PointerOffsets: []int64{16}, DataOffset: 8,
		EncodedLength: 32, CandidateEncoding: "raw32", CandidateKind: "raw_enc_key",
		XORMask: mask, MaxMatches: 2,
	}
	memory := fixtureConfigMemory{needleAddress + 16: pointer, objectAddress + 8: encoded}
	got, err := extractWindowsConfigCipherCandidate(memory, needleAddress, 8, recipe)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Config.Cipher extraction failed: got=%x err=%v", got, err)
	}
}

func TestPhase4ConfigCipherExtractorRejectsOverflowShortReadAndInvalidHex(t *testing.T) {
	recipe := windowsConfigCipherRecipe{
		Needle: []byte("Config.Cipher"), PointerOffsets: []int64{16}, DataOffset: 8,
		EncodedLength: 64, CandidateEncoding: "hex64", CandidateKind: "passphrase", MaxMatches: 1,
	}
	if _, err := extractWindowsConfigCipherCandidate(fixtureConfigMemory{}, ^uint64(0)-4, 8, recipe); err == nil {
		t.Fatal("overflowing Config.Cipher layout was accepted")
	}
	pointer := make([]byte, 8)
	binary.LittleEndian.PutUint64(pointer, 0x200000)
	memory := fixtureConfigMemory{0x100010: pointer, 0x200008: bytes.Repeat([]byte{'z'}, 64)}
	if _, err := extractWindowsConfigCipherCandidate(memory, 0x100000, 8, recipe); err == nil {
		t.Fatal("invalid hexadecimal Config.Cipher candidate was accepted")
	}
	delete(memory, 0x200008)
	if _, err := extractWindowsConfigCipherCandidate(memory, 0x100000, 8, recipe); err == nil {
		t.Fatal("short Config.Cipher read was accepted")
	}
}

func TestPhase4WindowsDiagnosticDefaultsAreStableAndEvidenceFree(t *testing.T) {
	diag := diagnostics{Platform: "windows"}
	applyPlatformDiagnosticDefaults(&diag)
	if diag.ShadowRouteStatus != "not_applicable" || len(diag.RoutePriority) != 0 ||
		diag.ProcessArchitecture != "unknown" || diag.ProcessArchitectureStatus != windowsArchitectureUnavailable ||
		diag.BinaryFingerprintStatus != windowsFingerprintUnavailable ||
		diag.BinarySigningStatus != windowsSigningUnavailable ||
		diag.CompatibilityRegistryStatus != windowsRegistryNotEvaluated ||
		diag.ConfigCipherRouteStatus != windowsConfigCipherNotEvaluated {
		t.Fatalf("unexpected Windows diagnostic defaults: %+v", diag)
	}
	if diag.WindowsRouteEvidence == nil || diag.FallbackStageCounts == nil || len(diag.WindowsRouteEvidence) != 0 ||
		len(diag.FallbackStageCounts) != 0 {
		t.Fatal("Windows defaults fabricated route evidence or omitted stable empty containers")
	}
}
