package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	darwinroute "github.com/zanescope/v-local-key-provider/internal/platform/darwin"
	windowsroute "github.com/zanescope/v-local-key-provider/internal/platform/windows"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func requireReleaseContractFragments(t *testing.T, path string, fragments ...string) string {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, fragment := range fragments {
		if !strings.Contains(text, fragment) {
			t.Errorf("%s is missing release regression gate %q", path, fragment)
		}
	}
	return text
}

func TestReleaseWorkflowKeepsSigningNotarizationAndProvenanceGates(t *testing.T) {
	release := requireReleaseContractFragments(t, ".github/workflows/release.yml",
		"persist-credentials: false",
		"arch: [amd64, arm64]",
		"go test ./...",
		"go vet ./...",
		"notarytool submit",
		"submission_status",
		"notarytool log",
		"xcrun stapler staple",
		"xcrun stapler validate",
		"codesign --verify --strict",
		"spctl --assess --type execute",
		"spctl --assess --type open",
		"signature-manifest-windows-",
		"signature-manifest-darwin-",
		"release-checksums.txt",
		"actions/attest@",
		"npm stage publish",
		"promotion-source", "promotion-run", "candidate_source", "candidate-run-id",
		"actions: read", "attestations: read", "actions/download-artifact@",
		"gh attestation verify", "--source-digest", "V_LOCAL_KEY_PROVIDER_RELEASE_PROMOTION_PATH",
	)
	for _, asset := range []string{
		"v-local-key-provider-windows-amd64.exe",
		"v-local-key-provider-windows-arm64.exe",
		"v-local-key-provider-darwin-amd64",
		"v-local-key-provider-helper-darwin-amd64",
		"v-local-key-provider-darwin-arm64",
		"v-local-key-provider-helper-darwin-arm64",
	} {
		if !strings.Contains(release, asset) {
			t.Errorf("signed release does not bind required asset %q", asset)
		}
	}
	requireReleaseContractFragments(t, "scripts/build.ps1",
		"signtool", "verify /pa /all", "TimeStamperCertificate", "Get-FileHash -Algorithm SHA256",
		"build_mode", "runtime_authenticode_required", "fixed_install_required",
		"main.releaseSignerSHA256", "main.releasePromotionSHA256", "signer_thumbprint", "signer_certificate_sha256",
		"timestamp_signer_thumbprint", "TestReleaseCompatibilityEvidenceGate",
		"V_LOCAL_KEY_PROVIDER_RELEASE_PROMOTION_PATH", "PromotionPath", "./cmd/v-local-key-provider",
	)
	requireReleaseContractFragments(t, "scripts/build-macos.sh",
		"main.buildMode=release", "--identifier com.zanescope.v-local-key-provider",
		"--identifier com.zanescope.v-local-key-provider.helper", "--options runtime", "--timestamp",
		"macos-helper.entitlements", "codesign --verify --strict", "TestReleaseCompatibilityEvidenceGate",
		"V_LOCAL_KEY_PROVIDER_RELEASE_PROMOTION_PATH", "main.releasePromotionSHA256", "./cmd/v-local-key-provider",
	)
	requireReleaseContractFragments(t, ".github/workflows/release-candidate.yml",
		"-Candidate", "V_LOCAL_KEY_PROVIDER_BUILD_MODE: candidate",
		"candidate-manifest.js create", "dist/candidate-manifest.json", "actions/attest@",
	)
	requireReleaseContractFragments(t, "runtime_trust_windows.go",
		"WTD_REVOKE_NONE", "WTD_REVOCATION_CHECK_NONE", "WTD_CACHE_ONLY_URL_RETRIEVAL",
		"WTHelperProvDataFromStateData", "WTHelperGetProvSignerFromChain", "WTHelperGetProvCertFromChain",
		"releaseSignerSHA256", "Authenticode signer does not match the release identity",
	)
	requireReleaseContractFragments(t, "crash_hardening_windows.go",
		"WerGetFlags", "WerSetFlags", "werFaultReportingFlagNoHeap",
		"WerRegisterExcludedMemoryBlock", "WerUnregisterExcludedMemoryBlock",
	)
	requireReleaseContractFragments(t, "runtime_trust_darwin.go",
		"com.zanescope.v-local-key-provider", "com.zanescope.v-local-key-provider.helper",
		"anchor apple generic", "Provider and helper signing identities do not match", "component owner or write permissions are not trusted",
	)
	requireReleaseContractFragments(t, "internal/daemon/transport_darwin.go", "LOCAL_PEERCRED", "os.Geteuid()")
	requireReleaseContractFragments(t, "internal/daemon/transport_windows.go", "processUserMatchesCurrent", "GetTokenUser")
	requireReleaseContractFragments(t, "platform_helper_darwin.go",
		"releaseBuild()", "V_LOCAL_KEY_PROVIDER_ALLOW_UNVERIFIED_HELPER", "development_override",
	)
	requireReleaseContractFragments(t, "npm/scripts/install.js",
		"installationDirectory", "LOCALAPPDATA", "Library', 'Application Support",
		"v-local', 'key-provider", "mode: 0o700",
	)
}

func TestWindowsSourceHasNoProcessTerminationPath(t *testing.T) {
	for _, path := range []string{
		"windows_acquisition_windows.go", "windows_config_cipher_adapter.go", "runtime_trust_windows.go",
		"internal/platform/windows/driver.go", "internal/platform/windows/process.go",
		"internal/platform/windows/native_process_windows.go", "internal/platform/windows/native_evidence_windows.go",
		"internal/platform/windows/native_binding_windows.go", "internal/platform/windows/native_config_windows.go",
		"internal/platform/windows/native_memory_windows.go", "internal/platform/windows/config_cipher.go",
		"internal/platform/windows/path_binding_windows.go",
	} {
		payload, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(string(payload))
		for _, forbidden := range []string{"taskkill", "terminateprocess", "wm_close", "process_terminate"} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("%s contains forbidden broad process-control primitive %q", path, forbidden)
			}
		}
	}
}

func TestRegressionMatrixKeepsAutomatedAndLiveBoundaries(t *testing.T) {
	matrix := requireReleaseContractFragments(t, "REGRESSION_TESTS.md",
		"P0-01", "P0-08",
		"P1-01", "P1-08",
		"P2-01", "P2-09",
		"P3-01", "P3-09",
		"P4-01", "P4-07",
		"P5-01", "P5-09",
		"go test -tags=live_regression",
		"mock 不能把该状态升级为 `real_device_verified`",
	)
	if strings.Contains(matrix, "mock 通过即视为真机") {
		t.Fatal("regression matrix weakens the real-device evidence boundary")
	}
	workflow := requireReleaseContractFragments(t, ".github/workflows/live-regression.yml",
		"workflow_dispatch:", "runs-on: [self-hosted", "confirm_authorized_data",
		"candidate_run_id", "candidate_source_commit", "actions: read", "attestations: read",
		"actions/download-artifact@", "run-id: ${{ inputs.candidate_run_id }}",
		"candidate-manifest.js verify", "gh attestation verify", "--signer-workflow", "--source-digest",
		"I_HAVE_EXPLICIT_AUTHORIZATION", "secrets.LIVE_ACCOUNT_DIR", "secrets.LIVE_DB_DIR",
		"V_LOCAL_KEY_PROVIDER_LIVE_EXPECT_DATABASE_COVERAGE",
		"V_LOCAL_KEY_PROVIDER_LIVE_EXPECT_CONFIG_CIPHER_STATUS",
		"V_LOCAL_KEY_PROVIDER_LIVE_EVIDENCE_PATH",
		"actions/upload-artifact@", "go test -tags=live_regression",
	)
	for _, automaticTrigger := range []string{"pull_request:", "schedule:"} {
		if strings.Contains(workflow, automaticTrigger) {
			t.Errorf("live acquisition workflow must not have automatic trigger %q", automaticTrigger)
		}
	}
	for _, forbidden := range []string{"go build -trimpath", "scripts/build-macos.sh"} {
		if strings.Contains(workflow, forbidden) {
			t.Errorf("live acquisition workflow rebuilds instead of executing the attested candidate: %q", forbidden)
		}
	}
}

func TestReleaseBuildMarkerIsExplicit(t *testing.T) {
	previous := buildMode
	t.Cleanup(func() { buildMode = previous })

	buildMode = "release"
	if !releaseBuild() {
		t.Fatal("release build marker was not recognized")
	}
	for _, nonReleaseMode := range []string{"", "development", "candidate"} {
		buildMode = nonReleaseMode
		if releaseBuild() {
			t.Fatalf("non-release build mode %q activated release-only trust policy", nonReleaseMode)
		}
	}
}

func TestReleaseCompatibilityEvidenceGate(t *testing.T) {
	if os.Getenv("V_LOCAL_KEY_PROVIDER_REQUIRE_RELEASE_EVIDENCE") != "1" {
		t.Skip("enabled only by signed release builders")
	}
	if err := releaseCompatibilityReadiness(
		os.Getenv("V_LOCAL_KEY_PROVIDER_RELEASE_TARGET"),
		os.Getenv("V_LOCAL_KEY_PROVIDER_RELEASE_ARCH"),
	); err != nil {
		t.Fatal(err)
	}
	root := os.Getenv("V_LOCAL_KEY_PROVIDER_RELEASE_EVIDENCE_DIR")
	if root == "" {
		root = "compatibility-evidence"
	}
	if err := validateReleaseEvidenceArtifacts(
		root,
		os.Getenv("V_LOCAL_KEY_PROVIDER_RELEASE_PROMOTION_PATH"),
		strings.ToLower(strings.TrimSpace(os.Getenv("V_LOCAL_KEY_PROVIDER_RELEASE_TARGET"))),
		strings.ToLower(strings.TrimSpace(os.Getenv("V_LOCAL_KEY_PROVIDER_RELEASE_ARCH"))),
	); err != nil {
		t.Fatalf("release compatibility evidence artifacts are not bound by an external promotion to the registry and exact candidate binary: %v", err)
	}
}

func TestReleaseCompatibilityGateRequiresEligibleEntryPerTarget(t *testing.T) {
	windowsEvidence := completeWindowsRouteEvidence()
	windowsEntry := fixtureWindowsRegistryEntry(windowsEvidence)
	darwinEvidence := completeDarwinRouteEvidence()
	darwinEntry := darwinCompatibilityEntry{
		Version: darwinEvidence.Version, Build: darwinEvidence.Build,
		ExecutableSHA256: darwinEvidence.ExecutableSHA256, SigningTeamID: darwinEvidence.SigningTeamID,
		DesignatedRequirementSHA256: darwinEvidence.DesignatedRequirementSHA256,
		ProcessArchitecture:         darwinEvidence.ProcessArchitecture, MacOSMajorMinor: darwinEvidence.MacOSMajorMinor,
		RouteSupportState: "supported", ValidatedCipherProfiles: []string{defaultProfileID},
	}
	if err := validateReleaseCompatibilityRegistry("windows", "amd64", []windowsCompatibilityEntry{windowsEntry}, nil); err != nil {
		t.Fatalf("eligible Windows target was rejected: %v", err)
	}
	if err := validateReleaseCompatibilityRegistry("darwin", "arm64", nil, []darwinCompatibilityEntry{darwinEntry}); err != nil {
		t.Fatalf("eligible Darwin target was rejected: %v", err)
	}
	if err := validateReleaseCompatibilityRegistry("windows", "arm64", []windowsCompatibilityEntry{windowsEntry}, nil); err == nil {
		t.Fatal("release gate accepted an architecture without candidate-bound evidence")
	}
	windowsEntry.ValidatedProfiles = nil
	if err := validateReleaseCompatibilityRegistry("windows", "amd64", []windowsCompatibilityEntry{windowsEntry}, nil); err == nil {
		t.Fatal("release gate accepted a registry entry without validated profiles")
	}
}

func TestReleaseProfilesMustMatchExactly(t *testing.T) {
	expected := []string{"profile-a", "profile-b"}
	if !sameReleaseProfiles([]string{"profile-b", "profile-a"}, expected) {
		t.Fatal("order-independent exact profile set was rejected")
	}
	for _, actual := range [][]string{
		{"profile-a"},
		{"profile-a", "profile-b", "profile-c"},
		{"profile-a", "profile-a"},
		{"profile-a", " profile-b"},
	} {
		if sameReleaseProfiles(actual, expected) {
			t.Fatalf("non-exact release profile set was accepted: %v", actual)
		}
	}
}

func writeReleaseFixtureArtifact(t *testing.T, root string, value releaseEvidenceArtifact) (string, []byte, string) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	digestBytes := sha256.Sum256(payload)
	digest := hex.EncodeToString(digestBytes[:])
	path := filepath.Join(root, digest+".json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return digest, payload, path
}

func writeReleaseFixturePromotion(t *testing.T, root string, value releasePromotionManifest) string {
	t.Helper()
	directory := filepath.Join(root, "promotions")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "fixture.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func fixturePromotion(target releasePromotionTarget) releasePromotionManifest {
	return releasePromotionManifest{
		SchemaVersion: 1, ProviderVersion: version,
		CandidateSourceCommit: strings.Repeat("a", 40), CandidateWorkflowRunID: "12345",
		CandidateAttestationWorkflow: releaseCandidateAttestationWorkflow,
		Targets:                      []releasePromotionTarget{target},
	}
}

func TestReleaseEvidenceArtifactIsContentAddressedAndExternallyPromoted(t *testing.T) {
	previousWindows := windowsCompatibilityRegistry
	previousDarwin := darwinCompatibilityRegistry
	t.Cleanup(func() {
		windowsCompatibilityRegistry = previousWindows
		darwinCompatibilityRegistry = previousDarwin
	})
	evidence := completeWindowsRouteEvidence()
	entry := fixtureWindowsRegistryEntry(evidence)
	artifact := releaseEvidenceArtifact{
		SchemaVersion: 1, CandidateSourceCommit: strings.Repeat("a", 40), CandidateWorkflowRunID: "12345",
		CandidateAttestationWorkflow: releaseCandidateAttestationWorkflow, CandidateAttestationVerified: true,
		CandidateArtifactName: releaseCandidateProviderAsset("windows", "amd64"),
		RunnerOS:              "windows", RunnerArch: "amd64", ProviderVersion: version,
		ProviderBinarySHA256: strings.Repeat("e", 64), WeChatVersion: entry.Version, WeChatBuild: entry.Build,
		TargetExecutableSHA256: entry.ExecutableSHA256, BinaryFingerprintStatus: "verified", BinarySigningStatus: "verified",
		BinarySignerSHA256: entry.BinarySignerSHA256, BinaryProductIdentity: entry.ProductIdentity,
		ProcessArchitecture: entry.ProcessArchitecture, ProcessArchitectureStatus: "verified_running_process",
		CompatibilityRegistryStatus: "registered_supported", ConfigCipherRouteStatus: windowsroute.ConfigCipherSucceeded,
		WindowsRouteEvidence: []string{"registry_candidate_entry", "registry_exact_match"},
		RouteSelected:        "windows_config_cipher", TargetBindingStatus: "path_verified",
		ResultCode: "complete", DatabaseCoverageStatus: "complete", ValidatedCipherProfiles: []string{defaultProfileID},
	}
	root := t.TempDir()
	digest, payload, path := writeReleaseFixtureArtifact(t, root, artifact)
	target := releasePromotionTarget{
		Platform: "windows", Architecture: "amd64", ProviderArtifactName: artifact.CandidateArtifactName,
		ProviderSHA256: artifact.ProviderBinarySHA256, EvidenceSHA256: []string{digest},
	}
	promotionPath := writeReleaseFixturePromotion(t, root, fixturePromotion(target))
	windowsCompatibilityRegistry = []windowsCompatibilityEntry{entry}
	darwinCompatibilityRegistry = nil
	if err := validateReleaseEvidenceArtifacts(root, promotionPath, "windows", "amd64"); err != nil {
		t.Fatalf("externally promoted release evidence was rejected: %v", err)
	}
	if err := os.WriteFile(path, append(payload, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateReleaseEvidenceArtifacts(root, promotionPath, "windows", "amd64"); err == nil {
		t.Fatal("release gate accepted an artifact whose content no longer matched its digest")
	}

	variants := []struct {
		name   string
		mutate func(*releaseEvidenceArtifact)
	}{
		{name: "runner architecture", mutate: func(value *releaseEvidenceArtifact) { value.RunnerArch = "arm64" }},
		{name: "provider version", mutate: func(value *releaseEvidenceArtifact) { value.ProviderVersion = "different" }},
		{name: "provider candidate", mutate: func(value *releaseEvidenceArtifact) { value.ProviderBinarySHA256 = strings.Repeat("f", 64) }},
		{name: "source commit", mutate: func(value *releaseEvidenceArtifact) { value.CandidateSourceCommit = strings.Repeat("b", 40) }},
		{name: "workflow run", mutate: func(value *releaseEvidenceArtifact) { value.CandidateWorkflowRunID = "54321" }},
		{name: "attestation", mutate: func(value *releaseEvidenceArtifact) { value.CandidateAttestationVerified = false }},
		{name: "route", mutate: func(value *releaseEvidenceArtifact) { value.RouteSelected = "windows_memory_fallback" }},
		{name: "config status", mutate: func(value *releaseEvidenceArtifact) { value.ConfigCipherRouteStatus = windowsroute.ConfigCipherPartial }},
		{name: "extra profile", mutate: func(value *releaseEvidenceArtifact) {
			value.ValidatedCipherProfiles = append(value.ValidatedCipherProfiles, "unexpected-profile")
		}},
	}
	for _, test := range variants {
		t.Run(test.name, func(t *testing.T) {
			value := artifact
			value.ValidatedCipherProfiles = append([]string(nil), artifact.ValidatedCipherProfiles...)
			test.mutate(&value)
			variantDigest, _, _ := writeReleaseFixtureArtifact(t, root, value)
			variantTarget := target
			variantTarget.EvidenceSHA256 = []string{variantDigest}
			variantPromotion := fixturePromotion(variantTarget)
			variantPromotionPath := writeReleaseFixturePromotion(t, root, variantPromotion)
			if err := validateReleaseEvidenceArtifacts(root, variantPromotionPath, "windows", "amd64"); err == nil {
				t.Fatalf("release gate accepted mismatched %s evidence", test.name)
			}
		})
	}
	if err := validateReleaseEvidenceArtifacts(root, filepath.Join(root, "missing.json"), "windows", "amd64"); err == nil {
		t.Fatal("release gate accepted evidence without an external promotion manifest")
	}
}

func TestWindowsReviewedNoStructureEvidenceRequiresFallbackRoute(t *testing.T) {
	previousWindows := windowsCompatibilityRegistry
	previousDarwin := darwinCompatibilityRegistry
	t.Cleanup(func() {
		windowsCompatibilityRegistry = previousWindows
		darwinCompatibilityRegistry = previousDarwin
	})
	evidence := completeWindowsRouteEvidence()
	entry := fixtureWindowsRegistryEntry(evidence)
	entry.ConfigCipherSupportState = "reviewed_no_structure"
	entry.Recipe = windowsConfigCipherRecipe{}
	windowsCompatibilityRegistry = []windowsCompatibilityEntry{entry}
	darwinCompatibilityRegistry = nil
	projections := releaseEvidenceRegistryEntries("windows", "amd64")
	if len(projections) != 1 ||
		projections[0].RequiredConfigCipherRouteStatus != windowsroute.ConfigCipherReviewedNoStructure ||
		len(projections[0].AllowedRoutes) != 1 || projections[0].AllowedRoutes[0] != "windows_memory_fallback" {
		t.Fatalf("reviewed-no-structure entry projected a false Config.Cipher success route: %#v", projections)
	}
}

func TestDarwinPromotionBindsProviderHelperAndRoute(t *testing.T) {
	previousWindows := windowsCompatibilityRegistry
	previousDarwin := darwinCompatibilityRegistry
	t.Cleanup(func() {
		windowsCompatibilityRegistry = previousWindows
		darwinCompatibilityRegistry = previousDarwin
	})
	evidence := completeDarwinRouteEvidence()
	entry := darwinCompatibilityEntry{
		Version: evidence.Version, Build: evidence.Build, ExecutableSHA256: evidence.ExecutableSHA256,
		SigningTeamID: evidence.SigningTeamID, DesignatedRequirementSHA256: evidence.DesignatedRequirementSHA256,
		ProcessArchitecture: evidence.ProcessArchitecture, MacOSMajorMinor: evidence.MacOSMajorMinor,
		RouteSupportState: "supported", ValidatedCipherProfiles: []string{defaultProfileID},
	}
	artifact := releaseEvidenceArtifact{
		SchemaVersion: 1, CandidateSourceCommit: strings.Repeat("a", 40), CandidateWorkflowRunID: "12345",
		CandidateAttestationWorkflow: releaseCandidateAttestationWorkflow, CandidateAttestationVerified: true,
		CandidateArtifactName: releaseCandidateProviderAsset("darwin", "arm64"),
		RunnerOS:              "darwin", RunnerArch: "arm64", ProviderVersion: version,
		ProviderBinarySHA256: strings.Repeat("e", 64), ProviderHelperSHA256: strings.Repeat("f", 64),
		WeChatVersion: entry.Version, WeChatBuild: entry.Build, TargetExecutableSHA256: entry.ExecutableSHA256,
		BinaryFingerprintStatus: "verified", BinarySigningStatus: "verified", SigningTeamID: entry.SigningTeamID,
		DesignatedRequirementSHA256: entry.DesignatedRequirementSHA256, ProcessArchitecture: entry.ProcessArchitecture,
		ProcessArchitectureStatus: "verified_running_process", CompatibilityRegistryStatus: "registered_supported",
		StandardRouteStatus:   darwinroute.StandardEligibleRegistry,
		StandardRouteEvidence: []string{"registry_candidate_entry", "registry_exact_match"},
		RouteSelected:         darwinDynamicRouteID("arm64", ""), TargetBindingStatus: "path_verified",
		ResultCode: "complete", DatabaseCoverageStatus: "complete", ValidatedCipherProfiles: []string{defaultProfileID},
	}
	root := t.TempDir()
	digest, _, _ := writeReleaseFixtureArtifact(t, root, artifact)
	target := releasePromotionTarget{
		Platform: "darwin", Architecture: "arm64", ProviderArtifactName: artifact.CandidateArtifactName,
		ProviderSHA256:     artifact.ProviderBinarySHA256,
		HelperArtifactName: releaseCandidateHelperAsset("darwin", "arm64"), HelperSHA256: artifact.ProviderHelperSHA256,
		EvidenceSHA256: []string{digest},
	}
	promotionPath := writeReleaseFixturePromotion(t, root, fixturePromotion(target))
	windowsCompatibilityRegistry = nil
	darwinCompatibilityRegistry = []darwinCompatibilityEntry{entry}
	if err := validateReleaseEvidenceArtifacts(root, promotionPath, "darwin", "arm64"); err != nil {
		t.Fatalf("Darwin Provider/helper promotion was rejected: %v", err)
	}
	target.HelperSHA256 = strings.Repeat("0", 64)
	promotionPath = writeReleaseFixturePromotion(t, root, fixturePromotion(target))
	if err := validateReleaseEvidenceArtifacts(root, promotionPath, "darwin", "arm64"); err == nil {
		t.Fatal("Darwin promotion accepted a helper digest different from the live-tested candidate set")
	}
}

func TestRuntimeRoleBindsHelperWatchdogToExecutable(t *testing.T) {
	previous := processArguments
	t.Cleanup(func() { processArguments = previous })

	tests := []struct {
		name      string
		arguments []string
		want      string
	}{
		{name: "provider watchdog", arguments: []string{"v-local-key-provider", "internal-hook-watchdog"}, want: "provider"},
		{name: "helper watchdog", arguments: []string{"v-local-key-provider-helper", "internal-hook-watchdog"}, want: "helper"},
		{name: "helper watchdog exe", arguments: []string{"v-local-key-provider-helper.exe", "internal-hook-watchdog"}, want: "helper"},
		{name: "helper acquire", arguments: []string{"v-local-key-provider-helper", "helper-acquire"}, want: "helper"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			processArguments = func() []string { return append([]string(nil), test.arguments...) }
			if got := runtimeRole(); got != test.want {
				t.Fatalf("runtime role = %q, want %q", got, test.want)
			}
		})
	}
}

func TestCrashArtifactHardeningCanBeEnabled(t *testing.T) {
	if err := hardenSensitiveProcess(); err != nil {
		t.Fatalf("sensitive process hardening failed: %v", err)
	}
}

func TestSensitiveOutputBufferOverwritesSupersededBacking(t *testing.T) {
	buffer := sensitiveOutputBuffer{limit: 64}
	if _, err := buffer.Write([]byte("phase5-secret")); err != nil {
		t.Fatal(err)
	}
	oldBacking := buffer.Bytes()
	if _, err := buffer.Write([]byte("-provider-output-that-forces-a-secure-growth")); err != nil {
		t.Fatal(err)
	}
	for index, value := range oldBacking {
		if value != 0 {
			t.Fatalf("superseded sensitive backing buffer was not overwritten at byte %d", index)
		}
	}
	currentBacking := buffer.Bytes()
	buffer.Clear()
	if buffer.Len() != 0 || buffer.over {
		t.Fatal("sensitive output buffer retained state after Clear")
	}
	for index, value := range currentBacking {
		if value != 0 {
			t.Fatalf("sensitive output backing buffer was not overwritten at byte %d", index)
		}
	}
}

// linkerStampedMainVars 收集 cmd/v-local-key-provider/main.go 中所有可被 -X 注入的
// 包级变量。-X 只对 string 类型的包级变量生效，其余类型会被链接器静默忽略。
func linkerStampedMainVars(t *testing.T) map[string]bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join("cmd", "v-local-key-provider", "main.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]bool{}
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.VAR {
			continue
		}
		for _, specification := range general.Specs {
			value, ok := specification.(*ast.ValueSpec)
			if !ok {
				continue
			}
			stringTyped := false
			if identifier, ok := value.Type.(*ast.Ident); ok && identifier.Name == "string" {
				stringTyped = true
			}
			for _, expression := range value.Values {
				if literal, ok := expression.(*ast.BasicLit); ok && literal.Kind == token.STRING {
					stringTyped = true
				}
			}
			if !stringTyped {
				continue
			}
			for _, name := range value.Names {
				values[name.Name] = true
			}
		}
	}
	return values
}

// Go 的链接器对不存在、拼错或非 string 的 -X 目标是静默忽略的：ldflags 一旦失效，
// 签名 release 二进制会带着默认的 development 模式出厂，而 releaseBuild() 为 false
// 时所有运行时信任校验都直接放行。既有契约只单向检查了构建脚本里包含这些字符串，
// 因此这里反向确认每个 -X main.<name> 都确实对应一个可注入的包级变量，并且真的被
// 传进 provider.Run。
func TestReleaseLdflagsTargetsResolveToStampableMainVars(t *testing.T) {
	declared := linkerStampedMainVars(t)
	payload, err := os.ReadFile(filepath.Join("cmd", "v-local-key-provider", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(payload)
	pattern := regexp.MustCompile(`-X main\.([A-Za-z_][A-Za-z0-9_]*)=`)
	seen := map[string]bool{}
	for _, script := range []string{
		filepath.Join("scripts", "build.ps1"),
		filepath.Join("scripts", "build-macos.sh"),
	} {
		text, readErr := os.ReadFile(script)
		if readErr != nil {
			t.Fatal(readErr)
		}
		matches := pattern.FindAllStringSubmatch(string(text), -1)
		if len(matches) == 0 {
			t.Fatalf("%s no longer stamps any build identity", script)
		}
		for _, match := range matches {
			name := match[1]
			seen[name] = true
			if !declared[name] {
				t.Errorf("%s stamps -X main.%s, but cmd/v-local-key-provider/main.go declares no stampable string variable of that name; the linker would ignore it silently", script, name)
				continue
			}
			if !strings.Contains(source, name) {
				t.Errorf("main.%s is stamped but never referenced", name)
			}
		}
	}
	for _, required := range []string{"buildMode", "releasePromotionSHA256"} {
		if !seen[required] {
			t.Errorf("release builds no longer stamp main.%s", required)
		}
	}
	// 被注入的身份必须真的进入 provider.Run，否则包级 buildMode 仍是默认值。
	run := source[strings.Index(source, "provider.Run("):]
	for name := range seen {
		if !strings.Contains(run, name) {
			t.Errorf("main.%s is stamped but not forwarded into provider.Run", name)
		}
	}
}

func TestUnknownBuildModeIsRejectedInsteadOfTreatedAsDevelopment(t *testing.T) {
	for _, known := range []string{"development", "candidate", "release", "RELEASE", " release "} {
		if !knownBuildMode(known) {
			t.Errorf("已知构建身份 %q 被拒绝", known)
		}
	}
	// 运行时信任校验的宽松分支是 `if !releaseBuild()`，未知取值不能落进去。
	for _, unknown := range []string{"", "   ", "dev", "prod", "release-candidate"} {
		if knownBuildMode(unknown) {
			t.Errorf("未知构建身份 %q 被当成合法取值", unknown)
		}
	}
}
