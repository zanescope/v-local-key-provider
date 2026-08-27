package provider

// 这些 facade 测试固定 main package 与 internal/platform/darwin 的集成契约。

import (
	darwinroute "github.com/zanescope/v-local-key-provider/internal/platform/darwin"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPhase3DarwinSourceDoesNotInferTargetArchitectureFromProviderBuild(t *testing.T) {
	var combined strings.Builder
	for _, path := range []string{
		"internal/platform/darwin/evidence.go",
		"internal/platform/darwin/hook.go",
		"internal/platform/darwin/hook_protocol.go",
	} {
		payload, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		combined.Write(payload)
	}
	source := combined.String()
	for _, forbidden := range []string{"runtime.GOARCH", `exec.Command("/usr/bin/file", "-b"`, `exec.LookPath("lldb")`} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("Darwin target architecture still uses forbidden inference %q", forbidden)
		}
	}
	for _, required := range []string{`"-o", "arch="`, "GetTarget()", "GetTriple()", `"/usr/bin/codesign"`, "captureIdentityMatches"} {
		if !strings.Contains(source, required) {
			t.Fatalf("Darwin Phase 3 machine evidence is missing %q", required)
		}
	}
}

func TestPhase5DarwinSubprocessesUseCentralBoundedRunner(t *testing.T) {
	for _, path := range []string{
		"platform_darwin.go", "platform_helper_darwin.go", "runtime_trust_darwin.go",
		"internal/platform/darwin/process_discovery.go", "internal/platform/darwin/native_process_darwin.go",
	} {
		payload, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(payload), "exec.Command") {
			t.Fatalf("%s bypasses the central bounded Darwin command runner", path)
		}
	}
	commandSource, err := os.ReadFile("darwin_command.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"darwinCleanEnvironment()", "sensitiveOutputBuffer", "errDarwinCommandOutputLimit", "Setpgid", "SIGKILL",
	} {
		if !strings.Contains(string(commandSource), required) {
			t.Fatalf("central Darwin command runner is missing %q", required)
		}
	}
	launcherSource, err := os.ReadFile("daemon_launch_darwin.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(launcherSource), "os.Environ()") {
		t.Fatal("Darwin daemon helper still inherits the caller environment")
	}
	hookSource, err := os.ReadFile(filepath.Join("internal", "platform", "darwin", "hook_driver.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"driver.runtime.RunCommand(ctx, command)", "driver.cleanEnvironment()", "configureProcessGroup(command)",
		"internal-hook-watchdog", "hookOutputMax", "hookDiagnosticMax",
	} {
		if !strings.Contains(string(hookSource), required) {
			t.Fatalf("specialized LLDB lifecycle is missing %q", required)
		}
	}
}

func TestPhase3ProviderNeverExecutesASIPStateChange(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	internalPaths, err := filepath.Glob(filepath.Join("internal", "platform", "darwin", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	paths = append(paths, internalPaths...)
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel == nil {
				return true
			}
			packageName, packageOK := selector.X.(*ast.Ident)
			if !packageOK || packageName.Name != "exec" ||
				(selector.Sel.Name != "Command" && selector.Sel.Name != "CommandContext") {
				return true
			}
			csrutil := false
			stateChange := false
			for _, argument := range call.Args {
				literal, ok := argument.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				value, unquoteErr := strconv.Unquote(literal.Value)
				if unquoteErr != nil {
					continue
				}
				csrutil = csrutil || value == "csrutil" || value == "/usr/bin/csrutil"
				stateChange = stateChange || value == "disable" || value == "enable"
			}
			if csrutil && stateChange {
				t.Errorf("Provider attempted to own a user-operated SIP state change in %s", path)
			}
			return true
		})
	}
}

func completeDarwinRouteEvidence() darwinBinaryEvidence {
	return darwinBinaryEvidence{
		Version: "4.1.10", Build: "31012", ExecutableSHA256: strings.Repeat("a", 64), BinaryFingerprintStatus: darwinroute.FingerprintVerified,
		BinarySigningStatus: darwinroute.SigningVerified, SigningTeamID: "TEAM123456",
		DesignatedRequirementSHA256: strings.Repeat("b", 64), ProcessArchitecture: "arm64",
		ProcessArchitectureStatus: darwinroute.ArchitectureVerified, ProcessTranslationStatus: "native",
		MacOSVersion: "15.6.1", MacOSMajorMinor: "15.6",
	}
}

func TestPhase3ActualArchitectureParserRejectsUniversalBinaryDescriptions(t *testing.T) {
	checks := map[string]string{
		"arm64": "arm64", "ARM64E": "arm64", "x86_64": "amd64", "amd64": "amd64",
		"Mach-O universal binary with 2 architectures: [x86_64] [arm64]": "unknown",
		"": "unknown",
	}
	for input, want := range checks {
		if got := normalizeDarwinArchitecture(input); got != want {
			t.Fatalf("normalizeDarwinArchitecture(%q)=%q, want %q", input, got, want)
		}
	}
	if got := darwinTranslationStatus("x86_64", "arm64"); got != "translated" {
		t.Fatalf("Rosetta translation status=%q", got)
	}
	if got := darwinTranslationStatus("arm64", "arm64"); got != "native" {
		t.Fatalf("native translation status=%q", got)
	}
}

func TestPhase3CompatibilityRegistryRequiresAnExactEvidenceMatch(t *testing.T) {
	evidence := completeDarwinRouteEvidence()
	entry := darwinCompatibilityEntry{
		Version: evidence.Version, Build: evidence.Build, ExecutableSHA256: evidence.ExecutableSHA256, SigningTeamID: evidence.SigningTeamID,
		DesignatedRequirementSHA256: evidence.DesignatedRequirementSHA256, ProcessArchitecture: evidence.ProcessArchitecture,
		MacOSMajorMinor: evidence.MacOSMajorMinor, RouteSupportState: "supported",
		ValidatedCipherProfiles: []string{defaultProfileID},
	}
	decision := evaluateDarwinRoute(evidence, []darwinCompatibilityEntry{entry})
	if decision.CompatibilityRegistryStatus != darwinroute.RegistryRegisteredSupported || decision.StandardRouteStatus != darwinroute.StandardEligibleRegistry {
		t.Fatalf("exact registry evidence was not accepted: %#v", decision)
	}
	evidence.ExecutableSHA256 = strings.Repeat("c", 64)
	decision = evaluateDarwinRoute(evidence, []darwinCompatibilityEntry{entry})
	if decision.CompatibilityRegistryStatus != darwinroute.RegistryUnregistered || decision.StandardRouteStatus != darwinroute.StandardEligibleGeneric {
		t.Fatalf("a different fingerprint inherited registry support: %#v", decision)
	}
}

func TestPhase3UnregisteredBuildGetsOnlyTheGenericSymbolRoute(t *testing.T) {
	decision := evaluateDarwinRoute(completeDarwinRouteEvidence(), nil)
	if decision.CompatibilityRegistryStatus != darwinroute.RegistryUnregistered || decision.StandardRouteStatus != darwinroute.StandardEligibleGeneric ||
		!containsString(decision.Evidence, "generic_symbol_route_only") {
		t.Fatalf("unexpected unregistered route decision: %#v", decision)
	}
}

func TestPhase5ReleaseRejectsUnregisteredDarwinBuild(t *testing.T) {
	previous := buildMode
	buildMode = "release"
	t.Cleanup(func() { buildMode = previous })
	decision := evaluateDarwinRoute(completeDarwinRouteEvidence(), nil)
	if decision.CompatibilityRegistryStatus != darwinroute.RegistryUnregistered ||
		decision.StandardRouteStatus != darwinroute.StandardUnsupported || darwinStandardRouteEligible(decision) ||
		!containsString(decision.Evidence, "release_requires_registry_exact_match") {
		t.Fatalf("release accepted an unregistered Darwin build: %#v", decision)
	}
}

func TestPhase5DarwinReleaseRegistryRequiresPromotionDigest(t *testing.T) {
	previousMode, previousPromotion := buildMode, releasePromotionSHA256
	buildMode = "release"
	releasePromotionSHA256 = ""
	t.Cleanup(func() {
		buildMode = previousMode
		releasePromotionSHA256 = previousPromotion
	})
	evidence := completeDarwinRouteEvidence()
	entry := darwinCompatibilityEntry{
		Version: evidence.Version, Build: evidence.Build, ExecutableSHA256: evidence.ExecutableSHA256,
		SigningTeamID: evidence.SigningTeamID, DesignatedRequirementSHA256: evidence.DesignatedRequirementSHA256,
		ProcessArchitecture: evidence.ProcessArchitecture, MacOSMajorMinor: evidence.MacOSMajorMinor,
		RouteSupportState: "supported", ValidatedCipherProfiles: []string{defaultProfileID},
	}
	decision := evaluateDarwinRoute(evidence, []darwinCompatibilityEntry{entry})
	if decision.CompatibilityRegistryStatus != darwinroute.RegistryRegisteredRejected {
		t.Fatalf("release accepted an unpromoted Darwin candidate: %#v", decision)
	}
	releasePromotionSHA256 = strings.Repeat("d", 64)
	decision = evaluateDarwinRoute(evidence, []darwinCompatibilityEntry{entry})
	if decision.CompatibilityRegistryStatus != darwinroute.RegistryRegisteredSupported ||
		!containsString(decision.Evidence, "release_promotion_verified") ||
		!containsString(decision.Evidence, "real_device_evidence_present") {
		t.Fatalf("promoted Darwin release candidate was rejected: %#v", decision)
	}
}

func TestPhase3ProcessAccessFailureUsesVerifiedSIPEvidence(t *testing.T) {
	if got := darwinProcessAccessFailure("sip_enabled_verified"); got != "sip_enabled" {
		t.Fatalf("verified enabled SIP was not exposed to final routing: %q", got)
	}
	for _, posture := range []string{"not_evaluated", "sip_disabled_verified", "restoration_required"} {
		if got := darwinProcessAccessFailure(posture); got != "task_for_pid_denied" {
			t.Fatalf("posture %q was incorrectly promoted to an enabled-SIP failure: %q", posture, got)
		}
	}
}

func TestPhase3TrustedHelperDenialFeedsFinalRoutingBeforeFinalization(t *testing.T) {
	if got := darwinDeniedAccessError(true, "used", "sip_enabled_verified"); got != "sip_enabled" {
		t.Fatalf("trusted helper denial did not preserve verified SIP evidence: %q", got)
	}
	if got := darwinDeniedAccessError(false, "", "sip_enabled_verified"); got != "task_for_pid_denied" {
		t.Fatalf("ordinary denial was incorrectly promoted to SIP evidence: %q", got)
	}
	if got := darwinDeniedAccessError(true, "used", "not_evaluated"); got != "task_for_pid_denied" {
		t.Fatalf("unverified posture was incorrectly promoted to SIP evidence: %q", got)
	}
}

func TestPhase3SIPDisabledRouteHasAnIndependentStableID(t *testing.T) {
	if got := darwinDynamicRouteID("arm64", "sip_disabled_verified"); got != "darwin_arm64_sip_disabled" {
		t.Fatalf("SIP-disabled route ID = %q", got)
	}
	if got := darwinDynamicRouteID("amd64", "sip_enabled_verified"); got != "darwin_amd64_standard_dynamic" {
		t.Fatalf("standard route ID = %q", got)
	}
}

func TestPhase3InvalidSigningAndIncompleteEvidenceFailClosed(t *testing.T) {
	evidence := completeDarwinRouteEvidence()
	evidence.BinarySigningStatus = darwinroute.SigningInvalid
	decision := evaluateDarwinRoute(evidence, nil)
	if decision.CompatibilityRegistryStatus != darwinroute.RegistryUntrustedBinary || decision.StandardRouteStatus != darwinroute.StandardUnsupported {
		t.Fatalf("invalid signing was not rejected: %#v", decision)
	}
	evidence = completeDarwinRouteEvidence()
	evidence.ProcessArchitectureStatus = darwinroute.ArchitectureUnavailable
	decision = evaluateDarwinRoute(evidence, nil)
	if decision.CompatibilityRegistryStatus != darwinroute.RegistryNotEvaluated || decision.StandardRouteStatus != darwinroute.StandardNotEvaluated {
		t.Fatalf("incomplete architecture evidence was upgraded: %#v", decision)
	}
}

func TestPhase3SupportedRegistryEntryRequiresProfiles(t *testing.T) {
	evidence := completeDarwinRouteEvidence()
	entry := darwinCompatibilityEntry{
		Version: evidence.Version, Build: evidence.Build, ExecutableSHA256: evidence.ExecutableSHA256, SigningTeamID: evidence.SigningTeamID,
		DesignatedRequirementSHA256: evidence.DesignatedRequirementSHA256, ProcessArchitecture: evidence.ProcessArchitecture,
		MacOSMajorMinor: evidence.MacOSMajorMinor, RouteSupportState: "supported",
	}
	decision := evaluateDarwinRoute(evidence, []darwinCompatibilityEntry{entry})
	if decision.CompatibilityRegistryStatus != darwinroute.RegistryRegisteredRejected || decision.StandardRouteStatus != darwinroute.StandardUnsupported {
		t.Fatalf("profile-free registry support was accepted: %#v", decision)
	}
}

func TestPhase5DarwinRegistryRejectsUnsupportedRouteState(t *testing.T) {
	evidence := completeDarwinRouteEvidence()
	entry := darwinCompatibilityEntry{
		Version: evidence.Version, Build: evidence.Build, ExecutableSHA256: evidence.ExecutableSHA256,
		SigningTeamID: evidence.SigningTeamID, DesignatedRequirementSHA256: evidence.DesignatedRequirementSHA256,
		ProcessArchitecture: evidence.ProcessArchitecture, MacOSMajorMinor: evidence.MacOSMajorMinor,
		RouteSupportState: "candidate", ValidatedCipherProfiles: []string{defaultProfileID},
	}
	if darwinRegistryEntryEligible(entry) {
		t.Fatal("non-supported candidate route state was accepted")
	}
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
