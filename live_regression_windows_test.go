//go:build live_regression && windows

package provider

import (
	"os"
	"strings"
	"testing"
)

func liveExpectedBoolean(t *testing.T, name string) bool {
	t.Helper()
	switch strings.ToLower(liveRequiredEnvironment(t, name)) {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		t.Fatalf("live regression requires %s to be a boolean", name)
		return false
	}
}

func TestPhase4WindowsLiveAcquisition(t *testing.T) {
	processesBefore, err := targetProcesses()
	if err != nil {
		t.Fatalf("cannot inventory Windows target processes before acquisition: %v", err)
	}
	if len(processesBefore) == 0 {
		t.Fatal("Phase 4 live regression requires a running Weixin/WeChat process")
	}
	instanceBefore := platformProcessInstanceID()
	result := runLiveAcquisition(t)
	defer clearLiveResponse(&result)
	assertLiveAcquisition(t, result)

	processesAfter, err := targetProcesses()
	if err != nil {
		t.Fatalf("cannot inventory Windows target processes after acquisition: %v", err)
	}
	if liveExpectedBoolean(t, "V_LOCAL_KEY_PROVIDER_LIVE_EXPECT_PROCESS_STABLE") &&
		(instanceBefore != platformProcessInstanceID() || len(processesBefore) != len(processesAfter)) {
		t.Fatalf("target process inventory changed during the default no-termination workflow: before=%d after=%d",
			len(processesBefore), len(processesAfter))
	}

	diag := result.Diagnostics
	expectedRegistry := liveRequiredEnvironment(t, "V_LOCAL_KEY_PROVIDER_LIVE_EXPECT_REGISTRY_STATUS")
	expectedConfig := liveRequiredEnvironment(t, "V_LOCAL_KEY_PROVIDER_LIVE_EXPECT_CONFIG_CIPHER_STATUS")
	expectedRoute := liveRequiredEnvironment(t, "V_LOCAL_KEY_PROVIDER_LIVE_EXPECT_ROUTE")
	if diag.CompatibilityRegistryStatus != expectedRegistry || diag.ConfigCipherRouteStatus != expectedConfig {
		t.Fatalf("Windows route evidence=%s/%s, want %s/%s",
			diag.CompatibilityRegistryStatus, diag.ConfigCipherRouteStatus, expectedRegistry, expectedConfig)
	}
	if diag.RouteSelected != expectedRoute {
		t.Fatalf("Windows route=%q, want %q", diag.RouteSelected, expectedRoute)
	}
	if diag.ProcessArchitectureStatus != windowsArchitectureVerified ||
		diag.ProcessArchitecture != liveRequiredEnvironment(t, "V_LOCAL_KEY_PROVIDER_LIVE_EXPECT_PROCESS_ARCH") {
		t.Fatalf("Windows target process architecture=%s/%s is not the expected verified ABI",
			diag.ProcessArchitecture, diag.ProcessArchitectureStatus)
	}
	if diag.BinaryFingerprintStatus != windowsFingerprintVerified || !validWindowsSHA256(diag.ExecutableSHA256) {
		t.Fatal("Windows live route lacks a verified target executable fingerprint")
	}
	if diag.BinarySigningStatus != windowsSigningVerified || !validWindowsSHA256(diag.BinarySignerSHA256) {
		t.Fatal("Windows live route lacks a verified Authenticode signer fingerprint")
	}
	if diag.BinaryProductIdentity != "weixin.exe" && diag.BinaryProductIdentity != "wechat.exe" {
		t.Fatal("Windows live route lacks a bounded target product identity")
	}
	if expected := strings.TrimSpace(os.Getenv("V_LOCAL_KEY_PROVIDER_LIVE_EXPECT_TARGET_BINDING")); expected != "" &&
		diag.TargetBindingStatus != expected {
		t.Fatalf("Windows target binding=%q, want %q", diag.TargetBindingStatus, expected)
	}
	if diag.ProcessCount != diag.TargetBoundProcessCount+diag.OtherAccountProcessCount+diag.UnknownAccountProcessCount ||
		diag.SelectedProcessCount != diag.TargetBoundProcessCount+diag.UnknownAccountProcessCount ||
		diag.OpenedProcessCount+diag.AccessDeniedCount != diag.SelectedProcessCount {
		t.Fatal("Windows live process/account/access counts are internally inconsistent")
	}
	if diag.TargetBindingStatus == "mismatch" &&
		(diag.OtherAccountProcessCount == 0 || diag.TargetBoundProcessCount != 0 || diag.UnknownAccountProcessCount != 0) {
		t.Fatal("Windows live mismatch is not backed by exclusive other-account process evidence")
	}
	if len(result.DatabaseKeys) > 0 {
		if result.DatabaseCredential == nil || len(result.DatabaseCredential.Roots) != 0 ||
			len(result.DatabaseCredential.Overrides) != len(result.DatabaseKeys) {
			t.Fatal("Windows live keys are not represented by per-database credential overrides")
		}
		for _, override := range result.DatabaseCredential.Overrides {
			if len(override.ProcessInstanceIDs) == 0 {
				t.Fatal("Windows live credential lost process-instance provenance")
			}
			for _, instanceID := range override.ProcessInstanceIDs {
				digest := strings.TrimPrefix(instanceID, "windows-process:")
				if !strings.HasPrefix(instanceID, "windows-process:") || !validWindowsSHA256(digest) {
					t.Fatal("Windows live credential contains invalid process-instance provenance")
				}
			}
		}
	}

	switch expectedRoute {
	case "windows_config_cipher":
		if expectedRegistry != windowsRegistryRegisteredSupported ||
			(expectedConfig != windowsConfigCipherPartial && expectedConfig != windowsConfigCipherSucceeded &&
				expectedConfig != windowsConfigCipherNoStructure && expectedConfig != windowsConfigCipherInvalidStructure &&
				expectedConfig != windowsConfigCipherNoVerifiedCandidate) {
			t.Fatal("Config.Cipher live route lacks exact registered route state")
		}
		if !containsLiveEvidence(diag.WindowsRouteEvidence, "registry_exact_match") ||
			!containsLiveEvidence(diag.WindowsRouteEvidence, "registry_candidate_entry") {
			t.Fatal("Config.Cipher live route lacks an exact candidate-registry match")
		}
	case "windows_memory_fallback":
		if !diag.StaticScanFallback || len(diag.FallbackStageCounts) == 0 || diag.PerProcessCollectorCount == 0 {
			t.Fatal("Windows fallback route lacks bounded stage or process-isolation evidence")
		}
	default:
		t.Fatalf("Phase 4 live regression does not accept unknown route %q", expectedRoute)
	}
	writeLiveEvidence(t, result)
}

func containsLiveEvidence(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
