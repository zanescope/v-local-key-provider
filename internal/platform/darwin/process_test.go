package darwin

import (
	"strings"
	"testing"
)

func TestVersionSupportSelectsRegisteredLayouts(t *testing.T) {
	checks := map[string]string{
		"4.1.10":  "commoncrypto_dynamic",
		"4.0.9":   "static_then_commoncrypto",
		"3.9.2":   "static_memory",
		"invalid": "unknown",
		"":        "unknown",
	}
	for version, want := range checks {
		if got := VersionSupport(version); got != want {
			t.Fatalf("VersionSupport(%q) = %q, want %q", version, got, want)
		}
	}
}

func TestPrelaunchHookRequiresCompleteMachineEvidence(t *testing.T) {
	evidence := fixtureEvidence()
	if !PrelaunchHookEligible(evidence) {
		t.Fatal("complete prelaunch evidence was rejected")
	}
	evidence.DesignatedRequirementSHA256 = strings.Repeat("x", 63)
	if PrelaunchHookEligible(evidence) {
		t.Fatal("incomplete designated requirement evidence was accepted")
	}
}
