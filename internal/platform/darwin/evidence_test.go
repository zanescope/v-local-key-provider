package darwin

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProcessExecutablePreservesSpacesInBundleFallback(t *testing.T) {
	collector := NewEvidenceCollector(EvidenceRuntime{})
	process := Process{Command: "/Users/example/My Applications/WeChat.app/Contents/MacOS/WeChat --flag"}
	want := "/Users/example/My Applications/WeChat.app/Contents/MacOS/WeChat"
	if got := collector.ProcessExecutable(process); got != want {
		t.Fatalf("process executable = %q, want %q", got, want)
	}
}

func TestEvidenceCollectorOwnsDarwinEvidencePolicy(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "WeChat.app", "Contents", "MacOS", "WeChat")
	if err := os.MkdirAll(filepath.Dir(executable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	runOutput := func(_ context.Context, path string, arguments []string, _ int) ([]byte, error) {
		switch path {
		case "/usr/libexec/PlistBuddy":
			if strings.Contains(arguments[1], "ShortVersion") {
				return []byte("4.1.11\n"), nil
			}
			return []byte("31100\n"), nil
		case "/bin/ps":
			return []byte("arm64\n"), nil
		case "/usr/bin/uname":
			return []byte("arm64\n"), nil
		case "/usr/bin/sw_vers":
			return []byte("15.6.1\n"), nil
		default:
			return nil, errors.New("unexpected command")
		}
	}
	runCombined := func(_ context.Context, _ string, arguments []string, _ int) ([]byte, error) {
		switch arguments[0] {
		case "--verify":
			return nil, nil
		case "-dv":
			return []byte("TeamIdentifier=TEAM123456\n"), nil
		case "-dr":
			return []byte("designated => identifier fixture and anchor apple\n"), nil
		default:
			return nil, errors.New("unexpected codesign arguments")
		}
	}
	collector := NewEvidenceCollector(EvidenceRuntime{
		RunOutput:             runOutput,
		RunCombinedOutput:     runCombined,
		ProcessExecutablePath: func(uint32) (string, error) { return executable, nil },
		ExecutableSHA256:      func(string) string { return strings.Repeat("a", 64) },
		PathIsLinkOrReparse:   func(string, fs.FileMode) (bool, error) { return false, nil },
	})
	evidence := collector.CollectEvidence(Process{PID: 42, Name: "WeChat"})
	if evidence.Version != "4.1.11" || evidence.Build != "31100" || evidence.MacOSMajorMinor != "15.6" {
		t.Fatalf("version evidence changed: %#v", evidence)
	}
	if evidence.ProcessArchitecture != "arm64" || evidence.ProcessArchitectureStatus != ArchitectureVerified ||
		evidence.ProcessTranslationStatus != "native" {
		t.Fatalf("architecture evidence changed: %#v", evidence)
	}
	if evidence.BinaryFingerprintStatus != FingerprintVerified || evidence.BinarySigningStatus != SigningVerified ||
		evidence.SigningTeamID != "TEAM123456" || !ValidSHA256(evidence.DesignatedRequirementSHA256) {
		t.Fatalf("binary trust evidence changed: %#v", evidence)
	}
}

func TestProcessInstanceIDFailsClosedWhenDiscoveryIsUnavailable(t *testing.T) {
	collector := NewEvidenceCollector(EvidenceRuntime{})
	if got := collector.ProcessInstanceID(nil); got != "darwin:process-list-unavailable" {
		t.Fatalf("process instance ID = %q", got)
	}
}
