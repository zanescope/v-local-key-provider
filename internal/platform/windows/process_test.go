package windows

import (
	"strings"
	"testing"
)

func TestStableProcessInstanceRequiresStartPathArchitectureAndFingerprint(t *testing.T) {
	evidence := ProcessEvidence{
		Process: Process{PID: 42, ParentID: 7, Name: "Weixin.exe"},
		Path:    `C:\Program Files\Tencent\Weixin.exe`, Started: 12345, Architecture: "amd64",
		Binary: BinaryEvidence{
			ExecutableSHA256: strings.Repeat("a", 64), BinarySigningStatus: SigningVerified,
			BinarySignerSHA256: strings.Repeat("b", 64), ProductIdentity: "weixin.exe",
		},
	}
	first := StableProcessInstanceID(evidence)
	if !strings.HasPrefix(first, "windows-process:") || len(first) != len("windows-process:")+64 {
		t.Fatalf("stable process evidence did not produce an opaque instance ID: %q", first)
	}
	evidence.Started++
	if second := StableProcessInstanceID(evidence); second == first || second == "" {
		t.Fatalf("process restart did not change the process instance ID: first=%q second=%q", first, second)
	}
	evidence.Started = 0
	if id := StableProcessInstanceID(evidence); id != "" {
		t.Fatalf("PID-only process evidence produced an instance ID: %q", id)
	}
}

func TestOrderedProcessEvidencePrioritizesTargetThenUnknown(t *testing.T) {
	values := []ProcessEvidence{
		{Process: Process{PID: 1}, Binding: "unknown"},
		{Process: Process{PID: 2}, Binding: "target"},
		{Process: Process{PID: 3}, Binding: "other"},
		{Process: Process{PID: 4}, Binding: "unknown"},
	}
	ordered := OrderedProcessEvidence(values)
	if ordered[0].Process.PID != 2 || ordered[1].Process.PID != 1 ||
		ordered[2].Process.PID != 4 || ordered[3].Process.PID != 3 {
		t.Fatalf("binding-aware scan order is unstable: %+v", ordered)
	}
}
