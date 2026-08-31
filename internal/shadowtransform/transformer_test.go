package shadowtransform

import (
	"context"
	"runtime"
	"testing"
)

func TestSafeRelativeUsesHostIndependentManifestPaths(t *testing.T) {
	if !safeRelative("Contents/Frameworks/helper", false) || !safeRelative(".", true) {
		t.Fatalf("slash-delimited transformation path was rejected on %s", runtime.GOOS)
	}
	for _, value := range []string{"", "/absolute", "../escape", "a/../escape", `a\\escape`, "C:/escape", "file:stream"} {
		if safeRelative(value, false) {
			t.Errorf("unsafe transformation path %q was accepted", value)
		}
	}
}

func TestCappedOutputReportsOverflow(t *testing.T) {
	output := &cappedOutput{}
	payload := make([]byte, 32*1024+1)
	written, err := output.Write(payload)
	if err != nil || written != len(payload) || len(output.value) != 32*1024 || !output.overflow {
		t.Fatalf("written=%d retained=%d overflow=%v err=%v", written, len(output.value), output.overflow, err)
	}
}

func TestExecRunnerRejectsNilContextAndRelativeCommands(t *testing.T) {
	runner := ExecRunner{}
	if err := runner.Run(nil, "/usr/bin/true"); err == nil {
		t.Fatal("nil command context was accepted")
	}
	if _, err := runner.Output(nil, "/usr/bin/true"); err == nil {
		t.Fatal("nil query context was accepted")
	}
	if err := runner.Run(context.Background(), "true"); err == nil {
		t.Fatal("PATH-resolved command was accepted")
	}
	if _, err := runner.Output(context.Background(), "true"); err == nil {
		t.Fatal("PATH-resolved query was accepted")
	}
}
