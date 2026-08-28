package darwin

import (
	"strings"
	"testing"
)

func TestHookPythonSourcePinsArchitectureSpecificArguments(t *testing.T) {
	x86 := HookPythonSource("amd64")
	arm := HookPythonSource("arm64")
	for _, fragment := range []string{`_register(frame, "r9")`, `_read_uint(process, stack + 8)`, `_read_uint(process, stack + 24)`} {
		if !strings.Contains(x86, fragment) {
			t.Fatalf("amd64 hook source missing %q", fragment)
		}
	}
	if !strings.Contains(arm, `_register(frame, "x5")`) || !strings.Contains(arm, `_register(frame, "x6")`) {
		t.Fatal("arm64 hook source lost CommonCrypto argument mapping")
	}
	for _, fragment := range []string{"GetNumResolvedLocations", "GetNumLocations", "_breakpoint_is_resolved", "vlocal-report-hooks"} {
		if !strings.Contains(arm, fragment) {
			t.Fatalf("resolved-breakpoint reporting is missing %q", fragment)
		}
	}
}

func TestHookOutputParsersStayStrictAndDeduplicatePIDs(t *testing.T) {
	key := strings.Repeat("ab", 32)
	output := "VLOCALHOOKS=1\nVLOCALHOOKS=4\nVLOCALPID=42\nVLOCALPID=42\nVLOCALKEY32=" + key + "\n" +
		"VLOCALPBKDF=2,3,256000,4,32,01020304,aabbccdd\n"
	if HookPythonCount(output) != 4 || len(ParseHookPythonKeys(output)) != 1 || len(ParsePBKDFCaptures(output)) != 1 {
		t.Fatalf("hook output was not parsed: %q", output)
	}
	pids := CapturedPIDs(output)
	if len(pids) != 1 || pids[0] != 42 || !HasKeyOrPBKDFCapture(output) {
		t.Fatalf("capture identity markers changed: pids=%v", pids)
	}
}

func TestHookCommandAndBreakpointParsing(t *testing.T) {
	commands := HookCommandFileWithPython(true, "/Applications/WeChat.app/Contents/MacOS/WeChat", "/tmp/hook.py", "WeChat")
	if !strings.Contains(commands, "process attach --name WeChat --waitfor") || !strings.Contains(commands, "vlocal-report-hooks") {
		t.Fatalf("unexpected LLDB commands: %s", commands)
	}
	if LLDBBreakpointCount("Breakpoint 1: 2 locations.\nBreakpoint 2: no locations (pending).\n") != 1 {
		t.Fatal("unresolved LLDB breakpoint was counted as installed")
	}
}

func TestWaitForCommandSelectsWeixinBundle(t *testing.T) {
	executable := "/Applications/Weixin.app/Contents/MacOS/Weixin"
	commands := HookCommandFileWithPython(true, executable, "/tmp/hook.py", WaitForProcessName(executable))
	if !strings.Contains(commands, "process attach --name Weixin --waitfor") {
		t.Fatalf("wait-for commands did not select Weixin: %s", commands)
	}
}
