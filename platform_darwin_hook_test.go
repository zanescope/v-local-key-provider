//go:build darwin && cgo

package main

import (
	"strings"
	"testing"
)

func TestDarwinVersionSupportSelectsMultipleLayouts(t *testing.T) {
	checks := map[string]string{
		"4.1.10": "commoncrypto_dynamic",
		"4.1.11": "commoncrypto_dynamic",
		"4.0.9":  "static_then_commoncrypto",
		"3.9.2":  "static_memory",
		"":       "unknown",
	}
	for version, want := range checks {
		if got := darwinVersionSupport(version); got != want {
			t.Fatalf("version %q support = %q, want %q", version, got, want)
		}
	}
}

func TestDarwinHookPythonSourceUsesArchitectureRegisters(t *testing.T) {
	x86 := darwinHookPythonSource("amd64", "/tmp/capture")
	if !strings.Contains(x86, `"rcx"`) || !strings.Contains(x86, `"r8"`) ||
		!strings.Contains(x86, `"r9"`) || !strings.Contains(x86, `stack + 8`) {
		t.Fatalf("x86_64 Python hook does not use ABI-correct registers:\n%s", x86)
	}
	arm := darwinHookPythonSource("arm64", "/tmp/capture")
	if !strings.Contains(arm, `"x3"`) || !strings.Contains(arm, `"x4"`) || !strings.Contains(arm, `"x5"`) || !strings.Contains(arm, `"x6"`) {
		t.Fatalf("arm64 Python hook does not use expected registers:\n%s", arm)
	}
}

func TestParseDarwinHookPythonKeys(t *testing.T) {
	output := "VLOCALHOOKS=3\nVLOCALKEY32=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n"
	captures := parseDarwinHookPythonKeys(output)
	if len(captures) != 1 || len(captures[0]) != 32 || captures[0][0] != 0 || captures[0][31] != 0x1f {
		t.Fatalf("unexpected Python hook capture: %#v", captures)
	}
	if got := darwinHookPythonCount(output); got != 3 {
		t.Fatalf("Python hook count = %d, want 3", got)
	}
}

func TestDarwinWaitForCommandsArmHookBeforeAttach(t *testing.T) {
	commands := darwinHookCommandFileWithPython(true, "/Applications/WeChat.app/Contents/MacOS/WeChat", "/tmp/hook.py")
	target := strings.Index(commands, "target create")
	load := strings.Index(commands, "command script import")
	attach := strings.Index(commands, "process attach")
	if target < 0 || load < target || attach < load {
		t.Fatalf("wait-for commands do not pre-arm hook before attach:\n%s", commands)
	}
}

func TestDarwinWaitForCommandsSelectWeixinBundle(t *testing.T) {
	commands := darwinHookCommandFileWithPython(true, "/Applications/Weixin.app/Contents/MacOS/Weixin", "/tmp/hook.py")
	if !strings.Contains(commands, "process attach --name Weixin --waitfor") {
		t.Fatalf("wait-for commands should follow the Weixin bundle name:\n%s", commands)
	}
}

func TestDarwinLLDBBreakpointCountIgnoresPendingLocations(t *testing.T) {
	output := "Breakpoint 1: no locations (pending).\nBreakpoint 2: where = libcommoncrypto.dylib`CCCryptorCreate\n"
	if got := darwinLLDBBreakpointCount(output); got != 1 {
		t.Fatalf("breakpoint count = %d, want 1", got)
	}
}
