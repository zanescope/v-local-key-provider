//go:build darwin && cgo

package provider

import (
	"encoding/hex"
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
	x86 := darwinHookPythonSource("amd64")
	if !strings.Contains(x86, `"rcx"`) || !strings.Contains(x86, `"r8"`) ||
		!strings.Contains(x86, `"r9"`) || !strings.Contains(x86, `stack + 8`) {
		t.Fatalf("x86_64 Python hook does not use ABI-correct registers:\n%s", x86)
	}
	arm := darwinHookPythonSource("arm64")
	if !strings.Contains(arm, `"x3"`) || !strings.Contains(arm, `"x4"`) || !strings.Contains(arm, `"x5"`) || !strings.Contains(arm, `"x6"`) {
		t.Fatalf("arm64 Python hook does not use expected registers:\n%s", arm)
	}
}

func TestDarwinHookPythonSourceCapturesPBKDFArgumentsWithoutSecretFile(t *testing.T) {
	source := darwinHookPythonSource("arm64")
	if !strings.Contains(source, "CCKeyDerivationPBKDF") || !strings.Contains(source, "VLOCALPBKDF=") || strings.Contains(source, "open(_capture_path") {
		t.Fatalf("PBKDF hook or in-memory capture is missing:\n%s", source)
	}
	output := "VLOCALPBKDF=2,3,256000,4,32,01020304,aabbccdd\n"
	captures := parseDarwinPBKDFCaptures(output)
	if len(captures) != 1 || captures[0].Rounds != 256000 || len(captures[0].Password) != 4 || captures[0].OutputLength != 32 {
		t.Fatalf("unexpected PBKDF capture: %#v", captures)
	}
}

func TestDarwinHookPythonSourceCountsOnlyResolvedBreakpoints(t *testing.T) {
	source := darwinHookPythonSource("arm64")
	for _, required := range []string{"GetNumResolvedLocations", "GetNumLocations", "_breakpoint_is_resolved", "vlocal-report-hooks"} {
		if !strings.Contains(source, required) {
			t.Fatalf("resolved-breakpoint reporting is missing %q:\n%s", required, source)
		}
	}
	if strings.Contains(source, "sum(1 for breakpoint in breakpoints if breakpoint.IsValid())") {
		t.Fatal("pending LLDB breakpoints are still reported as installed")
	}
}

func TestDarwinPassphraseCaptureRequiresCompleteKDFEvidenceAndTargetSalt(t *testing.T) {
	salt := strings.Repeat("ab", 16)
	targets := databaseTargets{Pages: []databasePage{{Salt: salt}}}
	valid := darwinPBKDFCapture{Algorithm: 2, PRF: 5, Rounds: v4KDFIterations, OutputLength: 32, Password: make([]byte, 32)}
	valid.Salt = make([]byte, 16)
	for index := range valid.Salt {
		valid.Salt[index] = 0xab
	}
	if !darwinPBKDFCaptureMatchesTargetSalt(valid, targets) {
		t.Fatal("complete target-bound KDF evidence was rejected")
	}
	invalidSalt := valid
	invalidSalt.Salt = append([]byte(nil), valid.Salt...)
	invalidSalt.Salt[0] ^= 0xff
	if darwinPBKDFCaptureMatchesTargetSalt(invalidSalt, targets) {
		t.Fatal("unrelated KDF salt was accepted as target evidence")
	}
}

func TestPhase3DarwinRoundsTwoPBKDFCaptureMapsRawKeyUsingXORSalt(t *testing.T) {
	keyHex := strings.Repeat("37", 32)
	saltHex := strings.Repeat("a4", 16)
	page := encryptedDatabasePage(t, keyHex, saltHex)
	page.Path = "message.db"
	targets := databaseTargets{
		BySalt: map[string][]string{saltHex: {page.Path}}, Pages: []databasePage{page}, Count: 1,
	}
	collector := newCandidateCollector(targets, mediaEvidence{})
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		t.Fatal(err)
	}
	for index := range salt {
		salt[index] ^= 0x3a
	}
	output := "VLOCALPBKDF=2,5,2,32,32," + keyHex + "," + hex.EncodeToString(salt) + "\n"
	if captures := consumeDarwinHookCaptures(output, collector); captures != 1 {
		t.Fatalf("capture count = %d, want 1", captures)
	}
	keys, ambiguous := collector.DatabaseKeys(targets)
	if ambiguous != 0 || keys[page.Path] != keyHex {
		t.Fatalf("rounds=2 PBKDF evidence was not mapped to the raw database key: keys=%v ambiguous=%d", keys, ambiguous)
	}
}

func TestPhase3DarwinUnrelatedPBKDFCaptureIsNotCountedAsUsed(t *testing.T) {
	targets := databaseTargets{Pages: []databasePage{{Salt: strings.Repeat("ab", 16)}}}
	collector := newCandidateCollector(targets, mediaEvidence{})
	output := "VLOCALPBKDF=2,3,1,4,16,01020304,aabbccdd\n"
	if captures := consumeDarwinHookCaptures(output, collector); captures != 0 {
		t.Fatalf("unvalidated PBKDF event was counted as an accepted capture: %d", captures)
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

func TestDarwinHookPythonCountRetainsResolvedStatusAfterPendingReport(t *testing.T) {
	output := "VLOCALHOOKS=0\nVLOCALHOOKS=3\nVLOCALHOOKS=1\n"
	if got := darwinHookPythonCount(output); got != 3 {
		t.Fatalf("resolved hook count = %d, want 3", got)
	}
}

func TestDarwinWaitForCommandsArmHookBeforeAttach(t *testing.T) {
	commands := darwinHookCommandFileWithPython(true, "/Applications/WeChat.app/Contents/MacOS/WeChat", "/tmp/hook.py")
	target := strings.Index(commands, "target create")
	load := strings.Index(commands, "command script import")
	attach := strings.Index(commands, "process attach")
	report := strings.Index(commands, "vlocal-report-hooks")
	resume := strings.Index(commands, "process continue")
	if target < 0 || load < target || attach < load || report < attach || resume < report {
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
