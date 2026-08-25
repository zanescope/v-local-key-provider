//go:build darwin && cgo

package provider

import (
	"crypto/aes"
	"testing"
)

func TestParseDarwinProcessListFiltersHelpers(t *testing.T) {
	processes := parseDarwinProcessList("" +
		"101 /Applications/WeChat.app/Contents/MacOS/WeChat /Applications/WeChat.app/Contents/MacOS/WeChat\n" +
		"102 WeChatAppEx /Applications/WeChat.app/Contents/Frameworks/WeChatAppEx.app/Contents/MacOS/WeChatAppEx\n" +
		"103 WeChat Helper /Applications/WeChat.app/Contents/Frameworks/WeChat Helper.app/Contents/MacOS/WeChat Helper\n" +
		"104 Weixin /Applications/Weixin.app/Contents/MacOS/Weixin\n")
	if len(processes) != 2 || processes[0].pid != 101 || processes[1].pid != 104 {
		t.Fatalf("unexpected Darwin process selection: %#v", processes)
	}
}

func TestDarwinProcessMatcherAcceptsMainBundleOnly(t *testing.T) {
	if !isDarwinWeChatProcess("WeChat", "/Applications/WeChat.app/Contents/MacOS/WeChat") {
		t.Fatal("main WeChat process should match")
	}
	if isDarwinWeChatProcess("WeChatAppEx", "/Applications/WeChat.app/Contents/MacOS/WeChatAppEx") {
		t.Fatal("WeChatAppEx helper should not match")
	}
}

func TestDarwinProcessExecutablePreservesSpacesInBundlePathFallback(t *testing.T) {
	process := darwinProcess{
		command: "/Users/example/My Applications/WeChat.app/Contents/MacOS/WeChat --flag",
	}
	want := "/Users/example/My Applications/WeChat.app/Contents/MacOS/WeChat"
	if got := darwinProcessExecutable(process); got != want {
		t.Fatalf("Darwin process executable = %q, want %q", got, want)
	}
}

func TestDarwinPipelineDoesNotStopAfterDatabaseWhenMediaIsStillMissing(t *testing.T) {
	const mediaKey = "0123456789abcdef"
	block, err := aes.NewCipher([]byte(mediaKey))
	if err != nil {
		t.Fatal(err)
	}
	plain := [16]byte{0xff, 0xd8, 0xff}
	var encrypted [16]byte
	block.Encrypt(encrypted[:], plain[:])
	evidence := mediaEvidence{V2Blocks: [][16]byte{encrypted}, XORCandidates: map[byte]int{0x2a: 1}}
	collector := newCandidateCollector(databaseTargets{}, evidence, unlimitedBudget())
	pipeline := darwinAcquisitionPipeline{
		collector: collector, scanMedia: evidence, needDatabaseScan: false, needMediaScan: true,
	}
	if pipeline.satisfied() {
		t.Fatal("pipeline stopped with requested media evidence still unresolved")
	}
	collector.ScanMediaPatterns([]byte(mediaKey))
	if !pipeline.satisfied() {
		t.Fatal("pipeline did not stop after every requested scope was resolved")
	}
}

func TestParseLaunchctlProcessList(t *testing.T) {
	output := `gui/501/application.com.tencent.xinWeChat.22815108.22815116 = {
	state = running
	bundle id = com.tencent.xinWeChat

	program = /Applications/WeChat.app/Contents/MacOS/WeChat
	arguments = {
		/Applications/WeChat.app/Contents/MacOS/WeChat
	}
	pid = 73508
	dynamic endpoints = {
		"endpoint" = {
			port = 0x11fdc3
		}
	}
}`
	processes := parseLaunchctlProcessList(output)
	if len(processes) != 1 || processes[0].pid != 73508 || processes[0].name != "WeChat" || processes[0].command != "/Applications/WeChat.app/Contents/MacOS/WeChat" {
		t.Fatalf("unexpected launchctl process: %#v", processes)
	}
}

func TestParseLaunchctlProcessRefsFiltersHelpers(t *testing.T) {
	output := `services = {
	   73508      -  application.com.tencent.xinWeChat.22815108.22815116
	   73514      -  com.apple.xpc.launchd.unmanaged.WeChatAppEx.73514
	   73520      -  application.com.tencent.xinWeChat.22815108.22815117
}`
	refs := parseLaunchctlProcessRefs(output)
	if len(refs) != 2 || refs[0].pid != 73508 || refs[1].label != "application.com.tencent.xinWeChat.22815108.22815117" {
		t.Fatalf("unexpected launchctl refs: %#v", refs)
	}
}
