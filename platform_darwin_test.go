//go:build darwin && cgo

package main

import "testing"

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
