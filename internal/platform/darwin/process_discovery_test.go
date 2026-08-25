package darwin

import "testing"

func TestParseProcessListFiltersHelpersAndDeduplicates(t *testing.T) {
	output := `101 /Applications/WeChat.app/Contents/MacOS/WeChat /Applications/WeChat.app/Contents/MacOS/WeChat
102 WeChatAppEx /Applications/WeChat.app/Contents/MacOS/WeChatAppEx
101 WeChat duplicate
104 微信 /Applications/微信.app/Contents/MacOS/微信
105 helper /Applications/WeChat.app/Contents/Frameworks/WeChat Helper`
	processes := ParseProcessList(output)
	if len(processes) != 2 || processes[0].PID != 101 || processes[1].PID != 104 {
		t.Fatalf("parsed processes = %+v", processes)
	}
}

func TestParseLaunchctlProcessListAndRefs(t *testing.T) {
	output := `service = {
    bundle id = com.tencent.xinWeChat
    program = "/Applications/WeChat.app/Contents/MacOS/WeChat"
    pid = 73508
}
73508 0 application.com.tencent.xinWeChat.1.2
73509 0 application.com.tencent.xinWeChat.WeChatAppEx.1`
	processes := ParseLaunchctlProcessList(output)
	if len(processes) != 1 || processes[0].PID != 73508 || processes[0].Name != "WeChat" {
		t.Fatalf("launchctl processes = %+v", processes)
	}
	refs := ParseLaunchctlProcessRefs(output)
	if len(refs) != 1 || refs[0].PID != 73508 || refs[0].Label != "application.com.tencent.xinWeChat.1.2" {
		t.Fatalf("launchctl refs = %+v", refs)
	}
}

func TestIsWeChatProcessRejectsHelperLikeCommands(t *testing.T) {
	if !IsWeChatProcess("WeChat", "/Applications/WeChat.app/Contents/MacOS/WeChat") {
		t.Fatal("main WeChat process was rejected")
	}
	for _, command := range []string{"WeChatAppEx", "crashpad_handler", "WeChat Helper"} {
		if IsWeChatProcess(command, command) {
			t.Fatalf("helper-like process %q was accepted", command)
		}
	}
}
