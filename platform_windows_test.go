//go:build windows

package main

import "testing"

func TestPrimaryTargetProcessesKeepsWeixinRootAndWechat(t *testing.T) {
	processes := []targetProcess{
		{pid: 10, parentID: 1, name: "Weixin.exe"},
		{pid: 11, parentID: 10, name: "Weixin.exe"},
		{pid: 12, parentID: 10, name: "Weixin.exe"},
		{pid: 20, parentID: 1, name: "WeChat.exe"},
	}
	selected := primaryTargetProcesses(processes)
	if len(selected) != 2 || selected[0].pid != 10 || selected[1].pid != 20 {
		t.Fatalf("unexpected primary processes: %#v", selected)
	}
}

func TestReadableRegionIncludesCommittedImageMemory(t *testing.T) {
	info := memoryBasicInformation{
		State: memCommit, Protect: pageReadOnly, Type: memImage, RegionSize: 4096,
	}
	if !readableRegion(info) {
		t.Fatal("committed readable image memory was excluded")
	}
}
