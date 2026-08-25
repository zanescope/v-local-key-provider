package windows

import "testing"

func TestPrimaryAndOrderedProcessesKeepRootBeforeChildren(t *testing.T) {
	processes := []Process{
		{PID: 11, ParentID: 10, Name: "Weixin.exe"},
		{PID: 10, ParentID: 1, Name: "Weixin.exe"},
		{PID: 20, ParentID: 1, Name: "WeChat.exe"},
	}
	primary := PrimaryProcesses(processes)
	if len(primary) != 2 || primary[0].PID != 10 || primary[1].PID != 20 {
		t.Fatalf("primary processes = %+v", primary)
	}
	ordered := OrderedProcesses(processes)
	if len(ordered) != 3 || ordered[0].PID != 10 || ordered[1].PID != 20 || ordered[2].PID != 11 {
		t.Fatalf("ordered processes = %+v", ordered)
	}
}

func TestMemoryStagePolicySeparatesWritableAndReadonlyRegions(t *testing.T) {
	writable := MemoryRegion{State: MemCommit, Protect: PageReadWrite, Type: MemPrivate}
	readonly := MemoryRegion{State: MemCommit, Protect: PageReadOnly, Type: MemImage}
	guarded := MemoryRegion{State: MemCommit, Protect: PageReadOnly | PageGuard, Type: MemImage}
	if !StageReadsRegion("bounded_writable_heap", writable) || StageReadsRegion("bounded_writable_heap", readonly) {
		t.Fatal("writable stage region policy is incorrect")
	}
	if !StageReadsRegion("bounded_readonly", readonly) || StageReadsRegion("bounded_readonly", writable) {
		t.Fatal("readonly stage region policy is incorrect")
	}
	if ReadableRegion(guarded) {
		t.Fatal("guarded memory was treated as readable")
	}
}

func TestFallbackStagePolicyIsBoundedAndCopied(t *testing.T) {
	stages := FallbackStages()
	if len(stages) != 5 {
		t.Fatalf("fallback stage count = %d", len(stages))
	}
	stages[0].Name = "mutated"
	if FallbackStages()[0].Name != "structured_key_object" {
		t.Fatal("fallback stage registry leaked mutable state")
	}
	if StageTailLength("salt_neighborhood", 128, 64) != 192 || StageTailLength("bounded_hex", 128, 64) != 64 {
		t.Fatal("stage overlap policy is incorrect")
	}
}
