package shadow

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
)

func TestMemoryLockerIsRaceSafeAndNeverAdmitsConcurrentOwners(t *testing.T) {
	locker := &MemoryLocker{}
	var active atomic.Int32
	var overlap atomic.Bool
	var wait sync.WaitGroup
	const goroutines = 32
	for index := 0; index < goroutines; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for attempt := 0; attempt < 500; attempt++ {
				release, err := locker.Acquire(context.Background())
				if err != nil {
					continue
				}
				if active.Add(1) != 1 {
					overlap.Store(true)
				}
				active.Add(-1)
				if err := release(); err != nil {
					t.Errorf("release failed: %v", err)
					return
				}
			}
		}()
	}
	wait.Wait()
	if overlap.Load() || active.Load() != 0 {
		t.Fatal("memory Shadow lock admitted concurrent owners")
	}
	release, err := locker.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if err := release(); err == nil {
		t.Fatal("memory Shadow lock accepted a repeated release")
	}
}

func TestMemoryJournalDeepCopiesSupervisorAndProcessBindings(t *testing.T) {
	deadline := contract.NewDeadline(1_000_000_000)
	record := RecoveryRecord{
		Version: recoveryRecordVersion, Operation: "synthetic_execute", State: StateActive,
		AttemptID: "0123456789abcdef0123456789abcdef", ChallengeID: "abcdefabcdefabcdefabcdefabcdefab",
		BuildSetDigest: testBuildDigest, SourceQualificationDigest: testSourceDigest,
		CleanupRoute: contract.CleanupRouteDirect, AccountBindingID: "aabbccddeeff0011",
		OptionsDigest: testOptionsDigest, RootLeaf: "attempt-0123456789abcdef0123456789abcdef",
		BundleID: "com.zanescope.vlocal.shadow.0123456789abcdef0123456789abcdef",
		Deadline: deadline, ExpectedSecurityPosture: "synthetic", Source: SourceBinding{
			Leaf: "WeChat.app", Device: 1, Inode: 2, UID: 501, Mode: 0o755,
			ManifestDigest: testSourceDigest,
		},
		PendingAction: ActionNone, Resources: []contract.ResourceBinding{
			{Kind: "workspace", Leaf: "attempt-0123456789abcdef0123456789abcdef", Device: 1, Inode: 10, UID: 501, Mode: 0o700, LinkCount: 1},
			{Kind: "clone_app", Leaf: "attempt-0123456789abcdef0123456789abcdef/WeChat.app", Device: 1, Inode: 11, UID: 501, Mode: 0o700, LinkCount: 1, DigestSHA256: "5555555555555555555555555555555555555555555555555555555555555555"},
			{Kind: "container", Leaf: "com.zanescope.vlocal.shadow.0123456789abcdef0123456789abcdef", Device: 1, Inode: 12, UID: 501, Mode: 0o700, LinkCount: 1},
			{Kind: "hook", Leaf: "attempt-0123456789abcdef0123456789abcdef/capture.dylib", Device: 1, Inode: 13, UID: 501, Mode: 0o600, LinkCount: 1},
			{Kind: "socket", Leaf: "attempt-0123456789abcdef0123456789abcdef/capture.sock", Device: 1, Inode: 14, UID: 501, Mode: 0o600, LinkCount: 1},
			{Kind: "supervisor", Leaf: "v-local-shadow-supervisor", Device: 1, Inode: 15, UID: 501, Mode: 0o500, LinkCount: 1, DigestSHA256: "4444444444444444444444444444444444444444444444444444444444444444"},
		},
	}
	supervisor := SupervisorProcessBinding{
		PID: 41001, StartMonotonicNS: 2_000_000_000,
		Digest: "4444444444444444444444444444444444444444444444444444444444444444",
	}
	if err := record.BindSupervisor(supervisor); err != nil {
		t.Fatal(err)
	}
	process := contract.ProcessBinding{
		PID: 41002, StartMonotonicNS: 2_100_000_000,
		SupervisorPID: supervisor.PID, SupervisorStartMonotonicNS: supervisor.StartMonotonicNS,
		ExecutableLeaf:   "attempt-0123456789abcdef0123456789abcdef/WeChat.app/Contents/MacOS/WeChat",
		ExecutableDigest: "5555555555555555555555555555555555555555555555555555555555555555",
		CloneRootLeaf:    record.RootLeaf, SupervisorDigest: supervisor.Digest,
	}
	if err := record.BindProcess(process); err != nil {
		t.Fatal(err)
	}
	journal := NewMemoryJournal()
	if err := journal.Save(record); err != nil {
		t.Fatal(err)
	}
	loaded, err := journal.Load()
	if err != nil {
		t.Fatal(err)
	}
	loaded.Supervisor.PID++
	loaded.Process.PID++
	if journal.Record.Supervisor.PID != supervisor.PID || journal.Record.Process.PID != process.PID ||
		journal.History[0].Supervisor.PID != supervisor.PID || journal.History[0].Process.PID != process.PID {
		t.Fatal("memory journal shared mutable supervisor or process pointers with a caller")
	}
}
