package shadow

import (
	"strings"
	"testing"

	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
)

func modelResource(kind, leaf string, inode uint64, digest string) contract.ResourceBinding {
	return contract.ResourceBinding{
		Kind: kind, Leaf: leaf, Device: 1, Inode: inode, UID: 501,
		Mode: 0o700, LinkCount: 1, DigestSHA256: digest,
	}
}

func modelRecordFixture() RecoveryRecord {
	attemptID := "0123456789abcdef0123456789abcdef"
	root := "attempt-" + attemptID
	digest := strings.Repeat("d", 64)
	return RecoveryRecord{
		Version: recoveryRecordVersion, Operation: "synthetic_execute", State: StatePrepared,
		AttemptID: attemptID, ChallengeID: "abcdefabcdefabcdefabcdefabcdefab",
		BuildSetDigest: strings.Repeat("a", 64), SourceQualificationDigest: strings.Repeat("b", 64),
		CleanupRoute: contract.CleanupRouteDirect, AccountBindingID: "0011223344556677",
		OptionsDigest: strings.Repeat("c", 64), RootLeaf: root,
		BundleID: "com.zanescope.vlocal.shadow." + attemptID,
		Deadline: contract.NewDeadline(1_000_000_000), ExpectedSecurityPosture: "synthetic",
		Source: SourceBinding{
			Leaf: "WeChat.app", Device: 1, Inode: 2, UID: 0, Mode: 0o755,
			ManifestDigest: strings.Repeat("b", 64),
		},
		PendingAction: ActionPrepareLaunch,
		Resources: []contract.ResourceBinding{
			modelResource("workspace", root, 10, ""),
			modelResource("clone_app", root+"/WeChat.app", 11, strings.Repeat("e", 64)),
			modelResource("container", "com.zanescope.vlocal.shadow."+attemptID, 12, ""),
			modelResource("hook", root+"/capture-hook.dylib", 13, ""),
			modelResource("socket", root+"/capture.sock", 14, ""),
			modelResource("supervisor", "v-local-shadow-supervisor", 15, digest),
		},
	}
}

func bindModelProcess(t *testing.T, record *RecoveryRecord) {
	t.Helper()
	digest := strings.Repeat("d", 64)
	supervisor := SupervisorProcessBinding{PID: 41001, StartMonotonicNS: 2_000_000_000, Digest: digest}
	if err := record.BindSupervisor(supervisor); err != nil {
		t.Fatal(err)
	}
	if err := record.BindProcess(contract.ProcessBinding{
		PID: 41002, StartMonotonicNS: 2_100_000_000,
		SupervisorPID: supervisor.PID, SupervisorStartMonotonicNS: supervisor.StartMonotonicNS,
		ExecutableLeaf:   record.RootLeaf + "/WeChat.app/Contents/MacOS/SyntheticTarget",
		ExecutableDigest: strings.Repeat("f", 64), CloneRootLeaf: record.RootLeaf,
		SupervisorDigest: supervisor.Digest,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryRecordRejectsCrossLifecycleBindings(t *testing.T) {
	base := modelRecordFixture()
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(*RecoveryRecord){
		"operation_posture": func(record *RecoveryRecord) {
			record.Operation = "execute"
		},
		"duplicate_resource_class": func(record *RecoveryRecord) {
			record.Resources = append(record.Resources,
				modelResource("hook", record.RootLeaf+"/other-hook.dylib", 20, ""))
		},
		"unpaired_capture_leaf": func(record *RecoveryRecord) {
			record.Resources = append([]contract.ResourceBinding(nil), record.Resources[:4]...)
		},
		"wrong_supervisor_leaf": func(record *RecoveryRecord) {
			record.Resources[5].Leaf = record.RootLeaf + "/v-local-shadow-supervisor"
		},
		"persisted_recovery_binding": func(record *RecoveryRecord) {
			record.Resources = append(record.Resources,
				modelResource("recovery_record", "recovery.json", 20, ""))
		},
		"release_without_process": func(record *RecoveryRecord) {
			record.PendingAction = ActionReleaseLaunch
		},
		"active_without_process": func(record *RecoveryRecord) {
			record.State = StateActive
			record.PendingAction = ActionNone
		},
		"process_outside_launch_checkpoint": func(record *RecoveryRecord) {
			bindModelProcess(t, record)
			record.PendingAction = ActionNone
		},
		"process_outside_main_executable_dir": func(record *RecoveryRecord) {
			bindModelProcess(t, record)
			record.Process.ExecutableLeaf = record.RootLeaf + "/WeChat.app/Contents/Resources/SyntheticTarget"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			record := cloneRecoveryRecord(base)
			record.Resources = append([]contract.ResourceBinding(nil), base.Resources...)
			mutate(&record)
			if err := record.Validate(); err == nil {
				t.Fatal("invalid recovery lifecycle was accepted")
			}
		})
	}
}

func TestBindResourceRejectsClassRebindingWithoutMutation(t *testing.T) {
	record := modelRecordFixture()
	before := append([]contract.ResourceBinding(nil), record.Resources...)
	err := record.BindResource(modelResource("hook", record.RootLeaf+"/other-hook.dylib", 20, ""))
	if err == nil {
		t.Fatal("resource class rebinding was accepted")
	}
	if len(record.Resources) != len(before) {
		t.Fatal("failed resource rebinding mutated the recovery record")
	}
	for index := range before {
		if record.Resources[index] != before[index] {
			t.Fatal("failed resource rebinding changed an existing binding")
		}
	}
}

func TestSaveCompletedRejectsPartialResourceSetWithoutMutation(t *testing.T) {
	record := modelRecordFixture()
	record.State = StatePlanned
	record.PendingAction = ActionPrepareWorkspace
	record.Resources = nil
	journal := NewMemoryJournal()
	coordinator := &Coordinator{config: Config{Journal: journal}}
	err := coordinator.saveCompleted(&record, StatePrepared,
		modelResource("workspace", record.RootLeaf, 10, ""),
		modelResource("clone_app", record.RootLeaf+"/WeChat.app", 11, strings.Repeat("e", 64)),
		modelResource("hook", record.RootLeaf+"/capture-hook.dylib", 13, ""),
	)
	if err == nil {
		t.Fatal("partial capture resources were accepted")
	}
	if record.State != StatePlanned || record.PendingAction != ActionPrepareWorkspace || len(record.Resources) != 0 {
		t.Fatal("failed completed checkpoint partially mutated the recovery record")
	}
	if journal.SaveCount != 0 {
		t.Fatal("invalid completed checkpoint reached durable storage")
	}
}
