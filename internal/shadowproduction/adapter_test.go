//go:build darwin

package shadowproduction

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	shadowmodel "github.com/zanescope/v-local-key-provider/internal/shadow"
	shadowaccount "github.com/zanescope/v-local-key-provider/internal/shadowaccount"
	shadowcontainer "github.com/zanescope/v-local-key-provider/internal/shadowcontainer"
	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
	shadowlaunch "github.com/zanescope/v-local-key-provider/internal/shadowlaunch"
	shadowsupervisor "github.com/zanescope/v-local-key-provider/internal/shadowsupervisor"
)

type adapterCaptureFake struct {
	candidate    []byte
	captureCalls int
}

func (*adapterCaptureFake) Validate() error { return nil }

func (*adapterCaptureFake) CreateLeaves(
	context.Context,
	shadowaccount.Record,
	shadowmodel.RecoveryRecord,
) ([]contract.ResourceBinding, error) {
	return nil, nil
}

func (value *adapterCaptureFake) Capture(
	context.Context,
	shadowaccount.Record,
	shadowmodel.RecoveryRecord,
) ([]byte, error) {
	value.captureCalls++
	return append([]byte(nil), value.candidate...), nil
}

func (*adapterCaptureFake) ValidateCredential([]byte) error { return nil }
func (*adapterCaptureFake) Stop(context.Context, shadowmodel.RecoveryRecord) error {
	return nil
}
func (*adapterCaptureFake) RemoveLeaves(
	context.Context,
	shadowaccount.Record,
	shadowmodel.RecoveryRecord,
) error {
	return nil
}
func (*adapterCaptureFake) LeavesAbsent(
	context.Context,
	shadowaccount.Record,
	shadowmodel.RecoveryRecord,
) (bool, bool, error) {
	return true, true, nil
}

type adapterProcessesFake struct {
	facts ProcessFacts
	err   error
	calls int
}

func (value *adapterProcessesFake) Absent(
	context.Context,
	shadowmodel.RecoveryRecord,
) (ProcessFacts, error) {
	value.calls++
	return value.facts, value.err
}

type adapterSessionFake struct {
	prepareFrame shadowsupervisor.Frame
	prepareErr   error
	releaseErr   error
	stopClean    bool
	stopErr      error
	closeClean   bool
	closeErr     error
	prepareCalls int
	releaseCalls int
	stopCalls    int
	closeCalls   int
}

func (value *adapterSessionFake) Prepare(context.Context) (shadowsupervisor.Frame, error) {
	value.prepareCalls++
	return value.prepareFrame, value.prepareErr
}

func (value *adapterSessionFake) Release(context.Context) error {
	value.releaseCalls++
	return value.releaseErr
}

func (value *adapterSessionFake) Stop(context.Context) (bool, error) {
	value.stopCalls++
	return value.stopClean, value.stopErr
}

func (value *adapterSessionFake) CloseProvider(context.Context) (bool, error) {
	value.closeCalls++
	return value.closeClean, value.closeErr
}

type adapterStarterFake struct {
	session          *adapterSessionFake
	mutateSupervisor func(*shadowsupervisor.Frame)
	mutateProcess    func(*shadowsupervisor.Frame)
	err              error
	calls            int
	config           shadowsupervisor.StartConfig
}

func (value *adapterStarterFake) Start(
	_ context.Context,
	config shadowsupervisor.StartConfig,
) (SupervisorSession, shadowsupervisor.Frame, error) {
	value.calls++
	value.config = config
	if value.err != nil {
		return nil, shadowsupervisor.Frame{}, value.err
	}
	supervisor := shadowsupervisor.Frame{
		Version: shadowsupervisor.ProtocolVersion, Type: "supervisor_bound",
		SupervisorPID: 4101, SupervisorStartNS: 101, SupervisorDigest: config.SupervisorDigest,
	}
	if value.mutateSupervisor != nil {
		value.mutateSupervisor(&supervisor)
	}
	process := shadowsupervisor.Frame{
		Version: shadowsupervisor.ProtocolVersion, Type: "bound",
		LeaseDeadlineNS: config.Init.LeaseDeadlineNS, Executable: config.Init.Executable,
		CloneRoot: config.Init.CloneRoot, ExecutableDigest: config.Init.ExecutableDigest,
		PID: 4102, StartNS: 102, SupervisorPID: supervisor.SupervisorPID,
		SupervisorStartNS: supervisor.SupervisorStartNS, SupervisorDigest: supervisor.SupervisorDigest,
	}
	if value.mutateProcess != nil {
		value.mutateProcess(&process)
	}
	value.session.prepareFrame = process
	return value.session, supervisor, nil
}

func adapterLaunchFake() shadowlaunch.Runtime {
	return shadowlaunch.Runtime{
		Register:   func(context.Context, string, string) error { return nil },
		Unregister: func(context.Context, string, string) error { return nil },
		RegisteredPaths: func(context.Context, string) ([]string, error) {
			return nil, nil
		},
	}
}

func adapterRecordFixture(t *testing.T) (*Prelaunch, shadowmodel.RecoveryRecord) {
	t.Helper()
	prelaunch, _, _ := newGateFixture(t)
	attemptID := "0123456789abcdef0123456789abcdef"
	digest := strings.Repeat("a", 64)
	root := "attempt-" + attemptID
	deadline := contract.NewDeadline(1)
	supervisor, err := prelaunch.SupervisorArtifact(context.Background(), shadowmodel.RecoveryRecord{})
	if err != nil {
		t.Fatal(err)
	}
	record := shadowmodel.RecoveryRecord{
		Version: 1, Operation: "execute", State: shadowmodel.StatePrepared, AttemptID: attemptID,
		ChallengeID: "abcdefabcdefabcdefabcdefabcdefab", BuildSetDigest: prelaunch.Bundle.Digest,
		SourceQualificationDigest: digest, CleanupRoute: contract.CleanupRouteDirect,
		AccountBindingID: prelaunch.Account.BindingID, OptionsDigest: strings.Repeat("b", 64),
		RootLeaf: root, BundleID: "com.zanescope.vlocal.shadow." + attemptID,
		Deadline: deadline, ExpectedSecurityPosture: "sip_enabled_verified",
		Source: shadowmodel.SourceBinding{
			Leaf: "WeChat.app", Device: 21, Inode: 22, UID: prelaunch.Account.UID,
			Mode: 0o755, ManifestDigest: digest,
		},
		PendingAction: shadowmodel.ActionPrepareLaunch,
		Resources: []contract.ResourceBinding{
			{Kind: "workspace", Leaf: root, Device: 31, Inode: 32, UID: prelaunch.Account.UID, Mode: 0o700, LinkCount: 1},
			{Kind: "clone_app", Leaf: root + "/WeChat.app", Device: 33, Inode: 34, UID: prelaunch.Account.UID, Mode: 0o700, LinkCount: 1},
			{Kind: "container", Leaf: "com.zanescope.vlocal.shadow." + attemptID, Device: 35, Inode: 36, UID: prelaunch.Account.UID, Mode: 0o700, LinkCount: 1},
			{Kind: "hook", Leaf: root + "/capture-hook.dylib", Device: 37, Inode: 38, UID: prelaunch.Account.UID, Mode: 0o600, LinkCount: 1},
			{Kind: "socket", Leaf: root + "/capture.sock", Device: 39, Inode: 40, UID: prelaunch.Account.UID, Mode: 0o600, LinkCount: 1},
			supervisor,
		},
	}
	if err := record.Validate(); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(
		prelaunch.Account.SecurityRoot,
		record.RootLeaf,
		"WeChat.app",
		"Contents",
		"MacOS",
		"SyntheticTarget",
	)
	if err := os.MkdirAll(filepath.Dir(executable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("synthetic executable fixture\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return prelaunch, record
}

func newAdapterFixture(
	t *testing.T,
	starter *adapterStarterFake,
) (*Adapter, shadowmodel.RecoveryRecord, *adapterCaptureFake, *adapterProcessesFake) {
	t.Helper()
	prelaunch, record := adapterRecordFixture(t)
	capture := &adapterCaptureFake{candidate: []byte{1, 2, 3, 4}}
	processes := &adapterProcessesFake{facts: ProcessFacts{ProcessAbsent: true, SupervisorAbsent: true}}
	adapter, err := NewAdapter(prelaunch, "Contents/MacOS/SyntheticTarget", RuntimeDependencies{
		Launch: adapterLaunchFake(), Container: shadowcontainer.Runtime{}, Capture: capture,
		Processes: processes, StartSupervisor: starter.Start,
	})
	if err != nil {
		t.Fatal(err)
	}
	return adapter, record, capture, processes
}

func TestAdapterRejectsUnboundOrCancelledPrelaunchStages(t *testing.T) {
	adapter, record, _, _ := newAdapterFixture(t, &adapterStarterFake{session: &adapterSessionFake{}})
	drifted := record
	drifted.BuildSetDigest = strings.Repeat("f", 64)
	if _, err := adapter.CreateWorkspace(context.Background(), drifted); err == nil {
		t.Fatal("workspace preparation accepted a drifted build set")
	}
	if err := adapter.Transform(context.Background(), drifted); err == nil {
		t.Fatal("transformation accepted a drifted build set")
	}
	if _, err := adapter.SupervisorArtifact(context.Background(), drifted); err == nil {
		t.Fatal("supervisor artifact accepted a drifted build set")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := adapter.SupervisorArtifact(cancelled, record); err == nil {
		t.Fatal("supervisor artifact ignored cancellation")
	}
}

func TestAdapterPersistsOwnershipBeforeReleaseAndCapture(t *testing.T) {
	session := &adapterSessionFake{stopClean: true, closeClean: true}
	starter := &adapterStarterFake{session: session}
	adapter, record, capture, processes := newAdapterFixture(t, starter)
	events := []string{}
	process, err := adapter.PrepareLaunch(
		context.Background(),
		record,
		func(supervisor shadowmodel.SupervisorProcessBinding) error {
			if session.prepareCalls != 0 || record.Supervisor != nil {
				t.Fatal("child preparation began before supervisor persistence")
			}
			events = append(events, "supervisor")
			return record.BindSupervisor(supervisor)
		},
		func(process contract.ProcessBinding) error {
			if session.prepareCalls != 1 || record.Supervisor == nil {
				t.Fatal("process persistence did not follow supervisor-bound preparation")
			}
			events = append(events, "process")
			return record.BindProcess(process)
		},
	)
	if err != nil || record.Process == nil || *record.Process != process ||
		!reflect.DeepEqual(events, []string{"supervisor", "process"}) {
		t.Fatalf("prepare result=%+v record=%+v events=%v err=%v", process, record.Process, events, err)
	}
	if err := record.SetPending(shadowmodel.ActionReleaseLaunch); err != nil {
		t.Fatal(err)
	}
	if err := adapter.ReleaseLaunch(context.Background(), record); err != nil || session.releaseCalls != 1 {
		t.Fatalf("releaseCalls=%d err=%v", session.releaseCalls, err)
	}
	record.PendingAction = shadowmodel.ActionNone
	record.State = shadowmodel.StateActive
	if err := record.Validate(); err != nil {
		t.Fatal(err)
	}
	candidate, err := adapter.Capture(context.Background(), record)
	if err != nil || !reflect.DeepEqual(candidate, capture.candidate) || capture.captureCalls != 1 {
		t.Fatalf("candidate=%v calls=%d err=%v", candidate, capture.captureCalls, err)
	}
	clean, err := adapter.StopSupervisor(context.Background(), record)
	if err != nil || !clean || session.stopCalls != 1 {
		t.Fatalf("clean=%v stopCalls=%d err=%v", clean, session.stopCalls, err)
	}
	if _, found := adapter.session(record.AttemptID); found {
		t.Fatal("clean supervisor session remained cached")
	}
	clean, err = adapter.StopSupervisor(context.Background(), record)
	if err != nil || !clean || processes.calls != 1 {
		t.Fatalf("independent absence fallback clean=%v calls=%d err=%v", clean, processes.calls, err)
	}
}

func TestAdapterClosesOrStopsSessionWhenPersistenceFails(t *testing.T) {
	persistErr := errors.New("fixture persistence failure")
	t.Run("supervisor", func(t *testing.T) {
		session := &adapterSessionFake{closeClean: true, stopClean: true}
		adapter, record, _, _ := newAdapterFixture(t, &adapterStarterFake{session: session})
		_, err := adapter.PrepareLaunch(
			context.Background(), record,
			func(shadowmodel.SupervisorProcessBinding) error { return persistErr },
			func(contract.ProcessBinding) error {
				t.Fatal("process callback ran after supervisor persistence failure")
				return nil
			},
		)
		if !errors.Is(err, persistErr) || session.closeCalls != 1 || session.prepareCalls != 0 || session.stopCalls != 0 {
			t.Fatalf("close=%d prepare=%d stop=%d err=%v", session.closeCalls, session.prepareCalls, session.stopCalls, err)
		}
		if _, found := adapter.session(record.AttemptID); found {
			t.Fatal("closed pre-child session remained cached")
		}
	})

	t.Run("process", func(t *testing.T) {
		session := &adapterSessionFake{closeClean: true, stopClean: true}
		adapter, record, _, _ := newAdapterFixture(t, &adapterStarterFake{session: session})
		_, err := adapter.PrepareLaunch(
			context.Background(), record,
			func(supervisor shadowmodel.SupervisorProcessBinding) error {
				return record.BindSupervisor(supervisor)
			},
			func(process contract.ProcessBinding) error {
				if err := record.BindProcess(process); err != nil {
					return err
				}
				return persistErr
			},
		)
		if !errors.Is(err, persistErr) || session.prepareCalls != 1 || session.stopCalls != 1 || session.closeCalls != 0 {
			t.Fatalf("prepare=%d stop=%d close=%d err=%v", session.prepareCalls, session.stopCalls, session.closeCalls, err)
		}
		if _, found := adapter.session(record.AttemptID); found {
			t.Fatal("stopped child session remained cached")
		}
	})
}

func TestAdapterRejectsUnboundProtocolFields(t *testing.T) {
	digest := strings.Repeat("c", 64)
	validSupervisor := shadowsupervisor.Frame{
		Version: shadowsupervisor.ProtocolVersion, Type: "supervisor_bound",
		SupervisorPID: 5101, SupervisorStartNS: 201, SupervisorDigest: digest,
	}
	if _, err := supervisorBinding(validSupervisor, digest); err != nil {
		t.Fatal(err)
	}
	supervisorMutations := map[string]func(*shadowsupervisor.Frame){
		"mode":       func(frame *shadowsupervisor.Frame) { frame.Mode = "preexec" },
		"lease":      func(frame *shadowsupervisor.Frame) { frame.LeaseDeadlineNS = 1 },
		"executable": func(frame *shadowsupervisor.Frame) { frame.Executable = "/tmp/extra" },
		"arguments":  func(frame *shadowsupervisor.Frame) { frame.Arguments = []string{"extra"} },
		"error":      func(frame *shadowsupervisor.Frame) { frame.ErrorCode = "unexpected" },
	}
	for name, mutate := range supervisorMutations {
		t.Run("supervisor_"+name, func(t *testing.T) {
			frame := validSupervisor
			mutate(&frame)
			if _, err := supervisorBinding(frame, digest); err == nil {
				t.Fatal("unexpected supervisor frame was accepted")
			}
		})
	}

	record := shadowmodel.RecoveryRecord{
		RootLeaf: "attempt-0123456789abcdef0123456789abcdef", Deadline: contract.NewDeadline(1),
	}
	config := shadowsupervisor.StartConfig{Init: shadowsupervisor.Frame{
		CloneRoot: "/tmp/attempt/", Executable: "/tmp/attempt/WeChat.app/Contents/MacOS/SyntheticTarget",
		ExecutableDigest: digest,
	}}
	supervisor := shadowmodel.SupervisorProcessBinding{PID: 5101, StartMonotonicNS: 201, Digest: digest}
	validProcess := shadowsupervisor.Frame{
		Version: shadowsupervisor.ProtocolVersion, Type: "bound",
		LeaseDeadlineNS: record.Deadline.CaptureStopNS, Executable: config.Init.Executable,
		CloneRoot: config.Init.CloneRoot, ExecutableDigest: digest,
		PID: 5102, StartNS: 202, SupervisorPID: supervisor.PID,
		SupervisorStartNS: supervisor.StartMonotonicNS, SupervisorDigest: supervisor.Digest,
	}
	if _, err := processBinding(record, config, "Contents/MacOS/SyntheticTarget", supervisor, validProcess); err != nil {
		t.Fatal(err)
	}
	processMutations := map[string]func(*shadowsupervisor.Frame){
		"mode":      func(frame *shadowsupervisor.Frame) { frame.Mode = "preexec" },
		"arguments": func(frame *shadowsupervisor.Frame) { frame.Arguments = []string{"extra"} },
		"error":     func(frame *shadowsupervisor.Frame) { frame.ErrorCode = "unexpected" },
	}
	for name, mutate := range processMutations {
		t.Run("process_"+name, func(t *testing.T) {
			frame := validProcess
			mutate(&frame)
			if _, err := processBinding(record, config, "Contents/MacOS/SyntheticTarget", supervisor, frame); err == nil {
				t.Fatal("unexpected child frame was accepted")
			}
		})
	}
}

func TestDigestExactExecutableHonorsCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "executable")
	if err := os.WriteFile(path, []byte("fixture\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := digestExactExecutable(ctx, path); err == nil {
		t.Fatal("cancelled executable digest was accepted")
	}
}

func TestDisabledCoordinatorRejectsBothExecutionRoutes(t *testing.T) {
	prelaunch, record := adapterRecordFixture(t)
	session := &adapterSessionFake{closeClean: true, stopClean: true}
	starter := &adapterStarterFake{session: session}
	journal := shadowmodel.NewMemoryJournal()
	coordinator, _, err := NewDisabledCoordinator(DisabledCoordinatorConfig{
		Prelaunch: prelaunch, ExecutableLeaf: "Contents/MacOS/SyntheticTarget",
		Dependencies: RuntimeDependencies{
			Launch: adapterLaunchFake(), Container: shadowcontainer.Runtime{},
			Capture: &adapterCaptureFake{}, Processes: &adapterProcessesFake{}, StartSupervisor: starter.Start,
		},
		Clock: cowGateClock{now: record.Deadline.T0NS}, Journal: journal,
		Locker: &shadowmodel.MemoryLocker{}, NewID: gateIDs(),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := contract.Request{
		Version: contract.Version, Operation: "execute", RequestID: record.AttemptID,
		ChallengeID: record.ChallengeID, BuildSetDigest: record.BuildSetDigest,
		SourceQualificationDigest: record.SourceQualificationDigest, CleanupRoute: record.CleanupRoute,
		AccountBindingID: record.AccountBindingID, OptionsDigest: record.OptionsDigest, Deadline: &record.Deadline,
	}
	for _, operation := range []string{"execute", "synthetic_execute"} {
		request.Operation = operation
		output, err := coordinator.Execute(context.Background(), request)
		if err != nil || output.Result.Status != "failed" ||
			output.Result.ErrorCode != contract.ErrorProductionRouteDisabled || starter.calls != 0 {
			t.Fatalf("operation=%s result=%+v starts=%d err=%v", operation, output.Result, starter.calls, err)
		}
	}
}
