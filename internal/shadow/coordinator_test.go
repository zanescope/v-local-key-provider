package shadow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"

	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
)

const (
	testBuildDigest   = "1111111111111111111111111111111111111111111111111111111111111111"
	testSourceDigest  = "2222222222222222222222222222222222222222222222222222222222222222"
	testOptionsDigest = "3333333333333333333333333333333333333333333333333333333333333333"
	testSecret        = "synthetic-secret-42"
)

type fakeClock struct {
	mu  sync.Mutex
	now uint64
}

type failAtClock struct {
	mu     sync.Mutex
	now    uint64
	calls  int
	failAt int
}

func (value *failAtClock) NowNS() (uint64, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	value.calls++
	if value.calls == value.failAt {
		return 0, errors.New("injected clock failure")
	}
	return value.now, nil
}

func (value *fakeClock) NowNS() (uint64, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	return value.now, nil
}

func (value *fakeClock) Advance(delta uint64) {
	value.mu.Lock()
	value.now += delta
	value.mu.Unlock()
}

func newSyntheticHarness(t *testing.T) (*Coordinator, *fakeClock, *MemoryJournal, *SyntheticAdapter) {
	t.Helper()
	clock := &fakeClock{now: 1_000_000_000}
	journal := NewMemoryJournal()
	adapter := &SyntheticAdapter{
		Clock: clock, AdvanceNS: clock.Advance, StepNS: 1_000_000,
		BuildSet: testBuildDigest, SourceDigest: testSourceDigest, SourceVersion: "4.1.11", SourceBuild: "26000",
		Credential: []byte(testSecret), Expected: []byte(testSecret),
		FailBefore: map[string]string{}, FailAfter: map[string]string{}, AdvanceByStage: map[string]uint64{},
	}
	sequence := 0
	coordinator, err := NewCoordinator(Config{
		BuildSetDigest: testBuildDigest, CleanupRoute: contract.CleanupRouteDirect,
		SyntheticRouteEnabled: true, ExpectedSecurityPosture: "synthetic",
		Clock: clock, Journal: journal, Locker: &MemoryLocker{}, Adapter: adapter,
		Cleanup: adapter,
		NewID: func() (string, error) {
			sequence++
			return fmt.Sprintf("%032x", sequence), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator, clock, journal, adapter
}

type mismatchedCleanup struct{ *SyntheticAdapter }

func (mismatchedCleanup) Route() string { return "broker" }

type cancelCaptureAdapter struct {
	*SyntheticAdapter
	cancel context.CancelFunc
}

func (value *cancelCaptureAdapter) Capture(
	ctx context.Context,
	record RecoveryRecord,
) ([]byte, error) {
	candidate, err := value.SyntheticAdapter.Capture(ctx, record)
	value.cancel()
	if err != nil {
		return candidate, err
	}
	return candidate, context.Canceled
}

func TestCoordinatorRejectsCleanupExecutorOutsideFrozenBuildRoute(t *testing.T) {
	coordinator, _, journal, adapter := newSyntheticHarness(t)
	_ = coordinator
	if _, err := NewCoordinator(Config{
		BuildSetDigest: testBuildDigest, CleanupRoute: contract.CleanupRouteDirect,
		SyntheticRouteEnabled: true, ExpectedSecurityPosture: "synthetic",
		Clock: &fakeClock{now: 1}, Journal: journal, Locker: &MemoryLocker{}, Adapter: adapter,
		Cleanup: mismatchedCleanup{SyntheticAdapter: adapter},
	}); err == nil {
		t.Fatal("cleanup executor route drift was accepted")
	}
}

func syntheticRequest(clock *fakeClock, requestID, challengeID string) contract.Request {
	t0, _ := clock.NowNS()
	deadline := contract.NewDeadline(t0)
	return contract.Request{
		Version: contract.Version, Operation: "synthetic_execute", RequestID: requestID, ChallengeID: challengeID,
		BuildSetDigest: testBuildDigest, SourceQualificationDigest: testSourceDigest,
		CleanupRoute: contract.CleanupRouteDirect, AccountBindingID: "aabbccddeeff0011",
		OptionsDigest: testOptionsDigest, Deadline: &deadline,
	}
}

func TestSyntheticQualificationIsReadOnlyAndKeepsProductionDisabled(t *testing.T) {
	coordinator, _, journal, adapter := newSyntheticHarness(t)
	request := contract.Request{
		Version: contract.Version, Operation: "qualify", RequestID: "11112222333344445555666677778888",
		BuildSetDigest: testBuildDigest, SourceQualificationDigest: testSourceDigest,
		CleanupRoute: contract.CleanupRouteDirect, AccountBindingID: "aabbccddeeff0011", OptionsDigest: testOptionsDigest,
	}
	output, err := coordinator.Qualify(context.Background(), request)
	if err != nil || output.Result.Status != "qualified" || output.Result.Qualification == nil ||
		output.Result.Qualification.ProductionRouteEnabled {
		t.Fatalf("qualification output=%+v err=%v", output, err)
	}
	if journal.SaveCount != 0 || adapter.Residue() {
		t.Fatal("read-only qualification created attempt state or residue")
	}
}

func TestCoordinatorRejectsNilContext(t *testing.T) {
	coordinator, clock, _, _ := newSyntheticHarness(t)
	if _, err := coordinator.Execute(nil, syntheticRequest(clock,
		"11111111222222223333333344444444", "55555555666666667777777788888888")); err == nil {
		t.Fatal("nil execution context was accepted")
	}
	request := contract.Request{
		Version: contract.Version, Operation: "qualify", RequestID: "99999999aaaabbbbccccddddeeeeffff",
		BuildSetDigest: testBuildDigest, SourceQualificationDigest: testSourceDigest,
		CleanupRoute: contract.CleanupRouteDirect, AccountBindingID: "aabbccddeeff0011", OptionsDigest: testOptionsDigest,
	}
	if _, err := coordinator.Qualify(nil, request); err == nil {
		t.Fatal("nil qualification context was accepted")
	}
}

func TestCoordinatorRejectsCancelledContextBeforeMutation(t *testing.T) {
	coordinator, clock, journal, adapter := newSyntheticHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := coordinator.Execute(ctx, syntheticRequest(clock,
		"11111111222222223333333344444444", "55555555666666667777777788888888")); err == nil {
		t.Fatal("cancelled execution context was accepted")
	}
	if journal.SaveCount != 0 || adapter.Residue() {
		t.Fatal("cancelled execution context created mutation or durable state")
	}
}

func TestCallerCancellationDuringCaptureCannotCancelFinalizer(t *testing.T) {
	coordinator, clock, journal, synthetic := newSyntheticHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	adapter := &cancelCaptureAdapter{SyntheticAdapter: synthetic, cancel: cancel}
	coordinator.config.Adapter = adapter
	coordinator.config.Cleanup = adapter
	output, err := coordinator.Execute(ctx, syntheticRequest(clock,
		"1234567890abcdef1234567890abcdef", "abcdef1234567890abcdef1234567890"))
	if err != nil || output.Result.Status != "failed" || output.Result.ErrorCode != contract.ErrorCapture ||
		len(output.Credential) != 0 || adapter.Residue() {
		t.Fatalf("cancelled capture output=%+v residue=%v err=%v", output.Result, adapter.Residue(), err)
	}
	absent, absentErr := journal.Absent()
	if absentErr != nil || !absent {
		t.Fatalf("cancelled capture retained recovery state: absent=%v err=%v", absent, absentErr)
	}
}

func TestCleanupContextClockFailureReturnsInternalWithoutMutation(t *testing.T) {
	clock := &failAtClock{now: 1_000_000_000, failAt: 3}
	journal := NewMemoryJournal()
	adapter := &SyntheticAdapter{
		Clock: clock, BuildSet: testBuildDigest, SourceDigest: testSourceDigest,
		SourceVersion: "4.1.11", SourceBuild: "26000", Credential: []byte(testSecret), Expected: []byte(testSecret),
		FailBefore: map[string]string{}, FailAfter: map[string]string{}, AdvanceByStage: map[string]uint64{},
	}
	coordinator, err := NewCoordinator(Config{
		BuildSetDigest: testBuildDigest, CleanupRoute: contract.CleanupRouteDirect,
		SyntheticRouteEnabled: true, ExpectedSecurityPosture: "synthetic",
		Clock: clock, Journal: journal, Locker: &MemoryLocker{}, Adapter: adapter, Cleanup: adapter,
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := contract.NewDeadline(clock.now)
	request := contract.Request{
		Version: contract.Version, Operation: "synthetic_execute",
		RequestID: "12341234123412341234123412341234", ChallengeID: "43214321432143214321432143214321",
		BuildSetDigest: testBuildDigest, SourceQualificationDigest: testSourceDigest,
		CleanupRoute: contract.CleanupRouteDirect, AccountBindingID: "aabbccddeeff0011",
		OptionsDigest: testOptionsDigest, Deadline: &deadline,
	}
	output, err := coordinator.Execute(context.Background(), request)
	if err != nil || output.Result.Status != "failed" || output.Result.ErrorCode != contract.ErrorInternal ||
		journal.SaveCount != 0 || adapter.Residue() {
		t.Fatalf("result=%+v saves=%d residue=%v err=%v", output.Result, journal.SaveCount, adapter.Residue(), err)
	}
}

func TestSyntheticVerticalSliceReturnsReadyOnlyAfterFixedCleanup(t *testing.T) {
	coordinator, clock, journal, adapter := newSyntheticHarness(t)
	request := syntheticRequest(clock, "9999aaaabbbbccccddddeeeeffff0000", "00112233445566778899aabbccddeeff")
	output, err := coordinator.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if output.Result.Status != "ready" || output.Result.ErrorCode != contract.ErrorNone ||
		!bytes.Equal(output.Credential, []byte(testSecret)) || output.Result.Receipt == nil {
		t.Fatalf("unexpected synthetic result: %+v", output.Result)
	}
	defer clearBytes(output.Credential)
	if adapter.Residue() {
		t.Fatal("synthetic ready returned with adapter residue")
	}
	absent, absentErr := journal.Absent()
	if absentErr != nil || !absent {
		t.Fatalf("synthetic ready retained recovery record: absent=%v err=%v", absent, absentErr)
	}
	expectedEvents := []string{
		"requalify", "create_workspace", "transform", "supervisor_artifact", "create_capture_leaves",
		"register_launch", "create_container", "prepare_launch", "release_launch", "capture",
		"stop_capture", "stop_supervisor", "unregister_launch", "remove_container", "remove_leaves",
		"remove_workspace", "verify_cleanup",
	}
	if !reflect.DeepEqual(adapter.Events, expectedEvents) {
		t.Fatalf("lifecycle order changed:\n got %v\nwant %v", adapter.Events, expectedEvents)
	}
	seenPending := map[string]bool{}
	supervisorPersistedBeforeProcess := false
	processPersistedBeforeRelease := false
	for _, record := range journal.History {
		seenPending[record.PendingAction] = true
		if record.PendingAction == ActionPrepareLaunch && record.Supervisor != nil && record.Process == nil &&
			record.SupervisorLeaseNS == record.Deadline.CaptureStopNS {
			supervisorPersistedBeforeProcess = true
		}
		if record.PendingAction == ActionPrepareLaunch && record.Process != nil && record.Process.PID > 0 &&
			record.Process.SupervisorPID > 0 && record.Process.SupervisorPID != record.Process.PID {
			processPersistedBeforeRelease = true
		}
		payload, marshalErr := json.Marshal(record)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if bytes.Contains(payload, []byte(testSecret)) {
			t.Fatal("secret entered durable recovery history")
		}
	}
	for _, action := range []string{ActionPrepareWorkspace, ActionTransform, ActionCreateLeaves, ActionRegisterLaunch,
		ActionCreateContainer, ActionPrepareLaunch, ActionReleaseLaunch, StateCleanupPending} {
		if !seenPending[action] && action != StateCleanupPending {
			t.Fatalf("write-ahead action %q was not persisted", action)
		}
	}
	if !processPersistedBeforeRelease {
		t.Fatal("target and supervisor bindings were not durable before release")
	}
	if !supervisorPersistedBeforeProcess {
		t.Fatal("supervisor PID/start/digest/lease were not durable before child creation")
	}
}

func TestAttemptLockReleaseFailureWithholdsCredential(t *testing.T) {
	coordinator, clock, journal, adapter := newSyntheticHarness(t)
	locker := coordinator.config.Locker.(*MemoryLocker)
	locker.FailRelease = true
	output, err := coordinator.Execute(context.Background(), syntheticRequest(clock,
		"1234567890abcdef1234567890abcdef", "abcdef1234567890abcdef1234567890"))
	if err != nil || output.Result.Status != "failed" || output.Result.ErrorCode != contract.ErrorInternal ||
		len(output.Credential) != 0 || output.Result.Receipt == nil {
		t.Fatalf("release failure output=%+v err=%v", output, err)
	}
	if adapter.Residue() {
		t.Fatal("attempt lock release failure hid adapter residue")
	}
	if absent, err := journal.Absent(); err != nil || !absent {
		t.Fatalf("release failure changed completed cleanup: absent=%v err=%v", absent, err)
	}
}

func TestAttemptLockReleaseFailureCannotHideCleanupPending(t *testing.T) {
	coordinator, clock, journal, adapter := newSyntheticHarness(t)
	coordinator.config.Locker.(*MemoryLocker).FailRelease = true
	adapter.FailBefore["remove_container"] = contract.ErrorCleanup
	output, err := coordinator.Execute(context.Background(), syntheticRequest(clock,
		"10101010101010101010101010101010", "20202020202020202020202020202020"))
	if err != nil || output.Result.Status != "cleanup_pending" || output.Result.ErrorCode != contract.ErrorCleanup ||
		output.Result.CredentialReleased || len(output.Credential) != 0 {
		t.Fatalf("release failure obscured cleanup-pending state: output=%+v err=%v", output, err)
	}
	if journal.Record == nil || !adapter.Residue() {
		t.Fatal("cleanup-pending recovery binding or residue was lost")
	}
}

func TestEverySyntheticSideEffectFailureUsesTheOnlyFinalizer(t *testing.T) {
	stages := []string{
		"create_workspace", "transform", "create_capture_leaves", "register_launch", "create_container",
		"prepare_launch", "release_launch", "capture",
	}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			coordinator, clock, journal, adapter := newSyntheticHarness(t)
			adapter.FailAfter[stage] = contract.ErrorCapture
			output, err := coordinator.Execute(context.Background(), syntheticRequest(clock,
				"12341234123412341234123412341234", "43214321432143214321432143214321"))
			if err != nil || output.Result.Status != "failed" || output.Result.CredentialReleased || len(output.Credential) != 0 {
				t.Fatalf("stage %s output=%+v err=%v", stage, output.Result, err)
			}
			if adapter.Residue() {
				t.Fatalf("stage %s left synthetic residue", stage)
			}
			if absent, _ := journal.Absent(); !absent {
				t.Fatalf("stage %s retained recovery record after successful reconciliation", stage)
			}
		})
	}
}

func TestTransformationThresholdBlocksLaterLaunchPreparation(t *testing.T) {
	coordinator, clock, journal, adapter := newSyntheticHarness(t)
	adapter.StepNS = 0
	adapter.AdvanceByStage["transform"] = contract.TransformationPreparationLimitNS
	output, err := coordinator.Execute(context.Background(), syntheticRequest(clock,
		"abababababababababababababababab", "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"))
	if err != nil || output.Result.Status != "failed" ||
		output.Result.ErrorCode != contract.ErrorTransformationUnsupported || adapter.Residue() {
		t.Fatalf("result=%+v residue=%v err=%v", output.Result, adapter.Residue(), err)
	}
	for _, event := range adapter.Events {
		if event == "supervisor_artifact" || event == "create_capture_leaves" || event == "prepare_launch" {
			t.Fatalf("late transformation crossed launch preparation at event %q", event)
		}
	}
	if absent, absentErr := journal.Absent(); absentErr != nil || !absent {
		t.Fatalf("late transformation cleanup absent=%v err=%v", absent, absentErr)
	}
}

func TestCleanupFailurePrecedesCapturedCredentialAndRecoversBeforeNextAttempt(t *testing.T) {
	coordinator, clock, journal, adapter := newSyntheticHarness(t)
	adapter.FailBefore["remove_container"] = contract.ErrorCleanup
	first, err := coordinator.Execute(context.Background(), syntheticRequest(clock,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
	if err != nil || first.Result.Status != "cleanup_pending" || first.Result.CredentialReleased || len(first.Credential) != 0 {
		t.Fatalf("cleanup failure did not suppress credential: result=%+v err=%v", first.Result, err)
	}
	if journal.Record == nil || !adapter.Residue() {
		t.Fatal("cleanup failure did not retain exact recovery state and residue")
	}
	delete(adapter.FailBefore, "remove_container")
	second, err := coordinator.Execute(context.Background(), syntheticRequest(clock,
		"cccccccccccccccccccccccccccccccc", "dddddddddddddddddddddddddddddddd"))
	if err != nil || second.Result.Status != "ready" || adapter.Residue() {
		t.Fatalf("startup reconciliation did not recover then run: result=%+v err=%v", second.Result, err)
	}
	clearBytes(second.Credential)
}

func TestJournalFailureAfterMutationStillFinalizesInMemoryBinding(t *testing.T) {
	coordinator, clock, journal, adapter := newSyntheticHarness(t)
	journal.FailSaveAt = 3
	output, err := coordinator.Execute(context.Background(), syntheticRequest(clock,
		"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "ffffffffffffffffffffffffffffffff"))
	if err != nil || output.Result.Status != "failed" || adapter.Residue() {
		t.Fatalf("journal failpoint result=%+v err=%v residue=%v", output.Result, err, adapter.Residue())
	}
	if absent, _ := journal.Absent(); !absent {
		t.Fatal("journal failpoint retained recovery state after exact cleanup")
	}
}

func TestReceiptValidationPrecedesRecoveryRecordDeletion(t *testing.T) {
	_, clock, journal, adapter := newSyntheticHarness(t)
	record := recoveryFixture()
	if err := journal.Save(record); err != nil {
		t.Fatal(err)
	}
	_, err := (Finalizer{Clock: clock, Journal: journal, Cleanup: adapter}).Finalize(
		context.Background(), record, true,
	)
	var cleanup *CleanupError
	if !errors.As(err, &cleanup) || !reflect.DeepEqual(cleanup.Stages, []string{"receipt_incomplete"}) {
		t.Fatalf("unexpected finalizer error: %v", err)
	}
	if absent, absentErr := journal.Absent(); absentErr != nil || absent {
		t.Fatalf("invalid receipt crossed recovery deletion: absent=%v err=%v", absent, absentErr)
	}
}

func TestFinalizerClockFailureRetainsRecoveryRecord(t *testing.T) {
	_, _, journal, adapter := newSyntheticHarness(t)
	record := recoveryFixture()
	if err := journal.Save(record); err != nil {
		t.Fatal(err)
	}
	clock := &failAtClock{now: record.Deadline.T0NS, failAt: 1}
	_, err := (Finalizer{Clock: clock, Journal: journal, Cleanup: adapter}).Finalize(
		context.Background(), record, false,
	)
	var cleanup *CleanupError
	if !errors.As(err, &cleanup) || !reflect.DeepEqual(
		cleanup.Stages,
		[]string{"cleanup_clock_end", "cleanup_clock_start"},
	) {
		t.Fatalf("unexpected finalizer error: %v", err)
	}
	if absent, absentErr := journal.Absent(); absentErr != nil || absent {
		t.Fatalf("clock failure crossed recovery deletion: absent=%v err=%v", absent, absentErr)
	}
}

func TestProviderDeadlineSegmentsWithholdCredential(t *testing.T) {
	t.Run("capture stop T+75", func(t *testing.T) {
		coordinator, clock, _, adapter := newSyntheticHarness(t)
		adapter.StepNS = 0
		adapter.AdvanceByStage["capture"] = contract.CaptureWindowNS
		output, err := coordinator.Execute(context.Background(), syntheticRequest(clock,
			"11111111222222223333333344444444", "55555555666666667777777788888888"))
		if err != nil || output.Result.Status != "failed" || output.Result.ErrorCode != contract.ErrorDeadlineCapture || len(output.Credential) != 0 {
			t.Fatalf("capture deadline result=%+v err=%v", output.Result, err)
		}
	})
	t.Run("provider cleanup T+100", func(t *testing.T) {
		coordinator, clock, journal, adapter := newSyntheticHarness(t)
		adapter.StepNS = 0
		adapter.AdvanceByStage["verify_cleanup"] = contract.ProviderCleanupWindowNS
		output, err := coordinator.Execute(context.Background(), syntheticRequest(clock,
			"99999999aaaabbbbccccddddeeeeffff", "00000000111122223333444455556666"))
		if err != nil || output.Result.Status != "cleanup_pending" || output.Result.ErrorCode != contract.ErrorCleanup || len(output.Credential) != 0 {
			t.Fatalf("cleanup deadline result=%+v err=%v", output.Result, err)
		}
		if absent, absentErr := journal.Absent(); absentErr != nil || absent {
			t.Fatalf("T+100 cleanup deadline removed recovery state: absent=%v err=%v", absent, absentErr)
		}
	})
}

func TestFinalizerRejectsNilContext(t *testing.T) {
	_, clock, journal, adapter := newSyntheticHarness(t)
	if _, err := (Finalizer{Clock: clock, Journal: journal, Cleanup: adapter}).Finalize(nil, recoveryFixture(), false); err == nil {
		t.Fatal("nil finalizer context was accepted")
	}
}
