package shadow

import (
	"context"
	"errors"
	"sort"
	"strings"

	clockmodel "github.com/zanescope/v-local-key-provider/internal/shadowclock"
	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
)

type CleanupError struct {
	Stages []string
}

func (value *CleanupError) Error() string {
	return "shadow cleanup did not reconcile fixed stages: " + strings.Join(value.Stages, ",")
}

type Finalizer struct {
	Clock   clockmodel.Clock
	Journal Journal
	Cleanup CleanupExecutor
}

func cleanupCompleteExceptRecovery(value contract.CleanupFacts) bool {
	value.RecoveryRecordAbsent = true
	return value.Complete()
}

func recoveryBinding(record *RecoveryRecord, journal Journal) (contract.ResourceBinding, error) {
	for _, resource := range record.Resources {
		if resource.Kind == "recovery_record" && resource.Leaf == "recovery.json" {
			return resource, nil
		}
	}
	binding, err := journal.Binding()
	if err != nil {
		return contract.ResourceBinding{}, err
	}
	if err := record.BindResource(binding); err != nil {
		return contract.ResourceBinding{}, err
	}
	return binding, nil
}

func elapsedMS(clock clockmodel.Clock, start uint64) (int64, error) {
	now, err := clock.NowNS()
	if err != nil || start == 0 || now < start || now-start > contract.ReturnWindowNS {
		return 0, errors.New("shadow timing clock is invalid")
	}
	return int64((now - start) / 1_000_000), nil
}

func receiptFor(record RecoveryRecord, facts contract.CleanupFacts) *contract.CleanupReceipt {
	return &contract.CleanupReceipt{
		Version: contract.Version, Operation: record.Operation, AttemptID: record.AttemptID, ChallengeID: record.ChallengeID,
		BuildSetDigest: record.BuildSetDigest, SourceQualificationDigest: record.SourceQualificationDigest,
		CleanupRoute: record.CleanupRoute, AccountBindingID: record.AccountBindingID, OptionsDigest: record.OptionsDigest,
		RootLeaf: record.RootLeaf, BundleID: record.BundleID,
		Resources: append([]contract.ResourceBinding(nil), record.Resources...), Process: record.Process,
		Cleanup: facts, Timings: record.Timings,
	}
}

func (value Finalizer) Finalize(ctx context.Context, record RecoveryRecord, requireReceipt bool) (*contract.CleanupReceipt, error) {
	if ctx == nil || value.Clock == nil || value.Journal == nil || value.Cleanup == nil || record.Validate() != nil {
		return nil, &CleanupError{Stages: []string{"finalizer_input"}}
	}
	failed := map[string]bool{}
	mark := func(stage string, err error) {
		if err != nil {
			failed[stage] = true
		}
	}
	mutationAllowed := func() bool {
		if ctx.Err() != nil || !nowBefore(value.Clock, record.Deadline.ProviderCleanupNS) {
			failed["provider_cleanup_deadline"] = true
			return false
		}
		return true
	}
	runMutation := func(stage string, action func() error) {
		if mutationAllowed() {
			mark(stage, action())
		}
	}
	start, startErr := value.Clock.NowNS()
	mark("cleanup_clock_start", startErr)
	record.State = StateCleanupPending
	record.PendingAction = ActionNone
	runMutation("journal_cleanup_pending", func() error { return value.Journal.Save(record) })
	runMutation("stop_capture", func() error { return value.Cleanup.StopCapture(ctx, record) })
	processStopped := false
	if mutationAllowed() {
		var stopErr error
		processStopped, stopErr = value.Cleanup.StopSupervisor(ctx, record)
		mark("stop_supervisor", stopErr)
	}
	runMutation("unregister_launch", func() error { return value.Cleanup.UnregisterLaunch(ctx, record) })
	runMutation("remove_container", func() error { return value.Cleanup.RemoveContainer(ctx, record) })
	runMutation("remove_leaves", func() error { return value.Cleanup.RemoveLeaves(ctx, record) })
	if processStopped {
		runMutation("remove_workspace", func() error { return value.Cleanup.RemoveWorkspace(ctx, record) })
	} else {
		failed["process_not_stopped"] = true
	}
	facts, verifyErr := value.Cleanup.VerifyCleanup(ctx, record)
	mark("verify_cleanup", verifyErr)
	if !cleanupCompleteExceptRecovery(facts) {
		failed["verify_residue"] = true
	}
	binding, bindingErr := recoveryBinding(&record, value.Journal)
	mark("bind_recovery_record", bindingErr)
	// Freeze and validate all receipt fields while the recovery record is still
	// durable. Recovery-record deletion is the final irreversible publication
	// step, so a structurally incomplete success receipt must not cross it.
	cleanupMS, timingErr := elapsedMS(value.Clock, start)
	mark("cleanup_clock_end", timingErr)
	if timingErr == nil {
		record.Timings.CleanupMS = cleanupMS
	}
	if len(failed) == 0 && requireReceipt {
		provisional := facts
		provisional.RecoveryRecordAbsent = true
		mark("receipt_incomplete", receiptFor(record, provisional).Validate())
	}
	if len(failed) == 0 {
		runMutation("remove_recovery_record", func() error { return value.Journal.Remove(binding) })
		if len(failed) == 0 {
			absent, absentErr := value.Journal.Absent()
			mark("verify_recovery_absent", absentErr)
			if !absent {
				failed["verify_recovery_absent"] = true
			} else {
				facts.RecoveryRecordAbsent = true
			}
		}
	}
	if len(failed) != 0 {
		stages := make([]string, 0, len(failed))
		for stage := range failed {
			stages = append(stages, stage)
		}
		sort.Strings(stages)
		return nil, &CleanupError{Stages: stages}
	}
	receipt := receiptFor(record, facts)
	if err := receipt.Validate(); err != nil {
		if requireReceipt {
			return nil, &CleanupError{Stages: []string{"receipt_incomplete"}}
		}
		return nil, nil
	}
	return receipt, nil
}
