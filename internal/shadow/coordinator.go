package shadow

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"

	clockmodel "github.com/zanescope/v-local-key-provider/internal/shadowclock"
	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
)

type Coordinator struct {
	config Config
}

func randomID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func NewCoordinator(config Config) (*Coordinator, error) {
	if config.Clock == nil || config.Journal == nil || config.Locker == nil || config.Adapter == nil || config.Cleanup == nil {
		return nil, errors.New("shadow coordinator dependencies are incomplete")
	}
	if config.CleanupRoute != contract.CleanupRouteDirect {
		return nil, errors.New("shadow cleanup route is not frozen")
	}
	if config.Cleanup.Route() != config.CleanupRoute {
		return nil, errors.New("shadow cleanup executor does not match the frozen route")
	}
	if config.ExpectedSecurityPosture != "sip_enabled_verified" && config.ExpectedSecurityPosture != "synthetic" {
		return nil, errors.New("shadow expected security posture is invalid")
	}
	if config.NewID == nil {
		config.NewID = randomID
	}
	return &Coordinator{config: config}, nil
}

func resultFor(request contract.Request, status, code string) contract.Result {
	return contract.Result{
		Version: contract.Version, RequestID: request.RequestID, Status: status,
		ErrorCode: code, CredentialReleased: false,
	}
}

func (value *Coordinator) Qualify(ctx context.Context, request contract.Request) (Output, error) {
	if value == nil || ctx == nil || ctx.Err() != nil || request.Validate() != nil || request.Operation != "qualify" {
		return Output{}, errors.New("invalid Shadow qualification request")
	}
	if request.BuildSetDigest != value.config.BuildSetDigest || request.CleanupRoute != value.config.CleanupRoute {
		return Output{Result: resultFor(request, "failed", contract.ErrorBuildSetMismatch)}, nil
	}
	qualification, source, err := value.config.Adapter.Qualify(ctx, request)
	if err != nil {
		return Output{Result: resultFor(request, "failed", failureCode(err, contract.ErrorSourceDrift))}, nil
	}
	if err := source.validate(); err != nil || source.ManifestDigest != qualification.SourceQualificationDigest ||
		qualification.BuildSetDigest != value.config.BuildSetDigest || qualification.CleanupRoute != value.config.CleanupRoute ||
		qualification.AccountBindingID != request.AccountBindingID || qualification.OptionsDigest != request.OptionsDigest {
		return Output{Result: resultFor(request, "failed", contract.ErrorSourceDrift)}, nil
	}
	qualification.ProductionRouteEnabled = value.config.ProductionRouteEnabled
	if err := qualification.Validate(); err != nil {
		return Output{Result: resultFor(request, "failed", contract.ErrorInternal)}, nil
	}
	result := resultFor(request, "qualified", contract.ErrorNone)
	result.Qualification = &qualification
	return Output{Result: result}, result.Validate()
}

func contextUntil(parent context.Context, clock clockmodel.Clock, absoluteNS uint64) (context.Context, context.CancelFunc, error) {
	remaining, err := clockmodel.Remaining(clock, absoluteNS)
	if err != nil {
		return nil, nil, err
	}
	if remaining <= 0 {
		ctx, cancel := context.WithCancel(parent)
		cancel()
		return ctx, func() {}, nil
	}
	ctx, cancel := context.WithTimeout(parent, remaining)
	return ctx, cancel, nil
}

func nowBefore(clock clockmodel.Clock, absoluteNS uint64) bool {
	before, err := clockmodel.Before(clock, absoluteNS)
	return err == nil && before
}

func (value *Coordinator) savePending(record *RecoveryRecord, action string) error {
	if err := record.SetPending(action); err != nil {
		return err
	}
	return value.config.Journal.Save(*record)
}

func (value *Coordinator) saveCompleted(record *RecoveryRecord, state string, resources ...contract.ResourceBinding) error {
	next := cloneRecoveryRecord(*record)
	for _, resource := range resources {
		if err := next.BindResource(resource); err != nil {
			return err
		}
	}
	next.PendingAction = ActionNone
	next.State = state
	if err := next.Validate(); err != nil {
		return err
	}
	*record = next
	return value.config.Journal.Save(next)
}

func (value *Coordinator) recoverPrevious(ctx context.Context) error {
	record, err := value.config.Journal.Load()
	if errors.Is(err, ErrNoRecoveryRecord) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = (Finalizer{Clock: value.config.Clock, Journal: value.config.Journal, Cleanup: value.config.Cleanup}).Finalize(ctx, record, false)
	return err
}

func (value *Coordinator) Execute(parent context.Context, request contract.Request) (output Output, resultErr error) {
	if value == nil || parent == nil || parent.Err() != nil || request.Validate() != nil ||
		(request.Operation != "execute" && request.Operation != "synthetic_execute") {
		return Output{}, errors.New("invalid Shadow execution request")
	}
	if request.BuildSetDigest != value.config.BuildSetDigest || request.CleanupRoute != value.config.CleanupRoute {
		return Output{Result: resultFor(request, "failed", contract.ErrorBuildSetMismatch)}, nil
	}
	if request.Operation == "execute" && !value.config.ProductionRouteEnabled ||
		request.Operation == "synthetic_execute" && !value.config.SyntheticRouteEnabled {
		return Output{Result: resultFor(request, "failed", contract.ErrorProductionRouteDisabled)}, nil
	}
	if request.Deadline == nil || !nowBefore(value.config.Clock, request.Deadline.CaptureStopNS) {
		return Output{Result: resultFor(request, "failed", contract.ErrorDeadlineCapture)}, nil
	}
	lockContext, cancelLock, err := contextUntil(parent, value.config.Clock, request.Deadline.CaptureStopNS)
	if err != nil {
		return Output{Result: resultFor(request, "failed", contract.ErrorInternal)}, nil
	}
	defer cancelLock()
	release, err := value.config.Locker.Acquire(lockContext)
	if err != nil {
		return Output{Result: resultFor(request, "failed", contract.ErrorDeadlineCapture)}, nil
	}
	if release == nil {
		return Output{Result: resultFor(request, "failed", contract.ErrorInternal)}, nil
	}
	defer func() {
		if err := release(); err != nil {
			clearBytes(output.Credential)
			output.Credential = nil
			// A cleanup_pending result is the stronger safety fact. Lock-release
			// failure must not erase the durable recovery warning and misreport
			// an attempt with possible residue as an ordinary failure.
			if resultErr == nil && output.Result.Status != "cleanup_pending" {
				failed := resultFor(request, "failed", contract.ErrorInternal)
				failed.Receipt = output.Result.Receipt
				output = Output{Result: failed}
				resultErr = failed.Validate()
			}
		}
	}()
	cleanupContext, cancelCleanup, err := contextUntil(
		context.WithoutCancel(parent), value.config.Clock, request.Deadline.ProviderCleanupNS,
	)
	if err != nil {
		return Output{Result: resultFor(request, "failed", contract.ErrorInternal)}, nil
	}
	defer cancelCleanup()
	if err := value.recoverPrevious(cleanupContext); err != nil {
		return Output{Result: resultFor(request, "cleanup_pending", contract.ErrorCleanup)}, nil
	}
	return value.executeLocked(parent, request)
}

func (value *Coordinator) executeLocked(parent context.Context, request contract.Request) (Output, error) {
	start, err := value.config.Clock.NowNS()
	if err != nil || start < request.Deadline.T0NS || start >= request.Deadline.CaptureStopNS {
		return Output{Result: resultFor(request, "failed", contract.ErrorDeadlineCapture)}, nil
	}
	attemptID, err := value.config.NewID()
	if err != nil || len(attemptID) != 32 {
		return Output{Result: resultFor(request, "failed", contract.ErrorInternal)}, nil
	}
	stageContext, cancelStage, err := contextUntil(parent, value.config.Clock, request.Deadline.CaptureStopNS)
	if err != nil {
		return Output{Result: resultFor(request, "failed", contract.ErrorInternal)}, nil
	}
	defer cancelStage()
	source, err := value.config.Adapter.Requalify(stageContext, request)
	if err != nil || source.validate() != nil || source.ManifestDigest != request.SourceQualificationDigest {
		return Output{Result: resultFor(request, "failed", contract.ErrorSourceDrift)}, nil
	}
	record := RecoveryRecord{
		Version: recoveryRecordVersion, Operation: request.Operation, State: StatePlanned, AttemptID: attemptID, ChallengeID: request.ChallengeID,
		BuildSetDigest: request.BuildSetDigest, SourceQualificationDigest: request.SourceQualificationDigest,
		CleanupRoute: request.CleanupRoute, AccountBindingID: request.AccountBindingID, OptionsDigest: request.OptionsDigest,
		RootLeaf: "attempt-" + attemptID, BundleID: "com.zanescope.vlocal.shadow." + attemptID,
		Deadline: *request.Deadline, ExpectedSecurityPosture: value.config.ExpectedSecurityPosture,
		Source: source, PendingAction: ActionNone, Resources: []contract.ResourceBinding{},
	}
	if err := value.config.Journal.Save(record); err != nil {
		return Output{Result: resultFor(request, "failed", contract.ErrorInternal)}, nil
	}
	prepareStart, err := value.config.Clock.NowNS()
	if err != nil {
		return value.finalizeFailure(parent, request, record, contract.ErrorInternal, nil)
	}
	if err := value.savePending(&record, ActionPrepareWorkspace); err != nil {
		return value.finalizeFailure(parent, request, record, contract.ErrorInternal, nil)
	}
	workspaceResources, err := value.config.Adapter.CreateWorkspace(stageContext, record)
	if err != nil {
		return value.finalizeFailure(parent, request, record, failureCode(err, contract.ErrorWorkspacePrepare), nil)
	}
	if err := value.saveCompleted(&record, StatePrepared, workspaceResources...); err != nil {
		return value.finalizeFailure(parent, request, record, contract.ErrorInternal, nil)
	}
	prepareMS, err := elapsedMS(value.config.Clock, prepareStart)
	if err != nil {
		return value.finalizeFailure(parent, request, record, contract.ErrorInternal, nil)
	}
	record.Timings.PrepareMS = prepareMS
	transformStart, err := value.config.Clock.NowNS()
	if err != nil {
		return value.finalizeFailure(parent, request, record, contract.ErrorInternal, nil)
	}
	if err := value.savePending(&record, ActionTransform); err != nil {
		return value.finalizeFailure(parent, request, record, contract.ErrorInternal, nil)
	}
	if err := value.config.Adapter.Transform(stageContext, record); err != nil {
		return value.finalizeFailure(parent, request, record, failureCode(err, contract.ErrorTransformationUnsupported), nil)
	}
	transformMS, err := elapsedMS(value.config.Clock, transformStart)
	if err != nil {
		return value.finalizeFailure(parent, request, record, contract.ErrorInternal, nil)
	}
	record.Timings.TransformMS = transformMS
	if transformMS >= int64(contract.TransformationPreparationLimitNS/1_000_000) {
		return value.finalizeFailure(parent, request, record, contract.ErrorTransformationUnsupported, nil)
	}
	supervisorResource, err := value.config.Adapter.SupervisorArtifact(stageContext, record)
	if err != nil || record.BindResource(supervisorResource) != nil {
		return value.finalizeFailure(parent, request, record, contract.ErrorSupervisor, nil)
	}
	if err := value.savePending(&record, ActionCreateLeaves); err != nil {
		return value.finalizeFailure(parent, request, record, contract.ErrorInternal, nil)
	}
	leaves, err := value.config.Adapter.CreateCaptureLeaves(stageContext, record)
	if err != nil {
		return value.finalizeFailure(parent, request, record, contract.ErrorWorkspacePrepare, nil)
	}
	if err := value.saveCompleted(&record, StatePrepared, leaves...); err != nil {
		return value.finalizeFailure(parent, request, record, contract.ErrorInternal, nil)
	}
	if err := value.savePending(&record, ActionRegisterLaunch); err != nil {
		return value.finalizeFailure(parent, request, record, contract.ErrorInternal, nil)
	}
	if err := value.config.Adapter.RegisterLaunch(stageContext, record); err != nil {
		return value.finalizeFailure(parent, request, record, contract.ErrorSupervisor, nil)
	}
	if err := value.saveCompleted(&record, StatePrepared); err != nil {
		return value.finalizeFailure(parent, request, record, contract.ErrorInternal, nil)
	}
	if err := value.savePending(&record, ActionCreateContainer); err != nil {
		return value.finalizeFailure(parent, request, record, contract.ErrorInternal, nil)
	}
	container, err := value.config.Adapter.CreateContainer(stageContext, record)
	if err != nil {
		return value.finalizeFailure(parent, request, record, contract.ErrorWorkspacePrepare, nil)
	}
	if err := value.saveCompleted(&record, StatePrepared, container); err != nil {
		return value.finalizeFailure(parent, request, record, contract.ErrorInternal, nil)
	}
	launchStart, err := value.config.Clock.NowNS()
	if err != nil {
		return value.finalizeFailure(parent, request, record, contract.ErrorInternal, nil)
	}
	if err := value.savePending(&record, ActionPrepareLaunch); err != nil {
		return value.finalizeFailure(parent, request, record, contract.ErrorInternal, nil)
	}
	process, err := value.config.Adapter.PrepareLaunch(stageContext, record, func(supervisor SupervisorProcessBinding) error {
		if err := record.BindSupervisor(supervisor); err != nil {
			return err
		}
		return value.config.Journal.Save(record)
	}, func(bound contract.ProcessBinding) error {
		if err := record.BindProcess(bound); err != nil {
			return err
		}
		return value.config.Journal.Save(record)
	})
	if err != nil || record.Supervisor == nil || record.Process == nil || *record.Process != process {
		return value.finalizeFailure(parent, request, record, contract.ErrorSupervisor, nil)
	}
	if err := value.savePending(&record, ActionReleaseLaunch); err != nil {
		return value.finalizeFailure(parent, request, record, contract.ErrorInternal, nil)
	}
	if err := value.config.Adapter.ReleaseLaunch(stageContext, record); err != nil {
		return value.finalizeFailure(parent, request, record, contract.ErrorSupervisor, nil)
	}
	if err := value.saveCompleted(&record, StateActive); err != nil {
		return value.finalizeFailure(parent, request, record, contract.ErrorInternal, nil)
	}
	credential, captureErr := value.config.Adapter.Capture(stageContext, record)
	launchCaptureMS, timingErr := elapsedMS(value.config.Clock, launchStart)
	if timingErr == nil {
		record.Timings.LaunchCaptureMS = launchCaptureMS
	}
	code := contract.ErrorNone
	if timingErr != nil {
		code = contract.ErrorInternal
	} else if captureErr != nil {
		code = failureCode(captureErr, contract.ErrorCapture)
	} else if !nowBefore(value.config.Clock, request.Deadline.CaptureStopNS) {
		code = contract.ErrorDeadlineCapture
	} else if err := value.config.Adapter.ValidateCredential(credential); err != nil {
		code = contract.ErrorCredentialInvalid
	}
	if code != contract.ErrorNone {
		return value.finalizeFailure(parent, request, record, code, credential)
	}
	return value.finalizeSuccess(parent, request, record, credential, start)
}

func (value *Coordinator) runFinalizer(parent context.Context, request contract.Request, record RecoveryRecord, requireReceipt bool) (*contract.CleanupReceipt, error) {
	ctx, cancel, err := contextUntil(
		context.WithoutCancel(parent), value.config.Clock, request.Deadline.ProviderCleanupNS,
	)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return (Finalizer{Clock: value.config.Clock, Journal: value.config.Journal, Cleanup: value.config.Cleanup}).Finalize(ctx, record, requireReceipt)
}

func (value *Coordinator) finalizeFailure(parent context.Context, request contract.Request, record RecoveryRecord, code string, credential []byte) (Output, error) {
	defer clearBytes(credential)
	receipt, cleanupErr := value.runFinalizer(parent, request, record, false)
	if cleanupErr != nil {
		return Output{Result: resultFor(request, "cleanup_pending", contract.ErrorCleanup)}, nil
	}
	if !nowBefore(value.config.Clock, request.Deadline.ReturnNS) {
		result := resultFor(request, "failed", contract.ErrorDeadlinePublication)
		result.Receipt = receipt
		return Output{Result: result}, result.Validate()
	}
	result := resultFor(request, "failed", code)
	result.Receipt = receipt
	return Output{Result: result}, result.Validate()
}

func (value *Coordinator) finalizeSuccess(parent context.Context, request contract.Request, record RecoveryRecord, credential []byte, start uint64) (Output, error) {
	receipt, cleanupErr := value.runFinalizer(parent, request, record, true)
	if cleanupErr != nil {
		clearBytes(credential)
		return Output{Result: resultFor(request, "cleanup_pending", contract.ErrorCleanup)}, nil
	}
	if !nowBefore(value.config.Clock, request.Deadline.ReturnNS) {
		clearBytes(credential)
		result := resultFor(request, "failed", contract.ErrorDeadlinePublication)
		result.Receipt = receipt
		return Output{Result: result}, result.Validate()
	}
	if !nowBefore(value.config.Clock, request.Deadline.ProviderCleanupNS) {
		clearBytes(credential)
		result := resultFor(request, "failed", contract.ErrorDeadlineProviderCleanup)
		result.Receipt = receipt
		return Output{Result: result}, result.Validate()
	}
	providerTotalMS, timingErr := elapsedMS(value.config.Clock, start)
	if timingErr != nil {
		clearBytes(credential)
		result := resultFor(request, "failed", contract.ErrorInternal)
		result.Receipt = receipt
		return Output{Result: result}, result.Validate()
	}
	receipt.Timings.ProviderTotalMS = providerTotalMS
	if err := receipt.Validate(); err != nil {
		clearBytes(credential)
		return Output{Result: resultFor(request, "failed", contract.ErrorInternal)}, nil
	}
	released := append([]byte(nil), credential...)
	clearBytes(credential)
	result := resultFor(request, "ready", contract.ErrorNone)
	result.CredentialReleased = true
	result.Receipt = receipt
	if err := result.Validate(); err != nil {
		clearBytes(released)
		return Output{}, err
	}
	return Output{Result: result, Credential: released}, nil
}
