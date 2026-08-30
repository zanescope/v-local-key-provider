//go:build darwin

package shadowproduction

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	shadowmodel "github.com/zanescope/v-local-key-provider/internal/shadow"
	clockmodel "github.com/zanescope/v-local-key-provider/internal/shadowclock"
	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
)

type CoWGateSummary struct {
	Version                   string `json:"version"`
	Status                    string `json:"status"`
	BuildSetDigest            string `json:"build_set_digest"`
	SourceQualificationDigest string `json:"source_qualification_digest"`
	WorkspacePrepared         bool   `json:"workspace_prepared"`
	TransformationApplied     bool   `json:"transformation_applied"`
	TransformationMS          int64  `json:"transformation_ms"`
	CloneAbsent               bool   `json:"clone_absent"`
	WorkspaceAbsent           bool   `json:"workspace_absent"`
	RecoveryRecordAbsent      bool   `json:"recovery_record_absent"`
	SourceUnchanged           bool   `json:"source_unchanged"`
}

type CoWGate struct {
	Prelaunch *Prelaunch
	Journal   shadowmodel.Journal
	Locker    shadowmodel.Locker
	Clock     clockmodel.Clock
	NewID     func() (string, error)
}

const (
	coWGateVersion            = "v-local-shadow-cow-gate/v1"
	transformationGateVersion = "v-local-shadow-transformation-gate/v1"
)

type TransformationGate struct {
	CoWGate
	ApplyTransform func(context.Context, shadowmodel.RecoveryRecord) error
}

func gateOptionsDigest(version, build, source, account string) string {
	digest := sha256.Sum256([]byte(version + "\x00" + build + "\x00" + source + "\x00" + account))
	return hex.EncodeToString(digest[:])
}

func gateContextUntil(
	parent context.Context,
	clock clockmodel.Clock,
	absoluteNS uint64,
	detachCancellation bool,
) (context.Context, context.CancelFunc, error) {
	remaining, err := clockmodel.Remaining(clock, absoluteNS)
	if err != nil {
		return nil, nil, err
	}
	if detachCancellation {
		parent = context.WithoutCancel(parent)
	}
	if remaining <= 0 {
		ctx, cancel := context.WithCancel(parent)
		cancel()
		return ctx, func() {}, nil
	}
	ctx, cancel := context.WithTimeout(parent, remaining)
	return ctx, cancel, nil
}

func (value CoWGate) finalize(ctx context.Context, record *shadowmodel.RecoveryRecord, summary *CoWGateSummary) error {
	var failures []error
	record.State = shadowmodel.StateCleanupPending
	record.PendingAction = shadowmodel.ActionNone
	if err := value.Journal.Save(*record); err != nil {
		failures = append(failures, errors.New("CoW gate could not persist cleanup_pending"))
	}
	if err := value.Prelaunch.RemoveWorkspace(ctx, *record); err != nil {
		failures = append(failures, errors.New("CoW gate exact workspace cleanup failed"))
	}
	summary.WorkspaceAbsent = value.Prelaunch.WorkspaceAbsent(*record)
	summary.CloneAbsent = summary.WorkspaceAbsent
	summary.SourceUnchanged = value.Prelaunch.SourceUnchanged(ctx, *record)
	if !summary.WorkspaceAbsent || !summary.SourceUnchanged {
		failures = append(failures, errors.New("CoW gate residue or source drift was detected"))
		return errors.Join(failures...)
	}
	binding, err := value.Journal.Binding()
	if err != nil {
		failures = append(failures, errors.New("CoW gate recovery identity is unavailable"))
	} else if err := value.Journal.Remove(binding); err != nil {
		failures = append(failures, errors.New("CoW gate recovery removal failed"))
	}
	absent, err := value.Journal.Absent()
	if err != nil || !absent {
		failures = append(failures, errors.New("CoW gate recovery absence was not proven"))
	} else {
		summary.RecoveryRecordAbsent = true
	}
	return errors.Join(failures...)
}

func (value CoWGate) run(
	ctx context.Context,
	version string,
	applyTransform func(context.Context, shadowmodel.RecoveryRecord) error,
) (summary CoWGateSummary, err error) {
	summary.Version = version
	summary.Status = "failed"
	if (version != coWGateVersion && version != transformationGateVersion) || ctx == nil || value.Prelaunch == nil ||
		value.Journal == nil || value.Locker == nil || value.Clock == nil || value.NewID == nil {
		return summary, errors.New("CoW gate dependencies are incomplete")
	}
	qualified, err := value.Prelaunch.Inspector.Qualify(ctx, value.Prelaunch.SourcePath, value.Prelaunch.Bundle.Source)
	if err != nil {
		return summary, errors.New("CoW gate source qualification failed")
	}
	summary.BuildSetDigest = value.Prelaunch.Bundle.Digest
	summary.SourceQualificationDigest = qualified.QualificationDigest
	requestID, err := value.NewID()
	if err != nil || len(requestID) != 32 {
		return summary, errors.New("CoW gate request identity is invalid")
	}
	request := contract.Request{
		Version: contract.Version, Operation: "qualify", RequestID: requestID,
		BuildSetDigest: value.Prelaunch.Bundle.Digest, SourceQualificationDigest: qualified.QualificationDigest,
		CleanupRoute: contract.CleanupRouteDirect, AccountBindingID: value.Prelaunch.Account.BindingID,
		OptionsDigest: gateOptionsDigest(version, value.Prelaunch.Bundle.Digest, qualified.QualificationDigest, value.Prelaunch.Account.BindingID),
	}
	release, err := value.Locker.Acquire(ctx)
	if err != nil {
		return summary, errors.New("CoW gate could not acquire the exclusive attempt lock")
	}
	if release == nil {
		return summary, errors.New("CoW gate lock release is unavailable")
	}
	defer func() {
		if releaseErr := release(); releaseErr != nil {
			summary.Status = "failed"
			err = errors.Join(err, errors.New("CoW gate could not release the exclusive attempt lock"))
		}
	}()
	if _, loadErr := value.Journal.Load(); !errors.Is(loadErr, shadowmodel.ErrNoRecoveryRecord) {
		if loadErr == nil {
			return summary, errors.New("CoW gate is blocked by an existing recovery record")
		}
		return summary, errors.New("CoW gate recovery state is unreadable")
	}
	_, source, err := value.Prelaunch.Qualify(ctx, request)
	if err != nil {
		return summary, errors.New("CoW gate source drifted before mutation")
	}
	t0, err := value.Clock.NowNS()
	if err != nil || t0 == 0 {
		return summary, errors.New("CoW gate monotonic T0 is unavailable")
	}
	challengeID, err := value.NewID()
	if err != nil || len(challengeID) != 32 {
		return summary, errors.New("CoW gate challenge identity is invalid")
	}
	record := shadowmodel.RecoveryRecord{
		Version: 1, Operation: "execute", State: shadowmodel.StatePlanned, AttemptID: requestID, ChallengeID: challengeID,
		BuildSetDigest: request.BuildSetDigest, SourceQualificationDigest: request.SourceQualificationDigest,
		CleanupRoute: request.CleanupRoute, AccountBindingID: request.AccountBindingID, OptionsDigest: request.OptionsDigest,
		RootLeaf: "attempt-" + requestID, BundleID: "com.zanescope.vlocal.shadow." + requestID,
		Deadline: contract.NewDeadline(t0), ExpectedSecurityPosture: "sip_enabled_verified", Source: source,
		PendingAction: shadowmodel.ActionPrepareWorkspace, Resources: []contract.ResourceBinding{},
	}
	if err := value.Journal.Save(record); err != nil {
		return summary, errors.New("CoW gate could not persist planned recovery state")
	}
	operationCtx, cancelOperation, contextErr := gateContextUntil(
		ctx, value.Clock, record.Deadline.CaptureStopNS, false,
	)
	if contextErr != nil {
		operationCtx = ctx
	}
	if cancelOperation != nil {
		defer cancelOperation()
	}
	operationErr := contextErr
	var resources []contract.ResourceBinding
	if operationErr == nil {
		resources, operationErr = value.Prelaunch.CreateWorkspace(operationCtx, record)
	}
	if operationErr == nil {
		for _, resource := range resources {
			if bindErr := record.BindResource(resource); bindErr != nil {
				operationErr = bindErr
				break
			}
		}
	}
	if operationErr == nil {
		record.State = shadowmodel.StatePrepared
		record.PendingAction = shadowmodel.ActionNone
		operationErr = value.Journal.Save(record)
		summary.WorkspacePrepared = operationErr == nil
	}
	if operationErr == nil && applyTransform != nil {
		record.PendingAction = shadowmodel.ActionTransform
		operationErr = value.Journal.Save(record)
	}
	if operationErr == nil && applyTransform != nil {
		transformStart, clockErr := value.Clock.NowNS()
		if clockErr != nil || transformStart == 0 {
			operationErr = errors.New("transformation gate monotonic start is unavailable")
		} else {
			operationErr = applyTransform(operationCtx, record)
			summary.TransformationApplied = operationErr == nil
			if operationErr == nil {
				transformEnd, endErr := value.Clock.NowNS()
				if endErr != nil || transformEnd < transformStart {
					operationErr = errors.New("transformation gate monotonic end is unavailable")
				} else {
					duration := transformEnd - transformStart
					summary.TransformationMS = int64(duration / 1_000_000)
					if duration >= contract.TransformationPreparationLimitNS {
						operationErr = errors.New("transformation gate exceeded the fixed preparation threshold")
					}
				}
			}
		}
	}
	if operationErr == nil && applyTransform != nil {
		record.PendingAction = shadowmodel.ActionNone
		operationErr = value.Journal.Save(record)
	}
	cleanupCtx, cancelCleanup, cleanupContextErr := gateContextUntil(
		ctx, value.Clock, record.Deadline.ProviderCleanupNS, true,
	)
	if cancelCleanup != nil {
		defer cancelCleanup()
	}
	cleanupErr := cleanupContextErr
	if cleanupErr == nil {
		cleanupErr = value.finalize(cleanupCtx, &record, &summary)
	}
	if operationErr != nil || cleanupErr != nil {
		return summary, errors.Join(errors.New("CoW gate operation failed"), operationErr, cleanupErr)
	}
	summary.Status = "qualified"
	return summary, nil
}

func (value CoWGate) Run(ctx context.Context) (CoWGateSummary, error) {
	return value.run(ctx, coWGateVersion, nil)
}

func (value TransformationGate) Run(ctx context.Context) (CoWGateSummary, error) {
	apply := value.ApplyTransform
	if apply == nil && value.Prelaunch != nil {
		apply = value.Prelaunch.Transform
	}
	if apply == nil {
		return CoWGateSummary{Version: transformationGateVersion, Status: "failed"},
			errors.New("transformation gate dependencies are incomplete")
	}
	return value.CoWGate.run(ctx, transformationGateVersion, apply)
}
