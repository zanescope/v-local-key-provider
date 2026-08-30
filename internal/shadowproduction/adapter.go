//go:build darwin

package shadowproduction

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	shadowmodel "github.com/zanescope/v-local-key-provider/internal/shadow"
	shadowaccount "github.com/zanescope/v-local-key-provider/internal/shadowaccount"
	shadowcontainer "github.com/zanescope/v-local-key-provider/internal/shadowcontainer"
	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
	shadowlaunch "github.com/zanescope/v-local-key-provider/internal/shadowlaunch"
	shadowsupervisor "github.com/zanescope/v-local-key-provider/internal/shadowsupervisor"
)

const maxLaunchExecutableBytes int64 = 256 * 1024 * 1024

// CaptureRuntime owns only the attempt-bound hook/socket leaves and transient
// candidate bytes. It may not own process, launch, container, or workspace
// cleanup, which remain fixed stages of the coordinator finalizer.
type CaptureRuntime interface {
	Validate() error
	CreateLeaves(context.Context, shadowaccount.Record, shadowmodel.RecoveryRecord) ([]contract.ResourceBinding, error)
	Capture(context.Context, shadowaccount.Record, shadowmodel.RecoveryRecord) ([]byte, error)
	ValidateCredential([]byte) error
	Stop(context.Context, shadowmodel.RecoveryRecord) error
	RemoveLeaves(context.Context, shadowaccount.Record, shadowmodel.RecoveryRecord) error
	LeavesAbsent(context.Context, shadowaccount.Record, shadowmodel.RecoveryRecord) (hookAbsent, socketAbsent bool, err error)
}

// ProcessFacts are independently observed facts for the exact bindings in one
// recovery record. Implementations must reject PID reuse and may not scan by
// process name or bundle-ID prefix.
type ProcessFacts struct {
	ProcessAbsent    bool
	SupervisorAbsent bool
}

type ProcessRuntime interface {
	Absent(context.Context, shadowmodel.RecoveryRecord) (ProcessFacts, error)
}

type SupervisorSession interface {
	Prepare(context.Context) (shadowsupervisor.Frame, error)
	Release(context.Context) error
	Stop(context.Context) (bool, error)
	CloseProvider(context.Context) (bool, error)
}

type SupervisorStarter func(
	context.Context,
	shadowsupervisor.StartConfig,
) (SupervisorSession, shadowsupervisor.Frame, error)

type RuntimeDependencies struct {
	Launch          shadowlaunch.Runtime
	Container       shadowcontainer.Runtime
	Capture         CaptureRuntime
	Processes       ProcessRuntime
	StartSupervisor SupervisorStarter
}

type activeSupervisor struct {
	session    SupervisorSession
	supervisor shadowmodel.SupervisorProcessBinding
	process    *contract.ProcessBinding
}

// Adapter is the production-capable platform composition. Merely constructing
// it never enables the production route; NewDisabledCoordinator below is the
// only coordinator assembly exposed by this package at the automation stage.
type Adapter struct {
	Prelaunch      *Prelaunch
	ExecutableLeaf string
	Launch         shadowlaunch.Runtime
	Container      shadowcontainer.Runtime
	CaptureRuntime CaptureRuntime
	Processes      ProcessRuntime
	start          SupervisorStarter

	mu       sync.Mutex
	sessions map[string]activeSupervisor
}

var _ shadowmodel.Adapter = (*Adapter)(nil)
var _ shadowmodel.CleanupExecutor = (*Adapter)(nil)

func safeExecutableLeaf(value string) bool {
	return value != "" && value != "." && !filepath.IsAbs(value) && !strings.Contains(value, "\\") &&
		filepath.Clean(value) == value && value != ".." && !strings.HasPrefix(value, ".."+string(filepath.Separator))
}

func defaultSupervisorStarter(
	ctx context.Context,
	config shadowsupervisor.StartConfig,
) (SupervisorSession, shadowsupervisor.Frame, error) {
	return shadowsupervisor.Start(ctx, config)
}

func NewAdapter(prelaunch *Prelaunch, executableLeaf string, dependencies RuntimeDependencies) (*Adapter, error) {
	if prelaunch == nil || prelaunch.Account.Validate() != nil || shadowaccount.Revalidate(prelaunch.Account) != nil ||
		prelaunch.Bundle.Digest == "" || prelaunch.Bundle.Root == "" || !safeExecutableLeaf(executableLeaf) ||
		dependencies.Launch.Validate() != nil || dependencies.Capture == nil ||
		dependencies.Capture.Validate() != nil || dependencies.Processes == nil {
		return nil, errors.New("production adapter configuration is incomplete")
	}
	if dependencies.StartSupervisor == nil {
		dependencies.StartSupervisor = defaultSupervisorStarter
	}
	return &Adapter{
		Prelaunch: prelaunch, ExecutableLeaf: executableLeaf,
		Launch: dependencies.Launch, Container: dependencies.Container,
		CaptureRuntime: dependencies.Capture, Processes: dependencies.Processes,
		start: dependencies.StartSupervisor, sessions: map[string]activeSupervisor{},
	}, nil
}

func (value *Adapter) bound(ctx context.Context, record shadowmodel.RecoveryRecord) bool {
	return value != nil && value.Prelaunch != nil && ctx != nil && ctx.Err() == nil && record.Validate() == nil &&
		record.BuildSetDigest == value.Prelaunch.Bundle.Digest &&
		record.AccountBindingID == value.Prelaunch.Account.BindingID
}

func (value *Adapter) Qualify(ctx context.Context, request contract.Request) (contract.Qualification, shadowmodel.SourceBinding, error) {
	return value.Prelaunch.Qualify(ctx, request)
}

func (value *Adapter) Requalify(ctx context.Context, request contract.Request) (shadowmodel.SourceBinding, error) {
	return value.Prelaunch.Requalify(ctx, request)
}

func (value *Adapter) CreateWorkspace(ctx context.Context, record shadowmodel.RecoveryRecord) ([]contract.ResourceBinding, error) {
	if !value.bound(ctx, record) {
		return nil, shadowmodel.NewFailure(contract.ErrorWorkspacePrepare)
	}
	return value.Prelaunch.CreateWorkspace(ctx, record)
}

func (value *Adapter) Transform(ctx context.Context, record shadowmodel.RecoveryRecord) error {
	if !value.bound(ctx, record) {
		return shadowmodel.NewFailure(contract.ErrorTransformationUnsupported)
	}
	return value.Prelaunch.Transform(ctx, record)
}

func (value *Adapter) SupervisorArtifact(ctx context.Context, record shadowmodel.RecoveryRecord) (contract.ResourceBinding, error) {
	if !value.bound(ctx, record) {
		return contract.ResourceBinding{}, shadowmodel.NewFailure(contract.ErrorSupervisor)
	}
	return value.Prelaunch.SupervisorArtifact(ctx, record)
}

func (value *Adapter) CreateCaptureLeaves(ctx context.Context, record shadowmodel.RecoveryRecord) ([]contract.ResourceBinding, error) {
	if !value.bound(ctx, record) {
		return nil, shadowmodel.NewFailure(contract.ErrorWorkspacePrepare)
	}
	return value.CaptureRuntime.CreateLeaves(ctx, value.Prelaunch.Account, record)
}

func (value *Adapter) RegisterLaunch(ctx context.Context, record shadowmodel.RecoveryRecord) error {
	if !value.bound(ctx, record) {
		return shadowmodel.NewFailure(contract.ErrorSupervisor)
	}
	return value.Launch.RegisterExact(ctx, value.Prelaunch.Account, record)
}

func (value *Adapter) CreateContainer(ctx context.Context, record shadowmodel.RecoveryRecord) (contract.ResourceBinding, error) {
	if !value.bound(ctx, record) {
		return contract.ResourceBinding{}, shadowmodel.NewFailure(contract.ErrorWorkspacePrepare)
	}
	return value.Container.Create(ctx, value.Prelaunch.Account, record)
}

func digestExactExecutable(ctx context.Context, path string) (string, error) {
	if ctx == nil || ctx.Err() != nil {
		return "", errors.New("production launch executable digest context is unavailable")
	}
	before, err := os.Lstat(path)
	resolved, resolveErr := filepath.EvalSymlinks(path)
	if err != nil || resolveErr != nil || resolved != path || !before.Mode().IsRegular() ||
		before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0o111 == 0 || before.Size() <= 0 ||
		before.Size() > maxLaunchExecutableBytes {
		return "", errors.New("production launch executable binding is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("production launch executable is unavailable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return "", errors.New("production launch executable drifted before read")
	}
	digest := sha256.New()
	buffer := make([]byte, 64*1024)
	limited := io.LimitReader(file, maxLaunchExecutableBytes+1)
	var read int64
	for {
		if err := ctx.Err(); err != nil {
			return "", errors.New("production launch executable digest was cancelled")
		}
		count, readErr := limited.Read(buffer)
		if count > 0 {
			written, writeErr := digest.Write(buffer[:count])
			if writeErr != nil || written != count {
				return "", errors.New("production launch executable digest failed")
			}
			read += int64(count)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return "", errors.New("production launch executable is unreadable")
		}
	}
	after, afterErr := file.Stat()
	if read != before.Size() || read > maxLaunchExecutableBytes || afterErr != nil ||
		!os.SameFile(opened, after) || after.Size() != opened.Size() || after.Mode() != opened.Mode() {
		return "", errors.New("production launch executable drifted during read")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func prerequisite(record shadowmodel.RecoveryRecord, kind, leaf string) bool {
	binding, found := resource(record, kind)
	return found && binding.Leaf == leaf
}

func capturePrerequisites(record shadowmodel.RecoveryRecord) bool {
	root := record.RootLeaf
	if !prerequisite(record, "workspace", root) ||
		!prerequisite(record, "clone_app", filepath.ToSlash(filepath.Join(root, "WeChat.app"))) ||
		!prerequisite(record, "container", record.BundleID) {
		return false
	}
	for _, kind := range []string{"hook", "socket"} {
		binding, found := resource(record, kind)
		if !found || !strings.HasPrefix(binding.Leaf, root+"/") {
			return false
		}
	}
	return true
}

func (value *Adapter) launchConfig(ctx context.Context, record shadowmodel.RecoveryRecord) (shadowsupervisor.StartConfig, error) {
	if ctx == nil || ctx.Err() != nil || record.PendingAction != shadowmodel.ActionPrepareLaunch ||
		record.Supervisor != nil || record.Process != nil ||
		record.SupervisorLeaseNS != 0 || !capturePrerequisites(record) {
		return shadowsupervisor.StartConfig{}, errors.New("production launch record is not at the prepare boundary")
	}
	expectedSupervisor, found := resource(record, "supervisor")
	currentSupervisor, err := value.Prelaunch.SupervisorArtifact(ctx, record)
	if err != nil || !found || currentSupervisor != expectedSupervisor || currentSupervisor.DigestSHA256 == "" {
		return shadowsupervisor.StartConfig{}, errors.New("production supervisor artifact drifted before launch")
	}
	workspace := filepath.Join(value.Prelaunch.Account.SecurityRoot, record.RootLeaf)
	executable := filepath.Join(workspace, "WeChat.app", filepath.FromSlash(value.ExecutableLeaf))
	if !strings.HasPrefix(executable, workspace+string(filepath.Separator)) {
		return shadowsupervisor.StartConfig{}, errors.New("production launch executable escaped its workspace")
	}
	executableDigest, err := digestExactExecutable(ctx, executable)
	if err != nil {
		return shadowsupervisor.StartConfig{}, err
	}
	return shadowsupervisor.StartConfig{
		SupervisorPath:   filepath.Join(value.Prelaunch.Bundle.Root, currentSupervisor.Leaf),
		SupervisorDigest: currentSupervisor.DigestSHA256,
		Init: shadowsupervisor.Frame{
			Version: shadowsupervisor.ProtocolVersion, Type: "init", Mode: "preexec",
			LeaseDeadlineNS: record.Deadline.CaptureStopNS, Executable: executable,
			CloneRoot: workspace, ExecutableDigest: executableDigest,
		},
		ResponseTimeout: 5 * time.Second,
	}, nil
}

func supervisorBinding(frame shadowsupervisor.Frame, expectedDigest string) (shadowmodel.SupervisorProcessBinding, error) {
	binding := shadowmodel.SupervisorProcessBinding{
		PID: frame.SupervisorPID, StartMonotonicNS: frame.SupervisorStartNS, Digest: frame.SupervisorDigest,
	}
	if frame.Version != shadowsupervisor.ProtocolVersion || frame.Type != "supervisor_bound" ||
		frame.Mode != "" || frame.LeaseDeadlineNS != 0 || frame.Executable != "" || frame.CloneRoot != "" ||
		frame.ExecutableDigest != "" || len(frame.Arguments) != 0 || frame.ErrorCode != "" ||
		frame.SupervisorDigest != expectedDigest || frame.PID != 0 || frame.StartNS != 0 ||
		binding.PID <= 0 || binding.StartMonotonicNS == 0 || len(binding.Digest) != 64 {
		return shadowmodel.SupervisorProcessBinding{}, errors.New("production supervisor returned an invalid binding")
	}
	return binding, nil
}

func processBinding(
	record shadowmodel.RecoveryRecord,
	config shadowsupervisor.StartConfig,
	executableLeaf string,
	supervisor shadowmodel.SupervisorProcessBinding,
	frame shadowsupervisor.Frame,
) (contract.ProcessBinding, error) {
	expectedExecutable := filepath.Join(config.Init.CloneRoot, "WeChat.app", filepath.FromSlash(executableLeaf))
	if frame.Version != shadowsupervisor.ProtocolVersion || frame.Type != "bound" || frame.PID <= 0 ||
		frame.Mode != "" || len(frame.Arguments) != 0 || frame.ErrorCode != "" ||
		frame.StartNS == 0 || frame.PID == supervisor.PID || frame.SupervisorPID != supervisor.PID ||
		frame.SupervisorStartNS != supervisor.StartMonotonicNS || frame.SupervisorDigest != supervisor.Digest ||
		!safeExecutableLeaf(executableLeaf) || config.Init.Executable != expectedExecutable ||
		frame.LeaseDeadlineNS != record.Deadline.CaptureStopNS || frame.Executable != config.Init.Executable ||
		frame.CloneRoot != config.Init.CloneRoot || frame.ExecutableDigest != config.Init.ExecutableDigest {
		return contract.ProcessBinding{}, errors.New("production supervisor returned an invalid child binding")
	}
	binding := contract.ProcessBinding{
		PID: frame.PID, StartMonotonicNS: frame.StartNS,
		SupervisorPID: supervisor.PID, SupervisorStartMonotonicNS: supervisor.StartMonotonicNS,
		ExecutableLeaf:   filepath.ToSlash(filepath.Join(record.RootLeaf, "WeChat.app", filepath.FromSlash(executableLeaf))),
		ExecutableDigest: frame.ExecutableDigest, CloneRootLeaf: record.RootLeaf,
		SupervisorDigest: supervisor.Digest,
	}
	if err := binding.Validate(); err != nil {
		return contract.ProcessBinding{}, err
	}
	return binding, nil
}

func (value *Adapter) putSession(attemptID string, active activeSupervisor) error {
	value.mu.Lock()
	defer value.mu.Unlock()
	if _, found := value.sessions[attemptID]; found {
		return errors.New("production attempt already owns a supervisor session")
	}
	value.sessions[attemptID] = active
	return nil
}

func (value *Adapter) updateSessionProcess(
	attemptID string,
	supervisor shadowmodel.SupervisorProcessBinding,
	process contract.ProcessBinding,
) error {
	value.mu.Lock()
	defer value.mu.Unlock()
	active, found := value.sessions[attemptID]
	if !found || active.supervisor != supervisor || active.process != nil {
		return errors.New("production supervisor session changed before child persistence")
	}
	copy := process
	active.process = &copy
	value.sessions[attemptID] = active
	return nil
}

func (value *Adapter) session(attemptID string) (activeSupervisor, bool) {
	value.mu.Lock()
	defer value.mu.Unlock()
	active, found := value.sessions[attemptID]
	return active, found
}

func (value *Adapter) removeSession(attemptID string) {
	value.mu.Lock()
	defer value.mu.Unlock()
	delete(value.sessions, attemptID)
}

func (value *Adapter) closeFailedSession(ctx context.Context, attemptID string, prepared bool) {
	active, found := value.session(attemptID)
	if !found {
		return
	}
	clean := false
	if prepared {
		clean, _ = active.session.Stop(ctx)
	} else {
		clean, _ = active.session.CloseProvider(ctx)
	}
	if clean {
		value.removeSession(attemptID)
	}
}

func (value *Adapter) PrepareLaunch(
	ctx context.Context,
	record shadowmodel.RecoveryRecord,
	persistSupervisor func(shadowmodel.SupervisorProcessBinding) error,
	persistProcess func(contract.ProcessBinding) error,
) (contract.ProcessBinding, error) {
	if !value.bound(ctx, record) || persistSupervisor == nil || persistProcess == nil {
		return contract.ProcessBinding{}, shadowmodel.NewFailure(contract.ErrorSupervisor)
	}
	config, err := value.launchConfig(ctx, record)
	if err != nil {
		return contract.ProcessBinding{}, shadowmodel.NewFailure(contract.ErrorSupervisor)
	}
	session, frame, err := value.start(ctx, config)
	if err != nil || session == nil {
		return contract.ProcessBinding{}, shadowmodel.NewFailure(contract.ErrorSupervisor)
	}
	supervisor, err := supervisorBinding(frame, config.SupervisorDigest)
	if err != nil || value.putSession(record.AttemptID, activeSupervisor{session: session, supervisor: supervisor}) != nil {
		_, _ = session.CloseProvider(ctx)
		return contract.ProcessBinding{}, shadowmodel.NewFailure(contract.ErrorSupervisor)
	}
	if err := persistSupervisor(supervisor); err != nil {
		value.closeFailedSession(ctx, record.AttemptID, false)
		return contract.ProcessBinding{}, err
	}
	bound, err := session.Prepare(ctx)
	if err != nil {
		value.closeFailedSession(ctx, record.AttemptID, false)
		return contract.ProcessBinding{}, shadowmodel.NewFailure(contract.ErrorSupervisor)
	}
	process, err := processBinding(record, config, value.ExecutableLeaf, supervisor, bound)
	if err != nil {
		value.closeFailedSession(ctx, record.AttemptID, true)
		return contract.ProcessBinding{}, shadowmodel.NewFailure(contract.ErrorSupervisor)
	}
	if err := value.updateSessionProcess(record.AttemptID, supervisor, process); err != nil {
		_, _ = session.Stop(ctx)
		return contract.ProcessBinding{}, shadowmodel.NewFailure(contract.ErrorSupervisor)
	}
	if err := persistProcess(process); err != nil {
		value.closeFailedSession(ctx, record.AttemptID, true)
		return contract.ProcessBinding{}, err
	}
	return process, nil
}

func (value *Adapter) ReleaseLaunch(ctx context.Context, record shadowmodel.RecoveryRecord) error {
	if !value.bound(ctx, record) || record.PendingAction != shadowmodel.ActionReleaseLaunch ||
		record.Supervisor == nil || record.Process == nil {
		return shadowmodel.NewFailure(contract.ErrorSupervisor)
	}
	active, found := value.session(record.AttemptID)
	if !found || active.supervisor != *record.Supervisor || active.process == nil || *active.process != *record.Process {
		return shadowmodel.NewFailure(contract.ErrorSupervisor)
	}
	if err := active.session.Release(ctx); err != nil {
		return shadowmodel.NewFailure(contract.ErrorSupervisor)
	}
	return nil
}

func (value *Adapter) Capture(ctx context.Context, record shadowmodel.RecoveryRecord) ([]byte, error) {
	if !value.bound(ctx, record) || record.State != shadowmodel.StateActive {
		return nil, shadowmodel.NewFailure(contract.ErrorCapture)
	}
	active, found := value.session(record.AttemptID)
	if !found || record.Supervisor == nil || active.supervisor != *record.Supervisor ||
		record.Process == nil || active.process == nil || *active.process != *record.Process {
		return nil, shadowmodel.NewFailure(contract.ErrorCapture)
	}
	return value.CaptureRuntime.Capture(ctx, value.Prelaunch.Account, record)
}

func (value *Adapter) ValidateCredential(candidate []byte) error {
	if value == nil || value.CaptureRuntime == nil {
		return errors.New("production capture validator is unavailable")
	}
	return value.CaptureRuntime.ValidateCredential(candidate)
}

func (value *Adapter) Route() string { return contract.CleanupRouteDirect }

func (value *Adapter) StopCapture(ctx context.Context, record shadowmodel.RecoveryRecord) error {
	if !value.bound(ctx, record) {
		return errors.New("production capture cleanup binding is invalid")
	}
	return value.CaptureRuntime.Stop(ctx, record)
}

func (value *Adapter) StopSupervisor(ctx context.Context, record shadowmodel.RecoveryRecord) (bool, error) {
	if !value.bound(ctx, record) {
		return false, errors.New("production supervisor cleanup binding is invalid")
	}
	if active, found := value.session(record.AttemptID); found {
		if record.Supervisor != nil && active.supervisor != *record.Supervisor ||
			record.Process != nil && (active.process == nil || *active.process != *record.Process) {
			return false, errors.New("production supervisor cleanup identity drifted")
		}
		clean := false
		var err error
		if active.process == nil {
			clean, err = active.session.CloseProvider(ctx)
		} else {
			clean, err = active.session.Stop(ctx)
		}
		if err == nil && clean {
			value.removeSession(record.AttemptID)
			return true, nil
		}
	}
	facts, err := value.Processes.Absent(ctx, record)
	if err != nil || !facts.ProcessAbsent || !facts.SupervisorAbsent {
		return false, errors.New("production supervisor or child absence is unproven")
	}
	if _, found := value.session(record.AttemptID); found {
		value.removeSession(record.AttemptID)
	}
	return true, nil
}

func (value *Adapter) UnregisterLaunch(ctx context.Context, record shadowmodel.RecoveryRecord) error {
	if !value.bound(ctx, record) {
		return errors.New("production launch cleanup binding is invalid")
	}
	return value.Launch.UnregisterExact(ctx, value.Prelaunch.Account, record)
}

func (value *Adapter) RemoveContainer(ctx context.Context, record shadowmodel.RecoveryRecord) error {
	if !value.bound(ctx, record) {
		return errors.New("production container cleanup binding is invalid")
	}
	return value.Container.Remove(ctx, value.Prelaunch.Account, record)
}

func (value *Adapter) RemoveLeaves(ctx context.Context, record shadowmodel.RecoveryRecord) error {
	if !value.bound(ctx, record) {
		return errors.New("production leaf cleanup binding is invalid")
	}
	return value.CaptureRuntime.RemoveLeaves(ctx, value.Prelaunch.Account, record)
}

func (value *Adapter) RemoveWorkspace(ctx context.Context, record shadowmodel.RecoveryRecord) error {
	return value.Prelaunch.RemoveWorkspace(ctx, record)
}

func (value *Adapter) VerifyCleanup(ctx context.Context, record shadowmodel.RecoveryRecord) (contract.CleanupFacts, error) {
	if !value.bound(ctx, record) {
		return contract.CleanupFacts{}, errors.New("production cleanup verification binding is invalid")
	}
	processes, processErr := value.Processes.Absent(ctx, record)
	hookAbsent, socketAbsent, leavesErr := value.CaptureRuntime.LeavesAbsent(ctx, value.Prelaunch.Account, record)
	if processErr != nil || leavesErr != nil {
		return contract.CleanupFacts{}, errors.New("production cleanup facts are unavailable")
	}
	return contract.CleanupFacts{
		ProcessAbsent: processes.ProcessAbsent, SupervisorAbsent: processes.SupervisorAbsent,
		LaunchRegistrationAbsent: value.Launch.Absent(ctx, record),
		ContainerAbsent:          value.Container.Absent(value.Prelaunch.Account, record),
		HookAbsent:               hookAbsent, SocketAbsent: socketAbsent,
		CloneAbsent: value.Prelaunch.CloneAbsent(record), WorkspaceAbsent: value.Prelaunch.WorkspaceAbsent(record),
		RecoveryRecordAbsent: false, SourceUnchanged: value.Prelaunch.SourceUnchanged(ctx, record),
		SecurityPostureExpected: value.Prelaunch.SecurityPosture() == record.ExpectedSecurityPosture,
	}, nil
}

type DisabledCoordinatorConfig struct {
	Prelaunch      *Prelaunch
	ExecutableLeaf string
	Dependencies   RuntimeDependencies
	Clock          interface {
		NowNS() (uint64, error)
	}
	Journal shadowmodel.Journal
	Locker  shadowmodel.Locker
	NewID   func() (string, error)
}

// NewDisabledCoordinator wires the platform adapter into the shared state
// machine while keeping both execution routes disabled. Promotion requires a
// separate code change after the ordered machine gates, not a runtime switch.
func NewDisabledCoordinator(config DisabledCoordinatorConfig) (*shadowmodel.Coordinator, *Adapter, error) {
	adapter, err := NewAdapter(config.Prelaunch, config.ExecutableLeaf, config.Dependencies)
	if err != nil || config.Clock == nil || config.Journal == nil || config.Locker == nil {
		return nil, nil, errors.New("disabled production coordinator configuration is incomplete")
	}
	coordinator, err := shadowmodel.NewCoordinator(shadowmodel.Config{
		BuildSetDigest: config.Prelaunch.Bundle.Digest, CleanupRoute: contract.CleanupRouteDirect,
		ProductionRouteEnabled: false, SyntheticRouteEnabled: false,
		ExpectedSecurityPosture: "sip_enabled_verified", Clock: config.Clock,
		Journal: config.Journal, Locker: config.Locker, Adapter: adapter, Cleanup: adapter, NewID: config.NewID,
	})
	if err != nil {
		return nil, nil, err
	}
	return coordinator, adapter, nil
}
