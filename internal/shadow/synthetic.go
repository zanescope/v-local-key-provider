package shadow

import (
	"context"
	"crypto/subtle"
	"errors"
	"sync"

	clockmodel "github.com/zanescope/v-local-key-provider/internal/shadowclock"
	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
)

type SyntheticAdapter struct {
	mu sync.Mutex

	Clock          clockmodel.Clock
	AdvanceNS      func(uint64)
	StepNS         uint64
	AdvanceByStage map[string]uint64
	BuildSet       string
	SourceDigest   string
	SourceVersion  string
	SourceBuild    string
	ProcessPID     int
	Credential     []byte
	Expected       []byte
	FailBefore     map[string]string
	FailAfter      map[string]string
	Events         []string

	workspace  bool
	clone      bool
	hook       bool
	socket     bool
	registered bool
	container  bool
	suspended  bool
	process    bool
	supervisor bool
	tampered   bool
}

func (value *SyntheticAdapter) step(stage string, sideEffect func()) error {
	value.mu.Lock()
	defer value.mu.Unlock()
	value.Events = append(value.Events, stage)
	if code := value.FailBefore[stage]; code != "" {
		return NewFailure(code)
	}
	if sideEffect != nil {
		sideEffect()
	}
	advance := value.StepNS
	if specific, found := value.AdvanceByStage[stage]; found {
		advance = specific
	}
	if value.AdvanceNS != nil && advance != 0 {
		value.AdvanceNS(advance)
	}
	if code := value.FailAfter[stage]; code != "" {
		return NewFailure(code)
	}
	return nil
}

func syntheticResource(kind, leaf string, inode uint64, mode uint32, digest string) contract.ResourceBinding {
	return contract.ResourceBinding{
		Kind: kind, Leaf: leaf, Device: 1, Inode: inode, UID: 501, Mode: mode, LinkCount: 1, DigestSHA256: digest,
	}
}

func (value *SyntheticAdapter) source() SourceBinding {
	return SourceBinding{Leaf: "WeChat.app", Device: 1, Inode: 10, UID: 0, Mode: 0o755, ManifestDigest: value.SourceDigest}
}

func (value *SyntheticAdapter) Qualify(_ context.Context, request contract.Request) (contract.Qualification, SourceBinding, error) {
	if err := value.step("qualify", nil); err != nil {
		return contract.Qualification{}, SourceBinding{}, err
	}
	return contract.Qualification{
		Version: contract.Version, BuildSetDigest: value.BuildSet, SourceQualificationDigest: value.SourceDigest,
		CleanupRoute: contract.CleanupRouteDirect, AccountBindingID: request.AccountBindingID, OptionsDigest: request.OptionsDigest,
		SourceVersion: value.SourceVersion, SourceBuild: value.SourceBuild,
	}, value.source(), nil
}

func (value *SyntheticAdapter) Requalify(_ context.Context, _ contract.Request) (SourceBinding, error) {
	if err := value.step("requalify", nil); err != nil {
		return SourceBinding{}, err
	}
	value.mu.Lock()
	defer value.mu.Unlock()
	if value.tampered {
		return SourceBinding{}, NewFailure(contract.ErrorSourceDrift)
	}
	return value.source(), nil
}

func (value *SyntheticAdapter) CreateWorkspace(_ context.Context, record RecoveryRecord) ([]contract.ResourceBinding, error) {
	err := value.step("create_workspace", func() { value.workspace, value.clone = true, true })
	if err != nil {
		return nil, err
	}
	return []contract.ResourceBinding{
		syntheticResource("workspace", record.RootLeaf, 101, 0o700, ""),
		syntheticResource("clone_app", record.RootLeaf+"/WeChat.app", 102, 0o700, "5555555555555555555555555555555555555555555555555555555555555555"),
	}, nil
}

func (value *SyntheticAdapter) Transform(context.Context, RecoveryRecord) error {
	return value.step("transform", nil)
}

func (value *SyntheticAdapter) SupervisorArtifact(context.Context, RecoveryRecord) (contract.ResourceBinding, error) {
	if err := value.step("supervisor_artifact", nil); err != nil {
		return contract.ResourceBinding{}, err
	}
	return syntheticResource("supervisor", "v-local-shadow-supervisor", 107, 0o700,
		"4444444444444444444444444444444444444444444444444444444444444444"), nil
}

func (value *SyntheticAdapter) CreateCaptureLeaves(_ context.Context, record RecoveryRecord) ([]contract.ResourceBinding, error) {
	err := value.step("create_capture_leaves", func() { value.hook, value.socket = true, true })
	if err != nil {
		return nil, err
	}
	return []contract.ResourceBinding{
		syntheticResource("hook", record.RootLeaf+"/hook.fifo", 104, 0o600, ""),
		syntheticResource("socket", record.RootLeaf+"/control.sock", 105, 0o600, ""),
	}, nil
}

func (value *SyntheticAdapter) RegisterLaunch(context.Context, RecoveryRecord) error {
	return value.step("register_launch", func() { value.registered = true })
}

func (value *SyntheticAdapter) CreateContainer(_ context.Context, record RecoveryRecord) (contract.ResourceBinding, error) {
	err := value.step("create_container", func() { value.container = true })
	if err != nil {
		return contract.ResourceBinding{}, err
	}
	return syntheticResource("container", record.BundleID, 103, 0o700, ""), nil
}

func (value *SyntheticAdapter) PrepareLaunch(
	_ context.Context,
	record RecoveryRecord,
	persistSupervisor func(SupervisorProcessBinding) error,
	persistProcess func(contract.ProcessBinding) error,
) (contract.ProcessBinding, error) {
	err := value.step("prepare_launch", func() { value.supervisor = true })
	if err != nil {
		return contract.ProcessBinding{}, err
	}
	if persistSupervisor == nil || persistProcess == nil {
		value.mu.Lock()
		value.supervisor = false
		value.mu.Unlock()
		return contract.ProcessBinding{}, errors.New("synthetic launch persistence callback is missing")
	}
	now, _ := value.Clock.NowNS()
	pid := value.ProcessPID
	if pid <= 0 {
		pid = 43210
	}
	supervisor := SupervisorProcessBinding{PID: pid + 1, StartMonotonicNS: now, Digest: "4444444444444444444444444444444444444444444444444444444444444444"}
	if err := persistSupervisor(supervisor); err != nil {
		value.mu.Lock()
		value.supervisor = false
		value.mu.Unlock()
		return contract.ProcessBinding{}, err
	}
	value.mu.Lock()
	value.suspended = true
	value.mu.Unlock()
	process := contract.ProcessBinding{
		PID: pid, StartMonotonicNS: now, SupervisorPID: supervisor.PID, SupervisorStartMonotonicNS: supervisor.StartMonotonicNS,
		ExecutableLeaf:   record.RootLeaf + "/WeChat.app/Contents/MacOS/WeChat",
		ExecutableDigest: "5555555555555555555555555555555555555555555555555555555555555555",
		CloneRootLeaf:    record.RootLeaf, SupervisorDigest: "4444444444444444444444444444444444444444444444444444444444444444",
	}
	if err := persistProcess(process); err != nil {
		value.mu.Lock()
		value.suspended, value.supervisor = false, false
		value.mu.Unlock()
		return contract.ProcessBinding{}, err
	}
	return process, nil
}

func (value *SyntheticAdapter) ReleaseLaunch(context.Context, RecoveryRecord) error {
	return value.step("release_launch", func() {
		if value.suspended {
			value.suspended = false
			value.process = true
		}
	})
}

func (value *SyntheticAdapter) Capture(context.Context, RecoveryRecord) ([]byte, error) {
	if err := value.step("capture", nil); err != nil {
		return nil, err
	}
	value.mu.Lock()
	defer value.mu.Unlock()
	if !value.process {
		return nil, NewFailure(contract.ErrorCapture)
	}
	return append([]byte(nil), value.Credential...), nil
}

func (value *SyntheticAdapter) ValidateCredential(candidate []byte) error {
	if len(candidate) == 0 || len(candidate) != len(value.Expected) || subtle.ConstantTimeCompare(candidate, value.Expected) != 1 {
		return errors.New("synthetic credential validation failed")
	}
	return nil
}

func (value *SyntheticAdapter) Route() string { return contract.CleanupRouteDirect }

func (value *SyntheticAdapter) StopCapture(context.Context, RecoveryRecord) error {
	return value.step("stop_capture", nil)
}

func (value *SyntheticAdapter) StopSupervisor(context.Context, RecoveryRecord) (bool, error) {
	err := value.step("stop_supervisor", func() {
		value.process, value.suspended, value.supervisor = false, false, false
	})
	value.mu.Lock()
	stopped := !value.process && !value.suspended && !value.supervisor
	value.mu.Unlock()
	return stopped, err
}

func (value *SyntheticAdapter) UnregisterLaunch(context.Context, RecoveryRecord) error {
	return value.step("unregister_launch", func() { value.registered = false })
}

func (value *SyntheticAdapter) RemoveContainer(context.Context, RecoveryRecord) error {
	return value.step("remove_container", func() { value.container = false })
}

func (value *SyntheticAdapter) RemoveLeaves(context.Context, RecoveryRecord) error {
	return value.step("remove_leaves", func() { value.hook, value.socket = false, false })
}

func (value *SyntheticAdapter) RemoveWorkspace(context.Context, RecoveryRecord) error {
	return value.step("remove_workspace", func() {
		if !value.process && !value.suspended {
			value.clone, value.workspace = false, false
		}
	})
}

func (value *SyntheticAdapter) VerifyCleanup(context.Context, RecoveryRecord) (contract.CleanupFacts, error) {
	if err := value.step("verify_cleanup", nil); err != nil {
		return contract.CleanupFacts{}, err
	}
	value.mu.Lock()
	defer value.mu.Unlock()
	return contract.CleanupFacts{
		ProcessAbsent: !value.process && !value.suspended, SupervisorAbsent: !value.supervisor,
		LaunchRegistrationAbsent: !value.registered, ContainerAbsent: !value.container,
		HookAbsent: !value.hook, SocketAbsent: !value.socket, CloneAbsent: !value.clone,
		WorkspaceAbsent: !value.workspace, RecoveryRecordAbsent: false,
		SourceUnchanged: !value.tampered, SecurityPostureExpected: true,
	}, nil
}

func (value *SyntheticAdapter) Residue() bool {
	value.mu.Lock()
	defer value.mu.Unlock()
	return value.workspace || value.clone || value.hook || value.socket || value.registered || value.container ||
		value.suspended || value.process || value.supervisor
}
