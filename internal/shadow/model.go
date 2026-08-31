package shadow

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
)

const recoveryRecordVersion = 1

const (
	StatePlanned        = "planned"
	StatePrepared       = "prepared"
	StateActive         = "active"
	StateCleanupPending = "cleanup_pending"
)

const (
	ActionNone             = "none"
	ActionPrepareWorkspace = "prepare_workspace"
	ActionTransform        = "transform"
	ActionCreateLeaves     = "create_capture_leaves"
	ActionRegisterLaunch   = "register_launch"
	ActionCreateContainer  = "create_container"
	ActionPrepareLaunch    = "prepare_launch"
	ActionReleaseLaunch    = "release_launch"
)

type SourceBinding struct {
	Leaf           string `json:"leaf"`
	Device         uint64 `json:"device"`
	Inode          uint64 `json:"inode"`
	UID            uint32 `json:"uid"`
	Mode           uint32 `json:"mode"`
	ManifestDigest string `json:"manifest_digest"`
}

type SupervisorProcessBinding struct {
	PID              int    `json:"pid"`
	StartMonotonicNS uint64 `json:"start_monotonic_ns"`
	Digest           string `json:"digest"`
}

func (value SupervisorProcessBinding) validate() error {
	_, digestErr := hex.DecodeString(value.Digest)
	if value.PID <= 0 || value.StartMonotonicNS == 0 || len(value.Digest) != 64 ||
		value.Digest != strings.ToLower(value.Digest) || digestErr != nil {
		return errors.New("supervisor process binding is invalid")
	}
	return nil
}

func (value SourceBinding) validate() error {
	_, digestErr := hex.DecodeString(value.ManifestDigest)
	if value.Leaf != "WeChat.app" || value.Device == 0 || value.Inode == 0 || value.Mode == 0 ||
		len(value.ManifestDigest) != 64 || value.ManifestDigest != strings.ToLower(value.ManifestDigest) || digestErr != nil {
		return errors.New("source binding is invalid")
	}
	return nil
}

type RecoveryRecord struct {
	Version                   int                        `json:"version"`
	Operation                 string                     `json:"operation"`
	State                     string                     `json:"state"`
	AttemptID                 string                     `json:"attempt_id"`
	ChallengeID               string                     `json:"challenge_id"`
	BuildSetDigest            string                     `json:"build_set_digest"`
	SourceQualificationDigest string                     `json:"source_qualification_digest"`
	CleanupRoute              string                     `json:"cleanup_route"`
	AccountBindingID          string                     `json:"account_binding_id"`
	OptionsDigest             string                     `json:"options_digest"`
	RootLeaf                  string                     `json:"root_leaf"`
	BundleID                  string                     `json:"bundle_id"`
	Deadline                  contract.Deadline          `json:"deadline"`
	ExpectedSecurityPosture   string                     `json:"expected_security_posture"`
	Source                    SourceBinding              `json:"source"`
	PendingAction             string                     `json:"pending_action"`
	SupervisorLeaseNS         uint64                     `json:"supervisor_lease_ns,omitempty"`
	Resources                 []contract.ResourceBinding `json:"resources"`
	Supervisor                *SupervisorProcessBinding  `json:"supervisor,omitempty"`
	Process                   *contract.ProcessBinding   `json:"process,omitempty"`
	Timings                   contract.Timings           `json:"timings"`
}

func (value RecoveryRecord) Validate() error {
	if value.Version != recoveryRecordVersion {
		return errors.New("recovery record version is invalid")
	}
	request := contract.Request{
		Version: contract.Version, Operation: value.Operation, RequestID: value.AttemptID,
		ChallengeID: value.ChallengeID, BuildSetDigest: value.BuildSetDigest,
		SourceQualificationDigest: value.SourceQualificationDigest, CleanupRoute: value.CleanupRoute,
		AccountBindingID: value.AccountBindingID, OptionsDigest: value.OptionsDigest, Deadline: &value.Deadline,
	}
	if err := request.Validate(); err != nil {
		return err
	}
	if value.RootLeaf != "attempt-"+value.AttemptID || value.BundleID != "com.zanescope.vlocal.shadow."+value.AttemptID {
		return errors.New("recovery record random identities are not attempt-bound")
	}
	validStates := map[string]bool{StatePlanned: true, StatePrepared: true, StateActive: true, StateCleanupPending: true}
	validActions := map[string]bool{ActionNone: true, ActionPrepareWorkspace: true, ActionTransform: true,
		ActionCreateLeaves: true, ActionRegisterLaunch: true, ActionCreateContainer: true,
		ActionPrepareLaunch: true, ActionReleaseLaunch: true}
	if !validStates[value.State] || !validActions[value.PendingAction] {
		return errors.New("recovery record state or pending action is invalid")
	}
	if value.Operation == "execute" && value.ExpectedSecurityPosture != "sip_enabled_verified" ||
		value.Operation == "synthetic_execute" && value.ExpectedSecurityPosture != "synthetic" {
		return errors.New("recovery record security posture is invalid")
	}
	if err := value.Source.validate(); err != nil {
		return err
	}
	if err := value.Timings.Validate(); err != nil {
		return err
	}
	seen := map[string]bool{}
	seenKinds := map[string]contract.ResourceBinding{}
	for _, resource := range value.Resources {
		if err := resource.Validate(); err != nil {
			return err
		}
		key := resource.Kind + "\x00" + resource.Leaf
		if seen[key] {
			return errors.New("recovery record repeats a resource binding")
		}
		if _, found := seenKinds[resource.Kind]; found {
			return errors.New("recovery record repeats a resource class")
		}
		seen[key] = true
		seenKinds[resource.Kind] = resource
	}
	require := func(kinds ...string) bool {
		for _, kind := range kinds {
			if _, found := seenKinds[kind]; !found {
				return false
			}
		}
		return true
	}
	only := func(kinds ...string) bool {
		return len(seenKinds) == len(kinds) && require(kinds...)
	}
	if workspace, found := seenKinds["workspace"]; found && workspace.Leaf != value.RootLeaf {
		return errors.New("recovery workspace is not attempt-bound")
	}
	if clone, found := seenKinds["clone_app"]; found && clone.Leaf != value.RootLeaf+"/WeChat.app" {
		return errors.New("recovery clone is not attempt-bound")
	}
	if container, found := seenKinds["container"]; found && container.Leaf != value.BundleID {
		return errors.New("recovery container is not attempt-bound")
	}
	for _, kind := range []string{"hook", "socket"} {
		if resource, found := seenKinds[kind]; found && !strings.HasPrefix(resource.Leaf, value.RootLeaf+"/") {
			return errors.New("recovery capture leaf is not attempt-bound")
		}
	}
	_, hookFound := seenKinds["hook"]
	_, socketFound := seenKinds["socket"]
	if _, found := seenKinds["recovery_record"]; found {
		return errors.New("durable recovery payload cannot self-bind its journal file")
	}
	if supervisor, found := seenKinds["supervisor"]; found && supervisor.Leaf != "v-local-shadow-supervisor" {
		return errors.New("recovery supervisor artifact leaf is invalid")
	}
	if hookFound != socketFound || len(value.Resources) != 0 && !require("workspace", "clone_app") {
		return errors.New("recovery resource lifecycle is incomplete")
	}
	switch value.State {
	case StatePlanned:
		if (value.PendingAction != ActionNone && value.PendingAction != ActionPrepareWorkspace) || len(value.Resources) != 0 ||
			value.Supervisor != nil || value.Process != nil {
			return errors.New("planned recovery lifecycle is invalid")
		}
	case StatePrepared:
		if value.PendingAction == ActionPrepareWorkspace || !require("workspace", "clone_app") {
			return errors.New("prepared recovery lifecycle is invalid")
		}
		switch value.PendingAction {
		case ActionNone:
			if !only("workspace", "clone_app") &&
				!only("workspace", "clone_app", "supervisor", "hook", "socket") &&
				!only("workspace", "clone_app", "supervisor", "hook", "socket", "container") {
				return errors.New("completed prepared checkpoint has unexpected resources")
			}
		case ActionTransform:
			if !only("workspace", "clone_app") {
				return errors.New("transform checkpoint has unexpected resources")
			}
		case ActionCreateLeaves:
			if !only("workspace", "clone_app", "supervisor") {
				return errors.New("capture-leaf checkpoint has unexpected resources")
			}
		case ActionRegisterLaunch, ActionCreateContainer:
			if !only("workspace", "clone_app", "supervisor", "hook", "socket") {
				return errors.New("launch-registration checkpoint has unexpected resources")
			}
		case ActionPrepareLaunch, ActionReleaseLaunch:
			if !only("workspace", "clone_app", "supervisor", "hook", "socket", "container") {
				return errors.New("launch checkpoint has unexpected resources")
			}
		}
	case StateActive:
		if value.PendingAction != ActionNone || !only("workspace", "clone_app", "container", "hook", "socket", "supervisor") ||
			value.Supervisor == nil || value.Process == nil {
			return errors.New("active recovery lifecycle is incomplete")
		}
	case StateCleanupPending:
		if value.PendingAction != ActionNone {
			return errors.New("cleanup recovery lifecycle retained a pending action")
		}
		if !only() && !only("workspace", "clone_app") &&
			!only("workspace", "clone_app", "supervisor") &&
			!only("workspace", "clone_app", "supervisor", "hook", "socket") &&
			!only("workspace", "clone_app", "supervisor", "hook", "socket", "container") {
			return errors.New("cleanup recovery lifecycle has an unreachable resource set")
		}
		if (value.Supervisor != nil || value.Process != nil) &&
			!only("workspace", "clone_app", "supervisor", "hook", "socket", "container") {
			return errors.New("cleanup recovery process binding lacks its launch resources")
		}
	}
	if value.PendingAction == ActionReleaseLaunch && (value.Supervisor == nil || value.Process == nil) {
		return errors.New("recovery pending action lacks its prior durable bindings")
	}
	if value.State == StatePrepared && value.PendingAction != ActionPrepareLaunch &&
		value.PendingAction != ActionReleaseLaunch && (value.Supervisor != nil || value.Process != nil) {
		return errors.New("prepared recovery process binding is outside the launch checkpoint")
	}
	if value.Supervisor != nil {
		if err := value.Supervisor.validate(); err != nil {
			return err
		}
		if value.SupervisorLeaseNS != value.Deadline.CaptureStopNS {
			return errors.New("recovery supervisor lease is not capture-deadline-bound")
		}
		supervisorResource, found := seenKinds["supervisor"]
		if !found || supervisorResource.DigestSHA256 != value.Supervisor.Digest {
			return errors.New("recovery supervisor process lacks its exact build artifact")
		}
	} else if value.SupervisorLeaseNS != 0 {
		return errors.New("recovery record has a lease without a supervisor binding")
	}
	if value.Process != nil {
		if err := value.Process.Validate(); err != nil {
			return err
		}
		if value.Supervisor == nil ||
			value.Process.SupervisorPID != value.Supervisor.PID ||
			value.Process.SupervisorStartMonotonicNS != value.Supervisor.StartMonotonicNS ||
			value.Process.SupervisorDigest != value.Supervisor.Digest {
			return errors.New("recovery process does not match its persisted supervisor")
		}
		executablePrefix := value.RootLeaf + "/WeChat.app/Contents/MacOS/"
		executableName := strings.TrimPrefix(value.Process.ExecutableLeaf, executablePrefix)
		if value.Process.CloneRootLeaf != value.RootLeaf || executableName == value.Process.ExecutableLeaf ||
			executableName == "" || strings.Contains(executableName, "/") {
			return errors.New("recovery process executable is not clone-bound")
		}
	}
	return nil
}

func (value *RecoveryRecord) BindSupervisor(supervisor SupervisorProcessBinding) error {
	if err := supervisor.validate(); err != nil {
		return err
	}
	if value.Supervisor != nil {
		if *value.Supervisor != supervisor || value.SupervisorLeaseNS != value.Deadline.CaptureStopNS {
			return errors.New("recovery supervisor binding cannot be overwritten")
		}
		return nil
	}
	if value.SupervisorLeaseNS != 0 || value.Deadline.CaptureStopNS == 0 {
		return errors.New("recovery supervisor lease cannot be established")
	}
	value.Supervisor = &supervisor
	value.SupervisorLeaseNS = value.Deadline.CaptureStopNS
	return nil
}

func (value *RecoveryRecord) SetPending(action string) error {
	previous := value.PendingAction
	value.PendingAction = action
	if err := value.Validate(); err != nil {
		value.PendingAction = previous
		return err
	}
	return nil
}

func (value *RecoveryRecord) BindResource(resource contract.ResourceBinding) error {
	if err := resource.Validate(); err != nil {
		return err
	}
	for _, existing := range value.Resources {
		if existing.Kind != resource.Kind {
			continue
		}
		if existing != resource {
			return errors.New("recovery resource class cannot be rebound")
		}
		return nil
	}
	value.Resources = append(value.Resources, resource)
	sort.Slice(value.Resources, func(left, right int) bool {
		if value.Resources[left].Kind == value.Resources[right].Kind {
			return value.Resources[left].Leaf < value.Resources[right].Leaf
		}
		return value.Resources[left].Kind < value.Resources[right].Kind
	})
	return nil
}

func (value *RecoveryRecord) BindProcess(process contract.ProcessBinding) error {
	if err := process.Validate(); err != nil {
		return err
	}
	if value.Supervisor == nil || process.SupervisorPID != value.Supervisor.PID ||
		process.SupervisorStartMonotonicNS != value.Supervisor.StartMonotonicNS ||
		process.SupervisorDigest != value.Supervisor.Digest {
		return errors.New("recovery process is not owned by the persisted supervisor")
	}
	if value.Process != nil {
		if *value.Process != process {
			return errors.New("recovery process binding cannot be overwritten")
		}
		return nil
	}
	value.Process = &process
	return nil
}

type Failure struct {
	Code string
}

func (value *Failure) Error() string {
	return fmt.Sprintf("shadow attempt failed at stable code %s", value.Code)
}

func NewFailure(code string) error {
	if err := contract.ValidateErrorCode(code); err != nil || code == contract.ErrorNone {
		code = contract.ErrorInternal
	}
	return &Failure{Code: code}
}

func failureCode(err error, fallback string) string {
	var failure *Failure
	if errors.As(err, &failure) {
		return failure.Code
	}
	if contract.ValidateErrorCode(fallback) != nil || fallback == contract.ErrorNone {
		return contract.ErrorInternal
	}
	return fallback
}
